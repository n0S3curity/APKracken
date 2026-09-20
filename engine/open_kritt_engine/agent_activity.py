"""Live agent-activity feed.

While a scan step runs, the engine appends what the agent is doing right now — reasoning,
tool calls, observations, device actions — to ``scans.reasoning.agent_activity``. The scan
API already serves ``reasoning`` verbatim and both scan pages poll it every second, so this
reuses the same live channel as ``dynamic_progress`` (see dynamic_investigation._write_progress).

Reporting is best-effort and must NEVER break a scan: every write is wrapped and swallowed.

The active sink is stored in a thread-local set by the worker around ``harness.run(...)``.
Harness code runs in that same worker thread, so ``report_activity`` reaches the right scan
without threading a handle through every call site.
"""
from __future__ import annotations

import json
import logging
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable

LOGGER = logging.getLogger("open_kritt_engine")

_state = threading.local()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _trim(text: str, limit: int = 500) -> str:
    collapsed = " ".join(str(text).split())
    return collapsed if len(collapsed) <= limit else collapsed[: limit - 1] + "…"


def set_activity_sink(sink: Callable[[dict], None] | None) -> None:
    _state.sink = sink


def clear_activity_sink() -> None:
    _state.sink = None


def report_activity(kind: str, text: str, **extra: Any) -> None:
    """Emit one live activity event to the current sink, if any. Never raises."""
    sink = getattr(_state, "sink", None)
    if sink is None:
        return
    try:
        event = {"t": _now(), "kind": str(kind), "text": _trim(text)}
        for key, value in extra.items():
            event[key] = value
        sink(event)
    except Exception:  # noqa: BLE001 - activity reporting must never break a scan
        pass


class ScanActivityWriter:
    """Sink that keeps a capped ring buffer of recent events and flushes them to
    ``scans.reasoning.agent_activity``, throttled so a busy ReAct loop does not hammer
    the DB. The tail is always flushed by :meth:`finalize`."""

    def __init__(
        self,
        db,
        scan_id: int,
        step_label: str,
        *,
        max_events: int = 60,
        min_interval: float = 0.4,
    ) -> None:
        self._db = db
        self._scan_id = int(scan_id)
        self._step_label = step_label
        self._events: list[dict] = []
        self._max = max_events
        self._min_interval = min_interval
        self._last_write = 0.0
        self._lock = threading.Lock()

    def __call__(self, event: dict) -> None:
        with self._lock:
            self._events.append(event)
            if len(self._events) > self._max:
                self._events = self._events[-self._max :]
            now = time.monotonic()
            if now - self._last_write < self._min_interval:
                return
            self._last_write = now
            snapshot = list(self._events)
        self._flush(snapshot)

    def _flush(self, events: list[dict]) -> None:
        payload = {"step": self._step_label, "events": events, "updated_at": _now()}
        try:
            with self._db.connect() as conn:
                conn.execute(
                    "update scans set reasoning = coalesce(reasoning,'{}'::jsonb) || "
                    "jsonb_build_object('agent_activity', %s::jsonb) where id=%s",
                    (json.dumps(payload), self._scan_id),
                )
                conn.commit()
        except Exception:  # noqa: BLE001 - never break a scan over progress
            LOGGER.debug("failed to write agent activity for scan %s", self._scan_id, exc_info=True)

    def finalize(self, note: str | None = None, kind: str = "done") -> None:
        with self._lock:
            if note:
                self._events.append({"t": _now(), "kind": kind, "text": _trim(note)})
                if len(self._events) > self._max:
                    self._events = self._events[-self._max :]
            snapshot = list(self._events)
            self._last_write = time.monotonic()
        self._flush(snapshot)
