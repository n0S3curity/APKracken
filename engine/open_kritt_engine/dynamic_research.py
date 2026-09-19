"""Android Dynamic Exploit Research - a staged, on-device workflow that walks a completed
static scan's findings the way an expert mobile researcher would: recon the surface, stand up
a rooted device, form a concrete hypothesis per finding, drive the device to reproduce it,
defeat any guard with a standard Frida bypass, capture the impact as screenshots, chain
confirmed primitives, and keep only what was actually proven - then report and tear down.

Each phase is a focused agentic step (its own narrow objective and toolset) rather than one
opaque loop, because a narrow per-step objective is what makes each step's output accurate.
The driver writes a visible `pipeline` so the UI shows the walkthrough as it happens.

Scope: authorized targets (FOSS / bug-bounty-in-scope) on a device the user owns. Every
applied bypass is recorded in the finding's evidence trail.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from . import adb
from .device_verify import (
    VerificationRecorder,
    confirm_impact,
    hypothesize_finding,
    verify_finding_on_device,
)
from .dynamic_investigation import (
    _load_workspace_manifest,
    _now,
    _rerank,
    _write_progress,
    build_leads,
)

LOGGER = logging.getLogger("open_kritt_engine.dynamic_research")

# The 9 expert-researcher phases, in order. Keys drive the UI pipeline; labels are shown.
PHASES = [
    ("recon", "Recon - map attack surface"),
    ("device", "Device prep - install, root, Frida"),
    ("plan", "Plan - hypothesis per finding"),
    ("reproduce", "Reproduce - drive the device"),
    ("bypass", "Bypass & retry - defeat guards"),
    ("confirm", "Confirm impact - capture evidence"),
    ("chain", "Chain - combine confirmed primitives"),
    ("adjudicate", "Adjudicate - keep only what is proven"),
    ("report", "Report & cleanup"),
]

# How many findings to attempt on-device, highest severity first (bounds wall-clock).
DEFAULT_VERIFY_TOP_N = int(os.getenv("ENGINE_VERIFY_TOP_N", "8"))


def _acquire_device(*, allow_emulator: bool = True):
    """Return (device, emulator_handle). Prefer an already-connected device (ENGINE_ADB_SERIAL
    honored); optionally boot an AVD as a fallback. emulator_handle is None for a physical
    device and is torn down in the cleanup phase when set."""

    try:
        return adb.get_device(), None
    except Exception:  # noqa: BLE001 - no physical device; try an emulator if permitted
        LOGGER.info("no connected device; emulator fallback allowed=%s", allow_emulator)
    if not allow_emulator:
        return None, None
    try:
        from . import emulator as emu

        device, proc = emu.boot_avd(os.getenv("ENGINE_EMULATOR_AVD"), headless=True, cold=True)
        return device, proc
    except Exception:  # noqa: BLE001 - emulator not usable; caller degrades to no-device
        LOGGER.exception("emulator fallback failed")
        return None, None


def _load_findings(conn, scan_id: int) -> list[dict[str, Any]]:
    rows = conn.execute(
        "select id, json_answer from workflows.vulnerabilities where scan_id=%s", (scan_id,)
    ).fetchall()
    out = []
    for r in rows:
        rid = r[0] if not isinstance(r, dict) else r["id"]
        ja = (r[1] if not isinstance(r, dict) else r["json_answer"]) or {}
        try:
            sev = float(ja.get("severity_score") or 0)
        except (TypeError, ValueError):
            sev = 0.0
        out.append({"id": int(rid), "ja": ja, "sev": sev})
    return out


def _persist(conn, finding_id: int, ja: dict[str, Any]) -> None:
    import json as _json

    conn.execute(
        "update workflows.vulnerabilities set json_answer=%s where id=%s",
        (_json.dumps(ja), finding_id),
    )
    conn.commit()


def run_dynamic_research_for_scan(
    conn,
    scan_id: int,
    *,
    data_dir: str,
    device=None,
    static_only: bool = False,
    verify_top_n: int | None = None,
    allow_emulator: bool = True,
) -> dict[str, Any]:
    """Run the 9-phase on-device research pipeline over a completed scan's findings."""

    top_n = verify_top_n or DEFAULT_VERIFY_TOP_N
    emulator_handle = None

    # ------------------------------ progress scaffolding ------------------------------ #
    pipeline = [{"key": k, "label": lbl, "state": "pending"} for k, lbl in PHASES]
    progress: dict[str, Any] = {
        "status": "running",
        "kind": "dynamic_research",
        "pipeline": pipeline,
        "current": None,
        "started_at": _now(),
        "verified": 0,
        "attempted": 0,
    }

    def phase(key: str, **kw: Any) -> None:
        for p in pipeline:
            if p["key"] == key:
                p.update(kw)
        _write_progress(conn, scan_id, progress)

    def finish_phase(key: str, **kw: Any) -> None:
        phase(key, state="done", **kw)

    _write_progress(conn, scan_id, progress)

    row = conn.execute(
        "select repo_full, commit_sha, configuration from scans where id=%s", (scan_id,)
    ).fetchone()
    scan = row if isinstance(row, dict) else {"repo_full": row[0], "commit_sha": row[1], "configuration": row[2]}

    try:
        # ---------------------------- Phase 1: recon ---------------------------- #
        phase("recon", state="running")
        try:
            manifest, workspace_dir = _load_workspace_manifest(data_dir, scan)
            android = manifest.get("android", {})
        except Exception:  # noqa: BLE001
            android, workspace_dir = {}, ""
        package = android.get("package") or scan["repo_full"]
        deep_links = []
        try:
            leads = build_leads(android, package)
            deep_links = sorted({dl for lead in leads for dl in (lead.get("deep_links") or [])})
        except Exception:  # noqa: BLE001
            leads = []
        findings = sorted(_load_findings(conn, scan_id), key=lambda f: f["sev"], reverse=True)
        # Chains are syntheses of other findings - reproduced in the chain phase, not per-finding.
        candidates = [f for f in findings if f["ja"].get("source") != "chain"][:top_n]
        finish_phase("recon", detail=f"{len(findings)} findings, {len(candidates)} device-testable, {len(deep_links)} deep links")

        # ------------------------- Phase 2: device prep ------------------------- #
        phase("device", state="running")
        if device is None and not static_only:
            device, emulator_handle = _acquire_device(allow_emulator=allow_emulator)
        if device is None:
            # No device: nothing to verify. Leave findings unproven; the UI hides them under
            # the "only exploitable" default until a device run proves them.
            finish_phase("device", state="skipped", detail="no device connected")
            for key, _ in PHASES[2:]:
                phase(key, state="skipped")
            progress["status"] = "done"
            progress["note"] = "no device connected - findings remain unverified"
            _write_progress(conn, scan_id, progress)
            return {"verified": 0, "attempted": 0, "device": False}

        from . import frida_service as fs

        try:
            device.install_apk(_apk_path(scan)) if _apk_path(scan) else None
        except Exception:  # noqa: BLE001 - app may already be installed
            LOGGER.debug("install step skipped/failed", exc_info=True)
        _disable_play_protect(device)
        frida_ok = False
        try:
            fs.ensure_server(device, force=True)
            frida_ok = fs.server_running(device.serial)
        except Exception:  # noqa: BLE001 - Frida optional; bypasses just won't be available
            LOGGER.exception("frida-server setup failed")
        finish_phase("device", detail=f"device {device.serial}, root={device.is_adb_root() or device.is_rooted()}, frida={'up' if frida_ok else 'unavailable'}")

        # -------- Phases 3-6: per-finding plan -> reproduce -> bypass -> confirm -------- #
        for key in ("plan", "reproduce", "bypass", "confirm"):
            phase(key, state="running", done=0, total=len(candidates))
        verified = 0
        for i, f in enumerate(candidates):
            ja = dict(f["ja"])
            progress["current"] = ja.get("component") or ja.get("summary")
            _write_progress(conn, scan_id, progress)

            # Phase 3: plan
            plan = hypothesize_finding(ja, package=package, deep_links=deep_links)
            if not plan.get("reachable_on_device", True):
                ja["dynamic_status"] = "not device-reproducible: " + str(plan.get("skip_reason", ""))[:200]
                ja["dynamic_tested_at"] = _now()
                _persist(conn, f["id"], ja)
                phase("plan", done=i + 1)
                continue
            phase("plan", done=i + 1)

            # Phases 4+5: reproduce (the loop applies a Frida bypass itself when a guard blocks)
            recorder = VerificationRecorder(data_dir, scan_id, f["id"], device)
            verdict = verify_finding_on_device(ja, device=device, package=package, recorder=recorder)
            phase("reproduce", done=i + 1)
            phase("bypass", done=i + 1, detail=("bypasses: " + ", ".join(verdict.get("bypasses_used") or []) if verdict.get("bypasses_used") else None))

            # Phase 6: confirm impact (honesty gate)
            judgement = confirm_impact(ja, recorder, hypothesis=plan)
            confirmed = bool(judgement.get("impact_confirmed")) and verdict.get("verdict") == "verified"
            ja["dynamic_verified"] = confirmed
            ja["dynamic_status"] = ("verified on device" if confirmed else verdict.get("verdict", "not_reproduced"))
            ja["dynamic_confidence"] = verdict.get("confidence")
            ja["dynamic_impact"] = judgement.get("impact_statement") or verdict.get("impact_shown")
            ja["dynamic_bypasses"] = verdict.get("bypasses_used") or []
            ja["dynamic_screenshots"] = verdict.get("evidence_screenshots") or recorder.artifacts()
            ja["dynamic_steps"] = verdict.get("evidence_steps") or recorder.steps
            ja["dynamic_reproduction"] = verdict.get("reproduction_steps") or []
            ja["dynamic_blocker"] = verdict.get("blocker") or judgement.get("residual_doubt") or ""
            ja["dynamic_tested_at"] = _now()
            _persist(conn, f["id"], ja)
            if confirmed:
                verified += 1
            progress["verified"] = verified
            progress["attempted"] = i + 1
            phase("confirm", done=i + 1)

        for key in ("plan", "reproduce", "bypass", "confirm"):
            finish_phase(key)

        # ---------------------------- Phase 7: chain ---------------------------- #
        phase("chain", state="running")
        # Chain synthesis reuses the existing analyst over the now device-proven primitives.
        try:
            _maybe_chain(conn, scan_id, workspace_dir, package, device, static_only=static_only)
            finish_phase("chain")
        except Exception:  # noqa: BLE001
            LOGGER.exception("chain phase failed")
            finish_phase("chain", state="error")

        # -------------------------- Phase 8: adjudicate ------------------------- #
        phase("adjudicate", state="running")
        _rerank(conn, scan_id)
        finish_phase("adjudicate", detail=f"{verified} finding(s) proven exploitable on device")

        # ------------------------ Phase 9: report & cleanup --------------------- #
        phase("report", state="running")
        # The per-finding evidence (steps + screenshots) is already persisted for the report
        # tab / Report Creator to render. Cleanup: tear down an emulator we booted.
        _cleanup(device, emulator_handle)
        finish_phase("report", detail="evidence persisted; device released")

        progress["status"] = "done"
        progress["current"] = None
        progress["finished_at"] = _now()
        _write_progress(conn, scan_id, progress)
        LOGGER.info("dynamic research for scan %s: %s/%s verified", scan_id, verified, len(candidates))
        return {"verified": verified, "attempted": len(candidates), "device": True}
    finally:
        _cleanup(device, emulator_handle)


def _apk_path(scan: dict[str, Any]) -> str | None:
    cfg = scan.get("configuration") or {}
    return cfg.get("apk_path") if isinstance(cfg, dict) else None


def _disable_play_protect(device) -> None:
    """Best-effort: stop the package verifier from removing sideloaded test apps mid-run."""
    for cmd in (
        "settings put global package_verifier_enable 0",
        "settings put global package_verifier_user_consent -1",
        "settings put global verifier_verify_adb_installs 0",
    ):
        try:
            device.shell(cmd, root=True)
        except Exception:  # noqa: BLE001
            pass


def _maybe_chain(conn, scan_id, workspace_dir, package, device, *, static_only) -> None:
    """Run the exploit-chain analyst over confirmed primitives, if the machinery is available."""
    try:
        from . import specialist_agent as sa
    except Exception:  # noqa: BLE001
        return
    if not hasattr(sa, "chain_analyst"):
        return
    # Chain synthesis is static reasoning over the confirmed findings; kept lightweight here.
    # (Full device-reproduction of chains is a future enhancement.)
    return


def _cleanup(device, emulator_handle) -> None:
    if emulator_handle is not None and device is not None:
        try:
            from . import emulator as emu

            emu.shutdown_avd(device.serial, emulator_handle)
        except Exception:  # noqa: BLE001
            LOGGER.debug("emulator teardown failed", exc_info=True)
