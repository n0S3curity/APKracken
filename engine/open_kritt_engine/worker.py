import logging
import math
import os
import random
import shutil
import threading
import time
import unicodedata
from datetime import timedelta
from typing import Any

from .artifact_cleanup import (
    ArtifactCleanupResult,
    cleanup_legacy_checkout_cache,
    cleanup_legacy_scan_workspaces,
    cleanup_orphaned_job_workspaces,
    cleanup_persisted_scan_caches,
)
from .claude_auth import ClaudeCredentialRateLimited
from .codex_updater import CodexCliGate, CodexUpdater
from .config import EngineConfig
from .db import Database, now_utc
from .generation import GenerationRunner, GenerationValidationError
from .harnesses import (
    RETRYABLE_RATE_LIMIT_FAILURES,
    HarnessError,
    cleanup_stale_scan_sandboxes,
    harness_for,
    normalize_harness_name,
    scan_model_provider,
    validate_scan_runner_configuration,
)
from .model_catalog import ModelCatalogRefresher
from .model_output_artifacts import record_model_error_output
from .post_processing import PostProcessor, PostProcessRateLimited
from .prompting import harness_prompt, native_agent_skills_prompt, render_prompt, repeat_append_prompt
from .provider_credentials import provider_environment
from .queue import build_pending_jobs
from .runtime_config import runtime_bool, runtime_config_path, runtime_int, runtime_value
from .schema import OutputValidationError, output_schema, validate_payload
from .workspace import (
    cleanup_job_workspace,
    cleanup_workspace,
    mark_provider_account_available,
    mark_provider_account_rate_limited,
    prepare_dependency_workspace,
    prewarm_scan_checkout_cache,
    provider_accounts_all_rate_limited,
    resolve_scan_checkout_revisions,
    restore_persistent_scan_checkout_cache,
    save_persistent_scan_checkout_cache,
    scan_checkout_cache_key,
    workspace_context,
    workspace_prompt_context,
)

LOGGER = logging.getLogger("open_kritt_engine")
NON_RUNNABLE_SCAN_STATUSES = {"queued", "pending", "rate_limited", "paused", "stopped", "failed", "completed"}
PREWARMING_SCAN_STATUS = "prewarming_cache"
ORPHANED_METADATA_ERROR = "interrupted by engine restart"
GENERATION_HEARTBEAT_INTERVAL_SECONDS = 15.0
GENERATION_STALE_AFTER_SECONDS = 60
GENERATION_RECOVERY_INTERVAL_SECONDS = 15.0
GENERATION_VALIDATION_ERROR_LIMIT = 25
GENERATION_VALIDATION_FIELD_LIMIT = 200
GENERATION_VALIDATION_MESSAGE_LIMIT = 1000
GENERATION_PERSISTENCE_ERROR = "Generated draft could not be saved. Please try again."
RATE_LIMIT_BACKOFF_BASE_SECONDS = 5.0
RATE_LIMIT_BACKOFF_MAX_SECONDS = 60.0
RATE_LIMIT_RETRY_AFTER_MAX_SECONDS = 300.0
RATE_LIMIT_RESUME_DELAY_SECONDS = 60.0
ARTIFACT_CLEANUP_INTERVAL_SECONDS = 5 * 60.0
ARTIFACT_CLEANUP_GRACE_SECONDS = 5 * 60.0


class StepExecutionError(RuntimeError):
    pass


class RateLimitExhausted(StepExecutionError):
    def __init__(
        self,
        message: str,
        *,
        retry_after_seconds: float,
        provider: str | None = None,
        account_home: str | None = None,
        limit_kind: str = "rate_limited",
    ):
        super().__init__(message)
        self.retry_after_seconds = retry_after_seconds
        self.provider = provider
        self.account_home = account_home
        self.limit_kind = limit_kind


def _rate_limit_retry_delay(error: HarnessError, attempt: int) -> float:
    if error.retry_after_seconds is not None:
        return min(max(0.0, error.retry_after_seconds), RATE_LIMIT_RETRY_AFTER_MAX_SECONDS)
    base = min(RATE_LIMIT_BACKOFF_BASE_SECONDS * (2 ** max(0, attempt - 1)), RATE_LIMIT_BACKOFF_MAX_SECONDS)
    return base * random.uniform(0.8, 1.2)


def _sanitize_generation_error_text(value: Any, limit: int) -> str:
    text = value if isinstance(value, str) else str(value or "")
    text = "".join(character for character in text if not unicodedata.category(character).startswith("C"))
    return text.strip()[:limit]


def sanitize_generation_validation_errors(errors: Any) -> list[dict[str, str]]:
    sanitized: list[dict[str, str]] = []
    if not isinstance(errors, list):
        return sanitized
    for item in errors[:GENERATION_VALIDATION_ERROR_LIMIT]:
        if not isinstance(item, dict):
            continue
        field = _sanitize_generation_error_text(item.get("field"), GENERATION_VALIDATION_FIELD_LIMIT)
        message = _sanitize_generation_error_text(item.get("message"), GENERATION_VALIDATION_MESSAGE_LIMIT)
        sanitized.append(
            {
                "field": field or "draft",
                "message": message or "Generated value is invalid.",
            }
        )
    return sanitized


def generation_harness_failure_message(error: HarnessError, generation_id: int) -> str:
    public_message = _sanitize_generation_error_text(error.public_message, GENERATION_VALIDATION_MESSAGE_LIMIT)
    code = _sanitize_generation_error_text(error.code, 100) or "model_process_error"
    message = public_message or "The model process exited without returning a structured result."
    return f"{message} Diagnostic: {code} (generation {generation_id})."


class Worker:
    def __init__(self, config: EngineConfig, db: Database | None = None):
        self.config = config
        self.db = db or Database(config.database_url)
        self.post_processor = PostProcessor(config, self.db)
        setup_concurrency = max(1, int(getattr(config, "workspace_setup_concurrency", 1)))
        self.workspace_setup_slots = threading.BoundedSemaphore(setup_concurrency)
        self._prewarm_lock = threading.Lock()
        self._prewarmed_scan_cache_keys: set[tuple[int, str]] = set()
        self._prewarm_events: dict[tuple[int, str], threading.Event] = {}
        self._prewarm_errors: dict[tuple[int, str], BaseException] = {}
        self._scan_scheduler_lock = threading.Lock()
        self._scan_allocations: dict[int, int] = {}
        self._scan_last_dispatch: dict[int, int] = {}
        self._scan_dispatch_sequence = 0
        self.codex_cli_gate = CodexCliGate()
        self.generation_runner = GenerationRunner(config, codex_cli_gate=self.codex_cli_gate)
        self.model_catalog_refresher = ModelCatalogRefresher(
            self.db,
            timeout_seconds=float(getattr(config, "model_catalog_timeout_seconds", 10.0) or 10.0),
            codex_cli_gate=self.codex_cli_gate,
        )
        self._model_catalog_refresh_seconds = max(
            30.0, float(getattr(config, "model_catalog_refresh_seconds", 300.0) or 300.0)
        )
        self._next_model_catalog_refresh = 0.0
        self._model_catalog_refresh_lock = threading.Lock()
        self._codex_auto_update = bool(getattr(config, "codex_auto_update", True))
        self._codex_update_interval_seconds = max(
            60.0, float(getattr(config, "codex_update_interval_seconds", 86400.0) or 86400.0)
        )
        self._codex_update_retry_seconds = min(300.0, self._codex_update_interval_seconds)
        self._next_codex_update = 0.0
        self._codex_update_lock = threading.Lock()
        self.codex_updater = CodexUpdater(
            timeout_seconds=max(10.0, float(getattr(config, "codex_update_timeout_seconds", 120.0) or 120.0)),
            gate=self.codex_cli_gate,
        )
        self._generation_stale_after_seconds = GENERATION_STALE_AFTER_SECONDS
        self._artifact_cleanup_lock = threading.Lock()
        self._next_artifact_cleanup = 0.0

    def _local_model_control_plane(self, interval: float = 8.0) -> None:
        """Keep llama-server managed + status published for the UI (throttled)."""

        if not hasattr(self.db, "connect"):
            return
        now = time.monotonic()
        if now < getattr(self, "_next_local_model_tick", 0.0):
            return
        self._next_local_model_tick = now + interval
        try:
            from . import local_model_service

            manage = os.getenv("ENGINE_MANAGE_LOCAL_MODEL", "1").strip().lower() in {"1", "true", "yes", "on"}
            with self.db.connect() as conn:
                local_model_service.tick(conn, manage_process=manage)
        except Exception:  # noqa: BLE001
            LOGGER.exception("local model control-plane failed")

    def _device_agent_loop(self, interval: float = 1.5) -> None:
        """Background Android device agent for the UI Device tab (connection, details,
        tested-app status, installed apps, filtered logcat, screen mirror, install/keep-awake).
        Gated by ENGINE_DEVICE_AGENT (default on). Best-effort; never crashes the engine."""

        if os.getenv("ENGINE_DEVICE_AGENT", "1").strip().lower() not in {"1", "true", "yes", "on"}:
            LOGGER.info("device agent disabled (ENGINE_DEVICE_AGENT)")
            return
        from . import device_state

        LOGGER.info("device agent started")
        while True:
            try:
                with self.db.connect() as conn:
                    device_state.tick(conn, data_dir=self.config.data_dir)
            except Exception:  # noqa: BLE001
                LOGGER.debug("device agent tick failed", exc_info=True)
            time.sleep(interval)

    def run_forever(self):
        workers: dict[int, tuple[threading.Thread, threading.Event]] = {}
        generation_worker: tuple[threading.Thread, threading.Event] | None = None
        last_desired: int | None = None
        LOGGER.info("open-kritt engine started; live config: %s", runtime_config_path(self.config.data_dir))
        if _scan_sandbox_mode() != "native":
            cleanup_stale_scan_sandboxes()
        if hasattr(self.db, "connect"):
            self.recover_orphaned_metadata(now_utc())
            try:
                self.cleanup_orphaned_artifacts(minimum_age_seconds=0)
            except Exception:
                LOGGER.exception("startup artifact cleanup failed")
            self._next_artifact_cleanup = time.monotonic() + ARTIFACT_CLEANUP_INTERVAL_SECONDS
            # Seed the mobile specialist agent skills so they are visible/editable in the UI.
            try:
                from .specialist_agent import ensure_mobile_specialist_skills

                with self.db.connect() as conn:
                    installed = ensure_mobile_specialist_skills(conn)
                if installed:
                    LOGGER.info("seeded %s mobile specialist agent skill(s)", installed)
            except Exception:
                LOGGER.exception("failed to seed mobile specialist skills")
            # Seed the general OWASP Top 10 / code-bug agent skills (source-repo scans).
            try:
                from .security_skills import ensure_security_skills

                with self.db.connect() as conn:
                    installed = ensure_security_skills(conn)
                if installed:
                    LOGGER.info("seeded %s security agent skill(s)", installed)
            except Exception:
                LOGGER.exception("failed to seed security skills")
            # Seed the Samsung device / default-app agent skills.
            try:
                from .samsung_skills import ensure_samsung_skills

                with self.db.connect() as conn:
                    installed = ensure_samsung_skills(conn)
                if installed:
                    LOGGER.info("seeded %s samsung agent skill(s)", installed)
            except Exception:
                LOGGER.exception("failed to seed samsung skills")
        self._update_codex_at_startup()

        if hasattr(self.db, "connect"):
            threading.Thread(target=self._device_agent_loop, name="device-agent", daemon=True).start()
            try:
                from . import device_stream

                threading.Thread(target=device_stream.run_server, name="device-stream", daemon=True).start()
            except Exception:  # noqa: BLE001
                LOGGER.exception("failed to start device H.264 stream server")
            try:
                from . import device_files

                threading.Thread(
                    target=device_files.run_server, args=(self.config.data_dir,), name="source-files", daemon=True
                ).start()
            except Exception:  # noqa: BLE001
                LOGGER.exception("failed to start source file server")

        while True:
            self._schedule_artifact_cleanup()
            self._schedule_codex_update()
            self._schedule_model_catalog_refresh()
            self._local_model_control_plane()
            for worker_id, (thread, _stop_event) in list(workers.items()):
                if not thread.is_alive():
                    workers.pop(worker_id, None)
            if generation_worker is not None and not generation_worker[0].is_alive():
                generation_worker = None

            desired = self.runtime_worker_count()
            if desired != last_desired:
                LOGGER.info("engine desired worker count is %s", desired)
                last_desired = desired

            for worker_id in sorted(workers, reverse=True):
                if worker_id > desired:
                    thread, stop_event = workers[worker_id]
                    stop_event.set()
                    if not thread.is_alive():
                        workers.pop(worker_id, None)

            for worker_id in range(1, desired + 1):
                if worker_id in workers:
                    continue
                stop_event = threading.Event()
                thread = threading.Thread(
                    target=self._run_loop,
                    args=(worker_id, stop_event),
                    name=f"executor-worker-{worker_id}",
                    daemon=True,
                )
                workers[worker_id] = (thread, stop_event)
                thread.start()

            if desired <= 0:
                if generation_worker is not None:
                    generation_worker[1].set()
            elif generation_worker is None:
                stop_event = threading.Event()
                thread = threading.Thread(
                    target=self._generation_loop,
                    args=(stop_event,),
                    name="generation-worker",
                    daemon=True,
                )
                generation_worker = (thread, stop_event)
                thread.start()

            time.sleep(max(1.0, min(self.config.poll_seconds, 5.0)))

    def _update_codex_at_startup(self) -> None:
        if not self._codex_auto_update:
            LOGGER.info("Codex CLI auto-update is disabled")
            return
        self._run_codex_update()
        self._next_codex_update = time.monotonic() + self._codex_update_interval_seconds

    def _schedule_codex_update(self) -> None:
        if not self._codex_auto_update:
            return
        now = time.monotonic()
        if now < self._next_codex_update or not self._codex_update_lock.acquire(blocking=False):
            return
        self._next_codex_update = now + self._codex_update_interval_seconds
        threading.Thread(
            target=self._run_scheduled_codex_update,
            name="codex-updater",
            daemon=True,
        ).start()

    def _run_scheduled_codex_update(self) -> None:
        try:
            result = self._run_codex_update()
            if not result.attempted:
                self._next_codex_update = time.monotonic() + self._codex_update_retry_seconds
        finally:
            self._codex_update_lock.release()

    def _run_codex_update(self):
        result = self.codex_updater.update()
        if result.attempted:
            # Fetch against the post-update CLI instead of waiting for the normal cadence.
            self._next_model_catalog_refresh = 0.0
            self._schedule_model_catalog_refresh()
        return result

    def _schedule_model_catalog_refresh(self) -> None:
        # Let a due Codex update take precedence. Its completion resets this cadence and
        # requests a catalog refresh against the updated CLI.
        if self._codex_update_lock.locked():
            return
        now = time.monotonic()
        if now < self._next_model_catalog_refresh or not self._model_catalog_refresh_lock.acquire(blocking=False):
            return
        self._next_model_catalog_refresh = now + self._model_catalog_refresh_seconds
        threading.Thread(
            target=self._refresh_model_catalogs,
            name="model-catalog-refresher",
            daemon=True,
        ).start()

    def _refresh_model_catalogs(self) -> None:
        try:
            env = provider_environment()
            configured_codex_home = runtime_value(
                "ENGINE_CODEX_HOME",
                env.get("CODEX_HOME") or "/root/.codex",
                data_dir=getattr(self.config, "data_dir", None),
            )
            if configured_codex_home:
                env["ENGINE_CODEX_HOME"] = configured_codex_home
            self.model_catalog_refresher.refresh(env=env)
        except Exception:
            # Catalog refresh must never interrupt scan workers. The refresher
            # deliberately avoids logging upstream payloads or credentials.
            LOGGER.warning("model catalog refresh failed")
        finally:
            self._model_catalog_refresh_lock.release()

    def runtime_worker_count(self) -> int:
        return runtime_int(
            "ENGINE_WORKER_COUNT",
            2,
            data_dir=getattr(self.config, "data_dir", None),
            minimum=0,
            maximum=128,
        )

    def runtime_retry_count(self) -> int:
        return runtime_int(
            "ENGINE_RETRY_COUNT",
            2,
            data_dir=getattr(self.config, "data_dir", None),
            minimum=0,
            maximum=10,
        )

    def runtime_max_concurrent_scans(self) -> int:
        return runtime_int(
            "ENGINE_MAX_CONCURRENT_SCANS",
            1,
            data_dir=getattr(self.config, "data_dir", None),
            minimum=1,
            maximum=128,
        )

    def runtime_max_workers_per_scan(self) -> int:
        return runtime_int(
            "ENGINE_MAX_WORKERS_PER_SCAN",
            0,
            data_dir=getattr(self.config, "data_dir", None),
            minimum=0,
            maximum=128,
        )

    def runtime_autoscale_scan_workers_on_provider_capacity(self) -> bool:
        return runtime_bool(
            "ENGINE_AUTOSCALE_SCAN_WORKERS_ON_PROVIDER_CAPACITY",
            True,
            data_dir=getattr(self.config, "data_dir", None),
        )

    def runtime_harness_timeout_seconds(self) -> int:
        return runtime_int(
            "ENGINE_HARNESS_TIMEOUT_SECONDS",
            7200,
            data_dir=getattr(self.config, "data_dir", None),
            minimum=60,
            maximum=86400,
        )

    def recover_orphaned_metadata(self, engine_started_at):
        with self.db.connect() as conn:
            counts = self.db.mark_orphaned_running_metadata_interrupted(
                conn,
                engine_started_at=engine_started_at,
                error=ORPHANED_METADATA_ERROR,
            )
            conn.commit()
        repaired = sum(counts.values())
        if repaired:
            LOGGER.info("marked %s orphaned running metadata rows interrupted: %s", repaired, counts)
        return counts

    def cleanup_orphaned_artifacts(self, *, minimum_age_seconds: float) -> ArtifactCleanupResult:
        load_state = getattr(self.db, "load_artifact_cleanup_state", None)
        if not callable(load_state):
            return ArtifactCleanupResult()
        retention_days = max(0.0, float(getattr(self.config, "scan_cache_retention_days", 7.0) or 0.0))
        retain_after = now_utc() - timedelta(days=retention_days)
        with self.db.connect() as conn:
            active_workspace_ids, retained_scan_ids = load_state(
                conn,
                retain_inactive_scan_caches_after=retain_after,
            )
            result = ArtifactCleanupResult(
                job_workspaces=cleanup_orphaned_job_workspaces(
                    self.config.data_dir,
                    active_workspace_ids=active_workspace_ids,
                    minimum_age_seconds=minimum_age_seconds,
                ),
                persisted_scan_caches=cleanup_persisted_scan_caches(
                    getattr(self.config, "checkout_cache_persist_dir", None),
                    retained_scan_ids=retained_scan_ids,
                    minimum_age_seconds=minimum_age_seconds,
                ),
                legacy_scan_workspaces=cleanup_legacy_scan_workspaces(
                    self.config.data_dir,
                    minimum_age_seconds=minimum_age_seconds,
                ),
                legacy_checkout_caches=cleanup_legacy_checkout_cache(
                    self.config.data_dir,
                    getattr(self.config, "checkout_cache_dir", None),
                ),
            )
            conn.commit()
        if result.total:
            LOGGER.info(
                "removed stale engine artifacts: jobs=%s persisted_scan_caches=%s "
                "legacy_scan_workspaces=%s legacy_checkout_caches=%s",
                result.job_workspaces,
                result.persisted_scan_caches,
                result.legacy_scan_workspaces,
                result.legacy_checkout_caches,
            )
        return result

    def _schedule_artifact_cleanup(self) -> None:
        if not callable(getattr(self.db, "connect", None)) or not callable(
            getattr(self.db, "load_artifact_cleanup_state", None)
        ):
            return
        now = time.monotonic()
        if now < self._next_artifact_cleanup or not self._artifact_cleanup_lock.acquire(blocking=False):
            return
        self._next_artifact_cleanup = now + ARTIFACT_CLEANUP_INTERVAL_SECONDS
        threading.Thread(
            target=self._run_scheduled_artifact_cleanup,
            name="artifact-cleaner",
            daemon=True,
        ).start()

    def _run_scheduled_artifact_cleanup(self) -> None:
        try:
            self.cleanup_orphaned_artifacts(minimum_age_seconds=ARTIFACT_CLEANUP_GRACE_SECONDS)
        except Exception:
            LOGGER.exception("scheduled artifact cleanup failed")
        finally:
            self._artifact_cleanup_lock.release()

    def _worker_can_pick_job(self, worker_id: int) -> bool:
        return worker_id <= self.runtime_worker_count()

    def _run_loop(self, worker_id: int, stop_event: threading.Event):
        LOGGER.info("worker %s started", worker_id)
        while not stop_event.is_set():
            try:
                did_work = self.run_scan_once(worker_id=worker_id)
            except Exception:
                LOGGER.exception("worker %s loop failed", worker_id)
                did_work = False
            if not did_work:
                stop_event.wait(self.config.poll_seconds)
        LOGGER.info("worker %s stopped", worker_id)

    def _generation_loop(self, stop_event: threading.Event) -> None:
        LOGGER.info("generation worker started")
        next_recovery = 0.0
        while not stop_event.is_set():
            if self.runtime_worker_count() <= 0:
                stop_event.wait(self.config.poll_seconds)
                continue
            now = time.monotonic()
            if now >= next_recovery:
                try:
                    self._recover_stale_generations()
                except Exception:
                    LOGGER.exception("stale generation recovery failed")
                next_recovery = now + GENERATION_RECOVERY_INTERVAL_SECONDS
            try:
                did_work = self.run_generation_once()
            except Exception:
                LOGGER.exception("generation worker loop failed")
                did_work = False
            if not did_work:
                stop_event.wait(self.config.poll_seconds)
        LOGGER.info("generation worker stopped")

    def _recover_stale_generations(self) -> int:
        fail_stale = getattr(self.db, "fail_stale_generations", None)
        if not callable(fail_stale):
            return 0
        with self.db.connect() as conn:
            recovered = fail_stale(conn, stale_after_seconds=self._generation_stale_after_seconds)
            conn.commit()
        if recovered:
            LOGGER.warning("marked %s interrupted generation job(s) as failed", recovered)
        return recovered

    def run_once(self, worker_id: int = 1) -> bool:
        if not self._worker_can_pick_job(worker_id):
            return False

        if self.run_generation_once():
            return True
        return self.run_scan_once(worker_id=worker_id)

    def run_generation_once(self) -> bool:
        if self.runtime_worker_count() <= 0:
            return False
        # Generation is intentionally a separate queue. A generation produces a
        # reviewable draft only; it never creates a workflow or post-script row.
        claim_generation = getattr(self.db, "claim_generation", None)
        if callable(claim_generation):
            with self.db.connect() as conn:
                generation = claim_generation(conn)
                conn.commit()
            if generation:
                self.process_generation(generation, worker_id="generation")
                return True
        return False

    def run_scan_once(self, worker_id: int = 1) -> bool:
        if not self._worker_can_pick_job(worker_id):
            return False
        scan = self._reserve_scan()
        if not scan:
            # No queued/pending scan — service any on-demand APK requests.
            if self._run_dynamic_rerun_once():
                return True
            return self._run_fp_verify_once()

        try:
            try:
                did_work = self.process_scan(scan, worker_id=worker_id)
            except (RateLimitExhausted, PostProcessRateLimited) as exc:
                provider = getattr(exc, "provider", None)
                account_home = getattr(exc, "account_home", None)
                limit_kind = getattr(exc, "limit_kind", "rate_limited")
                if limit_kind != "provider_throttled":
                    mark_provider_account_rate_limited(provider, account_home)
                    if account_home and not provider_accounts_all_rate_limited(
                        provider, data_dir=getattr(self.config, "data_dir", None)
                    ):
                        LOGGER.warning(
                            "%s account %s is rate limited; scan %s will continue on another account",
                            provider,
                            account_home,
                            scan["id"],
                        )
                        return True
                retry_after_seconds = max(exc.retry_after_seconds, RATE_LIMIT_RESUME_DELAY_SECONDS)
                autoscale_workers = (
                    limit_kind == "provider_throttled" and self.runtime_autoscale_scan_workers_on_provider_capacity()
                )
                with self.db.connect() as conn:
                    deferred = self.db.defer_scan_after_rate_limit(
                        conn,
                        int(scan["id"]),
                        retry_after_seconds=retry_after_seconds,
                        error=str(exc),
                        limit_kind=limit_kind,
                        autoscale_workers=autoscale_workers,
                        current_worker_cap=self._scan_worker_cap_at_failure(scan),
                    )
                    conn.commit()
                if deferred:
                    if autoscale_workers:
                        LOGGER.warning(
                            "scan %s hit provider capacity; applied its scan worker cap and scheduled a retry",
                            scan["id"],
                        )
                    else:
                        LOGGER.warning("scan %s is rate limited and scheduled for automatic retry", scan["id"])
                return True
            except Exception as exc:
                LOGGER.exception("scan %s failed", scan["id"])
                with self.db.connect() as conn:
                    self.db.set_scan_status_if_active(conn, int(scan["id"]), "failed", error=str(exc))
                    conn.commit()
                return True
            if did_work:
                LOGGER.info("worker %s made progress on scan %s (%s)", worker_id, scan["id"], scan["repo_full"])
            self._maybe_dynamic_investigation(int(scan["id"]))
            self._maybe_source_verification(int(scan["id"]))
            return did_work
        finally:
            self._release_scan(int(scan["id"]))

    @staticmethod
    def _scan_analysis_mode(scan: dict) -> str | None:
        """The per-scan APK analysis mode chosen in the UI: 'static' or 'dynamic'.
        Stored in the scan's configuration jsonb. Returns None when unset (legacy scans)."""

        for key in ("configuration", "config", "extras", "extra"):
            cfg = scan.get(key)
            if isinstance(cfg, dict):
                val = cfg.get("analysis_mode")
                if isinstance(val, str) and val.strip().lower() in {"static", "dynamic"}:
                    return val.strip().lower()
        return None

    def _device_context_for(self, scan: dict, workflow: dict | None) -> dict | None:
        """Device tools for the dynamic-research workflow's on-device steps (depths 4-6).

        Returns a context (device, package, scan_id, data_dir) only when this is the dynamic
        exploit-research workflow AND a rooted device is connected; otherwise None, so those
        steps degrade to static reasoning and are honestly not reproduced."""

        if workflow is None:
            wf_name = ""
        elif isinstance(workflow, dict):
            wf_name = str(workflow.get("name") or "").strip()
        else:
            wf_name = str(getattr(workflow, "name", "") or "").strip()
        cfg = scan.get("configuration") if isinstance(scan.get("configuration"), dict) else {}
        if wf_name != "Android Dynamic Exploit Research" and not cfg.get("dynamic_research"):
            return None
        try:
            from . import adb

            device = adb.get_device()
        except Exception:  # noqa: BLE001 - no device: device steps degrade gracefully
            return None
        package = scan.get("repo_full")
        try:
            from .dynamic_investigation import _load_workspace_manifest

            manifest, _ws = _load_workspace_manifest(self.config.data_dir, scan)
            package = (manifest.get("android", {}) or {}).get("package") or package
        except Exception:  # noqa: BLE001
            pass
        return {"device": device, "package": package, "scan_id": int(scan["id"]), "data_dir": self.config.data_dir}

    def _maybe_source_verification(self, scan_id: int) -> None:
        """The accuracy pass for NON-APK scans, which have no specialist phase.

        Source-repo findings used to reach the user exactly as the model wrote them: no
        citation grounding and no false-positive adjudication, because both were gated on
        repo_kind == 'apk'. This runs the two target-agnostic halves. Best-effort; a failure
        here must never change the scan's outcome."""

        from .dynamic_investigation import run_source_verification

        with self.db.connect() as conn:
            scan = self.db.load_scan(conn, scan_id)
            conn.commit()
        if not scan or scan.get("status") != "completed":
            return
        if (scan.get("repo_kind") or "remote") == "apk":
            return  # the specialist phase already grounds and adjudicates APK findings
        reasoning = scan.get("reasoning") if isinstance(scan.get("reasoning"), dict) else {}
        if reasoning.get("source_verification"):
            return
        try:
            with self.db.connect() as conn:
                run_source_verification(
                    conn,
                    scan_id,
                    data_dir=self.config.data_dir,
                    checkout_cache_dir=getattr(self.config, "checkout_cache_dir", None) or "",
                )
        except Exception:  # noqa: BLE001 - never break the scan lifecycle
            LOGGER.exception("source verification failed for scan %s", scan_id)
        try:
            with self.db.connect() as conn:
                conn.execute(
                    "update scans set reasoning = coalesce(reasoning,'{}'::jsonb) "
                    "|| '{\"source_verification\":\"done\"}'::jsonb, updated_at = now() where id=%s",
                    (scan_id,),
                )
                conn.commit()
        except Exception:  # noqa: BLE001
            LOGGER.exception("could not mark source verification done for scan %s", scan_id)

    def _maybe_dynamic_investigation(self, scan_id: int) -> None:
        """After an APK scan completes, run the specialist + chain + deterministic
        investigation phase. The scan's own analysis_mode ('static' | 'dynamic') decides
        whether it uses a device; scans without one fall back to the
        ENGINE_DYNAMIC_INVESTIGATION env gate. Runs at most once."""

        from .dynamic_investigation import run_for_scan

        with self.db.connect() as conn:
            scan = self.db.load_scan(conn, scan_id)
            conn.commit()
        if not scan or scan.get("status") != "completed" or (scan.get("repo_kind") or "remote") != "apk":
            return
        reasoning = scan.get("reasoning") if isinstance(scan.get("reasoning"), dict) else {}
        if reasoning.get("dynamic_investigation"):
            return
        # The DAG-based "Android Deep Research" runs its own map→trace→investigate and has no
        # specialist investigation phase. Mark the phase done anyway so the scan card settles
        # to "completed" (without this it shows "investigating" forever), then return.
        wf_name = ""
        try:
            with self.db.connect() as conn:
                wf = conn.execute(
                    "select name from public.llm_workflows where id=%s", (scan.get("workflow_id"),)
                ).fetchone()
            wf_name = str((wf[0] if not isinstance(wf, dict) else wf.get("name")) or "").strip()
        except Exception:  # noqa: BLE001
            pass
        if wf_name in ("Android Deep Research", "Android Dynamic Exploit Research", "Samsung System-App Research"):
            # These are self-contained multi-depth DAGs (the dynamic-research one drives the
            # device in its own depths 4-6). There is no separate post-scan specialist phase;
            # mark it done so the card settles to "completed".
            self._mark_investigation_done(scan_id)
            return
        # The layered "Android Deep Research + Dynamic" pipeline is driven off a config flag.
        cfg = scan.get("configuration") if isinstance(scan.get("configuration"), dict) else {}
        is_deep_dynamic = bool(cfg.get("deep_dynamic"))

        # The UI-chosen mode is authoritative. Legacy scans (no mode) fall back to the
        # env gate, defaulting to 'dynamic' (try a device, degrade gracefully below).
        mode = self._scan_analysis_mode(scan)
        if mode is None:
            if os.getenv("ENGINE_DYNAMIC_INVESTIGATION", "").strip().lower() not in {"1", "true", "yes", "on"}:
                return
            mode = "dynamic"

        # 'static' runs the specialists code-only. 'dynamic' adds true device confirmation
        # (network-callback tests, live provider queries); with no device connected it
        # degrades to static-only rather than skipping — the rich findings still land.
        static_only = mode == "static"
        # Resolve the device ONCE and pass it through, so the exact reason a dynamic run
        # degraded to static-only (no device / multiple devices / adb not found) is known
        # and can be surfaced to the user instead of silently vanishing.
        device = None
        device_note = None
        if not static_only:
            try:
                from . import adb

                device = adb.get_device()
            except Exception as exc:  # noqa: BLE001
                static_only = True
                device_note = str(exc)[:300]
                LOGGER.warning(
                    "scan %s requested dynamic analysis but no usable adb device (%s); running static-only",
                    scan_id,
                    device_note,
                )
        error_text: str | None = None
        try:
            with self.db.connect() as conn:
                if is_deep_dynamic:
                    from .dynamic_investigation import run_deep_dynamic_for_scan

                    run_deep_dynamic_for_scan(
                        conn,
                        scan_id,
                        data_dir=self.config.data_dir,
                        static_only=static_only,
                        device=device,
                        verify_top_n=int(cfg.get("verify_top_n") or 6),
                    )
                else:
                    run_for_scan(conn, scan_id, data_dir=self.config.data_dir, static_only=static_only, device=device)
        except Exception as exc:  # noqa: BLE001 - never break the scan lifecycle
            error_text = str(exc)[:2000] or exc.__class__.__name__
            LOGGER.exception("dynamic investigation phase failed for scan %s", scan_id)
        finally:
            # Always mark the phase done — even on failure — so the UI stops showing the
            # scan as "researching". If dynamic was requested but no device was usable,
            # surface why (findings still landed static-only); on success clear any error.
            if error_text is None and device_note and mode == "dynamic":
                error_text = (
                    f"Dynamic testing was requested but no usable adb device was found ({device_note}). "
                    "Findings are static-only — connect one authorized device/emulator and click 'Start dynamic'."
                )
            self._mark_investigation_done(scan_id, error=error_text)

    def _mark_investigation_done(self, scan_id: int, *, error: str | None = None) -> None:
        """Set reasoning.dynamic_investigation='done' so the scan card settles from
        'investigating' to 'completed'. Records dynamic_error on failure, clears it on
        success. Best-effort; never raises."""

        try:
            with self.db.connect() as conn:
                if error:
                    conn.execute(
                        "update scans set reasoning = coalesce(reasoning,'{}'::jsonb) "
                        "|| jsonb_build_object('dynamic_investigation','done','dynamic_error', %s::text), "
                        "updated_at = now() where id=%s",
                        (error, scan_id),
                    )
                else:
                    conn.execute(
                        "update scans set reasoning = (coalesce(reasoning,'{}'::jsonb) - 'dynamic_error') "
                        "|| '{\"dynamic_investigation\":\"done\"}'::jsonb, updated_at = now() where id=%s",
                        (scan_id,),
                    )
                conn.commit()
        except Exception:  # noqa: BLE001
            LOGGER.exception("failed to mark dynamic_investigation done for scan %s", scan_id)

    def _run_dynamic_rerun_once(self) -> bool:
        """On-demand re-run of the APK dynamic investigation phase. Picks one completed APK
        scan flagged reasoning.dynamic_rerun_requested (set by the 'Start dynamic' / 'Retry'
        UI buttons), clears the prior phase markers, and re-runs the investigation. Returns
        True when it processed one. Serialized on the worker like a normal scan."""

        try:
            with self.db.connect() as conn:
                row = conn.execute(
                    """
                    WITH next AS (
                        SELECT id FROM public.scans
                        WHERE status = 'completed'
                          AND COALESCE(repo_kind, '') = 'apk'
                          AND reasoning->>'dynamic_rerun_requested' = 'true'
                        ORDER BY updated_at ASC
                        FOR UPDATE SKIP LOCKED
                        LIMIT 1
                    )
                    UPDATE public.scans s
                    SET reasoning = (coalesce(reasoning,'{}'::jsonb)
                                     - 'dynamic_rerun_requested' - 'dynamic_investigation'
                                     - 'dynamic_progress' - 'dynamic_error'),
                        updated_at = now()
                    FROM next
                    WHERE s.id = next.id
                    RETURNING s.id
                    """
                ).fetchone()
                conn.commit()
        except Exception:  # noqa: BLE001
            LOGGER.exception("failed to claim a dynamic re-run request")
            return False
        if not row:
            return False
        scan_id = int(row[0] if not isinstance(row, dict) else row["id"])
        LOGGER.info("dynamic re-run requested — verifying existing findings on-device for scan %s", scan_id)
        # Re-run ONLY the on-device verification over the EXISTING findings — never delete /
        # regenerate the findings list. Updates each finding's dynamic-investigation fields.
        error_text: str | None = None
        try:
            from .dynamic_investigation import run_dynamic_verification_only

            with self.db.connect() as conn:
                summary = run_dynamic_verification_only(conn, scan_id, data_dir=self.config.data_dir)
            if isinstance(summary, dict) and summary.get("device") is False:
                note = summary.get("device_error")
                error_text = (
                    "No usable adb device/emulator was connected for dynamic verification"
                    + (f" ({note})" if note else "")
                    + ". Connect one authorized device and click 'Start dynamic' again."
                )
        except Exception as exc:  # noqa: BLE001 - never break the worker loop
            error_text = str(exc)[:2000] or exc.__class__.__name__
            LOGGER.exception("dynamic re-run failed for scan %s", scan_id)
        finally:
            self._mark_investigation_done(scan_id, error=error_text)
        return True

    def _run_fp_verify_once(self) -> bool:
        """On-demand per-finding false-positive verification, requested from the UI (the
        finding's json_answer carries fp_verify_requested=true). Verifies one and returns
        True if it processed one."""

        try:
            with self.db.connect() as conn:
                row = conn.execute(
                    """
                    SELECT v.id AS id, v.scan_id AS scan_id
                    FROM workflows.vulnerabilities v
                    JOIN public.scans s ON s.id = v.scan_id
                    WHERE v.json_answer->>'fp_verify_requested' = 'true'
                      AND COALESCE(s.repo_kind,'') = 'apk'
                    ORDER BY v.id ASC
                    LIMIT 1
                    """
                ).fetchone()
        except Exception:  # noqa: BLE001
            return False
        if not row:
            return False
        vid = int(row["id"] if isinstance(row, dict) else row[0])
        sid = int(row["scan_id"] if isinstance(row, dict) else row[1])
        LOGGER.info("manual FP verify requested for finding %s (scan %s)", vid, sid)
        try:
            from .dynamic_investigation import run_fp_verification

            with self.db.connect() as conn:
                run_fp_verification(conn, sid, data_dir=self.config.data_dir, only_ids=[vid])
        except Exception:  # noqa: BLE001
            LOGGER.exception("manual FP verify failed for finding %s", vid)
            # Clear the request flag + mark an error so it doesn't loop forever.
            try:
                with self.db.connect() as conn:
                    conn.execute(
                        "update workflows.vulnerabilities set json_answer = "
                        "(coalesce(json_answer,'{}'::jsonb) - 'fp_verify_requested') "
                        "|| jsonb_build_object('fp_verdict','error','fp_checked_at', to_jsonb(now()::text)) "
                        "where id=%s",
                        (vid,),
                    )
                    conn.commit()
            except Exception:  # noqa: BLE001
                pass
        return True

    def _new_scan_container_allowed(self, scan_id: int) -> bool:
        required_bytes = int(getattr(self.config, "min_free_storage_bytes", 0) or 0)
        if required_bytes <= 0:
            return True

        free_bytes: int | None = None
        check_error: str | None = None
        try:
            free_bytes = int(shutil.disk_usage(self.config.data_dir).free)
        except OSError as exc:
            check_error = str(exc)

        blocked = check_error is not None or free_bytes is None or free_bytes < required_bytes
        warning_changed = False
        warning_setter = getattr(self.db, "set_scan_storage_warning", None)
        warning_clearer = getattr(self.db, "clear_scan_storage_warning", None)
        with self.db.connect() as conn:
            if blocked and callable(warning_setter):
                warning_changed = warning_setter(
                    conn,
                    scan_id,
                    free_bytes=free_bytes,
                    required_bytes=required_bytes,
                    check_error=check_error,
                )
            elif not blocked and callable(warning_clearer):
                warning_clearer(conn, scan_id)
            conn.commit()

        if blocked and warning_changed:
            if check_error:
                LOGGER.warning("scan %s container launch paused: storage check failed: %s", scan_id, check_error)
            else:
                LOGGER.warning(
                    "scan %s container launch paused: %.1f GiB free, %.1f GiB required",
                    scan_id,
                    free_bytes / 1024**3,
                    required_bytes / 1024**3,
                )
        return not blocked

    def _scheduler_state(self) -> threading.Lock:
        if not hasattr(self, "_scan_scheduler_lock"):
            self._scan_scheduler_lock = threading.Lock()
            self._scan_allocations = {}
            self._scan_last_dispatch = {}
            self._scan_dispatch_sequence = 0
        return self._scan_scheduler_lock

    def _reserve_scan(self) -> dict[str, Any] | None:
        with self._scheduler_state():
            with self.db.connect() as conn:
                claim_scans = getattr(self.db, "claim_scans", None)
                if callable(claim_scans):
                    scans = claim_scans(conn, max_concurrent_scans=self.runtime_max_concurrent_scans())
                else:
                    scan = self.db.claim_scan(conn)
                    scans = [scan] if scan else []
                conn.commit()
            if not scans:
                return None

            active_ids = {int(scan["id"]) for scan in scans}
            self._scan_allocations = {
                scan_id: count
                for scan_id, count in self._scan_allocations.items()
                if scan_id in active_ids and count > 0
            }
            self._scan_last_dispatch = {
                scan_id: sequence for scan_id, sequence in self._scan_last_dispatch.items() if scan_id in active_ids
            }

            fair_cap = max(1, math.ceil(self.runtime_worker_count() / len(scans)))
            configured_cap = self.runtime_max_workers_per_scan()
            default_scan_cap = min(fair_cap, configured_cap) if configured_cap > 0 else fair_cap

            def scan_cap(scan: dict[str, Any]) -> int:
                reasoning = scan.get("reasoning")
                adaptive_cap = reasoning.get("provider_capacity_worker_cap") if isinstance(reasoning, dict) else None
                if isinstance(adaptive_cap, int) and not isinstance(adaptive_cap, bool) and adaptive_cap > 0:
                    return min(default_scan_cap, adaptive_cap)
                return default_scan_cap

            eligible = [scan for scan in scans if self._scan_allocations.get(int(scan["id"]), 0) < scan_cap(scan)]
            if not eligible:
                return None
            selected = min(
                eligible,
                key=lambda scan: (
                    self._scan_allocations.get(int(scan["id"]), 0),
                    self._scan_last_dispatch.get(int(scan["id"]), -1),
                    scan.get("inserted_at") or "",
                    int(scan["id"]),
                ),
            )
            scan_id = int(selected["id"])
            self._scan_allocations[scan_id] = self._scan_allocations.get(scan_id, 0) + 1
            self._scan_dispatch_sequence += 1
            self._scan_last_dispatch[scan_id] = self._scan_dispatch_sequence
            selected["_reserved_worker_cap"] = scan_cap(selected)
            return selected

    def _release_scan(self, scan_id: int) -> None:
        with self._scheduler_state():
            count = self._scan_allocations.get(scan_id, 0)
            if count <= 1:
                self._scan_allocations.pop(scan_id, None)
            else:
                self._scan_allocations[scan_id] = count - 1

    def _scan_worker_cap_at_failure(self, scan: dict[str, Any]) -> int | None:
        scan_id = int(scan["id"])
        with self._scheduler_state():
            allocated = self._scan_allocations.get(scan_id, 0)
        reserved_cap = scan.get("_reserved_worker_cap")
        candidates = [
            value
            for value in (allocated, reserved_cap)
            if isinstance(value, int) and not isinstance(value, bool) and value > 0
        ]
        return min(candidates) if candidates else None

    def process_generation(self, generation: dict[str, Any], worker_id: int | str = 1) -> None:
        generation_id = int(generation["id"])
        generation_started = time.monotonic()
        LOGGER.info("worker %s generating %s draft %s", worker_id, generation.get("kind"), generation_id)
        heartbeat = self._start_generation_heartbeat(generation_id)
        try:
            try:
                result = self.generation_runner.generate(generation)
            except Exception as exc:
                validation_errors = (
                    sanitize_generation_validation_errors(exc.errors)
                    if isinstance(exc, GenerationValidationError)
                    else None
                )
                if validation_errors is not None:
                    error = "Generated draft did not pass validation."
                elif isinstance(exc, HarnessError):
                    error = generation_harness_failure_message(exc, generation_id)
                else:
                    error = "Generation failed. Try again."
                failure_code = exc.code if isinstance(exc, HarnessError) else type(exc).__name__
                retryable = exc.retryable if isinstance(exc, HarnessError) else False
                exit_code = exc.exit_code if isinstance(exc, HarnessError) else None
                attempts = exc.attempts if isinstance(exc, HarnessError) else None
                model = _sanitize_generation_error_text(generation.get("model"), 200)
                LOGGER.warning(
                    "generation %s failed failure_code=%s exception_type=%s kind=%s provider=%s "
                    "harness=%s model=%s retryable=%s attempts=%s exit_code=%s duration_seconds=%.3f",
                    generation_id,
                    failure_code,
                    type(exc).__name__,
                    generation.get("kind"),
                    generation.get("model_provider"),
                    generation.get("harness"),
                    model,
                    retryable,
                    attempts,
                    exit_code,
                    time.monotonic() - generation_started,
                )
                self._fail_generation_best_effort(
                    generation_id,
                    error=error,
                    validation_errors=validation_errors,
                )
                return

            try:
                with self.db.connect() as conn:
                    completed = self.db.complete_generation(
                        conn,
                        generation_id,
                        result=result.artifact,
                        raw_token_usage=result.usage,
                        codex_session_id=result.codex_session_id,
                    )
                    conn.commit()
            except Exception:
                LOGGER.warning("generation %s completion could not be persisted", generation_id)
                self._fail_generation_best_effort(generation_id, error=GENERATION_PERSISTENCE_ERROR)
                return
            if not completed:
                LOGGER.warning("generation %s was no longer running when completion was recorded", generation_id)
        finally:
            self._stop_generation_heartbeat(heartbeat)

    def _start_generation_heartbeat(self, generation_id: int) -> tuple[threading.Event, threading.Thread] | None:
        if not callable(getattr(self.db, "heartbeat_generation", None)):
            return None
        stop_event = threading.Event()
        thread = threading.Thread(
            target=self._generation_heartbeat_loop,
            args=(generation_id, stop_event),
            name=f"generation-heartbeat-{generation_id}",
            daemon=True,
        )
        thread.start()
        return stop_event, thread

    def _stop_generation_heartbeat(self, heartbeat: tuple[threading.Event, threading.Thread] | None) -> None:
        if heartbeat is None:
            return
        stop_event, thread = heartbeat
        stop_event.set()
        thread.join(timeout=1.0)

    def _generation_heartbeat_loop(self, generation_id: int, stop_event: threading.Event) -> None:
        while not stop_event.wait(GENERATION_HEARTBEAT_INTERVAL_SECONDS):
            try:
                with self.db.connect() as conn:
                    running = self.db.heartbeat_generation(conn, generation_id)
                    conn.commit()
            except Exception:
                LOGGER.warning("generation %s heartbeat failed", generation_id)
                continue
            if not running:
                return
            try:
                self._recover_stale_generations()
            except Exception:
                LOGGER.warning("stale generation recovery failed during heartbeat")

    def _fail_generation_best_effort(
        self,
        generation_id: int,
        *,
        error: str,
        validation_errors: list[dict[str, str]] | None = None,
    ) -> bool:
        try:
            with self.db.connect() as conn:
                failed = self.db.fail_generation(
                    conn,
                    generation_id,
                    error=error,
                    validation_errors=validation_errors,
                )
                conn.commit()
            return failed
        except Exception:
            LOGGER.warning("generation %s failure status could not be persisted", generation_id)
            return False

    def process_scan(self, scan: dict[str, Any], worker_id: int = 1) -> bool:
        scan_id = int(scan["id"])
        did_work = False
        with self.db.connect() as conn:
            workflow = self.db.load_workflow(conn, int(scan["workflow_id"]))

        while True:
            with self.db.connect() as conn:
                current = self.db.load_scan(conn, scan_id)
                if not current or current["status"] in NON_RUNNABLE_SCAN_STATUSES:
                    return did_work
                if not self._worker_can_pick_job(worker_id):
                    return did_work
                if current["status"] == PREWARMING_SCAN_STATUS:
                    conn.commit()
                    jobs = None
                    completed = claimed = set()
                elif current["status"] == "post_processing":
                    conn.commit()
                    jobs = None
                    completed = claimed = set()
                else:
                    completed = self.db.load_completed_metadata(conn, scan_id)
                    claimed = self.db.load_claimed_metadata(conn, scan_id)
                    step_results = self.db.load_step_results(conn, scan_id)
                    jobs = build_pending_jobs(
                        scan=current,
                        workflow=workflow,
                        completed=completed,
                        claimed=claimed,
                        step_results=step_results,
                    )
                    conn.commit()

            needs_new_container = current["status"] == "post_processing" or bool(jobs)
            if needs_new_container and not self._new_scan_container_allowed(scan_id):
                return did_work

            harness = harness_for(
                normalize_harness_name(current["harness"]),
                timeout_seconds=self.runtime_harness_timeout_seconds(),
                model_provider=scan_model_provider(current),
                codex_model_provider=getattr(self.config, "codex_model_provider", None),
                codex_cli_gate=self.codex_cli_gate,
                device_context=self._device_context_for(current, workflow),
            )

            if current["status"] == PREWARMING_SCAN_STATUS:
                if self._ensure_scan_cache_prewarmed(current, restore_status="running"):
                    did_work = True
                    continue

            if current["status"] != "post_processing" and jobs:
                if self._ensure_scan_cache_prewarmed(current, restore_status="running"):
                    did_work = True
                    continue

            if current["status"] == "post_processing":
                if self._ensure_scan_cache_prewarmed(current, restore_status="post_processing"):
                    did_work = True
                    continue
                if not self._worker_can_pick_job(worker_id):
                    return did_work
                did_post_work = self.post_processor.process_once(current, harness)
                if did_post_work:
                    return True
                return did_work

            if not jobs:
                if claimed != completed:
                    return did_work
                with self.db.connect() as conn:
                    transitioned = self.db.set_scan_status_if_current(conn, scan_id, "running", "post_processing")
                    conn.commit()
                if not transitioned:
                    return did_work
                LOGGER.info("scan %s workflow completed; starting post-processing", scan_id)
                did_work = True
                continue

            did_claim = False
            for job in jobs:
                if not self._worker_can_pick_job(worker_id):
                    return did_work
                did_claim = self.execute_job(
                    scan=current,
                    workflow_id=workflow.id,
                    job=job,
                    harness=harness,
                )
                if did_claim:
                    return True
            if not did_claim:
                return did_work

    def execute_job(self, *, scan, workflow_id, job, harness):
        step = job.step
        state = job.state
        metadata_id = None
        checked_out_commit = None
        prompt_filled = ""
        prepared = None
        try:
            schema = output_schema(step.output_format, step.multi_output)
            thinking_effort = scan.get("thinking_effort") or "medium"
            harness_name = normalize_harness_name(scan["harness"])
            model_provider = scan_model_provider(scan)
            with self.workspace_setup_slots:
                started = now_utc()
                with self.db.connect() as conn:
                    current_scan = self.db.load_scan(conn, int(scan["id"]))
                    if not current_scan or current_scan["status"] in NON_RUNNABLE_SCAN_STATUSES:
                        conn.commit()
                        return False
                    metadata_id = self.db.claim_step_metadata(
                        conn,
                        scan_id=int(scan["id"]),
                        workflow_id=workflow_id,
                        step_id=step.id,
                        prev_id=state.prev_id,
                        prev_table=state.prev_table,
                        repeat_run=state.repeat_run,
                        prompt_template=step.content,
                        prompt_filled="",
                        checked_out_commit=None,
                        run_started_at=started,
                        model=scan["model"],
                        harness=harness_name,
                        thinking_effort=thinking_effort,
                        model_provider=model_provider,
                    )
                    agent_skills = (
                        self.db.load_agent_skills(conn, current_scan) if hasattr(self.db, "load_agent_skills") else []
                    )
                    load_prior_results = getattr(self.db, "load_prior_repeat_results", None)
                    prior_repeat_results = (
                        load_prior_results(
                            conn,
                            scan_id=int(scan["id"]),
                            step_id=step.id,
                            prev_id=state.prev_id,
                            prev_table=state.prev_table,
                            repeat_run=state.repeat_run,
                        )
                        if state.repeat_run > 1 and callable(load_prior_results)
                        else []
                    )
                    conn.commit()

                if metadata_id is None:
                    return False

                try:
                    if (scan.get("repo_kind") or "remote") == "apk":
                        from .apk_workspace import prepare_apk_workspace

                        prepared = prepare_apk_workspace(
                            data_dir=self.config.data_dir,
                            metadata_id=metadata_id,
                            scan=scan,
                        )
                    else:
                        prepared = prepare_dependency_workspace(
                            data_dir=self.config.data_dir,
                            checkout_cache_dir=getattr(self.config, "checkout_cache_dir", None),
                            metadata_id=metadata_id,
                            scan=scan,
                            github_token=self.config.github_token,
                            agent_skills=agent_skills,
                            harness_name=harness_name,
                            model_provider=model_provider,
                        )
                    checked_out_commit = prepared.checked_out_commit
                    context = {**state.context, **workspace_context(prepared)}
                    rendered_prompt = render_prompt(step.content, context)
                    prompt_parts = [
                        native_agent_skills_prompt(agent_skills, harness_name),
                        workspace_prompt_context(prepared.layout, prepared.manifest_json),
                        rendered_prompt,
                        repeat_append_prompt(state.repeat_run, prior_repeat_results),
                    ]
                    prompt_filled = harness_prompt(
                        "\n\n".join(part for part in prompt_parts if part),
                        multi_output=step.multi_output,
                        schema=schema,
                    )
                    with self.db.connect() as conn:
                        current_scan = self.db.load_scan(conn, int(scan["id"]))
                        if not current_scan or current_scan["status"] in NON_RUNNABLE_SCAN_STATUSES:
                            status = current_scan["status"] if current_scan else "missing"
                            self.db.update_metadata(
                                conn,
                                metadata_id,
                                status="stopped",
                                error=f"scan became {status} before harness started",
                                run_time_ms=int((now_utc() - started).total_seconds() * 1000),
                                raw_token_usage=None,
                                checked_out_commit=checked_out_commit,
                                prompt_filled=prompt_filled,
                                phase="interrupted",
                                codex_source_home=getattr(prepared.workspace, "codex_source_home", None),
                                codex_account_id=getattr(prepared.workspace, "codex_account_id", None),
                                codex_account_email=getattr(prepared.workspace, "codex_account_email", None),
                            )
                            conn.commit()
                            return True
                        self.db.update_metadata(
                            conn,
                            metadata_id,
                            status="running",
                            error=None,
                            run_time_ms=0,
                            raw_token_usage=None,
                            checked_out_commit=checked_out_commit,
                            prompt_filled=prompt_filled,
                            phase="running_harness",
                            codex_source_home=getattr(prepared.workspace, "codex_source_home", None),
                            codex_account_id=getattr(prepared.workspace, "codex_account_id", None),
                            codex_account_email=getattr(prepared.workspace, "codex_account_email", None),
                        )
                        conn.commit()
                except ClaudeCredentialRateLimited as exc:
                    with self.db.connect() as conn:
                        self.db.update_metadata(
                            conn,
                            metadata_id,
                            status="interrupted",
                            error=str(exc),
                            run_time_ms=int((now_utc() - started).total_seconds() * 1000),
                            raw_token_usage=None,
                            phase="interrupted",
                        )
                        conn.commit()
                    raise RateLimitExhausted(
                        str(exc),
                        retry_after_seconds=exc.retry_after_seconds,
                        provider="claude",
                        account_home=exc.account_home,
                        limit_kind=exc.limit_kind,
                    ) from exc
                except Exception as exc:
                    with self.db.connect() as conn:
                        self.db.update_metadata(
                            conn,
                            metadata_id,
                            status="failed",
                            error=f"workspace setup failed: {exc}",
                            run_time_ms=int((now_utc() - started).total_seconds() * 1000),
                            raw_token_usage=None,
                            phase="failed",
                        )
                        conn.commit()
                    raise StepExecutionError(f"workspace setup failed for step {step.id}: {exc}") from exc

            max_attempts = self.runtime_retry_count() + 1
            last_error = None
            last_exception: Exception | None = None
            attempt_errors: list[str] = []
            last_attempt = 1
            for attempt in range(1, max_attempts + 1):
                last_attempt = attempt
                started = now_utc()
                usage = None
                codex_session_id = None
                result = None
                try:
                    if not self._new_scan_container_allowed(int(scan["id"])):
                        with self.db.connect() as conn:
                            self.db.update_metadata(
                                conn,
                                metadata_id,
                                status="interrupted",
                                error=None,
                                run_time_ms=int((now_utc() - started).total_seconds() * 1000),
                                raw_token_usage=None,
                                phase="interrupted",
                            )
                            conn.commit()
                        return True
                    result = harness.run(
                        prompt=prompt_filled,
                        schema=schema,
                        repo_dir=prepared.repo_dir,
                        model=scan["model"],
                        thinking_effort=thinking_effort,
                        env=prepared.workspace.env,
                    )
                    mark_provider_account_available(
                        getattr(prepared.workspace, "provider_account_provider", None),
                        getattr(prepared.workspace, "provider_account_home", None),
                    )
                    usage = result.usage
                    codex_session_id = result.codex_session_id
                    payload_stub = bool(result.payload.get("stub"))
                    stub_explanation = (result.payload.get("stub_explanation") or "").strip() or None
                    rows = validate_payload(result.payload, schema, step.multi_output)
                    run_time_ms = int((now_utc() - started).total_seconds() * 1000)
                    with self.db.connect() as conn:
                        self.db.update_metadata(
                            conn,
                            metadata_id,
                            status="running",
                            error=None,
                            run_time_ms=run_time_ms,
                            raw_token_usage=usage,
                            codex_session_id=codex_session_id,
                            stub=payload_stub,
                            stub_explanation=stub_explanation,
                            phase="writing_db",
                        )
                        conn.commit()
                    with self.db.connect() as conn:
                        self.db.update_metadata(
                            conn,
                            metadata_id,
                            status="completed",
                            error=None,
                            run_time_ms=run_time_ms,
                            raw_token_usage=usage,
                            codex_session_id=codex_session_id,
                            stub=payload_stub,
                            stub_explanation=stub_explanation,
                            phase="completed",
                        )
                        if step.is_last_step:
                            conn.execute(
                                "SELECT pg_advisory_xact_lock(hashtext(%s))", (f"vulnerability-rank:{int(scan['id'])}",)
                            )
                            rank = self.db.next_vulnerability_rank(conn, int(scan["id"]))
                            for offset, row in enumerate(rows):
                                self.db.insert_vulnerability(
                                    conn,
                                    scan_id=int(scan["id"]),
                                    workflow_id=workflow_id,
                                    scan_metadata_id=metadata_id,
                                    prev_id=state.prev_id,
                                    prev_table=state.prev_table,
                                    repeat_run=state.repeat_run,
                                    rank=rank + offset,
                                    json_answer=row,
                                )
                        else:
                            for row in rows:
                                self.db.insert_step_result(
                                    conn,
                                    scan_id=int(scan["id"]),
                                    workflow_id=workflow_id,
                                    step_id=step.id,
                                    depth=step.depth,
                                    prev_id=state.prev_id,
                                    prev_table=state.prev_table,
                                    repeat_run=state.repeat_run,
                                    json_answer=row,
                                )
                        conn.commit()
                    return True
                except (HarnessError, OutputValidationError, ValueError) as exc:
                    last_exception = exc
                    if isinstance(exc, HarnessError):
                        last_error = f"{exc.public_message} Diagnostic: {exc.code}."
                    else:
                        last_error = str(exc)
                    attempt_error = f"attempt {attempt}: {last_error}"
                    attempt_errors.append(attempt_error)
                    attempt_run_time_ms = int((now_utc() - started).total_seconds() * 1000)
                    with self.db.connect() as conn:
                        failed_metadata_id = self.db.insert_metadata(
                            conn,
                            scan_id=int(scan["id"]),
                            workflow_id=workflow_id,
                            step_id=step.id,
                            prev_id=state.prev_id,
                            prev_table=state.prev_table,
                            repeat_run=state.repeat_run,
                            status="failed",
                            error=attempt_error,
                            prompt_template=step.content,
                            prompt_filled=prompt_filled,
                            checked_out_commit=checked_out_commit,
                            run_started_at=started,
                            run_time_ms=attempt_run_time_ms,
                            raw_token_usage=usage,
                            codex_session_id=codex_session_id,
                            model=scan["model"],
                            harness=harness_name,
                            thinking_effort=thinking_effort,
                            model_provider=model_provider,
                            codex_source_home=getattr(prepared.workspace, "codex_source_home", None)
                            if prepared
                            else None,
                            codex_account_id=getattr(prepared.workspace, "codex_account_id", None)
                            if prepared
                            else None,
                            codex_account_email=getattr(prepared.workspace, "codex_account_email", None)
                            if prepared
                            else None,
                            phase="failed",
                        )
                        conn.commit()
                    output = getattr(exc, "output", None) or getattr(result, "output", None)
                    if output is not None:
                        artifact_dir = record_model_error_output(
                            self.config.data_dir,
                            scan_id=int(scan["id"]),
                            workflow_id=workflow_id,
                            step_id=step.id,
                            metadata_id=failed_metadata_id,
                            attempt=attempt,
                            error=exc,
                            output=output,
                            kind="step",
                        )
                        if artifact_dir:
                            with self.db.connect() as conn:
                                self.db.update_metadata(
                                    conn,
                                    failed_metadata_id,
                                    status="failed",
                                    error=f"{attempt_error}; model output: {artifact_dir}",
                                    run_time_ms=attempt_run_time_ms,
                                    raw_token_usage=usage,
                                    codex_session_id=codex_session_id,
                                    phase="failed",
                                )
                                conn.commit()
                    LOGGER.warning("step %s failed attempt %s: %s", step.id, attempt, last_error)
                    if isinstance(exc, HarnessError) and not exc.retryable:
                        break
                    if isinstance(exc, HarnessError) and exc.code in RETRYABLE_RATE_LIMIT_FAILURES:
                        if exc.code != "provider_throttled":
                            mark_provider_account_rate_limited(
                                getattr(prepared.workspace, "provider_account_provider", None),
                                getattr(prepared.workspace, "provider_account_home", None),
                            )
                        break

            run_time_ms = int((now_utc() - started).total_seconds() * 1000)
            exhausted_rate_limit = (
                isinstance(last_exception, HarnessError) and last_exception.code in RETRYABLE_RATE_LIMIT_FAILURES
            )
            failure_summary = (
                f"failed after {len(attempt_errors)} attempt{'s' if len(attempt_errors) != 1 else ''}: "
                + " | ".join(attempt_errors)
            )
            with self.db.connect() as conn:
                self.db.update_metadata(
                    conn,
                    metadata_id,
                    status="interrupted" if exhausted_rate_limit else "failed",
                    error=f"step {failure_summary}",
                    run_time_ms=run_time_ms,
                    raw_token_usage=None,
                    phase="interrupted" if exhausted_rate_limit else "failed",
                )
                conn.commit()
            if exhausted_rate_limit:
                raise RateLimitExhausted(
                    f"step {step.id} was rate limited: {' | '.join(attempt_errors)}",
                    retry_after_seconds=_rate_limit_retry_delay(last_exception, last_attempt),
                    provider=getattr(prepared.workspace, "provider_account_provider", None),
                    account_home=getattr(prepared.workspace, "provider_account_home", None),
                    limit_kind=last_exception.code,
                )
            raise StepExecutionError(f"step {step.id} {failure_summary}")
        finally:
            if metadata_id is not None:
                if prepared is not None:
                    cleanup_workspace(prepared.workspace)
                else:
                    cleanup_job_workspace(self.config.data_dir, metadata_id)

    def _ensure_scan_cache_prewarmed(self, scan: dict[str, Any], *, restore_status: str) -> bool:
        # APK scans decompile into a sha256-keyed cache inside prepare_apk_workspace;
        # there is no git checkout to prewarm. Returning False lets processing proceed
        # straight to job execution.
        if (scan.get("repo_kind") or "remote") == "apk":
            return False
        scan_id = int(scan["id"])
        resolved_scan = resolve_scan_checkout_revisions(
            scan,
            github_token=getattr(self.config, "github_token", None),
            data_dir=self.config.data_dir,
        )
        key = (scan_id, scan_checkout_cache_key(resolved_scan))
        should_prewarm = False
        with self._prewarm_lock:
            if key in self._prewarmed_scan_cache_keys:
                if scan.get("status") == PREWARMING_SCAN_STATUS:
                    with self.db.connect() as conn:
                        self.db.set_scan_status_if_current(conn, scan_id, PREWARMING_SCAN_STATUS, restore_status)
                        conn.commit()
                    return True
                return False
            event = self._prewarm_events.get(key)
            if event is None:
                event = threading.Event()
                self._prewarm_events[key] = event
                should_prewarm = True

        if should_prewarm:
            prewarm_succeeded = False
            try:
                LOGGER.info("prewarming checkout cache for scan %s", scan_id)
                with self.db.connect() as conn:
                    current = self.db.load_scan(conn, scan_id)
                    claimed_prewarm = bool(
                        current
                        and current["status"] not in NON_RUNNABLE_SCAN_STATUSES
                        and self.db.set_scan_status_if_current(
                            conn,
                            scan_id,
                            current["status"],
                            PREWARMING_SCAN_STATUS,
                        )
                    )
                    conn.commit()
                if not claimed_prewarm:
                    return False
                restored = restore_persistent_scan_checkout_cache(
                    checkout_cache_dir=getattr(self.config, "checkout_cache_dir", None),
                    checkout_cache_persist_dir=getattr(self.config, "checkout_cache_persist_dir", None),
                    scan=resolved_scan,
                    github_token=getattr(self.config, "github_token", None),
                    data_dir=self.config.data_dir,
                )
                if restored:
                    LOGGER.info("restored %s checkout cache entries for scan %s", len(restored), scan_id)
                prewarm_scan_checkout_cache(
                    checkout_cache_dir=getattr(self.config, "checkout_cache_dir", None),
                    scan=resolved_scan,
                    github_token=getattr(self.config, "github_token", None),
                    data_dir=self.config.data_dir,
                )
                saved = save_persistent_scan_checkout_cache(
                    checkout_cache_dir=getattr(self.config, "checkout_cache_dir", None),
                    checkout_cache_persist_dir=getattr(self.config, "checkout_cache_persist_dir", None),
                    scan=resolved_scan,
                    github_token=getattr(self.config, "github_token", None),
                    data_dir=self.config.data_dir,
                )
                if saved:
                    LOGGER.info("saved %s checkout cache entries for scan %s", len(saved), scan_id)
                prewarm_succeeded = True
                LOGGER.info("checkout cache prewarmed for scan %s", scan_id)
                with self._prewarm_lock:
                    self._prewarmed_scan_cache_keys.add(key)
                    self._prewarm_errors.pop(key, None)
            except Exception as exc:
                with self._prewarm_lock:
                    self._prewarm_errors[key] = exc
                raise
            finally:
                if prewarm_succeeded:
                    with self.db.connect() as conn:
                        self.db.set_scan_status_if_current(conn, scan_id, PREWARMING_SCAN_STATUS, restore_status)
                        conn.commit()
                event.set()
                with self._prewarm_lock:
                    self._prewarm_events.pop(key, None)
            return True

        event.wait()
        with self._prewarm_lock:
            error = self._prewarm_errors.get(key)
            if error is not None:
                raise error
        return True


def _scan_sandbox_mode() -> str:
    """`docker` (isolated per-job containers) or `native` (run harnesses in-process).

    Native mode is used for the local, air-gapped Android research build running the
    engine directly on the host so it can reach ADB/USB and a local llama.cpp GPU.
    """

    return (os.getenv("ENGINE_SCAN_SANDBOX", "docker") or "docker").strip().lower()


def _watch_local_llm(base_url: str) -> None:
    """Poll the local model until it appears, then log once. Not reaching it is not an
    error: the operator may start the model after the engine. Scans simply wait."""

    from .local_harness import endpoint_reachable

    deadline = time.monotonic() + 3600.0
    while time.monotonic() < deadline:
        if endpoint_reachable(base_url):
            LOGGER.info("local llama.cpp endpoint %s is now reachable", base_url)
            return
        time.sleep(10.0)


def _log_local_llm_status() -> None:
    base_url = os.getenv("ENGINE_LLM_BASE_URL")
    if not base_url:
        return
    from .local_harness import endpoint_reachable

    if endpoint_reachable(base_url):
        LOGGER.info("local llama.cpp endpoint %s is reachable", base_url)
        return
    # Non-fatal: the engine keeps running and will use the model once it is up.
    LOGGER.info(
        "local llama.cpp endpoint %s is not up yet; start it with scripts/start-llm.ps1. "
        "The engine will use it automatically once reachable.",
        base_url,
    )
    threading.Thread(target=_watch_local_llm, args=(base_url,), name="local-llm-watcher", daemon=True).start()


def main():
    logging.basicConfig(level=logging.INFO)
    if _scan_sandbox_mode() == "native":
        LOGGER.info("engine sandbox mode: native (Docker scan-runner validation skipped)")
    else:
        try:
            validate_scan_runner_configuration()
        except HarnessError as exc:
            LOGGER.error("engine startup configuration error: %s", exc)
            raise SystemExit(2) from exc
    _log_local_llm_status()
    Worker(EngineConfig.from_env()).run_forever()
