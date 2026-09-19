"""Local model (llama.cpp) control plane, owned by the native engine worker.

The backend (in Docker) cannot manage the native llama-server process, so the engine
does: it reads the desired config from a shared DB row, keeps llama-server running,
restarts it on request from the UI, and writes live status back for the UI's status icon.

Single source of truth: public.local_model_config (a singleton row).
  config  : base_url, model_name, reasoning_effort, llama_dir/model_file/mmproj_file, autostart
  control : restart_token (UI bumps it to request a restart)
  status  : status / status_detail / status_at (engine writes these)

The engine also mirrors base_url / model / reasoning_effort into os.environ so the
existing LocalLLMClient (which reads those envs) picks up UI changes with no refactor.
"""

from __future__ import annotations

import os
import subprocess
import time
import urllib.request
from pathlib import Path
from typing import Any

import logging

LOGGER = logging.getLogger("open_kritt_engine")

# Defaults mirror scripts/start-llm.ps1 so the engine launches the known-good command.
_DEFAULT_LLAMA_DIR = os.getenv("ENGINE_LLAMA_DIR", r"C:\Users\Maor2\OneDrive\Desktop\TOOLS\llama-b9305-bin-win-cuda-13.1-x64")
_DEFAULT_MODEL_FILE = os.getenv("ENGINE_LLAMA_MODEL_FILE", "gemma-4-26B-A4B-it-UD-IQ4_NL.gguf")
_DEFAULT_MMPROJ_FILE = os.getenv("ENGINE_LLAMA_MMPROJ", "mmproj-F16.gguf")
_DEFAULT_PORT = int(os.getenv("ENGINE_LLAMA_PORT", "8005"))
_DEFAULT_BASE_URL = os.getenv("ENGINE_LLM_BASE_URL", f"http://127.0.0.1:{_DEFAULT_PORT}/v1")
_DEFAULT_MODEL_NAME = os.getenv("ENGINE_LOCAL_MODEL", "local")
_DEFAULT_REASONING = os.getenv("ENGINE_LOCAL_REASONING_EFFORT", "medium")

REASONING_EFFORTS = ("low", "medium", "high")

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS public.local_model_config (
    id             integer PRIMARY KEY DEFAULT 1,
    base_url       text NOT NULL DEFAULT 'http://127.0.0.1:8005/v1',
    model_name     text NOT NULL DEFAULT 'local',
    reasoning_effort text NOT NULL DEFAULT 'medium',
    llama_dir      text,
    model_file     text,
    mmproj_file    text,
    autostart      boolean NOT NULL DEFAULT true,
    restart_token  bigint NOT NULL DEFAULT 0,
    status         text NOT NULL DEFAULT 'unknown',
    status_detail  text,
    status_at      timestamptz,
    updated_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT local_model_config_singleton CHECK (id = 1)
)
"""


def ensure_table(conn) -> None:
    conn.execute(_CREATE_TABLE)
    # desired_running: user Stop/Start intent. When false the engine keeps llama stopped
    # (and does not auto-start it) until the UI asks to start again.
    conn.execute("ALTER TABLE public.local_model_config ADD COLUMN IF NOT EXISTS desired_running boolean NOT NULL DEFAULT true")
    conn.execute(
        """
        INSERT INTO public.local_model_config (id, base_url, model_name, reasoning_effort, llama_dir, model_file, mmproj_file)
        VALUES (1, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (id) DO NOTHING
        """,
        (_DEFAULT_BASE_URL, _DEFAULT_MODEL_NAME, _DEFAULT_REASONING, _DEFAULT_LLAMA_DIR, _DEFAULT_MODEL_FILE, _DEFAULT_MMPROJ_FILE),
    )
    conn.commit()


def load_config(conn) -> dict[str, Any]:
    row = conn.execute(
        """
        SELECT base_url, model_name, reasoning_effort, llama_dir, model_file, mmproj_file,
               autostart, restart_token, status, status_detail, status_at, desired_running
        FROM public.local_model_config WHERE id = 1
        """
    ).fetchone()
    if not row:
        return {}
    keys = ["base_url", "model_name", "reasoning_effort", "llama_dir", "model_file", "mmproj_file",
            "autostart", "restart_token", "status", "status_detail", "status_at", "desired_running"]
    return row if isinstance(row, dict) else dict(zip(keys, row))


def _write_status(conn, status: str, detail: str | None = None) -> None:
    conn.execute(
        "UPDATE public.local_model_config SET status=%s, status_detail=%s, status_at=now() WHERE id=1",
        (status, detail),
    )
    conn.commit()


def _apply_env(cfg: dict[str, Any]) -> None:
    """Mirror UI config into the process env so LocalLLMClient picks it up live."""

    if cfg.get("base_url"):
        os.environ["ENGINE_LLM_BASE_URL"] = str(cfg["base_url"])
    if cfg.get("model_name"):
        os.environ["ENGINE_LOCAL_MODEL"] = str(cfg["model_name"])
    effort = str(cfg.get("reasoning_effort") or _DEFAULT_REASONING).lower()
    os.environ["ENGINE_LOCAL_REASONING_EFFORT"] = effort if effort in REASONING_EFFORTS else "medium"


def _health(base_url: str, timeout: float = 3.0) -> bool:
    url = base_url.rstrip("/").removesuffix("/v1") + "/health"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310 - localhost only
            return resp.status == 200
    except Exception:  # noqa: BLE001
        return False


def _llama_command(cfg: dict[str, Any]) -> list[str] | None:
    llama_dir = Path(cfg.get("llama_dir") or _DEFAULT_LLAMA_DIR)
    exe = llama_dir / "llama-server.exe"
    model = llama_dir / (cfg.get("model_file") or _DEFAULT_MODEL_FILE)
    mmproj = llama_dir / (cfg.get("mmproj_file") or _DEFAULT_MMPROJ_FILE)
    if not exe.is_file() or not model.is_file():
        return None
    base_url = str(cfg.get("base_url") or _DEFAULT_BASE_URL)
    port = base_url.rstrip("/").removesuffix("/v1").rsplit(":", 1)[-1]
    port = port if port.isdigit() else str(_DEFAULT_PORT)
    cmd = [str(exe), "-m", str(model)]
    if mmproj.is_file():
        cmd += ["--mmproj", str(mmproj)]
    cmd += [
        "--host", "0.0.0.0", "--port", port, "--ctx-size", "61440", "--n-gpu-layers", "-1",
        "--alias", str(cfg.get("model_name") or _DEFAULT_MODEL_NAME), "--no-mmap", "--flash-attn", "on",
        "--reasoning", "on", "--parallel", "1", "--cache-type-v", "q8_0", "--cache-type-k", "q8_0",
    ]
    return cmd


class LlamaManager:
    """Owns the native llama-server process for the engine host."""

    def __init__(self) -> None:
        self._proc: subprocess.Popen | None = None

    def _kill_all(self) -> None:
        if self._proc and self._proc.poll() is None:
            try:
                self._proc.terminate()
            except Exception:  # noqa: BLE001
                pass
        self._proc = None
        # Also sweep any stray llama-server.exe so a restart never leaves two on the GPU.
        if os.name == "nt":
            subprocess.run(["taskkill", "/IM", "llama-server.exe", "/F", "/T"],
                           capture_output=True, check=False)

    def start(self, cfg: dict[str, Any]) -> str:
        cmd = _llama_command(cfg)
        if not cmd:
            return "llama-server.exe or model file not found; check the paths"
        creationflags = 0x00000008 if os.name == "nt" else 0  # DETACHED_PROCESS
        self._proc = subprocess.Popen(  # noqa: S603
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=creationflags
        )
        return ""

    def restart(self, cfg: dict[str, Any]) -> str:
        self._kill_all()
        time.sleep(2)
        return self.start(cfg)


_manager = LlamaManager()
_last_restart_token: int | None = None


def tick(conn, *, manage_process: bool = True) -> None:
    """One control-plane cycle: ensure the table, apply config env, honor restart requests,
    (optionally) keep llama-server running, and publish status. Best-effort; never raises."""

    global _last_restart_token
    try:
        ensure_table(conn)
        cfg = load_config(conn)
        if not cfg:
            return
        _apply_env(cfg)

        base_url = str(cfg.get("base_url") or _DEFAULT_BASE_URL)
        token = int(cfg.get("restart_token") or 0)
        desired_running = cfg.get("desired_running", True)

        # PROCESS CONTROL IS EXPLICIT-ONLY. The engine NEVER autonomously starts, restarts,
        # or stops llama-server — it acts solely when the user presses a Start/Restart/Stop
        # button (each bumps restart_token). There is no auto-start-when-down behavior. The
        # model is otherwise controlled by the user's scripts (start-llm.ps1 / restart.ps1).
        if manage_process:
            if _last_restart_token is None:
                # Engine just booted: adopt the current token WITHOUT acting, so an already
                # handled request is never replayed and nothing is auto-(re)started.
                _last_restart_token = token
            elif token > _last_restart_token:
                _last_restart_token = token
                if desired_running:
                    LOGGER.info("local model: explicit start/restart requested (token=%s)", token)
                    _write_status(conn, "starting", "starting on request")
                    err = _manager.restart(cfg)
                    if err:
                        _write_status(conn, "error", err)
                else:
                    LOGGER.info("local model: explicit stop requested (token=%s)", token)
                    _manager._kill_all()
                    _write_status(conn, "stopped", "stopped by user")
                    return
            # No new explicit request -> do NOTHING to the process (status-only below).

        # Publish current health (a fresh check so a just-started server flips to running).
        if _health(base_url):
            _write_status(conn, "running", None)
        elif not manage_process:
            _write_status(conn, "stopped", "not reachable")
    except Exception:  # noqa: BLE001
        LOGGER.exception("local model control-plane tick failed")
