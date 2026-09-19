"""Real-time H.264 device mirror (scrcpy-style) for the Device tab.

Streams the device's HARDWARE H.264 encoder output to the browser so the mirror is smooth
(20-30 fps) instead of the ~1 fps screenshot fallback. Mechanism:

  adb exec-out screenrecord --output-format=h264   (device MediaCodec H.264 encoder)
      -> engine reads the raw Annex-B stream from stdout
      -> forwards the bytes over a local WebSocket
      -> the browser decodes them with WebCodecs and paints a <canvas>.

Only the browser that opens the stream triggers screenrecord; nothing runs otherwise.

`screenrecord` caps a single capture at ~180s, so the stream is transparently restarted when
it ends (a fresh SPS/PPS + IDR re-syncs the decoder; a ~0.2s blip at the 3-min mark).
"""

from __future__ import annotations

import asyncio
import logging
import os
from urllib.parse import parse_qs, urlparse

LOGGER = logging.getLogger("open_kritt_engine")


def _enabled() -> bool:
    return os.getenv("ENGINE_DEVICE_STREAM", "1").strip().lower() in {"1", "true", "yes", "on"}


def _screenrecord_cmd(serial: str) -> list[str]:
    from .adb import adb_bin

    size = os.getenv("ENGINE_STREAM_SIZE", "720x1600")
    bitrate = os.getenv("ENGINE_STREAM_BITRATE", "6000000")
    return [
        adb_bin(), "-s", serial, "exec-out", "screenrecord",
        "--output-format=h264", f"--size={size}", f"--bit-rate={bitrate}",
        "--time-limit=180", "-",
    ]


def _active_serial_from_db() -> str | None:
    try:
        import psycopg

        url = os.getenv("DATABASE_URL")
        if not url:
            return None
        with psycopg.connect(url, connect_timeout=3) as conn:
            row = conn.execute("select active_serial from public.device_state where id=1").fetchone()
            return (row[0] if row else None) or None
    except Exception:  # noqa: BLE001
        return None


# Active viewers per serial. Killing the host adb client does NOT reliably stop the
# device-side screenrecord (it survives to its ~180s limit), so we explicitly kill it when
# the last viewer of a device disconnects. The WS server is single-threaded (one asyncio
# loop), so a plain dict is safe.
_active_viewers: dict[str, int] = {}


async def _kill_device_screenrecord(serial: str) -> None:
    from .adb import adb_bin

    try:
        p = await asyncio.create_subprocess_exec(
            adb_bin(), "-s", serial, "shell",
            "pkill screenrecord 2>/dev/null; killall screenrecord 2>/dev/null; true",
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
        )
        await asyncio.wait_for(p.wait(), timeout=5)
    except Exception:  # noqa: BLE001
        pass


def _client_serial(ws) -> str | None:
    path = ""
    req = getattr(ws, "request", None)
    if req is not None and getattr(req, "path", None):
        path = req.path
    else:
        path = getattr(ws, "path", "") or ""
    serial = (parse_qs(urlparse(path).query).get("serial") or [None])[0]
    return serial or _active_serial_from_db()


async def _handler(ws) -> None:
    import websockets

    serial = _client_serial(ws)
    if not serial:
        await ws.close(code=1011, reason="no device serial")
        return
    LOGGER.info("device H.264 stream: client connected (serial=%s)", serial)
    # First viewer of this device? Clear any stale screenrecord left by a prior crash.
    if _active_viewers.get(serial, 0) == 0:
        await _kill_device_screenrecord(serial)
    _active_viewers[serial] = _active_viewers.get(serial, 0) + 1
    proc = None
    try:
        # Restart screenrecord whenever it hits its ~180s cap; a client disconnect raises
        # ConnectionClosed from ws.send and breaks out entirely.
        while True:
            proc = await asyncio.create_subprocess_exec(
                *_screenrecord_cmd(serial),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                while True:
                    chunk = await proc.stdout.read(32768)
                    if not chunk:
                        break  # screenrecord ended (time limit) — restart below
                    await ws.send(chunk)
            finally:
                if proc.returncode is None:
                    try:
                        proc.kill()
                    except Exception:  # noqa: BLE001
                        pass
                await proc.wait()
    except websockets.exceptions.ConnectionClosed:
        pass
    except Exception:  # noqa: BLE001
        LOGGER.debug("device H.264 stream error", exc_info=True)
    finally:
        if proc is not None and proc.returncode is None:
            try:
                proc.kill()
            except Exception:  # noqa: BLE001
                pass
        # When the last viewer of this device leaves, stop the device-side screenrecord too.
        _active_viewers[serial] = max(0, _active_viewers.get(serial, 1) - 1)
        if _active_viewers.get(serial, 0) == 0:
            await _kill_device_screenrecord(serial)
        LOGGER.info("device H.264 stream: client disconnected")


async def _serve(host: str, port: int) -> None:
    import websockets

    async with websockets.serve(
        _handler, host, port, max_size=None, ping_interval=20, ping_timeout=20, compression=None
    ):
        LOGGER.info("device H.264 stream server listening on ws://%s:%s", host, port)
        await asyncio.Future()  # run forever


def run_server() -> None:
    """Blocking entry point — run in a dedicated daemon thread."""
    if not _enabled():
        LOGGER.info("device H.264 stream disabled (ENGINE_DEVICE_STREAM)")
        return
    host = os.getenv("ENGINE_DEVICE_STREAM_HOST", "127.0.0.1")
    port = int(os.getenv("ENGINE_DEVICE_STREAM_PORT", "9010"))
    try:
        asyncio.run(_serve(host, port))
    except Exception:  # noqa: BLE001
        LOGGER.exception("device H.264 stream server crashed")
