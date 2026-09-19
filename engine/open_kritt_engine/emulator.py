"""Android emulator (AVD) lifecycle for autonomous on-device verification.

The rest of the engine assumes a device is already connected (adb.get_device). This module
is the missing piece: it boots one of the user's Android Studio AVDs on demand, waits for it
to come fully up, hands back an adb.Device, and guarantees teardown afterwards — so a scan can
verify its findings on a clean, disposable emulator without a human plugging anything in.

GPU note: llama.cpp owns the discrete GPU. By default the emulator renders with a software
GPU (swiftshader) so verification never contends with the model; override with
ENGINE_EMULATOR_GPU=host only when the model is idle.
"""

from __future__ import annotations

import os
import re
import subprocess
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from . import adb
from .adb import AdbError, Device

LOGGER = __import__("logging").getLogger("open_kritt_engine.emulator")


class EmulatorError(RuntimeError):
    pass


def emulator_bin() -> str:
    explicit = os.getenv("ENGINE_EMULATOR_BIN")
    if explicit:
        return explicit
    sdk = os.getenv("ANDROID_SDK_ROOT") or os.getenv("ANDROID_HOME") or os.path.expanduser(
        "~/AppData/Local/Android/Sdk"
    )
    cand = Path(sdk) / "emulator" / ("emulator.exe" if os.name == "nt" else "emulator")
    return str(cand) if cand.exists() else "emulator"


def list_avds() -> list[str]:
    try:
        out = subprocess.run([emulator_bin(), "-list-avds"], capture_output=True, text=True, timeout=30, check=False)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        raise EmulatorError(f"could not list AVDs via {emulator_bin()!r}: {exc}") from exc
    return [line.strip() for line in (out.stdout or "").splitlines() if line.strip()]


def pick_avd(preferred: str | None = None, *, prefer_rooted: bool = True) -> str:
    """Choose an AVD: an explicit request, else a rooted image (needed for Frida bypasses),
    else the first available."""

    avds = list_avds()
    if not avds:
        raise EmulatorError("no AVDs are defined in Android Studio")
    want = preferred or os.getenv("ENGINE_EMULATOR_AVD")
    if want:
        if want in avds:
            return want
        # tolerate the '-'/'_' spelling drift Android Studio introduces
        norm = want.replace(" ", "_")
        for a in avds:
            if a == norm or a.replace(" ", "_") == norm:
                return a
        raise EmulatorError(f"requested AVD {want!r} not found; have: {avds}")
    if prefer_rooted:
        # Google reference images (e.g. Pixel_*, google_apis, non-PlayStore) grant root via a
        # plain `adb root`, which is what the Frida bypasses need. The manually-created
        # '*rooted*' AVD folders here are unregistered/broken, so match the reliable images.
        for hint in ("pixel", "google_apis", "aosp"):
            for a in avds:
                if hint in a.lower():
                    return a
    return avds[0]


def _free_serial() -> str:
    """An emulator console serial not already in use (even ports 5554-5584)."""
    taken = {d["serial"] for d in adb.list_devices()}
    for port in range(5554, 5586, 2):
        serial = f"emulator-{port}"
        if serial not in taken:
            return serial
    raise EmulatorError("no free emulator console port in 5554-5584")


def _boot_completed(serial: str) -> bool:
    try:
        out = adb._run(["-s", serial, "shell", "getprop", "sys.boot_completed"], timeout=10).stdout or ""
        anim = adb._run(["-s", serial, "shell", "getprop", "init.svc.bootanim"], timeout=10).stdout or ""
    except AdbError:
        return False
    return out.strip() == "1" and anim.strip() in ("stopped", "")


def boot_avd(
    name: str | None = None,
    *,
    headless: bool | None = None,
    cold: bool = True,
    boot_timeout: int = 300,
) -> tuple[Device, "subprocess.Popen"]:
    """Boot an AVD and return (Device, process) once it is fully up and rooted.

    The caller owns the returned process only for teardown; prefer booted_emulator()."""

    avd = pick_avd(name)
    serial = _free_serial()
    port = int(serial.split("-", 1)[1])
    if headless is None:
        headless = os.getenv("ENGINE_EMULATOR_HEADLESS", "1").strip().lower() in {"1", "true", "yes", "on"}
    gpu = os.getenv("ENGINE_EMULATOR_GPU", "swiftshader_indirect")

    args = [
        emulator_bin(), "-avd", avd, "-port", str(port),
        "-gpu", gpu, "-no-boot-anim", "-no-audio",
        "-wipe-data" if cold else "-no-snapshot-save",
    ]
    if cold:
        args.append("-no-snapshot-load")
    if headless:
        args.append("-no-window")

    LOGGER.info("booting AVD %s as %s (headless=%s, gpu=%s)", avd, serial, headless, gpu)
    proc = subprocess.Popen(
        args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )

    deadline = time.time() + boot_timeout
    # First wait for adb to see the serial at all, then for Android to finish booting.
    while time.time() < deadline:
        if proc.poll() is not None:
            raise EmulatorError(f"emulator process for {avd} exited early (code {proc.returncode})")
        if any(d["serial"] == serial and d["state"] == "device" for d in adb.list_devices()):
            break
        time.sleep(2)
    else:
        _kill(proc, serial)
        raise EmulatorError(f"emulator {avd} did not register on adb within {boot_timeout}s")

    while time.time() < deadline:
        if _boot_completed(serial):
            break
        time.sleep(3)
    else:
        _kill(proc, serial)
        raise EmulatorError(f"emulator {avd} did not finish booting within {boot_timeout}s")

    device = Device(serial)
    device.ensure_root()
    try:
        device.shell("settings put global window_animation_scale 0")
        device.shell("settings put global transition_animation_scale 0")
        device.shell("settings put global animator_duration_scale 0")
        device.set_stay_awake(True)
    except Exception:  # noqa: BLE001 - cosmetic setup, never fatal
        LOGGER.debug("post-boot tuning failed", exc_info=True)
    LOGGER.info("AVD %s ready on %s (root=%s)", avd, serial, device.is_adb_root())
    return device, proc


def _kill(proc: "subprocess.Popen | None", serial: str | None) -> None:
    if serial:
        try:
            adb._run(["-s", serial, "emu", "kill"], timeout=15)
        except Exception:  # noqa: BLE001
            pass
    if proc and proc.poll() is None:
        try:
            proc.terminate()
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                proc.kill()
        except Exception:  # noqa: BLE001
            pass


def shutdown_avd(serial: str | None, proc: "subprocess.Popen | None" = None) -> None:
    _kill(proc, serial)


@contextmanager
def booted_emulator(name: str | None = None, **kw) -> Iterator[Device]:
    """Boot an AVD for the duration of the block and guarantee teardown."""
    device, proc = boot_avd(name, **kw)
    try:
        yield device
    finally:
        shutdown_avd(device.serial, proc)
