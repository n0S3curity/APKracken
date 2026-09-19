"""ADB service for the Android dynamic-analysis build (Phase 3).

Drives a connected (rooted) Android device over adb: discovery, a global device lock
(the single research phone is a shared resource, so dynamic jobs serialize on it), and
the core operations used to exercise and observe an app at runtime — shell (optionally
as root via `su -c`), package listing, intent/deep-link launch, content-provider probing,
dumpsys, logcat capture, screenshots, and file pull.

All actions are explicit and bounded (timeouts). Root uses Magisk `su -c` since this is a
production build without `adb root`.
"""

from __future__ import annotations

import os
import shlex
import subprocess
import threading
from dataclasses import dataclass, field
from pathlib import Path

# The connected phone is one shared resource: serialize all dynamic device work.
DEVICE_LOCK = threading.Lock()


class AdbError(RuntimeError):
    pass


def adb_bin() -> str:
    return os.getenv("ENGINE_ADB_BIN") or "adb"


def _run(args: list[str], *, timeout: int = 60, binary: bool = False) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            [adb_bin(), *args],
            capture_output=True,
            text=not binary,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        raise AdbError(f"adb not found ({adb_bin()!r}); set ENGINE_ADB_BIN") from exc
    except subprocess.TimeoutExpired as exc:
        raise AdbError(f"adb timed out after {timeout}s: {' '.join(args)}") from exc


def list_devices() -> list[dict[str, str]]:
    result = _run(["devices", "-l"], timeout=15)
    devices = []
    for line in (result.stdout or "").splitlines()[1:]:
        line = line.strip()
        if not line or "\t" not in line and " " not in line:
            continue
        serial, _, rest = line.partition(" ")
        serial = serial.strip()
        if not serial:
            continue
        state = "device" if " device " in f" {rest} " or rest.strip().startswith("device") else rest.split()[0] if rest.split() else "unknown"
        info = {"serial": serial, "state": state}
        for token in rest.split():
            if ":" in token:
                key, _, value = token.partition(":")
                info[key] = value
        devices.append(info)
    return devices


def get_device(serial: str | None = None) -> "Device":
    serial = serial or os.getenv("ENGINE_ADB_SERIAL")
    devices = [d for d in list_devices() if d.get("state") == "device"]
    if not devices:
        raise AdbError("no authorized adb device connected")
    if serial:
        if not any(d["serial"] == serial for d in devices):
            raise AdbError(f"device {serial!r} not connected/authorized")
        return Device(serial)
    if len(devices) > 1:
        raise AdbError(f"multiple devices; set ENGINE_ADB_SERIAL (have: {[d['serial'] for d in devices]})")
    device = Device(devices[0]["serial"])
    if device.serial.startswith("emulator-"):
        device.ensure_root()  # emulators expose adb root; enables reading app-private data
    return device


@dataclass
class ShellResult:
    stdout: str
    stderr: str
    returncode: int | None


@dataclass
class Device:
    serial: str
    _props: dict[str, str] = field(default_factory=dict)
    _adb_root: bool | None = None

    def _args(self, args: list[str]) -> list[str]:
        return ["-s", self.serial, *args]

    def is_adb_root(self) -> bool:
        """True when adbd itself runs as root (emulators / userdebug), so shell commands
        are already root and do not need `su` wrapping."""
        if self._adb_root is None:
            out = _run(self._args(["shell", "id"]), timeout=15).stdout or ""
            self._adb_root = out.startswith("uid=0")
        return self._adb_root

    def ensure_root(self) -> bool:
        """Best-effort `adb root` (works on emulators / userdebug builds)."""
        if self.is_adb_root():
            return True
        _run(self._args(["root"]), timeout=20)
        import time as _time

        _time.sleep(2)
        self._adb_root = None
        return self.is_adb_root()

    def shell(self, command: str, *, root: bool = False, timeout: int = 60) -> ShellResult:
        # If adbd is already root (emulator), run directly; otherwise escalate with su.
        device_cmd = command if (not root or self.is_adb_root()) else f"su -c {shlex.quote(command)}"
        result = _run(self._args(["shell", device_cmd]), timeout=timeout)
        return ShellResult(stdout=(result.stdout or "").strip(), stderr=(result.stderr or "").strip(), returncode=result.returncode)

    def getprop(self, name: str) -> str:
        if name not in self._props:
            self._props[name] = self.shell(f"getprop {shlex.quote(name)}").stdout
        return self._props[name]

    def summary(self) -> dict[str, str]:
        return {
            "serial": self.serial,
            "model": self.getprop("ro.product.model"),
            "android_release": self.getprop("ro.build.version.release"),
            "sdk": self.getprop("ro.build.version.sdk"),
            "abi": self.getprop("ro.product.cpu.abi"),
            "rooted": "yes" if self.is_rooted() else "no",
        }

    def is_rooted(self) -> bool:
        return self.shell("id", root=True).stdout.startswith("uid=0")

    def list_packages(self, *, third_party: bool = True) -> list[str]:
        flag = "-3" if third_party else ""
        out = self.shell(f"pm list packages {flag}".strip()).stdout
        return sorted(line.split(":", 1)[1] for line in out.splitlines() if line.startswith("package:"))

    def package_paths(self, package: str) -> list[str]:
        out = self.shell(f"pm path {shlex.quote(package)}").stdout
        return [line.split(":", 1)[1] for line in out.splitlines() if line.startswith("package:")]

    def pull(self, remote: str, local: str, *, root: bool = False, timeout: int = 300) -> str:
        Path(local).parent.mkdir(parents=True, exist_ok=True)
        if root:
            # adb pull can't read app-private paths without root; stage via su + cat.
            tmp = f"/data/local/tmp/kritt_pull_{abs(hash(remote)) % 10_000_000}"
            self.shell(f"cp {shlex.quote(remote)} {tmp} && chmod 644 {tmp}", root=True, timeout=timeout)
            remote = tmp
        result = _run(self._args(["pull", remote, local]), timeout=timeout)
        if result.returncode != 0:
            raise AdbError(f"adb pull failed: {(result.stderr or '').strip()[:300]}")
        return local

    def am_start(
        self,
        *,
        component: str | None = None,
        action: str | None = None,
        data_uri: str | None = None,
        extras: dict[str, str] | None = None,
        wait: bool = True,
        timeout: int = 40,
    ) -> ShellResult:
        parts = ["am", "start"]
        if wait:
            parts.append("-W")
        if action:
            parts += ["-a", shlex.quote(action)]
        if data_uri:
            parts += ["-d", shlex.quote(data_uri)]
        if component:
            parts += ["-n", shlex.quote(component)]
        for key, value in (extras or {}).items():
            parts += ["--es", shlex.quote(key), shlex.quote(str(value))]
        return self.shell(" ".join(parts), timeout=timeout)

    def content_query(self, uri: str, *, timeout: int = 30) -> ShellResult:
        return self.shell(f"content query --uri {shlex.quote(uri)}", timeout=timeout)

    def dumpsys(self, service: str, *, timeout: int = 30) -> str:
        return self.shell(f"dumpsys {shlex.quote(service)}", timeout=timeout).stdout

    def logcat_clear(self) -> None:
        _run(self._args(["logcat", "-c"]), timeout=15)

    def logcat_dump(self, *, filters: str | None = None, max_lines: int = 400, timeout: int = 30) -> str:
        args = ["logcat", "-d", "-v", "time"]
        if filters:
            args += shlex.split(filters)
        out = (_run(self._args(args), timeout=timeout).stdout or "")
        lines = out.splitlines()
        return "\n".join(lines[-max_lines:])

    def screencap(self, local_png: str, *, timeout: int = 30) -> str:
        Path(local_png).parent.mkdir(parents=True, exist_ok=True)
        result = _run(self._args(["exec-out", "screencap", "-p"]), timeout=timeout, binary=True)
        if result.returncode != 0 or not result.stdout:
            raise AdbError("screencap failed")
        Path(local_png).write_bytes(result.stdout)
        return local_png

    def current_focus(self) -> str:
        out = self.dumpsys("window")
        for line in out.splitlines():
            if "mCurrentFocus" in line or "mFocusedApp" in line:
                return line.strip()
        return ""

    def force_stop(self, package: str) -> None:
        self.shell(f"am force-stop {shlex.quote(package)}")

    # --- Device-tab helpers ------------------------------------------------------------ #
    def app_pid(self, package: str) -> str:
        if not package:
            return ""
        return (self.shell(f"pidof {shlex.quote(package)}").stdout or "").strip().split(" ")[0]

    def is_app_running(self, package: str) -> bool:
        if not package:
            return False
        if self.app_pid(package):
            return True
        ps = self.shell(f"ps -A 2>/dev/null").stdout or ""
        return package in ps

    def install_apk(self, apk_path: str, *, reinstall: bool = True, timeout: int = 300) -> ShellResult:
        args = ["install"]
        if reinstall:
            args.append("-r")
        args.append(apk_path)
        result = _run(self._args(args), timeout=timeout)
        return ShellResult(
            stdout=(result.stdout or "").strip(),
            stderr=(result.stderr or "").strip(),
            returncode=result.returncode,
        )

    def resolve_launch_activity(self, package: str) -> str | None:
        out = _run(self._args(["shell", "cmd", "package", "resolve-activity", "--brief",
                               "-c", "android.intent.category.LAUNCHER", package]), timeout=20).stdout or ""
        for line in reversed(out.splitlines()):
            line = line.strip()
            if "/" in line and line.startswith(package):
                return line
        return None

    def launch_app(self, package: str, *, timeout: int = 20) -> int | None:
        """Launch the app's default activity and return its pid once it is up.

        Tries the resolved launcher component, then falls back to monkey. Used for attach-mode
        instrumentation (launch, then Frida-attach), which avoids spawn-gating."""
        import time as _t
        comp = self.resolve_launch_activity(package)
        if comp:
            _run(self._args(["shell", "am", "start", "-n", comp]), timeout=20)
        else:
            _run(self._args(["shell", "monkey", "-p", package, "-c",
                             "android.intent.category.LAUNCHER", "1"]), timeout=20)
        deadline = _t.time() + timeout
        while _t.time() < deadline:
            pid = self.app_pid(package)
            if pid:
                return pid
            _t.sleep(1)
        return None

    def tap(self, x: int, y: int) -> None:
        self.shell(f"input tap {int(x)} {int(y)}")

    def input_text(self, text: str) -> None:
        self.shell(f"input text {shlex.quote(text)}")

    def keyevent(self, key: str | int) -> None:
        self.shell(f"input keyevent {shlex.quote(str(key))}")

    def set_stay_awake(self, on: bool = True) -> None:
        """Keep the screen on while charging (USB) so it doesn't sleep during analysis."""
        self.shell(f"svc power stayon {'true' if on else 'false'}")
