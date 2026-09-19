"""Frida instrumentation service (Phase 3, Frida-first).

Ensures the matching frida-server is running on the rooted device (started via Magisk
`su`), then attaches to or spawns a target package, injects a script from a small library,
and captures the script's messages as runtime evidence.

Pinned to the frida-server version staged on the device (17.9.1 arm64) and the matching
host bindings in requirements.txt. Traffic interception (proxy/TLS) is intentionally a
later phase; this module covers hooking and behavioral capture.
"""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path
from dataclasses import dataclass, field
from typing import Any

from .adb import AdbError, Device, adb_bin, get_device

# Frida 16.x keeps the built-in `Java` bridge that the Android script ecosystem relies
# on (Frida 17 removed it, breaking Java.perform-based scripts). Pin to 16.7.19, which is
# staged on the research device.
DEFAULT_FRIDA_VERSION = os.getenv("ENGINE_FRIDA_VERSION", "16.7.19")


class FridaError(RuntimeError):
    pass


def _frida():
    try:
        import frida  # noqa: PLC0415 - optional heavy dependency, imported on demand

        return frida
    except ImportError as exc:  # pragma: no cover
        raise FridaError("frida bindings not installed (pip install frida==17.9.1)") from exc


def frida_server_path(device: Device, version: str = DEFAULT_FRIDA_VERSION) -> str:
    abi = device.getprop("ro.product.cpu.abi") or "arm64-v8a"
    arch = "arm64" if "arm64" in abi else "arm" if "arm" in abi else "x86_64" if "x86_64" in abi else "x86"
    candidate = f"/data/local/tmp/frida-server-{version}-android-{arch}"
    listing = device.shell(f"ls {candidate}").stdout
    if candidate in listing:
        return candidate
    # Fall back to any staged server matching the arch.
    staged = device.shell("ls /data/local/tmp/ | grep frida-server").stdout.splitlines()
    for name in staged:
        if arch in name:
            return f"/data/local/tmp/{name.strip()}"
    raise FridaError(f"no frida-server for arch {arch} found in /data/local/tmp (looked for {candidate})")


def _frida_device(serial: str | None, timeout: int = 8):
    """The frida handle for a SPECIFIC adb serial. With several devices attached (an emulator
    plus the physical phone), get_usb_device() is ambiguous and may hit the wrong one, so bind
    to the serial explicitly."""
    frida = _frida()
    if serial:
        return frida.get_device(serial, timeout=timeout)
    return frida.get_usb_device(timeout=timeout)


def server_running(serial: str | None = None) -> bool:
    try:
        _frida_device(serial, timeout=3).enumerate_processes()
        return True
    except Exception:  # noqa: BLE001 - any failure means not reachable
        return False


def _device_arch(device: Device) -> str:
    abi = device.getprop("ro.product.cpu.abi") or "arm64-v8a"
    return "arm64" if "arm64" in abi else "arm" if "arm" in abi else "x86_64" if "x86_64" in abi else "x86"


def _vendor_server(arch: str, version: str) -> Path | None:
    """A frida-server binary shipped with the engine (engine/vendor/frida/), used to stage a
    fresh emulator that has nothing in /data/local/tmp."""
    cand = Path(__file__).resolve().parent.parent / "vendor" / "frida" / f"frida-server-{version}-android-{arch}"
    return cand if cand.is_file() else None


def stage_server(device: Device, version: str = DEFAULT_FRIDA_VERSION) -> str:
    """Ensure a matching frida-server binary exists on the device; push the vendored one if
    the device (e.g. a freshly booted emulator) has none. Returns the on-device path."""
    try:
        return frida_server_path(device, version)
    except FridaError:
        pass
    arch = _device_arch(device)
    local = _vendor_server(arch, version)
    if local is None:
        raise FridaError(
            f"no frida-server staged on device and none vendored for {arch} {version} "
            f"(expected engine/vendor/frida/frida-server-{version}-android-{arch})"
        )
    remote = f"/data/local/tmp/frida-server-{version}-android-{arch}"
    push = subprocess.run([adb_bin(), "-s", device.serial, "push", str(local), remote],
                          capture_output=True, text=True, timeout=180, check=False)
    if push.returncode != 0:
        raise FridaError(f"failed to push frida-server: {push.stderr or push.stdout}")
    device.shell(f"chmod 755 {remote}", root=True)
    return remote


def restart_server(device: Device, version: str = DEFAULT_FRIDA_VERSION) -> subprocess.Popen:
    """Kill any frida-server and start the pinned one as ROOT.

    A frida-server left running as a non-root user answers enumerate() but cannot spawn, which
    surfaces later as a misleading "jailed Android" error. Forcing a clean root start removes
    that whole failure class."""

    server = stage_server(device, version)
    device.shell("pkill -f frida-server", root=True)
    time.sleep(1)
    device.shell(f"chmod 755 {server}", root=True)
    launch = f"{server} -D" if device.is_adb_root() else f"su -c '{server} -D'"
    handle = subprocess.Popen(
        [adb_bin(), "-s", device.serial, "shell", launch],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    deadline = time.time() + 20
    while time.time() < deadline:
        if server_running(device.serial):
            return handle
        time.sleep(0.5)
    handle.terminate()
    raise FridaError("frida-server did not become reachable within 20s after restart")


def ensure_server(device: Device | None = None, version: str = DEFAULT_FRIDA_VERSION, *, force: bool = False) -> subprocess.Popen | None:
    """Ensure a usable ROOT frida-server. With force=True (or when none is reachable) it does a
    clean root restart; a merely-reachable server is not trusted, since a stale non-root one
    enumerates fine but cannot spawn."""

    device = device or get_device()
    if force:
        return restart_server(device, version)
    if server_running(device.serial):
        return None
    server = stage_server(device, version)
    device.shell(f"chmod 755 {server}", root=True)
    # Emulators / userdebug run adbd as root (no `su`); Magisk devices need `su -c`.
    launch = f"{server} -D" if device.is_adb_root() else f"su -c '{server} -D'"
    handle = subprocess.Popen(
        [adb_bin(), "-s", device.serial, "shell", launch],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    deadline = time.time() + 20
    while time.time() < deadline:
        if server_running(device.serial):
            return handle
        time.sleep(0.5)
    handle.terminate()
    raise FridaError("frida-server did not become reachable within 20s")


@dataclass
class FridaRun:
    package: str
    script_name: str
    spawned: bool
    messages: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None

    @property
    def logs(self) -> list[str]:
        out = []
        for m in self.messages:
            if m.get("type") == "send":
                out.append(str(m.get("payload")))
            elif m.get("type") == "error":
                out.append("[script error] " + str(m.get("description")))
        return out


def run_script(
    package: str,
    script_source: str,
    *,
    spawn: bool = True,
    run_seconds: float = 6.0,
    device_timeout: int = 8,
    serial: str | None = None,
    attach_pid: int | None = None,
) -> FridaRun:
    """Inject script_source into package, collect its messages for run_seconds.

    attach_pid attaches to an already-running process (set by launching the app first), which
    avoids frida's spawn-gating that times out on some Android 13 builds."""

    frida = _frida()
    dev = _frida_device(serial, timeout=device_timeout)
    result = FridaRun(package=package, script_name="inline", spawned=spawn and attach_pid is None)
    session = None
    pid = None
    try:
        if attach_pid is not None:
            session = dev.attach(int(attach_pid))
        elif spawn:
            pid = dev.spawn([package])
            session = dev.attach(pid)
        else:
            session = dev.attach(package)
        script = session.create_script(script_source)
        script.on("message", lambda message, data: result.messages.append(message))
        script.load()
        if spawn and pid is not None:
            dev.resume(pid)
        time.sleep(run_seconds)
    except frida.ProcessNotFoundError as exc:
        result.error = f"process not found (is {package} installed/running?): {exc}"
    except frida.TransportError as exc:
        result.error = f"frida transport error: {exc}"
    except Exception as exc:  # noqa: BLE001 - surface any injection failure as evidence
        result.error = f"{type(exc).__name__}: {exc}"
    finally:
        try:
            if session is not None:
                session.detach()
        except Exception:  # noqa: BLE001
            pass
    return result


# --------------------------------------------------------------------------- #
# Small script library                                                        #
# --------------------------------------------------------------------------- #

SCRIPT_PROBE_LOADED = r"""
Java.perform(function () {
  send({event: 'java_vm_ready'});
  try {
    var app = Java.use('android.app.ActivityThread').currentApplication();
    var ctx = app.getApplicationContext();
    send({event: 'package', value: ctx.getPackageName()});
  } catch (e) { send({event: 'context_error', value: '' + e}); }
});
"""

SCRIPT_CRYPTO_TAP = r"""
Java.perform(function () {
  try {
    var Cipher = Java.use('javax.crypto.Cipher');
    Cipher.getInstance.overload('java.lang.String').implementation = function (t) {
      send({event: 'cipher', transformation: t});
      return this.getInstance(t);
    };
    send({event: 'crypto_hooks_installed'});
  } catch (e) { send({event: 'hook_error', value: '' + e}); }
});
"""

SCRIPT_SSL_PINNING_PROBE = r"""
Java.perform(function () {
  try {
    var TMF = Java.use('javax.net.ssl.TrustManagerFactory');
    send({event: 'ssl_stack_present'});
  } catch (e) { send({event: 'ssl_error', value: '' + e}); }
});
"""

# --------------------------------------------------------------------------- #
# Bypass library (audited, standard techniques). Applied automatically only to  #
# authorized targets (FOSS / bug-bounty-in-scope) on an owned emulator/device,  #
# solely to reach the vulnerable code path during verification. Every applied   #
# bypass is recorded in the finding's evidence trail.                           #
# --------------------------------------------------------------------------- #

# Universal TLS-pinning bypass: neutralises the common pinning surfaces (TrustManager,
# OkHttp CertificatePinner, TrustManagerImpl, Conscrypt) so intercepted HTTPS is readable.
SCRIPT_SSL_UNPIN = r"""
Java.perform(function () {
  var hits = [];
  function note(w){ if(hits.indexOf(w)<0){ hits.push(w); send({event:'ssl_unpin', where:w}); } }
  // 1. Custom X509TrustManager -> accept everything
  try {
    var X509TM = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    var TrustManager = Java.registerClass({
      name: 'com.okritt.TrustAll', implements: [X509TM],
      methods: { checkClientTrusted: function(){}, checkServerTrusted: function(){}, getAcceptedIssuers: function(){ return []; } }
    });
    var tms = [TrustManager.$new()];
    var init = SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;','[Ljavax.net.ssl.TrustManager;','java.security.SecureRandom');
    init.implementation = function(km, tm, sr){ note('SSLContext.init'); init.call(this, km, tms, sr); };
  } catch(e){}
  // 2. OkHttp CertificatePinner.check
  ['okhttp3.CertificatePinner','com.squareup.okhttp.CertificatePinner'].forEach(function(cn){
    try { var CP=Java.use(cn);
      CP.check.overload('java.lang.String','java.util.List').implementation=function(){ note(cn+'.check'); };
      try { CP.check.overload('java.lang.String','[Ljava.security.cert.Certificate;').implementation=function(){ note(cn+'.check[]'); }; } catch(e){}
    } catch(e){}
  });
  // 3. Conscrypt / TrustManagerImpl.verifyChain (Android default)
  try {
    var TMI = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    TMI.verifyChain.implementation = function(chain, atype, host, clientAuth, ocsp, tlsSct){ note('TrustManagerImpl.verifyChain'); return chain; };
  } catch(e){}
  send({event:'ssl_unpin_installed'});
});
"""

# Root / emulator / debugger detection bypass: makes common anti-analysis checks pass so the
# app runs normally on the (owned) rooted emulator instead of refusing to start.
SCRIPT_ANTI_DETECT_BYPASS = r"""
Java.perform(function () {
  var hid = [];
  function note(w){ if(hid.indexOf(w)<0){ hid.push(w); send({event:'anti_detect', where:w}); } }
  // File.exists() lies for known root artifacts
  try {
    var F = Java.use('java.io.File');
    var bad = ['su','magisk','superuser','busybox','xposed','frida'];
    F.exists.implementation = function(){
      var p = ('' + this.getAbsolutePath()).toLowerCase();
      for (var i=0;i<bad.length;i++){ if(p.indexOf(bad[i])>=0){ note('File.exists:'+bad[i]); return false; } }
      return this.exists();
    };
  } catch(e){}
  // Runtime.exec('su' / 'which su') -> fail
  try {
    var R = Java.use('java.lang.Runtime');
    R.exec.overload('java.lang.String').implementation = function(c){
      if(('' + c).toLowerCase().indexOf('su')>=0){ note('Runtime.exec:'+c); throw Java.use('java.io.IOException').$new('not found'); }
      return this.exec(c);
    };
  } catch(e){}
  // Build props that scream "emulator"
  try {
    var B = Java.use('android.os.Build');
    B.FINGERPRINT.value = 'google/redfin/redfin:13/TQ3A.230805.001/10316531:user/release-keys';
    B.MODEL.value = 'Pixel 6 Pro'; B.MANUFACTURER.value = 'Google'; B.PRODUCT.value = 'redfin';
    note('Build.props');
  } catch(e){}
  // Debugger checks
  try {
    var D = Java.use('android.os.Debug');
    D.isDebuggerConnected.implementation = function(){ note('Debug.isDebuggerConnected'); return false; };
  } catch(e){}
  send({event:'anti_detect_installed'});
});
"""

BYPASS_LIBRARY = {
    "ssl_unpin": SCRIPT_SSL_UNPIN,
    "anti_detect": SCRIPT_ANTI_DETECT_BYPASS,
}


def apply_bypasses(package: str, kinds: list[str], *, run_seconds: float = 4.0, serial: str | None = None) -> "FridaRun":
    """Spawn the package with the requested bypass scripts injected before its code runs.

    Returns the FridaRun so the caller can record which hooks actually fired as evidence."""
    scripts = [BYPASS_LIBRARY[k] for k in kinds if k in BYPASS_LIBRARY]
    if not scripts:
        raise FridaError(f"no known bypasses in {kinds!r}; have {list(BYPASS_LIBRARY)}")
    combined = "\n".join(scripts)
    return run_script(package, combined, spawn=True, run_seconds=run_seconds)


SCRIPT_LIBRARY = {
    "probe_loaded": SCRIPT_PROBE_LOADED,
    "crypto_tap": SCRIPT_CRYPTO_TAP,
    "ssl_pinning_probe": SCRIPT_SSL_PINNING_PROBE,
    "ssl_unpin": SCRIPT_SSL_UNPIN,
    "anti_detect": SCRIPT_ANTI_DETECT_BYPASS,
}
