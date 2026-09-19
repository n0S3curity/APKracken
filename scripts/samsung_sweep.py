"""Samsung system-app sweep: enumerate the pre-installed Samsung apps on a connected device,
pull their APKs into the scan inbox, and queue a "Samsung System-App Research" scan for each.

This is the "research the device's default apps" driver. It needs a connected, authorized,
rooted SAMSUNG device (the default apps live there; a Pixel emulator has none).

Usage (from the repo root, with the native engine's venv python):
  engine\\.venv\\Scripts\\python.exe scripts\\samsung_sweep.py --list
  engine\\.venv\\Scripts\\python.exe scripts\\samsung_sweep.py --pull --limit 20
  engine\\.venv\\Scripts\\python.exe scripts\\samsung_sweep.py --pull --scan --limit 20

Flags:
  --list         only print the Samsung/Sec system packages found on the device
  --pull         pull each package's base APK into the inbox
  --scan         after pulling, create a Samsung-research scan per app (needs the backend up)
  --limit N      cap how many apps (default 25); highest-value packages first
  --serial S     target a specific adb serial (default: ENGINE_ADB_SERIAL or the sole device)
  --inbox DIR    APK inbox dir (default: C:/Users/Maor2/kritt-data/apk-inbox)
  --backend URL  backend base (default http://127.0.0.1:3002 via docker host)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.request

ADB = os.getenv("ENGINE_ADB_BIN") or r"C:/Users/Maor2/AppData/Local/Android/Sdk/platform-tools/adb.exe"

# Packages worth prioritising (highest bug-bounty value first). A package matching an earlier
# pattern sorts before a later one; everything Samsung/Sec still gets included after these.
_PRIORITY = [
    "spay", "pay", "samsungaccount", "osp.app.signin", "account", "knox", "oneconnect",
    "smartthings", "bixby", "sbrowser", "messaging", "contacts", "dialer", "gallery",
    "themestore", "galaxystore", "samsungapps", "members", "shealth", "find",
]
_SAMSUNG_RE = re.compile(r"^(com\.samsung|com\.sec)\.", re.I)


def _adb(serial, args, timeout=120, binary=False):
    base = [ADB] + (["-s", serial] if serial else [])
    return subprocess.run(base + args, capture_output=True, text=not binary, timeout=timeout, check=False)


def _pick_serial(requested):
    if requested:
        return requested
    env = os.getenv("ENGINE_ADB_SERIAL")
    if env:
        return env
    out = _adb(None, ["devices"]).stdout or ""
    devs = [ln.split("\t")[0] for ln in out.splitlines()[1:] if ln.strip().endswith("\tdevice")]
    if not devs:
        sys.exit("no authorized adb device connected")
    if len(devs) > 1:
        sys.exit(f"multiple devices; pass --serial (have: {devs})")
    return devs[0]


def _priority_key(pkg):
    low = pkg.lower()
    for i, hint in enumerate(_PRIORITY):
        if hint in low:
            return (i, pkg)
    return (len(_PRIORITY), pkg)


def list_samsung(serial):
    """Return [(package, apk_path)] for Samsung/Sec packages, priority-sorted."""
    out = _adb(serial, ["shell", "pm", "list", "packages", "-f"]).stdout or ""
    found = {}
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("package:"):
            continue
        body = line[len("package:"):]
        # format: <apk_path>=<package>
        if "=" not in body:
            continue
        apk_path, pkg = body.rsplit("=", 1)
        if _SAMSUNG_RE.match(pkg):
            found[pkg] = apk_path
    return sorted(found.items(), key=lambda kv: _priority_key(kv[0]))


def pull_apk(serial, pkg, apk_path, inbox):
    os.makedirs(inbox, exist_ok=True)
    dest = os.path.join(inbox, pkg + ".apk")
    if os.path.exists(dest) and os.path.getsize(dest) > 0:
        return dest, "present"
    r = _adb(serial, ["pull", apk_path, dest], timeout=300)
    if r.returncode != 0 or not os.path.exists(dest):
        return None, (r.stderr or r.stdout or "pull failed")[:120]
    return dest, "pulled"


def queue_scan(backend, filename):
    body = json.dumps({"filename": filename, "workflow": "samsung"}).encode()
    req = urllib.request.Request(backend.rstrip("/") + "/api/apk/scan-existing", data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read().decode())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--pull", action="store_true")
    ap.add_argument("--scan", action="store_true")
    ap.add_argument("--limit", type=int, default=25)
    ap.add_argument("--serial")
    ap.add_argument("--inbox", default=r"C:/Users/Maor2/kritt-data/apk-inbox")
    ap.add_argument("--backend", default="http://127.0.0.1:3002")
    a = ap.parse_args()

    serial = _pick_serial(a.serial)
    man = _adb(serial, ["shell", "getprop", "ro.product.manufacturer"]).stdout.strip()
    print(f"device {serial} (manufacturer: {man or '?'})")
    if man and man.lower() != "samsung":
        print("WARNING: this device is not a Samsung; there will be no Samsung default apps to research.")

    apps = list_samsung(serial)
    print(f"found {len(apps)} Samsung/Sec packages; taking top {min(a.limit, len(apps))}")
    apps = apps[: a.limit]
    for pkg, path in apps:
        print(f"  {pkg}")
    if a.list and not (a.pull or a.scan):
        return

    for pkg, path in apps:
        dest, status = pull_apk(serial, pkg, path, a.inbox)
        if dest is None:
            print(f"  pull FAIL {pkg}: {status}")
            continue
        fname = os.path.basename(dest)
        print(f"  {status}: {fname}")
        if a.scan:
            try:
                res = queue_scan(a.backend, fname)
                print(f"    queued scan {res.get('scanId')} (samsung workflow)")
            except Exception as exc:  # noqa: BLE001
                print(f"    scan queue FAILED: {exc}")


if __name__ == "__main__":
    main()
