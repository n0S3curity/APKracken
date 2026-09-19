"""Engine-side Android device agent for the UI "Device" tab.

The physical device is USB-connected to the host, and only the native engine has adb — so
the engine is the device agent: it polls device state (connection, details, the tested app's
install/run status, installed apps, filtered logcat, a periodic screenshot) into the DB, and
performs actions the backend requests (install/reinstall, keep-awake). The backend just
reads/serves these rows; the frontend polls.

Heavy collection (screenshot, logcat, app/installed status) only runs while the tab is being
viewed (a fresh `screen_wanted_at` heartbeat written by the backend), so an idle tab imposes
almost no device load.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone

LOGGER = logging.getLogger("open_kritt_engine")

# The tab-open heartbeat (`screen_wanted_at`, written by the backend on each poll) gates the
# heavier metadata collection (logcat / app status / installed apps) so an unopened tab costs
# the device almost nothing. The live screen mirror is a separate real-time H.264 stream
# (device_stream.py) — not captured here.
_VIEW_FRESH_SECONDS = 6.0
_INSTALLED_APPS_REFRESH_SECONDS = 12.0
_DETAILS_REFRESH_SECONDS = 30.0


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _age_seconds(ts) -> float:
    if not ts:
        return 1e9
    try:
        if isinstance(ts, str):
            ts = datetime.fromisoformat(ts)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return (_now() - ts).total_seconds()
    except Exception:  # noqa: BLE001
        return 1e9


def ensure_tables(conn) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS public.device_state (
            id integer PRIMARY KEY DEFAULT 1,
            selected_serial text,
            last_test_serial text,
            tested_scan_id bigint,
            tested_package text,
            tested_apk_path text,
            screen_wanted_at timestamptz,
            connected boolean NOT NULL DEFAULT false,
            active_serial text,
            details jsonb,
            app_installed boolean,
            app_running boolean,
            devices jsonb,
            installed_apps jsonb,
            installed_apps_at timestamptz,
            logcat text,
            keep_awake boolean NOT NULL DEFAULT false,
            install_token bigint NOT NULL DEFAULT 0,
            install_done_token bigint NOT NULL DEFAULT 0,
            install_status text,
            updated_at timestamptz NOT NULL DEFAULT now(),
            CONSTRAINT device_state_singleton CHECK (id = 1)
        )
        """
    )
    conn.execute("INSERT INTO public.device_state (id) VALUES (1) ON CONFLICT (id) DO NOTHING")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS public.devices (
            serial text PRIMARY KEY,
            model text, brand text, manufacturer text,
            android_release text, sdk text, rooted boolean,
            first_seen timestamptz NOT NULL DEFAULT now(),
            last_seen timestamptz NOT NULL DEFAULT now()
        )
        """
    )
    conn.commit()


def _load_state(conn) -> dict:
    row = conn.execute("SELECT * FROM public.device_state WHERE id=1").fetchone()
    return dict(row) if row else {}


def note_test_serial(conn, serial: str | None) -> None:
    """Remember the last device a live test ran on — the Device tab defaults to it."""
    if not serial:
        return
    try:
        ensure_tables(conn)
        conn.execute("UPDATE public.device_state SET last_test_serial=%s, updated_at=now() WHERE id=1", (serial,))
        conn.commit()
    except Exception:  # noqa: BLE001
        LOGGER.debug("failed to record last_test_serial", exc_info=True)


def _choose_active(online: list[str], selected: str | None, last_test: str | None) -> str | None:
    if not online:
        return None
    if selected and selected in online:
        return selected
    if last_test and last_test in online:
        return last_test
    return online[0]


def _resolve_tested(conn, state: dict, data_dir: str) -> tuple[str | None, str | None]:
    """Return (package, apk_path) for the tested scan, resolving + caching on first use."""
    scan_id = state.get("tested_scan_id")
    if not scan_id:
        row = conn.execute(
            "SELECT id FROM scans WHERE COALESCE(repo_kind,'')='apk' ORDER BY id DESC LIMIT 1"
        ).fetchone()
        scan_id = row["id"] if row else None
        if scan_id:
            conn.execute("UPDATE public.device_state SET tested_scan_id=%s WHERE id=1", (scan_id,))
            conn.commit()
    if not scan_id:
        return None, None
    if state.get("tested_package") and state.get("tested_apk_path"):
        return state["tested_package"], state["tested_apk_path"]
    # Resolve the package from the decompiled workspace manifest (engine-only data).
    try:
        row = conn.execute(
            "SELECT commit_sha, configuration FROM scans WHERE id=%s", (scan_id,)
        ).fetchone()
        cfg = row.get("configuration") if isinstance(row.get("configuration"), dict) else {}
        apk_path = cfg.get("apk_path")
        sha = row.get("commit_sha")
        pkg = None
        if sha and len(str(sha)) == 64:
            wpath = os.path.join(data_dir, "apk-cache", str(sha), "WORKSPACE.json")
            if os.path.isfile(wpath):
                with open(wpath, encoding="utf-8") as handle:
                    pkg = (json.load(handle).get("android", {}) or {}).get("package")
        conn.execute(
            "UPDATE public.device_state SET tested_package=%s, tested_apk_path=%s WHERE id=1", (pkg, apk_path)
        )
        conn.commit()
        return pkg, apk_path
    except Exception:  # noqa: BLE001
        LOGGER.debug("failed to resolve tested package", exc_info=True)
        return state.get("tested_package"), state.get("tested_apk_path")


def _upsert_device(conn, serial: str, details: dict) -> None:
    conn.execute(
        """
        INSERT INTO public.devices (serial, model, brand, manufacturer, android_release, sdk, rooted, last_seen)
        VALUES (%s,%s,%s,%s,%s,%s,%s, now())
        ON CONFLICT (serial) DO UPDATE SET
            model=EXCLUDED.model, brand=EXCLUDED.brand, manufacturer=EXCLUDED.manufacturer,
            android_release=EXCLUDED.android_release, sdk=EXCLUDED.sdk, rooted=EXCLUDED.rooted,
            last_seen=now()
        """,
        (
            serial,
            details.get("model"),
            details.get("brand"),
            details.get("manufacturer"),
            details.get("android_release"),
            details.get("sdk"),
            details.get("rooted") == "yes" if isinstance(details.get("rooted"), str) else bool(details.get("rooted")),
        ),
    )
    conn.commit()


def _device_details(dev) -> dict:
    d = dev.summary()  # serial, model, android_release, sdk, rooted
    d["brand"] = dev.getprop("ro.product.brand")
    d["manufacturer"] = dev.getprop("ro.product.manufacturer")
    d["marketing_name"] = dev.getprop("ro.product.vendor.marketname") or dev.getprop("ro.config.marketing_name")
    return d


def tick(conn, *, data_dir: str) -> None:
    """One device-agent cycle. Best-effort; never raises."""
    from . import adb

    ensure_tables(conn)
    state = _load_state(conn)

    try:
        devices = adb.list_devices()
    except Exception as exc:  # noqa: BLE001 - adb missing / not on PATH
        conn.execute(
            "UPDATE public.device_state SET connected=false, active_serial=NULL, devices=%s, "
            "install_status=%s, updated_at=now() WHERE id=1",
            (json.dumps([]), f"adb unavailable: {str(exc)[:160]}"),
        )
        conn.commit()
        return

    online = [d["serial"] for d in devices if d.get("state") == "device"]
    active = _choose_active(online, state.get("selected_serial"), state.get("last_test_serial"))
    devices_json = json.dumps(devices)

    if not active:
        conn.execute(
            "UPDATE public.device_state SET connected=false, active_serial=NULL, app_installed=NULL, "
            "app_running=NULL, keep_awake=false, devices=%s, updated_at=now() WHERE id=1",
            (devices_json,),
        )
        conn.commit()
        return

    dev = adb.Device(active)
    if active.startswith("emulator-"):
        try:
            dev.ensure_root()
        except Exception:  # noqa: BLE001
            pass

    # Device details (persisted; refreshed on serial change or periodically).
    details = state.get("details") if isinstance(state.get("details"), dict) else {}
    if state.get("active_serial") != active or _age_seconds(state.get("updated_at")) > _DETAILS_REFRESH_SECONDS or not details:
        try:
            details = _device_details(dev)
            _upsert_device(conn, active, details)
        except Exception:  # noqa: BLE001
            LOGGER.debug("device detail read failed", exc_info=True)

    # Keep the screen awake while connected (re-applied when the active device changes).
    keep_awake = bool(state.get("keep_awake")) and state.get("active_serial") == active
    if not keep_awake:
        try:
            dev.set_stay_awake(True)
            dev.shell("settings put system screen_off_timeout 2147483647")
            keep_awake = True
        except Exception:  # noqa: BLE001
            keep_awake = False

    # Install / reinstall request (backend bumps install_token).
    install_status = state.get("install_status")
    install_done = int(state.get("install_done_token") or 0)
    install_token = int(state.get("install_token") or 0)
    tested_pkg, tested_apk = _resolve_tested(conn, state, data_dir)
    if install_token > install_done:
        install_status = "installing…"
        conn.execute("UPDATE public.device_state SET install_status=%s WHERE id=1", (install_status,))
        conn.commit()
        try:
            if tested_apk and os.path.isfile(tested_apk):
                res = dev.install_apk(tested_apk, reinstall=True)
                ok = res.returncode == 0 and "Success" in f"{res.stdout} {res.stderr}"
                install_status = "installed ✓" if ok else f"install failed: {(res.stderr or res.stdout)[:200]}"
            else:
                install_status = "no APK file found on host for the selected app"
        except Exception as exc:  # noqa: BLE001
            install_status = f"install error: {str(exc)[:200]}"
        install_done = install_token
        conn.execute(
            "UPDATE public.device_state SET install_done_token=%s, install_status=%s WHERE id=1",
            (install_done, install_status),
        )
        conn.commit()

    # Heavy collection only while the tab is open (fresh screen heartbeat from the backend).
    viewing = _age_seconds(state.get("screen_wanted_at")) < _VIEW_FRESH_SECONDS
    app_installed = state.get("app_installed")
    app_running = state.get("app_running")
    installed_apps = state.get("installed_apps")
    logcat = state.get("logcat")

    if viewing:
        try:
            app_installed = bool(dev.package_paths(tested_pkg)) if tested_pkg else None
            app_running = dev.is_app_running(tested_pkg) if tested_pkg else None
        except Exception:  # noqa: BLE001
            pass
        # Installed apps (throttled — the list rarely changes).
        if _age_seconds(state.get("installed_apps_at")) > _INSTALLED_APPS_REFRESH_SECONDS:
            try:
                apps = dev.list_packages(third_party=True)
                conn.execute(
                    "UPDATE public.device_state SET installed_apps=%s, installed_apps_at=now() WHERE id=1",
                    (json.dumps(apps),),
                )
                conn.commit()
                installed_apps = apps
            except Exception:  # noqa: BLE001
                pass
        # Logcat filtered to the tested app (by its live pid when running).
        try:
            pid = dev.app_pid(tested_pkg) if tested_pkg else ""
            if pid:
                logcat = dev.logcat_dump(filters=f"--pid={pid}", max_lines=200)
            elif tested_pkg:
                logcat = f"(app '{tested_pkg}' is not running — start it to stream its logcat)"
        except Exception:  # noqa: BLE001
            pass
        # The live screen mirror is a separate real-time H.264 stream (device_stream.py).

    conn.execute(
        """
        UPDATE public.device_state SET
            connected=true, active_serial=%s, details=%s, app_installed=%s, app_running=%s,
            devices=%s, logcat=%s, keep_awake=%s, updated_at=now()
        WHERE id=1
        """,
        (
            active,
            json.dumps(details or {}),
            app_installed,
            app_running,
            devices_json,
            logcat,
            keep_awake,
        ),
    )
    conn.commit()
