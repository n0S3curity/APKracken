"""APK ingestion + decompilation workspace for the Android research build.

Replaces the git-checkout input layer with an APK-native one. Given an APK path, this
produces a stable, cached, decompiled workspace tree that the local agentic harness
explores exactly like a repo checkout, plus a rich ``WORKSPACE.json`` (package,
components, exported flags, deep links, permissions, SDK levels, native ABIs) that is
injected into every step prompt.

It returns a ``DependencyWorkspace`` (the same object ``prepare_dependency_workspace``
returns), so ``execute_job`` and the whole downstream engine work unchanged.

Pipeline per APK (cached by sha256 under ENGINE_DATA_DIR/apk-cache/<sha256>):
  - jadx      -> readable Java + decoded AndroidManifest.xml + resources   (required)
  - apktool   -> smali + decoded resources                                 (best-effort)
  - zip       -> native libs (lib/<abi>/*.so) + assets                     (best-effort)
  - manifest  -> Android attack-surface intelligence (ElementTree + aapt2) (best-effort)

Tool locations are auto-discovered and overridable via env (ENGINE_JADX_BIN,
ENGINE_APKTOOL_JAR, ENGINE_AAPT2_BIN, JAVA_HOME).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import subprocess
import zipfile
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

from .workspace import DependencyWorkspace, JobWorkspace

LOGGER = logging.getLogger("open_kritt_engine")

ANDROID_NS = "http://schemas.android.com/apk/res/android"
_A = f"{{{ANDROID_NS}}}"
CACHE_MARKER = ".kritt-apk-complete"
JADX_TIMEOUT = int(os.getenv("ENGINE_JADX_TIMEOUT_SECONDS", "1200"))
APKTOOL_TIMEOUT = int(os.getenv("ENGINE_APKTOOL_TIMEOUT_SECONDS", "900"))


class ApkWorkspaceError(RuntimeError):
    pass


# --------------------------------------------------------------------------- #
# Tool discovery                                                              #
# --------------------------------------------------------------------------- #


def _first_existing(paths: list[str]) -> str | None:
    for candidate in paths:
        if candidate and Path(candidate).exists():
            return candidate
    return None


def jadx_bin() -> str:
    configured = os.getenv("ENGINE_JADX_BIN")
    if configured:
        return configured
    found = _first_existing(
        [
            str(Path.home() / "OneDrive/Desktop/TOOLS/jadx/build/jadx/bin/jadx.bat"),
            str(Path.home() / "OneDrive/Desktop/TOOLS/jadx/bin/jadx.bat"),
        ]
    )
    if found:
        return found
    return shutil.which("jadx.bat") or shutil.which("jadx") or "jadx"


def java_bin() -> str:
    java_home = os.getenv("JAVA_HOME")
    if java_home:
        candidate = Path(java_home) / "bin" / ("java.exe" if os.name == "nt" else "java")
        if candidate.exists():
            return str(candidate)
    return shutil.which("java") or "java"


def apktool_jar() -> str | None:
    configured = os.getenv("ENGINE_APKTOOL_JAR")
    if configured:
        return configured if Path(configured).exists() else None
    return _first_existing([str(Path.home() / "OneDrive/Desktop/TOOLS/apktool/apktool.jar")])


def aapt2_bin() -> str:
    return os.getenv("ENGINE_AAPT2_BIN") or shutil.which("aapt2") or "aapt2"


def _run(cmd: list[str], *, timeout: int, cwd: str | None = None) -> subprocess.CompletedProcess:
    # .bat/.cmd launchers must go through cmd.exe on Windows.
    if os.name == "nt" and cmd and str(cmd[0]).lower().endswith((".bat", ".cmd")):
        cmd = ["cmd", "/c", *cmd]
    # Decode as UTF-8 with replacement. Without an explicit encoding, text=True uses the
    # platform default (cp1252 on Windows), and any tool byte that isn't valid there (an
    # aapt2 badging label, a jadx warning, etc.) raises UnicodeDecodeError inside the
    # reader thread, leaving result.stdout as None and crashing downstream .splitlines().
    return subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )


# --------------------------------------------------------------------------- #
# Decompilation                                                               #
# --------------------------------------------------------------------------- #


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _run_jadx(apk_path: str, out_dir: Path) -> dict[str, Any]:
    binary = jadx_bin()
    result = _run(
        [binary, "-d", str(out_dir), "--no-debug-info", "--show-bad-code", apk_path],
        timeout=JADX_TIMEOUT,
    )
    sources = out_dir / "sources"
    resources = out_dir / "resources"
    # jadx exits non-zero when some methods fail to decompile but still writes full
    # output, so success is defined by output presence, not the return code.
    ok = sources.is_dir() or resources.is_dir()
    if not ok:
        raise ApkWorkspaceError(f"jadx produced no output (rc={result.returncode}): {(result.stderr or '')[-400:]}")
    return {"ok": ok, "returncode": result.returncode, "sources": sources.is_dir(), "resources": resources.is_dir()}


def _run_apktool(apk_path: str, out_dir: Path) -> dict[str, Any]:
    jar = apktool_jar()
    if not jar:
        return {"ok": False, "reason": "apktool.jar not found"}
    try:
        result = _run(
            [java_bin(), "-jar", jar, "d", apk_path, "-o", str(out_dir), "-f"],
            timeout=APKTOOL_TIMEOUT,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "reason": str(exc)}
    smali_present = any(out_dir.glob("smali*"))
    return {"ok": smali_present, "returncode": result.returncode, "smali": smali_present}


def _safe_member(name: str) -> bool:
    parts = Path(name).parts
    return bool(parts) and ".." not in parts and not name.startswith("/") and ":" not in name


def _extract_native_and_assets(apk_path: str, out_dir: Path) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    abis: set[str] = set()
    count = 0
    try:
        with zipfile.ZipFile(apk_path) as archive:
            for name in archive.namelist():
                if not (name.startswith("lib/") or name.startswith("assets/")):
                    continue
                if not _safe_member(name) or name.endswith("/"):
                    continue
                if name.startswith("lib/"):
                    segments = name.split("/")
                    if len(segments) >= 2:
                        abis.add(segments[1])
                archive.extract(name, out_dir)
                count += 1
    except (OSError, zipfile.BadZipFile) as exc:
        return {"ok": False, "reason": str(exc)}
    return {"ok": True, "files": count, "native_abis": sorted(abis)}


# --------------------------------------------------------------------------- #
# Manifest intelligence                                                       #
# --------------------------------------------------------------------------- #


def _attr(element: ElementTree.Element, name: str) -> str | None:
    return element.get(f"{_A}{name}")


def _bool_attr(element: ElementTree.Element, name: str) -> bool | None:
    value = _attr(element, name)
    if value is None:
        return None
    return value.strip().lower() == "true"


def _component_records(application: ElementTree.Element, tag: str, kind: str) -> list[dict[str, Any]]:
    records = []
    for element in application.findall(tag):
        intent_filters = element.findall("intent-filter")
        exported = _bool_attr(element, "exported")
        # Implicitly exported when an intent-filter is present and exported is unset
        # (true for targetSdk < 31; conservatively flagged for review either way).
        implicitly_exported = exported is None and bool(intent_filters)
        records.append(
            {
                "kind": kind,
                "name": _attr(element, "name"),
                "exported": exported,
                "implicitly_exported": implicitly_exported,
                "permission": _attr(element, "permission"),
                "has_intent_filter": bool(intent_filters),
                "grant_uri_permissions": _bool_attr(element, "grantUriPermissions"),
                "authorities": _attr(element, "authorities"),
            }
        )
    return records


def _deep_links(application: ElementTree.Element) -> list[dict[str, Any]]:
    links = []
    for element in application.iter():
        if element.tag not in {"activity", "activity-alias", "service", "receiver"}:
            continue
        component = _attr(element, "name")
        for intent_filter in element.findall("intent-filter"):
            data_nodes = intent_filter.findall("data")
            schemes = [d for d in (_attr(node, "scheme") for node in data_nodes) if d]
            if not schemes:
                continue
            links.append(
                {
                    "component": component,
                    "schemes": sorted(set(schemes)),
                    "hosts": sorted({h for h in (_attr(node, "host") for node in data_nodes) if h}),
                    "path_prefixes": sorted({p for p in (_attr(node, "pathPrefix") for node in data_nodes) if p}),
                    "paths": sorted({p for p in (_attr(node, "path") for node in data_nodes) if p}),
                    "auto_verify": _bool_attr(intent_filter, "autoVerify"),
                }
            )
    return links


def parse_android_manifest(manifest_xml: Path) -> dict[str, Any]:
    try:
        root = ElementTree.parse(manifest_xml).getroot()
    except (OSError, ElementTree.ParseError) as exc:
        return {"error": f"could not parse manifest: {exc}"}
    application = root.find("application")
    uses_sdk = root.find("uses-sdk")
    min_sdk = _attr(uses_sdk, "minSdkVersion") if uses_sdk is not None else None
    target_sdk = _attr(uses_sdk, "targetSdkVersion") if uses_sdk is not None else None
    uses_permissions = [p.get(f"{_A}name") for p in root.findall("uses-permission")]
    custom_permissions = [
        {"name": p.get(f"{_A}name"), "protection_level": p.get(f"{_A}protectionLevel")}
        for p in root.findall("permission")
    ]
    app_flags: dict[str, Any] = {}
    components: list[dict[str, Any]] = []
    deep_links: list[dict[str, Any]] = []
    if application is not None:
        app_flags = {
            "name": _attr(application, "name"),
            "debuggable": _bool_attr(application, "debuggable"),
            "allow_backup": _bool_attr(application, "allowBackup"),
            "uses_cleartext_traffic": _bool_attr(application, "usesCleartextTraffic"),
            "network_security_config": _attr(application, "networkSecurityConfig"),
        }
        for tag, kind in (("activity", "activity"), ("activity-alias", "activity-alias"), ("service", "service"), ("receiver", "receiver"), ("provider", "provider")):
            components.extend(_component_records(application, tag, kind))
        deep_links = _deep_links(application)
    exported = [c for c in components if c["exported"] or c["implicitly_exported"]]
    return {
        "package": root.get("package"),
        "version_code": root.get(f"{_A}versionCode"),
        "version_name": root.get(f"{_A}versionName"),
        "min_sdk": min_sdk,
        "target_sdk": target_sdk,
        "application": app_flags,
        "uses_permissions": [p for p in uses_permissions if p],
        "custom_permissions": custom_permissions,
        "components_total": len(components),
        "exported_components": exported,
        "components": components,
        "deep_links": deep_links,
    }


def aapt_badging(apk_path: str) -> dict[str, Any]:
    try:
        result = _run([aapt2_bin(), "dump", "badging", apk_path], timeout=120)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"error": str(exc)}
    info: dict[str, Any] = {"permissions": []}
    for line in (result.stdout or "").splitlines():
        if line.startswith("package:"):
            for key, attr in (("name", "package"), ("versionName", "version_name"), ("versionCode", "version_code")):
                token = f"{key}='"
                if token in line:
                    info[attr] = line.split(token, 1)[1].split("'", 1)[0]
        elif line.startswith("sdkVersion:"):
            info["min_sdk"] = line.split("'", 1)[1].strip("'")
        elif line.startswith("targetSdkVersion:"):
            info["target_sdk"] = line.split("'", 1)[1].strip("'")
        elif line.startswith("uses-permission:") and "name='" in line:
            info["permissions"].append(line.split("name='", 1)[1].split("'", 1)[0])
        elif line.startswith("launchable-activity:") and "name='" in line:
            info["launchable_activity"] = line.split("name='", 1)[1].split("'", 1)[0]
    return info


# --------------------------------------------------------------------------- #
# Workspace assembly                                                          #
# --------------------------------------------------------------------------- #


def decompile_apk(apk_path: str, cache_dir: Path) -> dict[str, Any]:
    cache_dir.mkdir(parents=True, exist_ok=True)
    steps: dict[str, Any] = {}
    steps["jadx"] = _run_jadx(apk_path, cache_dir / "jadx")
    steps["apktool"] = _run_apktool(apk_path, cache_dir / "apktool")
    steps["unpacked"] = _extract_native_and_assets(apk_path, cache_dir / "unpacked")
    # Surface the decoded manifest at the workspace root for easy access.
    for candidate in (cache_dir / "jadx" / "resources" / "AndroidManifest.xml", cache_dir / "apktool" / "AndroidManifest.xml"):
        if candidate.is_file():
            shutil.copyfile(candidate, cache_dir / "AndroidManifest.xml")
            break
    return steps


def _build_manifest(cache_dir: Path, apk_path: str, sha256: str, decompile_steps: dict[str, Any]) -> dict[str, Any]:
    manifest_xml = cache_dir / "AndroidManifest.xml"
    android_intel = parse_android_manifest(manifest_xml) if manifest_xml.is_file() else {"error": "manifest not found"}
    badging = aapt_badging(apk_path)
    package = android_intel.get("package") or badging.get("package") or Path(apk_path).stem
    native_abis = decompile_steps.get("unpacked", {}).get("native_abis", [])
    android = {
        **android_intel,
        "min_sdk": android_intel.get("min_sdk") or badging.get("min_sdk"),
        "target_sdk": android_intel.get("target_sdk") or badging.get("target_sdk"),
        "version_name": android_intel.get("version_name") or badging.get("version_name"),
        "version_code": android_intel.get("version_code") or badging.get("version_code"),
        "launchable_activity": badging.get("launchable_activity"),
        "native_abis": native_abis,
    }
    return {
        "primary": {
            "kind": "apk",
            "repo": package,
            "commit": sha256,
            "requested_commit": sha256,
            "path": str(cache_dir),
            "apk_sha256": sha256,
        },
        "dependencies": [],
        "android": android,
        "decompile": decompile_steps,
    }


def apk_workspace_layout(cache_dir: Path, manifest: dict[str, Any]) -> str:
    android = manifest.get("android", {})
    exported = android.get("exported_components", []) or []
    lines = [
        f"Android APK workspace root: {cache_dir}",
        "Workspace manifest: WORKSPACE.json (rich Android attack-surface intelligence).",
        "Directory layout:",
        "- jadx/sources/        decompiled Java (best for reading app logic)",
        "- jadx/resources/      decoded AndroidManifest.xml, res/, assets/, strings",
        "- apktool/smali*/      smali (use when Java decompilation is incomplete or obfuscated)",
        "- apktool/res/         apktool-decoded resources",
        "- unpacked/lib/<abi>/  native libraries (.so)",
        "- AndroidManifest.xml  decoded manifest (copy at workspace root)",
        f"Package: {android.get('package')}  version: {android.get('version_name')} ({android.get('version_code')})  "
        f"minSdk: {android.get('min_sdk')}  targetSdk: {android.get('target_sdk')}",
        f"Exported/implicitly-exported components: {len(exported)}  |  deep links: {len(android.get('deep_links', []))}  "
        f"|  native ABIs: {', '.join(android.get('native_abis', [])) or 'none'}",
        "When reporting file_path, use the workspace-relative path (e.g. jadx/sources/com/app/Foo.java).",
    ]
    return "\n".join(lines)


def _resolve_apk_path(scan: dict[str, Any]) -> str:
    for container_key in ("configuration", "extras", "extra", "config"):
        container = scan.get(container_key)
        if isinstance(container, dict):
            value = container.get("apk_path")
            if value:
                return str(value)
    raise ApkWorkspaceError("scan configuration.apk_path is required for an APK scan")


# Bundle formats that wrap one or more APKs inside a ZIP container.
_APK_BUNDLE_SUFFIXES = {".xapk", ".apks", ".apkm", ".zip"}


def _extract_biggest_apk(bundle_path: str, data_dir: str) -> str:
    """An XAPK/APKS bundle is a ZIP of a base APK plus split/config APKs. Extract the
    biggest .apk (the base APK carries the app code) and return its path. Cached by the
    bundle's sha256 so re-scans reuse the extraction."""

    bundle_sha = sha256_file(bundle_path)
    out_dir = Path(data_dir) / "xapk-extracted" / bundle_sha
    with zipfile.ZipFile(bundle_path) as zf:
        apk_entries = [e for e in zf.infolist() if not e.is_dir() and e.filename.lower().endswith(".apk")]
        if not apk_entries:
            raise ApkWorkspaceError(f"no .apk found inside bundle {Path(bundle_path).name}")
        biggest = max(apk_entries, key=lambda e: e.file_size)
        target = out_dir / (Path(biggest.filename).name or "base.apk")
        if not target.is_file():
            out_dir.mkdir(parents=True, exist_ok=True)
            tmp = target.with_suffix(target.suffix + ".part")
            with zf.open(biggest) as src, open(tmp, "wb") as dst:
                shutil.copyfileobj(src, dst)
            tmp.replace(target)
    LOGGER.info(
        "unwrapped bundle %s -> base APK %s (%.1f MB of %d apk entries)",
        Path(bundle_path).name,
        target.name,
        biggest.file_size / (1024 * 1024),
        len(apk_entries),
    )
    return str(target)


def _resolve_scannable_apk(apk_path: str, data_dir: str) -> str:
    """Return a plain .apk to decompile. If the input is an XAPK/APKS/zip bundle (by
    suffix, or by sniffing a zip whose members include .apk files), unwrap it first."""

    p = Path(apk_path)
    if p.suffix.lower() == ".apk":
        return apk_path
    if p.suffix.lower() in _APK_BUNDLE_SUFFIXES:
        return _extract_biggest_apk(apk_path, data_dir)
    # Unknown/absent suffix: sniff. A zip that contains .apk members is a bundle.
    try:
        if zipfile.is_zipfile(apk_path):
            with zipfile.ZipFile(apk_path) as zf:
                if any(n.lower().endswith(".apk") for n in zf.namelist()):
                    return _extract_biggest_apk(apk_path, data_dir)
    except (OSError, zipfile.BadZipFile):
        pass
    return apk_path


def prepare_apk_workspace(
    *,
    data_dir: str,
    metadata_id: int,
    scan: dict[str, Any],
    **_ignored: Any,
) -> DependencyWorkspace:
    """Decompile (cached) and materialize an APK workspace as a DependencyWorkspace."""

    apk_path = _resolve_apk_path(scan)
    if not Path(apk_path).is_file():
        raise ApkWorkspaceError(f"APK not found at {apk_path}")
    # Unwrap XAPK/APKS bundles (a ZIP of base + split APKs) to the base APK before hashing
    # and decompiling, so the cache key is the actual APK we analyze.
    apk_path = _resolve_scannable_apk(apk_path, data_dir)
    sha256 = sha256_file(apk_path)
    cache_dir = Path(data_dir) / "apk-cache" / sha256
    marker = cache_dir / CACHE_MARKER

    if not marker.is_file():
        LOGGER.info("decompiling APK %s (sha256=%s) -> %s", Path(apk_path).name, sha256[:12], cache_dir)
        if cache_dir.exists():
            shutil.rmtree(cache_dir, ignore_errors=True)
        steps = decompile_apk(apk_path, cache_dir)
        manifest = _build_manifest(cache_dir, apk_path, sha256, steps)
        manifest_json = json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True)
        (cache_dir / "WORKSPACE.json").write_text(manifest_json, encoding="utf-8")
        marker.write_text(sha256 + "\n", encoding="utf-8")
        LOGGER.info(
            "decompiled %s: jadx=%s apktool=%s exported=%s deep_links=%s",
            Path(apk_path).name,
            steps.get("jadx", {}).get("ok"),
            steps.get("apktool", {}).get("ok"),
            len(manifest["android"].get("exported_components", [])),
            len(manifest["android"].get("deep_links", [])),
        )
    else:
        manifest = json.loads((cache_dir / "WORKSPACE.json").read_text(encoding="utf-8"))
        manifest_json = json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True)
        LOGGER.info("using cached APK decompilation for sha256=%s", sha256[:12])

    layout = apk_workspace_layout(cache_dir, manifest)
    job_root = Path(data_dir) / "jobs" / f"metadata-{metadata_id}"
    job_root.mkdir(parents=True, exist_ok=True)
    workspace = JobWorkspace(root_dir=str(job_root), repo_base_dir=str(cache_dir), env={})
    return DependencyWorkspace(
        workspace=workspace,
        repo_dir=str(cache_dir),
        checked_out_commit=sha256,
        manifest=manifest,
        layout=layout,
        manifest_json=manifest_json,
    )
