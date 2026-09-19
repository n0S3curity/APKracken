"""Engine-side dynamic investigation phase (Phase 3.x).

Runs the specialist agents over an APK scan's attack-surface leads, then the chain
analyst, stores adjudicated vulnerabilities + exploit chains, and re-ranks all of the
scan's findings by severity. This is the single implementation used by both the CLI
(`scripts/kritt_android.py investigate`) and the worker's automatic post-scan phase.

Gated for the worker by ENGINE_DYNAMIC_INVESTIGATION=1 and an available adb device; it is
always best-effort and never fails the scan.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any

from .evidence import (
    SNIPPET_MISMATCH,
    UNGROUNDED,
    VERIFIED,
    finding_severity,
    verify_citation,
)

LOGGER = logging.getLogger("open_kritt_engine")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _write_progress(conn, scan_id: int, progress: dict[str, Any]) -> None:
    """Publish live dynamic-investigation progress into scans.reasoning.dynamic_progress
    (the scan API already serves `reasoning`, and the UI polls it every second)."""

    progress["updated_at"] = _now()
    try:
        conn.execute(
            "update scans set reasoning = coalesce(reasoning,'{}'::jsonb) || jsonb_build_object('dynamic_progress', %s::jsonb), updated_at = now() where id=%s",
            (json.dumps(progress), scan_id),
        )
        conn.commit()
    except Exception:  # noqa: BLE001 - progress reporting must never break the phase
        LOGGER.exception("failed to write dynamic progress for scan %s", scan_id)


def _load_workspace_manifest(data_dir: str, scan: dict[str, Any]) -> dict[str, Any]:
    from .apk_workspace import sha256_file

    config = scan.get("configuration") or {}
    apk_path = config.get("apk_path") if isinstance(config, dict) else None
    sha = scan.get("commit_sha")
    if not sha or len(str(sha)) != 64:
        if not apk_path:
            raise RuntimeError("scan has no apk sha256 or apk_path")
        sha = sha256_file(apk_path)
    with open(os.path.join(data_dir, "apk-cache", str(sha), "WORKSPACE.json"), encoding="utf-8") as handle:
        return json.load(handle), os.path.join(data_dir, "apk-cache", str(sha))


def _app_namespace(package: str) -> str:
    """The app's own top-level namespace (first two package segments, e.g. com.ideomobile)."""

    parts = (package or "").split(".")
    return ".".join(parts[:2]) if len(parts) >= 2 else (package or "")


def _is_app_component(name: str, package: str) -> bool:
    """True when a component class belongs to the app's own code rather than a bundled SDK
    (androidx.*, com.google.*, com.squareup.*, …)."""

    if not name:
        return False
    ns = _app_namespace(package)
    return name == package or name.startswith(package + ".") or (bool(ns) and name.startswith(ns + "."))


def _component_exposure(android: dict[str, Any], component_name: str) -> dict[str, Any]:
    """How a component can be reached from outside the app, from manifest intel:
      - exported=True                       -> reachability 'direct'  (adb/other apps hit it directly)
      - exported=False + grantUriPermissions -> reachability 'chained' (only via a URI grant from another component)
      - exported=False, no grant            -> reachability 'internal' (in-process only)
    Returns {} for app-wide leads / components not found in the manifest."""

    if not component_name:
        return {}
    name = str(component_name).split(" ")[0]  # strip the "(label)" suffix of app-wide leads
    match = next((c for c in android.get("components", []) if c.get("name") == name), None)
    if not match:
        return {}
    exported = bool(match.get("exported")) or bool(match.get("implicitly_exported"))
    grant = bool(match.get("grant_uri_permissions"))
    reachability = "direct" if exported else ("chained" if grant else "internal")
    result = {"exported": exported, "grant_uri_permissions": grant, "reachability": reachability}
    # ContentProviders are addressed by their authority, NOT their class name — surface it
    # so a content:// URI / adb query can actually be built for the finding.
    if match.get("authorities"):
        result["authorities"] = match.get("authorities")
    return result


def build_leads(android: dict[str, Any], package: str, *, include_third_party: bool = False) -> list[dict[str, Any]]:
    """Full Android lead set: one per exported component (routed to its component-type
    specialist) plus app-wide vulnerability-class specialists. Ordered by expected value.

    By default only the app's own components are investigated; bundled third-party SDK
    components (androidx/firebase/picasso/etc.) are skipped unless include_third_party."""

    deep_link_targets = {dl["component"] for dl in android.get("deep_links", [])}
    dl_uris = [
        f"{s}://{(dl.get('hosts') or [''])[0]}/web?url="
        for dl in android.get("deep_links", [])
        for s in dl.get("schemes", [])
    ]
    exported = android.get("exported_components", [])
    leads: list[dict[str, Any]] = []

    def is_webview(name: str) -> bool:
        return name in deep_link_targets or "webview" in name.lower()

    def keep(name: str) -> bool:
        return include_third_party or _is_app_component(name, package)

    # EXPORTED COMPONENTS FIRST — they are the primary externally-reachable attack surface.
    # 1. WebView / deep-link activities (highest value).
    for c in exported:
        name = c.get("name") or ""
        if c.get("kind") in ("activity", "activity-alias") and is_webview(name) and keep(name):
            leads.append({"component": name, "vulnerability_type": "webview / deep link", "kind": c.get("kind"), "deep_links": dl_uris})

    # 2. Exported ContentProviders.
    for c in android.get("components", []):
        if c.get("kind") == "provider" and c.get("authorities") and keep(c.get("name") or ""):
            leads.append({"component": c.get("name"), "vulnerability_type": "content provider", "kind": "provider", "authorities": c.get("authorities")})

    # 3. Exported Services.
    for c in exported:
        if c.get("kind") == "service" and keep(c.get("name") or ""):
            leads.append({"component": c.get("name"), "vulnerability_type": "exported service", "kind": "service"})

    # 4. Exported BroadcastReceivers.
    for c in exported:
        if c.get("kind") == "receiver" and keep(c.get("name") or ""):
            leads.append({"component": c.get("name"), "vulnerability_type": "exported receiver", "kind": "receiver"})

    # 5. Other exported Activities (non-WebView).
    for c in exported:
        name = c.get("name") or ""
        if c.get("kind") in ("activity", "activity-alias") and not is_webview(name) and keep(name):
            leads.append({"component": name, "vulnerability_type": "exported activity", "kind": "activity", "deep_links": dl_uris})

    # 5b. Native libraries (JNI). One lead — the native specialist uses list_native_libs /
    # native_recon / native_disasm to enumerate the bundled .so files and investigate the
    # JNI attack surface (command injection, overflows, unchecked JNI input, secrets).
    if android.get("native_abis"):
        leads.append({"component": f"{package} (native libraries / JNI)", "vulnerability_type": "native library", "kind": "native", "deep_links": dl_uris})

    # 6. App-wide vulnerability-class specialists (whole-app scans, run after components).
    for label in [
        "webview UXSS (universal XSS)",
        "insecure storage",
        "hardcoded secrets",
        "cryptography",
        "network / TLS security",
        "SQL injection",
        "sensitive logging",
        "custom permissions",
        "PendingIntent usage",
        "race conditions",
        "insecure broadcasts and receivers",
        "intent redirection",
    ]:
        leads.append({"component": f"{package} ({label})", "vulnerability_type": label, "kind": "app-wide", "deep_links": dl_uris})
    return leads


def _finding_row(scan_id: int, workflow_id: int, json_answer: dict[str, Any]) -> tuple:
    return (scan_id, workflow_id, json.dumps(json_answer))


def check_fileprovider_paths(workspace_dir: str) -> dict[str, Any] | None:
    """Deterministic FileProvider over-exposure check: a <root-path path="/"> or
    <external-path path="."> grants access to the whole filesystem / external storage.
    A small model won't reliably flag this, so decide it by rule, not by inference."""

    import re
    from pathlib import Path

    for rel in (
        "jadx/resources/res/xml/provider_paths.xml",
        "apktool/res/xml/provider_paths.xml",
        "jadx/resources/res/xml/file_paths.xml",
        "apktool/res/xml/file_paths.xml",
        "jadx/resources/res/xml/paths.xml",
        "apktool/res/xml/filepaths.xml",
    ):
        path = Path(workspace_dir) / rel
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        dangerous = re.search(r'<(root-path|external-path|files-path)[^>]*path\s*=\s*"(/|\.|)"', text)
        if dangerous:
            numbered = "\n".join(f"{i + 1:>4}  {ln}" for i, ln in enumerate(text.splitlines()))
            return {
                "rel": rel,
                "matched": dangerous.group(0),
                "code_evidence": numbered,
            }
    return None


# Well-known secret formats. If the VALUE matches one of these it is a secret regardless
# of surrounding naming — these prefixes/shapes do not occur by accident.
_KNOWN_SECRET_FORMAT = (
    r"AKIA[0-9A-Z]{16}"                              # AWS access key id
    r"|AIza[0-9A-Za-z_\-]{30,}"                      # Google API key
    r"|ya29\.[0-9A-Za-z_\-]{20,}"                    # Google OAuth token
    r"|sk_(?:live|test)_[0-9A-Za-z]{16,}"            # Stripe secret key
    r"|ghp_[0-9A-Za-z]{30,}|gho_[0-9A-Za-z]{30,}"    # GitHub tokens
    r"|xox[baprs]-[0-9A-Za-z\-]{10,}"                # Slack token
    r"|eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"  # JWT
    r"|-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"
)

# Patterns that surface a *candidate* literal. Whether the captured VALUE is actually a
# secret is decided by _looks_like_secret_value below (a name containing "token" assigned
# to the label "token" is not a secret). Each entry: (regex, label).
_SECRET_PATTERNS: list[tuple[str, str]] = [
    # credential map entries: map.put("shopuser", "!ns3csh0p") — key names a principal.
    (r'\.put\(\s*"([^"]*(?:user|login|email|account|pass|pwd|secret|cred)[^"]*)"\s*,\s*"([^"]{4,})"\s*\)', "hardcoded credential map entry"),
    # assignment to a secret-named variable/field: String apiSecret = "…"
    (r'(?i)\b(?:String|val|var|final\s+String)\s+(\w*(?:password|passwd|secret|apikey|api_key|authkey|privatekey|accesskey|client_secret|clientsecret)\w*)\s*=\s*"([^"]{6,})"', "hardcoded secret assignment"),
    # any literal matching a known secret format, wherever it appears
    (rf'"({_KNOWN_SECRET_FORMAT})"', "hardcoded secret (known format)"),
    (rf'({_KNOWN_SECRET_FORMAT})', "embedded key material"),
    # bearer / basic auth literals with real material
    (r'"(Bearer\s+[A-Za-z0-9\-_\.=]{16,})"', "hardcoded bearer token"),
    (r'"(Basic\s+[A-Za-z0-9+/=]{16,})"', "hardcoded basic-auth token"),
]

# Third-party / SDK package roots. Their constants (JSON keys, header names, analytics
# labels, regex tokenizers) are the dominant source of false positives, so we never treat
# them as the app's own hardcoded secrets.
_LIBRARY_PATH_MARKERS = (
    "/androidx/", "/android/support/", "/kotlin/", "/kotlinx/", "/org/jetbrains/",
    "/com/google/", "/okhttp3/", "/okio/", "/io/grpc/", "/retrofit2/", "/javax/",
    "/org/apache/", "/io/reactivex/", "/com/squareup/", "/com/facebook/", "/dagger/",
    "/io/sentry/", "/com/bumptech/", "/org/json/", "/j$/", "/kotlinx/", "/com/razorpay/",
    "/com/cloudinary/", "/com/stripe/", "/io/flutter/", "/com/microsoft/", "/reactivex/",
)


def _shannon_entropy(s: str) -> float:
    from math import log2

    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * log2(c / n) for c in counts.values())


def _looks_like_secret_value(value: str) -> bool:
    """True only for values that plausibly ARE a secret — not labels, key names, header
    names, resource paths, dotted class names, format strings, or messages."""

    import re

    if re.search(_KNOWN_SECRET_FORMAT, value):
        return True
    if len(value) < 8 or len(value) > 200:
        return False
    if any(ch in value for ch in " %{}\\[]()"):
        return False  # sentences, format strings, regex/template/code blobs
    # A bare identifier / snake / CONST / camelCase word is a name, not a secret.
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value):
        return False
    # kebab or dotted lowercase labels: x-goog-api-key, com.foo.bar, next_page.token
    if re.fullmatch(r"[a-z0-9]+(?:[-._:][a-z0-9]+)+", value):
        return False
    # resource / URL paths and dotted names
    if "/" in value or value.count(".") >= 1:
        return False
    # Require genuine mixing (>=3 of lower/upper/digit/symbol) and real entropy.
    classes = sum(bool(re.search(p, value)) for p in (r"[a-z]", r"[A-Z]", r"[0-9]", r"[^A-Za-z0-9]"))
    return classes >= 3 and _shannon_entropy(value) >= 2.5


def _app_source_roots(workspace_dir, package: str | None):
    """Prefer the app's own package sub-tree; fall back to all sources minus libraries."""

    from pathlib import Path

    src = Path(workspace_dir) / "jadx" / "sources"
    if package:
        pkg_root = src / Path(*package.split("."))
        if pkg_root.is_dir():
            return [pkg_root]
    if src.is_dir():
        return [src]
    # Source-repo scan: there is no decompiled tree, so the checkout itself is the source root.
    # Without this the deterministic checks silently scanned nothing on every non-APK target.
    root = Path(workspace_dir)
    return [root] if root.is_dir() else []


def check_hardcoded_secrets(workspace_dir: str, *, package: str | None = None, max_files: int = 4000) -> list[dict[str, Any]]:
    """Deterministic hardcoded-secret scan over the app's decompiled sources.

    High precision by design: it scans the app's own package first (never bundled SDKs),
    and every candidate literal must pass _looks_like_secret_value — a field merely NAMED
    "token"/"password" assigned to a plain label is not reported. A small model finds real
    secrets only intermittently, so we decide the unambiguous ones by rule."""

    import re
    from pathlib import Path

    compiled = [(re.compile(pat), label) for pat, label in _SECRET_PATTERNS]
    roots = _app_source_roots(workspace_dir, package)
    hits: list[dict[str, Any]] = []
    seen: set[str] = set()
    scanned = 0

    for root in roots:
        for fp in root.rglob("*.java"):
            if scanned >= max_files:
                break
            scanned += 1
            low = fp.as_posix().lower()
            if any(marker in low for marker in _LIBRARY_PATH_MARKERS):
                continue  # never flag bundled third-party SDK constants
            try:
                text = fp.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            lines = text.splitlines()
            for lineno, line in enumerate(lines, 1):
                if line.lstrip().startswith("@Metadata") or "d1 = {" in line or "d2 = {" in line:
                    continue  # kotlin metadata blobs
                for rx, label in compiled:
                    m = rx.search(line)
                    if not m:
                        continue
                    groups = [g for g in m.groups() if g]
                    value = groups[-1] if groups else m.group(0)
                    if not _looks_like_secret_value(value):
                        continue
                    rel = fp.relative_to(workspace_dir).as_posix()
                    key = f"{rel}:{value}"
                    if key in seen:
                        continue
                    seen.add(key)
                    lo, hi = max(0, lineno - 4), min(len(lines), lineno + 3)
                    ctx = "\n".join(f"{i + 1:>4}  {lines[i]}" for i in range(lo, hi))
                    hits.append({
                        "rel": rel,
                        "line": lineno,
                        "label": label,
                        "match": m.group(0).strip(),
                        "value": value,
                        "code_evidence": ctx,
                    })
    return hits


def run_for_scan(conn, scan_id: int, *, data_dir: str, max_leads: int = 8, device=None, static_only: bool = False) -> dict[str, Any]:
    """Investigate one APK scan's leads with specialists + chain analyst; store + rank.

    `conn` is a psycopg connection. Returns a summary dict. Commits as it goes.
    """

    from . import adb, specialist_agent as sa

    row = conn.execute(
        "select id, workflow_id, repo_full, commit_sha, configuration from scans where id=%s", (scan_id,)
    ).fetchone()
    if row is None:
        raise RuntimeError(f"scan {scan_id} not found")
    scan = row if isinstance(row, dict) else {
        "id": row[0], "workflow_id": row[1], "repo_full": row[2], "commit_sha": row[3], "configuration": row[4]
    }
    manifest, workspace_dir = _load_workspace_manifest(data_dir, scan)
    android = manifest.get("android", {})
    package = android.get("package") or scan["repo_full"]
    cfg = scan.get("configuration") if isinstance(scan.get("configuration"), dict) else {}
    include_third_party = bool(cfg.get("include_third_party"))
    if not static_only and device is None:
        device = adb.get_device()
    if static_only:
        device = None
    workflow_id = int(scan["workflow_id"])

    conn.execute(
        "delete from workflows.vulnerabilities where scan_id=%s and json_answer->>'source' in ('dynamic','specialist','chain')",
        (scan_id,),
    )
    conn.commit()

    # Load the editable specialist prompts from the DB (seeded as agent skills). The
    # deterministic router picks which one runs per component; edits in the UI take effect
    # on the next scan. Missing rows fall back to the built-in prompts.
    try:
        sa.ensure_mobile_specialist_skills(conn)
        specialist_prompts = sa.load_mobile_specialist_prompts(conn)
    except Exception:  # noqa: BLE001 - never block the scan on skill loading
        specialist_prompts = None

    active_leads = build_leads(android, package, include_third_party=include_third_party)[:max_leads]
    progress: dict[str, Any] = {
        "status": "running",
        "phase": "specialists",
        "mode": "static" if static_only else "dynamic",
        "total": len(active_leads),
        "done": 0,
        "vulnerable": 0,
        "current": None,
        "started_at": _now(),
        "leads": [
            {"index": i, "component": lead["component"], "specialist": sa.pick_specialist(lead), "state": "pending"}
            for i, lead in enumerate(active_leads)
        ],
    }
    _write_progress(conn, scan_id, progress)

    confirmed: list[dict[str, Any]] = []
    for i, lead in enumerate(active_leads):
        progress["current"] = {"component": lead["component"], "specialist": sa.pick_specialist(lead)}
        progress["leads"][i]["state"] = "running"
        _write_progress(conn, scan_id, progress)
        try:
            finding = sa.investigate_lead(lead, workspace_dir=workspace_dir, package=package, device=device, static_only=static_only, specialist_prompts=specialist_prompts)
        except Exception:  # noqa: BLE001 - one lead failing must not abort the phase
            LOGGER.exception("specialist failed for lead %s", lead.get("component"))
            progress["leads"][i]["state"] = "error"
            progress["done"] = i + 1
            _write_progress(conn, scan_id, progress)
            continue
        is_vuln = bool(finding.get("is_vulnerable")) and not bool(finding.get("false_positive"))
        progress["leads"][i]["state"] = "vulnerable" if is_vuln else "clean"
        if is_vuln:
            progress["leads"][i]["severity"] = finding.get("severity_score")
            progress["vulnerable"] += 1
        progress["done"] = i + 1
        _write_progress(conn, scan_id, progress)
        if not is_vuln:
            continue
        finding["component"] = lead["component"]
        confirmed.append(finding)
        exposure = _component_exposure(android, lead["component"])
        json_answer = {
            "source": "specialist",
            "summary": finding.get("title"),
            "vulnerability_type": finding.get("vulnerability_type"),
            "component": lead["component"],
            # Manifest-derived reachability so the UI can flag whether the component is
            # directly hittable (exported) or only exploitable via a chain.
            "exported": exposure.get("exported"),
            "reachability": exposure.get("reachability"),
            "grant_uri_permissions": exposure.get("grant_uri_permissions"),
            "authorities": exposure.get("authorities"),
            "file_path": finding.get("code_file") or ("jadx/sources/" + str(lead["component"]).split(" ")[0].replace(".", "/") + ".java"),
            "line": 0,
            "explanation": f"{finding.get('impact')}\n\nStatic: {finding.get('static_evidence')}\n\nDynamic proof: {finding.get('dynamic_evidence')}\n\nChainable primitive: {finding.get('chainable_primitive')}",
            "malicious_input_example": finding.get("poc"),
            "exploitable": bool(finding.get("exploitable_externally")),
            "confidence": finding.get("confidence"),
            "severity_score": finding.get("severity_score"),
            # Structured evidence for the finding-detail timeline.
            "static_evidence": finding.get("static_evidence"),
            "dynamic_evidence": finding.get("dynamic_evidence"),
            "poc": finding.get("poc"),
            "impact": finding.get("impact"),
            "chainable_primitive": finding.get("chainable_primitive"),
            "code_file": finding.get("code_file"),
            "code_evidence": finding.get("code_evidence"),
        }
        conn.execute(
            "insert into workflows.vulnerabilities (scan_id, workflow_id, scan_metadata_id, prev_id, json_answer) values (%s,%s,0,0,%s)",
            (scan_id, workflow_id, json.dumps(json_answer)),
        )
        conn.commit()

    # Deterministic FileProvider over-exposure check (models under-report config bugs).
    fp = check_fileprovider_paths(workspace_dir)
    if fp:
        fp_provider = next(
            (c for c in android.get("components", []) if c.get("kind") == "provider" and c.get("grant_uri_permissions")),
            None,
        )
        fp_exposure = (
            _component_exposure(android, fp_provider.get("name")) if fp_provider else {}
        ) or {"exported": False, "grant_uri_permissions": True, "reachability": "chained"}
        json_answer = {
            "source": "specialist",
            "summary": "FileProvider exposes the entire filesystem via an over-broad path config",
            "vulnerability_type": "Insecure FileProvider Paths",
            "component": (fp_provider or {}).get("name") or "FileProvider (provider_paths)",
            "exported": fp_exposure.get("exported"),
            "reachability": fp_exposure.get("reachability"),
            "grant_uri_permissions": fp_exposure.get("grant_uri_permissions"),
            "authorities": fp_exposure.get("authorities") or (fp_provider or {}).get("authorities"),
            "file_path": fp["rel"],
            "line": 0,
            "explanation": (
                f"The FileProvider path configuration grants access to the whole filesystem / external storage "
                f"({fp['matched']}). "
                + (
                    "This provider is NOT exported, so it cannot be reached directly with an `adb content query` — "
                    "it is exploitable only when another component hands out a content:// URI grant (a chain: e.g. a "
                    "setResult / intent redirection / an exported activity that returns a grantable URI). "
                    if fp_exposure.get("reachability") == "chained"
                    else "Any app granted a content:// URI from this app can read arbitrary app-private files. "
                )
            ),
            "malicious_input_example": (
                "getContentResolver().openInputStream(Uri.parse("
                "\"content://<authority>/root/data/data/<pkg>/shared_prefs/Prefs.xml\"))"
            ),
            "exploitable": True,
            "confidence": "high",
            "severity_score": 7,
            "static_evidence": f"{fp['rel']}: {fp['matched']}",
            "dynamic_evidence": "not tested (deterministic static config check)",
            "poc": (
                "// malicious app that received a content:// grant from this app:\n"
                "getContentResolver().openInputStream(Uri.parse(\n"
                "  \"content://com.insecureshop.file_provider/root/data/data/com.insecureshop/shared_prefs/Prefs.xml\"))"
            ),
            "chainable_primitive": "read arbitrary app-private files via an over-broad FileProvider path",
            "code_file": fp["rel"],
            "code_evidence": fp["code_evidence"],
        }
        conn.execute(
            "insert into workflows.vulnerabilities (scan_id, workflow_id, scan_metadata_id, prev_id, json_answer) values (%s,%s,0,0,%s)",
            (scan_id, workflow_id, json.dumps(json_answer)),
        )
        conn.commit()
        confirmed.append({"title": json_answer["summary"], "vulnerability_type": json_answer["vulnerability_type"], "component": json_answer["component"], "chainable_primitive": json_answer["chainable_primitive"], "severity_score": 7})

    # Deterministic hardcoded-secret scan (models find these only intermittently).
    for hit in check_hardcoded_secrets(workspace_dir, package=package):
        json_answer = {
            "source": "specialist",
            "summary": f"Hardcoded secret in source: {hit['label']}",
            "vulnerability_type": "Hardcoded Credentials / Secrets",
            "component": hit["rel"].split("/sources/")[-1].removesuffix(".java").replace("/", "."),
            "file_path": hit["rel"],
            "line": hit["line"],
            "explanation": (
                f"A {hit['label']} is embedded directly in the decompiled application code "
                f"({hit['rel']}:{hit['line']}). Anyone who unpacks the APK (jadx/apktool) recovers this "
                f"value verbatim — it provides no confidentiality. For login credentials this is a full "
                f"authentication bypass: any user can sign in with the shipped username/password."
            ),
            "malicious_input_example": f"Recovered literal: {hit['value']}",
            "exploitable": True,
            "confidence": "high",
            "severity_score": 8,
            "static_evidence": f"{hit['rel']}:{hit['line']}  {hit['match']}",
            "dynamic_evidence": "not tested (deterministic static string scan)",
            "poc": (
                "# unpack the shipped APK and read the credential straight out of the code:\n"
                "jadx -d out app.apk\n"
                f"grep -rn '{hit['value']}' out/sources/\n"
                f"# then authenticate with the recovered secret ({hit['value']})."
            ),
            "chainable_primitive": "authenticate/authorize using a secret shipped inside the APK",
            "code_file": hit["rel"],
            "code_evidence": hit["code_evidence"],
        }
        conn.execute(
            "insert into workflows.vulnerabilities (scan_id, workflow_id, scan_metadata_id, prev_id, json_answer) values (%s,%s,0,0,%s)",
            (scan_id, workflow_id, json.dumps(json_answer)),
        )
        conn.commit()
        confirmed.append({"title": json_answer["summary"], "vulnerability_type": json_answer["vulnerability_type"], "component": json_answer["component"], "chainable_primitive": json_answer["chainable_primitive"], "severity_score": 8})

    chains = []
    if len(confirmed) >= 2:
        progress["phase"] = "chain-analysis"
        progress["current"] = {"component": "correlating findings into attack chains", "specialist": "chain_analyst"}
        _write_progress(conn, scan_id, progress)
        try:
            chains = sa.chain_analyst(confirmed, workspace_dir=workspace_dir, package=package, android_intel=android, device=device, static_only=static_only)
        except Exception:  # noqa: BLE001
            LOGGER.exception("chain analyst failed")
    for ch in chains:
        json_answer = {
            "source": "chain",
            "summary": "CHAIN: " + str(ch.get("title")),
            "vulnerability_type": "Exploit Chain",
            "component": ", ".join(ch.get("components_involved", [])),
            "file_path": "(multiple)",
            "line": 0,
            "explanation": f"{ch.get('combined_impact')}\n\nSteps:\n" + "\n".join(f"  {i+1}. {s}" for i, s in enumerate(ch.get("steps", []))) + f"\n\nFeasibility: {ch.get('feasibility')}",
            "malicious_input_example": ch.get("poc"),
            "exploitable": True,
            "severity_score": ch.get("severity_score"),
            # Structured evidence for the finding-detail timeline.
            "chain_steps": ch.get("steps", []),
            "components_involved": ch.get("components_involved", []),
            "combined_impact": ch.get("combined_impact"),
            "feasibility": ch.get("feasibility"),
            "poc": ch.get("poc"),
        }
        conn.execute(
            "insert into workflows.vulnerabilities (scan_id, workflow_id, scan_metadata_id, prev_id, json_answer) values (%s,%s,0,0,%s)",
            (scan_id, workflow_id, json.dumps(json_answer)),
        )
        conn.commit()

    # Ground every citation against the snapshot BEFORE the model re-checks anything: a
    # finding pointing at code that is not there is disproved without spending model steps.
    try:
        run_evidence_validation(conn, scan_id, workspace_dir)
    except Exception:  # noqa: BLE001
        LOGGER.exception("evidence validation failed for scan %s", scan_id)

    # False-positive verification: re-check High+ findings like a human researcher.
    if cfg.get("fp_verify", True):
        try:
            run_fp_verification(conn, scan_id, data_dir=data_dir, device=device, static_only=static_only)
        except Exception:  # noqa: BLE001
            LOGGER.exception("FP verification failed for scan %s", scan_id)

    _rerank(conn, scan_id)
    progress["phase"] = "done"
    progress["status"] = "done"
    progress["current"] = None
    progress["chains"] = len(chains)
    progress["finished_at"] = _now()
    _write_progress(conn, scan_id, progress)
    summary = {"leads": len(active_leads), "vulnerabilities": len(confirmed), "chains": len(chains)}
    LOGGER.info("dynamic investigation for scan %s: %s", scan_id, summary)
    return summary


def _rerank(conn, scan_id: int) -> None:
    rows = conn.execute("select id, json_answer from workflows.vulnerabilities where scan_id=%s", (scan_id,)).fetchall()

    def score(r) -> float:
        j = (r[1] if not isinstance(r, dict) else r["json_answer"]) or {}
        base = finding_severity(j)
        # A citation the snapshot contradicts outright sinks below everything else: the
        # finding points at code that is not there, so it cannot be a real vulnerability.
        if j.get("evidence_verdict") in UNGROUNDED:
            return base - 2000
        # Likely false positives sink to the bottom of the ranking.
        if j.get("fp_verdict") == "false_positive":
            return base - 1000
        if j.get("evidence_verdict") == SNIPPET_MISMATCH:
            base -= 3
        return base + 0.5 if j.get("source") == "chain" else base

    for rank, r in enumerate(sorted(rows, key=score, reverse=True), start=1):
        rid = r[0] if not isinstance(r, dict) else r["id"]
        conn.execute("update workflows.vulnerabilities set rank=%s where id=%s", (rank, rid))
    conn.commit()


# --------------------------------------------------------------------------- #
# Android Deep Research + Dynamic — the layered 3-phase pipeline                #
#   Phase 1: Mobile PT triage (static specialists + deterministic checks)       #
#   Phase 2: Deep research (exploit-chain synthesis + background-seeded deeper   #
#            re-investigation of the top findings)                               #
#   Phase 3: Dynamic verification of the top high-severity findings on a         #
#            connected device (falls back to static-only when none is present)   #
# Built entirely on the proven specialist machinery; findings carry             #
# source='specialist'/'chain' so they render with code + PoC + on-device proof. #
# --------------------------------------------------------------------------- #


def _insert_vuln(conn, scan_id: int, workflow_id: int, json_answer: dict[str, Any]) -> int:
    row = conn.execute(
        "insert into workflows.vulnerabilities (scan_id, workflow_id, scan_metadata_id, prev_id, json_answer) "
        "values (%s,%s,0,0,%s) returning id",
        (scan_id, workflow_id, json.dumps(json_answer)),
    ).fetchone()
    conn.commit()
    return int(row[0] if not isinstance(row, dict) else row["id"])


def _specialist_json_answer(finding: dict[str, Any], lead: dict[str, Any], android: dict[str, Any], *, phase: str) -> dict[str, Any]:
    """Same shape run_for_scan stores for a specialist finding (so it renders identically),
    tagged with the pipeline phase it came from."""

    exposure = _component_exposure(android, lead["component"])
    return {
        "source": "specialist",
        "phase_origin": phase,
        "summary": finding.get("title"),
        "vulnerability_type": finding.get("vulnerability_type"),
        "component": lead["component"],
        "exported": exposure.get("exported"),
        "reachability": exposure.get("reachability"),
        "grant_uri_permissions": exposure.get("grant_uri_permissions"),
        "authorities": exposure.get("authorities"),
        "file_path": finding.get("code_file") or ("jadx/sources/" + str(lead["component"]).split(" ")[0].replace(".", "/") + ".java"),
        "line": 0,
        "explanation": f"{finding.get('impact')}\n\nStatic: {finding.get('static_evidence')}\n\nDynamic proof: {finding.get('dynamic_evidence')}\n\nChainable primitive: {finding.get('chainable_primitive')}",
        "malicious_input_example": finding.get("poc"),
        "exploitable": bool(finding.get("exploitable_externally")),
        "confidence": finding.get("confidence"),
        "severity_score": finding.get("severity_score"),
        "static_evidence": finding.get("static_evidence"),
        "dynamic_evidence": finding.get("dynamic_evidence"),
        "poc": finding.get("poc"),
        "impact": finding.get("impact"),
        "chainable_primitive": finding.get("chainable_primitive"),
        "code_file": finding.get("code_file"),
        "code_evidence": finding.get("code_evidence"),
    }


def check_ssl_bypass(workspace_dir: str, *, package: str | None = None, max_files: int = 4000) -> list[dict[str, Any]]:
    """WebViewClient.onReceivedSslError implementations that call handler.proceed().

    A textbook, fully deterministic MITM bug: the app accepts ANY TLS certificate. The
    specialists kept missing it because it lives in a helper class no exported component
    names directly, so no attack-surface lead ever pointed at it. Pattern matching finds it
    with certainty and costs no model time."""

    roots = _app_source_roots(workspace_dir, package)
    out: list[dict[str, Any]] = []
    seen = 0
    for root in roots:
        for dirpath, _dirs, files in os.walk(root):
            for name in files:
                if not name.endswith((".java", ".kt")):
                    continue
                seen += 1
                if seen > max_files:
                    return out
                full = os.path.join(dirpath, name)
                try:
                    text = open(full, encoding="utf-8", errors="replace").read()
                except OSError:
                    continue
                if "onReceivedSslError" not in text:
                    continue
                lines = text.splitlines()
                for i, line in enumerate(lines):
                    # The real override, not the Kotlin @Metadata blob that also spells the
                    # method name inside a string literal.
                    if "onReceivedSslError(" not in line or "@Metadata" in line:
                        continue
                    # The override body: proceed() inside it means every bad cert is accepted.
                    window = lines[i : i + 12]
                    hit = next((j for j, w in enumerate(window) if ".proceed()" in w), None)
                    if hit is None:
                        continue
                    rel = os.path.relpath(full, workspace_dir).replace("\\", "/")
                    out.append({
                        "rel": rel,
                        "line": i + hit + 1,
                        "evidence": "\n".join(window[: hit + 1]).strip(),
                    })
                    break
    return out


def _deterministic_findings(workspace_dir: str, android: dict[str, Any], package: str) -> list[dict[str, Any]]:
    """The deterministic FileProvider + hardcoded-secret findings as json_answer dicts
    (source='specialist'), identical to what run_for_scan produces inline."""

    out: list[dict[str, Any]] = []
    for ssl in check_ssl_bypass(workspace_dir, package=package):
        out.append({
            "source": "specialist",
            "summary": "WebView accepts any TLS certificate (onReceivedSslError calls proceed)",
            "vulnerability_type": "Improper Certificate Validation",
            "component": os.path.splitext(os.path.basename(ssl["rel"]))[0],
            "exported": False,
            "reachability": "direct",
            "file_path": ssl["rel"],
            "line": ssl["line"],
            "explanation": (
                "This WebViewClient overrides onReceivedSslError and calls handler.proceed(), so the WebView "
                "silently accepts expired, self-signed, and attacker-supplied certificates. Any network attacker "
                "on the same path (public Wi-Fi, hostile DNS, a malicious proxy) can machine-in-the-middle every "
                "page and request the WebView loads, reading and rewriting traffic including credentials and "
                "session tokens."
            ),
            "code_evidence": ssl["evidence"],
            "severity_score": 7,
            "confidence": "high",
            "exploitable": True,
            "malicious_actor": "a network attacker sharing the victim's network path",
            "poc": (
                "Put the device behind mitmproxy with an untrusted CA and open any WebView screen; the page "
                "loads instead of showing an SSL warning, and traffic is readable in the proxy."
            ),
        })
    fp = check_fileprovider_paths(workspace_dir)
    if fp:
        fp_provider = next(
            (c for c in android.get("components", []) if c.get("kind") == "provider" and c.get("grant_uri_permissions")),
            None,
        )
        fp_exposure = (
            _component_exposure(android, fp_provider.get("name")) if fp_provider else {}
        ) or {"exported": False, "grant_uri_permissions": True, "reachability": "chained"}
        out.append({
            "source": "specialist",
            "summary": "FileProvider exposes the entire filesystem via an over-broad path config",
            "vulnerability_type": "Insecure FileProvider Paths",
            "component": (fp_provider or {}).get("name") or "FileProvider (provider_paths)",
            "exported": fp_exposure.get("exported"),
            "reachability": fp_exposure.get("reachability"),
            "grant_uri_permissions": fp_exposure.get("grant_uri_permissions"),
            "authorities": fp_exposure.get("authorities") or (fp_provider or {}).get("authorities"),
            "file_path": fp["rel"],
            "line": 0,
            "explanation": (
                f"The FileProvider path configuration grants access to the whole filesystem / external storage "
                f"({fp['matched']}). "
                + (
                    "This provider is NOT exported, so it cannot be reached directly with an `adb content query` — "
                    "it is exploitable only when another component hands out a content:// URI grant (a chain). "
                    if fp_exposure.get("reachability") == "chained"
                    else "Any app granted a content:// URI from this app can read arbitrary app-private files. "
                )
            ),
            "malicious_input_example": (
                "getContentResolver().openInputStream(Uri.parse("
                "\"content://<authority>/root/data/data/<pkg>/shared_prefs/Prefs.xml\"))"
            ),
            "exploitable": True,
            "confidence": "high",
            "severity_score": 7,
            "static_evidence": f"{fp['rel']}: {fp['matched']}",
            "dynamic_evidence": "not tested (deterministic static config check)",
            "poc": (
                "// malicious app that received a content:// grant from this app:\n"
                "getContentResolver().openInputStream(Uri.parse(\n"
                "  \"content://com.insecureshop.file_provider/root/data/data/com.insecureshop/shared_prefs/Prefs.xml\"))"
            ),
            "chainable_primitive": "read arbitrary app-private files via an over-broad FileProvider path",
            "code_file": fp["rel"],
            "code_evidence": fp["code_evidence"],
        })
    for hit in check_hardcoded_secrets(workspace_dir, package=package):
        out.append({
            "source": "specialist",
            "summary": f"Hardcoded secret in source: {hit['label']}",
            "vulnerability_type": "Hardcoded Credentials / Secrets",
            "component": hit["rel"].split("/sources/")[-1].removesuffix(".java").replace("/", "."),
            "file_path": hit["rel"],
            "line": hit["line"],
            "explanation": (
                f"A {hit['label']} is embedded directly in the decompiled application code "
                f"({hit['rel']}:{hit['line']}). Anyone who unpacks the APK (jadx/apktool) recovers this "
                f"value verbatim — it provides no confidentiality. For login credentials this is a full "
                f"authentication bypass: any user can sign in with the shipped username/password."
            ),
            "malicious_input_example": f"Recovered literal: {hit['value']}",
            "exploitable": True,
            "confidence": "high",
            "severity_score": 8,
            "static_evidence": f"{hit['rel']}:{hit['line']}  {hit['match']}",
            "dynamic_evidence": "not tested (deterministic static string scan)",
            "poc": (
                "# unpack the shipped APK and read the credential straight out of the code:\n"
                "jadx -d out app.apk\n"
                f"grep -rn '{hit['value']}' out/sources/\n"
                f"# then authenticate with the recovered secret ({hit['value']})."
            ),
            "chainable_primitive": "authenticate/authorize using a secret shipped inside the APK",
            "code_file": hit["rel"],
            "code_evidence": hit["code_evidence"],
        })
    return out


def _findings_background(stored: list[dict[str, Any]]) -> str:
    lines = []
    for s in stored:
        ja = s["ja"]
        lines.append(
            f"- [{ja.get('vulnerability_type')}] {ja.get('summary')} in {ja.get('component')} "
            f"(severity {ja.get('severity_score')}, {ja.get('reachability')})"
        )
    return "Other findings already confirmed in this app (use as leads/background, not finished work):\n" + "\n".join(lines[:20])


def _enrich_finding(base: dict[str, Any], deeper: dict[str, Any]) -> dict[str, Any]:
    """Merge a deeper re-investigation into an existing finding, only ever strengthening it
    (longer evidence/PoC, higher severity) — never downgrading a confirmed finding."""

    out = dict(base)

    def take_longer(dst_key: str, src_key: str | None = None) -> None:
        new = deeper.get(src_key or dst_key)
        if new and len(str(new)) > len(str(out.get(dst_key) or "")):
            out[dst_key] = new

    take_longer("code_evidence")
    take_longer("poc")
    take_longer("static_evidence")
    take_longer("impact")
    take_longer("chainable_primitive")
    try:
        out["severity_score"] = max(float(out.get("severity_score") or 0), float(deeper.get("severity_score") or 0))
    except (TypeError, ValueError):
        pass
    out["deep_researched"] = True
    out["malicious_input_example"] = out.get("poc")
    out["explanation"] = (
        f"{out.get('impact')}\n\nStatic: {out.get('static_evidence')}\n\n"
        f"Dynamic proof: {out.get('dynamic_evidence')}\n\nChainable primitive: {out.get('chainable_primitive')}"
    )
    return out


def _deep_link_uris(android: dict[str, Any]) -> list[str]:
    return [
        f"{s}://{(dl.get('hosts') or [''])[0]}/web?url="
        for dl in android.get("deep_links", [])
        for s in dl.get("schemes", [])
    ]


def _lead_from_finding(ja: dict[str, Any], android: dict[str, Any]) -> dict[str, Any]:
    """Reconstruct an investigation lead from a stored finding, so its dynamic verification
    routes to the right specialist and can build a content:// URI / deep link on device."""

    comp = str(ja.get("component") or "")
    base = comp.split(" ")[0]
    match = next((c for c in android.get("components", []) if c.get("name") == base), None)
    return {
        "component": comp,
        "vulnerability_type": ja.get("vulnerability_type"),
        "kind": (match or {}).get("kind") or "",
        "authorities": ja.get("authorities") or (match or {}).get("authorities"),
        "deep_links": _deep_link_uris(android),
    }


def _apply_dynamic_result(
    ja: dict[str, Any], verified: dict[str, Any] | None, *, has_device: bool, error: str | None = None
) -> dict[str, Any]:
    """Merge an on-device verification result INTO an existing finding — updating only the
    dynamic-investigation fields (status, evidence, on-device transcript, PoC), never
    discarding the finding or its static evidence."""

    out = dict(ja)
    if not has_device:
        out["dynamic_status"] = "static-only (no device connected)" + (f": {error}" if error else "")
        if not out.get("dynamic_evidence") or "not tested" in str(out.get("dynamic_evidence")).lower():
            out["dynamic_evidence"] = (
                "not verified on device — no adb device/emulator was connected. Connect one authorized "
                "device and click 'Start dynamic' to confirm this finding on-device."
            )
        return out
    if verified is None:
        out["dynamic_status"] = "verification error" + (f": {error}" if error else " (see engine logs)")
        return out
    reproduced = bool(verified.get("is_vulnerable")) and not bool(verified.get("false_positive"))
    out["dynamic_verified"] = reproduced
    out["dynamic_status"] = "verified on device" if reproduced else "not reproduced on device"
    if verified.get("dynamic_evidence"):
        out["dynamic_evidence"] = verified.get("dynamic_evidence")
    if verified.get("_transcript"):
        # The actual on-device tool calls + observations — the detailed dynamic investigation.
        out["dynamic_transcript"] = str(verified.get("_transcript"))[-6000:]
    if verified.get("poc") and len(str(verified.get("poc"))) > len(str(out.get("poc") or "")):
        out["poc"] = verified.get("poc")
        out["malicious_input_example"] = verified.get("poc")
    if verified.get("code_evidence") and len(str(verified.get("code_evidence"))) > len(str(out.get("code_evidence") or "")):
        out["code_evidence"] = verified.get("code_evidence")
    out["dynamic_tested_at"] = _now()
    out["explanation"] = (
        f"{out.get('impact')}\n\nStatic: {out.get('static_evidence')}\n\n"
        f"Dynamic proof: {out.get('dynamic_evidence')}\n\nChainable primitive: {out.get('chainable_primitive')}"
    )
    return out


def run_deep_dynamic_for_scan(
    conn,
    scan_id: int,
    *,
    data_dir: str,
    max_leads: int = 14,
    static_only: bool = False,
    verify_top_n: int = 6,
    device=None,
) -> dict[str, Any]:
    """The layered Android Deep Research + Dynamic pipeline (see module banner). Reuses the
    same specialist machinery as run_for_scan, staged into three visible phases with a
    `pipeline` progress array the UI renders. Best-effort; commits as it goes."""

    from . import adb, specialist_agent as sa

    row = conn.execute(
        "select id, workflow_id, repo_full, commit_sha, configuration from scans where id=%s", (scan_id,)
    ).fetchone()
    if row is None:
        raise RuntimeError(f"scan {scan_id} not found")
    scan = row if isinstance(row, dict) else {
        "id": row[0], "workflow_id": row[1], "repo_full": row[2], "commit_sha": row[3], "configuration": row[4]
    }
    manifest, workspace_dir = _load_workspace_manifest(data_dir, scan)
    android = manifest.get("android", {})
    package = android.get("package") or scan["repo_full"]
    cfg = scan.get("configuration") if isinstance(scan.get("configuration"), dict) else {}
    include_third_party = bool(cfg.get("include_third_party"))
    workflow_id = int(scan["workflow_id"])

    # Phases 1-2 are static by design (triage + deep research over the code). Phase 3 uses a
    # device if one is connected; with none, findings are marked static-only.
    has_device = False
    if not static_only:
        if device is None:
            try:
                device = adb.get_device()
            except Exception:  # noqa: BLE001
                device = None
        has_device = device is not None
    if not has_device:
        device = None
    if has_device:
        try:
            from . import device_state

            device_state.note_test_serial(conn, getattr(device, "serial", None))
        except Exception:  # noqa: BLE001
            pass

    conn.execute(
        "delete from workflows.vulnerabilities where scan_id=%s and json_answer->>'source' in ('dynamic','specialist','chain')",
        (scan_id,),
    )
    conn.commit()

    try:
        sa.ensure_mobile_specialist_skills(conn)
        specialist_prompts = sa.load_mobile_specialist_prompts(conn)
    except Exception:  # noqa: BLE001
        specialist_prompts = None

    active_leads = build_leads(android, package, include_third_party=include_third_party)[:max_leads]
    progress: dict[str, Any] = {
        "status": "running",
        "mode": "dynamic" if has_device else "static",
        "phase": "triage",
        "pipeline": [
            {"key": "triage", "label": "Mobile PT triage", "state": "running", "done": 0, "total": len(active_leads)},
            {"key": "deep", "label": "Deep research", "state": "pending"},
            {
                "key": "verify",
                "label": "Dynamic verification",
                "state": "pending",
                "done": 0,
                "total": 0,
                "note": None if has_device else "no device connected — static-only",
            },
        ],
        "total": len(active_leads),
        "done": 0,
        "vulnerable": 0,
        "current": None,
        "started_at": _now(),
        "leads": [
            {"index": i, "component": lead["component"], "specialist": sa.pick_specialist(lead), "state": "pending"}
            for i, lead in enumerate(active_leads)
        ],
    }

    def set_phase(key: str, **kw: Any) -> None:
        for p in progress["pipeline"]:
            if p["key"] == key:
                p.update(kw)

    _write_progress(conn, scan_id, progress)

    # ------------------------------ Phase 1: triage ------------------------------ #
    confirmed: list[dict[str, Any]] = []  # for the chain analyst
    stored: list[dict[str, Any]] = []     # {id, ja, lead, severity} — targets for phases 2/3
    for i, lead in enumerate(active_leads):
        progress["current"] = {"component": lead["component"], "specialist": sa.pick_specialist(lead)}
        progress["leads"][i]["state"] = "running"
        _write_progress(conn, scan_id, progress)
        try:
            finding = sa.investigate_lead(
                lead, workspace_dir=workspace_dir, package=package, device=None, static_only=True,
                specialist_prompts=specialist_prompts,
            )
        except Exception:  # noqa: BLE001
            LOGGER.exception("triage specialist failed for lead %s", lead.get("component"))
            progress["leads"][i]["state"] = "error"
            progress["done"] = i + 1
            set_phase("triage", done=i + 1)
            _write_progress(conn, scan_id, progress)
            continue
        is_vuln = bool(finding.get("is_vulnerable")) and not bool(finding.get("false_positive"))
        progress["leads"][i]["state"] = "vulnerable" if is_vuln else "clean"
        progress["done"] = i + 1
        set_phase("triage", done=i + 1)
        if is_vuln:
            progress["leads"][i]["severity"] = finding.get("severity_score")
            progress["vulnerable"] += 1
        _write_progress(conn, scan_id, progress)
        if not is_vuln:
            continue
        finding["component"] = lead["component"]
        confirmed.append(finding)
        ja = _specialist_json_answer(finding, lead, android, phase="triage")
        vid = _insert_vuln(conn, scan_id, workflow_id, ja)
        stored.append({"id": vid, "ja": ja, "lead": lead, "severity": float(finding.get("severity_score") or 0)})

    for ja in _deterministic_findings(workspace_dir, android, package):
        ja["phase_origin"] = "triage"
        _insert_vuln(conn, scan_id, workflow_id, ja)
        confirmed.append({
            "title": ja["summary"], "vulnerability_type": ja["vulnerability_type"], "component": ja["component"],
            "chainable_primitive": ja.get("chainable_primitive"), "severity_score": ja.get("severity_score"),
        })
    set_phase("triage", state="done")
    _write_progress(conn, scan_id, progress)

    # --------------------------- Phase 2: deep research --------------------------- #
    progress["phase"] = "deep-research"
    progress["current"] = {"component": "correlating findings + deeper re-investigation", "specialist": "deep_research"}
    set_phase("deep", state="running")
    _write_progress(conn, scan_id, progress)

    chains: list[dict[str, Any]] = []
    if len(confirmed) >= 2:
        try:
            chains = sa.chain_analyst(
                confirmed, workspace_dir=workspace_dir, package=package, android_intel=android,
                device=None, static_only=True,
            )
        except Exception:  # noqa: BLE001
            LOGGER.exception("chain analyst failed")
    for ch in chains:
        _insert_vuln(conn, scan_id, workflow_id, {
            "source": "chain",
            "phase_origin": "deep",
            "summary": "CHAIN: " + str(ch.get("title")),
            "vulnerability_type": "Exploit Chain",
            "component": ", ".join(ch.get("components_involved", [])),
            "file_path": "(multiple)",
            "line": 0,
            "explanation": f"{ch.get('combined_impact')}\n\nSteps:\n" + "\n".join(f"  {i+1}. {s}" for i, s in enumerate(ch.get("steps", []))) + f"\n\nFeasibility: {ch.get('feasibility')}",
            "malicious_input_example": ch.get("poc"),
            "exploitable": True,
            "severity_score": ch.get("severity_score"),
            "chain_steps": ch.get("steps", []),
            "components_involved": ch.get("components_involved", []),
            "combined_impact": ch.get("combined_impact"),
            "feasibility": ch.get("feasibility"),
            "poc": ch.get("poc"),
        })

    # Background-seeded deeper re-investigation of the highest-value findings. Extra keys on
    # the lead dict are serialized into the specialist prompt, so the model sees the other
    # findings as leads and is told to dig further and strengthen the evidence/PoC.
    background = _findings_background(stored)
    deep_targets = sorted(stored, key=lambda s: s["severity"], reverse=True)[: min(4, len(stored))]
    for st in deep_targets:
        progress["current"] = {"component": st["lead"]["component"], "specialist": "deep_research"}
        _write_progress(conn, scan_id, progress)
        deep_lead = dict(st["lead"])
        deep_lead["research_background"] = background
        deep_lead["deep_research_directive"] = (
            "Re-investigate this lead MORE DEEPLY given the background findings above: follow every sink and "
            "cross-component/native call, hunt for deeper or chained issues, and STRENGTHEN the exact code "
            "evidence and the concrete PoC. Only report if still genuinely vulnerable."
        )
        try:
            deeper = sa.investigate_lead(
                deep_lead, workspace_dir=workspace_dir, package=package, device=None, static_only=True,
                specialist_prompts=specialist_prompts, max_steps=20,
            )
        except Exception:  # noqa: BLE001
            LOGGER.exception("deep re-investigation failed for %s", st["lead"].get("component"))
            continue
        if not (bool(deeper.get("is_vulnerable")) and not bool(deeper.get("false_positive"))):
            continue
        merged = _enrich_finding(st["ja"], deeper)
        conn.execute("update workflows.vulnerabilities set json_answer=%s where id=%s", (json.dumps(merged), st["id"]))
        conn.commit()
        st["ja"] = merged
        st["severity"] = float(merged.get("severity_score") or st["severity"])
    set_phase("deep", state="done", chains=len(chains))
    _write_progress(conn, scan_id, progress)

    # ------------------------- Phase 3: dynamic verification ---------------------- #
    progress["phase"] = "dynamic-verify"
    set_phase("verify", state="running")
    # The top findings by severity get the (expensive) live on-device pass, capped at
    # verify_top_n. No hard severity floor — otherwise a run with only low/medium findings
    # would silently skip dynamic testing entirely.
    targets = sorted(stored, key=lambda s: s["severity"], reverse=True)[:verify_top_n]
    set_phase("verify", total=len(targets), done=0)
    progress["verify"] = {"total": len(targets), "done": 0, "verified": 0, "has_device": has_device}
    _write_progress(conn, scan_id, progress)

    for j, st in enumerate(targets):
        progress["current"] = {"component": st["lead"]["component"], "specialist": "dynamic-verify"}
        _write_progress(conn, scan_id, progress)
        verified = None
        verify_err = None
        if has_device:
            try:
                verified = sa.investigate_lead(
                    st["lead"], workspace_dir=workspace_dir, package=package, device=device, static_only=False,
                    specialist_prompts=specialist_prompts, max_steps=16,
                )
            except Exception as exc:  # noqa: BLE001
                LOGGER.exception("dynamic verification failed for %s", st["lead"].get("component"))
                verify_err = str(exc)[:200]
        ja = _apply_dynamic_result(st["ja"], verified, has_device=has_device, error=verify_err)
        conn.execute("update workflows.vulnerabilities set json_answer=%s where id=%s", (json.dumps(ja), st["id"]))
        conn.commit()
        st["ja"] = ja
        if ja.get("dynamic_verified") is True:
            progress["verify"]["verified"] = progress["verify"].get("verified", 0) + 1
        progress["verify"]["done"] = j + 1
        set_phase("verify", done=j + 1)
        _write_progress(conn, scan_id, progress)
    set_phase("verify", state="done")

    # Ground every citation against the snapshot BEFORE the model re-checks anything: a
    # finding pointing at code that is not there is disproved without spending model steps.
    try:
        run_evidence_validation(conn, scan_id, workspace_dir)
    except Exception:  # noqa: BLE001
        LOGGER.exception("evidence validation failed for scan %s", scan_id)

    # False-positive verification: re-check High+ findings like a human researcher.
    if cfg.get("fp_verify", True):
        try:
            run_fp_verification(conn, scan_id, data_dir=data_dir, device=device, static_only=static_only)
        except Exception:  # noqa: BLE001
            LOGGER.exception("FP verification failed for scan %s", scan_id)

    _rerank(conn, scan_id)
    progress["phase"] = "done"
    progress["status"] = "done"
    progress["current"] = None
    progress["chains"] = len(chains)
    progress["finished_at"] = _now()
    _write_progress(conn, scan_id, progress)
    summary = {
        "leads": len(active_leads),
        "vulnerabilities": len(stored),
        "chains": len(chains),
        "verified_targets": len(targets),
        "device": has_device,
    }
    LOGGER.info("deep+dynamic investigation for scan %s: %s", scan_id, summary)
    return summary


def run_dynamic_verification_only(
    conn, scan_id: int, *, data_dir: str, verify_top_n: int | None = None, device=None
) -> dict[str, Any]:
    """Re-run ONLY the on-device dynamic verification over a scan's EXISTING findings.

    This is what the "Start dynamic" / "Retry" buttons trigger. It never deletes or
    regenerates the findings list — it walks the current findings, runs the live on-device
    confirmation for the top ones, and updates each finding's dynamic-investigation fields in
    place (status, evidence, on-device transcript, PoC)."""

    from . import adb, specialist_agent as sa

    row = conn.execute(
        "select id, workflow_id, repo_full, commit_sha, configuration from scans where id=%s", (scan_id,)
    ).fetchone()
    if row is None:
        raise RuntimeError(f"scan {scan_id} not found")
    scan = row if isinstance(row, dict) else {
        "id": row[0], "workflow_id": row[1], "repo_full": row[2], "commit_sha": row[3], "configuration": row[4]
    }
    manifest, workspace_dir = _load_workspace_manifest(data_dir, scan)
    android = manifest.get("android", {})
    package = android.get("package") or scan["repo_full"]
    cfg = scan.get("configuration") if isinstance(scan.get("configuration"), dict) else {}
    cap = int(verify_top_n or cfg.get("verify_top_n") or 6)

    device_err = None
    if device is None:
        try:
            device = adb.get_device()
        except Exception as exc:  # noqa: BLE001
            device = None
            device_err = str(exc)[:300]
    has_device = device is not None
    if has_device:
        try:
            from . import device_state

            device_state.note_test_serial(conn, getattr(device, "serial", None))
        except Exception:  # noqa: BLE001
            pass

    try:
        sa.ensure_mobile_specialist_skills(conn)
        specialist_prompts = sa.load_mobile_specialist_prompts(conn)
    except Exception:  # noqa: BLE001
        specialist_prompts = None

    # Load the EXISTING findings (component-based ones; exploit-chain syntheses aren't
    # per-component dynamically triggerable). Nothing is deleted.
    rows = conn.execute(
        "select id, json_answer from workflows.vulnerabilities where scan_id=%s", (scan_id,)
    ).fetchall()
    findings: list[dict[str, Any]] = []
    for r in rows:
        rid = r[0] if not isinstance(r, dict) else r["id"]
        ja = (r[1] if not isinstance(r, dict) else r["json_answer"]) or {}
        if ja.get("source") == "chain" or not ja.get("component"):
            continue
        findings.append({"id": rid, "ja": ja, "severity": float(ja.get("severity_score") or 0)})
    findings.sort(key=lambda f: f["severity"], reverse=True)
    targets = findings[:cap]

    progress: dict[str, Any] = {
        "status": "running",
        "mode": "dynamic" if has_device else "static",
        "phase": "dynamic-verify",
        "pipeline": [
            {
                "key": "verify",
                "label": "Dynamic verification",
                "state": "running",
                "done": 0,
                "total": len(targets),
                "note": None if has_device else ("no device connected" + (f": {device_err}" if device_err else "")),
            }
        ],
        "total": len(targets),
        "done": 0,
        "vulnerable": 0,
        "current": None,
        "started_at": _now(),
        "verify": {"total": len(targets), "done": 0, "verified": 0, "has_device": has_device},
        "leads": [
            {"index": i, "component": t["ja"].get("component"), "specialist": "dynamic-verify", "state": "pending"}
            for i, t in enumerate(targets)
        ],
    }
    _write_progress(conn, scan_id, progress)

    for i, t in enumerate(targets):
        progress["current"] = {"component": t["ja"].get("component"), "specialist": "dynamic-verify"}
        progress["leads"][i]["state"] = "running"
        _write_progress(conn, scan_id, progress)
        verified = None
        verify_err = None
        if has_device:
            lead = _lead_from_finding(t["ja"], android)
            try:
                verified = sa.investigate_lead(
                    lead, workspace_dir=workspace_dir, package=package, device=device, static_only=False,
                    specialist_prompts=specialist_prompts, max_steps=16,
                )
            except Exception as exc:  # noqa: BLE001
                LOGGER.exception("dynamic verification failed for %s", t["ja"].get("component"))
                verify_err = str(exc)[:200]
        ja = _apply_dynamic_result(t["ja"], verified, has_device=has_device, error=device_err or verify_err)
        conn.execute("update workflows.vulnerabilities set json_answer=%s where id=%s", (json.dumps(ja), t["id"]))
        conn.commit()
        reproduced = ja.get("dynamic_verified") is True
        progress["leads"][i]["state"] = "vulnerable" if reproduced else "clean"
        if reproduced:
            progress["verify"]["verified"] += 1
            progress["vulnerable"] += 1
        progress["done"] = i + 1
        progress["verify"]["done"] = i + 1
        progress["pipeline"][0]["done"] = i + 1
        _write_progress(conn, scan_id, progress)

    progress["pipeline"][0]["state"] = "done"
    progress["phase"] = "done"
    progress["status"] = "done"
    progress["current"] = None
    progress["finished_at"] = _now()
    _write_progress(conn, scan_id, progress)
    summary = {
        "targets": len(targets),
        "verified": progress["verify"]["verified"],
        "device": has_device,
        "device_error": device_err,
    }
    LOGGER.info("dynamic verification (re-run) for scan %s: %s", scan_id, summary)
    return summary


def _write_fp_progress(conn, scan_id: int, progress: dict[str, Any]) -> None:
    progress["updated_at"] = _now()
    try:
        conn.execute(
            "update scans set reasoning = coalesce(reasoning,'{}'::jsonb) || jsonb_build_object('fp_progress', %s::jsonb), updated_at = now() where id=%s",
            (json.dumps(progress), scan_id),
        )
        conn.commit()
    except Exception:  # noqa: BLE001
        LOGGER.debug("failed to write fp progress", exc_info=True)


def run_evidence_validation(conn, scan_id: int, workspace_dir: str) -> dict[str, Any]:
    """Ground every finding's code citation against the snapshot (model-free).

    Each finding is annotated with `evidence_verdict` / `evidence_detail`. When the quoted
    code turns out to live on a different line than claimed, the line is corrected instead of
    the finding being thrown away. Ranking (`_rerank`) then sinks whatever the snapshot
    contradicts, and the false-positive adjudicator skips it entirely."""

    rows = conn.execute(
        "select id, json_answer from workflows.vulnerabilities where scan_id=%s", (scan_id,)
    ).fetchall()
    counts: dict[str, int] = {}
    for r in rows:
        rid = int(r[0] if not isinstance(r, dict) else r["id"])
        ja = (r[1] if not isinstance(r, dict) else r["json_answer"]) or {}
        try:
            result = verify_citation(workspace_dir, ja)
        except Exception:  # noqa: BLE001 - grounding must never break a scan
            LOGGER.exception("evidence validation failed for finding %s", rid)
            continue
        verdict = result.get("verdict") or ""
        counts[verdict] = counts.get(verdict, 0) + 1
        ja["evidence_verdict"] = verdict
        ja["evidence_detail"] = result.get("detail")
        ja["evidence_checked_at"] = _now()
        actual = result.get("actual_line")
        if verdict == VERIFIED and actual and int(actual) != int(ja.get("line") or 0):
            ja["line_reported"] = ja.get("line")
            ja["line"] = int(actual)
        conn.execute(
            "update workflows.vulnerabilities set json_answer=%s where id=%s", (json.dumps(ja), rid)
        )
    conn.commit()
    LOGGER.info("evidence validation for scan %s: %s", scan_id, counts)
    return counts


# Paths whose secrets are not production secrets. The APK flow never needed this because a
# decompiled app has no test tree; a source checkout is mostly the opposite.
_NON_PROD_PATH_HINTS = (
    "/test/", "/tests/", "/testdata/", "/it/", "/integration-test",
    "/example", "/examples/", "/sample", "/demo", "/mock", "/fixture", "/benchmark",
)


def _source_secret_findings(workspace_dir: str) -> list[dict[str, Any]]:
    """Deterministic hardcoded-secret findings for a source checkout.

    check_hardcoded_secrets returns raw matches; the APK flow shapes them into findings in
    _deterministic_findings, so the source path needs its own shaping. It also filters test and
    example trees, which is where most literal credentials in a real repository live and where
    none of them are exploitable."""

    out: list[dict[str, Any]] = []
    for hit in check_hardcoded_secrets(workspace_dir):
        rel = str(hit.get("rel") or "").replace("\\", "/")
        low = "/" + rel.lower()
        if any(h in low for h in _NON_PROD_PATH_HINTS):
            continue
        value = str(hit.get("value") or "")
        out.append({
            "source": "specialist",
            "summary": "Hardcoded secret in source: " + str(hit.get("label") or "credential"),
            "vulnerability_type": "Hardcoded Credentials / Secrets",
            "file_path": rel,
            "line": hit.get("line") or 0,
            "code_evidence": hit.get("code_evidence") or hit.get("match") or "",
            "explanation": (
                "A literal secret is committed in the source tree. Anyone with read access to the "
                "repository, a published artifact, or the built package can recover it, and rotating "
                "it requires a code change and redeploy. Matched: " + str(hit.get("match") or "")[:160]
            ),
            "severity_score": 7,
            "confidence": "high",
            "exploitable": True,
            "malicious_actor": "anyone able to read the repository or a built artifact",
            "poc": "Recover the literal from " + rel + " line " + str(hit.get("line") or 0) + " and authenticate with it.",
            "secret_value_prefix": value[:4] + "..." if value else "",
        })
    return out


def run_source_verification(conn, scan_id: int, *, data_dir: str, checkout_cache_dir: str) -> dict[str, Any]:
    """The accuracy pass for NON-APK (source repo) scans.

    Source scans have no specialist/chain phase, so until now they received no grounding and
    no false-positive adjudication at all — every raw model claim reached the user. This runs
    the two target-agnostic halves: deterministic citation grounding, then the FP adjudicator
    (which only needs read_file/grep over the snapshot)."""

    from .workspace import resolve_scan_snapshot_dir

    row = conn.execute(
        "select id, repo_full, commit_sha, repo_kind, configuration from scans where id=%s", (scan_id,)
    ).fetchone()
    if row is None:
        raise RuntimeError(f"scan {scan_id} not found")
    scan = row if isinstance(row, dict) else {
        "id": row[0], "repo_full": row[1], "commit_sha": row[2], "repo_kind": row[3], "configuration": row[4]
    }
    workspace_dir = resolve_scan_snapshot_dir(checkout_cache_dir, scan)
    if not workspace_dir:
        LOGGER.info("source verification for scan %s: no snapshot on disk, skipping", scan_id)
        return {"skipped": "no snapshot"}

    # Deterministic checks first: no model time, exact results. The APK flow has had these
    # from the start; source scans had none at all.
    try:
        wf_row = conn.execute("select workflow_id from scans where id=%s", (scan_id,)).fetchone()
        wf_id = int((wf_row[0] if not isinstance(wf_row, dict) else wf_row["workflow_id"]) or 0)
        secrets = _source_secret_findings(workspace_dir)
        for sec in secrets:
            _insert_vuln(conn, scan_id, wf_id, sec)
        if secrets:
            LOGGER.info("source verification: %s deterministic secret finding(s)", len(secrets))
    except Exception:  # noqa: BLE001
        LOGGER.exception("deterministic secret scan failed for scan %s", scan_id)

    evidence = run_evidence_validation(conn, scan_id, workspace_dir)
    summary: dict[str, Any] = {"evidence": evidence}
    try:
        summary["fp"] = run_fp_verification(
            conn, scan_id, data_dir=data_dir, static_only=True,
            workspace_dir=workspace_dir, source_repo=True,
        )
    except Exception:  # noqa: BLE001
        LOGGER.exception("FP verification failed for source scan %s", scan_id)
    _rerank(conn, scan_id)
    return summary


def run_fp_verification(
    conn,
    scan_id: int,
    *,
    data_dir: str,
    device=None,
    static_only: bool = False,
    only_ids: list[int] | None = None,
    # Was 7.0, which skipped every Medium finding. Adjudication is cheap relative to the
    # specialist pass, so verify anything that is not clearly informational.
    min_severity: float = 4.0,
    cap: int = 40,
    workspace_dir: str | None = None,
    source_repo: bool = False,
) -> dict[str, Any]:
    """Re-verify findings with the false-positive adjudicator (reads source, checks
    reachability + guards, uses adb when a device is present). `only_ids` = specific findings
    (the per-finding "Verify" button); otherwise auto-runs on High+ (severity >= min_severity)
    findings that haven't been checked yet. Marks each finding's verdict and demotes FPs."""

    from . import adb, specialist_agent as sa

    row = conn.execute(
        "select id, workflow_id, repo_full, commit_sha, configuration from scans where id=%s", (scan_id,)
    ).fetchone()
    if row is None:
        raise RuntimeError(f"scan {scan_id} not found")
    scan = row if isinstance(row, dict) else {
        "id": row[0], "workflow_id": row[1], "repo_full": row[2], "commit_sha": row[3], "configuration": row[4]
    }
    if workspace_dir:
        # Source-repo scan: the caller resolved the snapshot; there is no APK manifest.
        android: dict[str, Any] = {}
    else:
        manifest, workspace_dir = _load_workspace_manifest(data_dir, scan)
        android = manifest.get("android", {})
    package = android.get("package") or scan["repo_full"]

    if not static_only and device is None:
        try:
            device = adb.get_device()
        except Exception:  # noqa: BLE001
            device = None
    if device is None:
        static_only = True

    if source_repo:
        # The mobile adjudicator asks about manifests, exported components and adb; on a
        # server-side repo those questions are meaningless and bias it toward rejection.
        specialist_prompts = {"fp_adjudicator": sa.SOURCE_FP_ADJUDICATOR_PROMPT}
    else:
        try:
            sa.ensure_mobile_specialist_skills(conn)
            specialist_prompts = sa.load_mobile_specialist_prompts(conn)
        except Exception:  # noqa: BLE001 - never block the scan on skill loading
            specialist_prompts = None

    rows = conn.execute(
        "select id, json_answer from workflows.vulnerabilities where scan_id=%s", (scan_id,)
    ).fetchall()
    findings = []
    for r in rows:
        rid = r[0] if not isinstance(r, dict) else r["id"]
        ja = (r[1] if not isinstance(r, dict) else r["json_answer"]) or {}
        findings.append({"id": int(rid), "ja": ja, "sev": finding_severity(ja)})

    if only_ids is not None:
        idset = {int(x) for x in only_ids}
        targets = [f for f in findings if f["id"] in idset]
    else:
        # Auto: High+ severity, skip exploit-chain syntheses and already-verified findings.
        targets = [
            f for f in findings
            if f["sev"] >= min_severity
            and f["ja"].get("source") != "chain"
            and not f["ja"].get("fp_checked_at")
            # Already disproved deterministically — no need to spend model steps on it.
            and f["ja"].get("evidence_verdict") not in UNGROUNDED
        ]
    targets = sorted(targets, key=lambda f: f["sev"], reverse=True)[:cap]

    progress = {
        "status": "running",
        "mode": "dynamic" if device is not None else "static",
        "total": len(targets),
        "done": 0,
        "false_positives": 0,
        "current": None,
        "started_at": _now(),
    }
    _write_fp_progress(conn, scan_id, progress)

    for i, t in enumerate(targets):
        ja = dict(t["ja"])
        progress["current"] = ja.get("component") or ja.get("summary")
        _write_fp_progress(conn, scan_id, progress)
        try:
            v = sa.adjudicate_finding(
                ja, workspace_dir=workspace_dir, package=package, device=device,
                static_only=static_only, specialist_prompts=specialist_prompts,
            )
        except Exception:  # noqa: BLE001
            LOGGER.exception("FP adjudication failed for finding %s", t["id"])
            v = None
        if v:
            ja["fp_verdict"] = v.get("verdict")
            ja["fp_confidence"] = v.get("confidence")
            ja["fp_reachable"] = v.get("reachable")
            ja["fp_reason"] = v.get("reason")
            ja["fp_blockers"] = v.get("blockers") or []
            ja["fp_bypass_needed"] = v.get("bypass_needed") or ""
            ja["fp_transcript"] = v.get("_transcript")
        else:
            ja["fp_verdict"] = "error"
        ja["fp_checked_at"] = _now()
        ja.pop("fp_verify_requested", None)
        conn.execute("update workflows.vulnerabilities set json_answer=%s where id=%s", (json.dumps(ja), t["id"]))
        conn.commit()
        if ja.get("fp_verdict") == "false_positive":
            progress["false_positives"] += 1
        progress["done"] = i + 1
        _write_fp_progress(conn, scan_id, progress)

    _rerank(conn, scan_id)
    progress["status"] = "done"
    progress["current"] = None
    progress["finished_at"] = _now()
    _write_fp_progress(conn, scan_id, progress)
    summary = {"verified": len(targets), "false_positives": progress["false_positives"], "device": device is not None}
    LOGGER.info("FP verification for scan %s: %s", scan_id, summary)
    return summary


def maybe_run_after_scan(db, scan: dict[str, Any], *, data_dir: str) -> None:
    """Worker hook: best-effort dynamic investigation after an APK scan completes."""

    if os.getenv("ENGINE_DYNAMIC_INVESTIGATION", "").strip().lower() not in {"1", "true", "yes", "on"}:
        return
    if (scan.get("repo_kind") or "remote") != "apk":
        return
    static_only = False
    try:
        from . import adb

        adb.get_device()  # raises if no device
    except Exception:  # noqa: BLE001
        static_only = True
        LOGGER.info("dynamic investigation: no adb device, running static-only specialists")
    try:
        with db.connect() as conn:
            run_for_scan(conn, int(scan["id"]), data_dir=data_dir, static_only=static_only)
    except Exception:  # noqa: BLE001 - never break the scan lifecycle
        LOGGER.exception("dynamic investigation phase failed for scan %s", scan.get("id"))
