"""Specialist vulnerability agents (Phase 3.x).

An attack-surface lead (an exported component, a deep link, a provider) is NOT a finding
- it is a starting point. For each lead, a *specialist* agent for that vulnerability class
reads the decompiled code, forms a concrete hypothesis, and PROVES or REFUTES it on the
device, then reports the precise vulnerability (or that it is a false positive).

The signature capability is `network_callback_test`: to prove "this WebView opens an
attacker-controlled URL from outside the app", the agent crafts a deep link whose URL
points at a host callback (reachable from the device via `adb reverse`); if the device
fetches it, exploitability is proven end-to-end.

Reuses the local model client + workspace tools from local_harness; adds device tools.
"""

from __future__ import annotations

import http.server
import json
import os
import secrets
import subprocess
import threading
import time
from typing import Any
from urllib.parse import quote

from .adb import Device, adb_bin, get_device
from .local_harness import LocalLLMClient, WorkspaceTools, _loads_lenient, trim_history

# --------------------------------------------------------------------------- #
# Output: a precise, adjudicated finding (not the surface lead)               #
# --------------------------------------------------------------------------- #

FINDING_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "is_vulnerable": {"type": "boolean"},
        "false_positive": {"type": "boolean"},
        "vulnerability_type": {"type": "string"},
        "title": {"type": "string"},
        "impact": {"type": "string"},
        "exploitable_externally": {"type": "boolean"},
        "static_evidence": {"type": "string"},
        "dynamic_evidence": {"type": "string"},
        "poc": {"type": "string"},
        "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
        "severity_score": {"type": "number"},
        "chainable_primitive": {"type": "string"},
        "code_file": {"type": "string"},
        "code_evidence": {"type": "string"},
    },
    "required": [
        "is_vulnerable",
        "false_positive",
        "vulnerability_type",
        "title",
        "impact",
        "exploitable_externally",
        "static_evidence",
        "dynamic_evidence",
        "poc",
        "confidence",
        "severity_score",
        "chainable_primitive",
        "code_file",
        "code_evidence",
    ],
    "additionalProperties": False,
}


# --------------------------------------------------------------------------- #
# Dynamic proof: does the app fetch an attacker-controlled URL?               #
# --------------------------------------------------------------------------- #


class _CallbackHandler(http.server.BaseHTTPRequestHandler):
    hits: list[str] = []

    def do_GET(self):  # noqa: N802
        type(self).hits.append(self.path)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"kritt-poc-ok")

    def log_message(self, *args):  # silence
        return


def network_callback_test(device: Device, deeplink_template: str, *, port: int = 8899, wait: float = 10.0) -> dict[str, Any]:
    """Replace the token CALLBACK in deeplink_template with a host callback URL, launch the
    deep link, and report whether the device fetched it (proving external URL load)."""

    token = secrets.token_hex(4)
    handler = type(f"H{token}", (_CallbackHandler,), {"hits": []})
    server = http.server.HTTPServer(("127.0.0.1", port), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    # Make the device's localhost:port reach this host listener.
    subprocess.run([adb_bin(), "-s", device.serial, "reverse", f"tcp:{port}", f"tcp:{port}"],
                   capture_output=True, text=True, timeout=15)
    callback = f"http://127.0.0.1:{port}/kritt-proof-{token}"
    uri = deeplink_template.replace("CALLBACK", quote(callback, safe=""))
    try:
        device.am_start(action="android.intent.action.VIEW", data_uri=uri)
        deadline = time.time() + wait
        while time.time() < deadline and not handler.hits:
            time.sleep(0.3)
    finally:
        subprocess.run([adb_bin(), "-s", device.serial, "reverse", "--remove", f"tcp:{port}"],
                       capture_output=True, text=True, timeout=10)
        server.shutdown()
        device.force_stop(device_package_guess(uri))
    fetched = any(token in h for h in handler.hits)
    return {"fetched": fetched, "launched_uri": uri, "callback_hits": list(handler.hits)}


def device_package_guess(uri: str) -> str:
    # deep links here are scheme://<package host>/...
    try:
        return uri.split("://", 1)[1].split("/", 1)[0]
    except IndexError:
        return ""


# --------------------------------------------------------------------------- #
# Specialist toolset (code + device + dynamic proof)                          #
# --------------------------------------------------------------------------- #


class SpecialistTools:
    CODE_TOOLS = ["read_file", "grep", "list_dir", "head"]
    # Native (.so / ELF) analysis — static, so available even without a device.
    NATIVE_TOOLS = ["list_native_libs", "native_recon", "native_disasm"]
    DEVICE_TOOLS = ["launch_deeplink", "network_callback_test", "content_query", "read_app_file", "list_app_files", "am_start_component", "logcat"]

    def __init__(self, workspace_dir: str, device: Device | None, package: str, static_only: bool = False):
        self.workspace_dir = workspace_dir
        self.code = WorkspaceTools(workspace_dir)
        self.device = device
        self.package = package
        self.static_only = static_only or device is None

    def names(self) -> list[str]:
        base = list(self.CODE_TOOLS) + list(self.NATIVE_TOOLS)
        return base if self.static_only else base + self.DEVICE_TOOLS

    def dispatch(self, name: str, args: dict[str, Any]) -> str:
        if self.static_only and name in self.DEVICE_TOOLS:
            return "[static-only mode: device tools are unavailable; rely on code analysis]"
        args = args if isinstance(args, dict) else {}
        try:
            if name in ("read_file", "grep", "list_dir", "head"):
                return self.code.dispatch(name, args)
            if name in self.NATIVE_TOOLS:
                from . import native_tools
                if name == "list_native_libs":
                    return native_tools.list_native_libs(self.workspace_dir)
                if name == "native_recon":
                    return native_tools.native_recon(self.workspace_dir, str(args.get("path", "")))
                if name == "native_disasm":
                    return native_tools.native_disasm(
                        self.workspace_dir, str(args.get("path", "")), str(args.get("symbol", ""))
                    )
            if name == "launch_deeplink":
                self.device.logcat_clear()
                res = self.device.am_start(action="android.intent.action.VIEW", data_uri=str(args.get("uri", "")))
                focus = self.device.current_focus()
                return f"am start: {res.stdout[:200]}\nfocus: {focus[:160]}"
            if name == "network_callback_test":
                template = str(args.get("deeplink_template", ""))
                if "CALLBACK" not in template:
                    return "[error: deeplink_template must contain the literal token CALLBACK where the URL goes]"
                result = network_callback_test(self.device, template)
                verdict = "FETCHED (app loaded the attacker-controlled URL)" if result["fetched"] else "not fetched"
                return f"{verdict}\nlaunched: {result['launched_uri']}\nhits: {result['callback_hits']}"
            if name == "content_query":
                res = self.device.content_query(str(args.get("uri", "")))
                return f"rc={res.returncode}\n{(res.stdout or res.stderr)[:2000]}"
            if name == "read_app_file":
                # Read a file under the target app's private data dir via root — proves
                # whether secrets (credentials, tokens) are actually stored there.
                rel = str(args.get("path", "")).lstrip("/")
                out = self.device.shell(f"cat /data/data/{self.package}/{rel}", root=True)
                return (out.stdout or out.stderr)[:3000] or "[empty or not found]"
            if name == "list_app_files":
                sub = str(args.get("subdir", "")).lstrip("/")
                out = self.device.shell(f"ls -la /data/data/{self.package}/{sub}", root=True)
                return (out.stdout or out.stderr)[:2000]
            if name == "am_start_component":
                self.device.logcat_clear()
                extras = args.get("extras") if isinstance(args.get("extras"), dict) else None
                res = self.device.am_start(component=str(args.get("component", "")), extras=extras)
                return f"am start: {res.stdout[:200]}\nfocus: {self.device.current_focus()[:160]}\nlogcat:\n{self.device.logcat_dump(max_lines=15)[:800]}"
            if name == "logcat":
                return self.device.logcat_dump(max_lines=40)
        except Exception as exc:  # noqa: BLE001
            return f"[tool error: {type(exc).__name__}: {exc}]"
        return f"[unknown tool: {name}]"


# --------------------------------------------------------------------------- #
# Specialist prompts                                                          #
# --------------------------------------------------------------------------- #

_SCORING = (
    "\n\nAlways: base every claim on code you read (and, when available, a dynamic result you observed). "
    "Set severity_score 0-10 (CVSS-like: consider external reachability, privilege, data sensitivity, and whether "
    "it needs user interaction). Set chainable_primitive to a short phrase describing what this bug GIVES an "
    "attacker that could be chained (e.g. 'arbitrary URL load in a file-access-enabled WebView', 'read the app "
    "private data dir', 'launch a non-exported component', 'attacker-controlled Intent execution'), or '' if none. "
    "CRUCIAL: set code_file to the workspace-relative path of the vulnerable source (e.g. "
    "jadx/sources/com/app/Foo.java) and code_evidence to the EXACT vulnerable lines copied VERBATIM from that file "
    "you read (the specific statements — the loadUrl/getQueryParameter/Cipher.getInstance/PendingIntent.getActivity/"
    "getSharedPreferences call and its context) — never a paraphrase, copy the real characters.\n"
    "The `poc` field MUST be a CONCRETE, COPY-PASTE exploit using the REAL component/authority/action/scheme/extra "
    "names from THIS app — NEVER a prose description. Provide EITHER (a) an exact adb command when the bug is "
    "reachable that way — e.g. `adb shell am start -n com.app/.Target --es url \"http://evil\"`, "
    "`adb shell am broadcast -a com.app.ACTION --es cmd x`, `adb shell content query --uri content://com.app.provider/`, "
    "`adb shell am start-service -n com.app/.Svc` — OR (b) a minimal MALICIOUS-APP code snippet (real Java/Kotlin: build "
    "the crafted Intent and startActivity/sendBroadcast/bindService, register the receiver, request the custom "
    "permission in AndroidManifest, or the JS/HTML for a WebView exploit, or the code that hijacks the mutable "
    "PendingIntent). Pick whichever actually triggers this bug; when adb cannot express it (e.g. PendingIntent hijack, "
    "intent redirection to a non-exported component, permission acquisition) give the app code. "
    "If it is a false positive, set is_vulnerable=false, false_positive=true, severity_score 0, code_evidence to the "
    "code that makes it safe, and poc to '' and explain why."
)

WEBVIEW_SPECIALIST = (
    "You are a specialist Android WebView / deep-link security agent. A WebView-hosting component reachable "
    "from outside the app was found. Read its decompiled source under jadx/sources/ and examine how it handles "
    "the incoming intent/deep-link data and the WebView config (loadUrl source; setJavaScriptEnabled; "
    "setAllowUniversalAccessFromFileURLs / setAllowFileAccess; addJavascriptInterface; any URL allowlist and "
    "whether it is bypassable, e.g. endsWith/contains checks defeated by a subdomain, fragment #, or @). "
    "Prove exploitability with network_callback_test using a deeplink_template containing the literal token "
    "CALLBACK where the URL goes (e.g. 'insecureshop://com.insecureshop/web?url=CALLBACK'); FETCHED proves "
    "external attacker-controlled URL load. If file access is enabled, note the file:// credential-theft risk."
    + _SCORING
)

UXSS_SPECIALIST = (
    "You are a specialist Android WebView UXSS (Universal Cross-Site Scripting) agent. UXSS = running "
    "ATTACKER JavaScript in the security context of ANOTHER origin that is loaded in an in-app WebView "
    "(cookie/session theft, authenticated cross-origin reads, account takeover). Read every WebView-hosting class "
    "under jadx/sources/ (grep for WebView, evaluateJavascript, loadUrl, addJavascriptInterface, @JavascriptInterface, "
    "shouldOverrideUrlLoading, setJavaScriptEnabled) AND the AndroidManifest intent-filters. Hunt these TWO families:\n\n"
    "FAMILY 1 — BRIDGE REPLY-PATH UXSS (TOCTOU origin race): a @JavascriptInterface bridge checks the caller's "
    "origin ONCE, then later runs JS on the CURRENT page via evaluateJavascript() / loadUrl(\"javascript:...\") "
    "WITHOUT re-checking the origin at execution time. The gap is any async callback, a persistent event/OS listener "
    "(volume/lifecycle/dialog-dismiss callback) that survives navigation, or a stored callback string field. A "
    "callback-id or result value that the bridge CONCATENATES into the evaluateJavascript string is the injection "
    "point (e.g. callbackId = \"x','',true);ATTACKER_JS//\" — the // comments out the rest). Attacker flow: their "
    "page passes the origin check and registers the listener/callback, then navigates the WebView to the victim "
    "origin (e.g. https://accounts.google.com); an ambient event fires the stored callback and ATTACKER_JS executes "
    "on the victim origin. SIGNALS: evaluateJavascript / loadUrl(\"javascript:\") built by STRING CONCATENATION of a "
    "bridge-supplied value; callbacks/listeners stored as fields and invoked after onPageStarted/onPageFinished; no "
    "re-validation of the current URL before executing JS.\n\n"
    "FAMILY 2 — NAVIGATION-PATH UXSS (javascript: scheme / intent routing): the app loads a `javascript:` URL into a "
    "WebView with NO scheme allowlist, so attacker script runs on whatever page is currently loaded. Vectors: "
    "(a) an intent / deep-link URL extra passed straight to webView.loadUrl(...) — onNewIntent/onCreate reading "
    "getStringExtra(\"url\"/\"KEY_URL\"/\"KEY_INTENT_URL\") with no https-only / scheme check; (b) AndroidManifest "
    "declares <data android:scheme=\"javascript\"/> as BROWSABLE on an exported activity; (c) an unvalidated "
    "`S.browser_fallback_url=javascript:...` inside an intent:// URL that shouldOverrideUrlLoading hands to loadUrl; "
    "(d) shouldOverrideUrlLoading dispatching intent:// from a child / hidden frame. SIGNALS: loadUrl(x) where x can "
    "be `javascript:` (no url.startsWith(\"https\") / scheme allowlist), scheme=\"javascript\" in the manifest, "
    "browser_fallback_url handling, unfiltered KEY_URL / url extras reaching loadUrl.\n\n"
    "For any URL allowlist, test bypasses (subdomain, @, #, missing scheme check) as for open-redirect. PROVE it "
    "where possible: for Family 2 use am_start_component / launch_deeplink to send the exported activity a "
    "`javascript:alert(document.domain)` URL extra, or network_callback_test with a deeplink_template whose url= is "
    "the token CALLBACK to prove attacker-URL load; for Family 1, show the exact injected callback string. Set `poc` "
    "to the CONCRETE trigger using the REAL activity / extra / scheme names from THIS app — e.g. "
    "`adb shell am start -n <pkg>/<activity> --es <urlExtra> \"javascript:alert(document.domain)\"`, OR the "
    "`intent://x#Intent;scheme=app;package=com.not.installed;S.browser_fallback_url=javascript:alert(document.domain);end` "
    "payload, OR the malicious HTML/JS that registers the listener plus the injected callbackId for Family 1. State "
    "WHICH family, the exact victim-origin impact (session/cookie theft, account takeover), and whether an external "
    "attacker can reach it (exported activity / deep link / a page loaded in the WebView). If a strict https-only "
    "scheme allowlist with no bypass AND origin re-validation before every evaluateJavascript are present, mark it a "
    "false positive and quote the guard." + _SCORING
)

CONTENT_PROVIDER_SPECIALIST = (
    "You are a specialist Android ContentProvider security agent. An exported (or otherwise reachable) provider "
    "was found. Read its decompiled source (query/insert/update/delete/openFile) under jadx/sources/. Determine "
    "if an external app can: read/write sensitive data; perform SQL injection via selection/projection/sortOrder "
    "built with string concatenation; or path-traversal via openFile (content://auth/../../databases/...). Use "
    "content_query to test: query the base URI, sub-paths, and injection payloads (e.g. \"content://AUTH/x' OR "
    "'1'='1\") and path traversal. A Permission Denial means guarded; returned rows/data means exposed. If this is a "
    "FileProvider, read its path-config XML (provider_paths.xml / file_paths.xml, shown in the evidence): a "
    "<root-path path=\"/\"> or <external-path path=\".\"> exposes the ENTIRE filesystem/external storage — any app "
    "granted a content:// URI reads arbitrary app files. Report the concrete data exposure / SQLi / traversal / "
    "FileProvider over-exposure with the exact content:// PoC." + _SCORING
)

INTENT_REDIRECTION_SPECIALIST = (
    "You are a specialist Android intent-redirection / PendingIntent security agent. A reachable component was "
    "found. Read its decompiled source. Look for: (a) intent redirection — the component reads an Intent from "
    "the incoming intent's extras (getParcelableExtra(\"...\"), getIntent().getExtras()) and passes it to "
    "startActivity/startService/sendBroadcast, letting an external app launch NON-exported internal components "
    "or actions with the app's privileges; (b) mutable/implicit PendingIntent (FLAG_MUTABLE or missing "
    "FLAG_IMMUTABLE, or a PendingIntent wrapping an implicit Intent) that an attacker can hijack. Prove with "
    "am_start_component passing a crafted 'extras' map (e.g. an extra_intent that targets an internal component) "
    "and observe via logcat/focus whether the redirect fires. Report the concrete redirection/hijack + PoC."
    + _SCORING
)

CRYPTO_SPECIALIST = (
    "You are a specialist Android cryptography security agent. Read the component/util source under jadx/sources/ "
    "(grep for Cipher, SecretKeySpec, IvParameterSpec, MessageDigest, Random, getInstance). Identify concrete "
    "misuse: hardcoded keys/IVs, ECB mode, constant/predictable IV, weak algorithms (DES/MD5/SHA1 for security), "
    "java.util.Random for secrets, or keys derived from static values. Quote the exact key/IV/transformation from "
    "the code as evidence. Report what an attacker can decrypt/forge as a result." + _SCORING
)

STORAGE_SPECIALIST = (
    "You are a specialist Android insecure-storage security agent. Read the source (grep for SharedPreferences, "
    "getSharedPreferences, Prefs, openFileOutput, getExternalStorage, SQLite) to find sensitive data (credentials, "
    "tokens, PII) written to insecure storage. PROVE it on the device: use list_app_files('shared_prefs') and "
    "read_app_file('shared_prefs/<name>.xml') (and databases/) to show the ACTUAL stored secret in cleartext. "
    "Note if data is on world-readable external storage. Report the concrete secret exposed and how another app "
    "or an attacker with the right primitive reaches it." + _SCORING
)

PENDING_INTENT_SPECIALIST = (
    "You are a specialist Android PendingIntent security agent. Read the source (grep for PendingIntent, "
    "getActivity, getBroadcast, getService, getForegroundService, FLAG_MUTABLE, FLAG_IMMUTABLE). Identify concrete "
    "hijack conditions: (a) a MUTABLE PendingIntent (FLAG_MUTABLE, or on targetSdk<31 with neither FLAG_IMMUTABLE "
    "nor a fully-specified component) that wraps an IMPLICIT base Intent — a component that receives it (another "
    "app, a notification action, an SDK) can fill the blank and redirect it to run with THIS app's identity and "
    "permissions; (b) a PendingIntent handed to an untrusted sink. Quote the exact PendingIntent construction and "
    "the base Intent. State what an attacker gains (send a broadcast/start a component as the victim app). "
    "targetSdk for this app is in WORKSPACE.json - it matters for the default mutability. Report the concrete "
    "hijack + impact + a PoC, or mark it a false positive (e.g. FLAG_IMMUTABLE set, or explicit component)." + _SCORING
)

RACE_CONDITION_SPECIALIST = (
    "You are a specialist Android race-condition / concurrency security agent. Read the source for attacker-"
    "triggerable races: TOCTOU (check-then-use on a file/path/permission an attacker can swap, e.g. verify then "
    "open a world-writable or external-storage path; symlink swaps); shared mutable state (static/singleton fields, "
    "SharedPreferences, a WebView JS bridge) written from an exported or asynchronous context (exported "
    "Activity/Service/Receiver, callback, thread) without synchronization, where a fast second request changes the "
    "state another request trusts; startActivityForResult / result-delivery races; and insecure world-readable/"
    "writable temp files (MODE_WORLD_*, getExternalCacheDir). Identify a concrete race, who triggers it, and the "
    "security consequence (auth bypass, data corruption, privilege confusion). Races are hard to prove dynamically "
    "- base the finding on the code pattern + attacker-controllable timing and mark confidence honestly (often "
    "'low'/'medium'). Report the concrete race + impact, or mark it a false positive with the reason." + _SCORING
)

GENERIC_COMPONENT_SPECIALIST = (
    "You are a specialist Android component-security agent. An externally reachable component (activity/service/"
    "receiver) was found. Read its decompiled source and determine what an external app can make it do: perform a "
    "privileged action without authorization, leak data, inject/redirect intents, or trigger unsafe behavior with "
    "attacker-controlled extras. Prove or refute with am_start_component (crafted extras) / launch_deeplink and "
    "logcat. Report the concrete vulnerability + PoC, or mark it a false positive with the reason." + _SCORING
)

EXPORTED_ACTIVITY_SPECIALIST = (
    "You are a specialist Android exported-Activity security agent. An externally-launchable Activity was found. "
    "Read its source (onCreate, onNewIntent). Determine whether an external app can: (a) trigger a privileged action "
    "without authorization using attacker-controlled getIntent() extras; (b) inject unvalidated extras that reach a "
    "sink (SQL, file, WebView, another Intent); (c) hijack the task/UI via launchMode (singleTask/singleInstance) or "
    "taskAffinity; (d) leak data back via setResult to the caller. Quote the exact getIntent()/getStringExtra/"
    "onNewIntent handling. Report the concrete abuse + a PoC (am start -n pkg/activity with crafted --es/--ei "
    "extras), or mark it a false positive." + _SCORING
)

EXPORTED_SERVICE_SPECIALIST = (
    "You are a specialist Android exported-Service security agent. An externally-reachable Service (started/bound, "
    "or exposing an AIDL/Messenger interface) was found. Read its source (onStartCommand, onBind, the AIDL Stub, "
    "handleMessage). Determine whether an external app can invoke privileged operations, read/modify data, or "
    "escalate privileges without a signature-level permission. Quote the exact handling of the incoming Intent/"
    "Message. Report the concrete abuse + a PoC (am start-service / bindService), or mark it a false positive." + _SCORING
)

BROADCAST_RECEIVER_SPECIALIST = (
    "You are a specialist Android broadcast security agent. Investigate BOTH manifest-declared receivers AND "
    "DYNAMICALLY-registered ones (grep for registerReceiver / new IntentFilter) — dynamic receivers are NOT in the "
    "manifest, so you must find them in code. Look for THREE bug classes and report EACH you find as a separate "
    "finding:\n"
    "1. Injectable receiver: a receiver (esp. dynamically-registered without a permission) whose onReceive takes "
    "attacker-controlled extras and performs a sensitive action (starts an activity/service with an attacker URL, "
    "changes state). Any app can send that action.\n"
    "2. Sensitive-data leak via implicit broadcast: sendBroadcast(intent) with NO target package and NO "
    "receiverPermission carrying secrets (putExtra with username/password/token/PII). Any app registering that "
    "action receives the secrets.\n"
    "3. Missing receiverPermission on sendBroadcast.\n"
    "Quote the exact registerReceiver / onReceive / sendBroadcast + putExtra lines. Give a PoC: for injection an "
    "`adb shell am broadcast -a <action> --es <key> <val>`; for a leak, a tiny malicious receiver "
    "(<receiver> with <intent-filter action=...> + onReceive that reads the extras). Report each concrete "
    "injection/leak, or mark a false positive." + _SCORING
)

PERMISSIONS_SPECIALIST = (
    "You are a specialist Android permissions security agent. Review the manifest intelligence + code for custom-"
    "permission weaknesses: a custom permission with protectionLevel normal/dangerous (not signature) guarding a "
    "sensitive component, so ANY app can request it and gain access; permission re-delegation / confused deputy (a "
    "component performs a permission-protected action on behalf of an unprivileged caller without re-checking); a "
    "sensitive component with no permission at all. Quote the manifest <permission>/<uses-permission> declaration or "
    "the delegating code. Report the concrete weakness + impact, or mark it a false positive." + _SCORING
)

NETWORK_SECURITY_SPECIALIST = (
    "You are a specialist Android network/TLS security agent. Read the code + resources/xml (network_security_config) "
    "for: cleartext HTTP (http:// endpoints, usesCleartextTraffic=true); disabled TLS validation (a custom "
    "X509TrustManager whose checkServerTrusted is empty / trusts all, an ALLOW_ALL HostnameVerifier, "
    "WebViewClient.onReceivedSslError calling handler.proceed()); missing certificate pinning on sensitive endpoints; "
    "a permissive network_security_config (cleartextTrafficPermitted=true, user trust-anchors). Quote the exact "
    "TrustManager/HostnameVerifier/onReceivedSslError/config. Report the MITM exposure + impact, or false positive." + _SCORING
)

SECRETS_SPECIALIST = (
    "You are a specialist Android hardcoded-secrets agent. grep the decompiled sources, res/values/strings.xml, "
    "BuildConfig, and assets/ for hardcoded credentials, API keys, tokens, private keys, Firebase/cloud configs, "
    "signing secrets, or backend URLs with embedded auth. Distinguish real secrets from public identifiers/config. "
    "Quote the exact line containing the hardcoded value (you may redact the middle of a long secret but keep enough "
    "to prove it is real). Report what the secret grants an attacker + where it lives, or mark it a false positive." + _SCORING
)

LOGGING_SPECIALIST = (
    "You are a specialist Android sensitive-logging agent. grep for Log.d/Log.v/Log.i/Log.w/Log.e, System.out.print, "
    "and printStackTrace that emit sensitive data (credentials, tokens, PII, full request/response bodies, keys, "
    "SharedPreferences dumps). Quote the exact logging statement and the sensitive argument. Report the leak + how an "
    "attacker reads it (adb logcat, READ_LOGS, a log-reader exploit), or mark it a false positive." + _SCORING
)

SQL_INJECTION_SPECIALIST = (
    "You are a specialist Android SQL-injection agent. grep for rawQuery/execSQL/db.query where selection, "
    "selectionArgs, table, or sortOrder are built by concatenating (+ or String.format) external input "
    "(getStringExtra/getQueryParameter/provider selection). Determine whether attacker-controlled input reaches a SQL "
    "string unparameterised. Quote the exact query-construction line. Report the injection + a concrete payload, or "
    "mark it a false positive (parameterised with ? placeholders)." + _SCORING
)

NATIVE_LIBRARY_SPECIALIST = (
    "You are a specialist Android native-library (.so / JNI) security agent. The app bundles native code under "
    "unpacked/lib/<abi>/*.so. Investigate it for vulnerabilities reachable from the app's Java attack surface.\n"
    "TOOLS available to you: `list_native_libs` (see the .so files); `native_recon` with {\"path\":\"unpacked/lib/"
    "arm64-v8a/libX.so\"} to get the JNI exports (Java_* functions = the native surface reachable from Java), the "
    "imported functions with DANGEROUS ones flagged (system/exec/popen = command injection; strcpy/strcat/sprintf/"
    "memcpy/gets = buffer overflow; dlopen/mprotect = code loading; GetByteArrayElements/GetStringUTFChars = unchecked "
    "JNI input), and interesting embedded strings (hardcoded keys/URLs/commands/format strings); `native_disasm` with "
    "{\"path\":...,\"symbol\":\"Java_...\"} to disassemble one function.\n"
    "Analysis method:\n"
    "1. Run native_recon on the app's own .so (prefer arm64-v8a; skip obvious third-party SDK libs). Identify the "
    "JNI-exported functions. For each, grep jadx/sources for the matching `native` method declaration and the "
    "System.loadLibrary call, and find which Java class/component invokes it.\n"
    "2. For each JNI export reachable from an EXPORTED or attacker-reachable Java component, hunt: command injection "
    "(attacker string reaching system/exec/popen), buffer/stack overflow (attacker-sized data into strcpy/memcpy/"
    "sprintf with no bounds check), integer overflow feeding an allocation/copy, format-string (%s/%n reaching printf), "
    "unchecked GetByteArrayElements/GetStringUTFChars length, and insecure crypto / hardcoded keys in the .so.\n"
    "3. Verify with native_disasm: confirm the dangerous import is actually called on attacker-controlled data and that "
    "no length/validation guard dominates it. Distinguish a real reachable bug from a benign internal use.\n"
    "4. Deliberate falsification: prove the end-to-end path Java entrypoint -> native method (JNI) -> dangerous sink. If "
    "you cannot demonstrate attacker reachability, mark it a false positive or honest low-confidence uncertainty.\n"
    "Report the concrete native vulnerability with the CROSS-LAYER trigger (the Java entrypoint through the JNI method "
    "to the native sink) and a PoC (the malicious app / adb call that reaches the JNI method with the crafted input). "
    "Set code_file to the .so path (unpacked/lib/<abi>/libX.so) and code_evidence to the JNI export + flagged dangerous "
    "import (and the disasm snippet you relied on). If unreachable or benign, mark it a false positive." + _SCORING
)

# --------------------------------------------------------------------------- #
# False-positive adjudicator (verify each finding like a human researcher)      #
# --------------------------------------------------------------------------- #

# The Android adjudicator above asks about manifests, exported components and adb. Pointing
# it at a server-side repository asks the wrong questions, so source scans get their own.
SOURCE_FP_ADJUDICATOR_PROMPT = (
    "You are a senior application-security reviewer doing FALSE-POSITIVE TRIAGE on ONE reported finding in a "
    "server-side / library codebase. Decide whether it is a REAL bug an external attacker can reach and abuse, "
    "or a false positive. Do NOT trust the report - read the ACTUAL code with your tools and judge for yourself.\n\n"
    "1. REACHABILITY - Is the vulnerable code reachable from an EXTERNAL entrypoint (an HTTP route, RPC/gRPC "
    "handler, queue consumer, webhook, scheduled job fed by user data, or the public API of a library)? read_file "
    "the cited file, then grep for callers of that method and follow them OUTWARD until you reach an entrypoint or "
    "run out of callers. Internal-only helpers, dead code, examples, generated stubs, build tooling and test "
    "fixtures are not attacker-reachable.\n"
    "2. CHAINED REACHABILITY (mandatory before rejecting anything as unreachable) - a private or internal method is "
    "still reachable if a public handler calls it with attacker-controlled data. Only after searching for callers "
    "and finding none may you call it unreachable.\n"
    "3. GUARDS / BYPASSES - Are there checks that actually stop it: authentication, an authorization or role check, "
    "input validation, an allowlist, a parameterised query or ORM binding, output encoding, a path canonicaliser, a "
    "framework protection on by default? Read them. Do they HOLD for the stated input, or are they bypassable "
    "(wrong order, missing on one branch, canonicalisation mismatch, regex hole, only on the happy path)? If a "
    "bypass is needed, state exactly what it is.\n"
    "4. PRECONDITIONS - Does it need conditions an external attacker cannot meet: admin privileges already held, a "
    "non-default configuration, local filesystem or debugger access, an unrealistic race?\n"
    "5. EVIDENCE MATCH - Does the reported file, line and code_evidence correspond to real code that is actually "
    "there, or to paraphrased, moved or invented code? Quote what you actually see.\n\n"
    "Return the verdict exploitable only when an external attacker with no more than ordinary privileges can "
    "trigger it in the default configuration; needs_conditions when it is real but requires a specific bypass, "
    "chain, role or configuration (state it); false_positive when it is not practically reachable or a guard holds. "
    "Give the concrete blockers and any bypass needed.\n\n"
    "FAILED LOOKUPS ARE NOT EVIDENCE. If a read_file or grep returns nothing the code may still exist elsewhere - "
    "retry with list_dir or a broader grep. You may NOT return false_positive because you could not find something; "
    "that is uncertainty, not proof of safety. Return needs_conditions and say what you could not verify."
)


FP_ADJUDICATOR_PROMPT = (
    "You are a senior Android exploitation reviewer doing FALSE-POSITIVE TRIAGE on ONE reported finding. Decide, "
    "like a human bug-bounty researcher, whether it is a REAL bug an external attacker can actually exploit, or a "
    "false positive / not practically exploitable. Do NOT trust the report's claim — read the ACTUAL decompiled "
    "code and the manifest with your tools and judge for yourself.\n\n"
    "Answer these questions by investigating:\n"
    "1. REACHABILITY — Is the vulnerable code reachable by an EXTERNAL attacker? read_file the cited file. Is it the "
    "app's own code, or a bundled/obfuscated LIBRARY class that no exported component reaches (e.g. "
    "jadx/sources/g8/m.java, androidx/*, kotlin/*, okhttp3/*)? Is the owning component exported / does it have an "
    "intent-filter, deep link, or provider authority? grep for who actually calls this class/method and whether that "
    "call path starts at an exported entry point.\n"
    "1b. CHAINED REACHABILITY (mandatory before rejecting anything as unreachable) - 'not exported' is NOT "
    "the same as 'not reachable'. Before you may call a non-exported component a false positive you MUST "
    "search for a way an EXPORTED component hands control or data to it: grep the exported components for "
    "startActivity / startService / sendBroadcast on an Intent built from getIntent() extras, getParcelableExtra "
    "of android.intent.extra.STREAM, setResult, a redirected Uri, or a granted content:// URI. If such a path "
    "exists the finding is REAL but chained: return 'needs_conditions' and name the exported component and "
    "the hop. Only after looking and finding no exported caller and no redirection may you return "
    "'false_positive' for a non-exported component.\n"
    "2. GUARDS / BYPASSES — Are there validations that stop the exploit: a URL host/scheme allowlist (e.g. only "
    "https://example.com is loaded), permission or signature checks, input validation? read them. Do they actually "
    "HOLD, or are they BYPASSABLE (subdomain, @, #, regex hole, missing scheme check, path traversal)? If a bypass "
    "is required, state exactly what it is.\n"
    "3. PRECONDITIONS — Does exploitation need conditions an attacker can't meet (root, a specific already-installed "
    "app, an already-granted permission, unrealistic user interaction, debug/test-only code)?\n"
    "4. EVIDENCE MATCH — Does the reported code_evidence / PoC correspond to real, reachable code, or to dead / "
    "hallucinated / wrong-file code?\n\n"
    "Use read_file / grep / list_dir on the real sources. If a device is connected you MAY prove reachability with "
    "am_start_component / content_query / launch_deeplink (a 'Permission Denial', no-such-component, or no effect "
    "PROVES it is NOT reachable). Then return the verdict: 'exploitable' only if a real external attacker can trigger "
    "it as configured; 'needs_conditions' if it is real but requires a specific bypass/chain/precondition (state it); "
    "'false_positive' if it is not practically exploitable (unreachable/obfuscated library, a guard that holds, dead "
    "code, wrong file). Give the concrete blockers and any bypass needed. Be strict about unreachable and "
    "library/dead code - but never downgrade a chain-reachable bug to 'false_positive'; that is what "
    "'needs_conditions' is for. Rejecting a real chained bug is as costly as accepting a fake one."
    "\n\nFAILED LOOKUPS ARE NOT EVIDENCE. If a read_file or grep comes back empty or errors, the file may still "
    "exist under a different path - retry with list_dir or a broader grep before drawing any conclusion. You may "
    "NOT return 'false_positive' on the grounds that you could not find or read something; that is uncertainty, "
    "not proof of safety. In that case return 'needs_conditions' and say exactly what you were unable to verify."
)

FP_VERDICT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": ["exploitable", "needs_conditions", "false_positive"]},
        "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
        "reachable": {"type": "boolean"},
        "reason": {"type": "string"},
        "blockers": {"type": "array", "items": {"type": "string"}},
        "bypass_needed": {"type": "string"},
    },
    "required": ["verdict", "confidence", "reachable", "reason"],
    "additionalProperties": False,
}


SPECIALISTS = {
    "webview": WEBVIEW_SPECIALIST,
    "uxss": UXSS_SPECIALIST,
    "native_library": NATIVE_LIBRARY_SPECIALIST,
    "content_provider": CONTENT_PROVIDER_SPECIALIST,
    "intent_redirection": INTENT_REDIRECTION_SPECIALIST,
    "pending_intent": PENDING_INTENT_SPECIALIST,
    "race_condition": RACE_CONDITION_SPECIALIST,
    "crypto": CRYPTO_SPECIALIST,
    "storage": STORAGE_SPECIALIST,
    "exported_activity": EXPORTED_ACTIVITY_SPECIALIST,
    "exported_service": EXPORTED_SERVICE_SPECIALIST,
    "broadcast_receiver": BROADCAST_RECEIVER_SPECIALIST,
    "permissions": PERMISSIONS_SPECIALIST,
    "network_security": NETWORK_SECURITY_SPECIALIST,
    "secrets": SECRETS_SPECIALIST,
    "logging": LOGGING_SPECIALIST,
    "sql_injection": SQL_INJECTION_SPECIALIST,
    "generic": GENERIC_COMPONENT_SPECIALIST,
}

# UI-facing name + one-line description for each specialist. Combined with the prompt above
# (the `content`), these become editable agent skills in the Agent Skills page, one per
# specialist. The deterministic router (pick_specialist) selects which one runs on each
# component; the engine loads the (editable) DB copy at scan time, falling back to the
# built-in prompt when a skill row is missing.
MOBILE_SKILL_META: dict[str, tuple[str, str]] = {
    "webview": ("Android WebView & Deep-Link Specialist", "Arbitrary-URL load, JS bridges, file access, and bypassable URL allowlists in WebView / deep-link components."),
    "uxss": ("Android WebView UXSS Specialist", "Universal XSS in in-app WebViews: bridge reply-path TOCTOU origin races and javascript:-scheme / intent-routing navigation UXSS — session/cookie theft and account takeover."),
    "native_library": ("Android Native Library (.so / JNI) Specialist", "ELF/JNI analysis of bundled .so files: command injection, buffer/format-string overflows, unchecked JNI input, and hardcoded secrets — with cross-layer Java→JNI→native reachability."),
    "content_provider": ("Android ContentProvider Specialist", "Data exposure, SQL injection, path traversal, and over-broad FileProvider paths in ContentProviders."),
    "intent_redirection": ("Android Intent-Redirection Specialist", "Intent redirection that launches non-exported components/actions with the app's own privileges."),
    "pending_intent": ("Android PendingIntent Hijack Specialist", "Mutable / implicit PendingIntents an attacker can hijack to act with the app's identity."),
    "race_condition": ("Android Race-Condition & TOCTOU Specialist", "Attacker-triggerable races, TOCTOU on files/paths, and unsafe shared mutable state."),
    "crypto": ("Android Cryptography Specialist", "Hardcoded keys/IVs, ECB mode, weak algorithms, and insecure randomness."),
    "storage": ("Android Insecure-Storage Specialist", "Credentials/tokens/PII written to SharedPreferences, SQLite, or world-readable storage in cleartext."),
    "exported_activity": ("Android Exported-Activity Specialist", "Privileged actions, unvalidated extras, task hijacking, and setResult leaks in exported activities."),
    "exported_service": ("Android Exported-Service Specialist", "Privileged operations reachable via started / bound / AIDL / Messenger services."),
    "broadcast_receiver": ("Android Broadcast Security Specialist", "Injectable receivers, credential leaks via implicit broadcasts, and missing receiver permissions."),
    "permissions": ("Android Permissions & Confused-Deputy Specialist", "Weak custom permissions, permission re-delegation, and unguarded sensitive components."),
    "network_security": ("Android Network / TLS Security Specialist", "Cleartext traffic, disabled TLS validation, missing pinning, and permissive network configs."),
    "secrets": ("Android Hardcoded-Secrets Specialist", "Hardcoded credentials, API keys, tokens, and signing secrets in code / resources / assets."),
    "logging": ("Android Sensitive-Logging Specialist", "Credentials, tokens, and PII leaked through Log / print / stack traces."),
    "sql_injection": ("Android SQL-Injection Specialist", "Unparameterised SQL built from attacker-controlled input in queries and providers."),
    "generic": ("Android Component-Security Specialist", "General exported-component abuse: privileged actions, data leaks, and intent injection."),
}

# Editable mobile agent skills that are NOT per-vuln-class specialists (not routed by
# pick_specialist) — e.g. the false-positive adjudicator that re-checks each finding.
MOBILE_EXTRA_SKILLS: list[dict[str, str]] = [
    {
        "selector": "fp_adjudicator",
        "name": "Android False-Positive Adjudicator",
        "description": "Re-verifies each finding like a human researcher: reachability, guards/bypasses, preconditions, and evidence match — marks real / needs-conditions / false-positive.",
        "content": FP_ADJUDICATOR_PROMPT,
    },
]

_MOBILE_SLUG_PREFIX = "mobile-"


def _selector_to_slug(selector: str) -> str:
    return _MOBILE_SLUG_PREFIX + selector.replace("_", "-")


def _slug_to_selector(slug: str) -> str:
    return slug[len(_MOBILE_SLUG_PREFIX):].replace("-", "_")


def mobile_specialist_skill_defs() -> list[dict[str, str]]:
    """The specialists as agent-skill records (slug/name/description/content)."""

    defs: list[dict[str, str]] = []
    for selector, content in SPECIALISTS.items():
        name, description = MOBILE_SKILL_META.get(selector, (f"Android {selector} specialist", ""))
        defs.append(
            {
                "slug": _selector_to_slug(selector),
                "selector": selector,
                "name": name,
                "description": description,
                "content": content,
            }
        )
    for extra in MOBILE_EXTRA_SKILLS:
        defs.append(
            {
                "slug": _selector_to_slug(extra["selector"]),
                "selector": extra["selector"],
                "name": extra["name"],
                "description": extra["description"],
                "content": extra["content"],
            }
        )
    return defs


def ensure_mobile_specialist_skills(conn) -> int:
    """Seed the specialist agent skills into public.agent_skills (insert-if-missing, so a
    user's UI edits are never overwritten). Returns the number newly installed."""

    installed = 0
    for skill in mobile_specialist_skill_defs():
        cur = conn.execute(
            """
            INSERT INTO public.agent_skills (slug, name, description, content)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (slug) DO NOTHING
            """,
            (skill["slug"], skill["name"], skill["description"], skill["content"]),
        )
        installed += cur.rowcount or 0
    conn.commit()
    return installed


def load_mobile_specialist_prompts(conn) -> dict[str, str]:
    """Load the (editable) specialist prompts from the DB as {selector: content}. Missing
    rows simply fall back to the built-in SPECIALISTS constant at use time."""

    prompts: dict[str, str] = {}
    for slug, content in conn.execute(
        "SELECT slug, content FROM public.agent_skills WHERE slug LIKE %s",
        (_MOBILE_SLUG_PREFIX + "%",),
    ).fetchall():
        if content and str(content).strip():
            prompts[_slug_to_selector(slug)] = content
    return prompts


def pick_specialist(lead: dict[str, Any]) -> str:
    kind = str(lead.get("kind", "")).lower()
    text = f"{lead.get('component','')} {lead.get('vulnerability_type','')}".lower()
    # Vulnerability-class keywords (most specific first).
    if kind == "native" or "native" in text or ".so" in text or "jni" in text:
        return "native_library"
    if "uxss" in text or "universal cross" in text or "cross-site" in text or "cross site" in text:
        return "uxss"
    if "webview" in text or "deep" in text:
        return "webview"
    if "sql" in text:
        return "sql_injection"
    if "secret" in text or "hardcoded" in text or "api key" in text:
        return "secrets"
    if "network" in text or "tls" in text or "cleartext" in text or "pinning" in text or "mitm" in text:
        return "network_security"
    if "permission" in text:
        return "permissions"
    if "logging" in text or "sensitive log" in text:
        return "logging"
    if "pending" in text:
        return "pending_intent"
    if "race" in text or "concurren" in text or "toctou" in text:
        return "race_condition"
    if "redirect" in text:
        return "intent_redirection"
    if "crypto" in text or "cipher" in text:
        return "crypto"
    if "storage" in text or "pref" in text:
        return "storage"
    # Component-type routing.
    if kind == "provider" or "provider" in text:
        return "content_provider"
    if kind == "service" or "service" in text:
        return "exported_service"
    if kind == "receiver" or "receiver" in text:
        return "broadcast_receiver"
    if kind in ("activity", "activity-alias") or "activity" in text:
        return "exported_activity"
    return "generic"


# --------------------------------------------------------------------------- #
# Investigation loop                                                          #
# --------------------------------------------------------------------------- #


def _controller_schema(tool_names: list[str]) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "thought": {"type": "string"},
            "tool": {"type": "string", "enum": [*tool_names, "finish"]},
            "arguments": {"type": "object", "additionalProperties": True},
        },
        "required": ["tool"],
        "additionalProperties": False,
    }


def _component_source_path(component: str) -> str | None:
    comp = str(component or "").split(" ")[0]
    if comp and "." in comp and "(" not in str(component):
        return "jadx/sources/" + comp.replace(".", "/") + ".java"
    return None


_STATIC_SINKS = {
    "webview": r"loadUrl|getQueryParameter|addJavascriptInterface|setAllowUniversalAccessFromFileURLs|setJavaScriptEnabled",
    "uxss": r"evaluateJavascript|loadUrl\(|javascript:|@JavascriptInterface|addJavascriptInterface|shouldOverrideUrlLoading|browser_fallback_url|onNewIntent|getStringExtra",
    "content_provider": r"public.*(query|insert|update|delete|openFile)|rawQuery|SQLiteDatabase|selection",
    "storage": r"getSharedPreferences|SharedPreferences|\.edit\(\)|openFileOutput|getExternalStorage|MODE_",
    "crypto": r"Cipher\.getInstance|SecretKeySpec|IvParameterSpec|MessageDigest|java\.util\.Random|\"AES|DES\"",
    "intent_redirection": r"getParcelableExtra|startActivity|startService|sendBroadcast|getIntent\(\)",
    "pending_intent": r"PendingIntent\.|FLAG_MUTABLE|FLAG_IMMUTABLE",
    "race_condition": r"synchronized|getExternalCacheDir|createTempFile|MODE_WORLD|Thread|runOnUiThread",
    "exported_activity": r"getIntent\(\)|getStringExtra|getParcelableExtra|onNewIntent|onCreate\(|setResult",
    "exported_service": r"onStartCommand|onBind|handleMessage|Messenger|extends Service|\.Stub",
    "broadcast_receiver": r"onReceive|registerReceiver|sendBroadcast|abortBroadcast|getResultData",
    "permissions": r"android:permission|protectionLevel|checkPermission|enforcePermission|checkCallingPermission",
    "network_security": r"TrustManager|checkServerTrusted|HostnameVerifier|onReceivedSslError|http://|SSLContext|setHostnameVerifier",
    "secrets": r"[Aa]pi[_-]?[Kk]ey|SECRET|[Pp]assword\s*=|[Tt]oken\s*=|BEGIN [A-Z ]*PRIVATE KEY|AIza[0-9A-Za-z_\-]{10}|sk_live|Bearer ",
    "logging": r"Log\.[dviwe]\(|System\.out\.print|printStackTrace",
    "sql_injection": r"rawQuery|execSQL|db\.query|\.query\(|String\.format|SELECT .*\"\s*\+|WHERE .*\+",
}


def _pregather_static(lead: dict[str, Any], tools: "SpecialistTools", specialist_key: str) -> str:
    """Code-only pre-gather: the component's source + a grep of the class's sink patterns."""

    blocks: list[str] = []
    path = _component_source_path(lead.get("component", ""))
    if path:
        blocks.append(f"{path}:\n" + tools.dispatch("read_file", {"path": path}))
    pattern = _STATIC_SINKS.get(specialist_key)
    if pattern:
        blocks.append(f"grep {pattern!r} in jadx/sources:\n" + tools.dispatch("grep", {"pattern": pattern, "path": "jadx/sources", "max_results": 40}))
    if specialist_key == "content_provider":
        # FileProvider exposure lives in its path config, not code — surface it.
        for xml in ("jadx/resources/res/xml/provider_paths.xml", "apktool/res/xml/provider_paths.xml",
                    "jadx/resources/res/xml/file_paths.xml", "apktool/res/xml/file_paths.xml",
                    "jadx/resources/res/xml/filepaths.xml", "apktool/res/xml/paths.xml"):
            content = tools.dispatch("read_file", {"path": xml})
            if not content.startswith("["):
                blocks.append(f"{xml} (FileProvider path config — root-path '/' or external-path '.' = whole filesystem exposed):\n{content}")
    return "\n\n".join(b for b in blocks if b.strip())[:9000]


def _extract_real_code(tools: "SpecialistTools", code_file: str, code_evidence: str) -> tuple[str, str]:
    """Return (verified_code_with_line_numbers, code_file) — pull the ACTUAL lines from the
    decompiled source so the UI shows real app code, not a paraphrase."""

    path = code_file if code_file and "/" in code_file else _component_source_path(code_file) or code_file
    if not path:
        return code_evidence, code_file
    text = tools.code.dispatch("read_file", {"path": path})
    if text.startswith("[") or not text.strip():
        return code_evidence, code_file
    lines = text.splitlines()
    # Find the model's most distinctive quoted line inside the real file.
    candidates = sorted((ln.strip() for ln in (code_evidence or "").splitlines() if len(ln.strip()) > 12), key=len, reverse=True)
    for needle in candidates[:6]:
        for i, ln in enumerate(lines):
            if needle[:60] in ln:
                lo, hi = max(0, i - 4), min(len(lines), i + 6)
                snippet = "\n".join(f"{n + 1:>4}  {lines[n]}" for n in range(lo, hi))
                return snippet, path
    return code_evidence, path


def _pregather_evidence(lead: dict[str, Any], tools: "SpecialistTools", specialist_key: str) -> str:
    """Deterministically collect on-device evidence for this class BEFORE the agent runs,
    so a small model interprets concrete facts instead of having to discover them."""

    blocks: list[str] = []
    try:
        if specialist_key == "storage":
            listing = tools.dispatch("list_app_files", {"subdir": "shared_prefs"})
            blocks.append("shared_prefs directory:\n" + listing)
            for line in listing.splitlines():
                parts = line.split()
                name = parts[-1] if parts else ""
                if name.endswith(".xml"):
                    blocks.append(f"shared_prefs/{name}:\n" + tools.dispatch("read_app_file", {"path": f"shared_prefs/{name}"}))
            blocks.append("databases:\n" + tools.dispatch("list_app_files", {"subdir": "databases"}))
        elif specialist_key == "content_provider":
            for authority in ([lead.get("authorities")] if lead.get("authorities") else []):
                for sub in ("", "/prefs", "/../databases", "/../shared_prefs"):
                    uri = f"content://{authority}{sub}"
                    blocks.append(f"content_query {uri}:\n" + tools.dispatch("content_query", {"uri": uri}))
        elif specialist_key == "webview":
            for tmpl in (lead.get("deep_links") or [])[:2]:
                template = tmpl if "CALLBACK" in tmpl else (tmpl.rstrip("=") + "=CALLBACK" if tmpl.endswith("=") else tmpl + "CALLBACK")
                blocks.append(f"network_callback_test {template}:\n" + tools.dispatch("network_callback_test", {"deeplink_template": template}))
    except Exception as exc:  # noqa: BLE001 - pre-gather is best-effort
        blocks.append(f"[pre-gather error: {exc}]")
    return "\n\n".join(b for b in blocks if b.strip())[:8000]


def investigate_lead(
    lead: dict[str, Any],
    *,
    workspace_dir: str,
    package: str,
    device: Device | None = None,
    max_steps: int = 14,
    min_steps: int = 5,
    static_only: bool = False,
    specialist_prompts: dict[str, str] | None = None,
) -> dict[str, Any]:
    if not static_only and device is None:
        device = get_device()
    if static_only:
        device = None
    client = LocalLLMClient(model="local", timeout_seconds=1200)
    tools = SpecialistTools(workspace_dir, device, package, static_only=static_only)
    specialist_key = pick_specialist(lead)
    # Prefer the editable DB skill for this specialist; fall back to the built-in prompt.
    specialist = (specialist_prompts or {}).get(specialist_key) or SPECIALISTS[specialist_key]
    transcript: list[str] = []

    pregathered = _pregather_static(lead, tools, specialist_key) if tools.static_only else _pregather_evidence(lead, tools, specialist_key)
    evidence_label = "the component source + sink grep below" if tools.static_only else "the deterministic on-device evidence below"
    mode_note = (
        "STATIC-ONLY MODE: no device is available. Base the finding purely on the decompiled code; set "
        "dynamic_evidence to 'not tested (static-only analysis)' and choose confidence honestly. "
        if tools.static_only
        else ""
    )
    if pregathered:
        transcript.append("[pre-gathered evidence]\n" + pregathered)

    messages = [
        {"role": "system", "content": specialist + "\n\n" + mode_note + "Call exactly one tool per turn; use `thought` to plan."},
        {
            "role": "user",
            "content": (
                f"Package: {package}\nLead: {json.dumps(lead)}\n"
                f"Deep links available for this app: {lead.get('deep_links')}\n\n"
                + (f"Evidence already collected for you ({evidence_label}) — treat as authoritative facts:\n" + pregathered + "\n\n" if pregathered else "")
                + "Read the vulnerable source, quote the exact vulnerable lines, "
                + ("" if tools.static_only else "prove or refute exploitability with a tool, ")
                + "then finish with the precise finding."
            ),
        },
    ]
    tool_names = tools.names()
    controller = _controller_schema(tool_names)
    tool_calls = 0
    seen_calls: set[str] = set()
    tested_dynamically = False
    require_dynamic = not tools.static_only
    for step in range(1, max_steps + 1):
        messages = trim_history(messages)  # keep the history within the model context window
        reply = client.chat(messages=messages, json_schema=controller, schema_name="tool", temperature=0.2, max_tokens=1500)
        decision = _loads_lenient(reply.get("content", "")) or {}
        tool = str(decision.get("tool") or "").strip()
        args = decision.get("arguments") if isinstance(decision.get("arguments"), dict) else {}
        if decision.get("thought"):
            transcript.append(f"[{step}] {decision['thought']}")
        if tool in ("finish", "") or tool not in tool_names:
            if tool_calls < min_steps or (require_dynamic and not tested_dynamically):
                nudge = "Do not finish yet. Read the vulnerable source and grep for the exact sink (loadUrl / getQueryParameter / Cipher / PendingIntent / getSharedPreferences)"
                nudge += " and PROVE exploitability with a device tool before finishing." if require_dynamic else " before finishing."
                messages.append({"role": "user", "content": nudge})
                continue
            break
        call_key = f"{tool}:{json.dumps(args, sort_keys=True)}"
        if call_key in seen_calls:
            messages.append({"role": "user", "content": "You already ran that exact call. Try a different tool or grep pattern, then finish."})
            continue
        seen_calls.add(call_key)
        tool_calls += 1
        if tool in ("network_callback_test", "content_query", "read_app_file", "am_start_component"):
            tested_dynamically = True
        obs = tools.dispatch(tool, args)
        transcript.append(f"[{step}] {tool}({json.dumps(args)[:160]}) -> {obs[:600]}")
        messages.append({"role": "assistant", "content": json.dumps(decision)})
        messages.append({"role": "user", "content": f"Observation:\n{obs[:14000]}\nChoose the next tool or finish."})

    final_messages = [
        {"role": "system", "content": "Return only the JSON finding for this lead, matching the schema, grounded in the evidence. Copy code_evidence VERBATIM from the source. Keep prose fields to 1-3 sentences."},
        {"role": "user", "content": specialist + "\n\n" + mode_note + "Evidence:\n" + "\n".join(transcript)[-16000:]},
    ]
    finding = None
    for max_tokens in (4096, 8192):
        final = client.chat(messages=final_messages, json_schema=FINDING_SCHEMA, schema_name="specialist_finding", temperature=0.1, max_tokens=max_tokens, no_think=True)
        finding = _loads_lenient(final.get("content", "")) or _loads_lenient(final.get("reasoning", ""))
        if finding is not None:
            break
        if final.get("finish_reason") != "length":
            break
    if finding is None:
        finding = {"is_vulnerable": False, "false_positive": True, "title": "unparseable", "_raw": str(final.get("content", ""))[:1500]}
    # Replace the model's quote with the ACTUAL lines pulled from the decompiled file.
    code_file = finding.get("code_file") or _component_source_path(lead.get("component", "")) or ""
    real_code, resolved = _extract_real_code(tools, code_file, finding.get("code_evidence") or "")
    finding["code_evidence"] = real_code
    finding["code_file"] = resolved
    finding["_transcript"] = "\n".join(transcript)[-6000:]
    return finding


def adjudicate_finding(
    finding_ja: dict[str, Any],
    *,
    workspace_dir: str,
    package: str,
    device: Device | None = None,
    max_steps: int = 12,
    min_steps: int = 5,
    static_only: bool = False,
    specialist_prompts: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Re-verify ONE finding like a human researcher (reachability, guards/bypasses,
    preconditions, evidence match). Returns a verdict dict: verdict / confidence / reachable /
    reason / blockers / bypass_needed / _transcript."""

    if not static_only and device is None:
        try:
            device = get_device()
        except Exception:  # noqa: BLE001
            device = None
            static_only = True
    if static_only:
        device = None
    client = LocalLLMClient(model="local", timeout_seconds=1200)
    tools = SpecialistTools(workspace_dir, device, package, static_only=static_only)
    prompt = (specialist_prompts or {}).get("fp_adjudicator") or FP_ADJUDICATOR_PROMPT
    transcript: list[str] = []

    code_file = (
        finding_ja.get("code_file")
        or finding_ja.get("file_path")
        or _component_source_path(finding_ja.get("component", ""))
        or ""
    )
    pre = ""
    if code_file and "/" in str(code_file):
        pre = f"{code_file}:\n" + tools.code.dispatch("read_file", {"path": code_file})
        transcript.append("[pre-read cited file]\n" + pre[:4000])

    finding_summary = {
        "vulnerability_type": finding_ja.get("vulnerability_type"),
        "summary": finding_ja.get("summary"),
        "component": finding_ja.get("component"),
        "exported": finding_ja.get("exported"),
        "reachability": finding_ja.get("reachability"),
        "authorities": finding_ja.get("authorities"),
        "code_file": code_file,
        "severity_score": finding_ja.get("severity_score"),
        "claimed_code_evidence": (finding_ja.get("code_evidence") or "")[:1500],
        "claimed_poc": (finding_ja.get("poc") or finding_ja.get("malicious_input_example") or "")[:800],
    }
    mode_note = (
        "STATIC-ONLY MODE: no device is available — judge reachability from the decompiled code + manifest. "
        if tools.static_only
        else "A device IS connected — you MAY prove/refute reachability with am_start_component / content_query / launch_deeplink. "
    )
    messages = [
        {"role": "system", "content": prompt + "\n\n" + mode_note + "Call exactly one tool per turn; use `thought` to plan. Read the real code before deciding."},
        {
            "role": "user",
            "content": (
                f"Package: {package}\nFinding under review:\n{json.dumps(finding_summary, ensure_ascii=False)}\n\n"
                + (f"Cited file already read for you:\n{pre[:6000]}\n\n" if pre else "")
                + "Verify whether an EXTERNAL attacker can really exploit this, or it is a false positive. Read the "
                "actual code, grep for who reaches this class/component, and inspect the guards. Then finish with the verdict."
            ),
        },
    ]
    tool_names = tools.names()
    controller = _controller_schema(tool_names)
    tool_calls = 0
    seen_calls: set[str] = set()
    for step in range(1, max_steps + 1):
        messages = trim_history(messages)  # keep the history within the model context window
        reply = client.chat(messages=messages, json_schema=controller, schema_name="tool", temperature=0.2, max_tokens=1200)
        decision = _loads_lenient(reply.get("content", "")) or {}
        tool = str(decision.get("tool") or "").strip()
        args = decision.get("arguments") if isinstance(decision.get("arguments"), dict) else {}
        if decision.get("thought"):
            transcript.append(f"[{step}] {decision['thought']}")
        if tool in ("finish", "") or tool not in tool_names:
            if tool_calls < min_steps:
                messages.append({"role": "user", "content": "Do not finish yet — read the cited file and grep for who calls this component/class before judging reachability."})
                continue
            break
        call_key = f"{tool}:{json.dumps(args, sort_keys=True)}"
        if call_key in seen_calls:
            messages.append({"role": "user", "content": "You already ran that exact call. Try a different file/pattern, then finish."})
            continue
        seen_calls.add(call_key)
        tool_calls += 1
        obs = tools.dispatch(tool, args)
        transcript.append(f"[{step}] {tool}({json.dumps(args)[:160]}) -> {obs[:600]}")
        messages.append({"role": "assistant", "content": json.dumps(decision)})
        messages.append({"role": "user", "content": f"Observation:\n{obs[:12000]}\nChoose the next tool or finish."})

    final_messages = [
        {"role": "system", "content": "Return ONLY the JSON verdict matching the schema, grounded in what you actually read. Be strict: 'false_positive' when the code is unreachable / an obfuscated-library / guarded / dead / wrong-file; 'needs_conditions' when real but requiring a bypass or chain (name it in bypass_needed); 'exploitable' only when a real external attacker can trigger it as configured."},
        {"role": "user", "content": prompt + "\n\nFinding:\n" + json.dumps(finding_summary, ensure_ascii=False) + "\n\nEvidence you gathered:\n" + "\n".join(transcript)[-14000:]},
    ]
    verdict = None
    for max_tokens in (1024, 2048):
        final = client.chat(messages=final_messages, json_schema=FP_VERDICT_SCHEMA, schema_name="fp_verdict", temperature=0.1, max_tokens=max_tokens, no_think=True)
        verdict = _loads_lenient(final.get("content", "")) or _loads_lenient(final.get("reasoning", ""))
        if verdict is not None:
            break
        if final.get("finish_reason") != "length":
            break
    if not isinstance(verdict, dict) or "verdict" not in verdict:
        verdict = {
            "verdict": "needs_conditions",
            "confidence": "low",
            "reachable": bool(finding_ja.get("exported")),
            "reason": "Adjudicator could not produce a structured verdict; left unresolved.",
            "blockers": [],
            "bypass_needed": "",
        }
    verdict["_transcript"] = "\n".join(transcript)[-6000:]
    return verdict


# --------------------------------------------------------------------------- #
# Chain analyst: combine primitives into higher-severity attack chains        #
# --------------------------------------------------------------------------- #

CHAIN_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "chains": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "steps": {"type": "array", "items": {"type": "string"}},
                    "components_involved": {"type": "array", "items": {"type": "string"}},
                    "combined_impact": {"type": "string"},
                    "severity_score": {"type": "number"},
                    "feasibility": {"type": "string", "enum": ["high", "medium", "low"]},
                    "poc": {"type": "string"},
                },
                "required": ["title", "steps", "components_involved", "combined_impact", "severity_score", "feasibility", "poc"],
                "additionalProperties": False,
            },
        }
    },
    "required": ["chains"],
    "additionalProperties": False,
}

CHAIN_ANALYST = (
    "You are an Android exploit-chaining analyst. You are given a set of CONFIRMED vulnerabilities in one app, "
    "each with a 'chainable_primitive' describing what it gives an attacker. Your job: find the HIGHEST-SEVERITY "
    "attack CHAINS where combining two or more primitives turns lower-severity issues into a severe compromise "
    "(e.g. 'arbitrary URL load in a WebView with file access' + 'plaintext credentials in shared_prefs' => load "
    "a file:// or JS payload that reads and exfiltrates the stored credentials => full account takeover). Also "
    "consider intent-redirection to reach non-exported components, provider data feeding another sink, and "
    "attacker-controlled data persisted by one component then trusted by another. Reason step by step from an "
    "external attacker with no permissions. VERIFY the critical link with tools where possible (read_app_file to "
    "confirm a secret exists, content_query, network_callback_test). Only report chains that are more severe than "
    "their individual parts; give each an ordered step list, the components involved, combined impact, a "
    "severity_score 0-10 (a real chain to sensitive data should score high), feasibility, and a concrete PoC. "
    "If no meaningful chain exists, return an empty chains array."
)


def chain_analyst(
    findings: list[dict[str, Any]],
    *,
    workspace_dir: str,
    package: str,
    android_intel: dict[str, Any] | None = None,
    device: Device | None = None,
    max_steps: int = 12,
    static_only: bool = False,
) -> list[dict[str, Any]]:
    if not static_only and device is None:
        device = get_device()
    if static_only:
        device = None
    client = LocalLLMClient(model="local", timeout_seconds=1200)
    tools = SpecialistTools(workspace_dir, device, package, static_only=static_only)
    summary = [
        {
            "title": f.get("title") or f.get("summary"),
            "type": f.get("vulnerability_type"),
            "component": f.get("component"),
            "primitive": f.get("chainable_primitive"),
            "severity": f.get("severity_score"),
        }
        for f in findings
    ]
    transcript: list[str] = []
    messages = [
        {"role": "system", "content": CHAIN_ANALYST + "\n\nCall one tool per turn to verify a link; use `thought` to reason. Finish when you have assessed the chains."},
        {
            "role": "user",
            "content": (
                f"Package: {package}\nConfirmed vulnerabilities and their primitives:\n{json.dumps(summary, indent=2)}\n\n"
                f"App components: {json.dumps((android_intel or {}).get('components', [])[:30])}\n"
                "Identify and verify the strongest chains, then finish."
            ),
        },
    ]
    tool_names = tools.names()
    controller = _controller_schema(tool_names)
    seen: set[str] = set()
    for step in range(1, max_steps + 1):
        messages = trim_history(messages)  # keep the history within the model context window
        reply = client.chat(messages=messages, json_schema=controller, schema_name="tool", temperature=0.2, max_tokens=1500)
        decision = _loads_lenient(reply.get("content", "")) or {}
        tool = str(decision.get("tool") or "").strip()
        args = decision.get("arguments") if isinstance(decision.get("arguments"), dict) else {}
        if decision.get("thought"):
            transcript.append(f"[{step}] {decision['thought']}")
        if tool in ("finish", "") or tool not in tool_names:
            if step <= 2 and not tools.static_only:
                messages.append({"role": "user", "content": "Verify at least one chain link with a tool (e.g. read_app_file on shared_prefs) before finishing."})
                continue
            break
        key = f"{tool}:{json.dumps(args, sort_keys=True)}"
        if key in seen:
            messages.append({"role": "user", "content": "Already ran that. Try a different verification or finish."})
            continue
        seen.add(key)
        obs = tools.dispatch(tool, args)
        transcript.append(f"[{step}] {tool}({json.dumps(args)[:140]}) -> {obs[:600]}")
        messages.append({"role": "assistant", "content": json.dumps(decision)})
        messages.append({"role": "user", "content": f"Observation:\n{obs[:8000]}\nNext tool or finish."})

    result = None
    for max_tokens in (4096, 8192):
        final = client.chat(
            messages=[
                {"role": "system", "content": "Return only the JSON object with the 'chains' array, matching the schema, grounded in the evidence."},
                {"role": "user", "content": CHAIN_ANALYST + "\n\nFindings:\n" + json.dumps(summary) + "\n\nVerification notes:\n" + "\n".join(transcript)[-14000:]},
            ],
            json_schema=CHAIN_SCHEMA,
            schema_name="chains",
            temperature=0.15,
            max_tokens=max_tokens,
            no_think=True,
        )
        result = _loads_lenient(final.get("content", "")) or _loads_lenient(final.get("reasoning", ""))
        if result is not None:
            break
        if final.get("finish_reason") != "length":
            break
    chains = (result or {}).get("chains", []) if isinstance(result, dict) else []
    return chains
