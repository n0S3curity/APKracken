"""Samsung-device / default-app security agent skills.

These specialize a scan for Samsung's pre-installed system apps (com.samsung.* / com.sec.* /
com.samsung.android.*), their custom framework surface (Knox, Samsung permissions, Samsung
services), and their deep-link / provider / account ecosystem. Attach them to a scan of a
Samsung system-app APK (pulled from the device) so the tool-using agent hunts the classes that
actually pay out on Samsung's Mobile Security Rewards Program.

Same shape as security_skills.py: (selector, name, description, content), slug prefix
`samsung-`, seeded insert-if-missing so UI edits survive.

Scope: authorized research on a device you own, against Samsung's published rewards program.
"""

from __future__ import annotations

import logging

LOGGER = logging.getLogger("open_kritt_engine")

_SLUG_PREFIX = "samsung-"

# (selector, name, description, content)
_SAMSUNG_SKILLS: list[tuple[str, str, str, str]] = [
    (
        "exported-system-components",
        "Exported Samsung system components",
        "Exported Activities/Services/Receivers in com.samsung.*/com.sec.* reachable by any third-party app.",
        "Hunt EXPORTED SAMSUNG SYSTEM COMPONENTS. Samsung system apps (com.samsung.android.*, com.sec.*) ship "
        "many exported (or implicitly exported via intent-filter) Activities/Services/BroadcastReceivers that any "
        "installed app can invoke. Enumerate them from the manifest, then read each handler for a privileged action "
        "taken on caller-controlled input WITHOUT verifying the caller: writing settings, launching a WebView, "
        "starting another component with attacker extras, returning private data via setResult, or performing a "
        "system operation the app holds a signature/system permission for. A system-privileged component that "
        "forwards attacker data to a privileged sink is the core Samsung bug. Report component, exported evidence, "
        "the privileged sink file:line, the caller-controlled input, and a concrete adb `am` PoC.",
    ),
    (
        "custom-permission-downgrade",
        "Samsung custom permission protection-level flaws",
        "Samsung components 'protected' by a custom permission whose protectionLevel is normal/dangerous, or held broadly.",
        "Hunt CUSTOM PERMISSION DOWNGRADES. Samsung defines many custom permissions (com.samsung.android.*.permission.*, "
        "com.sec.*.permission.*). A component is only as protected as its permission's protectionLevel. Read "
        "<permission> declarations: flag any guarding a sensitive component that is protectionLevel `normal` or "
        "`dangerous` (auto/user grantable) instead of `signature`, or defined in a DIFFERENT app so its level is "
        "attacker-controllable (permission-definition squatting / re-declaration). Also flag components with a "
        "permission attribute that no <permission> actually defines (fails open on some OS versions). Map each "
        "sensitive exported component to its guard permission and prove a third-party app can obtain or bypass it.",
    ),
    (
        "content-provider-exposure",
        "Samsung ContentProvider exposure & path traversal",
        "Exported/grantUri Samsung providers leaking settings/account/media data or arbitrary file read via openFile.",
        "Hunt SAMSUNG CONTENTPROVIDER EXPOSURE. Samsung apps expose many providers (authorities like "
        "com.samsung.android.*.provider, com.sec.*). Check each exported provider for: query()/call() returning "
        "sensitive rows (account, contacts, settings, messages, logs) without caller checks; SQL built by "
        "concatenation in selection; and openFile()/openAssetFile() that build a filesystem path from the incoming "
        "Uri without canonicalisation (path traversal reading app-private or system files across the provider's "
        "system UID). Report authority, method, the tainted Uri->path/SQL, and an adb `content query/read` or "
        "`content call` PoC.",
    ),
    (
        "deeplink-webview",
        "Samsung deep-link / scheme -> WebView",
        "samsung:// and app-specific schemes routed into a WebView or privileged handler without host allowlisting.",
        "Hunt SAMSUNG DEEP-LINK -> WEBVIEW/PRIVILEGED HANDLER. Samsung apps register many schemes/hosts "
        "(samsungapps://, samsung://, sbrowser/internet intent:// handling, members://, bixby://, "
        "smartthings://, shealth://, and https app-links). Trace a deep link's url/host/path parameter into a "
        "WebView.loadUrl / setJavaScriptEnabled+addJavascriptInterface, an intent:// re-dispatch, or a "
        "privileged action. Test allowlist bypasses (subdomain, @, #, missing scheme check, case). A system app "
        "loading attacker-controlled web content with a JS bridge or file access is high impact. Report the "
        "scheme/host, the parameter, the sink, and the crafted deep-link PoC.",
    ),
    (
        "knox-enterprise-surface",
        "Knox / enterprise (DeviceAdmin, container, attestation)",
        "Knox SDK / enterprise components: policy bypass, container data exposure, DeviceAdmin abuse, attestation gaps.",
        "Hunt KNOX / ENTERPRISE SURFACE. Look at Knox/enterprise components (com.samsung.android.knox.*, "
        "EnterpriseDeviceManager, KnoxContainerManager, DeviceAdmin/DeviceAdminReceiver, Knox SDK bindings). Hunt: "
        "exported components that apply or relax Knox policy without caller verification; container-to-personal (or "
        "personal-to-container) data leakage through exported providers/services; DeviceAdmin receivers that act on "
        "unauthenticated broadcasts; Knox attestation/verification results trusted from an untrusted source. "
        "Report the component, the policy/data operation, the missing caller/attestation check, and the PoC path.",
    ),
    (
        "account-sso",
        "Samsung Account / SSO token theft",
        "Samsung Account authenticator/SSO flows leaking tokens or accepting attacker redirect/callbacks.",
        "Hunt SAMSUNG ACCOUNT / SSO ISSUES (com.osp.app.signin, com.samsung.android.samsungaccount, "
        "AccountManager authenticator). Hunt: exported components that return an access/refresh token or auth code to "
        "a caller-supplied Intent/PendingIntent/redirect without validating the requesting package/signature; SSO "
        "callbacks that trust an attacker-controlled redirect URI; access tokens written to logs, world/other-app "
        "readable storage, or returned via setResult to an exported activity. Trace the token from mint/store to the "
        "point an unauthorized app can read it. Report the flow, the token sink, and the malicious-app PoC.",
    ),
    (
        "pay-financial",
        "Samsung Pay / financial component abuse",
        "Samsung Pay/HCE/wallet components exposing payment tokens, card data, or privileged pay actions.",
        "Hunt SAMSUNG PAY / FINANCIAL (com.samsung.android.spay, spayfw, HCE services). Highest-value, treat "
        "conservatively. Hunt: exported services/receivers that trigger a pay/tokenization action or return "
        "card/token artifacts to a caller without strict signature checks; token or PAN material in logs, IPC "
        "payloads, or shared storage; deep links into pay flows that skip authentication; and HCE apdu handlers "
        "reachable by a malicious app. Report only concrete, code-evidenced exposure of payment material or a "
        "privileged pay action reachable by an unauthorized caller, with the exact sink and PoC.",
    ),
    (
        "services-aidl",
        "Samsung system services / AIDL (Binder) surface",
        "Exported Samsung system services and AIDL interfaces performing privileged ops without caller verification.",
        "Hunt SAMSUNG SYSTEM SERVICES / AIDL. Samsung adds system services and exported bound services with AIDL "
        "interfaces (com.samsung.android.*). For each exported <service> and its .aidl/Stub, read the transact/method "
        "implementations: does a method perform a privileged operation (settings write, file access, other-app data, "
        "policy change, command) using args from the binder caller WITHOUT checkCallingPermission / "
        "Binder.getCallingUid signature verification? Samsung services often assume only system callers. Report the "
        "service, the AIDL method, the privileged op, the missing caller check, and a bindService PoC snippet.",
    ),
    (
        "insecure-broadcast-leak",
        "Samsung broadcast / sticky-intent data leaks & injection",
        "Samsung system apps sending sensitive data in implicit/sticky broadcasts, or acting on unprotected receivers.",
        "Hunt SAMSUNG BROADCAST ISSUES. Two directions: (1) LEAK - Samsung system apps sendBroadcast() with sensitive "
        "extras (account, location, IMEI/serial, tokens, state) as an IMPLICIT broadcast (no package/permission), so "
        "any app with a matching receiver reads it; and sticky broadcasts persisting sensitive data. (2) INJECTION - "
        "exported/dynamically-registered receivers with no permission that perform a privileged action on the "
        "broadcast's extras. Trace the extras source->sink. Report the action, the sensitive extra or privileged "
        "sink, and an adb `am broadcast` (injection) or a listener-app (leak) PoC.",
    ),
    (
        "bixby-voice-intents",
        "Bixby / voice intent surface",
        "Bixby capsules/voice actions and com.samsung.android.bixby.* components exposing privileged intents.",
        "Hunt BIXBY / VOICE SURFACE (com.samsung.android.bixby.*, com.samsung.android.visionintelligence, voice "
        "actions). Hunt exported Bixby components and voice-action handlers that map an utterance/intent parameter to "
        "a privileged action (launching components, changing settings, reading data) without caller verification, and "
        "deep links into Bixby that reach those actions. Report the component/action, the controlled parameter, the "
        "privileged sink, and the intent/deep-link PoC.",
    ),
    (
        "smartthings-iot",
        "SmartThings / IoT pairing & cloud tokens",
        "com.samsung.android.oneconnect (SmartThings) components exposing pairing, device control, or cloud tokens.",
        "Hunt SMARTTHINGS / IOT (com.samsung.android.oneconnect / SmartThings). Hunt: exported components that expose "
        "device pairing, local device control, or the SmartThings cloud/session token to an unauthorized caller; "
        "deep links (smartthings://) reaching device-control actions; cloud tokens or hub credentials in logs/shared "
        "storage; and provider/service methods returning connected-device or account data without caller checks. "
        "Report the component/flow, the token or control primitive, and the PoC.",
    ),
    (
        "internet-browser",
        "Samsung Internet (SBrowser) intent & file handling",
        "com.sec.android.app.sbrowser custom intent://, file://, and WebView handling reachable by other apps.",
        "Hunt SAMSUNG INTERNET (com.sec.android.app.sbrowser). Hunt: exported components that open a caller-supplied "
        "URL/file, intent:// URL handling that can reach privileged internal components or file:// with universal "
        "access, custom-tab / view-intent flows that load attacker content with weakened WebView settings, and "
        "download/file handlers writing to attacker-influenced paths. Report the entry component, the URL/file "
        "parameter, the WebView/file sink and its settings, and the PoC.",
    ),
    (
        "dex-desktop-mode",
        "Samsung DeX / desktop-mode intent handling",
        "DeX-specific components/intents that expose privileged actions only when in desktop mode.",
        "Hunt SAMSUNG DEX SURFACE. DeX (desktop mode) adds components and intent handling that behave differently or "
        "expose extra actions when docked. Hunt exported DeX components/receivers (com.samsung.android.*dex*) that "
        "take a privileged action on caller input, and mode-transition broadcasts that leak or accept sensitive "
        "state. Report the component, the DeX-specific action, the controlled input, and the PoC (noting the DeX "
        "precondition).",
    ),
    (
        "preinstalled-partner-apps",
        "Pre-installed partner / OEM bloat with system privileges",
        "Non-Samsung pre-installed apps signed/privileged on the device with weaker security than AOSP.",
        "Hunt PRE-INSTALLED PARTNER / OEM APPS. Samsung devices ship carrier/partner pre-installed apps that run with "
        "elevated (system/priv-app) privileges but often have weaker code than AOSP. Enumerate priv-app / "
        "system-partition packages that are NOT core Android, and apply the standard exported-component / provider / "
        "deep-link / broadcast hunts, weighting by the system privileges they hold (a privileged partner app with an "
        "exported command component is high impact). Report the package, its privilege evidence, the reachable sink, "
        "and the PoC.",
    ),
]


def samsung_skill_defs() -> list[dict[str, str]]:
    return [
        {"slug": _SLUG_PREFIX + selector, "selector": selector, "name": name, "description": desc, "content": content}
        for (selector, name, desc, content) in _SAMSUNG_SKILLS
    ]


def ensure_samsung_skills(conn) -> int:
    """Seed the Samsung device/default-app agent skills (insert-if-missing). Returns count added."""
    installed = 0
    for skill in samsung_skill_defs():
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
