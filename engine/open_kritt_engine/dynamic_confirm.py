"""Static -> dynamic confirmation on a connected device (Phase 3).

Takes a static finding / attack-surface lead and exercises it at runtime over ADB to
produce concrete evidence: does the exported activity actually launch, does the deep
link reach its target, does the content provider return data or deny access. This is the
reliable, ActivityManager-level confirmation loop (Frida hooking is a deeper, separate
capability). Every check is bounded and captures the raw device response as evidence.

Outcomes:
  confirmed    - the lead is exploitable/reachable as described
  guarded      - reachable but protected (e.g. permission denial) -> refines severity
  refuted      - not reachable / not present
  error        - the probe could not run
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Any

from .adb import Device, get_device

EVIDENCE_DIR = os.getenv("ENGINE_DYNAMIC_EVIDENCE_DIR") or os.path.join(
    os.getenv("ENGINE_DATA_DIR", "."), "dynamic-evidence"
)


@dataclass
class Evidence:
    check: str
    target: str
    outcome: str = "error"  # confirmed | guarded | refuted | error
    detail: str = ""
    artifacts: dict[str, str] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "check": self.check,
            "target": self.target,
            "outcome": self.outcome,
            "detail": self.detail[:1000],
            "artifacts": self.artifacts,
        }


def _short(text: str, limit: int = 400) -> str:
    return " ".join((text or "").split())[:limit]


def confirm_exported_activity(device: Device, package: str, activity: str, *, screenshot: bool = True) -> Evidence:
    component = activity if "/" in activity else f"{package}/{activity if activity.startswith('.') or '.' in activity else '.' + activity}"
    result = device.am_start(component=component)
    out = result.stdout or result.stderr
    ev = Evidence(check="exported_activity", target=component, detail=_short(out))
    if "SecurityException" in out or "Permission Denial" in out:
        ev.outcome = "guarded"
    elif "Status: ok" in out:
        ev.outcome = "confirmed"
    else:
        ev.outcome = "refuted"
    if screenshot and ev.outcome == "confirmed":
        try:
            os.makedirs(EVIDENCE_DIR, exist_ok=True)
            path = os.path.join(EVIDENCE_DIR, f"{package}_{component.split('/')[-1].strip('.')}.png")
            device.screencap(path)
            ev.artifacts["screenshot"] = path
        except Exception:  # noqa: BLE001 - evidence capture is best-effort
            pass
    return ev


def confirm_deep_link(device: Device, uri: str, *, expected_component_hint: str | None = None) -> Evidence:
    result = device.am_start(action="android.intent.action.VIEW", data_uri=uri)
    out = result.stdout or result.stderr
    ev = Evidence(check="deep_link", target=uri, detail=_short(out))
    if "SecurityException" in out or "Permission Denial" in out:
        ev.outcome = "guarded"
    elif "Status: ok" in out and "Activity:" in out:
        ev.outcome = "confirmed"
        for token in out.split():
            if token.startswith(("com.", "org.", "net.")) or "/" in token:
                ev.artifacts["launched_activity"] = token
                break
    else:
        ev.outcome = "refuted"
    return ev


def confirm_content_provider(device: Device, uri: str) -> Evidence:
    result = device.content_query(uri)
    out = result.stdout or result.stderr
    ev = Evidence(check="content_provider", target=uri, detail=_short(out))
    if "Permission Denial" in out or "SecurityException" in out:
        ev.outcome = "guarded"
    elif "Row:" in out:
        ev.outcome = "confirmed"  # data leaked to an unprivileged caller
    elif "No result found" in out or out.strip() == "":
        ev.outcome = "refuted"
    else:
        ev.outcome = "error"
    return ev


def confirm_findings(
    package: str,
    findings: list[dict[str, Any]],
    *,
    device: Device | None = None,
    provider_authorities: list[str] | None = None,
    deep_links: list[str] | None = None,
) -> list[Evidence]:
    """Run the appropriate runtime probe for each static finding / lead."""

    device = device or get_device()
    device.logcat_clear()
    evidence: list[Evidence] = []
    for finding in findings:
        component = str(finding.get("component") or "")
        vtype = str(finding.get("vulnerability_type") or finding.get("kind") or "").lower()
        if "provider" in vtype or "provider" in component.lower():
            for authority in provider_authorities or []:
                evidence.append(confirm_content_provider(device, f"content://{authority}/"))
        elif "deep" in vtype or "webview" in vtype or "webview" in component.lower():
            for uri in deep_links or []:
                evidence.append(confirm_deep_link(device, uri))
        elif "activity" in vtype or component:
            if component and "provider" not in component.lower():
                evidence.append(confirm_exported_activity(device, package, component))
    device.force_stop(package)
    return evidence
