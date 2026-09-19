"""Autonomous on-device verification of a static finding, with screenshot evidence.

Given a finding and a rooted device, this drives the app to reproduce the reported issue,
applies standard Frida bypasses when a guard blocks the path, captures a screenshot at every
meaningful step, and returns a verdict plus a screenshot-backed step trail. It is what turns
a static claim into "here is the bug happening, with pictures."

Scope: only for authorized targets (FOSS / bug-bounty-in-scope) on a device the user owns.
Every bypass applied is recorded in the evidence trail.
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Any

LOGGER = logging.getLogger("open_kritt_engine.device_verify")


def evidence_root(data_dir: str) -> Path:
    base = os.getenv("ENGINE_DYNAMIC_EVIDENCE_DIR") or os.path.join(data_dir, "dynamic-evidence")
    return Path(base)


def evidence_root_of(path: Path) -> Path:
    """Given <root>/<scan>/<finding>/<file>, return <root> so we can make a UI-relative path."""
    return path.parent.parent.parent


def _slug(text: str) -> str:
    keep = "".join(c if c.isalnum() else "-" for c in (text or "").lower())
    return "-".join(p for p in keep.split("-") if p)[:32]


class VerificationRecorder:
    """Owns one finding's evidence directory: numbered screenshots + an ordered step log."""

    def __init__(self, data_dir: str, scan_id: int, finding_id: int, device) -> None:
        self.device = device
        self.dir = evidence_root(data_dir) / str(scan_id) / str(finding_id)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.steps: list[dict[str, Any]] = []
        self._n = 0

    def screenshot(self, label: str = "") -> str | None:
        """Capture a screenshot; return its path relative to the evidence root (for the UI)."""
        self._n += 1
        name = f"{self._n:02d}_{_slug(label) or 'shot'}.png"
        dest = self.dir / name
        try:
            self.device.screencap(str(dest))
        except Exception:  # noqa: BLE001 - a failed screenshot must not abort verification
            LOGGER.debug("screencap failed for %s", label, exc_info=True)
            return None
        if not dest.exists() or dest.stat().st_size == 0:
            return None
        return str(dest.relative_to(evidence_root_of(dest))).replace("\\", "/")

    def record(self, *, action: str, args: dict[str, Any] | None, thought: str,
               observation: str, screenshot: str | None) -> None:
        self.steps.append({
            "n": len(self.steps) + 1,
            "action": action,
            "args": args or {},
            "thought": thought or "",
            "observation": (observation or "")[:1200],
            "screenshot": screenshot,
            "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        })

    def artifacts(self) -> list[str]:
        """Every screenshot on disk (UI-relative), in capture order, so no evidence is dropped."""
        root = evidence_root_of(self.dir / "x")
        return [str(png.relative_to(root)).replace("\\", "/") for png in sorted(self.dir.glob("*.png"))]


# --------------------------------------------------------------------------- #
# Verify tools: device actions the model can call, each auto-recorded with a    #
# screenshot so the evidence trail builds itself.                              #
# --------------------------------------------------------------------------- #

class VerifyTools:
    """Device + Frida actions for verification, each producing a recorded, screenshotted step."""

    def __init__(self, device, package: str, recorder: VerificationRecorder) -> None:
        self.device = device
        self.package = package
        self.rec = recorder
        self.bypasses_applied: list[str] = []
        self._frida_started = False

    def names(self) -> list[str]:
        return [
            "launch_app", "launch_deeplink", "am_start_component", "tap", "input_text",
            "keyevent", "content_query", "read_app_file", "list_app_files", "logcat",
            "frida_bypass", "screenshot",
        ]

    def help(self) -> str:
        return (
            "launch_app{} - start the app, return its pid; call this first.\n"
            "launch_deeplink{uri} - fire a VIEW intent for a deep link and see where it lands.\n"
            "am_start_component{component,extras?} - start an exported component with extras.\n"
            "tap{x,y} / input_text{text} / keyevent{key} - drive the UI.\n"
            "content_query{uri} - query an exported ContentProvider.\n"
            "read_app_file{path} / list_app_files{sub?} - read app-private storage (root).\n"
            "logcat{} - recent log lines.\n"
            "frida_bypass{kinds:[ssl_unpin,anti_detect]} - neutralise a guard if it blocks you.\n"
            "screenshot{label} - capture the current screen as evidence."
        )

    def dispatch(self, tool: str, args: dict[str, Any], thought: str = "") -> str:
        obs, shot_label = self._run(tool, args)
        shot = self.rec.screenshot(shot_label or tool)
        self.rec.record(action=tool, args=args, thought=thought, observation=obs, screenshot=shot)
        return obs

    def _run(self, tool: str, args: dict[str, Any]) -> tuple[str, str]:
        d = self.device
        try:
            if tool == "launch_app":
                pid = d.launch_app(self.package)
                return ("launched, pid=" + str(pid) if pid else "app did not start", "app-launched")
            if tool == "launch_deeplink":
                uri = str(args.get("uri", ""))
                d.logcat_clear()
                out = d.am_start(action="android.intent.action.VIEW", data_uri=uri)
                return ("am start VIEW " + uri + "\n" + out.stdout + "\nfocus: " + d.current_focus(), "deeplink")
            if tool == "am_start_component":
                comp = str(args.get("component", ""))
                extras = args.get("extras") if isinstance(args.get("extras"), dict) else None
                d.logcat_clear()
                out = d.am_start(component=comp, extras=extras)
                tail = d.logcat_dump(max_lines=15)
                return ("am start " + comp + "\n" + out.stdout + "\nfocus: " + d.current_focus() + "\n" + tail, "start-component")
            if tool == "tap":
                d.tap(int(args.get("x", 0)), int(args.get("y", 0)))
                return ("tapped " + str(args.get("x")) + "," + str(args.get("y")), "tap")
            if tool == "input_text":
                d.input_text(str(args.get("text", "")))
                return ("typed " + repr(args.get("text", "")), "type")
            if tool == "keyevent":
                d.keyevent(str(args.get("key", "")))
                return ("keyevent " + str(args.get("key")), "key")
            if tool == "content_query":
                return (d.content_query(str(args.get("uri", ""))).stdout, "content-query")
            if tool == "read_app_file":
                rel = str(args.get("path", "")).lstrip("/")
                return (d.shell("cat /data/data/" + self.package + "/" + rel, root=True).stdout[:4000], "read-file")
            if tool == "list_app_files":
                sub = str(args.get("sub", "")).lstrip("/")
                return (d.shell("ls -la /data/data/" + self.package + "/" + sub, root=True).stdout[:4000], "list-files")
            if tool == "logcat":
                return (d.logcat_dump(max_lines=40), "logcat")
            if tool == "frida_bypass":
                return (self._frida_bypass(args), "after-bypass")
            if tool == "screenshot":
                return ("screenshot: " + str(args.get("label", "")), str(args.get("label", "shot")))
            return ("[unknown tool: " + tool + "]", tool)
        except Exception as exc:  # noqa: BLE001 - a tool failure is evidence, not a crash
            return ("[" + tool + " error: " + type(exc).__name__ + ": " + str(exc) + "]", tool)

    def _frida_bypass(self, args: dict[str, Any]) -> str:
        from . import frida_service as fs

        kinds = args.get("kinds") or ["ssl_unpin", "anti_detect"]
        kinds = [k for k in kinds if k in fs.BYPASS_LIBRARY]
        if not kinds:
            return "[no known bypasses requested]"
        try:
            if not self._frida_started:
                fs.ensure_server(self.device, force=True)
                self._frida_started = True
            pid = self.device.app_pid(self.package) or self.device.launch_app(self.package)
            if not pid:
                return "[could not launch app to attach bypasses]"
            run = fs.run_script(
                self.package, "\n".join(fs.BYPASS_LIBRARY[k] for k in kinds),
                spawn=False, attach_pid=int(pid), serial=self.device.serial, run_seconds=4,
            )
            for k in kinds:
                if k not in self.bypasses_applied:
                    self.bypasses_applied.append(k)
            fired = [ln for ln in run.logs if any(t in ln for t in ("installed", "fired", "unpin", "anti_detect"))]
            return "applied bypasses " + str(kinds) + "; hooks: " + str(fired[:6]) + "; err=" + str(run.error)
        except Exception as exc:  # noqa: BLE001
            return "[frida_bypass error: " + type(exc).__name__ + ": " + str(exc) + "]"


VERIFY_SYSTEM = (
    "You are an autonomous mobile exploitation verifier. You are given ONE reported vulnerability "
    "in an app installed on a rooted device you control (an authorized test target). Your job: "
    "REPRODUCE it on the device and prove it is real, capturing screenshots along the way.\n\n"
    "Method:\n"
    "1. launch_app first, then screenshot the starting state.\n"
    "2. Drive the exact attack path from the finding: fire the deep link, start the exported "
    "component with the malicious extra, query the provider, or read the private file.\n"
    "3. If a guard blocks you (TLS pinning, root/emulator detection, a client-side check), call "
    "frida_bypass to neutralise it, then retry the step. Every bypass is logged.\n"
    "4. screenshot the moment that demonstrates impact (attacker URL loaded, private data shown, "
    "action performed).\n"
    "5. finish with an honest verdict.\n\n"
    "Call exactly one tool per turn; use `thought` to say what you expect to see. Do not finish "
    "until you have either demonstrated the issue with a screenshot or genuinely exhausted the path."
)

VERDICT_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": ["verified", "not_reproduced", "blocked"]},
        "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
        "reproduction_steps": {"type": "array", "items": {"type": "string"}},
        "impact_shown": {"type": "string"},
        "bypasses_used": {"type": "array", "items": {"type": "string"}},
        "blocker": {"type": "string"},
    },
    "required": ["verdict", "confidence", "reproduction_steps", "impact_shown"],
    "additionalProperties": False,
}


def verify_finding_on_device(
    finding: dict[str, Any], *, device, package: str, recorder: VerificationRecorder,
    max_steps: int = 16, min_steps: int = 3,
) -> dict[str, Any]:
    """Drive the device to reproduce ONE finding; return a verdict + screenshot-backed steps."""

    from .local_harness import LocalLLMClient, _loads_lenient, trim_history
    from .specialist_agent import _controller_schema

    client = LocalLLMClient(model="local", timeout_seconds=1200)
    tools = VerifyTools(device, package, recorder)
    controller = _controller_schema(tools.names())

    summary = {k: finding.get(k) for k in ("summary", "vulnerability_type", "component", "file_path",
                                           "line", "malicious_input_example", "adb_poc", "poc", "trigger_flow")}
    messages = [
        {"role": "system", "content": VERIFY_SYSTEM + "\n\nTools:\n" + tools.help()},
        {"role": "user", "content": "Package: " + package + "\nFinding to reproduce:\n"
         + json.dumps(summary, indent=2) + "\n\nBegin: launch_app, then reproduce."},
    ]
    tool_calls = 0
    seen: set[str] = set()
    for step in range(1, max_steps + 1):
        messages = trim_history(messages)
        reply = client.chat(messages=messages, json_schema=controller, schema_name="tool",
                            temperature=0.2, max_tokens=1200)
        decision = _loads_lenient(reply.get("content", "")) or {}
        tool = str(decision.get("tool") or "").strip()
        args = decision.get("arguments") if isinstance(decision.get("arguments"), dict) else {}
        thought = str(decision.get("thought") or "")
        if tool in ("finish", "") or tool not in tools.names():
            if tool_calls < min_steps:
                messages.append({"role": "user", "content": "Do not finish yet — launch the app and actually attempt the reproduction on the device first."})
                continue
            break
        key = tool + ":" + json.dumps(args, sort_keys=True)
        if key in seen:
            messages.append({"role": "user", "content": "You already ran that exact call. Try a different action or finish."})
            continue
        seen.add(key)
        tool_calls += 1
        obs = tools.dispatch(tool, args, thought=thought)
        messages.append({"role": "assistant", "content": json.dumps(decision)})
        messages.append({"role": "user", "content": "Observation:\n" + obs[:6000] + "\nNext tool or finish."})

    steps_text = "\n".join(
        "[" + str(s["n"]) + "] " + s["action"] + "(" + json.dumps(s["args"])[:120] + ") -> " + s["observation"][:200]
        for s in recorder.steps
    )
    final_messages = [
        {"role": "system", "content": "Return only the JSON verdict. Base it strictly on what actually happened on the device below. 'verified' requires a screenshot that shows the impact."},
        {"role": "user", "content": "Finding: " + json.dumps(summary) + "\n\nWhat happened on the device:\n"
         + steps_text[-12000:] + "\n\nBypasses applied: " + str(tools.bypasses_applied)},
    ]
    verdict = None
    for mt in (2048, 4096):
        final = client.chat(messages=final_messages, json_schema=VERDICT_SCHEMA, schema_name="verdict",
                            temperature=0.1, max_tokens=mt, no_think=True)
        verdict = _loads_lenient(final.get("content", "")) or _loads_lenient(final.get("reasoning", ""))
        if verdict:
            break
    verdict = verdict or {"verdict": "blocked", "confidence": "low", "reproduction_steps": [],
                          "impact_shown": "", "blocker": "no structured verdict produced"}
    verdict["bypasses_used"] = tools.bypasses_applied
    verdict["evidence_screenshots"] = recorder.artifacts()
    verdict["evidence_steps"] = recorder.steps
    return verdict


# --------------------------------------------------------------------------- #
# Discrete agentic sub-steps around reproduction, so the research reads like an  #
# expert's walkthrough (plan -> reproduce -> confirm) rather than one opaque    #
# loop. Each is a focused call with a narrow objective, which is what makes the  #
# per-step output accurate.                                                     #
# --------------------------------------------------------------------------- #

HYPOTHESIS_SCHEMA = {
    "type": "object",
    "properties": {
        "reachable_on_device": {"type": "boolean"},
        "actor": {"type": "string"},
        "entry": {"type": "string"},
        "controlled_input": {"type": "string"},
        "device_actions": {"type": "array", "items": {"type": "string"}},
        "expected_observable": {"type": "string"},
        "likely_guards": {"type": "array", "items": {"type": "string"}},
        "skip_reason": {"type": "string"},
    },
    "required": ["reachable_on_device", "device_actions", "expected_observable"],
    "additionalProperties": False,
}


def hypothesize_finding(finding: dict[str, Any], *, package: str, deep_links=None) -> dict[str, Any]:
    """Phase 'plan': turn a static finding into a concrete on-device attack plan, or decide it
    is not device-reproducible (e.g. a pure code-quality issue) and should be skipped."""

    from .local_harness import LocalLLMClient, _loads_lenient

    client = LocalLLMClient(model="local", timeout_seconds=600)
    summary = {k: finding.get(k) for k in ("summary", "vulnerability_type", "component", "file_path",
                                           "line", "malicious_input_example", "adb_poc", "poc", "trigger_flow")}
    msgs = [
        {"role": "system", "content": (
            "You are planning how to REPRODUCE one reported Android vulnerability on a rooted test "
            "device, like an expert doing a walkthrough. Decide if it is reproducible via device "
            "actions (an intent/deep link, an exported component with extras, a provider query, an app "
            "file read, or a UI flow). Give the concrete ordered device_actions and the exact "
            "expected_observable that would prove it. If it can only be shown by reading code (not on "
            "device), set reachable_on_device=false with a skip_reason.")},
        {"role": "user", "content": "Package: " + package + "\nDeep links: " + json.dumps(deep_links or [])
         + "\nFinding:\n" + json.dumps(summary, indent=2)},
    ]
    out = client.chat(messages=msgs, json_schema=HYPOTHESIS_SCHEMA, schema_name="hypothesis",
                      temperature=0.2, max_tokens=1200, no_think=True)
    return _loads_lenient(out.get("content", "")) or _loads_lenient(out.get("reasoning", "")) or {
        "reachable_on_device": True, "device_actions": [], "expected_observable": "", "likely_guards": [],
    }


CONFIRM_SCHEMA = {
    "type": "object",
    "properties": {
        "impact_confirmed": {"type": "boolean"},
        "what_the_screenshot_shows": {"type": "string"},
        "impact_statement": {"type": "string"},
        "residual_doubt": {"type": "string"},
    },
    "required": ["impact_confirmed", "what_the_screenshot_shows", "impact_statement"],
    "additionalProperties": False,
}


def confirm_impact(finding: dict[str, Any], recorder: VerificationRecorder, *, hypothesis: dict[str, Any]) -> dict[str, Any]:
    """Phase 'confirm': judge, strictly from what happened on the device, whether the expected
    impact was actually demonstrated — the honesty gate before a finding is called verified."""

    from .local_harness import LocalLLMClient, _loads_lenient

    client = LocalLLMClient(model="local", timeout_seconds=600)
    steps_text = "\n".join(
        "[" + str(s["n"]) + "] " + s["action"] + " -> " + s["observation"][:200]
        + ("  (screenshot: " + s["screenshot"] + ")" if s.get("screenshot") else "")
        for s in recorder.steps
    )
    msgs = [
        {"role": "system", "content": (
            "Decide, strictly from what actually happened on the device, whether the expected impact "
            "was demonstrated. Be conservative: 'impact_confirmed' true only if an observation or "
            "screenshot concretely shows it (attacker URL loaded, private data returned, action "
            "performed). A launch with no observed effect is NOT confirmation.")},
        {"role": "user", "content": "Expected: " + json.dumps(hypothesis.get("expected_observable", ""))
         + "\n\nWhat happened on device:\n" + steps_text[-10000:]},
    ]
    out = client.chat(messages=msgs, json_schema=CONFIRM_SCHEMA, schema_name="confirm",
                      temperature=0.1, max_tokens=1000, no_think=True)
    return _loads_lenient(out.get("content", "")) or _loads_lenient(out.get("reasoning", "")) or {
        "impact_confirmed": False, "what_the_screenshot_shows": "", "impact_statement": "",
        "residual_doubt": "no structured judgement produced",
    }
