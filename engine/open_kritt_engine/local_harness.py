"""Local, air-gapped agentic harness backed by a llama.cpp server (llama-server).

This is the keystone of the local-only Android research build. It implements the same
interface as the cloud harnesses (``run(prompt, schema, repo_dir, model, ...)
-> HarnessResult``) so the entire downstream engine — validation, dedup, ranking,
post-scripts, storage — keeps working unchanged, but every token is produced by the
operator's local model over an OpenAI-compatible endpoint.

Design choices (see docs/ANDROID_RESEARCH_INVESTIGATION.md):
- **Single inference slot.** llama-server is started with ``--parallel 1``; a module
  semaphore serializes all calls so concurrent engine workers queue instead of racing.
- **Deterministic tools, model for reasoning.** The model navigates a checked-out /
  decompiled workspace through a small sandboxed toolset (read_file/list_dir/grep/head)
  rather than ingesting the whole tree — essential given a ~60k context and a small
  active-parameter MoE.
- **Grammar-constrained output.** The controller turn (pick a tool or finish) and the
  final answer are each constrained with the server's JSON-schema → grammar support, so
  a small model reliably emits valid JSON that matches the step's declared schema.
- **Reasoning captured, not trusted.** With ``--reasoning on`` the server returns
  ``reasoning_content`` separately; we keep it for the transcript but only parse
  ``content`` for structured data.
"""

from __future__ import annotations

import copy
import json
import os
import re
import threading
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

# Imported lazily-safe: harnesses.py imports this module only inside harness_for(),
# so importing these names at module load does not create a cycle at import time.
from .agent_activity import report_activity
from .harnesses import HarnessError, HarnessOutput, HarnessResult, _with_extractor_marker
from .schema import EXTRACTOR_HELPER_FIELD

DEFAULT_BASE_URL = "http://127.0.0.1:8005/v1"
DEFAULT_MODEL_ALIAS = "local"

# One llama-server, one slot (--parallel 1). Serialize every request across workers.
_LLM_SLOT = threading.Semaphore(1)

CONTROLLER_SYSTEM_PROMPT = (
    "You are a security research agent working strictly inside a provided workspace. "
    "You investigate by calling tools that read files under the workspace root. "
    "Never assume file contents you have not read. Do not access paths outside the workspace. "
    "Each turn, respond with a single JSON object choosing exactly one tool to advance the task, "
    "or the `finish` tool when you have gathered enough evidence to produce the final answer. "
    "Use `thought` to briefly plan your next step."
)

FINAL_SYSTEM_PROMPT = (
    "Produce the final answer for the task using only evidence gathered from the workspace. "
    "Return only a single JSON object that validates against the provided schema. "
    "Do not include markdown, commentary, or any text outside the JSON object.\n\n"
    "Output contract (strict): the fields `stub`, `stub_explanation`, and `results` describe whether you "
    "found anything. `stub` does NOT mean placeholder code. If you found one or more findings, set "
    "`stub` to false, set `stub_explanation` to an empty string, and put every finding object in `results`. "
    "If you found nothing, set `stub` to true, set `results` to an empty array, and set `stub_explanation` "
    "to a short reason. Never set `stub` to true while `results` is non-empty."
)


def _env(name: str, default: str) -> str:
    value = os.getenv(name)
    return value if value else default


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


def local_base_url() -> str:
    return _env("ENGINE_LLM_BASE_URL", DEFAULT_BASE_URL).rstrip("/")


def local_model_name() -> str:
    """The local model identifier (llama --alias), UI-configurable via ENGINE_LOCAL_MODEL."""
    return _env("ENGINE_LOCAL_MODEL", DEFAULT_MODEL_ALIAS)


def local_reasoning_effort() -> str:
    """UI-configurable 'smartness' knob for the local model's reasoning/analysis turns:
    low | medium | high. Applied to non-structured calls; the final grammar-constrained
    answer still runs no_think so findings stay parseable."""
    value = _env("ENGINE_LOCAL_REASONING_EFFORT", "medium").lower()
    return value if value in {"low", "medium", "high"} else "medium"


def endpoint_reachable(base_url: str | None = None, timeout: float = 4.0) -> bool:
    url = (base_url or local_base_url()).rstrip("/") + "/models"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:  # noqa: S310 - local operator URL
            return 200 <= response.status < 300
    except Exception:  # noqa: BLE001 - any failure means "not reachable"
        return False


# --------------------------------------------------------------------------- #
# llama-server client (OpenAI-compatible /chat/completions)                    #
# --------------------------------------------------------------------------- #


class LocalLLMClient:
    def __init__(self, *, base_url: str | None = None, model: str = DEFAULT_MODEL_ALIAS, timeout_seconds: int = 600):
        self.base_url = (base_url or local_base_url()).rstrip("/")
        # A caller asking for the local model (or nothing) resolves to the UI-configured
        # model name; an explicit non-default (a cloud model id) is passed through as-is.
        self.model = local_model_name() if (not model or model == DEFAULT_MODEL_ALIAS) else model
        self.timeout_seconds = timeout_seconds

    def chat(
        self,
        messages: list[dict[str, Any]],
        *,
        json_schema: dict[str, Any] | None = None,
        schema_name: str = "response",
        temperature: float = 0.2,
        max_tokens: int | None = None,
        no_think: bool = False,
    ) -> dict[str, Any]:
        """One completion. Returns {content, reasoning, finish_reason, usage, raw}.

        `no_think=True` disables the model's reasoning pass for that call, so a
        grammar-constrained final answer is emitted directly instead of the model
        spending its whole token budget thinking (which leaves empty content)."""

        body: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "stream": False,
        }
        if max_tokens is not None:
            body["max_tokens"] = max_tokens
        if no_think:
            # llama.cpp forwards chat_template_kwargs to the jinja template; most
            # thinking templates honour enable_thinking=false. reasoning_effort is a
            # belt-and-suspenders hint for builds that read it.
            body["chat_template_kwargs"] = {"enable_thinking": False}
            body["reasoning_effort"] = "none"
        else:
            # Reasoning/analysis turns use the UI-configured "smartness" effort.
            body["reasoning_effort"] = local_reasoning_effort()
        if json_schema is not None:
            clean = _sanitize_schema(json_schema)
            # OpenAI-compatible json_schema response format (llama.cpp maps it to a
            # GBNF grammar). Also mirror it at the llama.cpp-native top-level key for
            # older/newer builds that read one or the other.
            body["response_format"] = {
                "type": "json_schema",
                "json_schema": {"name": schema_name, "schema": clean, "strict": True},
            }
            body["json_schema"] = clean

        data = json.dumps(body).encode("utf-8")
        request = urllib.request.Request(
            self.base_url + "/chat/completions",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with _LLM_SLOT:
            try:
                with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:  # noqa: S310
                    raw = json.loads(response.read().decode("utf-8"))
            except urllib.error.HTTPError as exc:
                detail = _read_error_body(exc)
                raise HarnessError(
                    f"local model HTTP {exc.code}: {detail}",
                    code="provider_rejected",
                    harness="local",
                    output=HarnessOutput(stderr=detail, returncode=exc.code),
                ) from exc
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                raise HarnessError(
                    f"could not reach local model at {self.base_url}: {exc}",
                    code="network_error",
                    harness="local",
                ) from exc
            except json.JSONDecodeError as exc:
                raise HarnessError(
                    "local model returned a non-JSON HTTP body",
                    code="invalid_output",
                    harness="local",
                ) from exc

        choice = (raw.get("choices") or [{}])[0]
        message = choice.get("message") or {}
        return {
            "content": message.get("content") or "",
            "reasoning": message.get("reasoning_content") or message.get("reasoning") or "",
            "finish_reason": choice.get("finish_reason"),
            "usage": raw.get("usage"),
            "raw": raw,
        }


def _read_error_body(exc: urllib.error.HTTPError) -> str:
    try:
        return exc.read().decode("utf-8", errors="replace")[:2000]
    except Exception:  # noqa: BLE001
        return str(exc)


def _sanitize_schema(schema: dict[str, Any]) -> dict[str, Any]:
    """Strip keys that some json-schema→grammar converters reject (e.g. $schema)."""

    clean = copy.deepcopy(schema)
    if isinstance(clean, dict):
        clean.pop("$schema", None)
    return clean


# --------------------------------------------------------------------------- #
# Workspace-sandboxed tools                                                    #
# --------------------------------------------------------------------------- #

_MAX_FILE_BYTES = 60_000
_MAX_GREP_RESULTS = 80
_MAX_GREP_FILES = 4000
_MAX_LIST_ENTRIES = 400
_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".gradle", ".idea"}


class WorkspaceTools:
    """Read-only filesystem tools confined to ``root``."""

    def __init__(self, root: str):
        self.root = Path(root).resolve()

    def _resolve(self, rel: str) -> Path:
        candidate = (self.root / (rel or ".")).resolve()
        try:
            candidate.relative_to(self.root)
        except ValueError as exc:
            raise ValueError(f"path escapes workspace: {rel!r}") from exc
        return candidate

    def read_file(self, path: str, max_bytes: int = _MAX_FILE_BYTES) -> str:
        target = self._resolve(path)
        if not target.is_file():
            return f"[not a file: {path}]"
        limit = min(int(max_bytes or _MAX_FILE_BYTES), _MAX_FILE_BYTES)
        data = target.read_bytes()[:limit]
        text = data.decode("utf-8", errors="replace")
        suffix = "\n[truncated]" if target.stat().st_size > limit else ""
        return text + suffix

    def list_dir(self, path: str = ".") -> str:
        target = self._resolve(path)
        if not target.is_dir():
            return f"[not a directory: {path}]"
        entries = []
        for child in sorted(target.iterdir(), key=lambda p: (p.is_file(), p.name.lower())):
            if child.name in _SKIP_DIRS:
                continue
            entries.append(f"{'d' if child.is_dir() else 'f'} {child.name}")
            if len(entries) >= _MAX_LIST_ENTRIES:
                entries.append("[... truncated]")
                break
        return "\n".join(entries) if entries else "[empty]"

    def head(self, path: str, lines: int = 40) -> str:
        text = self.read_file(path)
        rows = text.splitlines()
        n = max(1, min(int(lines or 40), 200))
        return "\n".join(rows[:n])

    def grep(self, pattern: str, path: str = ".", max_results: int = _MAX_GREP_RESULTS) -> str:
        try:
            regex = re.compile(pattern)
        except re.error as exc:
            return f"[invalid regex: {exc}]"
        base = self._resolve(path)
        results: list[str] = []
        scanned = 0
        roots = [base] if base.is_dir() else [base.parent]
        for root in roots:
            for file in root.rglob("*"):
                if any(part in _SKIP_DIRS for part in file.parts):
                    continue
                if not file.is_file():
                    continue
                scanned += 1
                if scanned > _MAX_GREP_FILES:
                    results.append("[file scan limit reached]")
                    return "\n".join(results)
                try:
                    with file.open("r", encoding="utf-8", errors="ignore") as handle:
                        for number, line in enumerate(handle, 1):
                            if regex.search(line):
                                rel = file.relative_to(self.root).as_posix()
                                results.append(f"{rel}:{number}: {line.strip()[:200]}")
                                if len(results) >= min(int(max_results or _MAX_GREP_RESULTS), _MAX_GREP_RESULTS):
                                    results.append("[result limit reached]")
                                    return "\n".join(results)
                except OSError:
                    continue
        return "\n".join(results) if results else "[no matches]"

    def dispatch(self, name: str, arguments: dict[str, Any]) -> str:
        arguments = arguments if isinstance(arguments, dict) else {}
        try:
            if name == "read_file":
                return self.read_file(str(arguments.get("path", "")), int(arguments.get("max_bytes", _MAX_FILE_BYTES)))
            if name == "list_dir":
                return self.list_dir(str(arguments.get("path", ".")))
            if name == "head":
                return self.head(str(arguments.get("path", "")), int(arguments.get("lines", 40)))
            if name == "grep":
                return self.grep(
                    str(arguments.get("pattern", "")),
                    str(arguments.get("path", ".")),
                    int(arguments.get("max_results", _MAX_GREP_RESULTS)),
                )
            # Native (.so / ELF) analysis — so any workflow step can research native libs.
            if name in ("list_native_libs", "native_recon", "native_disasm"):
                from . import native_tools

                if name == "list_native_libs":
                    return native_tools.list_native_libs(str(self.root))
                if name == "native_recon":
                    return native_tools.native_recon(str(self.root), str(arguments.get("path", "")))
                return native_tools.native_disasm(
                    str(self.root), str(arguments.get("path", "")), str(arguments.get("symbol", ""))
                )
        except (ValueError, TypeError) as exc:
            return f"[tool error: {exc}]"
        return f"[unknown tool: {name}]"


TOOL_NAMES = ["read_file", "list_dir", "head", "grep", "list_native_libs", "native_recon", "native_disasm"]
TOOL_HELP = (
    "Available tools (call one per turn):\n"
    "- read_file{path, max_bytes?}: return the UTF-8 contents of a workspace file.\n"
    "- list_dir{path?}: list entries of a workspace directory (default root).\n"
    "- head{path, lines?}: first N lines of a file.\n"
    "- grep{pattern, path?, max_results?}: regex-search files under a path for matches.\n"
    "- list_native_libs{}: list the bundled native .so libraries (unpacked/lib/<abi>/).\n"
    "- native_recon{path}: for one .so, get its JNI exports (Java_* = native surface reachable from Java), imported functions with DANGEROUS ones flagged (system/exec/strcpy/memcpy/dlopen/GetByteArrayElements...), and interesting strings (keys/URLs/commands/format-strings).\n"
    "- native_disasm{path, symbol}: disassemble one native function (ARM64/ARM/x86) to inspect its behavior.\n"
    "- finish{}: stop investigating; you are ready to write the final structured answer."
)


def _controller_schema(tool_names: list[str] | None = None) -> dict[str, Any]:
    names = tool_names if tool_names is not None else TOOL_NAMES
    return {
        "type": "object",
        "properties": {
            "thought": {"type": "string"},
            "tool": {"type": "string", "enum": [*names, "finish"]},
            "arguments": {"type": "object", "additionalProperties": True},
        },
        "required": ["tool"],
        "additionalProperties": False,
    }


# --------------------------------------------------------------------------- #
# JSON parsing helpers                                                         #
# --------------------------------------------------------------------------- #


def _loads_lenient(text: str) -> dict[str, Any] | None:
    text = (text or "").strip()
    if not text:
        return None
    try:
        value = json.loads(text)
        return value if isinstance(value, dict) else None
    except json.JSONDecodeError:
        pass
    # Fall back to the first balanced {...} object in the text.
    start = text.find("{")
    while start != -1:
        depth = 0
        in_string = False
        escape = False
        for index in range(start, len(text)):
            char = text[index]
            if in_string:
                if escape:
                    escape = False
                elif char == "\\":
                    escape = True
                elif char == '"':
                    in_string = False
            elif char == '"':
                in_string = True
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    try:
                        value = json.loads(text[start : index + 1])
                        if isinstance(value, dict):
                            return value
                    except json.JSONDecodeError:
                        break
        start = text.find("{", start + 1)
    return None


def _is_step_envelope(schema: dict[str, Any]) -> bool:
    """True when the schema is the standard workflow step output (stub/results envelope)."""
    props = schema.get("properties") if isinstance(schema, dict) else None
    return isinstance(props, dict) and "results" in props and "stub" in props


def _reconcile_output(payload: dict[str, Any], schema: dict[str, Any]) -> dict[str, Any]:
    """Enforce the engine's stub/results invariant that a JSON schema cannot express.

    Small local models sometimes emit a structurally-valid object that breaks the
    cross-field rule (e.g. stub=true with a non-empty results array, or misreading
    "stub" as "placeholder"). The results array is the source of truth, so we derive
    stub from it — a lossless normalization — and clamp cardinality for single-output
    steps. This mirrors validate_payload()'s invariants so the downstream engine accepts
    the answer instead of forcing avoidable retries.
    """

    results = payload.get("results")
    if not isinstance(results, list):
        results = []
    # Single-output steps declare results.maxItems == 1.
    try:
        max_items = schema["properties"]["results"].get("maxItems")
    except (KeyError, TypeError, AttributeError):
        max_items = None
    if isinstance(max_items, int) and len(results) > max_items:
        results = results[:max_items]
    payload["results"] = results
    if results:
        payload["stub"] = False
        payload["stub_explanation"] = ""
    else:
        payload["stub"] = True
        if not str(payload.get("stub_explanation") or "").strip():
            payload["stub_explanation"] = "No finding was established for this task."
    # Multi-output schemas require the extractor-helper marker as a const-true property.
    # Grammar-constrained answers already carry it, but hand-built envelopes (e.g. the
    # [[REQUIRES_DEVICE]] no-device stub) do not — add it whenever the schema declares it.
    props = schema.get("properties") if isinstance(schema, dict) else None
    if isinstance(props, dict) and EXTRACTOR_HELPER_FIELD in props:
        payload[EXTRACTOR_HELPER_FIELD] = True
    return payload


def _merge_usage(total: dict[str, int], usage: dict[str, Any] | None) -> None:
    if not isinstance(usage, dict):
        return
    for key in ("prompt_tokens", "completion_tokens", "total_tokens"):
        value = usage.get(key)
        if isinstance(value, int):
            total[key] = total.get(key, 0) + value


# --------------------------------------------------------------------------- #
# The harness                                                                  #
# --------------------------------------------------------------------------- #


def ctx_char_budget() -> int:
    """Char budget for a ReAct message history so it never exceeds the model's context
    window. Derived from ENGINE_LOCAL_CTX_TOKENS (the llama-server --ctx-size), leaving room
    for the reply + schema overhead. ~3.3 chars/token is a conservative estimate for the
    code/JSON-heavy prompts these agents produce."""

    try:
        ctx = int(os.getenv("ENGINE_LOCAL_CTX_TOKENS", "32768"))
    except ValueError:
        ctx = 32768
    # Keep the history to ~78% of the window (the rest covers the reply + schema + the fact
    # that dense code/JSON can tokenize to <3 chars/token). ~3 chars/token → char budget.
    return max(8000, int(ctx * 0.78) * 3)


def trim_history(messages: list[dict[str, Any]], max_chars: int | None = None) -> list[dict[str, Any]]:
    """Keep a ReAct history under the context budget: always keep the system message + the
    first task message, then keep the MOST RECENT turns that fit, dropping older middle
    tool-observation pairs (a small note marks the elision). Prevents the request-exceeds-
    context-size errors that grow as an investigation accumulates observations."""

    budget = max_chars if max_chars is not None else ctx_char_budget()
    total = sum(len(str(m.get("content", ""))) for m in messages)
    if total <= budget or len(messages) <= 3:
        return messages
    head = messages[:2]
    rest = messages[2:]
    remaining = budget - sum(len(str(m.get("content", ""))) for m in head) - 120
    kept: list[dict[str, Any]] = []
    for m in reversed(rest):
        c = len(str(m.get("content", "")))
        if kept and c > remaining:
            break
        kept.insert(0, m)
        remaining -= c
        if remaining <= 0:
            break
    if len(kept) < len(rest):
        head = head + [{"role": "user", "content": "[... earlier investigation steps trimmed to fit the context window ...]"}]
    return head + kept


class LocalHarness:
    name = "local"

    def __init__(self, timeout_seconds: int, model_provider: str | None = None, device_context: dict | None = None):
        self.timeout_seconds = timeout_seconds
        self.model_provider = model_provider
        # When set (dynamic-research device steps), the ReAct loop also exposes on-device tools
        # (launch/deeplink/tap/screenshot/frida_bypass...) alongside the static workspace tools.
        self.device_context = device_context
        self.max_tool_steps = _int_env("ENGINE_LOCAL_MAX_TOOL_STEPS", 24)
        # Small models sometimes "finish" before reading any code. Force a minimum of
        # real investigation before the final answer is allowed.
        self.min_tool_steps = _int_env("ENGINE_LOCAL_MIN_TOOL_STEPS", 4)
        # The final answer must fit reasoning tokens + a multi-finding JSON object;
        # 4k truncates on rich schemas. 60k context leaves ample room.
        self.max_tokens = _int_env("ENGINE_LOCAL_MAX_TOKENS", 8192)

    def run(
        self,
        *,
        prompt: str,
        schema: dict[str, Any],
        repo_dir: str,
        model: str,
        thinking_effort: str | None = None,
        env: dict[str, str] | None = None,
        allow_tools: bool = True,
    ) -> HarnessResult:
        client = LocalLLMClient(model=model or DEFAULT_MODEL_ALIAS, timeout_seconds=self.timeout_seconds)
        usage_total: dict[str, int] = {}
        transcript: list[str] = []

        # Integrity gate: a step marked [[REQUIRES_DEVICE]] must NOT run without device tools,
        # or the model will fabricate an on-device "reproduction" it never performed. With no
        # device, emit an empty stub so the step honestly yields nothing.
        has_device = bool(self.device_context and self.device_context.get("device") is not None)
        if "[[REQUIRES_DEVICE]]" in (prompt or "") and not has_device:
            transcript.append("[device step skipped: no device connected — nothing reproduced]")
            stub = _reconcile_output({"stub": True, "results": []}, schema)
            return HarnessResult(
                payload=stub,
                usage={"usage": None, "harness": "local", "model": client.model},
                output=HarnessOutput(stdout="\n".join(transcript)),
            )

        if allow_tools:
            self._investigate(client, prompt, repo_dir, usage_total, transcript)

        final_messages = [
            {"role": "system", "content": FINAL_SYSTEM_PROMPT},
            {"role": "user", "content": self._final_prompt(prompt, transcript, allow_tools)},
        ]
        payload = None
        final: dict[str, Any] = {}
        for max_tokens in (self.max_tokens, self.max_tokens * 2):
            final = client.chat(
                messages=final_messages,
                json_schema=schema,
                schema_name="kritt_step_output",
                temperature=0.1,
                max_tokens=max_tokens,
            )
            _merge_usage(usage_total, final.get("usage"))
            payload = _loads_lenient(final.get("content", ""))
            if payload is not None:
                break
            # Only a truncated ("length") answer is worth retrying with more room.
            if final.get("finish_reason") != "length":
                break
            transcript.append(f"[final answer truncated at {max_tokens} tokens; retrying with more]")
        if final.get("reasoning"):
            transcript.append("[final reasoning]\n" + str(final["reasoning"])[:4000])

        if payload is None:
            raise HarnessError(
                "local model did not return a parseable JSON final answer "
                f"(finish_reason={final.get('finish_reason')}).",
                code="invalid_output",
                harness="local",
                output=HarnessOutput(stdout="\n".join(transcript)[-8000:], stderr=str(final.get("content", ""))[:4000]),
            )
        # Only the standard workflow step envelope carries stub/results + the extractor
        # marker. Post-processing calls (dedupe, severity/bounty rank, post-scripts) pass
        # their own schemas, so the raw grammar-constrained payload is returned untouched.
        if _is_step_envelope(schema):
            payload = _reconcile_output(payload, schema)
            payload = _with_extractor_marker(payload)
        transcript.append("[final answer]\n" + json.dumps(payload)[:4000])
        return HarnessResult(
            payload=payload,
            usage={"usage": usage_total or None, "harness": "local", "model": client.model},
            output=HarnessOutput(stdout="\n".join(transcript)[-16000:]),
        )

    def _investigate(
        self,
        client: LocalLLMClient,
        prompt: str,
        repo_dir: str,
        usage_total: dict[str, int],
        transcript: list[str],
    ) -> None:
        tools = WorkspaceTools(repo_dir)
        # Optional on-device toolset for dynamic-research device steps.
        device_tools = None
        device_names: list[str] = []
        dc = self.device_context
        if dc and dc.get("device") is not None:
            try:
                import uuid as _uuid

                from .device_verify import VerificationRecorder, VerifyTools

                rec = VerificationRecorder(dc["data_dir"], int(dc["scan_id"]), "step-" + _uuid.uuid4().hex[:10], dc["device"])
                device_tools = VerifyTools(dc["device"], dc.get("package") or "", rec)
                device_names = device_tools.names()
                transcript.append(f"[device tools available: {', '.join(device_names)}]")
            except Exception as exc:  # noqa: BLE001 - device tools are best-effort
                transcript.append(f"[device tools unavailable: {exc}]")
        all_names = [*TOOL_NAMES, *device_names]
        help_text = TOOL_HELP + (("\n\nON-DEVICE TOOLS (a rooted test device is connected):\n" + device_tools.help()) if device_tools else "")
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": CONTROLLER_SYSTEM_PROMPT + "\n\n" + help_text},
            {
                "role": "user",
                "content": (
                    f"Task:\n{prompt}\n\n"
                    f"Workspace root is the current directory. Start by listing it. "
                    f"When you have enough evidence, call `finish`."
                ),
            },
        ]
        controller_schema = _controller_schema(all_names)
        tool_calls_made = 0
        for step in range(1, self.max_tool_steps + 1):
            messages = trim_history(messages)  # never exceed the model's context window
            reply = client.chat(
                messages=messages,
                json_schema=controller_schema,
                schema_name="kritt_tool_selection",
                temperature=0.2,
                max_tokens=2048,
            )
            _merge_usage(usage_total, reply.get("usage"))
            decision = _loads_lenient(reply.get("content", "")) or {}
            tool = str(decision.get("tool") or "").strip()
            thought = str(decision.get("thought") or "").strip()
            arguments = decision.get("arguments") if isinstance(decision.get("arguments"), dict) else {}
            if thought:
                transcript.append(f"[step {step}] thought: {thought}")
                report_activity("thought", thought)
            if tool in ("finish", "") or tool not in all_names:
                if tool_calls_made < self.min_tool_steps:
                    transcript.append(f"[step {step}] premature finish rejected (only {tool_calls_made} tool calls)")
                    messages.append({"role": "assistant", "content": json.dumps(decision)})
                    messages.append(
                        {
                            "role": "user",
                            "content": (
                                "Do not finish yet. You have not inspected enough of the app. Read the decoded "
                                "AndroidManifest.xml and the source of each exported component listed in WORKSPACE.json "
                                "(look under jadx/sources/), and grep for secrets, WebView, and crypto usage. "
                                "Choose the next tool."
                            ),
                        }
                    )
                    continue
                transcript.append(f"[step {step}] finish")
                report_activity("finish", "Finished investigating this unit.")
                return
            tool_calls_made += 1
            report_activity("tool", f"{tool}({json.dumps(arguments)[:160]})", tool=tool)
            if device_tools is not None and tool in device_names:
                observation = device_tools.dispatch(tool, arguments, thought=thought)
                # Surface the saved screenshot path so the model can cite it in its output.
                shot = device_tools.rec.steps[-1].get("screenshot") if device_tools.rec.steps else None
                if shot:
                    observation = f"{observation}\n[screenshot saved: {shot}]"
            else:
                observation = tools.dispatch(tool, arguments)
            transcript.append(f"[step {step}] {tool}({json.dumps(arguments)[:200]})\n{observation[:1500]}")
            report_activity("observation", f"{tool} → {observation[:200]}", tool=tool)
            messages.append({"role": "assistant", "content": json.dumps(decision)})
            messages.append(
                {"role": "user", "content": f"Observation from {tool}:\n{observation[:6000]}\n\nChoose the next tool or finish."}
            )
        transcript.append("[investigation step limit reached]")

    def _final_prompt(self, prompt: str, transcript: list[str], allow_tools: bool) -> str:
        if not allow_tools or not transcript:
            return prompt
        evidence = "\n\n".join(transcript)[-24000:]
        return (
            f"{prompt}\n\n"
            "Evidence gathered from the workspace during investigation (tool observations and your own notes):\n"
            f"{evidence}\n\n"
            "Now return the final structured answer required by the schema, grounded only in this evidence."
        )
