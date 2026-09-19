"""Tests for the local llama.cpp agentic harness.

The mock-client test exercises the full LocalHarness.run() agent loop (tool calls,
finish, schema-constrained final answer) without a live model, so the harness is
proven end-to-end offline. A separate opt-in live test runs against a real
llama-server when ENGINE_LLM_LIVE_TEST=1 and the endpoint is reachable.
"""

import json
import os
import tempfile
from pathlib import Path

import pytest

from open_kritt_engine import local_harness as lh
from open_kritt_engine.harnesses import HarnessError, harness_for
from open_kritt_engine.schema import output_schema, validate_payload


def _sample_workspace() -> str:
    root = tempfile.mkdtemp()
    Path(root, "AndroidManifest.xml").write_text(
        "<manifest package='com.demo'>\n  <activity android:name='.Main' android:exported='true'/>\n</manifest>",
        encoding="utf-8",
    )
    smali = Path(root, "smali")
    smali.mkdir()
    (smali / "Main.smali").write_text('const-string v0, "https://api.demo.com/key?token=abc"\n', encoding="utf-8")
    return root


def test_harness_for_returns_local():
    harness = harness_for("local", timeout_seconds=30)
    assert harness.name == "local"
    assert type(harness).__name__ == "LocalHarness"


def test_workspace_tools_sandbox_and_search():
    root = _sample_workspace()
    tools = lh.WorkspaceTools(root)
    listing = tools.list_dir(".")
    assert "AndroidManifest.xml" in listing and "smali" in listing
    assert "exported='true'" in tools.grep("exported", ".")
    assert "Main.smali" in tools.grep("https://", ".")
    assert tools.read_file("smali/Main.smali").startswith("const-string")


def test_workspace_tools_block_escape():
    root = _sample_workspace()
    tools = lh.WorkspaceTools(root)
    with pytest.raises(ValueError):
        tools._resolve("../../etc/passwd")


@pytest.mark.parametrize(
    "text,expected_tool",
    [
        ('{"tool":"finish"}', "finish"),
        ('prefix ```json\n{"tool":"grep","arguments":{"pattern":"x"}}\n``` suffix', "grep"),
        ("not json at all", None),
    ],
)
def test_loads_lenient(text, expected_tool):
    parsed = lh._loads_lenient(text)
    if expected_tool is None:
        assert parsed is None
    else:
        assert parsed["tool"] == expected_tool


def test_sanitize_schema_strips_meta():
    schema = output_schema({"summary": "string"}, multi_output=True)
    clean = lh._sanitize_schema(schema)
    assert "$schema" not in clean
    assert "$schema" in schema  # original untouched


def test_reconcile_stub_true_with_results_becomes_finding():
    schema = output_schema({"summary": "string"}, multi_output=True)
    payload = {
        "stub": True,
        "stub_explanation": "This is a stub for the actual extraction logic.",
        "results": [{"summary": "Hardcoded token"}],
    }
    fixed = lh._reconcile_output(payload, schema)
    assert fixed["stub"] is False and fixed["stub_explanation"] == ""
    validate_payload(lh._with_extractor_marker(fixed), schema, multi_output=True)


def test_reconcile_empty_results_becomes_stub():
    schema = output_schema({"summary": "string"}, multi_output=True)
    fixed = lh._reconcile_output({"stub": False, "stub_explanation": "", "results": []}, schema)
    assert fixed["stub"] is True and fixed["stub_explanation"].strip()
    validate_payload(lh._with_extractor_marker(fixed), schema, multi_output=True)


def test_reconcile_clamps_single_output_cardinality():
    schema = output_schema({"summary": "string"}, multi_output=False)
    fixed = lh._reconcile_output(
        {"stub": False, "stub_explanation": "", "results": [{"summary": "a"}, {"summary": "b"}]}, schema
    )
    assert len(fixed["results"]) == 1
    validate_payload(lh._with_extractor_marker(fixed), schema, multi_output=False)


class _ScriptedClient:
    """Stand-in for LocalLLMClient that returns a fixed sequence of chat responses."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.model = "local"
        self.calls = []

    def chat(self, messages, *, json_schema=None, schema_name="response", temperature=0.2, max_tokens=None):
        self.calls.append({"schema_name": schema_name, "has_schema": json_schema is not None})
        content = self._responses.pop(0)
        return {"content": content, "reasoning": "", "usage": {"total_tokens": 7}, "raw": {}}


def test_run_full_agent_loop_with_mock(monkeypatch):
    root = _sample_workspace()
    schema = output_schema(
        {"summary": "string", "file_path": "string", "vulnerability_type": "string"},
        multi_output=True,
    )
    final_answer = {
        "stub": False,
        "stub_explanation": "",
        "results": [
            {
                "summary": "Hardcoded API token in smali",
                "file_path": "smali/Main.smali",
                "vulnerability_type": "hardcoded_secret",
            }
        ],
    }
    scripted = _ScriptedClient(
        [
            json.dumps({"thought": "list the workspace", "tool": "list_dir", "arguments": {"path": "."}}),
            json.dumps({"thought": "inspect smali", "tool": "grep", "arguments": {"pattern": "https://", "path": "."}}),
            json.dumps({"thought": "enough evidence", "tool": "finish", "arguments": {}}),
            json.dumps(final_answer),
        ]
    )
    monkeypatch.setattr(lh, "LocalLLMClient", lambda **kwargs: scripted)

    harness = lh.LocalHarness(timeout_seconds=30)
    harness.min_tool_steps = 0  # mock scripts an exact call sequence
    result = harness.run(prompt="Find hardcoded secrets.", schema=schema, repo_dir=root, model="local")

    # The final payload validates against the engine's own schema contract.
    payload = result.payload
    assert payload["_kritt_extractor_helper"] is True
    validate_payload(payload, schema, multi_output=True)
    assert payload["results"][0]["vulnerability_type"] == "hardcoded_secret"
    # The loop ran tool turns then a schema-constrained final turn.
    assert scripted.calls[-1]["schema_name"] == "kritt_step_output"
    assert scripted.calls[-1]["has_schema"] is True
    assert result.usage["usage"]["total_tokens"] == 7 * len(scripted.calls)
    assert "grep" in result.output.stdout


def test_run_raises_on_unparseable_final(monkeypatch):
    root = _sample_workspace()
    schema = output_schema({"summary": "string"}, multi_output=False)
    scripted = _ScriptedClient([json.dumps({"tool": "finish", "arguments": {}}), "this is not json"])
    monkeypatch.setattr(lh, "LocalLLMClient", lambda **kwargs: scripted)
    harness = lh.LocalHarness(timeout_seconds=30)
    harness.min_tool_steps = 0  # mock scripts an exact call sequence
    with pytest.raises(HarnessError) as excinfo:
        harness.run(prompt="x", schema=schema, repo_dir=root, model="local")
    assert excinfo.value.code == "invalid_output"


@pytest.mark.skipif(
    os.getenv("ENGINE_LLM_LIVE_TEST") != "1" or not lh.endpoint_reachable(),
    reason="live llama-server not available (set ENGINE_LLM_LIVE_TEST=1 and start the model)",
)
def test_live_inference_produces_valid_payload():
    root = _sample_workspace()
    schema = output_schema(
        {"summary": "string", "file_path": "string", "vulnerability_type": "string"},
        multi_output=True,
    )
    harness = harness_for("local", timeout_seconds=600)
    result = harness.run(
        prompt=(
            "You are auditing a decompiled Android app workspace for hardcoded secrets. "
            "Inspect the files and report any hardcoded credentials, tokens, or API keys."
        ),
        schema=schema,
        repo_dir=root,
        model="local",
    )
    validate_payload(result.payload, schema, multi_output=True)
