"""Deterministic external-entrypoint discovery for source-repo scans.

An APK scan starts with authoritative manifest intelligence: WORKSPACE.json hands the model
every exported component before it reads a line of code. A source-repo scan started blind --
the model had to discover the whole attack surface by grepping, and on a 1707-file Java repo
it enumerated 5 of ~280 request handlers before its step budget ran out. Everything downstream
(trace, investigate) is a fan-out from that list, so ~2% enumeration capped the entire scan.

This module is the source-repo counterpart of the Android manifest: a fast, model-free sweep
for the route/handler markers of common server frameworks. It is deliberately recall-oriented
-- a few false entrypoints cost the model one read_file each, while a missed one is invisible.
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any

LOGGER = logging.getLogger("open_kritt_engine.source_surface")

_SKIP_DIRS = {
    ".git", "node_modules", "vendor", "third_party", "build", "dist", "out", "target",
    ".gradle", ".idea", "__pycache__", ".venv", "venv", "site-packages", "testdata",
}
_SKIP_FILE_HINTS = ("/test/", "/tests/", "/mock", "_test.", ".test.", "spec.")
_EXTS = {".java", ".kt", ".py", ".js", ".ts", ".go", ".rb", ".php", ".cs", ".rs", ".scala", ".proto"}

# (kind, compiled pattern). Kept broad on purpose: a wrong guess costs one read_file.
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("http-route", re.compile(r"@(Get|Post|Put|Delete|Patch|Request)Mapping\b")),
    ("http-route", re.compile(r"@(Path|GET|POST|PUT|DELETE|PATCH)\s*[\(\n]")),
    ("http-route", re.compile(r"@(app|router|bp|blueprint)\.(get|post|put|delete|patch|route)\b", re.I)),
    ("http-route", re.compile(r"\b(app|router|r|mux|srv)\.(Get|Post|Put|Delete|Patch|HandleFunc|Handle)\s*\(")),
    ("http-route", re.compile(r"\burlpatterns\b|\bpath\(\s*[\"']")),
    ("http-route", re.compile(r"@WebServlet\b|extends\s+HttpServlet\b")),
    ("http-handler", re.compile(r"\b(doGet|doPost|doPut|doDelete)\s*\(")),
    ("http-handler", re.compile(r"\bchannelRead0?\s*\(|HttpRequestHandler\b")),
    # yamcs / protobuf-RPC style service methods: void name(Context ctx, Req, Observer)
    ("rpc-handler", re.compile(r"\bpublic\s+void\s+[a-z]\w*\s*\(\s*\w*Context\s+\w+\s*,")),
    ("rpc-service", re.compile(r"^\s*(service|rpc)\s+\w+", re.M)),
    ("graphql", re.compile(r"@(Query|Mutation|Subscription)\b|type\s+(Query|Mutation)\b")),
    ("websocket", re.compile(r"@(ServerEndpoint|OnMessage|MessageMapping)\b|WebSocketHandler\b")),
    ("queue-consumer", re.compile(r"@(KafkaListener|RabbitListener|JmsListener|SqsListener|StreamListener)\b")),
    ("cli-entry", re.compile(r"\bdef\s+main\s*\(|public\s+static\s+void\s+main\s*\(")),
    ("deserialize-sink", re.compile(r"\b(readObject|ObjectInputStream|yaml\.load|pickle\.loads|unserialize)\s*\(")),
]

_MAX_FILES = 12000
_MAX_BYTES = 1_500_000


def _interesting(path: str) -> bool:
    low = path.replace("\\", "/").lower()
    if any(h in low for h in _SKIP_FILE_HINTS):
        return False
    return os.path.splitext(low)[1] in _EXTS


def discover_entrypoints(repo_dir: str, *, max_files: int = _MAX_FILES) -> list[dict[str, Any]]:
    """Grep the checkout for externally reachable handler markers. Never raises."""

    found: list[dict[str, Any]] = []
    seen = 0
    for dirpath, dirnames, filenames in os.walk(repo_dir):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS and not d.startswith(".")]
        for name in filenames:
            full = os.path.join(dirpath, name)
            if not _interesting(full):
                continue
            seen += 1
            if seen > max_files:
                LOGGER.info("entrypoint sweep hit the %s-file cap", max_files)
                return found
            try:
                if os.path.getsize(full) > _MAX_BYTES:
                    continue
                text = open(full, encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            rel = os.path.relpath(full, repo_dir).replace("\\", "/")
            for kind, pattern in _PATTERNS:
                for m in pattern.finditer(text):
                    line = text.count("\n", 0, m.start()) + 1
                    found.append({"kind": kind, "file": rel, "line": line, "match": m.group(0).strip()[:60]})
    return found


def surface_summary(entries: list[dict[str, Any]], *, per_kind: int = 12, max_chars: int = 6000) -> str:
    """A compact, honest briefing: totals first, then a capped sample per kind.

    The totals matter more than the samples -- they tell the model how much surface it is
    expected to cover, so it cannot mistake a handful of examples for the whole job."""

    if not entries:
        return ""
    by_kind: dict[str, list[dict[str, Any]]] = {}
    for e in entries:
        by_kind.setdefault(e["kind"], []).append(e)
    files = {e["file"] for e in entries}
    lines = [
        "EXTERNAL ENTRYPOINT INTELLIGENCE (deterministic pre-scan of this checkout).",
        f"A pattern sweep found {len(entries)} candidate entrypoint markers across {len(files)} files.",
        "Treat this as the attack surface you are expected to COVER, not as a finished answer:",
        "the list is pattern-matched, so verify each one in the code, and it may miss framework",
        "registrations that no pattern matches - keep looking beyond it.",
        "",
    ]
    for kind in sorted(by_kind, key=lambda k: -len(by_kind[k])):
        hits = by_kind[kind]
        lines.append(f"{kind}: {len(hits)} markers")
        for e in hits[:per_kind]:
            lines.append(f"  - {e['file']}:{e['line']}  {e['match']}")
        if len(hits) > per_kind:
            lines.append(f"  ... and {len(hits) - per_kind} more {kind} markers not listed")
        lines.append("")
    text = "\n".join(lines).rstrip()
    if len(text) > max_chars:
        # The per-kind totals above are what matters; drop sample lines rather than spend the
        # model context window on examples.
        text = text[:max_chars].rsplit("\n", 1)[0]
        text += "\n  ... sample truncated; the per-kind totals above describe the full surface."
    return text
