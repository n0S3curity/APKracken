"""Deterministic grounding of a finding's code citation against the scan snapshot.

A model may claim any file, line, or snippet; until this module existed nothing downstream
checked, so a hallucinated citation cost the model nothing and reached the user as a real
finding. Here the snapshot is re-read and the citation is held to three facts: the file must
exist, the line must fall inside it, and the quoted code must actually appear in that file.
Findings that fail are marked and demoted rather than silently trusted.

This is intentionally model-free: it is the one part of the pipeline that cannot hallucinate.
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Any

LOGGER = logging.getLogger("open_kritt_engine.evidence")

# Verdicts, worst to best. "verified" is the only one that proves the citation is real.
VERIFIED = "verified"
NO_CITATION = "no_citation"
FILE_MISSING = "file_missing"
LINE_OUT_OF_RANGE = "line_out_of_range"
SNIPPET_MISMATCH = "snippet_mismatch"
# An exploit chain is a synthesis across several components; it has no single cited file,
# so "the file does not exist" is not evidence against it.
NOT_APPLICABLE = "not_applicable"

# A citation the snapshot contradicts outright: the file simply is not there.
UNGROUNDED = {FILE_MISSING}

_SEVERITY_WORDS = (
    ("critical", 9.5),
    ("high", 8.0),
    ("medium", 5.0),
    ("moderate", 5.0),
    ("low", 3.0),
    ("informational", 1.0),
    ("info", 1.0),
    ("none", 0.0),
)

# Quoted code shorter than this is too generic to prove anything ("return;", "}").
_MIN_NEEDLE_CHARS = 12
_MAX_NEEDLES = 8
_MAX_FILE_BYTES = 4_000_000


def finding_severity(ja: dict[str, Any]) -> float:
    """The numeric severity of a finding, however the producing workflow expressed it.

    Base workflow steps emit `severity` as a word ("High"); the specialists emit a numeric
    `severity_score`. Reading only `severity_score` silently scored every base finding 0.0,
    which made the High+ false-positive gate select nothing at all."""

    raw = ja.get("severity_score")
    if raw is not None and str(raw).strip() != "":
        try:
            return float(raw)
        except (TypeError, ValueError):
            pass
    word = str(ja.get("severity") or "").strip().lower()
    for prefix, score in _SEVERITY_WORDS:
        if word.startswith(prefix):
            return score
    return 0.0


# The workspace read_file tool returns numbered lines ("  64          foo();"), and models
# quote them verbatim, gutter included. Strip a leading line number so a faithful quote is
# not mistaken for a fabricated one.
_GUTTER_RE = re.compile(r"^\s*\d{1,6}\s*[:|]?\s+")


def _strip_gutter(line: str) -> str:
    stripped = _GUTTER_RE.sub("", line)
    return stripped if stripped.strip() else line


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", text or "").strip()


def citation_of(ja: dict[str, Any]) -> tuple[str, int | None, str]:
    """(path, line, quoted code) as the finding states them, across schema variants."""

    path = ""
    for key in ("code_file", "file_path", "path"):
        value = ja.get(key)
        if isinstance(value, str) and value.strip():
            path = value.strip()
            break
    line: int | None = None
    raw_line = ja.get("line")
    try:
        if raw_line is not None and str(raw_line).strip() != "":
            line = int(float(raw_line))
    except (TypeError, ValueError):
        line = None
    snippet = ""
    for key in ("code_evidence", "code", "snippet"):
        value = ja.get(key)
        if isinstance(value, str) and value.strip():
            snippet = value
            break
    return path, line, snippet


def _resolve(workspace_dir: str, path: str) -> Path | None:
    """Resolve a cited path inside the snapshot, tolerating the roots models prepend."""

    root = Path(workspace_dir).resolve()
    cleaned = str(path or "").strip().lstrip("/").replace("\\", "/")
    if not cleaned:
        return None
    candidates = [cleaned]
    # Models often echo, or drop, the decompiled-source root.
    for prefix in ("jadx/sources/", "sources/", "unpacked/"):
        if cleaned.startswith(prefix):
            candidates.append(cleaned[len(prefix):])
        else:
            candidates.append(prefix + cleaned)
    for candidate in candidates:
        try:
            resolved = (root / candidate).resolve()
        except (OSError, RuntimeError):
            continue
        if not str(resolved).startswith(str(root)):
            continue  # never follow a citation out of the snapshot
        if resolved.is_file():
            return resolved
    return None


def _needles(snippet: str) -> list[str]:
    """The substantial lines of the quoted code, normalised for comparison."""

    out: list[str] = []
    for raw in (snippet or "").splitlines():
        norm = _norm(_strip_gutter(raw))
        if len(norm) >= _MIN_NEEDLE_CHARS:
            out.append(norm)
    if not out:
        whole = _norm(snippet)
        if len(whole) >= _MIN_NEEDLE_CHARS:
            out.append(whole)
    out.sort(key=len, reverse=True)
    return out[:_MAX_NEEDLES]


def verify_citation(workspace_dir: str, ja: dict[str, Any]) -> dict[str, Any]:
    """Check one finding's citation against the snapshot.

    Returns {verdict, detail} and, when the quoted code is found on a different line than
    claimed, `actual_line` so the finding can be corrected instead of discarded."""

    if str(ja.get("source") or "").strip().lower() == "chain":
        return {
            "verdict": NOT_APPLICABLE,
            "detail": "exploit chain spans several components; grounded via its member findings",
        }

    path, line, snippet = citation_of(ja)
    if not path:
        return {"verdict": NO_CITATION, "detail": "the finding cites no file"}

    resolved = _resolve(workspace_dir, path)
    if resolved is None:
        return {"verdict": FILE_MISSING, "detail": f"{path} does not exist in the snapshot"}

    try:
        if resolved.stat().st_size > _MAX_FILE_BYTES:
            return {"verdict": NO_CITATION, "detail": f"{path} is too large to verify"}
        text = resolved.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return {"verdict": NO_CITATION, "detail": f"could not read {path}: {exc}"}

    lines = text.splitlines()
    result: dict[str, Any] = {}

    needles = _needles(snippet)
    if needles:
        normalized = [_norm(one) for one in lines]
        for needle in needles:
            for index, candidate in enumerate(normalized):
                if needle in candidate:
                    result["actual_line"] = index + 1
                    result["verdict"] = VERIFIED
                    result["detail"] = f"quoted code found at {path}:{index + 1}"
                    return result
        return {
            "verdict": SNIPPET_MISMATCH,
            "detail": f"the quoted code does not appear in {path}",
        }

    # No quote to match: the best we can prove is that the cited line exists.
    if line is not None and line > 0:
        if line > len(lines):
            return {
                "verdict": LINE_OUT_OF_RANGE,
                "detail": f"{path} has {len(lines)} lines, finding cites line {line}",
            }
        return {"verdict": VERIFIED, "detail": f"{path}:{line} exists (no quote to match)"}
    return {"verdict": NO_CITATION, "detail": f"{path} exists but the finding quotes no code"}
