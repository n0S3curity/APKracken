"""Read-only workspace server for the Vulnerability page.

The decompiled sources live in the engine's apk-cache (host-only data the backend container
can't read), so the engine serves them over a tiny local HTTP endpoint:

  GET /source?sha=<apk-sha256>&path=<rel>            -> full file text  ("View full file")
  GET /grep?sha=<sha>&pattern=<regex>&path=<rel?>     -> matching lines  (agentic chat tool)
  GET /list?sha=<sha>&path=<rel?>                     -> directory listing (agentic chat tool)

Strictly read-only and path-traversal guarded to a single apk-cache/<sha> tree. Bound to
0.0.0.0 so the browser (127.0.0.1) AND the Docker backend (host.docker.internal) can reach it.
Enabled with the device agent (env ENGINE_DEVICE_AGENT / ENGINE_SOURCE_PORT).
"""

from __future__ import annotations

import http.server
import json
import logging
import os
import re
import socketserver
import urllib.parse

LOGGER = logging.getLogger("open_kritt_engine")

_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_MAX_BYTES = 4_000_000
_GREP_MAX_MATCHES = 80
_GREP_MAX_FILES = 6000


def _safe_target(data_dir: str, sha: str, rel: str):
    """Resolve rel within apk-cache/<sha>, or None if traversal/invalid."""
    if not _SHA_RE.match(sha or ""):
        return None
    base = os.path.realpath(os.path.join(data_dir, "apk-cache", sha))
    target = os.path.realpath(os.path.join(base, rel or ""))
    if target != base and not target.startswith(base + os.sep):
        return None
    return base, target


def _grep(base: str, target: str, pattern: str) -> str:
    try:
        rx = re.compile(pattern)
    except re.error as exc:
        return f"[bad regex: {exc}]"
    root = target if os.path.isdir(target) else os.path.join(base, "jadx", "sources")
    if not os.path.isdir(root):
        root = base
    out: list[str] = []
    scanned = 0
    for dirpath, _dirs, files in os.walk(root):
        for fn in files:
            if scanned >= _GREP_MAX_FILES or len(out) >= _GREP_MAX_MATCHES:
                break
            if not fn.endswith((".java", ".kt", ".xml", ".smali", ".txt", ".json")):
                continue
            scanned += 1
            fp = os.path.join(dirpath, fn)
            try:
                with open(fp, encoding="utf-8", errors="replace") as fh:
                    for lineno, line in enumerate(fh, 1):
                        if rx.search(line):
                            rel = os.path.relpath(fp, base).replace("\\", "/")
                            out.append(f"{rel}:{lineno}: {line.strip()[:200]}")
                            if len(out) >= _GREP_MAX_MATCHES:
                                break
            except OSError:
                continue
        if scanned >= _GREP_MAX_FILES or len(out) >= _GREP_MAX_MATCHES:
            break
    if not out:
        return f"(no matches for {pattern!r} under {os.path.relpath(root, base).replace(os.sep, '/')})"
    header = f"{len(out)} match(es) for {pattern!r}" + (" (truncated)" if len(out) >= _GREP_MAX_MATCHES else "") + ":\n"
    return header + "\n".join(out)


def _list(base: str, target: str) -> str:
    if not os.path.isdir(target):
        return f"[not a directory: {os.path.relpath(target, base).replace(os.sep, '/')}]"
    entries = []
    try:
        for name in sorted(os.listdir(target))[:400]:
            full = os.path.join(target, name)
            entries.append(name + ("/" if os.path.isdir(full) else ""))
    except OSError as exc:
        return f"[list error: {exc}]"
    rel = os.path.relpath(target, base).replace(os.sep, "/")
    return json.dumps({"dir": rel, "entries": entries})


def _make_handler(data_dir: str):
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_OPTIONS(self):  # noqa: N802
            self._send(204, b"")

        def do_GET(self):  # noqa: N802
            parsed = urllib.parse.urlparse(self.path)
            q = urllib.parse.parse_qs(parsed.query)
            if parsed.path == "/evidence":
                return self._serve_evidence((q.get("path") or [""])[0])
            sha = (q.get("sha") or [""])[0].lower()
            rel = (q.get("path") or [""])[0]
            resolved = _safe_target(data_dir, sha, rel)
            if resolved is None:
                return self._send(400, b"bad sha / path")
            base, target = resolved

            if parsed.path == "/source":
                if not os.path.isfile(target):
                    return self._send(404, b"not found")
                try:
                    with open(target, "rb") as fh:
                        data = fh.read(_MAX_BYTES)
                except OSError:
                    return self._send(500, b"read error")
                return self._send(200, data, "text/plain; charset=utf-8")

            if parsed.path == "/grep":
                pattern = (q.get("pattern") or [""])[0]
                if not pattern:
                    return self._send(400, b"missing pattern")
                return self._send(200, _grep(base, target, pattern).encode("utf-8", "replace"))

            if parsed.path == "/list":
                return self._send(200, _list(base, target).encode("utf-8", "replace"))

            return self._send(404, b"not found")

        def _serve_evidence(self, rel: str):
            # Screenshot evidence from the dynamic-research pipeline. rel is
            # <scan>/<finding>/<file>.png under <data_dir>/dynamic-evidence, path-guarded.
            import posixpath
            root = os.path.realpath(
                os.getenv("ENGINE_DYNAMIC_EVIDENCE_DIR") or os.path.join(data_dir, "dynamic-evidence")
            )
            safe = posixpath.normpath("/" + rel.replace("\\", "/")).lstrip("/")
            target = os.path.realpath(os.path.join(root, safe))
            if not target.startswith(root + os.sep) or not os.path.isfile(target):
                return self._send(404, b"not found")
            ctype = "image/png" if target.lower().endswith(".png") else "application/octet-stream"
            try:
                with open(target, "rb") as fh:
                    return self._send(200, fh.read(_MAX_BYTES), ctype)
            except OSError:
                return self._send(500, b"read error")

        def _send(self, code: int, body: bytes, ctype: str = "text/plain; charset=utf-8"):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if body:
                try:
                    self.wfile.write(body)
                except Exception:  # noqa: BLE001
                    pass

        def log_message(self, *args):  # silence default logging
            return

    return Handler


def run_server(data_dir: str) -> None:
    """Blocking entry point — run in a dedicated daemon thread."""
    if os.getenv("ENGINE_DEVICE_AGENT", "1").strip().lower() not in {"1", "true", "yes", "on"}:
        return
    port = int(os.getenv("ENGINE_SOURCE_PORT", "9011"))
    host = os.getenv("ENGINE_SOURCE_HOST", "0.0.0.0")
    try:
        server = socketserver.ThreadingTCPServer((host, port), _make_handler(data_dir))
        server.daemon_threads = True
        LOGGER.info("workspace source server listening on http://%s:%s", host, port)
        server.serve_forever()
    except Exception:  # noqa: BLE001
        LOGGER.exception("workspace source server crashed")
