"""Seed Android workflows and queue APK scans directly against Postgres.

Interim tooling for the local Android build until the backend/UI expose `local`
harness + `apk` targets. Run with the engine venv (needs DATABASE_URL, psycopg):

    engine/.venv/Scripts/python scripts/kritt_android.py seed
    engine/.venv/Scripts/python scripts/kritt_android.py scan <path-to-apk> [--workflow "APK Security Triage"]

`seed` is idempotent (keyed by workflow name). `scan` inserts a queued scan the
running engine will pick up; it prints the scan id.
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "engine")))

import psycopg
from psycopg.rows import dict_row

FINDING_FIELDS = {
    "summary": "string",
    "vulnerability_type": "string",
    "component": "string",
    "file_path": "string",
    "line": "number",
    "explanation": "string",
    "attack_vector": "string",
    "adb_poc": "string",
    "severity": "string",
    "exploitable": "boolean",
}

TRIAGE_PROMPT = (
    "You are a mobile penetration tester analyzing the decompiled Android app {{repo_full}}.\n\n"
    "The workspace has decompiled Java (jadx/sources/), smali (apktool/), resources, and a WORKSPACE.json with the "
    "app's manifest intelligence (package, exported components, deep links, permissions, and security flags such as "
    "debuggable / allowBackup / usesCleartextTraffic) shown above. Use that intelligence to focus on real attack "
    "surface.\n\n"
    "Investigate for concrete, exploitable security vulnerabilities and prioritize:\n"
    "- Exported components (activity/service/receiver/provider) reachable by other apps without a signature permission\n"
    "- Insecure WebView usage and deep links (arbitrary loadUrl, addJavascriptInterface, file access)\n"
    "- Hardcoded secrets, credentials, API keys, or endpoints (search strings, BuildConfig, resources, assets)\n"
    "- Insecure storage of sensitive data (SharedPreferences, external storage, SQLite)\n"
    "- Weak or broken cryptography (ECB, hardcoded keys/IV, weak PRNG)\n"
    "- Exported ContentProvider path traversal or SQL injection\n"
    "- Manifest misconfigurations already flagged in the intelligence\n\n"
    "Read the relevant decompiled code to confirm each issue. Report only concrete findings supported by code "
    "evidence. For each, set component to the responsible component, file_path/line to the vulnerable code (use a "
    "workspace-relative path such as jadx/sources/com/app/Foo.java), give a concrete adb/intent PoC in adb_poc when "
    "applicable, and set exploitable true only when another app or a remote actor can realistically trigger it. "
    "Return a stub only if you genuinely find nothing."
)

WORKFLOW_NAME = "APK Security Triage"
WORKFLOW_DESCRIPTION = "Single-pass Android static triage over a decompiled APK: exported surface, WebView/deep links, secrets, storage, crypto, manifest misconfig."


def _db_url() -> str:
    url = os.getenv("DATABASE_URL")
    if not url:
        sys.exit("DATABASE_URL is not set (source .env.native or export it).")
    # libpq rejects Prisma's ?schema=public
    return url.split("?", 1)[0]


def seed(conn) -> int:
    existing = conn.execute(
        "select id, step_ids from llm_workflows where name = %s", (WORKFLOW_NAME,)
    ).fetchone()
    if existing:
        print(f"workflow already seeded: id={existing['id']}")
        return int(existing["id"])
    step = conn.execute(
        """
        insert into steps (content, output_format, name, depth, multi_output, consume_all_previous,
                           is_last_step, output_table)
        values (%s, %s, %s, 0, true, false, true, 'workflows.vulnerabilities')
        returning id
        """,
        (TRIAGE_PROMPT, json.dumps(FINDING_FIELDS), "APK security triage"),
    ).fetchone()
    step_id = int(step["id"])
    workflow = conn.execute(
        """
        insert into llm_workflows (step_ids, name, description, extra)
        values (%s, %s, %s, %s)
        returning id
        """,
        ([step_id], WORKFLOW_NAME, WORKFLOW_DESCRIPTION, []),
    ).fetchone()
    workflow_id = int(workflow["id"])
    print(f"seeded workflow '{WORKFLOW_NAME}' id={workflow_id} (step {step_id})")
    return workflow_id


def create_scan(conn, apk_path: str, workflow_name: str) -> int:
    workflow = conn.execute("select id from llm_workflows where name = %s", (workflow_name,)).fetchone()
    if not workflow:
        sys.exit(f"workflow {workflow_name!r} not found; run `seed` first.")
    from open_kritt_engine.apk_workspace import sha256_file

    post_script = conn.execute("select id from post_scripts order by id limit 1").fetchone()
    apk_abs = os.path.abspath(apk_path).replace("\\", "/")
    display = os.path.splitext(os.path.basename(apk_abs))[0]
    apk_sha = sha256_file(apk_abs)
    row = conn.execute(
        """
        insert into scans (workflow_id, post_script_id, repo_full, repo_kind, commit_sha, repo_scope,
                           dependencies, configuration, model, model_provider, harness, thinking_effort,
                           status, config, scopes, agent_skill_ids)
        values (%s, %s, %s, 'apk', %s, %s, %s, %s, %s, %s, %s, %s, 'queued', %s, %s, %s)
        returning id
        """,
        (
            int(workflow["id"]),
            int(post_script["id"]),
            display,
            apk_sha,
            "full application",
            [],
            json.dumps({"apk_path": apk_abs, "repeat_runs": 1}),
            "local",
            "local",
            "local",
            "medium",
            json.dumps({}),
            json.dumps({"files": [], "lines": []}),
            [],
        ),
    ).fetchone()
    scan_id = int(row["id"])
    print(f"queued scan id={scan_id} for {apk_abs} using workflow '{workflow_name}'")
    return scan_id


def _load_workspace_manifest(scan: dict) -> dict:
    from open_kritt_engine.apk_workspace import sha256_file

    config = scan.get("configuration") or {}
    apk_path = config.get("apk_path") if isinstance(config, dict) else None
    # commit_sha holds the apk sha256 for scans created after the fix; older rows fall
    # back to recomputing it from the configured apk_path.
    sha = scan.get("commit_sha")
    if not sha or len(str(sha)) != 64:
        if not apk_path:
            sys.exit("cannot locate decompiled workspace: no apk sha256 or apk_path on scan")
        sha = sha256_file(apk_path)
    data_dir = os.getenv("ENGINE_DATA_DIR", ".")
    path = os.path.join(data_dir, "apk-cache", sha, "WORKSPACE.json")
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def confirm_scan(conn, scan_id: int) -> None:
    """Run the dynamic-confirmation pass for a completed APK scan and persist evidence."""

    from open_kritt_engine import adb, dynamic_confirm as dc

    scan = conn.execute(
        "select id, workflow_id, repo_full, commit_sha, configuration from scans where id = %s", (scan_id,)
    ).fetchone()
    if not scan:
        sys.exit(f"scan {scan_id} not found")
    manifest = _load_workspace_manifest(scan)
    android = manifest.get("android", {})
    package = android.get("package") or scan["repo_full"]

    device = adb.get_device()
    print(f"device: {device.summary()}")
    device.logcat_clear()

    # Build leads from static manifest intelligence.
    activities = [c["name"] for c in android.get("exported_components", []) if c.get("kind") in ("activity", "activity-alias")]
    deep_link_uris = [f"{s}://{(dl.get('hosts') or [''])[0]}/x" for dl in android.get("deep_links", []) for s in dl.get("schemes", [])]
    authorities = [c.get("authorities") for c in android.get("components", []) if c.get("kind") == "provider" and c.get("authorities")]

    # Idempotent re-run: clear prior dynamic artefacts for this scan.
    conn.execute("delete from workflows.dynamic_evidence where scan_id = %s", (scan_id,))
    conn.execute(
        "delete from workflows.vulnerabilities where scan_id = %s and json_answer->>'source' = 'dynamic'", (scan_id,)
    )

    evidence: list[tuple[dc.Evidence, str]] = []
    for name in activities:
        evidence.append((dc.confirm_exported_activity(device, package, name, screenshot=False), "exported_activity"))
    for uri in deep_link_uris:
        evidence.append((dc.confirm_deep_link(device, uri), "deep_link"))
    for authority in authorities:
        evidence.append((dc.confirm_content_provider(device, f"content://{authority}/"), "content_provider"))
    device.force_stop(package)

    created = 0
    for ev, kind in evidence:
        vuln_id = None
        if ev.outcome in ("confirmed", "guarded"):
            exploitable = ev.outcome == "confirmed"
            label = {"exported_activity": "Exported Activity", "deep_link": "Deep Link", "content_provider": "Content Provider"}[kind]
            json_answer = {
                "source": "dynamic",
                "summary": f"{label} {ev.target} — {ev.outcome} at runtime",
                "vulnerability_type": f"{label} (runtime-{ev.outcome})",
                "component": ev.target,
                "file_path": "AndroidManifest.xml",
                "line": 0,
                "explanation": f"Runtime confirmation on {device.serial}: {ev.detail}",
                "malicious_input_example": f"adb shell am start / content query against {ev.target}",
                "exploitable": exploitable,
                "dynamic_outcome": ev.outcome,
            }
            row = conn.execute(
                """
                insert into workflows.vulnerabilities (scan_id, workflow_id, scan_metadata_id, prev_id, json_answer)
                values (%s, %s, 0, 0, %s) returning id
                """,
                (scan_id, int(scan["workflow_id"]), json.dumps(json_answer)),
            ).fetchone()
            vuln_id = int(row["id"])
            created += 1
        conn.execute(
            """
            insert into workflows.dynamic_evidence (scan_id, vulnerability_id, check_kind, target, outcome, detail, artifacts, device_serial)
            values (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (scan_id, vuln_id, kind, ev.target, ev.outcome, ev.detail, json.dumps(ev.artifacts), device.serial),
        )

    outcomes: dict[str, int] = {}
    for ev, _ in evidence:
        outcomes[ev.outcome] = outcomes.get(ev.outcome, 0) + 1
    print(f"\ndynamic confirmation complete: {dict(sorted(outcomes.items()))}")
    print(f"stored {len(evidence)} evidence rows; created {created} runtime-confirmed findings for scan {scan_id}")


def investigate_scan(conn, scan_id: int, max_leads: int = 3) -> None:
    """Run a specialist agent per attack-surface lead: read code, prove/refute on device,
    store only real, adjudicated vulnerabilities (false positives filtered out)."""

    from open_kritt_engine import adb, specialist_agent as sa
    from open_kritt_engine.apk_workspace import sha256_file

    scan = conn.execute(
        "select id, workflow_id, repo_full, commit_sha, configuration from scans where id=%s", (scan_id,)
    ).fetchone()
    manifest = _load_workspace_manifest(scan)
    android = manifest.get("android", {})
    package = android.get("package") or scan["repo_full"]
    sha = scan["commit_sha"] if len(str(scan["commit_sha"])) == 64 else sha256_file(scan["configuration"]["apk_path"])
    workspace_dir = os.path.join(os.getenv("ENGINE_DATA_DIR", "."), "apk-cache", sha)
    device = adb.get_device()

    # Prioritise real vuln classes: WebView/deep-link targets, providers, storage, crypto, then activities.
    deep_link_targets = {dl["component"] for dl in android.get("deep_links", [])}
    dl_uris = [f"{s}://{(dl.get('hosts') or [''])[0]}/web?url=" for dl in android.get("deep_links", []) for s in dl.get("schemes", [])]
    leads: list[dict] = []
    for c in android.get("exported_components", []):
        name = c.get("name") or ""
        if name in deep_link_targets or "webview" in name.lower():
            leads.append({"component": name, "vulnerability_type": "webview / deep link", "kind": c.get("kind"), "deep_links": dl_uris})
    leads.append({"component": f"{package} (insecure storage)", "vulnerability_type": "insecure storage", "kind": "storage"})
    leads.append({"component": f"{package} (cryptography)", "vulnerability_type": "crypto", "kind": "crypto"})
    leads.append({"component": f"{package} (PendingIntent usage)", "vulnerability_type": "pending intent", "kind": "pending_intent"})
    leads.append({"component": f"{package} (race conditions)", "vulnerability_type": "race condition", "kind": "race_condition"})
    for c in android.get("components", []):
        if c.get("kind") == "provider" and c.get("authorities"):
            leads.append({"component": c.get("name"), "vulnerability_type": "content provider", "kind": "provider", "authorities": c.get("authorities")})
    for c in android.get("exported_components", []):
        name = c.get("name") or ""
        if name not in deep_link_targets and "webview" not in name.lower() and c.get("kind") in ("activity", "activity-alias"):
            leads.append({"component": name, "vulnerability_type": "exported component / intent redirection", "kind": c.get("kind"), "deep_links": dl_uris})

    # Replace prior dynamic/specialist/chain findings for this scan.
    conn.execute("delete from workflows.vulnerabilities where scan_id=%s and json_answer->>'source' in ('dynamic','specialist','chain')", (scan_id,))
    conn.commit()

    confirmed: list[dict] = []
    for lead in leads[:max_leads]:
        print(f"\n>>> specialist investigating: {lead['component']} ({lead['vulnerability_type']})")
        finding = sa.investigate_lead(lead, workspace_dir=workspace_dir, package=package, device=device)
        vuln = bool(finding.get("is_vulnerable")) and not bool(finding.get("false_positive"))
        print(f"    -> is_vulnerable={finding.get('is_vulnerable')} score={finding.get('severity_score')} title={finding.get('title')!r}")
        if not vuln:
            continue
        finding["component"] = lead["component"]
        confirmed.append(finding)
        json_answer = {
            "source": "specialist",
            "summary": finding.get("title"),
            "vulnerability_type": finding.get("vulnerability_type"),
            "component": lead["component"],
            "file_path": "jadx/sources/" + lead["component"].split(" ")[0].replace(".", "/") + ".java",
            "line": 0,
            "explanation": f"{finding.get('impact')}\n\nStatic: {finding.get('static_evidence')}\n\nDynamic proof: {finding.get('dynamic_evidence')}\n\nChainable primitive: {finding.get('chainable_primitive')}",
            "malicious_input_example": finding.get("poc"),
            "exploitable": bool(finding.get("exploitable_externally")),
            "confidence": finding.get("confidence"),
            "severity_score": finding.get("severity_score"),
        }
        conn.execute(
            "insert into workflows.vulnerabilities (scan_id, workflow_id, scan_metadata_id, prev_id, json_answer) values (%s,%s,0,0,%s)",
            (scan_id, int(scan["workflow_id"]), json.dumps(json_answer)),
        )
        conn.commit()

    print(f"\n>>> chain analyst over {len(confirmed)} confirmed vulnerabilities ...")
    chains = sa.chain_analyst(confirmed, workspace_dir=workspace_dir, package=package, android_intel=android, device=device) if len(confirmed) >= 2 else []
    for ch in chains:
        print(f"    CHAIN [score {ch.get('severity_score')}] {ch.get('title')}")
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
        }
        conn.execute(
            "insert into workflows.vulnerabilities (scan_id, workflow_id, scan_metadata_id, prev_id, json_answer) values (%s,%s,0,0,%s)",
            (scan_id, int(scan["workflow_id"]), json.dumps(json_answer)),
        )
        conn.commit()

    # Re-rank ALL findings for this scan by severity score (chains and specialists first).
    rows = conn.execute("select id, json_answer from workflows.vulnerabilities where scan_id=%s", (scan_id,)).fetchall()
    def score(r):
        j = r["json_answer"] or {}
        base = float(j.get("severity_score") or 0)
        if j.get("source") == "chain":
            base += 0.5  # tie-break chains above their parts
        return base
    for rank, r in enumerate(sorted(rows, key=score, reverse=True), start=1):
        conn.execute("update workflows.vulnerabilities set rank=%s where id=%s", (rank, r["id"]))
    conn.commit()
    print(f"\ninvestigated {min(len(leads), max_leads)} leads; {len(confirmed)} vulns + {len(chains)} chains; re-ranked {len(rows)} findings for scan {scan_id}")


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("seed")
    scan_parser = sub.add_parser("scan")
    scan_parser.add_argument("apk")
    scan_parser.add_argument("--workflow", default=WORKFLOW_NAME)
    confirm_parser = sub.add_parser("confirm")
    confirm_parser.add_argument("scan_id", type=int)
    inv_parser = sub.add_parser("investigate")
    inv_parser.add_argument("scan_id", type=int)
    inv_parser.add_argument("--max", type=int, default=3, dest="max_leads")
    inv_parser.add_argument("--static", action="store_true", help="static-only: no device, code analysis only")
    args = parser.parse_args()
    with psycopg.connect(_db_url(), row_factory=dict_row) as conn:
        if args.cmd == "seed":
            seed(conn)
        elif args.cmd == "scan":
            seed(conn)
            create_scan(conn, args.apk, args.workflow)
        elif args.cmd == "confirm":
            confirm_scan(conn, args.scan_id)
        elif args.cmd == "investigate":
            from open_kritt_engine.dynamic_investigation import run_for_scan

            summary = run_for_scan(
                conn,
                args.scan_id,
                data_dir=os.getenv("ENGINE_DATA_DIR", "."),
                max_leads=args.max_leads,
                static_only=args.static,
            )
            print(summary)
        conn.commit()


if __name__ == "__main__":
    main()
