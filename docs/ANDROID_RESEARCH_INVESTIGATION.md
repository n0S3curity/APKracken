# open·kritt → Android Research Platform — Investigation & Roadmap

> Author: Claude (Fable 5), acting as Sr. Android RE / Sr. Mobile Pentester / Malware Researcher / Software Architect / AI Systems Engineer.
> Source of truth: the cloned source at commit-of-clone. README treated as historical only.
> Target profile (from scoping): **local-only, air-gapped llama.cpp on RTX 5080 (16 GB) + Ryzen 9 9950X3D / 32 GB**, **full static + dynamic lifecycle**, **Frida-first (traffic interception later)**, **bug-bounty + client-pentest targets**, **engine running natively on Windows**.

---

## 0. Executive summary

open·kritt is **not** an Android tool. It is a **generic, resumable, parallel prompt-DAG execution engine** that points *agentic cloud AI CLIs* (Claude Code, Codex, Cursor) at *checked-out git repositories* and turns their output into a **deduplicated, severity- and bounty-ranked finding set** with per-finding **post-script enrichment** (validation / PoC / report) and exhaustive **prompt+token observability**.

The strategic insight: **the orchestration core is excellent and directly reusable for Android**, but three layers must be replaced and one whole dimension must be added:

| Layer | Verdict | Why |
|---|---|---|
| Prompt-DAG engine, output schema, dedup, ranking, post-scripts, observability, workflow builder UI, generations, agent skills | **KEEP & retarget** | Input-agnostic; maps 1:1 onto Android research phases |
| Harness layer (cloud agentic CLIs) | **REPLACE** with a local agentic harness on llama.cpp | Air-gapped local-only; llama-server is not agentic on its own |
| Input/workspace layer (git checkout) | **REPLACE** with APK ingest + decompile + device acquisition | Android inputs are APKs and live devices, not git repos |
| Docker-per-job sandbox + cloud account/credential mgmt | **REPLACE/SIMPLIFY** | Native-Windows + local-only removes the untrusted-cloud threat model and the multi-account complexity |
| Static toolchain, dynamic/device subsystem (ADB+Frida), static↔dynamic correlation, Android intelligence pack, local RAG index, grammar-constrained decoding | **ADD (net-new)** | The actual Android research value lives here |

The single highest-leverage build is a **`LocalAgenticHarness`** that satisfies the existing harness interface (`run(prompt, schema, repo_dir, model, …) -> HarnessResult`) but drives a **ReAct-style tool loop against llama-server** with **GBNF grammar derived from the engine's existing `output_schema()`** and an **Android-native toolset** (decompiled filesystem, jadx queries, smali/dex search, `adb`, Frida). Because the interface is unchanged, *the entire downstream engine keeps working*.

---

## 1. Current architecture

**Polyglot monorepo, five cooperating services** (verified in `AGENTS.md` + source):

- `frontend/` — React 18 + Vite. Workflow builder (`WorkflowBuilder.jsx`, 1192 LOC), scan creation (`CreateScan.jsx`, 1467), scan detail/live view (`ScanDetail.jsx`, 1840), vulnerability view (`VulnerabilityPage.jsx`, 904), accounts/providers (`Accounts.jsx`, 1072), post-scripts, severity rankers, agent skills, AI generation.
- `backend/` — Node + Express + Prisma over Postgres. CRUD API for the domain model; heavy validation (`lib/validation.js`, 730), repo resolution (`lib/repo.js`, 768), account/credential management (`lib/accountLogins.js` 560, `lib/providerCredentials.js` 223).
- `engine/` — Python 3.11 worker. **The heart.** Pulls jobs, prepares workspaces, runs harnesses, validates+stores results, dedups, ranks, post-processes. Key modules: `worker.py` (1382), `harnesses.py` (1792), `workspace.py` (1432), `db.py` (1737), `post_processing.py` (988), `generation.py` (803), `prompting.py` (680), `repository.py` (578), `model_catalog.py` (519), `schema.py` (102), `queue.py` (129).
- `database/` — Postgres 16, `init/NNN_*.sql` additive/idempotent/forward-only migrations (24 of them; feature evolution is legible from their names: agent skills → severity rankers → model catalogs → generations → scan management → bounty rank).
- `executor-view/` — standalone read-only Python HTTP server (`server.py`, port 8090) that reads the DB directly for live execution monitoring, with optional token auth.

Orchestration: **Docker Compose**. Each *tool-enabled harness run* additionally spins up a **disposable root Docker job container** (`docker run --rm`, per-job network, bind-mounted workspace, pids limit, tmpfs) — the isolation boundary for running agents over untrusted code.

**Domain model** (`backend/prisma/schema.prisma`, authoritative):
- **Step** — one prompt + declared `output_format`; fan-out semantics via `depth`, `multi_output`, `consume_all_previous`, `is_last_step`.
- **Workflow** — ordered `step_ids` + declared `extra` template keys.
- **Scan** — a run of a workflow against `repo_full`/`commit_sha`/`repo_scope` (+ `dependencies`, `agent_skill_ids`, `model`/`harness`/`thinking_effort`, `severity_ranker`, `configuration`, `scopes`).
- **Vulnerability** — a finding (`json_answer`), with **dedup** fields (canonical/cluster/reason/model) and **bounty-rank** fields (impact level, min/max reward, reasoning, root bug).
- **VulnerabilityEnrichment** — post-script output per finding (unique per `(vulnerability, post_script)`), supports `stub` + `stub_explanation`.
- **StepResult** — raw per-step output, LIST-partitioned by `{scan_id}-{step_depth}`, lineage via `prev_id`/`prev_table`.
- **StepMetadata / PostProcessMetadata** — full telemetry: `prompt_template`, `prompt_filled`, `output_json`, token counts, timing, model/harness, checked-out commit.

---

## 2. Internal workflows (how research is decomposed)

The engine's model is a **breadth-fanned prompt tree** (confirmed in `queue.py::build_pending_jobs`):

1. Depth 0 starts from one root **State** = the scan context.
2. A `multi_output` step returns an **array of records**; each record spawns a child State at the next depth (fan-out), with the record's fields merged into the child's template context.
3. A `consume_all_previous` depth instead **collapses all previous-depth outputs into one batch** exposed as `{{multi_output_depth_N}}` — a single agent reasons over the whole set (used for cross-cutting analysis / dedup-style passes).
4. `repeat_runs` re-runs the *same* task cumulatively; `repeat_append_prompt` feeds prior results back as *untrusted data* and demands only genuinely-new records.
5. The last depth writes to `workflows.vulnerabilities`; intermediate depths write to `workflows.step_results`.

The two **built-in playbooks** (`defaultWorkflowSeeds.json`) reveal the intended shape:
- **external-flow-analysis** — depth0 *map external entrypoints* → depth1 *trace reachable flows* → depth2 *investigate flow vulnerabilities*. Generic web/API attack-surface reasoning.
- **Cosmos ABCI Panic Halt Review** — Go/blockchain-specific (reflects the team's Immunefi/HackenProof Web3 bounty origin). depth0 *enumerate ABCI methods* → depth1 *four parallel panic-class investigations*.

**Both are server/blockchain-oriented. There is zero Android content anywhere.** But the *shape* — enumerate surface → trace flows → investigate — is exactly the Android static methodology.

---

## 3. Data flow

```
Scan (repo_full, workflow, model/harness, config, scopes, severity_ranker, extra)
  │
  ▼  build_pending_jobs()  →  Job(step, State{context, prev_id, repeat_run})
  │
  ▼  execute_job():
     prepare_dependency_workspace()  ── git checkout repo(+deps) into job workspace,
     │                                   materialize agent home (skills, provider auth),
     │                                   return {repo_dir, layout, manifest_json, env, commit}
     render_prompt(step.content, context ∪ workspace_context)   ← {{repo_full}}, {{extra.x}}, …
     harness_prompt(+ schema block + stub contract + skills + repeat-append)
     │
     ▼  harness.run(prompt, schema=output_schema(step.output_format), repo_dir, model, env)
     │      → agentic CLI explores repo_dir in a disposable container → JSON
     │
     ▼  validate_payload()  (stub/results/schema invariants)
     ▼  store StepResult / Vulnerability  + StepMetadata (prompt_filled, output_json, tokens, timing)
  │
  ▼  post-processing (per finding): dedup → severity rank → bounty rank → post-scripts (enrichment/PoC/report)
```

Everything after `harness.run` is **input-agnostic**. The only Android-specific work is *upstream* (what fills `repo_dir` and the context) and *inside the harness* (what tools it can use).

---

## 4. Execution flow (control)

- `worker.py` runs a **worker pool** (`ENGINE_WORKER_COUNT`, default 2), sharing slots between scan steps and post-processing, gated by `ENGINE_MAX_CONCURRENT_SCANS` / `ENGINE_MAX_WORKERS_PER_SCAN`, storage guards (`ENGINE_MIN_FREE_STORAGE_GB`), and a workspace-setup semaphore.
- `execute_job` (worker.py:915) claims step metadata idempotently, prepares the workspace, renders+fills the prompt, sets status `running`, then runs the harness with **retry** (`ENGINE_RETRY_COUNT`) and **rate-limit backoff**.
- Scans are **resumable**: `completed`/`claimed` sets + partitioned `step_results` let a restarted engine recompute exactly the missing jobs. Checkout caches are prewarmed and persisted (`prewarm_scan_checkout_cache`, `save_persistent_scan_checkout_cache`).
- Rate-limit/quota/capacity failures are richly classified (`harnesses.py::_classify_harness_output`) and drive account rotation and autoscaling.

This machinery is **battle-tested and directly valuable** — a long Android dynamic run (e.g., 200 exported components × Frida probes) needs exactly this resumability and parallelism.

---

## 5. Current strengths

1. **Resumable, parallel, idempotent DAG execution** with fan-out + consume-all + cumulative repeats. Rare to get right; already done.
2. **Strict structured-output contract** (`schema.py`): every step must emit `{_kritt_extractor_helper, stub, stub_explanation, results[]}` validated against a generated JSON Schema. *This is precisely what small local models need* — and llama.cpp can enforce it with grammar.
3. **Full provenance/observability**: every `prompt_template`, `prompt_filled`, `output_json`, token count, timing, and checked-out revision is persisted. Reproducible research + audit trail out of the box.
4. **Dedup + severity + bounty ranking** — impact level, min/max reward, reasoning, root-bug clustering. *Exactly* the deliverable a bug-bounty/pentest researcher wants.
5. **Post-scripts / enrichment** — per-finding second passes with reserved render keys (`_reserved_report`, `_reserved_poc`, `_chip_*`). A ready-made "validate → build PoC → write report" stage.
6. **`patched_since`** — precomputed git diff between the pinned finding commit and upstream default, so the model can judge "still unpatched?" without hallucinating git. Conceptually reusable for **APK version-diffing**.
7. **AI-authored workflows** (`generation.py`) — natural-language → workflow/post-script drafts. A local model can extend the platform's own playbooks.
8. **Agent skills** — reusable instruction bundles injected into the agent home (native slash-command for Claude/Codex, prompt-block fallback). A clean home for Android RE know-how.
9. **Clean harness interface** — swapping the AI backend is a single well-defined seam.

---

## 6. Weaknesses (for the Android/local-only goal)

1. **Cloud-agent–coupled.** All three harnesses are external agentic CLIs (`claude`, `codex`, `cursor-agent`) that require provider auth and internet. Nothing local. (`harnesses.py`)
2. **Git-repo–coupled inputs.** `prepare_dependency_workspace`, `repository.py`, `patched_since`, and the whole `repo_full`/`commit_sha`/`repo_scope` model assume git. No APK, DEX, resources, native libs, or device concept.
3. **No dynamic/runtime dimension at all.** No ADB, no device model, no instrumentation, no traffic, no runtime evidence. The entire "dynamic" half of the mission is greenfield.
4. **Docker-per-job on Windows is friction.** Bind-mount path translation (`_host_path_for_engine_data_path`) + Linux root containers + `--network` isolation don't map cleanly to a native-Windows engine that must reach USB/ADB and a local GPU. For your non-malware targets, the sandbox's value is low relative to its cost.
5. **Heavy multi-account/provider machinery** (`Accounts.jsx` 1072, `accountLogins.js` 560, model catalogs, codex updater) is dead weight in a single-user local-only world.
6. **Array fields are string-only** in the generated schema (`schema.py` `FIELD_TYPE_MAP["array"] = items:string`). Rich nested Android evidence (e.g., structured intent-filter objects) must be flattened or the schema builder extended.
7. **Engine tests disabled in CI** (per `AGENTS.md`) — several assume a writable Linux `/root` home; they'll need Windows-friendly rework.
8. **No local model/GGUF management** anywhere — no concept of model files, context windows, quant, or GPU layers.

---

## 7. Technical debt

- **Legacy compatibility carried forward**: `Scan.config` (legacy JSON) alongside authoritative columns; `dependencies` (legacy) alongside `dependencies_detail`; multiple duplicate migration numbers (`003_*`, `005_*`, `006_*`, `016_*`, `019_*`) — additive-only discipline left scars. For a private fork you can **collapse the migration history** into a clean baseline.
- **Provider-specific branching** threads through `harnesses.py` (OpenRouter vs Claude-native output formats, Codex JSONL parsing, Cursor JSON). Replacing with one local harness removes most of it.
- **Codex/Claude auth + OAuth expiry + updater** (`claude_auth.py` 407, `codex_auth.py`, `codex_updater.py`) — hundreds of lines that vanish in local-only.
- **Windows path handling** is not a first-class concern anywhere; the engine assumes POSIX homes and Docker host paths.

---

## 8. Bottlenecks

- **Single GPU, single model.** With one RTX 5080 (16 GB), you cannot run many large-context agents in parallel the way the cloud design assumes. `ENGINE_WORKER_COUNT` parallelism becomes **queue depth against one llama-server**, not true concurrency. Architecture must shift from "many parallel expensive agents" to "**deep task decomposition + a fast small model + retrieval**, escalating only hard synthesis steps to a slower large-context pass."
- **Context window vs decompiled size.** A large APK decompiles to tens of thousands of files; you cannot dump it into context. **A local code index / RAG over the decompiled workspace is mandatory**, not optional.
- **Cold decompilation.** jadx/apktool on a big APK is minutes of CPU. Must be cached per-APK-hash (mirror the existing checkout-cache pattern) and done once, not per step.
- **Device serialization.** One rooted phone is a single shared resource; dynamic jobs must be **serialized/locked per device** (the codebase already has a lock pattern — `scanLocks.js`, `workflowLocks.js` — extend it to a device lock).

---

## 9. Opportunities for improvement (architecture)

1. **Introduce a first-class `Target` abstraction** above the git-centric `Scan`. A Target is one of: `apk` (file/hash), `device` (adb serial), or `apk+device` (installed & instrumented). `repo_dir` becomes `workspace_dir` = the decompiled + resource + native tree; `commit_sha` becomes `apk_sha256` (+ optional versionCode for diffing).
2. **`LocalAgenticHarness`** implementing the existing interface, backed by llama-server, with tool-calling + GBNF-constrained final answer. (§0)
3. **Two-tier model routing**: a fast small model (e.g. 7–14B) for enumeration/extraction/triage under grammar; a 24–32B (quantized, CPU-offloaded) model for `consume_all` synthesis, dedup reasoning, and report writing. Store the choice per-step like `thinking_effort` already is.
4. **Decompilation-as-workspace**: `prepare_dependency_workspace` → `prepare_apk_workspace` producing a stable tree (`/smali`, `/java` (jadx), `/resources`, `/lib` per-ABI, `AndroidManifest.xml` decoded, `apktool.yml`, extracted strings/assets), plus a `workspace_manifest_json` describing package, components, permissions, SDK levels, signing, native ABIs — reusing the existing manifest/layout context slots.
5. **Static↔dynamic correlation store**: link a static finding (exported component, deep link, crypto sink) to runtime evidence (Frida hook hit, logcat, intent result) via new tables mirroring `VulnerabilityEnrichment`.
6. **Device subsystem** as its own worker capability with a device lock, health checks (`adb get-state`), and a Frida session manager.

---

## 10. Missing capabilities (the Android intelligence pack — net-new)

**Static:**
- APK ingest (drag-drop / folder watch, mirroring `LOCAL_REPOS_PATH`), split-APK/AAB/XAPK merge, hash + dedupe by `apk_sha256`.
- Decompilers: **jadx** (Java), **apktool** (smali + decoded resources), **baksmali** fallback; native: **radare2/ghidra headless** for `.so` triage.
- Manifest intelligence: exported activities/services/receivers/providers, `intent-filter` + deep links + `android:scheme`/`host`/`pathPrefix`, permissions (+ custom permission protection levels), `exported`/`grantUriPermissions`, `debuggable`, `allowBackup`, `usesCleartextTraffic`, `networkSecurityConfig`, min/target SDK.
- Secrets & endpoints: API keys, Firebase/GCP configs, hardcoded URLs, cloud buckets, JWTs, keystores in assets, `strings.xml`/`BuildConfig` constants.
- Crypto & storage misuse: ECB, static IV/keys, weak PRNG, `SharedPreferences`/SQLite for secrets, external-storage writes, WebView `addJavascriptInterface`/`setAllowFileAccess`, `loadUrl` sinks.
- Component attack surface: exported providers (path traversal/SQLi), intent redirection, PendingIntent mutability, task-hijack (`launchMode`), broadcast injection.
- Library & SBOM: third-party SDK inventory + known-vuln matching, tracker/adware SDK detection.
- **The jadx-analyzer MCP already in your toolbelt** (`load_apk`, `get_class_source`, `get_smali_of_method`, `get_android_manifest`, `get_exported_components`, `search_method_by_name`) is a *ready-made deterministic tool surface* for the local agent — wire it as the harness's primary code-query tool instead of blind grep.

**Dynamic (Frida-first):**
- ADB layer: install/launch/pull, logcat capture, `dumpsys`, `pm`/`cmd`, screen capture, file pull from app sandbox, content-provider probing (`content query`), activity/intent fuzzing (`am start` with crafted extras/URIs).
- Frida: auto-push matching `frida-server`, spawn-gated attach, script library (SSL-pinning bypass, root/emulator-detection bypass, crypto tap, WebView taps, class/method tracer, keystore/`SharedPreferences` dump, clipboard/IPC taps), live hook-hit → evidence store.
- Runtime attack surface exercise: drive each exported component/deep link discovered statically and record what actually happens (crash, leaked data, privileged action).
- (Later, per your sequencing) traffic interception: proxy + CA install + `networkSecurityConfig`/pinning handling.

**Cross-cutting:**
- **Android workflow seeds** (the DAG playbooks): *manifest-attack-surface → component/flow trace → vuln investigation*; *deep-link exploitation*; *exported-provider audit*; *crypto/storage audit*; *native-lib triage*; *secrets & endpoints*; *dynamic-confirmation* (statically-found → Frida-verified).
- **Android output schemas** per depth (component records, flow records, finding records with `component`, `intent_uri`, `frida_script`, `adb_repro`).
- **Android severity rankers** + **bounty rankers** tuned to mobile programs (MASVS/OWASP-MASTG mapping, CVSS-mobile).
- **Android post-scripts**: build a runnable `adb`/Frida PoC, capture a repro, write a MASVS-aligned report section.
- **Android agent skills**: MASTG test knowledge, smali reading tips, common obfuscator signatures, per-SDK quirks.

---

## 11. AI integration opportunities (local, reasoning-first)

The mission asks AI to **reason, not summarize**. Concrete local-model roles, each with *why / how / context in / output out*:

1. **Grammar-constrained enumeration** — *Why:* small models drift on format. *How:* GBNF from `output_schema()`; the model can only emit valid records. *In:* manifest JSON + jadx component list. *Out:* structured exported-component/deep-link records. (Deterministic tools do extraction; AI classifies exploitability.)
2. **Flow tracing over an index** — *Why:* whole-APK doesn't fit context. *How:* ReAct loop with `jadx get_class_source`/`search_method_by_name`/smali tools + a local embedding index; the model *navigates* rather than ingests. *In:* one entrypoint. *Out:* ordered `flow_trace` to a sink.
3. **Vulnerability adjudication with falsification** — reuse the built-in prompts' "second-pass falsification" discipline: the model must try to *disprove* reachability before asserting a finding. *Out:* finding + `trigger_flow` + `adb`/intent repro.
4. **Dynamic hypothesis → Frida script synthesis** — *Why:* turn a static hypothesis into a runtime test. *How:* model writes a Frida hook (from a skill library of patterns), engine runs it on the locked device, hook-hit JSON is fed back for the model to confirm/deny. *This is the reasoning loop that static-only tools can't do.*
5. **Static↔dynamic correlation** — a `consume_all` synthesis step reasons over (static finding set ∪ runtime evidence set) to produce confirmed, ranked, deduped findings.
6. **Cross-version diff reasoning** (the `patched_since` analog) — decompile two APK versions, diff, ask the model "what changed security-wise / was my finding fixed / what new surface appeared."
7. **Report authorship** — larger model writes the MASVS-aligned client deliverable from the structured evidence, via the existing post-script/`_reserved_report` path.
8. **Self-extending playbooks** — `generation.py` lets the local model draft new Android workflows/post-scripts from a sentence.

---

## 12. UX improvements

- **APK dropzone + device panel** as the two primary entry points (replace the git-URL-first `CreateScan`). A device panel shows connected `adb devices`, root/Frida status, and a "acquire for scan" lock button.
- **Unified evidence timeline** on the finding page: static locus (smali/java + line) ↔ runtime evidence (logcat, Frida hit, screenshot) side by side. Extend `VulnerabilityPage.jsx`.
- **Manifest/attack-surface visual map** — components, exported flags, deep links, permissions as an interactive graph (the workflow builder already proves you can ship rich React views).
- **Live decompile/scan progress** via the existing `executor-view` and `ScanDetail` live model.
- **Kill the multi-account/provider UI**; replace `Accounts.jsx` with a **local model manager** (GGUF picker, quant, context, GPU layers, "load/unload", VRAM gauge).
- **One-click PoC replay** — re-run a stored `adb`/Frida PoC against the current device from the finding page.

---

## 13. Automation opportunities

- **Folder-watch ingestion** (mirror `LOCAL_REPOS_PATH` bind mount): drop an APK → auto-decompile → auto-run the default Android workflow → ranked findings, unattended.
- **One APK → full lifecycle**: static pass → install on locked device → dynamic confirmation pass → correlated report, as a single chained "meta-workflow."
- **Batch corpora**: point at a folder of APKs (e.g., a bounty program's app family) and fan the same workflow across all — the queue engine already supports this scale.
- **Regression/monitoring**: re-scan on new APK version, auto-diff, alert on new surface or regressed fix (the `patched_since` pattern, retargeted).
- **Device provisioning automation**: auto-push frida-server matching device arch, auto-install/uninstall target, auto-reset app state between runs.

---

## 14. Security improvements

- **Native-Windows means you own the sandbox tradeoff.** For bug-bounty/pentest (non-malware) targets you can drop Docker-per-job and run the local harness directly for speed and device/GPU access. **But** keep an *opt-in* isolation mode (Windows Sandbox / a Linux VM / WSL2) for any untrusted or suspected-malicious APK — one boolean per Target.
- **Treat the target app's data as untrusted** throughout prompts (the codebase already does this well — `repeat_append_prompt` and `patched_since` explicitly label tool data as untrusted; keep that discipline for decompiled strings and runtime output, which are attacker-controlled).
- **Device hygiene**: a dedicated research phone, app-state reset between runs, and a clear boundary so a malicious app can't pivot to the host over ADB.
- **Secret handling**: findings will surface real secrets from real apps — store them encrypted at rest and redact in any exported report unless explicitly included.
- **Local-only is itself the biggest security win**: no client app bytes or findings leave the machine (satisfies pentest NDAs and bounty program rules).

---

## 15. Performance improvements

- **Decompile cache keyed by `apk_sha256`** (reuse the checkout-cache machinery) — never decompile the same APK twice.
- **Persistent local code index** (symbols + embeddings) per APK so flow-tracing steps navigate instead of re-reading.
- **llama-server tuning**: keep the model resident (avoid reload per job), size context to the 16 GB budget, use grammar to cut ret/­reroll cost, batch small enumeration prompts.
- **Deterministic-first**: let tools (jadx MCP, apktool, regex secret scanners, `dumpsys`) do extraction; spend scarce GPU tokens only on *reasoning*. This is the single biggest speed/quality lever on a single-GPU box.
- **Two-tier routing** (small fast / large synthesis) keeps throughput up while preserving depth where it matters.
- **Serialize device work, parallelize static work** — static steps are CPU-bound and fan out well; dynamic steps bottleneck on the one phone and must queue.

---

## Phase 0 — COMPLETED (2026-07-22)

Branch `feat/android-local-phase0`. Engine now boots natively on Windows, fully offline, against Dockerized Postgres, with zero cloud credentials.

**Changes made:**
- `engine/open_kritt_engine/oslock.py` (new) — cross-platform `flock` shim (POSIX `fcntl` / Windows `msvcrt`). `import fcntl` swapped to `from . import oslock as fcntl` in `prompting.py`, `repository.py`, `workspace.py` (the only Windows import blockers).
- `worker.py::main()` — added `_scan_sandbox_mode()` (`ENGINE_SCAN_SANDBOX=native|docker`); native mode skips `validate_scan_runner_configuration()` (Docker requirement) and the startup `cleanup_stale_scan_sandboxes()`. Added `_log_local_llm_status()` non-fatal health check against `ENGINE_LLM_BASE_URL`.
- `.env.native` (new) — native-Windows engine config.
- `scripts/start-llm.ps1` (new) — wraps the exact llama-server launch command.
- `scripts/start-engine.ps1` (new) — loads `.env.native`, runs the engine from `engine/.venv`; `-Once` for a smoke boot.

**Key Windows gotcha found & fixed:** connecting to `localhost:5432` took ~8s (Windows tries IPv6 `::1` first, which the Docker `127.0.0.1`-published port ignores). Using `127.0.0.1` → 0.04s. `.env.native` uses `127.0.0.1` for both Postgres and the llama endpoint.

**How to run (Phase 0):**
```powershell
docker compose up -d db                 # Postgres with full schema (auto-initialized)
python -m venv engine\.venv ; engine\.venv\Scripts\pip install -r engine\requirements.txt
.\scripts\start-llm.ps1                  # (optional for idle boot) start the local model
.\scripts\start-engine.ps1               # run the engine natively; -Once for a 10s smoke test
```

**Verified:** engine imports on Windows; `oslock` acquires/releases via msvcrt; Postgres schema present (all `public` + `workflows` tables, 6 seeded post-scripts, 30 agent skills); engine boots → native mode → DB connected → workers + generation worker started → idles with no errors.

**Known non-blocking:** 35 engine unit tests fail on Windows (symlink privilege, Unix perm bits, `os.getuid`, git remote history, Docker/codex homes). These exercise cloud/Docker/POSIX paths the local build replaces (Phase 2 workspace swap) or gates off; consistent with AGENTS.md (engine tests disabled in CI). Not caused by Phase 0 changes — no failure references the lock shim, and all core modules import.

---

## Phase 1 — COMPLETED (2026-07-22)

The keystone: a local agentic harness on llama-server, live-verified against the operator's model (`gemma-4-26B-A4B` on the RTX 5080).

**Changes made:**
- `engine/open_kritt_engine/local_harness.py` (new) — `LocalHarness` implementing the harness interface. Components:
  - `LocalLLMClient` — dependency-free OpenAI-compatible client (`/chat/completions`) over stdlib `urllib`; **single-flight `_LLM_SLOT` semaphore** honoring `--parallel 1`; passes the step schema as `response_format: json_schema` (+ llama.cpp-native `json_schema`) so the final answer is grammar-constrained; strips `$schema`; captures `reasoning_content` separately.
  - `WorkspaceTools` — read-only, path-sandboxed `read_file` / `list_dir` / `head` / `grep` confined to the workspace root (escape attempts raise).
  - ReAct loop — controller turns are grammar-constrained to a tool-selection schema (`thought` + `tool` enum + `arguments`); on `finish`, a final schema-constrained turn yields the structured answer.
  - `_reconcile_output()` — enforces the engine's stub/results invariant a JSON schema can't express (results are the source of truth; derive `stub`, clamp single-output cardinality). Needed because small models emit structurally-valid but cross-field-invalid output.
- `harnesses.py` — `harness_for` returns `LocalHarness` for `local`; `normalize_harness_name` maps `llama`/`llamacpp`/`local-llm`/… → `local`.
- `worker.py` — health check reworded to a calm INFO + a background `local-llm-watcher` thread that logs once the endpoint comes up (start-order no longer matters; not an error).
- `engine/tests/test_local_harness.py` (new) — 13 tests: sandbox, escape-block, lenient JSON, schema sanitize, stub reconciliation, a **mock-client full `run()` loop**, and an **opt-in live test** (`ENGINE_LLM_LIVE_TEST=1`).

**Verified:** all 13 tests pass, including live inference. The live model ran the agent loop, correctly identified a hardcoded secret in a sample `smali/Main.smali`, and produced a payload that passes the engine's own `validate_payload`. First live run exposed (and the harness now fixes) a small-model tendency to misread `stub` — reconciliation + a sharper contract prompt resolve it.

**Live-test knob:**
```powershell
.\scripts\start-llm.ps1        # start the model
$env:ENGINE_LLM_LIVE_TEST="1"; $env:ENGINE_LLM_BASE_URL="http://127.0.0.1:8005/v1"
engine\.venv\Scripts\python -m pytest engine\tests\test_local_harness.py -v
```

**Deliberately deferred to Phase 2:** a full worker-orchestrated scan (DB scan row → queue → `execute_job` → store → dedup → rank) needs the input/workspace layer, which is git/POSIX-oriented and slated for replacement by APK ingestion. Forcing a git-repo scan through it on Windows now would fight code Phase 2 replaces. The harness itself is proven against the live model, so that boundary is clean.

---

## Phase 2 — COMPLETED (2026-07-22)

The input layer is now APK-native and a real APK scan runs end-to-end through the engine to ranked findings, fully local.

**Changes made:**
- `engine/open_kritt_engine/apk_workspace.py` (new) — `prepare_apk_workspace()` returning a `DependencyWorkspace` (drop-in for the git path). Pipeline cached by `apk_sha256`: **jadx** (Java + decoded manifest + resources), **apktool** (smali, best-effort), **zipfile** (native libs/assets), and manifest intelligence via ElementTree + aapt2 → `WORKSPACE.json` (package, exported/implicitly-exported components, deep links, permissions, custom permissions, `debuggable`/`allowBackup`/`usesCleartextTraffic`, SDK levels, native ABIs). Tools auto-discovered (jadx/apktool/aapt2/JAVA_HOME), env-overridable.
- `worker.py::execute_job` + `_ensure_scan_cache_prewarmed`, `post_processing.py::_prepare_workspace` — branch on `repo_kind=='apk'` to use `prepare_apk_workspace` and skip the git checkout/prewarm.
- `workspace.py::_job_identity` — Windows-safe (no `os.getuid` when POSIX ids are absent).
- `local_harness.py` — final-answer token budget raised to 8192 + length-aware retry; `_reconcile_output` already enforces stub/results; **investigation floor** (`ENGINE_LOCAL_MIN_TOOL_STEPS`, default 4) so the small model can't "finish" before reading code.
- `scripts/kritt_android.py` (new) — interim CLI to seed an Android workflow and queue APK scans directly (until the backend/UI expose `local`+`apk`). `.env.native` gains JAVA_HOME + jadx/apktool paths + tool-step caps.

**Verified end-to-end on InsecureShop (`com.insecureshop`, pulled from the connected device):**
- Decompilation in ~16s; manifest intel extracted correctly (8 exported/implicitly-exported components incl. an exported ContentProvider + UploadService, the `insecureshop://` deep link → WebViewActivity, debuggable/allowBackup/cleartext flags).
- A **direct** harness run over the decompiled tree found 3 real vulns (ContentProvider, WebView deep link, manifest misconfig) with accurate `adb` PoCs in ~149s.
- A **full engine-orchestrated scan** (queued → running → step → post_processing) stored **3 findings, ranked 1/2/3**, each with an `adb` PoC — fully local, no cloud.

**Key lessons captured:**
- A single "triage the whole app" step is the wrong shape for a small model (it stubbed twice). Grounding the prompt in the deterministic `WORKSPACE.json` manifest intel (report each true security flag / exported component, then deepen with code) made findings reliable. The **correct production design is the engine's fan-out**: enumerate exported components (deterministic) → investigate each individually (narrow tasks the small model handles well) — a Phase 2.x refinement.
- Post-processing dedupe is slow on the local single-slot model (minutes for a few findings); worth a lighter local dedupe strategy later.

**Known / next:**
- Backend/UI still don't expose `local` harness + `apk` targets (interim: `scripts/kritt_android.py`). Wiring the APK dropzone + device-app picker (device is reachable via `adb`, already validated) is the remaining Phase 2 UI work.
- Convert `APK Security Triage` (single-pass) into the fan-out `Android Attack Surface` workflow for consistent yield and per-component depth.

---

## Phase 3 — Dynamic subsystem, first increment (2026-07-22)

Static leads are now confirmed at runtime on the connected rooted device. Verified live on the Galaxy S20 (SM-G985F, Android 13, arm64, Magisk root).

**Changes made:**
- `engine/open_kritt_engine/adb.py` (new) — ADB service: device discovery, a global **device lock** (the one phone is a shared resource), root via Magisk `su -c`, and ops: `shell`, `getprop`, `list_packages`/`package_paths`, `pull`, `am_start` (intent/deep-link launch), `content_query`, `dumpsys`, `logcat`, `screencap`, `force_stop`, `current_focus`.
- `engine/open_kritt_engine/frida_service.py` (new) — ensure the matching frida-server (via `su`), spawn/attach a package, inject a script, capture messages as evidence; a small script library (probe, crypto tap, SSL probe). `frida==16.7.19` pinned (16.x keeps the `Java` bridge; 17 removed it).
- `engine/open_kritt_engine/dynamic_confirm.py` (new) — the static→dynamic loop: `confirm_exported_activity` / `confirm_deep_link` / `confirm_content_provider` / `confirm_findings`, each returning structured `Evidence` (`confirmed` | `guarded` | `refuted` | `error`) with artifacts (screenshots).
- `requirements.txt` — `frida==16.7.19`.

**Verified live (InsecureShop, driven from Phase-2 manifest intel):**
- 5 exported activities (Chooser/AboutUs/ProductList/WebView/WebView2) → **CONFIRMED** launchable via `am start`.
- Deep link `insecureshop://` → **CONFIRMED** reaches `WebViewActivity`.
- Exported `InsecureShopProvider` → **GUARDED** (`SecurityException: Permission Denial` from an unprivileged caller) — a real severity refinement static analysis alone would miss.
- Screenshot evidence captured on confirmed launches.

**Important lessons / caveats:**
- **ADB confirmation is the reliable core.** It talks to ActivityManager and Just Works — high-value for confirming exported components, deep links, and providers.
- **Frida on this device needs the operator's proper server setup.** My `su -c` launch of frida-server hit two issues: (1) Frida 17 dropped the `Java` bridge (switched to 16.7.19), and (2) frida-server couldn't resolve `system_server` and **spawn-gating crashed `system_server`** (device auto-recovered via the Android watchdog in ~5s). This is a known Magisk/Android-13 SELinux-context issue; the user's normal Frida method (e.g. MagiskFrida / correct context, likely `setenforce 0` or a magisk module) avoids it. I did **not** modify SELinux enforcement autonomously. Frida hooking is deferred to "attach after the operator starts frida-server the usual way", and prefer **attach-after-launch over spawn** to avoid destabilizing the runtime.

### Phase 3.x — static↔dynamic correlation (done, verified)

- `database/init/025_dynamic_evidence.sql` — `workflows.dynamic_evidence` (scan_id, vulnerability_id, check_kind, target, outcome, detail, artifacts, device_serial). Applied.
- `scripts/kritt_android.py confirm <scan_id>` — loads the scan's static manifest intel (from the decompiled `WORKSPACE.json`), runs the runtime confirmation for every exported activity / deep link / content-provider lead, persists `Evidence` rows, and inserts each confirmed/guarded lead as a `vulnerability` row (json `source:"dynamic"`, `dynamic_outcome`) so it shows in the UI. Idempotent. (Also fixed a `create_scan` bug that stored `commit_sha="workspace"` instead of the apk sha256.)
- **Verified in the UI on scan 1:** 12 findings (3 static + 9 dynamic), 10 exploitable — 6 exported activities + the deep link **confirmed** at runtime, both content providers **guarded** (permission denial). Static findings and runtime-confirmed attack surface now appear together in one scan.

### Phase 3.x — specialist vulnerability agents (done, verified) — THE quality fix

Feedback: "exported" is a *lead*, not a finding; the tool must use a specialist agent to determine false-positive vs. exploitable and name the *actual* vulnerability. Built:

- `engine/open_kritt_engine/specialist_agent.py` — per-class specialist agents. Each takes a surface lead, runs a ReAct loop with **code tools (read/grep the decompiled source) + device tools + a dynamic proof** (`network_callback_test`: `adb reverse` + a host callback listener + a crafted deep link; if the device fetches the callback, external attacker-controlled URL load is *proven*). Output is an adjudicated finding: `is_vulnerable`, `false_positive`, precise `vulnerability_type`/`title`/`impact`, `exploitable_externally`, static + dynamic evidence, `poc`, `confidence`.
- `scripts/kritt_android.py investigate <scan_id> [--max N]` — builds leads from the manifest intel, runs the specialist per lead, and stores **only real, adjudicated vulnerabilities** (false positives dropped).
- Robustness lessons baked in: show enough of the observation to get past jadx's huge `@Metadata` boilerplate (the vulnerable `onCreate` sits past a 4k cutoff), detect repeated identical tool calls to break loops, and require a dynamic proof before finishing; final-answer length-retry.

**Verified live on InsecureShop** — the WebView specialist read `WebViewActivity.java`, ran `network_callback_test("insecureshop://com.insecureshop/web?url=CALLBACK")` → **FETCHED**, and produced: *"Arbitrary URL Load via Deep Link — WebViewActivity passes the `url` deep-link parameter to `loadUrl` without validation; an external app can open an attacker-controlled URL"*, exploitable=true, high confidence, with a copy-paste `am start` PoC. It also proved the `/webview` path's `endsWith("insecureshopapp.com")` allowlist is bypassable via a `#insecureshopapp.com` fragment. Both WebView activities now appear in the UI as precise, proven findings (scan 1: 3 static + 2 specialist).

### Phase 3.x — specialist library + exploit-chaining analyst (done, verified)

- `specialist_agent.py` expanded to a library: **webview/deep-link, content-provider (SQLi/path-traversal), intent-redirection / PendingIntent, crypto, insecure-storage, generic-component**. New device tools: `content_query`, `read_app_file` / `list_app_files` (read the target app's private data dir via root — proves stored secrets), `am_start_component` (crafted extras for intent-injection tests). Findings now carry `severity_score` (0-10) and a `chainable_primitive`.
- **Chain analyst** (`chain_analyst`) — reasons over the confirmed findings' primitives to find higher-severity chains, verifies links with tools, and emits chains with ordered steps, combined impact, `severity_score`, feasibility, and a PoC. `scripts/kritt_android.py investigate` runs specialists → chain analyst → **re-ranks all findings by severity** (chains first).
- **Critical lesson — reasoning vs. structured output.** With `--reasoning on`, the model spent its whole token budget *thinking* and emitted **empty** grammar-constrained content (`finish_reason: length`), so structured finals silently failed (storage/crypto "unparseable", 0 chains) even though the reasoning was correct. Fix: `LocalLLMClient.chat(no_think=True)` sends `chat_template_kwargs={"enable_thinking": false}` for final structured calls, so the model emits the JSON directly. Applied to every specialist/chain final answer.
- **Verified on InsecureShop:** the chain analyst chained a score-7 WebView arbitrary-URL bug + a score-4 cleartext-SharedPreferences bug into a **score-9 "Exfiltration of Cleartext Auth Tokens via WebView File Access → Full Account Takeover"**, with the exact `file://` steps (enabled by `setAllowUniversalAccessFromFileURLs(true)`) and a working `exploit.html` + `am start` PoC.

**Still next:**
- A finding-detail timeline that shows the raw `dynamic_evidence` (device response, screenshot) next to the static locus.
- Assign the dynamic pass a severity ranker and **re-rank by outcome** (confirmed > guarded).
- Make dynamic confirmation an engine post-processing phase (not just the CLI), and expose `adb_*`/`frida_run` as harness tools so the local agent drives it.
- Traffic interception (proxy/TLS) — the originally-deferred later phase.

---

### Phase 3.x — reliability, engine integration, emulator (done)

- **Reliability — deterministic evidence pre-gathering.** `investigate_lead` now runs a class-specific `_pregather_evidence` BEFORE the agent (storage → `list_app_files`/`read_app_file` of shared_prefs+databases; content_provider → `content_query` of the authority and traversal sub-paths; webview → `network_callback_test`) and injects the concrete results as authoritative facts. A small model then *interprets facts* instead of having to discover them. Verified: the storage specialist now reliably confirms the cleartext-prefs finding (was run-to-run flaky before).
- **Engine integration.** New `engine/open_kritt_engine/dynamic_investigation.py` (`run_for_scan` / `build_leads` / `maybe_run_after_scan`) is the single implementation of the specialist+chain+rerank phase. `worker.py` calls `_maybe_dynamic_investigation()` after a scan completes — gated by `ENGINE_DYNAMIC_INVESTIGATION=1`, APK scans only, requires an adb device, runs at most once (marker in `scans.reasoning`), fully best-effort. An APK scan can now run static → dynamic specialists → chaining → ranking automatically.
- **Emulator support.** Physical device removed; switched to an Android Studio AVD (`Pixel_6_Pro`, x86_64, **adb root**). ADB service made root-adaptive: `Device.is_adb_root()` / `ensure_root()` skip `su` when adbd is already root (emulators), and `get_device()` auto-`adb root`s emulators. Device proofs re-verified on the emulator (WebView callback fetch, prefs read, storage specialist).
- **Resource caveat:** the x86_64 emulator + the 13 GB `--no-mmap` model + Docker strain 32 GB RAM — the Postgres container and llama-server were OOM-killed during heavy runs. Mitigations: drop `--no-mmap`, give the AVD less RAM, or use a smaller model while emulating. Restart: `docker start open-kritt-db`, `scripts/start-llm.ps1`.
### Phase 3.x — more specialists + finding timeline (done)

- **Two more specialists.** `pending_intent` (mutable/implicit PendingIntent hijack, aware of targetSdk default mutability) and `race_condition` (TOCTOU, unsynchronised shared state written from exported/async contexts, world-readable temp files, result-delivery races). Eight specialists total; `pick_specialist` routes `pending`→pending_intent and `race`/`toctou`→race_condition. `build_leads` adds app-wide PendingIntent + race leads (in both the engine module and CLI).
- **Finding-detail timeline (done).** Findings now store structured evidence in `json_answer` (`static_evidence`, `dynamic_evidence`, `poc`, `chainable_primitive`, `severity_score`; chains carry `chain_steps`, `components_involved`, `combined_impact`, `feasibility`). `VulnerabilityPage.jsx` renders a **Dynamic analysis** timeline (reusing the attack-path dot/line pattern): specialist findings show STATIC → DYNAMIC PROOF → POC stages beside the `file:line` locus; chains show the ordered exploit STEP 1..N; both with severity/confidence/feasibility/primitive chips. No backend change needed (`serializeVulnerability` already passes the full `jsonAnswer`). Verified in the UI on the chain (score 9, steps 1-6) and the WebView specialist (static/dynamic/poc).
- **Frontend HMR caveat:** vite's file watcher does not see edits through the OneDrive→Docker bind mount; frontend changes need `docker restart open-kritt-frontend` to load.

### Phase 3.x — real vulnerable code in the UI + static-only mode (done)

- **Real vulnerable code, not just a filename.** The finding schema gained `code_file` + `code_evidence`. Each specialist quotes the vulnerable lines, and the engine then **deterministically re-extracts the ACTUAL lines** from the decompiled file (`_extract_real_code`: finds the model's quoted line in the source and returns ±5 lines with real line numbers) so the UI shows genuine app code, never a paraphrase. `VulnerabilityPage.jsx` renders a red-bordered **VULNERABLE CODE — <file>** block in the Dynamic-analysis section. Verified: e.g. `UploadNotificationConfig.java:141 PendingIntent.getBroadcast(context,0,new Intent(),134217728)` and `Prefs.java:99 sharedPreferences.edit().putString("password", str)`.
- **Static-only mode.** `investigate_lead` / `chain_analyst` / `run_for_scan` accept `static_only`; `SpecialistTools` exposes code-only tools (no device), pre-gathering switches to `_pregather_static` (component source + a class-specific sink grep), the prompt sets STATIC-ONLY MODE and `dynamic_evidence="not tested (static-only analysis)"`, and no adb device is required. CLI: `kritt_android.py investigate <scan> --static`.
- **Verified static-only run on InsecureShop (no device):** 4 specialist findings each with real `code_evidence` + a score-10 chain — including the new **PendingIntent Hijack** (mutable implicit PendingIntent) and the real **credential-in-cleartext** sink (`putString("password", …)`), all found from code alone.

### Phase 3.x — complete specialist library (16 specialists)

Every Android component type now has a dedicated specialist, plus every vuln class discussed:
- **Component types:** `exported_activity` (intent injection / task hijack / setResult leak), `exported_service` (onStartCommand/onBind/AIDL/Messenger abuse), `broadcast_receiver` (forged-broadcast injection / unprotected dynamic receivers / broadcast sniffing), `content_provider` (SQLi / path traversal / data exposure).
- **Vuln classes:** `webview` (deep-link URL load / JS bridge / file access), `intent_redirection`, `pending_intent`, `crypto`, `storage`, `secrets` (hardcoded keys/creds in code/resources/BuildConfig/assets), `network_security` (cleartext / TrustManager / HostnameVerifier / onReceivedSslError / pinning / network_security_config), `permissions` (custom-permission protectionLevel, re-delegation / confused deputy), `logging` (sensitive data in Log/print), `sql_injection` (raw concatenated queries), `race_condition` (TOCTOU / unsynchronised exported-async state), plus `generic`.
- `pick_specialist` routes by vuln-class keyword then component `kind`; `_STATIC_SINKS` has a grep pattern per class for static pre-gathering; `build_leads` emits one lead per exported component (routed to its type specialist) + the app-wide class leads. InsecureShop → 18 leads. All 16 route-tested.

---

## 16. Prioritized implementation roadmap

Each phase is independently valuable and leaves a working platform.

### Phase 0 — Foundation & fork hygiene (fast)
- Fork privately; collapse the 24 migrations into a clean baseline; strip cloud-provider/account/codex/claude-auth/updater code paths behind a feature flag (don't delete yet).
- Stand up **llama-server** on the 5080; confirm OpenAI-compatible endpoint + GBNF grammar from a sample `output_schema()`.
- Make the engine run **natively on Windows** (Python venv), Postgres via Docker only. Add a Windows path shim for workspace/home handling.
- **Exit criterion:** engine boots on Windows, talks to Postgres, no cloud dependency required to start.

### Phase 1 — Local agentic harness (keystone)
- Implement `LocalAgenticHarness` satisfying `run(prompt, schema, repo_dir, …) -> HarnessResult`: ReAct loop against llama-server, tool-calling, **GBNF-constrained final JSON**, usage/token accounting into the existing metadata.
- Tools v1 (filesystem over a workspace): `read_file`, `list_dir`, `grep`, `head`.
- Register it in `harness_for`; add a "local" model provider; simplify model selection to GGUF files.
- **Exit criterion:** an existing (repo-based) workflow runs end-to-end **fully offline** and produces valid, stored, ranked findings.

### Phase 2 — Static Android pipeline (first real Android value)
- `Target` abstraction + `prepare_apk_workspace` (jadx + apktool + native extract + decoded manifest + `workspace_manifest_json`), cached by `apk_sha256`.
- Wire the **jadx-analyzer MCP** as the harness's primary code-query tool set.
- Ship the **Android static workflow seeds** + output schemas + Android severity/bounty rankers (§10).
- APK dropzone + folder-watch ingestion; findings visible in the existing UI.
- **Exit criterion:** drop an APK → get ranked, evidence-backed static findings with smali/java loci, unattended.

### Phase 3 — Dynamic subsystem (Frida-first)
- Device model + **device lock**; ADB service (install/launch/logcat/pull/`am`/`content`/`dumpsys`); Frida session manager (auto-push server, spawn-gate attach, script library).
- New harness tools: `adb_*`, `frida_run(script)`; runtime-evidence store; static↔dynamic correlation tables.
- **Dynamic-confirmation workflow**: statically-found leads → Frida/adb verification → confirmed findings.
- **Exit criterion:** a static "exported component / deep link / pinning" lead is *automatically confirmed at runtime* on the rooted phone with captured evidence.

### Phase 4 — Correlation, PoC & reporting (pentest deliverable)
- `consume_all` synthesis step correlating static + dynamic into a single ranked, deduped finding set.
- Android post-scripts: generate runnable `adb`/Frida PoC + captured repro + MASVS-aligned report section (via `_reserved_poc`/`_reserved_report`).
- Unified evidence-timeline finding UI; one-click PoC replay.
- **Exit criterion:** one APK + device → a client-ready, reproducible, MASVS-mapped report generated locally.

### Phase 5 — Force multipliers
- Cross-version APK diffing (the `patched_since` analog); batch corpora scanning; regression monitoring on new versions.
- Local RAG index for large APKs; two-tier model routing; self-extending Android playbooks via `generation.py`.
- Native `.so` triage (radare2/ghidra headless) as a harness tool; SBOM + known-vuln SDK matching.
- Optional opt-in isolation mode for untrusted APKs.

---

## Confirmed decisions (2026-07-22)

1. **APK sourcing — both.** UI offers (a) select an installed app from the connected device (with full device connect/disconnect lifecycle management), and (b) drop an APK file. Device selection uses `pm list packages` + `pm path` + `adb pull`.
2. **Report format — free-form, basic, readable.** A human-readable investigation writeup the researcher takes forward manually. No MASVS template requirement.
3. **Local model — single multimodal MoE, kept as-is.** Launch command (authoritative):
   ```
   llama-server.exe -m gemma-4-26B-A4B-it-UD-IQ4_NL.gguf --mmproj mmproj-F16.gguf \
     --host 0.0.0.0 --port 8005 --ctx-size 61440 --n-gpu-layers -1 --alias local \
     --no-mmap --flash-attn on --reasoning on --parallel 1 --cache-type-v q8_0 --cache-type-k q8_0
   ```
   Implications: OpenAI-compatible endpoint at `http://localhost:8005/v1`, alias `local`, **60K context**, **single inference slot (`--parallel 1`)** → gate all model calls through one LLM semaphore; **multimodal (`--mmproj`)** → feed device screenshots as a native evidence channel; **`--reasoning on`** → separate/store the reasoning trace; ~4B active params → deterministic-tools-first, model-for-reasoning-only.
4. **Frida — root frida-server only.** No non-root gadget fallback.
5. **Isolation — native-by-default.** Engine runs directly on Windows (no per-job Docker sandbox); a per-target "untrusted" toggle to run decompilation inside WSL/VM can come later. Justified: static analysis only reads files; dynamic analysis executes on the phone, not the host; targets are authorized bug-bounty/pentest apps, not malware.

### Vision (multimodal) usage plan
- Dynamic evidence: `adb exec-out screencap -p` → base64 → model, to interpret rendered UI state, confirm PoCs visually, and read WebView content.
- Guide intent/deep-link fuzzing by what is actually on screen after an `am start`.
- Optional static: render layout XML previews or icon/asset inspection.
