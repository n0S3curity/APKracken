// The "Android Deep Research" workflow — a staged research DAG modeled on the
// external-flow-analysis (map → trace → investigate) and Cosmos ABCI (rigor: analysis
// method, verify-every-check, falsification, exclusions) reference workflows, specialized
// for Android APKs. Seeded once; selectable per APK scan so it can be A/B-compared against
// the default single-pass "APK Security Triage".
import { prisma } from '../db.js';

export const ANDROID_DEEP_WORKFLOW_NAME = 'Android Deep Research';

// --- Stage 0: map the externally reachable Android attack surface --------------------
const STEP_MAP_SCHEMA = {
  entry_kind: 'string',
  component: 'string',
  exported: 'boolean',
  authority: 'string',
  actor: 'string',
  controlled_input: 'string',
  file_path: 'string',
  line: 'number',
  reachability_evidence: 'string',
  exclusions_checked: 'array',
};

const STEP_MAP_PROMPT = `You are a mobile security researcher mapping the externally reachable attack surface of the Android app {{repo_full}}. The Workspace context and WORKSPACE.json above give the decompiled sources (jadx/sources/) and authoritative manifest intelligence (exported components, deep links, provider authorities, permissions, security flags).

Find every distinct production entrypoint through which an actor OUTSIDE the app can cause it to receive or process input. Consider: exported Activities/Services/Receivers, deep links (scheme + host), exported or grantUriPermissions ContentProviders (by authority), custom-permission-guarded components, PendingIntents handed to other apps, WebView JavaScript bridges (@JavascriptInterface), AIDL/Messenger IPC, dynamically-registered BroadcastReceivers, FileProvider grants, and native entrypoints (System.loadLibrary + native methods).

For every entrypoint:
- Name the component/class and the concrete ingress (intent-filter action/scheme, provider authority, exported flag, JS-bridge method).
- State the external ACTOR that can reach it (another installed app, adb, a remote deep link, web content inside a WebView) and the INPUT they control.
- Give the exact jadx source path and line of the handler (onCreate/onNewIntent/onStartCommand/onReceive/query/@JavascriptInterface method) or its manifest registration.
- Set exported (true/false from the manifest) and, for providers, authority.
- reachability_evidence: prove reachability from the manifest + code, not from names or comments.

Exclude bundled third-party SDKs (androidx, com.google.*, firebase, okhttp, squareup, ...), test/debug-only code, and components with no external actor; record what you excluded in exclusions_checked. Do not merge distinct components into one record. Return a stub when no externally reachable entrypoint can be established.`;

// --- Stage 1: trace reachable production flows (no vuln claims yet) -------------------
const STEP_TRACE_SCHEMA = {
  flow_summary: 'string',
  flow_trace: 'array',
  terminal_sink: 'string',
  input_to_sink: 'string',
  security_relevance: 'string',
  file_path: 'string',
  line: 'number',
};

const STEP_TRACE_PROMPT = `You are tracing production execution flows from ONE externally reachable Android entrypoint in {{repo_full}}.

Entrypoint:
- kind: {{entry_kind}}
- component: {{component}}  (exported={{exported}}, authority={{authority}})
- external actor: {{actor}}
- controlled input: {{controlled_input}}
- location: {{file_path}}:{{line}}
- reachability: {{reachability_evidence}}

Read the component's decompiled source and trace every materially distinct flow the external actor can drive from this entrypoint through production code to a security-sensitive SINK. Sinks include: WebView.loadUrl / addJavascriptInterface / setAllowUniversalAccessFromFileURLs, SQL (rawQuery/execSQL/query selection built by concatenation), file open (openFile / File / FileInputStream / path traversal), Cipher / crypto, a re-dispatched Intent (startActivity/sendBroadcast/startService with attacker data), Runtime.exec, network calls, SharedPreferences writes of secrets, and JNI/native calls (native methods).

For each flow:
- flow_summary: what it does and where it ends.
- flow_trace: ordered array of hops, each "path:line symbol - behavior" (parse extras/query args, validation, dispatch, the sink).
- terminal_sink: the sink reached; input_to_sink: the attacker-controlled value as it arrives at that sink.
- security_relevance: why this flow deserves review.

Separate paths whose validation, authorization, data handling, or consequences differ; do not create records for cosmetic helpers. Do NOT report vulnerabilities yet — this stage is an accurate flow map only. Exclude impossible, test-only, and dead paths. Return a stub when no reachable flow exists.`;

// --- Stage 2: investigate each flow for a concrete, high-value vulnerability ----------
const STEP_INVESTIGATE_SCHEMA = {
  summary: 'string',
  vulnerability_type: 'string',
  file_path: 'string',
  line: 'number',
  explanation: 'string',
  trigger_flow: 'array',
  malicious_input_example: 'string',
  malicious_actor: 'string',
  exploitable: 'boolean',
  severity_score: 'number',
  confidence: 'string',
  exported: 'boolean',
  reachability: 'string',
  authorities: 'string',
  code_evidence: 'string',
  poc: 'string',
};

const STEP_INVESTIGATE_PROMPT = `You are a mobile penetration tester investigating ONE externally reachable Android flow in {{repo_full}} for a concrete, high-value vulnerability.

Entrypoint: {{component}} (exported={{exported}}, authority={{authority}}), actor {{actor}}, controlled input {{controlled_input}}, at {{file_path}}:{{line}}.
Flow under review:
- summary: {{flow_summary}}
- trace: {{flow_trace}}
- terminal sink: {{terminal_sink}}
- input to sink: {{input_to_sink}}
- security relevance: {{security_relevance}}

Analysis method:
1. Read the exact vulnerable code for this flow (jadx/sources/), the sink, and every guard between ingress and sink.
2. Verify every check: state what each validation / allowlist / permission / bounds check actually proves, then compare it with what the sink assumes. Test bypass: subdomain / @ / # tricks on URL allowlists, string concatenation in SQL, path traversal (../) into openFile, missing FLAG_IMMUTABLE on a PendingIntent, an extra_intent redirected to a non-exported component, normalization mismatches, missing null/length checks.
3. Name the malicious actor and the exact input they control, and rebuild the end-to-end trigger from attacker ingress to the sink.
4. Deliberate falsification: try to disprove reachability and impact. If the component is NOT exported, the bug is exploitable only via a chain (a content:// URI grant or intent redirection from another component) — say so and set reachability to "chained"; if exported, "direct". Missing evidence is uncertainty, not proof of safety or exploitability.
5. Exclude: style issues, hypotheticals, test/debug-only behavior, bundled third-party SDK code, and anything needing unsupported configuration.

Report a finding ONLY if it is concrete, reachable from the stated actor, and supported by code evidence:
- severity_score: 0-10 CVSS-like (weigh exported/direct vs chain-only, data sensitivity, whether user interaction is needed).
- exported / reachability ("direct" | "chained" | "internal") / authorities: from the manifest.
- code_evidence: the EXACT vulnerable lines copied VERBATIM from the file (the sink call and its context) — never a paraphrase.
- poc: a concrete adb command using the REAL component/authority/action/scheme (e.g. adb shell am start -n pkg/.Comp --es key val, adb shell content query --uri content://authority/...), OR a minimal malicious-app Java/Kotlin snippet — NEVER prose.
- trigger_flow: ordered attacker-ingress-to-sink hops (path:line symbol).
- exploitable: true only when the actor can realistically trigger it in the configured production path.
Return a stub when the flow contains no supported vulnerability — never invent a finding.`;

// --- Native branch (depth 0, terminal): research the bundled .so / JNI libraries -----
const STEP_NATIVE_SCHEMA = {
  summary: 'string',
  vulnerability_type: 'string',
  file_path: 'string',
  line: 'number',
  explanation: 'string',
  trigger_flow: 'array',
  malicious_input_example: 'string',
  malicious_actor: 'string',
  exploitable: 'boolean',
  severity_score: 'number',
  confidence: 'string',
  reachability: 'string',
  code_evidence: 'string',
  poc: 'string',
};

const STEP_NATIVE_PROMPT = `You are a native-library (.so / JNI) security researcher analyzing the Android app {{repo_full}}. The app bundles native code under unpacked/lib/<abi>/*.so.

TOOLS: list_native_libs (see the .so files); native_recon{path} — for one .so returns its JNI exports (Java_* = the native surface reachable from Java), imported functions with DANGEROUS ones flagged (system/exec/popen = command injection; strcpy/strcat/sprintf/memcpy/gets = buffer overflow; dlopen/mprotect = code loading; GetByteArrayElements/GetStringUTFChars = unchecked JNI input), and interesting strings (hardcoded keys/URLs/commands/format strings); native_disasm{path,symbol} — disassemble one function to inspect it.

Analysis method:
1. Run list_native_libs, then native_recon on each app-owned .so (prefer arm64-v8a; skip obvious third-party SDK libs like libsqlite/libflutter/libreactnativejni unless the app clearly drives them with attacker data).
2. For each JNI export, grep jadx/sources for the matching \`native\` method declaration, the System.loadLibrary call, and the Java class that declares it; determine whether that Java class is reachable from an EXPORTED or otherwise attacker-reachable component (cross-layer reachability).
3. Hunt: command injection (attacker string reaching system/exec/popen), buffer/stack overflow (attacker-sized data into strcpy/memcpy/sprintf without a bounds check), integer overflow feeding an allocation/copy, format-string (%s/%n reaching printf), unchecked GetByteArrayElements/GetStringUTFChars length, insecure crypto / hardcoded keys in the .so.
4. Verify with native_disasm: confirm the dangerous import is actually called on attacker-controlled data with no dominating length/validation guard. Distinguish a real reachable bug from a benign internal use.
5. Deliberate falsification: prove the end-to-end path Java entrypoint → native method (JNI) → dangerous sink. If you cannot demonstrate attacker reachability, treat it as a false positive / honest low-confidence uncertainty, not a finding.

Report each concrete native vulnerability:
- file_path: the .so path (unpacked/lib/<abi>/libX.so); code_evidence: the JNI export + the flagged dangerous import (and the disasm snippet you relied on).
- trigger_flow: ordered CROSS-LAYER hops (Java entrypoint → JNI method → native sink).
- malicious_input_example / poc: the malicious app or adb call that reaches the JNI method with the crafted input — concrete, never prose.
- severity_score 0-10 (CVSS-like), confidence, reachability ("direct" | "chained" | "internal"), exploitable (true only when reachable from an external actor).
Return a stub when the app bundles no native library or no supported native vulnerability is verified — never invent one.`;

// Appended to every step so it behaves like a human doing an iterative deep dive across
// research passes (the workflow is looped via configuration.repeat_runs).
const DEEP_RESEARCH_LOOP = `

Work like a human security researcher doing an ITERATIVE DEEP DIVE — not a single shallow pass:
- HYPOTHESIZE then TEST: form a concrete idea of how this could be abused, then prove or refute it against the code with the tools.
- FOLLOW EVERY LEAD recursively: when the code calls another method, component, provider, ContentProvider, WebView, or native (JNI) function, follow it (read_file / grep / native_recon / native_disasm). Chase the attacker-controlled data from source to sink across files and layers — do not stop at the surface.
- DEEPEN partial results: a missing check, a reachable sink, or a controllable value is a thread to pull — ask what it actually enables and what ELSE it unlocks, then keep pulling.
- THINK IN CHAINS: when you confirm a primitive (control a URL, read a file, launch a component, reach a native buffer, leak a token), note what it can be combined with for a more severe outcome, and go find the other half.
- Keep looping (read → hypothesize → verify → follow the next lead) until you have proven a concrete exploit path or genuinely exhausted the reachable paths for this target. Never finish after a single observation.

This step runs across MULTIPLE RESEARCH PASSES. On later passes, the results of earlier passes are shown to you above — treat them as LEADS, not as finished work: chase what an earlier pass left uncertain or only partially traced, follow the next hop the prior findings imply, build attack chains from the confirmed primitives, and push the highest-value flows further toward a full exploit. Return only genuinely NEW or DEEPER results than the earlier passes; return a stub only when the reachable surface is truly exhausted.`;

async function createStep({ name, content, outputFormat, depth, isLast, outputTable }) {
  return prisma.step.create({
    data: {
      content,
      outputFormat: JSON.stringify(outputFormat),
      name,
      depth,
      multiOutput: true,
      isLastStep: isLast,
      outputTable,
    },
  });
}

export async function ensureAndroidDeepResearchWorkflow() {
  const existing = await prisma.workflow.findFirst({ where: { name: ANDROID_DEEP_WORKFLOW_NAME } });
  if (existing) return existing;

  const mapStep = await createStep({
    name: 'Map Android attack surface',
    content: STEP_MAP_PROMPT + DEEP_RESEARCH_LOOP,
    outputFormat: STEP_MAP_SCHEMA,
    depth: 0,
    isLast: false,
    outputTable: 'workflows.step_results',
  });
  // Native branch: an independent depth-0 terminal step that researches the .so/JNI
  // libraries directly to findings (it writes vulnerabilities, so it does not feed the
  // Java trace stage which consumes depth-0 step_results).
  const nativeStep = await createStep({
    name: 'Investigate native libraries (.so / JNI)',
    content: STEP_NATIVE_PROMPT + DEEP_RESEARCH_LOOP,
    outputFormat: STEP_NATIVE_SCHEMA,
    depth: 0,
    isLast: true,
    outputTable: 'workflows.vulnerabilities',
  });
  const traceStep = await createStep({
    name: 'Trace reachable flows',
    content: STEP_TRACE_PROMPT + DEEP_RESEARCH_LOOP,
    outputFormat: STEP_TRACE_SCHEMA,
    depth: 1,
    isLast: false,
    outputTable: 'workflows.step_results',
  });
  const investigateStep = await createStep({
    name: 'Investigate flow vulnerabilities',
    content: STEP_INVESTIGATE_PROMPT + DEEP_RESEARCH_LOOP,
    outputFormat: STEP_INVESTIGATE_SCHEMA,
    depth: 2,
    isLast: true,
    outputTable: 'workflows.vulnerabilities',
  });

  return prisma.workflow.create({
    data: {
      stepIds: [mapStep.id, nativeStep.id, traceStep.id, investigateStep.id],
      name: ANDROID_DEEP_WORKFLOW_NAME,
      description:
        'Deep multi-stage Android research: map the external attack surface, trace each reachable flow to its ' +
        'sink, then investigate each flow for concrete, code-evidenced vulnerabilities with a runnable PoC — plus a ' +
        'dedicated native (.so / JNI) branch that analyzes the bundled ELF libraries (JNI exports, dangerous imports, ' +
        'disassembly) for cross-layer Java→JNI→native bugs. Reachability-first, with verify-every-check + falsification ' +
        'rigor. (Experimental — compare vs APK Security Triage.)',
      extra: [],
    },
  });
}
