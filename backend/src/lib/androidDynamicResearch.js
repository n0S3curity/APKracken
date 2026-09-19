// "Android Dynamic Exploit Research" — a multi-depth DAG that walks a mobile research the way
// an expert would, one focused step per phase (narrow per-step objectives = more accurate
// output). It has a horizontal branch at depth 0 (a parallel native/JNI track) and a vertical
// chain that ends on-device:
//
//   depth 0  ├─ Recon: exported entrypoints ─────────────► (feeds the chain)
//            └─ Native/JNI recon & investigate ──────────► (terminal, writes findings)
//   depth 1     Trace: reachable flow to sink
//   depth 2     Guards: enumerate the defenses
//   depth 3     Bypass plan: how to defeat each guard
//   depth 4     Hypothesize: the concrete on-device trigger
//   depth 5     Reproduce on device            [REQUIRES_DEVICE]
//   depth 6     Bypass & re-verify on device   [REQUIRES_DEVICE]
//   depth 7     Confirm & report (verdict + PoC, terminal)
//
// Depths 5-6 are the only device steps; the engine's local harness exposes device + Frida +
// screenshot tools for them when a rooted device is connected, and hard-skips them (emitting
// nothing, never fabricating) when none is. Depth 7 judges from the captured device evidence.
import { prisma } from '../db.js';

export const ANDROID_DYNAMIC_RESEARCH_WORKFLOW_NAME = 'Android Dynamic Exploit Research';

const DEV = '[[REQUIRES_DEVICE]] ';
const DEVICE_TOOLS_NOTE =
  ' A rooted test device you control is connected (authorized target). Device tools: launch_app, ' +
  'launch_deeplink{uri}, am_start_component{component,extras}, tap{x,y}, input_text{text}, ' +
  'keyevent{key}, content_query{uri}, read_app_file{path}, list_app_files{sub}, logcat, ' +
  'frida_bypass{kinds:[ssl_unpin,anti_detect]}, screenshot{label}. Every device action captures a ' +
  'screenshot and its observation returns the saved path — copy those paths verbatim into ' +
  'screenshots. One tool per turn.';

// Identity fields carried forward so late depths still know what they are working on.
const CARRY = { component: 'string', file_path: 'string', line: 'number' };

const STEPS = [
  // ---- depth 0a: recon (feeds the chain) ----
  {
    name: 'Recon — exported entrypoints', depth: 0, isLast: false, table: 'workflows.step_results',
    content:
      'Map the externally reachable Java/Kotlin attack surface of {{repo_full}}. WORKSPACE.json has the ' +
      'authoritative manifest intelligence. Enumerate each distinct production entrypoint an outside actor can ' +
      'reach: exported Activities/Services/Receivers, deep links (scheme+host), exported/grantUriPermissions ' +
      'ContentProviders (by authority), WebView JavaScript bridges, PendingIntents, FileProvider grants. Prove ' +
      'reachability from manifest+code. One record per entrypoint; exclude bundled SDKs and test code. Stub if none.',
    schema: {
      component: 'string', entry_kind: 'string', exported: 'boolean', authority: 'string', deep_link: 'string',
      controlled_input: 'string', file_path: 'string', line: 'number', reachability_evidence: 'string',
    },
  },
  // ---- depth 0b: native/JNI (horizontal, terminal) ----
  {
    name: 'Native/JNI recon & investigate', depth: 0, isLast: true, table: 'workflows.vulnerabilities',
    content:
      'Analyze the bundled native libraries of {{repo_full}} (unpacked/lib/<abi>/*.so). Use list_native_libs, ' +
      'native_recon{path} (JNI exports, dangerous imports like system/exec/strcpy/memcpy, hardcoded strings), and ' +
      'native_disasm{path,symbol}. For each app-owned .so, find JNI-reachable dangerous sinks fed by attacker data ' +
      '(command injection, buffer overflow, format string, unchecked JNI input) and prove the cross-layer path ' +
      'Java entrypoint -> native method -> sink. Report only concrete, code-evidenced native vulnerabilities with a ' +
      'severity_score and confidence; copy the dangerous import/disasm as code_evidence. Stub if no app-owned native ' +
      'vulnerability is proven.',
    schema: {
      summary: 'string', vulnerability_type: 'string', component: 'string', file_path: 'string', line: 'number',
      code_evidence: 'string', explanation: 'string', severity_score: 'number', confidence: 'string',
      exploitable: 'boolean',
    },
  },
  // ---- depth 1: trace ----
  {
    name: 'Trace — reachable flow to sink', depth: 1, isLast: false, table: 'workflows.step_results',
    content:
      'Trace production flows from ONE entrypoint in {{repo_full}}: {{component}} (kind={{entry_kind}}, ' +
      'exported={{exported}}, authority={{authority}}, deep_link={{deep_link}}) at {{file_path}}:{{line}}; input ' +
      '{{controlled_input}}. Read the source and trace each materially distinct flow the actor can drive to a ' +
      'security-sensitive SINK (WebView.loadUrl/addJavascriptInterface, SQL, file open/traversal, Cipher, a ' +
      're-dispatched Intent, Runtime.exec, secret read/write, JNI). Give an ordered flow_trace of "path:line symbol - ' +
      'behavior" hops, the terminal_sink, and the input as it reaches the sink. Map accurately; do not judge exploitability yet. Stub if no reachable flow. ITERATIVE DEEPENING: work this ONE unit like an expert deep dive, not a glance. HYPOTHESISE then TEST against the code with your tools; FOLLOW EVERY LEAD recursively - when the flow calls another method/component/provider/native function, read it and chase the attacker-controlled data across files and layers to its real sink. A missing check, a reachable sink, or a controllable value is a thread to PULL: ask what it enables and what else it unlocks, then keep pulling until you have proven a concrete path or genuinely exhausted this unit. On later research passes, treat earlier findings shown to you as LEADS - go one hop deeper, build chains from confirmed primitives, and return only genuinely NEW or DEEPER results.',
    schema: {
      ...CARRY, flow_summary: 'string', flow_trace: 'array', terminal_sink: 'string', input_to_sink: 'string',
      security_relevance: 'string',
    },
  },
  // ---- depth 2: guards enumerate ----
  {
    name: 'Guards — enumerate defenses', depth: 2, isLast: false, table: 'workflows.step_results',
    content:
      'Read the code of one flow in {{repo_full}} ({{flow_summary}}; sink {{terminal_sink}} <- {{input_to_sink}}; ' +
      'focal {{file_path}}:{{line}}) and enumerate EVERY defense between ingress and sink: TLS certificate pinning, ' +
      'root/emulator/debugger detection, authentication/authorization checks, URL allowlists, input validation, ' +
      'signature checks. For each guard state what it proves and whether it HOLDS or is BYPASSABLE (and how). If ' +
      'there are none, say so. Carry the flow identity forward.',
    schema: {
      ...CARRY, flow_summary: 'string', terminal_sink: 'string', input_to_sink: 'string',
      guards: 'array', has_guards: 'boolean', guard_detail: 'string',
    },
  },
  // ---- depth 3: bypass plan ----
  {
    name: 'Bypass plan — defeat each guard', depth: 3, isLast: false, table: 'workflows.step_results',
    content:
      'Given the guards on one flow in {{repo_full}} ({{guards}}; detail: {{guard_detail}}), decide exactly how to ' +
      'defeat them at runtime so the flow can be exercised. Map each guard to the standard bypass: ssl_unpin for TLS ' +
      'pinning; anti_detect for root/emulator/debugger detection; note any app-specific client-side check that a ' +
      'crafted input alone defeats. Set needs_bypass and the concrete bypass_kinds to apply. Carry identity forward.',
    schema: {
      ...CARRY, flow_summary: 'string', terminal_sink: 'string', input_to_sink: 'string',
      needs_bypass: 'boolean', bypass_kinds: 'array', bypass_rationale: 'string',
    },
  },
  // ---- depth 4: hypothesize ----
  {
    name: 'Hypothesize — on-device trigger', depth: 4, isLast: false, table: 'workflows.step_results',
    content:
      'Design the concrete on-device trigger for one flow in {{repo_full}} ({{flow_summary}}; sink ' +
      '{{terminal_sink}} <- {{input_to_sink}}; needs_bypass={{needs_bypass}}, bypass_kinds={{bypass_kinds}}). Give the ' +
      'exact ordered device_actions (an adb/intent launch, a deep link with a crafted url= parameter, an exported ' +
      'component with malicious extras, a provider URI, or a UI tap/type sequence), a minimal malicious_input, and the ' +
      'precise expected_observable that would PROVE impact. If it cannot be shown on a device, set ' +
      'device_reproducible=false with a reason.',
    schema: {
      ...CARRY, flow_summary: 'string', device_reproducible: 'boolean', device_actions: 'array',
      malicious_input: 'string', expected_observable: 'string', needs_bypass: 'boolean', bypass_kinds: 'array',
      skip_reason: 'string',
    },
  },
  // ---- depth 5: reproduce on device ----
  {
    name: 'Reproduce — drive the device', depth: 5, isLast: false, table: 'workflows.step_results',
    content: DEV +
      'REPRODUCE one hypothesis on the device for {{repo_full}}. Flow: {{flow_summary}}. Plan: {{device_actions}}. ' +
      'Malicious input: {{malicious_input}}. Expected: {{expected_observable}}. launch_app first and screenshot the ' +
      'start, then execute the device_actions in order, screenshotting after each. Observe whether the ' +
      'expected_observable actually occurs. Do NOT apply bypasses here even if blocked — record what happened and set ' +
      'blocked=true with block_reason if a guard stopped you. Copy every returned screenshot path into screenshots.' +
      DEVICE_TOOLS_NOTE,
    schema: {
      ...CARRY, flow_summary: 'string', expected_observable: 'string', needs_bypass: 'boolean',
      bypass_kinds: 'array', reproduced: 'boolean', observed: 'string', blocked: 'boolean', block_reason: 'string',
      screenshots: 'array',
    },
  },
  // ---- depth 6: bypass & re-verify on device ----
  {
    name: 'Bypass & re-verify — defeat guards live', depth: 6, isLast: false, table: 'workflows.step_results',
    content: DEV +
      'Re-attempt one flow on the device for {{repo_full}} ({{flow_summary}}) that did not yet clearly succeed. ' +
      'Earlier: reproduced={{reproduced}}, blocked={{blocked}} ({{block_reason}}); observed {{observed}}. If it is ' +
      'already reproduced and unblocked, confirm once more with a screenshot and return reproduced_after_bypass=true, ' +
      'bypasses_used=[]. Otherwise call frida_bypass with the right kinds ({{bypass_kinds}}: ssl_unpin for TLS ' +
      'pinning, anti_detect for root/emulator/debug detection), then re-run the attack actions and screenshot the ' +
      'result. Record which bypasses_used actually let the attack through, the final observed impact, and the ' +
      'expected_observable it was compared against.' + DEVICE_TOOLS_NOTE,
    schema: {
      ...CARRY, flow_summary: 'string', expected_observable: 'string', reproduced_after_bypass: 'boolean',
      bypasses_used: 'array', observed: 'string', screenshots: 'array',
    },
  },
  // ---- depth 7: confirm & report (terminal) ----
  {
    name: 'Confirm & report — verdict + evidence', depth: 7, isLast: true, table: 'workflows.vulnerabilities',
    content:
      'Deliver the final verdict for one investigated flow in {{repo_full}} ({{flow_summary}} at ' +
      '{{file_path}}:{{line}}), STRICTLY from what happened on the device: reproduced_after_bypass=' +
      '{{reproduced_after_bypass}} (bypasses {{bypasses_used}}); observed {{observed}}; expected ' +
      '{{expected_observable}}; screenshots {{screenshots}}. Set exploitable=true AND dynamic_verified=true ONLY if a ' +
      'screenshot/observation concretely showed the expected impact on the device — otherwise both false. Give a ' +
      'severity_score 0-10, confidence, the ordered reproduction_steps a human could follow, the impact statement, the ' +
      'exact dynamic_screenshots paths (copy from screenshots), dynamic_bypasses used, a runnable poc, and a short ' +
      'remediation. A flow not reproduced on the device must NOT be exploitable. Stub if nothing was proven.',
    schema: {
      summary: 'string', vulnerability_type: 'string', component: 'string', file_path: 'string', line: 'number',
      severity_score: 'number', confidence: 'string', exploitable: 'boolean', dynamic_verified: 'boolean',
      impact: 'string', reproduction_steps: 'array', dynamic_screenshots: 'array', dynamic_bypasses: 'array',
      poc: 'string', remediation: 'string',
    },
  },
];

async function makeSteps() {
  const ids = [];
  for (const s of STEPS) {
    const created = await prisma.step.create({
      data: {
        content: s.content,
        outputFormat: JSON.stringify(s.schema),
        name: s.name,
        depth: s.depth,
        multiOutput: true,
        isLastStep: s.isLast,
        outputTable: s.table,
      },
    });
    ids.push(created.id);
  }
  return ids;
}

export async function ensureAndroidDynamicResearchWorkflow() {
  const existing = await prisma.workflow.findFirst({
    where: { name: ANDROID_DYNAMIC_RESEARCH_WORKFLOW_NAME },
  });
  if (existing) {
    if ((existing.stepIds || []).length !== STEPS.length) {
      const ids = await makeSteps();
      return prisma.workflow.update({ where: { id: existing.id }, data: { stepIds: ids } });
    }
    // Same shape: refresh each step's prompt/schema in place so edits to STEPS take effect
    // (the DAG structure is unchanged, so stepIds line up positionally).
    for (let i = 0; i < STEPS.length; i += 1) {
      await prisma.step.update({
        where: { id: existing.stepIds[i] },
        data: { content: STEPS[i].content, outputFormat: JSON.stringify(STEPS[i].schema), name: STEPS[i].name },
      });
    }
    return existing;
  }
  const ids = await makeSteps();
  return prisma.workflow.create({
    data: {
      stepIds: ids,
      name: ANDROID_DYNAMIC_RESEARCH_WORKFLOW_NAME,
      description:
        'Autonomous on-device exploit research as a multi-depth DAG modeled on an expert researcher, with a parallel ' +
        'native/JNI track: recon the surface, trace each flow to its sink, enumerate guards, plan bypasses, ' +
        'hypothesize the trigger, reproduce it on a rooted device with screenshots, defeat guards (TLS pinning, ' +
        'root/emulator/debug detection) with Frida and re-verify, then confirm and report — keeping only findings ' +
        'actually reproduced on the device, each with a screenshot walkthrough, applied bypasses, a runnable PoC, and ' +
        'remediation. Depths 5-6 require a connected rooted device; without one they reproduce nothing (never fabricate).',
      extra: [],
    },
  });
}
