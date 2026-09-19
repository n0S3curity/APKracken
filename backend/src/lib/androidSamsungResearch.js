// "Samsung System-App Research" — a multi-depth DAG specialized for finding bugs in Samsung's
// pre-installed / default apps (com.samsung.* / com.sec.*) and their custom framework surface
// (custom permissions, Knox, Samsung system services/AIDL, Samsung deep links). Same shape and
// device machinery as the generic dynamic-exploit workflow, but every step is written for the
// Samsung ecosystem, and the engine attaches the samsung-* agent skills to the scan.
//
//   depth 0     Samsung recon: exported components, custom-permission guards, providers, AIDL services, schemes
//   depth 1     Trace: attacker input -> privileged Samsung sink
//   depth 2     Caller verification & guards: signature/permission/caller checks (and bypassability)
//   depth 3     Hypothesize: the concrete trigger from an UNPRIVILEGED third-party app
//   depth 4     Reproduce on device            [REQUIRES_DEVICE]
//   depth 5     Bypass & re-verify on device   [REQUIRES_DEVICE]
//   depth 6     Confirm & report (verdict + PoC, terminal)
//
// Depths 4-5 need a connected rooted Samsung device (the default apps live there). Without one
// they reproduce nothing (never fabricate), same guard as the generic workflow.
import { prisma } from '../db.js';

export const SAMSUNG_RESEARCH_WORKFLOW_NAME = 'Samsung System-App Research';

const DEV = '[[REQUIRES_DEVICE]] ';
const DEVICE_TOOLS_NOTE =
  ' A rooted device is connected (authorized target). Device tools: launch_app, launch_deeplink{uri}, ' +
  'am_start_component{component,extras}, tap{x,y}, input_text{text}, keyevent{key}, content_query{uri}, ' +
  'read_app_file{path}, list_app_files{sub}, logcat, frida_bypass{kinds:[ssl_unpin,anti_detect]}, ' +
  'screenshot{label}. Every device action captures a screenshot whose observation returns the saved path — ' +
  'copy those paths verbatim into screenshots. Drive the attack from an UNPRIVILEGED caller (adb / a plain app), ' +
  'never from a system context. One tool per turn.';

const CARRY = { component: 'string', file_path: 'string', line: 'number' };

const STEPS = [
  {
    name: 'Samsung recon - system components & guards', depth: 0, isLast: false, table: 'workflows.step_results',
    content:
      'You are mapping the attack surface of the Samsung system app {{repo_full}} (com.samsung.* / com.sec.*). ' +
      'WORKSPACE.json has the manifest intelligence. Enumerate each entry a third-party (unprivileged) app on the ' +
      'same device can reach: exported (or intent-filter-implicit) Activities/Services/Receivers; exported/grantUri ' +
      'ContentProviders (by authority); AIDL/bound services; Samsung deep-link schemes/hosts (samsung://, ' +
      'samsungapps://, members://, bixby://, smartthings://, shealth://, sbrowser intent://). For EACH, record its ' +
      'guard: the android:permission and, if any, that permission\'s protectionLevel (normal/dangerous/signature) and ' +
      'who defines it. Note whether the app is system/priv-app. A Samsung system component reachable by a normal app ' +
      'and guarded weakly (or not at all) is the lead. One record per entry; stub if none are third-party-reachable.',
    schema: {
      component: 'string', entry_kind: 'string', exported: 'boolean', authority: 'string',
      guard_permission: 'string', guard_level: 'string', deep_link: 'string', controlled_input: 'string',
      file_path: 'string', line: 'number', reachability_evidence: 'string',
    },
  },
  {
    name: 'Trace - input to privileged Samsung sink', depth: 1, isLast: false, table: 'workflows.step_results',
    content:
      'Trace one Samsung entry in {{repo_full}}: {{component}} (kind={{entry_kind}}, exported={{exported}}, ' +
      'guard={{guard_permission}}/{{guard_level}}, authority={{authority}}, deep_link={{deep_link}}) at ' +
      '{{file_path}}:{{line}}; input {{controlled_input}}. Read the handler and trace the caller-controlled input to a ' +
      'PRIVILEGED sink the Samsung app can reach with its system/signature privileges: a settings/secure-settings ' +
      'write, another component started with attacker extras, a WebView.loadUrl with a JS bridge, a provider ' +
      'openFile/SQL, an AIDL method performing a system op, a returned token/PII (setResult), Runtime.exec, or a Knox/' +
      'account/pay operation. Give an ordered flow_trace of "path:line symbol - behavior" hops and the terminal_sink. ' +
      'Map accurately; do not judge exploitability yet. Stub if no privileged sink is reachable. ITERATIVE DEEPENING: work this ONE unit like an expert deep dive, not a glance. HYPOTHESISE then TEST against the code with your tools; FOLLOW EVERY LEAD recursively - when the flow calls another method/component/provider/native function, read it and chase the attacker-controlled data across files and layers to its real sink. A missing check, a reachable sink, or a controllable value is a thread to PULL: ask what it enables and what else it unlocks, then keep pulling until you have proven a concrete path or genuinely exhausted this unit. On later research passes, treat earlier findings shown to you as LEADS - go one hop deeper, build chains from confirmed primitives, and return only genuinely NEW or DEEPER results.',
    schema: {
      ...CARRY, flow_summary: 'string', flow_trace: 'array', terminal_sink: 'string', input_to_sink: 'string',
      guard_permission: 'string', guard_level: 'string', security_relevance: 'string',
    },
  },
  {
    name: 'Caller verification & guards', depth: 2, isLast: false, table: 'workflows.step_results',
    content:
      'Assess whether an UNPRIVILEGED app can actually reach the sink of one Samsung flow in {{repo_full}} ' +
      '({{flow_summary}}; sink {{terminal_sink}} <- {{input_to_sink}}; declared guard {{guard_permission}} ' +
      '[{{guard_level}}]). Read the code for REAL caller verification, which Samsung apps often assume rather than ' +
      'enforce: checkCallingPermission / enforceCallingPermission, Binder.getCallingUid()/getCallingPid() signature ' +
      'checks, PackageManager signature comparison, or a protectionLevel=signature permission. Decide: does a caller ' +
      'check hold, or is it MISSING/bypassable (declared permission is normal/dangerous so grantable; permission ' +
      'defined elsewhere; check only on one branch; relies on a spoofable extra)? State exactly what an unprivileged ' +
      'app must hold or do to reach the sink.',
    schema: {
      ...CARRY, flow_summary: 'string', terminal_sink: 'string', input_to_sink: 'string',
      caller_check: 'string', reachable_by_unprivileged: 'boolean', bypass_needed: 'string',
    },
  },
  {
    name: 'Hypothesize - third-party trigger', depth: 3, isLast: false, table: 'workflows.step_results',
    content:
      'Design how a plain third-party app (or adb, as a stand-in for one) triggers one Samsung flow in {{repo_full}} ' +
      '({{flow_summary}}; sink {{terminal_sink}}; reachable_by_unprivileged={{reachable_by_unprivileged}}; ' +
      'bypass_needed={{bypass_needed}}). Give the exact ordered device_actions: an `am start`/`am startservice`/' +
      '`am broadcast` on the exported component with crafted extras, a `content query/call/read` on the provider, a ' +
      'crafted Samsung deep link, or a bindService+AIDL call. Give the minimal malicious_input and the precise ' +
      'expected_observable that PROVES the privileged effect (a setting changed, private data returned, file read, ' +
      'action performed). If it needs a signature permission an attacker cannot get, set device_reproducible=false ' +
      'with the reason.',
    schema: {
      ...CARRY, flow_summary: 'string', device_reproducible: 'boolean', device_actions: 'array',
      malicious_input: 'string', expected_observable: 'string', needs_bypass: 'boolean', bypass_kinds: 'array',
      skip_reason: 'string',
    },
  },
  {
    name: 'Reproduce on device', depth: 4, isLast: false, table: 'workflows.step_results',
    content: DEV +
      'REPRODUCE one Samsung hypothesis on the device for {{repo_full}}. Flow: {{flow_summary}}. Plan: ' +
      '{{device_actions}}. Malicious input: {{malicious_input}}. Expected: {{expected_observable}}. The target ' +
      'Samsung app is already installed on the device as a system app - do NOT try to install it. Drive the plan as ' +
      'an unprivileged caller (adb `am`/`content`, deep link), screenshotting after each action, and observe whether ' +
      'the expected_observable occurs. Do NOT apply bypasses here; if a permission/caller check blocks you, set ' +
      'blocked=true with block_reason. Copy every returned screenshot path into screenshots.' + DEVICE_TOOLS_NOTE,
    schema: {
      ...CARRY, flow_summary: 'string', expected_observable: 'string', needs_bypass: 'boolean',
      bypass_kinds: 'array', reproduced: 'boolean', observed: 'string', blocked: 'boolean',
      block_reason: 'string', screenshots: 'array',
    },
  },
  {
    name: 'Bypass & re-verify on device', depth: 5, isLast: false, table: 'workflows.step_results',
    content: DEV +
      'Re-attempt one Samsung flow on the device for {{repo_full}} ({{flow_summary}}) that did not yet clearly ' +
      'succeed. Earlier: reproduced={{reproduced}}, blocked={{blocked}} ({{block_reason}}); observed {{observed}}. ' +
      'Most Samsung IPC bugs need no runtime bypass - if it is already reproduced, confirm once more with a ' +
      'screenshot and return reproduced_after_bypass=true, bypasses_used=[]. Only if a TLS-pinning or ' +
      'root/emulator/debug check blocks the path, call frida_bypass with the right kinds ({{bypass_kinds}}), then ' +
      're-run and screenshot. Record which bypasses_used (if any) let it through, the final observed impact, and the ' +
      'expected_observable it was compared against.' + DEVICE_TOOLS_NOTE,
    schema: {
      ...CARRY, flow_summary: 'string', expected_observable: 'string', reproduced_after_bypass: 'boolean',
      bypasses_used: 'array', observed: 'string', screenshots: 'array',
    },
  },
  {
    name: 'Confirm & report - verdict + evidence', depth: 6, isLast: true, table: 'workflows.vulnerabilities',
    content:
      'Deliver the final verdict for one investigated Samsung flow in {{repo_full}} ({{flow_summary}} at ' +
      '{{file_path}}:{{line}}), STRICTLY from what happened on the device: reproduced_after_bypass=' +
      '{{reproduced_after_bypass}} (bypasses {{bypasses_used}}); observed {{observed}}; expected ' +
      '{{expected_observable}}; screenshots {{screenshots}}. Set exploitable=true AND dynamic_verified=true ONLY if a ' +
      'screenshot/observation concretely showed the privileged effect reachable by an unprivileged caller - otherwise ' +
      'both false. Give severity_score 0-10 (weigh system privilege + no user interaction + data sensitivity), ' +
      'confidence, ordered reproduction_steps, the impact statement, the exact dynamic_screenshots paths, ' +
      'dynamic_bypasses used, a runnable poc (adb/intent/AIDL), and remediation. A flow not reproduced on the device ' +
      'must NOT be exploitable. Stub if nothing was proven.',
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
        content: s.content, outputFormat: JSON.stringify(s.schema), name: s.name,
        depth: s.depth, multiOutput: true, isLastStep: s.isLast, outputTable: s.table,
      },
    });
    ids.push(created.id);
  }
  return ids;
}

// The samsung-* agent skills to attach to every Samsung-research scan, so the tool-using agent
// gets the Samsung-specific hunting guidance injected on top of the specialized step prompts.
export async function samsungAgentSkillIds() {
  const rows = await prisma.agentSkill.findMany({ where: { slug: { startsWith: 'samsung-' } }, select: { id: true } });
  return rows.map((r) => r.id);
}

export async function ensureSamsungResearchWorkflow() {
  const existing = await prisma.workflow.findFirst({ where: { name: SAMSUNG_RESEARCH_WORKFLOW_NAME } });
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
      name: SAMSUNG_RESEARCH_WORKFLOW_NAME,
      description:
        'Autonomous research on Samsung pre-installed / default apps (com.samsung.* / com.sec.*) and their custom ' +
        'framework surface: recon exported system components and their custom-permission guards, providers, AIDL ' +
        'services and Samsung deep links; trace attacker input to a privileged Samsung sink; assess real caller ' +
        'verification; hypothesize the unprivileged-app trigger; reproduce it on a rooted Samsung device with ' +
        'screenshots; bypass any TLS/anti-analysis guard; and confirm + report only what was reproduced on-device, ' +
        'with a runnable PoC and remediation. The samsung-* agent skills are attached automatically. Depths 4-5 ' +
        'require a connected rooted Samsung device (that is where the default apps live).',
      extra: [],
    },
  });
}
