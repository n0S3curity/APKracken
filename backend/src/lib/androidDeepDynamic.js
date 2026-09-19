// The "Android Deep Research + Dynamic" workflow — the layered pipeline the engine runs
// end-to-end in its post-scan investigation phase (see engine dynamic_investigation
// .run_deep_dynamic_for_scan). Unlike the DAG-based "Android Deep Research", this one is
// built on the PROVEN specialist machinery and is staged into three visible phases:
//
//   Phase 1 — Mobile PT triage:  the per-component + app-wide specialists (static), plus
//             the deterministic checks (hardcoded secrets, over-broad FileProvider).
//   Phase 2 — Deep research:     the exploit-chain analyst + a deeper, background-seeded
//             re-investigation of the highest-value findings (human-like iterative dig).
//   Phase 3 — Dynamic verify:    for the top high-severity findings, a live on-device
//             confirmation (ADB/Frida) that attaches DETAILED dynamic evidence — only when
//             a device/emulator is connected; otherwise those findings are marked
//             "static-only (no device connected)".
//
// The base workflow step below is intentionally a thin static triage (identical in spirit
// to "APK Security Triage") so the scan itself completes quickly and the heavy, staged work
// happens in the engine phase, where progress + detailed evidence are fully controlled.
import { prisma } from '../db.js';

export const ANDROID_DEEP_DYNAMIC_WORKFLOW_NAME = 'Android Deep Research + Dynamic';

const BASE_PROMPT =
  'You are a mobile penetration tester doing a first-pass triage of the decompiled Android app {{repo_full}}. ' +
  'The Workspace context and WORKSPACE.json above contain authoritative manifest intelligence (exported ' +
  'components, deep links, provider authorities, permissions, and security flags such as debuggable / ' +
  'allowBackup / usesCleartextTraffic).\n\n' +
  'That manifest intelligence is your ATTACK SURFACE MAP, not a list of findings. An exported component, a ' +
  'deep link, or an enabled security flag is NOT by itself a vulnerability - never report one as a finding.\n\n' +
  'Report a finding only where you have READ the decompiled code (jadx/sources/) and can show ' +
  'attacker-controlled input reaching a security-sensitive operation (insecure WebView / deep links, ' +
  'hardcoded secrets, insecure storage, weak crypto, exported ContentProvider injection or path traversal). ' +
  'Give code_evidence as the EXACT vulnerable lines copied VERBATIM from the file, the real file_path and ' +
  'line, a severity_score 0-10, a confidence of high/medium/low, and a concrete adb/intent PoC - never prose. ' +
  'Set exploitable true only when the actor can trigger it on a default install.\n\n' +
  'This is only the opening pass - the engine then runs the full specialist, exploit-chain, deep-research, ' +
  'and on-device verification phases, and it grounds every citation you give against the real source. A ' +
  'finding whose quoted code is not in the file it cites is discarded, so never invent one. Return a stub ' +
  'when nothing is supported by code evidence.';

// severity_score / confidence / code_evidence feed the engine's evidence grounding and the
// false-positive adjudicator (which selects targets by numeric severity). Omitting them scored
// every base finding 0 and excluded it from verification entirely.
const BASE_FINDING_FIELDS = {
  summary: 'string',
  vulnerability_type: 'string',
  component: 'string',
  file_path: 'string',
  line: 'number',
  explanation: 'string',
  attack_vector: 'string',
  code_evidence: 'string',
  adb_poc: 'string',
  severity: 'string',
  severity_score: 'number',
  confidence: 'string',
  exploitable: 'boolean',
};

export async function ensureAndroidDeepDynamicWorkflow() {
  const existing = await prisma.workflow.findFirst({
    where: { name: ANDROID_DEEP_DYNAMIC_WORKFLOW_NAME },
  });
  if (existing) {
    // Keep a previously seeded copy in step with the prompt/schema above; a stale one silently
    // disables the evidence + false-positive machinery that depends on the newer fields.
    const stepId = (existing.stepIds || [])[0];
    if (stepId) {
      await prisma.step.update({
        where: { id: stepId },
        data: { content: BASE_PROMPT, outputFormat: JSON.stringify(BASE_FINDING_FIELDS) },
      });
    }
    return existing;
  }
  const step = await prisma.step.create({
    data: {
      content: BASE_PROMPT,
      outputFormat: JSON.stringify(BASE_FINDING_FIELDS),
      name: 'Android deep+dynamic base triage',
      depth: 0,
      multiOutput: true,
      isLastStep: true,
      outputTable: 'workflows.vulnerabilities',
    },
  });
  return prisma.workflow.create({
    data: {
      stepIds: [step.id],
      name: ANDROID_DEEP_DYNAMIC_WORKFLOW_NAME,
      description:
        'Layered Android pipeline built on the specialist machinery, staged into three phases the engine runs after ' +
        'the base pass: (1) Mobile PT triage — every component + app-wide specialist (static) plus deterministic ' +
        'secret/FileProvider checks; (2) Deep research — the exploit-chain analyst plus a deeper, background-seeded ' +
        're-investigation of the highest-value findings; (3) Dynamic verification — a live on-device (ADB/Frida) ' +
        'confirmation of the top high-severity findings that attaches detailed dynamic evidence (falls back to ' +
        'static-only when no device is connected). Findings render with vulnerable code, full PoC, and the on-device ' +
        'proof on the finding page.',
      extra: [],
    },
  });
}
