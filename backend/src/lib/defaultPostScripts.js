// Default post-scripts for the two device-verifying mobile research flows. A post-script is
// a per-finding follow-up prompt: for every confirmed finding the engine runs it once, with
// the finding's fields interpolated into {{...}}, and stores the structured output alongside
// the finding. These two turn a confirmed finding into an actionable exploit / report.
//
// Seeded idempotently at backend startup (server.js), the same way default severity rankers
// and workflows are. They are ordinary post-scripts afterwards (editable, deletable); the
// Android pentest / Samsung tabs simply pre-select the matching one as their default.
import { prisma } from '../db.js';

export const ANDROID_RESEARCH_POST_SCRIPT_NAME = 'Android exploit PoC & remediation';
export const SAMSUNG_RESEARCH_POST_SCRIPT_NAME = 'Samsung bug-bounty writeup';

export const MOBILE_RESEARCH_POST_SCRIPTS = [
  {
    name: ANDROID_RESEARCH_POST_SCRIPT_NAME,
    description:
      'Turns a confirmed Android finding into a runnable PoC, ordered exploit steps, attacker impact, CVSS and a concrete fix.',
    content:
      'You are documenting a CONFIRMED Android finding from the on-device exploit-research workflow so a developer can ' +
      'reproduce and fix it. Do not re-judge whether the bug is real; assume it is and make it actionable.\n\n' +
      'Finding: "{{summary}}" — a {{vulnerability_type}} in component {{component}} at {{file_path}}:{{line}}.\n' +
      'Technical detail: {{explanation}}\n' +
      'Vulnerable code (verbatim): {{code_evidence}}\n' +
      'Observed proof-of-concept trigger, if any: {{adb_poc}}\n' +
      'Exploitable on a default install: {{exploitable}}\n\n' +
      'Produce:\n' +
      '- poc_command: a single, concrete, copy-pasteable trigger a tester runs against a default install — a real adb/am ' +
      'command, deep link, malicious-app intent with real extras, provider URI, or Frida one-liner. Use the ACTUAL ' +
      'component/authority/action/scheme from the finding, never a placeholder or prose.\n' +
      '- exploit_steps: an ordered list of the exact steps to reproduce it end to end (setup, any runtime-guard bypass ' +
      'such as SSL unpinning or root-detection defeat, trigger, and how to observe success).\n' +
      '- attacker_impact: what a malicious app or actor concretely gains (the data read/written, the action taken, the ' +
      'boundary crossed) — be specific, not generic.\n' +
      '- prerequisites: what the attacker needs (another installed app, adb, a granted URI, user interaction, none).\n' +
      '- cvss_vector: a CVSS v3.1 base vector reflecting real reachability.\n' +
      '- severity: Critical | High | Medium | Low | Info, consistent with the vector.\n' +
      '- remediation: the smallest safe code/config fix that closes THIS flow (e.g. add a caller/permission check, ' +
      'validate the input, disable the bridge, set exported=false), referencing the real component/file.',
    outputFormat: {
      poc_command: 'string',
      exploit_steps: 'array',
      attacker_impact: 'string',
      prerequisites: 'string',
      cvss_vector: 'string',
      severity: 'string',
      remediation: 'string',
    },
  },
  {
    name: SAMSUNG_RESEARCH_POST_SCRIPT_NAME,
    description:
      'Drafts a Samsung Mobile Security Rewards (SVE) style report for a confirmed system-app finding: repro, impact, severity, fix.',
    content:
      'You are drafting a vulnerability report for the Samsung Mobile Security Rewards Program (SVE) from a CONFIRMED ' +
      'finding in a Samsung pre-installed / system app. Assume the finding is real; produce a submission-quality writeup.\n\n' +
      'Finding: "{{summary}}" — a {{vulnerability_type}} in component {{component}} at {{file_path}}:{{line}}.\n' +
      'Technical detail: {{explanation}}\n' +
      'Vulnerable code (verbatim): {{code_evidence}}\n' +
      'Observed proof-of-concept trigger, if any: {{adb_poc}}\n' +
      'Exploitable by an unprivileged caller on a default device: {{exploitable}}\n\n' +
      'The central Samsung question is the PRIVILEGE BOUNDARY: can an unprivileged third-party app or a physically ' +
      'present actor reach a privileged/system action here, and is the caller check missing or a custom permission ' +
      'downgraded? Ground the whole report in that.\n\n' +
      'Produce:\n' +
      '- title: a concise report title naming the affected Samsung package and the bug class.\n' +
      '- affected_package: the com.samsung.* / com.sec.* package (and component) affected.\n' +
      '- attack_prerequisites: exactly what the attacker needs (an unprivileged installed app, physical access, a ' +
      'specific permission the app wrongly exposes, user interaction, none) and the privilege boundary crossed.\n' +
      '- reproduction_steps: an ordered, unambiguous list a Samsung triager can follow on a retail device — including a ' +
      'real trigger (malicious-app intent with actual extras, adb/am command, deep link, or provider URI, never a ' +
      'placeholder) and how to confirm success.\n' +
      '- impact: what an unprivileged attacker gains (system capability, cross-app/system data, account/Pay/Knox reach) ' +
      'and why it matters on a default Samsung device.\n' +
      '- severity: Critical | High | Medium | Low, justified by unprivileged reachability and the boundary crossed.\n' +
      '- remediation: the concrete fix (enforce a caller signature/permission check, raise a downgraded custom ' +
      "permission to signature, set exported=false, validate input) referencing the real component.\n" +
      '- report_markdown: the full report assembled as clean markdown (Summary, Affected Package, Prerequisites, ' +
      'Reproduction, Impact, Severity, Remediation) ready to paste into a Samsung SVE submission.',
    outputFormat: {
      title: 'string',
      affected_package: 'string',
      attack_prerequisites: 'string',
      reproduction_steps: 'array',
      impact: 'string',
      severity: 'string',
      remediation: 'string',
      report_markdown: 'string',
    },
  },
];

export const MOBILE_RESEARCH_POST_SCRIPT_NAMES = MOBILE_RESEARCH_POST_SCRIPTS.map((ps) => ps.name);

// Idempotent: create each research post-script only if a post-script of that name is absent.
// Never edits or deletes an existing one (a user may have customised it).
export async function ensureMobileResearchPostScripts(client = prisma) {
  return client.$transaction(async (tx) => {
    await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext('open-kritt-mobile-research-post-scripts'))`;

    const installed = [];
    for (const ps of MOBILE_RESEARCH_POST_SCRIPTS) {
      const existing = await tx.postScript.findFirst({
        where: { name: ps.name },
        orderBy: { insertedAt: 'asc' },
        select: { id: true },
      });
      if (existing) continue;
      await tx.postScript.create({
        data: {
          name: ps.name,
          description: ps.description,
          content: ps.content,
          outputFormat: JSON.stringify(ps.outputFormat),
        },
      });
      installed.push(ps.name);
    }
    return installed;
  });
}
