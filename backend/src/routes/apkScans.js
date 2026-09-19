// APK scans: accept a dropped/selected .apk, save it to the host APK inbox (bind-mounted
// so the native engine can read it), and create a scan with sensible APK defaults. The
// default "APK Security Triage" workflow + local harness/model IS the default APK config;
// it is auto-created here if it does not already exist.
import { Router } from 'express';
import express from 'express';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { prisma } from '../db.js';
import {
  ANDROID_SEVERITY_RANKER_NAME,
  ensureDefaultSeverityRankers,
} from '../lib/defaultSeverityRankers.js';
import { ensureAndroidDeepResearchWorkflow } from '../lib/androidDeepResearch.js';
import { ensureAndroidDeepDynamicWorkflow } from '../lib/androidDeepDynamic.js';
import { ensureAndroidDynamicResearchWorkflow } from '../lib/androidDynamicResearch.js';
import { ensureSamsungResearchWorkflow, samsungAgentSkillIds } from '../lib/androidSamsungResearch.js';

const router = Router();
const INBOX = process.env.APK_INBOX_DIR || '/apk-inbox';
const INBOX_HOST = (process.env.APK_INBOX_HOST || INBOX).replace(/\\/g, '/');
const APK_WORKFLOW_NAME = 'APK Security Triage';

const TRIAGE_PROMPT =
  'You are a mobile penetration tester analyzing the decompiled Android app {{repo_full}}. ' +
  'The Workspace context and WORKSPACE.json above contain authoritative manifest intelligence ' +
  '(exported components, deep links, permissions, and security flags such as debuggable / allowBackup / ' +
  'usesCleartextTraffic).\n\n' +
  'Treat that manifest intelligence as your ATTACK SURFACE MAP, not as a list of findings. An exported ' +
  'component, a deep link, or an enabled security flag is NOT by itself a vulnerability - never report one ' +
  'as a finding on its own.\n\n' +
  'Report a finding only when you have READ the decompiled code (jadx/sources/) and can show ' +
  'attacker-controlled input reaching a security-sensitive operation: insecure WebView / deep-link handling, ' +
  'hardcoded production secrets, insecure storage, weak crypto, SQL or path injection through an exported ' +
  'ContentProvider, PendingIntent hijack, or an exported component taking a privileged action on attacker ' +
  'data.\n\n' +
  'For each finding:\n' +
  '- code_evidence: the EXACT vulnerable lines copied VERBATIM from the file - never a paraphrase and never ' +
  'invented. If you have not read the code, you do not have a finding.\n' +
  '- file_path + line: the real location of those exact lines.\n' +
  '- severity_score: 0-10 (CVSS-like), weighing whether the actor reaches it directly (exported) or only ' +
  'through a chain, and how sensitive the data is.\n' +
  '- confidence: \"high\" | \"medium\" | \"low\" - how sure you are the flow is real and reachable.\n' +
  '- adb_poc: a concrete adb/intent command using the REAL component/authority/action - never prose.\n' +
  '- exploitable: true only when that actor can realistically trigger it on a default install.\n\n' +
  'Before reporting, try to DISPROVE each finding: look for the guard, validation, permission, or signature ' +
  'check that would stop it, and drop the finding if one does. Missing evidence is uncertainty, not proof.\n' +
  'Return a stub when you cannot support a concrete finding with code evidence - never invent one.';

// severity_score / confidence / code_evidence are not cosmetic: the engine's false-positive
// adjudicator selects targets by numeric severity, and the evidence pass grounds code_evidence
// against the snapshot. Without these fields every finding scored 0 and was never checked.
const FINDING_FIELDS = {
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

async function ensureApkWorkflow() {
  const existing = await prisma.workflow.findFirst({ where: { name: APK_WORKFLOW_NAME } });
  if (existing) {
    // A workflow seeded by an older build keeps its old prompt and schema forever, which
    // silently disables the evidence + false-positive machinery that depends on the newer
    // fields. Keep the seeded copy in step with the definition above.
    const stepId = (existing.stepIds || [])[0];
    if (stepId) {
      await prisma.step.update({
        where: { id: stepId },
        data: { content: TRIAGE_PROMPT, outputFormat: JSON.stringify(FINDING_FIELDS) },
      });
    }
    return existing;
  }
  const step = await prisma.step.create({
    data: {
      content: TRIAGE_PROMPT,
      outputFormat: JSON.stringify(FINDING_FIELDS),
      name: 'APK security triage',
      depth: 0,
      multiOutput: true,
      isLastStep: true,
      outputTable: 'workflows.vulnerabilities',
    },
  });
  return prisma.workflow.create({
    data: {
      stepIds: [step.id],
      name: APK_WORKFLOW_NAME,
      description:
        'Default single-pass Android static triage over a decompiled APK. The engine then runs the ' +
        'specialist + exploit-chain investigation in the mode chosen at upload (static, or static+dynamic).',
      extra: [],
    },
  });
}

// Accepted Android package suffixes. .apk is a raw app; .xapk/.apks/.apkm are ZIP
// bundles (base + split APKs) the engine unwraps to the biggest APK before scanning.
const APK_SUFFIX_RE = /\.(apk|xapk|apks|apkm)$/i;

function sanitizeName(name) {
  const base = path.basename(String(name || 'app.apk')).replace(/[^A-Za-z0-9._-]/g, '_');
  return APK_SUFFIX_RE.test(base) ? base : `${base}.apk`;
}

// 'static' = specialist + chain + deterministic pass over decompiled code only.
// 'dynamic' = the above plus live device confirmation (ADB/Frida); degrades to static
// automatically if no device/emulator is connected when the scan runs.
function normalizeAnalysisMode(raw) {
  return String(raw || '').toLowerCase() === 'dynamic' ? 'dynamic' : 'static';
}

// The Android/APK severity ranker is the default rank design for APK scans. Look up its
// content (seeding it first if a fresh DB hasn't yet), copied onto the scan at creation.
async function apkSeverityRankerContent() {
  let ranker = await prisma.severityRanker.findFirst({
    where: { name: ANDROID_SEVERITY_RANKER_NAME },
    orderBy: { insertedAt: 'asc' },
    select: { content: true },
  });
  if (!ranker) {
    await ensureDefaultSeverityRankers();
    ranker = await prisma.severityRanker.findFirst({
      where: { name: ANDROID_SEVERITY_RANKER_NAME },
      orderBy: { insertedAt: 'asc' },
      select: { content: true },
    });
  }
  return ranker?.content ?? null;
}

async function createApkScan(filename, analysisMode = 'static', includeThirdParty = false, workflowKey = 'triage', passes) {
  // 'triage'   = default single-pass + engine specialist investigation phase.
  // 'deep'     = the staged Android Deep Research DAG (map → trace → investigate), A/B.
  // 'deepdyn'  = the layered pipeline (Mobile PT triage → deep research → on-device
  //              verification) the engine runs end-to-end in run_deep_dynamic_for_scan.
  const isDeep = workflowKey === 'deep';
  const isDeepDynamic = workflowKey === 'deepdyn';
  // 'exploit' = the 9-phase autonomous on-device exploit-research workflow: static triage,
  // then the engine reproduces each finding on a rooted device with Frida + screenshots.
  const isDynamicResearch = workflowKey === 'exploit';
  // 'samsung' = the Samsung system-app research DAG (com.samsung.*/com.sec.*), samsung-* skills attached.
  const isSamsung = workflowKey === 'samsung';
  const workflow = isSamsung
    ? await ensureSamsungResearchWorkflow()
    : isDynamicResearch
    ? await ensureAndroidDynamicResearchWorkflow()
    : isDeepDynamic
      ? await ensureAndroidDeepDynamicWorkflow()
      : isDeep
        ? await ensureAndroidDeepResearchWorkflow()
        : await ensureApkWorkflow();
  // Research passes = the macro loop: the deep DAG re-runs this many times, each pass
  // extending the prior with new/deeper findings (human-like iterative research). 1–5.
  const loopPasses = isDeep ? Math.min(5, Math.max(1, Math.trunc(Number(passes)) || 2)) : 1;
  // Deep+dynamic caps how many of the highest-severity findings get the (expensive) live
  // on-device verification pass — keeps runtime bounded on the single local GPU. 1–20.
  const verifyTopN = isDeepDynamic ? Math.min(20, Math.max(1, Math.trunc(Number(passes)) || 6)) : null;
  const postScript = await prisma.postScript.findFirst({ orderBy: { id: 'asc' } });
  if (!postScript) throw new Error('No post-scripts seeded.');
  const severityRanker = await apkSeverityRankerContent();
  const attachedSkillIds = isSamsung ? await samsungAgentSkillIds() : [];
  const localPath = path.join(INBOX, filename);
  const sha = crypto.createHash('sha256').update(fs.readFileSync(localPath)).digest('hex');
  const scan = await prisma.scan.create({
    data: {
      workflowId: workflow.id,
      postScriptId: postScript.id,
      repoFull: filename.replace(APK_SUFFIX_RE, ''),
      repoKind: 'apk',
      commitSha: sha,
      repoScope: 'full application',
      severityRanker,
      dependencies: [],
      configuration: {
        apk_path: `${INBOX_HOST}/${filename}`,
        repeat_runs: loopPasses,
        // deep+dynamic drives its own verification off a connected device, so it always
        // requests 'dynamic' mode (degrades to static-only per-finding when none is present).
        analysis_mode: (isDeepDynamic || isDynamicResearch || isSamsung) ? 'dynamic' : normalizeAnalysisMode(analysisMode),
        // Off by default: only the app's own code is investigated; bundled SDKs are skipped.
        include_third_party: includeThirdParty === true || includeThirdParty === 'true' || includeThirdParty === '1',
        // Marks the layered pipeline for the engine's investigation phase + the cap on how
        // many top findings get live on-device verification.
        ...(isDeepDynamic ? { deep_dynamic: true, verify_top_n: verifyTopN } : {}),
        // The dynamic-research workflow drives the engine's 9-phase on-device pipeline.
        ...(isDynamicResearch ? { dynamic_research: true, verify_top_n: Math.min(20, Math.max(1, Math.trunc(Number(passes)) || 8)) } : {}),
        ...(isSamsung ? { dynamic_research: true, samsung_research: true, verify_top_n: Math.min(20, Math.max(1, Math.trunc(Number(passes)) || 8)) } : {}),
      },
      model: 'local',
      modelProvider: 'local',
      harness: 'local',
      thinkingEffort: 'medium',
      status: 'queued',
      config: {},
      scopes: { files: [], lines: [] },
      agentSkillIds: attachedSkillIds,
    },
  });
  return scan;
}

// List .apk files already sitting in the inbox (drop a file in the folder OR upload).
router.get('/inbox', (req, res) => {
  try {
    const files = fs.existsSync(INBOX)
      ? fs.readdirSync(INBOX).filter((f) => f.toLowerCase().endsWith('.apk'))
      : [];
    res.json({ files, inboxHost: INBOX_HOST });
  } catch {
    res.json({ files: [], inboxHost: INBOX_HOST });
  }
});

// Upload a dropped APK (raw body) and create the scan.
router.post('/scan', express.raw({ type: '*/*', limit: '512mb' }), async (req, res, next) => {
  try {
    if (!Buffer.isBuffer(req.body) || req.body.length === 0) {
      return res.status(400).json({ error: 'Empty request body — send the .apk file as the raw body.' });
    }
    const filename = sanitizeName(req.query.filename);
    fs.mkdirSync(INBOX, { recursive: true });
    fs.writeFileSync(path.join(INBOX, filename), req.body);
    const scan = await createApkScan(filename, req.query.mode, req.query.thirdParty, req.query.workflow, req.query.passes);
    res.json({ scanId: scan.id.toString(), filename, analysisMode: normalizeAnalysisMode(req.query.mode) });
  } catch (e) {
    next(e);
  }
});

// Create a scan from an APK already present in the inbox folder.
router.post('/scan-existing', async (req, res, next) => {
  try {
    const filename = sanitizeName(req.body?.filename);
    if (!fs.existsSync(path.join(INBOX, filename))) {
      return res.status(404).json({ error: 'APK not found in the inbox folder.' });
    }
    const scan = await createApkScan(filename, req.body?.mode, req.body?.thirdParty, req.body?.workflow, req.body?.passes);
    res.json({ scanId: scan.id.toString(), filename, analysisMode: normalizeAnalysisMode(req.body?.mode) });
  } catch (e) {
    next(e);
  }
});

export default router;
