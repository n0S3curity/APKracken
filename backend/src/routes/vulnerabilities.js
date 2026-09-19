import { Router } from 'express';
import { prisma } from '../db.js';
import { serializeVulnerability } from '../lib/serialize.js';
import { chatComplete, agentChat, containerReachableUrl } from '../lib/localModelChat.js';
import HTMLtoDOCX from 'html-to-docx';

const router = Router();

// GET /api/vulnerabilities/evidence?path=<scan>/<finding>/<file>.png
// Proxies a dynamic-research screenshot from the engine's file server (host-side) so the
// browser can render it same-origin. Path is guarded engine-side against traversal.
router.get('/evidence', async (req, res) => {
  const rel = String(req.query.path || '');
  if (!/^[\w./-]+\.(png|jpg|jpeg|webp)$/i.test(rel) || rel.includes('..')) {
    return res.status(400).json({ error: 'bad evidence path' });
  }
  const base = containerReachableUrl(process.env.SOURCE_SERVER_URL || 'http://127.0.0.1:9011');
  try {
    const upstream = await fetch(`${base}/evidence?path=${encodeURIComponent(rel)}`);
    if (!upstream.ok) return res.status(upstream.status).end();
    res.setHeader('Content-Type', upstream.headers.get('content-type') || 'image/png');
    res.setHeader('Cache-Control', 'private, max-age=60');
    const buf = Buffer.from(await upstream.arrayBuffer());
    return res.end(buf);
  } catch {
    return res.status(502).json({ error: 'evidence server unreachable' });
  }
});

// --- Per-vulnerability AI chat -------------------------------------------------------- //

// Conversation history is persisted so the model only needs the (large) finding context
// assembled once — the first turn stores a `system` message with everything, and every
// later turn reuses the stored conversation instead of re-pulling from the DB.
async function ensureChatTable() {
  await prisma.$executeRawUnsafe(`
    CREATE TABLE IF NOT EXISTS public.vulnerability_chat_messages (
      id bigserial PRIMARY KEY,
      vulnerability_id bigint NOT NULL,
      scan_id bigint,
      role text NOT NULL,
      content text NOT NULL,
      created_at timestamptz NOT NULL DEFAULT now()
    )`);
  await prisma.$executeRawUnsafe(
    `CREATE INDEX IF NOT EXISTS vuln_chat_msg_vuln_idx ON public.vulnerability_chat_messages (vulnerability_id, id)`
  );
}

async function loadChatMessages(vulnerabilityId) {
  await ensureChatTable();
  return prisma.$queryRawUnsafe(
    `SELECT id, role, content, created_at FROM public.vulnerability_chat_messages
      WHERE vulnerability_id = $1 ORDER BY id ASC`,
    vulnerabilityId
  );
}

async function insertChatMessage(vulnerabilityId, scanId, role, content) {
  await prisma.$executeRawUnsafe(
    `INSERT INTO public.vulnerability_chat_messages (vulnerability_id, scan_id, role, content)
     VALUES ($1, $2, $3, $4)`,
    vulnerabilityId,
    scanId ?? null,
    role,
    content
  );
}

// Assemble the full, concrete context for ONE finding from the DB (filenames, vulnerable
// source, static + dynamic analysis, PoC, attack flow). Sent once as the system message.
function buildVulnContext(v, scan) {
  const a = v.jsonAnswer && typeof v.jsonAnswer === 'object' ? v.jsonAnswer : {};
  const cfg = scan?.configuration && typeof scan.configuration === 'object' ? scan.configuration : {};
  const S = [];
  const add = (label, value) => {
    if (value === null || value === undefined) return;
    const text = Array.isArray(value) ? value.filter(Boolean).join('\n') : String(value);
    if (text.trim()) S.push(`${label}: ${text}`);
  };
  const section = (title, value) => {
    const text = Array.isArray(value) ? value.filter(Boolean).join('\n') : value ? String(value) : '';
    if (text.trim()) {
      S.push('');
      S.push(`=== ${title} ===`);
      S.push(text.trim());
    }
  };

  S.push(
    'You are a senior Android mobile-security engineer. You are helping the user analyze ONE specific ' +
      'vulnerability finding from an APK penetration test. Answer concretely, precisely, and concisely, grounded ' +
      'in the finding data below and standard Android security knowledge. When asked for exploitation, give exact ' +
      'adb commands or minimal real code using the actual component/authority/file names from this finding. If the ' +
      'data below does not contain something, say so plainly instead of inventing it.'
  );
  S.push('');
  S.push('=== APPLICATION ===');
  add('App / target', scan?.repoFull);
  add('Package', cfg.package || a.package || (a.component ? String(a.component).split(/[ (]/)[0] : null));
  add('APK sha256', scan?.commitSha);

  S.push('');
  S.push('=== FINDING ===');
  add('Type', a.vulnerability_type);
  add('Summary', a.summary || v.summary);
  add('Severity score', a.severity_score != null ? `${a.severity_score}/10` : null);
  add('Component', a.component);
  add('Exported', a.exported);
  add('Reachability', a.reachability);
  add('Authorities', a.authorities);
  add('Grant URI permissions', a.grant_uri_permissions);
  add('File', a.code_file || a.file_path || v.file_path);
  add('Line', a.line || v.line);
  add('Chainable primitive', a.chainable_primitive);
  add('Confidence', a.confidence);

  section('EXPLANATION', a.explanation || v.explanation);
  section(`VULNERABLE SOURCE CODE (${a.code_file || a.file_path || 'source'})`, a.code_evidence);
  section('STATIC EVIDENCE', a.static_evidence);
  section(
    'DYNAMIC INVESTIGATION',
    [
      a.dynamic_status ? `Status: ${a.dynamic_status}` : '',
      a.dynamic_evidence || '',
      a.dynamic_transcript ? `\nOn-device steps (tools + observations):\n${a.dynamic_transcript}` : '',
    ]
      .filter(Boolean)
      .join('\n')
  );
  section('PROOF OF CONCEPT', a.poc || a.malicious_input_example || v.malicious_input_example);
  section(
    'ATTACK FLOW',
    (Array.isArray(a.trigger_flow) && a.trigger_flow.length
      ? a.trigger_flow
      : Array.isArray(a.chain_steps)
        ? a.chain_steps
        : []
    ).map((step, i) => `${i + 1}. ${typeof step === 'string' ? step : JSON.stringify(step)}`)
  );
  section('IMPACT', a.impact || a.combined_impact);
  return S.join('\n');
}

// GET /api/vulnerabilities/:id — a single finding with its post-script output.
router.get('/:id', async (req, res, next) => {
  try {
    const id = BigInt(req.params.id);
    const v = await prisma.vulnerability.findUnique({ where: { id } });
    if (!v) return res.status(404).json({ error: 'Vulnerability not found.' });
    const [enrichments, duplicates] = await Promise.all([
      prisma.vulnerabilityEnrichment.findMany({ where: { vulnerabilityId: id }, orderBy: [{ id: 'asc' }] }),
      prisma.vulnerability.findMany({
        where: { scanId: v.scanId, dedupeCanonicalId: id, dedupeIsCanonical: false },
        select: { id: true },
        orderBy: [{ id: 'asc' }],
      }),
    ]);
    res.json(
      serializeVulnerability(v, {
        enrichments,
        duplicateIds: duplicates.map((d) => d.id),
      })
    );
  } catch (e) {
    next(e);
  }
});

// PATCH /api/vulnerabilities/:id — user review: interesting flag and/or comments.
// interesting: 1 (interesting), 0 (not interesting), or null (unmarked).
router.patch('/:id', async (req, res, next) => {
  try {
    const id = BigInt(req.params.id);
    const existing = await prisma.vulnerability.findUnique({ where: { id }, select: { id: true } });
    if (!existing) return res.status(404).json({ error: 'Vulnerability not found.' });

    const body = req.body || {};
    const data = {};
    if ('interesting' in body) {
      const val = body.interesting;
      if (val === null) data.interesting = null;
      else if (val === 0 || val === 1 || val === '0' || val === '1') data.interesting = BigInt(Number(val));
      else
        return res
          .status(422)
          .json({ errors: [{ field: 'interesting', message: 'interesting must be 0, 1, or null.' }] });
    }
    if ('comments' in body) {
      data.comments = body.comments === null || body.comments === '' ? null : String(body.comments);
    }
    if (Object.keys(data).length === 0) {
      return res.status(422).json({ errors: [{ field: 'body', message: 'Provide interesting and/or comments.' }] });
    }

    const updated = await prisma.vulnerability.update({
      where: { id },
      data,
      select: { id: true, interesting: true, comments: true },
    });
    res.json({
      id: updated.id.toString(),
      interesting:
        updated.interesting === null || updated.interesting === undefined ? null : Number(updated.interesting),
      comments: updated.comments ?? null,
    });
  } catch (e) {
    next(e);
  }
});

// --- Per-vulnerability AI report (bug-bounty writeup) --------------------------------- //

async function ensureReportTable() {
  await prisma.$executeRawUnsafe(`
    CREATE TABLE IF NOT EXISTS public.vulnerability_reports (
      vulnerability_id bigint PRIMARY KEY,
      scan_id bigint,
      content_html text,
      updated_at timestamptz NOT NULL DEFAULT now()
    )`);
}

// The device this finding was (or would be) tested on — for the report's "Tested Environment".
async function testedDeviceInfo() {
  try {
    const st = await prisma.$queryRawUnsafe(
      `SELECT active_serial, last_test_serial FROM public.device_state WHERE id = 1`
    );
    const serial = st?.[0]?.active_serial || st?.[0]?.last_test_serial || null;
    const rows = serial
      ? await prisma.$queryRawUnsafe(
          `SELECT serial, brand, model, manufacturer, android_release, sdk FROM public.devices WHERE serial = $1`,
          serial
        )
      : await prisma.$queryRawUnsafe(
          `SELECT serial, brand, model, manufacturer, android_release, sdk FROM public.devices ORDER BY last_seen DESC LIMIT 1`
        );
    return rows?.[0] || null;
  } catch {
    return null;
  }
}

function deviceSection(d) {
  if (!d) return '=== TESTED DEVICE ===\nNo physical device is on record. State testing as static analysis (or emulator) accordingly — do not invent a device.';
  return [
    '=== TESTED DEVICE (use for the "Tested Environment" section) ===',
    `Model: ${[d.brand, d.model].filter(Boolean).join(' ') || d.model || 'unknown'}`,
    d.manufacturer ? `Manufacturer: ${d.manufacturer}` : '',
    `Android version: ${d.android_release || '?'}${d.sdk ? ` (SDK ${d.sdk})` : ''}`,
    d.serial ? `Serial: ${d.serial}` : '',
  ]
    .filter(Boolean)
    .join('\n');
}

const REPORT_SYSTEM =
  'You are a senior mobile-security researcher writing a professional, submission-ready vulnerability report for a ' +
  'bug bounty program, for ONE specific finding. Use ONLY the data provided — never invent commands, code, or a ' +
  'device.\n\nOUTPUT RULES:\n' +
  '- Output ONLY HTML body content: no <html>/<head>/<body> tags, no markdown, no code fences.\n' +
  '- Use semantic HTML: <h1> title, <h2> section headings, <p>, <ol>/<ul>/<li>, <strong>, <table>, and ' +
  '<pre><code> for code / adb commands / PoC (preserve exact formatting and characters).\n' +
  '- Sections in order: <h1> title; a <p> summary line with Severity + Affected component + Package; ' +
  '"Summary"; "Affected Component" (file path and line); "Vulnerability Details" (explanation + the vulnerable ' +
  'code VERBATIM inside <pre><code>); "Steps to Reproduce" (ordered list); "Proof of Concept" (the exact adb ' +
  'command or code inside <pre><code>); "Impact"; "Remediation"; "Tested Environment" (device model, ' +
  'manufacturer, Android version from the tested-device data — or say static/emulator if none).\n' +
  '- Put the ACTUAL proof-of-concept and vulnerable code from the data verbatim. If a field is missing, write ' +
  '"Not available" instead of fabricating.\n- Precise, concise, professional tone for a triager.';

async function generateReportHtml(v, scan) {
  const device = await testedDeviceInfo();
  const context = buildVulnContext(serializeVulnerability(v, {}), scan);
  const user = `${context}\n\n${deviceSection(device)}\n\nWrite the complete HTML report now.`;
  let html = await chatComplete(
    [
      { role: 'system', content: REPORT_SYSTEM },
      { role: 'user', content: user },
    ],
    { temperature: 0.35, maxTokens: 3500 }
  );
  // Strip any accidental markdown code fences around the HTML.
  html = html
    .replace(/^\s*```(?:html)?\s*/i, '')
    .replace(/\s*```\s*$/i, '')
    .trim();
  return html;
}

// GET /api/vulnerabilities/:id/report — the saved report (or null).
router.get('/:id/report', async (req, res, next) => {
  try {
    const id = BigInt(req.params.id);
    await ensureReportTable();
    const rows = await prisma.$queryRawUnsafe(
      `SELECT content_html, updated_at FROM public.vulnerability_reports WHERE vulnerability_id = $1`,
      id
    );
    res.json({ html: rows?.[0]?.content_html ?? null, updatedAt: rows?.[0]?.updated_at ?? null });
  } catch (e) {
    next(e);
  }
});

// POST /api/vulnerabilities/:id/report/generate — (re)generate the report with the model.
router.post('/:id/report/generate', async (req, res, next) => {
  try {
    const id = BigInt(req.params.id);
    const v = await prisma.vulnerability.findUnique({ where: { id } });
    if (!v) return res.status(404).json({ error: 'Vulnerability not found.' });
    const scan = await prisma.scan.findUnique({
      where: { id: v.scanId },
      select: { repoFull: true, commitSha: true, configuration: true },
    });
    const html = await generateReportHtml(v, scan);
    await ensureReportTable();
    await prisma.$executeRawUnsafe(
      `INSERT INTO public.vulnerability_reports (vulnerability_id, scan_id, content_html, updated_at)
       VALUES ($1, $2, $3, now())
       ON CONFLICT (vulnerability_id) DO UPDATE SET content_html = EXCLUDED.content_html, updated_at = now()`,
      id,
      v.scanId,
      html
    );
    res.json({ html, updatedAt: new Date().toISOString() });
  } catch (e) {
    if (e?.status === 502) return res.status(502).json({ error: e.message });
    next(e);
  }
});

// PUT /api/vulnerabilities/:id/report — save the (edited) report HTML.
router.put('/:id/report', async (req, res, next) => {
  try {
    const id = BigInt(req.params.id);
    const html = typeof req.body?.html === 'string' ? req.body.html : null;
    if (html === null) return res.status(422).json({ errors: [{ field: 'html', message: 'html is required.' }] });
    const v = await prisma.vulnerability.findUnique({ where: { id }, select: { scanId: true } });
    if (!v) return res.status(404).json({ error: 'Vulnerability not found.' });
    await ensureReportTable();
    await prisma.$executeRawUnsafe(
      `INSERT INTO public.vulnerability_reports (vulnerability_id, scan_id, content_html, updated_at)
       VALUES ($1, $2, $3, now())
       ON CONFLICT (vulnerability_id) DO UPDATE SET content_html = EXCLUDED.content_html, updated_at = now()`,
      id,
      v.scanId,
      html
    );
    res.json({ ok: true, updatedAt: new Date().toISOString() });
  } catch (e) {
    next(e);
  }
});

// --- Per-vulnerability exploit flow + verification (model-generated) ------------------ //

async function ensureFlowTable() {
  await prisma.$executeRawUnsafe(`
    CREATE TABLE IF NOT EXISTS public.vulnerability_flows (
      vulnerability_id bigint PRIMARY KEY,
      scan_id bigint,
      flow_json jsonb,
      updated_at timestamptz NOT NULL DEFAULT now()
    )`);
}

const FLOW_SYSTEM =
  'You are an Android security analyst. From the finding data, produce a concrete EXPLOIT FLOW and the ' +
  'VERIFICATIONS/checks present on the vulnerable component, so a reviewer can follow the vulnerability from the ' +
  'external entry point to the sink without re-investigating.\n\n' +
  'Output ONLY valid JSON (no prose, no markdown) matching exactly:\n' +
  '{"flow":[{"title":string,"kind":"entry"|"validation"|"step"|"sink","file":string,"line":number,"code":string,"description":string}],' +
  '"verifications":[{"check":string,"result":string,"status":"risk"|"ok"|"info","detail":string}]}\n\n' +
  'Rules:\n' +
  '- "flow" is ORDERED from the external attacker entry point to the dangerous sink. kind: "entry" = the externally ' +
  'reachable ingress (exported activity/service/receiver/provider, deep link); "validation" = a guard/check that ' +
  'exists OR is missing (say which); "step" = intermediate data flow; "sink" = the dangerous operation (loadUrl, ' +
  'rawQuery, openFile, Runtime.exec, a re-dispatched Intent, etc.).\n' +
  '- "file" MUST be a workspace-relative path from the data (e.g. jadx/sources/com/app/Foo.java); "line" a line ' +
  "number from the evidence. Use the finding's code_file/line and the trigger_flow hops. If a hop's exact file/line " +
  'is unknown, reuse the finding code_file and set line to 0 — NEVER invent a path.\n' +
  '- "code" = the exact relevant line(s) from the evidence for that node (short).\n' +
  '- "verifications" = the security checks on the component: exported state, URI/grant permissions, provider ' +
  'authorities, URL host/scheme allowlisting, input validation, permission guards, signature checks. "result" ' +
  'states what the check actually is (e.g. "none — any URL is loaded", "allowlist: only https://example.com", ' +
  '"grantUriPermissions=true", "authority: com.app.provider"); "status": "risk" = missing/weak check an attacker ' +
  'abuses, "ok" = a control that holds, "info" = neutral fact.\n' +
  '- Base everything ONLY on the provided data. Keep strings short and concrete.';

async function generateFlowJson(v, scan) {
  const context = buildVulnContext(serializeVulnerability(v, {}), scan);
  const raw = await chatComplete(
    [
      { role: 'system', content: FLOW_SYSTEM },
      { role: 'user', content: `${context}\n\nProduce the exploit-flow JSON now.` },
    ],
    { temperature: 0.2, maxTokens: 2600, responseFormat: { type: 'json_object' } }
  );
  const clean = raw.replace(/^\s*```(?:json)?\s*/i, '').replace(/\s*```\s*$/i, '').trim();
  let parsed;
  try {
    parsed = JSON.parse(clean);
  } catch {
    // Lenient fallback: extract the outermost {...} object if the model wrapped it in prose.
    const a = clean.indexOf('{');
    const b = clean.lastIndexOf('}');
    try {
      parsed = a >= 0 && b > a ? JSON.parse(clean.slice(a, b + 1)) : null;
    } catch {
      parsed = null;
    }
    if (!parsed) {
      const err = new Error('The model did not return valid flow JSON — try again.');
      err.status = 502;
      throw err;
    }
  }
  return {
    flow: Array.isArray(parsed.flow) ? parsed.flow : [],
    verifications: Array.isArray(parsed.verifications) ? parsed.verifications : [],
  };
}

// POST /api/vulnerabilities/:id/verify — request false-positive verification of this finding.
// The engine picks up the flagged finding, re-checks it with tools (reachability, guards,
// bypasses, adb when a device is present) and writes the verdict back into json_answer.
router.post('/:id/verify', async (req, res, next) => {
  try {
    const id = BigInt(req.params.id);
    const v = await prisma.vulnerability.findUnique({ where: { id }, select: { id: true } });
    if (!v) return res.status(404).json({ error: 'Vulnerability not found.' });
    await prisma.$executeRaw`
      UPDATE workflows.vulnerabilities
         SET json_answer = coalesce(json_answer, '{}'::jsonb) || '{"fp_verify_requested":true}'::jsonb
       WHERE id = ${id}`;
    res.json({ ok: true });
  } catch (e) {
    next(e);
  }
});

// GET /api/vulnerabilities/:id/flow — the saved exploit flow (or null).
router.get('/:id/flow', async (req, res, next) => {
  try {
    const id = BigInt(req.params.id);
    await ensureFlowTable();
    const rows = await prisma.$queryRawUnsafe(
      `SELECT flow_json, updated_at FROM public.vulnerability_flows WHERE vulnerability_id = $1`,
      id
    );
    const fj = rows?.[0]?.flow_json ?? null;
    res.json({ flow: fj?.flow ?? null, verifications: fj?.verifications ?? null, updatedAt: rows?.[0]?.updated_at ?? null });
  } catch (e) {
    next(e);
  }
});

// POST /api/vulnerabilities/:id/flow/generate — (re)generate the exploit flow with the model.
router.post('/:id/flow/generate', async (req, res, next) => {
  try {
    const id = BigInt(req.params.id);
    const v = await prisma.vulnerability.findUnique({ where: { id } });
    if (!v) return res.status(404).json({ error: 'Vulnerability not found.' });
    const scan = await prisma.scan.findUnique({
      where: { id: v.scanId },
      select: { repoFull: true, commitSha: true, configuration: true },
    });
    const result = await generateFlowJson(v, scan);
    await ensureFlowTable();
    await prisma.$executeRawUnsafe(
      `INSERT INTO public.vulnerability_flows (vulnerability_id, scan_id, flow_json, updated_at)
       VALUES ($1, $2, $3::jsonb, now())
       ON CONFLICT (vulnerability_id) DO UPDATE SET flow_json = EXCLUDED.flow_json, updated_at = now()`,
      id,
      v.scanId,
      JSON.stringify(result)
    );
    res.json({ ...result, updatedAt: new Date().toISOString() });
  } catch (e) {
    if (e?.status === 502) return res.status(502).json({ error: e.message });
    next(e);
  }
});

// POST /api/vulnerabilities/:id/report/docx — convert the report HTML to a .docx (server-side).
router.post('/:id/report/docx', async (req, res, next) => {
  try {
    const html = typeof req.body?.html === 'string' ? req.body.html : '';
    if (!html.trim()) return res.status(422).json({ errors: [{ field: 'html', message: 'html is required.' }] });
    const full = `<!DOCTYPE html><html><head><meta charset="utf-8"></head><body>${html}</body></html>`;
    const buffer = await HTMLtoDOCX(full, null, { table: { row: { cantSplit: true } }, footer: false });
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document');
    res.setHeader('Content-Disposition', 'attachment; filename="report.docx"');
    res.end(Buffer.isBuffer(buffer) ? buffer : Buffer.from(buffer));
  } catch (e) {
    next(e);
  }
});

// GET /api/vulnerabilities/:id/chat — the conversation for this finding (no system msg).
router.get('/:id/chat', async (req, res, next) => {
  try {
    const id = BigInt(req.params.id);
    const rows = await loadChatMessages(id);
    res.json({
      messages: rows
        .filter((m) => m.role !== 'system')
        .map((m) => ({ id: m.id.toString(), role: m.role, content: m.content, createdAt: m.created_at })),
    });
  } catch (e) {
    next(e);
  }
});

// POST /api/vulnerabilities/:id/chat — ask the local model about this finding.
router.post('/:id/chat', async (req, res, next) => {
  try {
    const id = BigInt(req.params.id);
    const message = String(req.body?.message ?? '').trim();
    if (!message) return res.status(422).json({ errors: [{ field: 'message', message: 'Message is required.' }] });
    if (message.length > 8000) {
      return res.status(422).json({ errors: [{ field: 'message', message: 'Message is too long (max 8000 chars).' }] });
    }

    const v = await prisma.vulnerability.findUnique({ where: { id } });
    if (!v) return res.status(404).json({ error: 'Vulnerability not found.' });

    // Always load the scan for its apk sha256 — the agent's source tools are keyed by it.
    const scan = await prisma.scan.findUnique({
      where: { id: v.scanId },
      select: { repoFull: true, commitSha: true, configuration: true },
    });

    const stored = await loadChatMessages(id);
    const hasSystem = stored.length > 0 && stored[0].role === 'system';

    // Build the big finding context ONCE (first turn only). Later turns reuse it from history.
    let contextMsg = null;
    if (!hasSystem) contextMsg = buildVulnContext(serializeVulnerability(v, {}), scan);

    // Model context: system + prior user/assistant turns (tool-step messages are display-only).
    const apiMessages = [];
    if (contextMsg) apiMessages.push({ role: 'system', content: contextMsg });
    for (const m of stored) {
      if (m.role === 'tool' || m.role === 'system') continue;
      apiMessages.push({ role: m.role, content: m.content });
    }
    apiMessages.push({ role: 'user', content: message });

    // Agentic: the model may read/grep the decompiled source before answering. Persist only
    // after it succeeds, so a failed/unreachable model never leaves a dangling user message.
    const { answer, toolSteps } = await agentChat(apiMessages, { sha: scan?.commitSha });

    if (contextMsg) await insertChatMessage(id, v.scanId, 'system', contextMsg);
    await insertChatMessage(id, v.scanId, 'user', message);
    if (toolSteps && toolSteps.length) await insertChatMessage(id, v.scanId, 'tool', JSON.stringify(toolSteps));
    await insertChatMessage(id, v.scanId, 'assistant', answer);

    const rows = await loadChatMessages(id);
    res.json({
      messages: rows
        .filter((m) => m.role !== 'system')
        .map((m) => ({ id: m.id.toString(), role: m.role, content: m.content, createdAt: m.created_at })),
    });
  } catch (e) {
    if (e?.status === 502) return res.status(502).json({ error: e.message });
    next(e);
  }
});

// DELETE /api/vulnerabilities/:id/chat — clear the conversation (incl. the stored context).
router.delete('/:id/chat', async (req, res, next) => {
  try {
    const id = BigInt(req.params.id);
    await ensureChatTable();
    await prisma.$executeRawUnsafe(
      `DELETE FROM public.vulnerability_chat_messages WHERE vulnerability_id = $1`,
      id
    );
    res.status(204).end();
  } catch (e) {
    next(e);
  }
});

export default router;
