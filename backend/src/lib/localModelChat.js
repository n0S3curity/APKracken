// Direct backend → local llama-server chat calls for the per-vulnerability AI chat.
// The engine owns model calls for scans; this is a separate, low-latency path so the UI
// can hold a focused conversation about a single finding without going through the queue.
import { prisma } from '../db.js';

// The local model runs on the Docker HOST (native llama-server). Its configured base_url
// uses 127.0.0.1/localhost, which inside the backend container points at the container
// itself — rewrite it to host.docker.internal so the container can reach the host.
export function containerReachableUrl(rawUrl) {
  let url = String(rawUrl || '').trim();
  if (!url) return '';
  url = url.replace('://127.0.0.1', '://host.docker.internal').replace('://localhost', '://host.docker.internal');
  return url.replace(/\/+$/, '');
}

export async function resolveLocalModel() {
  let base = '';
  let model = 'local';
  try {
    const rows = await prisma.$queryRawUnsafe(
      `SELECT base_url, model_name FROM public.local_model_config WHERE id = 1`
    );
    const r = rows?.[0] || {};
    base = r.base_url || '';
    model = (r.model_name || 'local').trim() || 'local';
  } catch {
    // table may not exist yet — fall back to defaults below
  }
  base = containerReachableUrl(process.env.LOCAL_MODEL_PROXY_URL || base || 'http://host.docker.internal:8091/v1');
  return { base, model };
}

// Call the OpenAI-compatible /chat/completions endpoint and return the assistant's text.
export async function chatComplete(
  messages,
  { temperature = 0.3, maxTokens = 1200, timeoutMs = 180000, responseFormat = null } = {}
) {
  const { base, model } = await resolveLocalModel();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let resp;
  try {
    const body = { model, messages, temperature, max_tokens: maxTokens, stream: false };
    // llama.cpp supports OpenAI-style response_format to force valid JSON output.
    if (responseFormat) body.response_format = responseFormat;
    resp = await fetch(`${base}/chat/completions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
  } catch (e) {
    clearTimeout(timer);
    const err = new Error(
      e.name === 'AbortError'
        ? 'The local model timed out. It may be loading or busy with a scan — try again shortly.'
        : `Could not reach the local model at ${base}. Start it (scripts/start-llm.ps1) and try again.`
    );
    err.status = 502;
    throw err;
  }
  clearTimeout(timer);
  if (!resp.ok) {
    const text = await resp.text().catch(() => '');
    const err = new Error(`The local model returned HTTP ${resp.status}. ${text.slice(0, 300)}`.trim());
    err.status = 502;
    throw err;
  }
  const data = await resp.json().catch(() => ({}));
  let content = data?.choices?.[0]?.message?.content ?? '';
  // Some templates leak the reasoning block into content — drop it, keep the answer.
  content = String(content)
    .replace(/<think>[\s\S]*?<\/think>/gi, '')
    .trim();
  return content || '(The model returned an empty response. Try rephrasing your question.)';
}

// --- Agentic chat: the model reads the decompiled source with tools before answering ----- //

// The engine serves the read-only workspace (source/grep/list) on the host; the backend
// container reaches it via host.docker.internal.
function sourceServerBase() {
  return containerReachableUrl(process.env.SOURCE_SERVER_URL || 'http://127.0.0.1:9011');
}

// Extract EVERY top-level balanced JSON object in the text (the model often emits several
// tool-call objects back-to-back, which is not one valid JSON value).
function allJsonObjects(raw) {
  const s = String(raw || '').replace(/```(?:json)?/gi, '');
  const out = [];
  let i = 0;
  while (i < s.length) {
    if (s[i] !== '{') {
      i += 1;
      continue;
    }
    let depth = 0;
    let inStr = false;
    let esc = false;
    const start = i;
    for (; i < s.length; i += 1) {
      const c = s[i];
      if (inStr) {
        if (esc) esc = false;
        else if (c === '\\') esc = true;
        else if (c === '"') inStr = false;
      } else if (c === '"') inStr = true;
      else if (c === '{') depth += 1;
      else if (c === '}') {
        depth -= 1;
        if (depth === 0) {
          i += 1;
          break;
        }
      }
    }
    try {
      out.push(JSON.parse(s.slice(start, i)));
    } catch {
      /* skip malformed */
    }
  }
  return out;
}

// Strip an outer ```markdown ... ``` fence the model sometimes wraps its answer in.
function finalizeAnswer(text) {
  const s = String(text || '')
    .trim()
    .replace(/^```(?:markdown|md)?\s*\n?/i, '')
    .replace(/\n?```\s*$/i, '')
    .trim();
  return s || '(no answer)';
}

// Plain-text answer fallback (model replied without JSON) — strip any leftover reasoning.
function cleanAnswer(raw) {
  return (
    String(raw || '')
      .replace(/<think>[\s\S]*?<\/think>/gi, '')
      .replace(/\{[\s\S]*"action"\s*:\s*"tool"[\s\S]*\}/g, '')
      .trim() || '(no answer)'
  );
}

async function runChatTool(tool, args, sha) {
  if (!sha) return '[no decompiled workspace is available for this finding]';
  const base = sourceServerBase();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 20000);
  try {
    let url;
    if (tool === 'read_file') url = `${base}/source?sha=${sha}&path=${encodeURIComponent(args.path || '')}`;
    else if (tool === 'grep')
      url = `${base}/grep?sha=${sha}&pattern=${encodeURIComponent(args.pattern || '')}&path=${encodeURIComponent(args.path || '')}`;
    else if (tool === 'list_dir') url = `${base}/list?sha=${sha}&path=${encodeURIComponent(args.path || '')}`;
    else return `[unknown tool: ${tool}]`;
    const r = await fetch(url, { signal: controller.signal });
    const text = await r.text();
    return r.ok ? text : `[${tool} failed: HTTP ${r.status} ${text.slice(0, 80)}]`;
  } catch (e) {
    return `[${tool} error: ${e.name === 'AbortError' ? 'timeout' : e.message}]`;
  } finally {
    clearTimeout(timer);
  }
}

const CHAT_TOOL_DIRECTIVE =
  'You are an Android security expert answering the user about ONE specific vulnerability finding. You have TOOLS to ' +
  'read the decompiled app, and you MUST use them to ground your answer in the real source instead of guessing.\n\n' +
  'PROTOCOL — reply with JSON only, never prose:\n' +
  '• To investigate, emit ONE tool call:\n' +
  '  {"action":"tool","thought":"why","tool":"read_file","args":{"path":"jadx/sources/com/app/Foo.java"}}\n' +
  '  {"action":"tool","thought":"why","tool":"grep","args":{"pattern":"loadUrl|startsWith|@JavascriptInterface","path":"jadx/sources"}}\n' +
  '  {"action":"tool","thought":"why","tool":"list_dir","args":{"path":"jadx/sources/com/app"}}\n' +
  '• When you have read enough, give the FINAL answer as ONE object:\n' +
  '  {"action":"answer","content":"the full answer to the user, in markdown"}\n\n' +
  'RULES:\n' +
  '- The tool RESULTS come back to you in the next message; you cannot know a file\'s contents until you read it.\n' +
  '- Do NOT answer and call tools in the same reply. Investigate first (tool calls), THEN answer.\n' +
  '- When asked about code, checks/validations, the exploit flow, or to write payloads: read the relevant files with ' +
  'read_file / grep FIRST, then answer with the concrete details you found.\n' +
  '- `path` is workspace-relative (starts with jadx/sources/...). Never invent a path — list_dir / grep to find it.\n' +
  '- The final {"action":"answer",...} content is the ONLY thing the user sees — put the real answer there, not JSON.';

// Run the ReAct loop. The model may emit several tool objects at once — run them all, feed
// the results back, and loop until it returns an {"action":"answer"} (or plain text).
export async function agentChat(messages, { sha, maxSteps = 7 } = {}) {
  const toolSteps = [];
  const work = [{ role: 'system', content: CHAT_TOOL_DIRECTIVE }, ...messages];
  for (let step = 0; step < maxSteps; step += 1) {
    const forceAnswer = step === maxSteps - 1;
    const raw = await chatComplete(forceAnswer ? [...work, { role: 'user', content: 'Stop investigating. Give your FINAL answer now as {"action":"answer","content":"..."} in markdown.' }] : work, {
      temperature: 0.2,
      maxTokens: 1500,
    });
    const objs = allJsonObjects(raw);
    const answerObj = objs.find((o) => o && (o.action === 'answer' || (o.content && !o.tool)));
    const toolObjs = objs.filter((o) => o && o.action === 'tool' && o.tool);

    // No tools requested → the model answered (JSON answer, or plain text).
    if (!toolObjs.length) {
      const ans = answerObj ? String(answerObj.content || answerObj.answer || '') : cleanAnswer(raw);
      return { answer: finalizeAnswer(ans), toolSteps };
    }
    if (forceAnswer && answerObj) {
      return { answer: finalizeAnswer(answerObj.content || answerObj.answer || ''), toolSteps };
    }

    // Run every requested tool, then feed all observations back for the next decision.
    const observations = [];
    for (const o of toolObjs.slice(0, 4)) {
      const args = o.args && typeof o.args === 'object' ? o.args : {};
      const obs = await runChatTool(String(o.tool), args, sha);
      toolSteps.push({ tool: o.tool, args, thought: o.thought || '', preview: obs.slice(0, 300) });
      observations.push(`Result of ${o.tool}(${JSON.stringify(args)}):\n${obs.slice(0, 7000)}`);
    }
    work.push({ role: 'assistant', content: JSON.stringify(toolObjs.map((o) => ({ action: 'tool', tool: o.tool, args: o.args }))) });
    work.push({
      role: 'user',
      content:
        `${observations.join('\n\n')}\n\n` +
        'Based on these results, either investigate more (another tool call) or give the final answer as ' +
        '{"action":"answer","content":"..."}. Answer only when you have read what you need.',
    });
  }
  return { answer: '(the model kept investigating without answering — try asking again)', toolSteps };
}
