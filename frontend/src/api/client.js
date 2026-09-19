// Thin fetch wrapper around the open-kritt API.
// In dev, Vite proxies /api -> backend. In prod, VITE_API_BASE_URL can point
// directly at the backend origin.

function isLoopbackHostname(hostname) {
  const normalized = hostname?.replace(/^\[|\]$/g, '').toLowerCase();
  return (
    normalized === 'localhost' ||
    normalized?.endsWith('.localhost') ||
    normalized === '127.0.0.1' ||
    normalized === '::1'
  );
}

/**
 * Ignore loopback API overrides in the browser. They either bypass the local
 * same-origin proxy or refer to the visitor's computer for remote deployments.
 * Falling back to /api lets Vite's server-side proxy reach the backend in both
 * cases without requiring CORS.
 */
export function resolveApiBase(configuredBase, pageLocation) {
  const base = (configuredBase || '').replace(/\/$/, '');
  if (!base || !pageLocation) return base;

  try {
    const configuredUrl = new URL(base, pageLocation.origin);
    return isLoopbackHostname(configuredUrl.hostname) ? '' : base;
  } catch {
    return base;
  }
}

const BASE = resolveApiBase(
  import.meta.env.VITE_API_BASE_URL,
  typeof window === 'undefined' ? undefined : window.location
);

export class ApiError extends Error {
  constructor(message, status, errors) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.errors = errors || [];
  }
}

export function apiErrorMessages(error, { includeField = true } = {}) {
  const details = Array.isArray(error?.errors)
    ? error.errors
        .map((item) => {
          const message = typeof item?.message === 'string' ? item.message.trim() : '';
          if (!message) return '';
          const field = typeof item?.field === 'string' ? item.field.trim() : '';
          return includeField && field ? `${field}: ${message}` : message;
        })
        .filter(Boolean)
    : [];
  if (details.length) return details;
  return [error?.message || 'Request failed.'];
}

async function request(path, options = {}) {
  const res = await fetch(`${BASE}/api${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
    body: options.body ? JSON.stringify(options.body) : undefined,
  });
  if (res.status === 204) return null;
  let data = null;
  try {
    data = await res.json();
  } catch {
    /* no body */
  }
  if (!res.ok) {
    throw new ApiError(data?.error || `Request failed (${res.status})`, res.status, data?.errors);
  }
  return data;
}

export const api = {
  // overview
  overview: () => request('/overview'),
  // non-secret engine runtime settings
  settings: () => request('/settings'),
  updateSettings: (body) => request('/settings', { method: 'PATCH', body }),
  // local model (llama.cpp) config + status + restart
  localModel: () => request('/local-model'),
  updateLocalModel: (body) => request('/local-model', { method: 'PATCH', body }),
  restartLocalModel: () => request('/local-model/restart', { method: 'POST' }),
  stopLocalModel: () => request('/local-model/stop', { method: 'POST' }),
  startLocalModel: () => request('/local-model/start', { method: 'POST' }),
  // android device (Device tab)
  device: () => request('/device'),
  updateDevice: (body) => request('/device', { method: 'PATCH', body }),
  installDeviceApp: () => request('/device/install', { method: 'POST' }),
  deviceApkScans: () => request('/device/apk-scans'),
  // workflows
  workflows: () => request('/workflows'),
  workflow: (id) => request(`/workflows/${id}`),
  createWorkflow: (body) => request('/workflows', { method: 'POST', body }),
  updateWorkflow: (id, body) => request(`/workflows/${id}`, { method: 'PUT', body }),
  deleteWorkflow: (id) => request(`/workflows/${id}`, { method: 'DELETE' }),
  // steps
  steps: () => request('/steps'),
  // scans
  scans: (status) => request(`/scans${status && status !== 'all' ? `?status=${status}` : ''}`),
  scanPage: ({ status = 'all', page = 1, pageSize = 6 } = {}) => {
    const params = new URLSearchParams({ page: String(page), pageSize: String(pageSize) });
    if (status && status !== 'all') params.set('status', status);
    return request(`/scans?${params}`);
  },
  scan: (id) => request(`/scans/${id}`),
  scanVulnerabilities: (id) => request(`/scans/${id}/vulnerabilities`),
  createScan: (body) => request('/scans', { method: 'POST', body }),
  updateScan: (id, body) => request(`/scans/${id}`, { method: 'PATCH', body }),
  // model providers currently configured for the engine
  modelProviders: () => request('/model-providers'),
  // configured providers and their selectable model catalogs
  modelCatalog: () => request('/model-catalog'),
  // provider accounts, provider login sessions, and the managed OpenRouter key
  accounts: (refresh = false) => request(`/accounts${refresh ? '?refresh=1' : ''}`),
  accountSummary: () => request('/accounts/summary'),
  accountProvider: (provider, refresh = false) =>
    request(`/accounts/provider/${encodeURIComponent(provider)}${refresh ? '?refresh=1' : ''}`),
  saveProviderCredential: (provider, credential) =>
    request(`/accounts/${provider}`, { method: 'POST', body: { credential } }),
  removeProviderCredential: (provider) => request(`/accounts/${provider}`, { method: 'DELETE' }),
  removeProviderAccount: (provider, accountId) =>
    request(`/accounts/${encodeURIComponent(provider)}/account/${encodeURIComponent(accountId)}`, {
      method: 'DELETE',
    }),
  startCodexWeeklyUsage: (accountId) =>
    request(`/accounts/codex/account/${encodeURIComponent(accountId)}/start-weekly`, { method: 'POST' }),
  useCodexManualReset: (accountId) =>
    request(`/accounts/codex/account/${encodeURIComponent(accountId)}/reset`, {
      method: 'POST',
      body: { confirm: 'use-reset' },
    }),
  startProviderLogin: (provider, accountId = null) =>
    request(`/accounts/${provider}/login`, {
      method: 'POST',
      ...(accountId ? { body: { accountId } } : {}),
    }),
  providerLogin: (sessionId) => request(`/accounts/login/${sessionId}`),
  submitProviderLoginCode: (sessionId, code) =>
    request(`/accounts/login/${sessionId}/input`, { method: 'POST', body: { code } }),
  cancelProviderLogin: (sessionId) => request(`/accounts/login/${sessionId}`, { method: 'DELETE' }),
  // AI-authored workflow and post-script drafts
  createGeneration: (body) => request('/generations', { method: 'POST', body }),
  generation: (id) => request(`/generations/${id}`),
  updateScanStatus: (id, status) => request(`/scans/${id}`, { method: 'PATCH', body: { status } }),
  resumeScan: (id) => request(`/scans/${id}`, { method: 'PATCH', body: { status: 'pending' } }),
  // (re)run the APK dynamic investigation phase on a completed APK scan
  rerunDynamic: (id) => request(`/scans/${id}/rerun-dynamic`, { method: 'POST' }),
  deleteScan: (id, { force = false } = {}) =>
    request(`/scans/${id}${force ? '?force=1' : ''}`, { method: 'DELETE' }),
  // vulnerabilities
  vulnerability: (id) => request(`/vulnerabilities/${id}`),
  updateVulnerability: (id, body) => request(`/vulnerabilities/${id}`, { method: 'PATCH', body }),
  // false-positive verification (engine re-checks the finding with tools)
  verifyVulnerability: (id) => request(`/vulnerabilities/${id}/verify`, { method: 'POST' }),
  // per-vulnerability AI chat with the local model
  vulnChatHistory: (id) => request(`/vulnerabilities/${id}/chat`),
  vulnChatSend: (id, message) => request(`/vulnerabilities/${id}/chat`, { method: 'POST', body: { message } }),
  vulnChatClear: (id) => request(`/vulnerabilities/${id}/chat`, { method: 'DELETE' }),
  // per-vulnerability AI report
  vulnReport: (id) => request(`/vulnerabilities/${id}/report`),
  vulnReportGenerate: (id) => request(`/vulnerabilities/${id}/report/generate`, { method: 'POST' }),
  vulnReportSave: (id, html) => request(`/vulnerabilities/${id}/report`, { method: 'PUT', body: { html } }),
  // per-vulnerability exploit flow + verification
  vulnFlow: (id) => request(`/vulnerabilities/${id}/flow`),
  vulnFlowGenerate: (id) => request(`/vulnerabilities/${id}/flow/generate`, { method: 'POST' }),
  // local repos available to scan
  localRepos: () => request('/local-repos'),
  apkInbox: () => request('/apk/inbox'),
  scanApkExisting: (
    filename,
    {
      mode = 'static',
      thirdParty = false,
      workflow = 'triage',
      passes = 2,
      model,
      model_provider,
      harness,
      thinking_effort,
      postScriptIds,
      rankerIds,
      rankerExtra,
    } = {}
  ) =>
    request('/apk/scan-existing', {
      method: 'POST',
      body: {
        filename,
        mode,
        thirdParty,
        workflow,
        passes,
        model,
        model_provider,
        harness,
        thinking_effort,
        postScriptIds,
        rankerIds,
        rankerExtra,
      },
    }),
  uploadApkScan: async (
    file,
    {
      mode = 'static',
      thirdParty = false,
      workflow = 'triage',
      passes = 2,
      model,
      model_provider,
      harness,
      thinking_effort,
      postScriptIds,
      rankerIds,
      rankerExtra,
    } = {}
  ) => {
    const q = new URLSearchParams({
      filename: file.name,
      mode,
      thirdParty: thirdParty ? '1' : '0',
      workflow,
      passes: String(passes),
    });
    // Optional model / post-script / ranker overrides (pentest tabs); omit when unset.
    if (model) q.set('model', model);
    if (model_provider) q.set('model_provider', model_provider);
    if (harness) q.set('harness', harness);
    if (thinking_effort) q.set('thinking_effort', thinking_effort);
    if (postScriptIds) q.set('postScriptIds', postScriptIds);
    if (rankerIds) q.set('rankerIds', rankerIds);
    if (rankerExtra) q.set('rankerExtra', rankerExtra);
    const res = await fetch(`${BASE}/api/apk/scan?${q.toString()}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/octet-stream' },
      body: file,
    });
    let data = null;
    try {
      data = await res.json();
    } catch {
      /* no body */
    }
    if (!res.ok) throw new ApiError(data?.error || 'APK upload failed.', res.status, data?.errors);
    return data;
  },
  // post-scripts
  postScripts: () => request('/post-scripts'),
  postScript: (id) => request(`/post-scripts/${id}`),
  createPostScript: (body) => request('/post-scripts', { method: 'POST', body }),
  updatePostScript: (id, body) => request(`/post-scripts/${id}`, { method: 'PUT', body }),
  deletePostScript: (id) => request(`/post-scripts/${id}`, { method: 'DELETE' }),
  // agent skills
  agentSkills: () => request('/agent-skills'),
  agentSkill: (id) => request(`/agent-skills/${id}`),
  createAgentSkill: (body) => request('/agent-skills', { method: 'POST', body }),
  updateAgentSkill: (id, body) => request(`/agent-skills/${id}`, { method: 'PUT', body }),
  deleteAgentSkill: (id) => request(`/agent-skills/${id}`, { method: 'DELETE' }),
  // severity rankers
  severityRankers: () => request('/severity-rankers'),
  severityRanker: (id) => request(`/severity-rankers/${id}`),
  createSeverityRanker: (body) => request('/severity-rankers', { method: 'POST', body }),
  updateSeverityRanker: (id, body) => request(`/severity-rankers/${id}`, { method: 'PUT', body }),
  deleteSeverityRanker: (id) => request(`/severity-rankers/${id}`, { method: 'DELETE' }),
};
