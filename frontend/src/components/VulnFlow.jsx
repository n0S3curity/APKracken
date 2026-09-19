import { useEffect, useMemo, useState } from 'react';
import { api, apiErrorMessages } from '../api/client.js';

const KIND = {
  entry: { label: 'ENTRY', icon: '🚪', color: 'var(--accent)' },
  validation: { label: 'CHECK', icon: '🛡', color: 'var(--pend)' },
  step: { label: 'STEP', icon: '↓', color: 'var(--text-3)' },
  sink: { label: 'SINK', icon: '🎯', color: 'var(--fail)' },
};
const kindMeta = (k) => KIND[k] || KIND.step;

const STATUS = {
  risk: { color: 'var(--fail)', dot: '✕' },
  ok: { color: 'var(--ok)', dot: '✓' },
  info: { color: 'var(--text-3)', dot: '•' },
};

// Parse a legacy trigger_flow hop ("path:line symbol - behavior") into a flow node.
function parseHop(h, i, n) {
  const s = String(h || '');
  const dash = s.indexOf(' - ');
  const left = dash >= 0 ? s.slice(0, dash) : s;
  const desc = dash >= 0 ? s.slice(dash + 3) : '';
  const m = left.match(/([\w./$-]+):(\d+)\s*(.*)/);
  let file = null;
  let line = null;
  let sym = left;
  if (m) {
    file = m[1];
    line = Number(m[2]);
    sym = (m[3] || '').trim() || m[1];
  }
  return {
    title: sym || `Step ${i + 1}`,
    kind: i === 0 ? 'entry' : i === n - 1 ? 'sink' : 'step',
    file,
    line,
    code: '',
    description: desc,
  };
}

export default function VulnFlow({ vuln, scan, openFile }) {
  const ja = vuln?.jsonAnswer && typeof vuln.jsonAnswer === 'object' ? vuln.jsonAnswer : {};
  const [flow, setFlow] = useState(null);
  const [verifications, setVerifications] = useState(null);
  const [generating, setGenerating] = useState(false);
  const [error, setError] = useState(null);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    let alive = true;
    setLoaded(false);
    setError(null);
    api
      .vulnFlow(vuln.id)
      .then((d) => {
        if (!alive) return;
        setFlow(Array.isArray(d?.flow) ? d.flow : null);
        setVerifications(Array.isArray(d?.verifications) ? d.verifications : null);
      })
      .catch(() => {})
      .finally(() => alive && setLoaded(true));
    return () => {
      alive = false;
    };
  }, [vuln.id]);

  // Fall back to the finding's own trigger_flow until a detailed flow is generated.
  const displayedFlow = useMemo(() => {
    if (flow && flow.length) return flow;
    const tf = Array.isArray(ja.trigger_flow) ? ja.trigger_flow : Array.isArray(vuln.trigger_flow) ? vuln.trigger_flow : [];
    if (tf.length) return tf.map((h, i) => parseHop(h, i, tf.length));
    return [];
  }, [flow, ja.trigger_flow, vuln.trigger_flow]);

  // Deterministic verification facts straight from the finding's manifest intel.
  const detVerif = useMemo(() => {
    const rows = [];
    if (ja.exported != null)
      rows.push({ check: 'Exported', result: ja.exported ? 'true' : 'false', status: ja.exported ? 'risk' : 'ok', detail: ja.exported ? 'Reachable directly by any app / adb.' : 'Not exported — needs a chain to reach.' });
    if (ja.reachability)
      rows.push({ check: 'Reachability', result: String(ja.reachability), status: ja.reachability === 'direct' ? 'risk' : ja.reachability === 'internal' ? 'ok' : 'info', detail: '' });
    if (ja.grant_uri_permissions != null)
      rows.push({ check: 'URI grant permissions', result: `grantUriPermissions=${ja.grant_uri_permissions}`, status: ja.grant_uri_permissions ? 'risk' : 'info', detail: ja.grant_uri_permissions ? 'Can hand out content:// URI grants.' : '' });
    if (ja.authorities) rows.push({ check: 'Provider authority', result: String(ja.authorities), status: 'info', detail: '' });
    return rows;
  }, [ja.exported, ja.reachability, ja.grant_uri_permissions, ja.authorities]);

  const mergedVerif = useMemo(() => {
    const seen = new Set(detVerif.map((r) => r.check.toLowerCase()));
    const extra = (verifications || []).filter((r) => r && r.check && !seen.has(String(r.check).toLowerCase()));
    return [...detVerif, ...extra];
  }, [detVerif, verifications]);

  const generate = async () => {
    setGenerating(true);
    setError(null);
    try {
      const d = await api.vulnFlowGenerate(vuln.id);
      setFlow(Array.isArray(d?.flow) ? d.flow : []);
      setVerifications(Array.isArray(d?.verifications) ? d.verifications : []);
    } catch (e) {
      setError(apiErrorMessages(e)[0] || 'Flow generation failed. Is the local model running?');
    } finally {
      setGenerating(false);
    }
  };

  const open = (node) => {
    if (node.file && scan?.commitSha && openFile) openFile({ file: node.file, line: node.line || null });
  };

  const heading = { fontSize: 12, textTransform: 'uppercase', letterSpacing: 0.7, color: 'var(--text-3)', margin: '0 0 12px', fontWeight: 600 };

  return (
    <div style={{ marginBottom: 30 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10, marginBottom: 12 }}>
        <h3 style={{ ...heading, margin: 0 }}>Exploit flow</h3>
        <button
          type="button"
          onClick={generate}
          disabled={generating}
          style={{ fontSize: 11.5, fontWeight: 600, padding: '5px 12px', borderRadius: 8, border: 0, cursor: generating ? 'default' : 'pointer', background: generating ? 'var(--surface-2)' : 'var(--accent)', color: generating ? 'var(--text-3)' : '#fff' }}
        >
          {generating ? 'Generating…' : flow && flow.length ? 'Regenerate' : 'Generate detailed flow'}
        </button>
      </div>

      {error && <div style={{ fontSize: 12, color: 'var(--fail)', marginBottom: 10 }}>{error}</div>}

      {displayedFlow.length === 0 && !generating && (
        <div style={{ fontSize: 12.5, color: 'var(--text-3)', marginBottom: 18 }}>
          No flow yet — click “Generate detailed flow” to have the model map the vulnerability from entry point to sink.
        </div>
      )}

      {displayedFlow.length > 0 && (
        <div style={{ marginBottom: 24 }}>
          {displayedFlow.map((node, i) => {
            const meta = kindMeta(node.kind);
            const clickable = !!(node.file && scan?.commitSha);
            const last = i === displayedFlow.length - 1;
            return (
              <div key={i} style={{ display: 'flex', gap: 14, alignItems: 'stretch' }}>
                {/* rail */}
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', flex: 'none', width: 26 }}>
                  <div style={{ width: 26, height: 26, borderRadius: '50%', background: meta.color, color: '#fff', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 12, flex: 'none' }}>
                    {i + 1}
                  </div>
                  {!last && <div style={{ width: 2, flex: 1, background: 'var(--border-2)', minHeight: 14 }} />}
                </div>
                {/* card */}
                <div
                  onClick={() => clickable && open(node)}
                  style={{
                    flex: 1,
                    minWidth: 0,
                    marginBottom: 12,
                    border: `1px solid ${node.kind === 'sink' ? 'var(--fail)' : 'var(--border)'}`,
                    borderRadius: 10,
                    background: 'var(--surface)',
                    padding: '11px 14px',
                    cursor: clickable ? 'pointer' : 'default',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', marginBottom: 5 }}>
                    <span style={{ fontSize: 10, fontWeight: 700, color: '#fff', background: meta.color, padding: '2px 7px', borderRadius: 10, letterSpacing: 0.5 }}>
                      {meta.label}
                    </span>
                    <span style={{ fontSize: 13.5, fontWeight: 600, color: 'var(--text)' }}>{node.title}</span>
                    {clickable && (
                      <span className="mono" style={{ marginLeft: 'auto', fontSize: 11, color: 'var(--accent)' }}>
                        {shortFile(node.file)}
                        {node.line ? `:${node.line}` : ''} ↗
                      </span>
                    )}
                  </div>
                  {node.description && (
                    <div style={{ fontSize: 12.5, color: 'var(--text-2)', lineHeight: 1.5 }}>{node.description}</div>
                  )}
                  {node.code && String(node.code).trim() && (
                    <pre style={{ margin: '8px 0 0', background: 'var(--code-bg)', border: '1px solid var(--border-2)', borderRadius: 6, padding: '7px 10px', fontSize: 11.5, overflowX: 'auto', whiteSpace: 'pre-wrap', color: 'var(--text)' }}>
                      <code style={{ fontFamily: "'Geist Mono', ui-monospace, monospace" }}>{node.code}</code>
                    </pre>
                  )}
                  {clickable && (
                    <div style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 6 }}>Click to view the full file with this line marked →</div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Verification */}
      {mergedVerif.length > 0 && (
        <>
          <h3 style={heading}>Verification</h3>
          <div style={{ border: '1px solid var(--border)', borderRadius: 10, background: 'var(--surface)', overflow: 'hidden' }}>
            {mergedVerif.map((r, i) => {
              const st = STATUS[r.status] || STATUS.info;
              return (
                <div key={i} style={{ display: 'flex', gap: 12, padding: '10px 14px', borderBottom: i < mergedVerif.length - 1 ? '1px solid var(--border-2)' : 'none', alignItems: 'flex-start' }}>
                  <span style={{ color: st.color, flex: 'none', width: 16, textAlign: 'center', fontWeight: 700 }}>{st.dot}</span>
                  <div style={{ flex: 'none', width: 160, fontSize: 12.5, fontWeight: 600, color: 'var(--text)' }}>{r.check}</div>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div className="mono" style={{ fontSize: 12, color: st.color, wordBreak: 'break-word' }}>{r.result}</div>
                    {r.detail && <div style={{ fontSize: 11.5, color: 'var(--text-3)', marginTop: 2 }}>{r.detail}</div>}
                  </div>
                </div>
              );
            })}
          </div>
        </>
      )}
    </div>
  );
}

function shortFile(f) {
  const s = String(f || '');
  const parts = s.split('/');
  return parts.length > 2 ? '…/' + parts.slice(-2).join('/') : s;
}
