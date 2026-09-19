import { useEffect, useRef, useState } from 'react';
import { api, apiErrorMessages } from '../api/client.js';

const VERDICT = {
  exploitable: { label: 'Exploitable', color: 'var(--ok)', icon: '✅' },
  needs_conditions: { label: 'Needs conditions', color: 'var(--pend)', icon: '⚙' },
  false_positive: { label: 'Likely false positive', color: 'var(--fail)', icon: '⚠' },
  error: { label: 'Verification error', color: 'var(--text-3)', icon: '—' },
};

// Shows the false-positive adjudicator's verdict for a finding + a button to (re)run it.
export default function VulnVerdict({ vuln, reload }) {
  const ja = vuln?.jsonAnswer && typeof vuln.jsonAnswer === 'object' ? vuln.jsonAnswer : {};
  const verdict = ja.fp_verdict;
  const requested = ja.fp_verify_requested === true;
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const pollRef = useRef(null);

  const pending = requested || busy;

  // Poll for the verdict while a verification is in flight.
  useEffect(() => {
    if (!pending) return undefined;
    pollRef.current = setInterval(() => reload && reload(), 3000);
    return () => clearInterval(pollRef.current);
  }, [pending, reload]);

  useEffect(() => {
    if (ja.fp_checked_at) setBusy(false);
  }, [ja.fp_checked_at]);

  const verify = async () => {
    setBusy(true);
    setError(null);
    try {
      await api.verifyVulnerability(vuln.id);
      reload && reload();
    } catch (e) {
      setError(apiErrorMessages(e)[0] || 'Verify request failed.');
      setBusy(false);
    }
  };

  const meta = VERDICT[verdict];
  const blockers = Array.isArray(ja.fp_blockers) ? ja.fp_blockers.filter(Boolean) : [];

  return (
    <div
      style={{
        border: `1px solid ${meta ? meta.color : 'var(--border)'}`,
        borderRadius: 12,
        background: 'var(--surface)',
        padding: '12px 16px',
        marginBottom: 22,
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
        {meta ? (
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 7, fontSize: 13, fontWeight: 700, color: '#fff', background: meta.color, padding: '4px 12px', borderRadius: 20 }}>
            {meta.icon} {meta.label}
          </span>
        ) : (
          <span style={{ fontSize: 12.5, color: 'var(--text-3)' }}>Exploitability not verified yet</span>
        )}
        {ja.fp_confidence && <span style={{ fontSize: 11.5, color: 'var(--text-3)' }}>confidence: {ja.fp_confidence}</span>}
        {ja.fp_reachable === false && <span style={{ fontSize: 11.5, color: 'var(--fail)' }}>not reachable</span>}
        <button
          type="button"
          onClick={verify}
          disabled={pending}
          style={{
            marginLeft: 'auto',
            fontSize: 12,
            fontWeight: 600,
            padding: '5px 12px',
            borderRadius: 8,
            border: 0,
            cursor: pending ? 'default' : 'pointer',
            background: pending ? 'var(--surface-2)' : 'var(--accent)',
            color: pending ? 'var(--text-3)' : '#fff',
          }}
        >
          {pending ? 'Verifying…' : meta ? 'Re-verify' : 'Verify (FP check)'}
        </button>
      </div>

      {pending && (
        <div style={{ fontSize: 12, color: 'var(--text-3)', marginTop: 8 }}>
          Re-checking like a researcher — reading the source, tracing reachability, inspecting guards… (needs the local model running)
        </div>
      )}

      {error && <div style={{ fontSize: 12, color: 'var(--fail)', marginTop: 8 }}>{error}</div>}

      {ja.fp_reason && !pending && (
        <div style={{ fontSize: 13, color: 'var(--text)', lineHeight: 1.5, marginTop: 10 }}>{ja.fp_reason}</div>
      )}

      {blockers.length > 0 && !pending && (
        <div style={{ marginTop: 8 }}>
          <div style={{ fontSize: 11, textTransform: 'uppercase', letterSpacing: 0.5, color: 'var(--text-3)', marginBottom: 3 }}>
            Exploitation blockers
          </div>
          <ul style={{ margin: 0, paddingLeft: 18 }}>
            {blockers.map((b, i) => (
              <li key={i} style={{ fontSize: 12.5, color: 'var(--text-2)', lineHeight: 1.5 }}>{b}</li>
            ))}
          </ul>
        </div>
      )}

      {ja.fp_bypass_needed && !pending && (
        <div style={{ fontSize: 12.5, color: 'var(--text-2)', marginTop: 8 }}>
          <span style={{ color: 'var(--pend)', fontWeight: 600 }}>Bypass needed: </span>
          {ja.fp_bypass_needed}
        </div>
      )}
    </div>
  );
}
