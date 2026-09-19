import { useEffect, useMemo, useRef, useState } from 'react';
import CopyButton from './CopyButton.jsx';

// The engine serves decompiled sources over a local HTTP endpoint (host-only data the backend
// container can't read). Default port 9011; override with VITE_SOURCE_PORT.
const SOURCE_PORT = import.meta.env.VITE_SOURCE_PORT || 9011;

export default function FullFileModal({ file, sha, highlightLine, onClose }) {
  const [content, setContent] = useState(null);
  const [error, setError] = useState(null);
  const lineRef = useRef(null);

  useEffect(() => {
    if (!file || !sha) return undefined;
    let alive = true;
    setContent(null);
    setError(null);
    const proto = window.location.protocol === 'https:' ? 'https' : 'http';
    const url = `${proto}://${window.location.hostname}:${SOURCE_PORT}/source?sha=${encodeURIComponent(sha)}&path=${encodeURIComponent(file)}`;
    fetch(url)
      .then((r) => {
        if (!r.ok) throw new Error(r.status === 404 ? 'File not found in the decompiled workspace.' : `HTTP ${r.status}`);
        return r.text();
      })
      .then((t) => {
        if (alive) setContent(t);
      })
      .catch((e) => {
        if (alive) setError(e.message === 'Failed to fetch' ? 'Could not reach the engine source server (is the engine running?).' : e.message);
      });
    return () => {
      alive = false;
    };
  }, [file, sha]);

  useEffect(() => {
    const onEsc = (e) => e.key === 'Escape' && onClose();
    window.addEventListener('keydown', onEsc);
    return () => window.removeEventListener('keydown', onEsc);
  }, [onClose]);

  // Scroll the highlighted line into view once content loads.
  useEffect(() => {
    if (content && lineRef.current) {
      lineRef.current.scrollIntoView({ block: 'center' });
    }
  }, [content]);

  const lines = useMemo(() => (content ? content.split('\n') : []), [content]);

  return (
    <div
      onClick={onClose}
      style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.55)', backdropFilter: 'blur(2px)', zIndex: 1000, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 24 }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{ width: 'min(1000px, 96vw)', height: 'min(84vh, 900px)', display: 'flex', flexDirection: 'column', background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 12, boxShadow: '0 0 0 1px rgba(140,140,150,0.30), 0 24px 70px rgba(0,0,0,0.6)', overflow: 'hidden' }}
      >
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, padding: '12px 16px', borderBottom: '1px solid var(--border-2)' }}>
          <div className="mono" style={{ fontSize: 12, color: 'var(--text-2)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {file}
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flex: 'none' }}>
            {content != null && <CopyButton text={content} label="Copy file" />}
            <button
              type="button"
              onClick={onClose}
              style={{ border: '1px solid var(--border-2)', background: 'var(--surface)', color: 'var(--text-2)', borderRadius: 7, fontSize: 12, padding: '4px 10px', cursor: 'pointer' }}
            >
              Close
            </button>
          </div>
        </div>
        <div style={{ flex: 1, overflow: 'auto', background: 'var(--code-bg)' }}>
          {error && <div style={{ padding: 20, color: 'var(--fail)', fontSize: 12.5 }}>{error}</div>}
          {!error && content == null && <div style={{ padding: 20, color: 'var(--text-3)', fontSize: 12.5 }}>Loading…</div>}
          {content != null && (
            <pre style={{ margin: 0, fontSize: 12, lineHeight: 1.55, fontFamily: "'Geist Mono', ui-monospace, monospace" }}>
              {lines.map((ln, i) => {
                const num = i + 1;
                const hit = highlightLine && num === highlightLine;
                return (
                  <div
                    key={i}
                    ref={hit ? lineRef : null}
                    style={{ display: 'flex', background: hit ? 'var(--accent-subtle)' : 'transparent', padding: '0 12px' }}
                  >
                    <span style={{ width: 52, flex: 'none', textAlign: 'right', paddingRight: 14, color: 'var(--text-3)', userSelect: 'none' }}>{num}</span>
                    <span style={{ whiteSpace: 'pre', color: 'var(--text)' }}>{ln || ' '}</span>
                  </div>
                );
              })}
            </pre>
          )}
        </div>
      </div>
    </div>
  );
}
