import { useEffect, useRef, useState } from 'react';
import { api, apiErrorMessages } from '../api/client.js';
import { useConfirm } from './ConfirmProvider.jsx';

// Document styling — shared by the on-screen editor, the print (PDF) window, and the DOCX
// export so all three look identical. Always a white "paper" look (printable), theme-independent.
const REPORT_CSS = `
.report-doc { background:#fff; color:#111; font-family: Georgia, 'Times New Roman', serif; font-size:12pt; line-height:1.55; }
.report-doc h1 { font-size:21pt; margin:0 0 6pt; color:#111; }
.report-doc h2 { font-size:14pt; margin:18pt 0 6pt; border-bottom:1px solid #ccc; padding-bottom:3pt; color:#111; }
.report-doc h3 { font-size:12pt; margin:12pt 0 4pt; color:#111; }
.report-doc p { margin:0 0 8pt; }
.report-doc ul, .report-doc ol { margin:0 0 8pt 22pt; padding:0; }
.report-doc li { margin:2pt 0; }
.report-doc pre { background:#f4f4f6; border:1px solid #ddd; border-radius:4px; padding:10px 12px; overflow-x:auto; font-family:'Consolas','Courier New',monospace; font-size:10.5pt; line-height:1.45; white-space:pre-wrap; word-break:break-word; }
.report-doc code { font-family:'Consolas','Courier New',monospace; }
.report-doc table { border-collapse:collapse; margin:0 0 8pt; }
.report-doc th, .report-doc td { border:1px solid #ccc; padding:5px 9px; text-align:left; font-size:11pt; }
.report-doc strong { color:#000; }
.report-doc a { color:#1a56db; }
`;

const TOOLBAR = [
  ['Bold', () => document.execCommand('bold')],
  ['Italic', () => document.execCommand('italic')],
  ['H1', () => document.execCommand('formatBlock', false, 'H1')],
  ['H2', () => document.execCommand('formatBlock', false, 'H2')],
  ['H3', () => document.execCommand('formatBlock', false, 'H3')],
  ['¶', () => document.execCommand('formatBlock', false, 'P')],
  ['• List', () => document.execCommand('insertUnorderedList')],
  ['1. List', () => document.execCommand('insertOrderedList')],
  ['Code', () => document.execCommand('formatBlock', false, 'PRE')],
];

function download(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

export default function ReportEditor({ vulnId, vulnName }) {
  const editorRef = useRef(null);
  const [loaded, setLoaded] = useState(false);
  const [hasReport, setHasReport] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [saving, setSaving] = useState(false);
  const [dirty, setDirty] = useState(false);
  const [error, setError] = useState(null);
  const [savedAt, setSavedAt] = useState(null);
  const confirm = useConfirm();

  const setHtml = (html) => {
    if (editorRef.current) editorRef.current.innerHTML = html || '';
  };

  useEffect(() => {
    let alive = true;
    setLoaded(false);
    setError(null);
    api
      .vulnReport(vulnId)
      .then((data) => {
        if (!alive) return;
        if (data?.html) {
          setHasReport(true);
          setHtml(data.html);
          setSavedAt(data.updatedAt || null);
        } else {
          setHasReport(false);
        }
      })
      .catch(() => {})
      .finally(() => alive && setLoaded(true));
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [vulnId]);

  const filename = (ext) =>
    `report-${String(vulnName || 'vulnerability').replace(/[^A-Za-z0-9._-]+/g, '_').slice(0, 60)}.${ext}`;

  const generate = async () => {
    if (hasReport && dirty) {
      const ok = await confirm({
        title: 'Regenerate report',
        message: 'Replace the current report with a freshly generated one? Unsaved edits will be lost.',
        confirmLabel: 'Regenerate',
        danger: true,
      });
      if (!ok) return;
    }
    setGenerating(true);
    setError(null);
    try {
      const data = await api.vulnReportGenerate(vulnId);
      setHtml(data.html);
      setHasReport(true);
      setDirty(false);
      setSavedAt(data.updatedAt || null);
    } catch (e) {
      setError(apiErrorMessages(e)[0] || 'Generation failed. Is the local model running?');
    } finally {
      setGenerating(false);
    }
  };

  const save = async () => {
    if (!editorRef.current) return;
    setSaving(true);
    setError(null);
    try {
      const data = await api.vulnReportSave(vulnId, editorRef.current.innerHTML);
      setDirty(false);
      setSavedAt(data.updatedAt || new Date().toISOString());
    } catch (e) {
      setError(apiErrorMessages(e)[0] || 'Save failed.');
    } finally {
      setSaving(false);
    }
  };

  const wrapped = () =>
    `<!DOCTYPE html><html><head><meta charset="utf-8"><style>${REPORT_CSS}</style></head><body><div class="report-doc" style="max-width:800px;margin:0 auto;padding:24px;">${
      editorRef.current?.innerHTML || ''
    }</div></body></html>`;

  const exportPdf = () => {
    const w = window.open('', '_blank');
    if (!w) {
      setError('Popup blocked — allow popups to export PDF.');
      return;
    }
    w.document.write(wrapped());
    w.document.close();
    w.focus();
    setTimeout(() => w.print(), 300);
  };

  const exportDocx = async () => {
    setError(null);
    try {
      // DOCX is generated server-side (reliable Node conversion); we POST the current HTML.
      const res = await fetch(`/api/vulnerabilities/${vulnId}/report/docx`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ html: editorRef.current?.innerHTML || '' }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      download(await res.blob(), filename('docx'));
    } catch (e) {
      setError('DOCX export failed. Try PDF instead.');
    }
  };

  const btn = (label, onClick, opts = {}) => (
    <button
      type="button"
      onClick={onClick}
      disabled={opts.disabled}
      style={{
        fontSize: 12,
        fontWeight: opts.primary ? 600 : 500,
        padding: '6px 12px',
        borderRadius: 8,
        cursor: opts.disabled ? 'default' : 'pointer',
        border: opts.primary ? 0 : '1px solid var(--border)',
        background: opts.primary ? (opts.disabled ? 'var(--surface-2)' : 'var(--accent)') : 'var(--surface)',
        color: opts.primary ? (opts.disabled ? 'var(--text-3)' : '#fff') : 'var(--text-2)',
      }}
    >
      {label}
    </button>
  );

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      <style>{REPORT_CSS}</style>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
        {btn(generating ? 'Generating…' : hasReport ? 'Regenerate' : 'Generate', generate, {
          primary: !hasReport,
          disabled: generating,
        })}
        {btn(saving ? 'Saving…' : 'Save', save, { primary: hasReport, disabled: saving || !hasReport })}
        <div style={{ width: 1, height: 22, background: 'var(--border-2)', margin: '0 2px' }} />
        {btn('Export PDF', exportPdf, { disabled: !hasReport })}
        {btn('Export DOCX', exportDocx, { disabled: !hasReport })}
        <span style={{ marginLeft: 'auto', fontSize: 11, color: dirty ? 'var(--pend)' : 'var(--text-3)' }}>
          {dirty ? 'unsaved edits' : savedAt ? `saved ${new Date(savedAt).toLocaleString()}` : ''}
        </span>
      </div>

      {error && <div style={{ fontSize: 12, color: 'var(--fail)' }}>{error}</div>}

      {loaded && !hasReport && !generating && (
        <div style={{ textAlign: 'center', padding: '30px 20px', color: 'var(--text-2)', fontSize: 13.5, lineHeight: 1.5 }}>
          <div style={{ fontSize: 30, marginBottom: 8 }}>📄</div>
          Generate a bug-bounty vulnerability report for this finding — the model uses the code, the PoC, the
          dynamic evidence, and the tested device. You can then edit it inline and export to PDF or DOCX.
        </div>
      )}

      {generating && (
        <div style={{ textAlign: 'center', padding: '30px 20px', color: 'var(--text-3)', fontSize: 13 }}>
          Writing the report… this can take a moment on the local model.
        </div>
      )}

      {/* Formatting toolbar (only meaningful when a report exists) */}
      {hasReport && !generating && (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, padding: '6px 8px', border: '1px solid var(--border-2)', borderRadius: 8, background: 'var(--surface-2)' }}>
          {TOOLBAR.map(([label, fn]) => (
            <button
              key={label}
              type="button"
              onMouseDown={(e) => {
                e.preventDefault();
                fn();
                setDirty(true);
              }}
              style={{ fontSize: 11.5, padding: '4px 9px', borderRadius: 6, border: '1px solid var(--border-2)', background: 'var(--surface)', color: 'var(--text-2)', cursor: 'pointer', minWidth: 30 }}
            >
              {label}
            </button>
          ))}
        </div>
      )}

      {/* The editable document */}
      <div
        style={{
          display: hasReport && !generating ? 'block' : 'none',
          maxHeight: '62vh',
          overflowY: 'auto',
          background: 'var(--surface-2)',
          borderRadius: 10,
          padding: 20,
        }}
      >
        <div
          ref={editorRef}
          className="report-doc"
          contentEditable
          suppressContentEditableWarning
          onInput={() => setDirty(true)}
          style={{
            background: '#fff',
            maxWidth: 800,
            margin: '0 auto',
            padding: '40px 48px',
            minHeight: 400,
            boxShadow: '0 2px 14px rgba(0,0,0,0.25)',
            borderRadius: 3,
            outline: 'none',
          }}
        />
      </div>
    </div>
  );
}
