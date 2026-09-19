import { useState } from 'react';

// Small "Copy" button for code / payload / adb fields. Copies `text` to the clipboard
// and briefly shows a confirmation.
export default function CopyButton({ text, label = 'Copy', title, style }) {
  const [copied, setCopied] = useState(false);
  const value = text == null ? '' : String(text);

  const copy = async (e) => {
    e.preventDefault();
    e.stopPropagation();
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(value);
      } else {
        const ta = document.createElement('textarea');
        ta.value = value;
        ta.style.position = 'fixed';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
      }
      setCopied(true);
      setTimeout(() => setCopied(false), 1400);
    } catch {
      /* clipboard blocked — ignore */
    }
  };

  return (
    <button
      type="button"
      onClick={copy}
      title={title || 'Copy to clipboard'}
      disabled={!value}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 5,
        height: 24,
        padding: '0 9px',
        borderRadius: 6,
        border: '1px solid var(--border)',
        background: copied ? 'var(--ok-bg, var(--surface-2))' : 'var(--surface-2)',
        color: copied ? 'var(--ok)' : 'var(--text-2)',
        fontSize: 11,
        fontWeight: 600,
        cursor: value ? 'pointer' : 'default',
        whiteSpace: 'nowrap',
        ...style,
      }}
    >
      {copied ? '✓ Copied' : `⧉ ${label}`}
    </button>
  );
}
