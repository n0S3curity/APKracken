import { createContext, useCallback, useContext, useMemo, useRef, useState } from 'react';

import { Button } from './ui.jsx';
import { useModalDialog } from '../lib/useModalDialog.js';

// A designed replacement for window.confirm(). Because a styled modal resolves
// asynchronously (on a button click), the hook returns a Promise<boolean>:
//   const confirm = useConfirm();
//   if (!(await confirm({ title, message, danger }))) return;

const ConfirmContext = createContext(null);

export function useConfirm() {
  const confirm = useContext(ConfirmContext);
  if (!confirm) throw new Error('useConfirm must be used within <ConfirmProvider>');
  return confirm;
}

export function ConfirmProvider({ children }) {
  const [state, setState] = useState(null); // { options, resolve } | null
  const resolveRef = useRef(null);

  const confirm = useCallback((options = {}) => {
    return new Promise((resolve) => {
      resolveRef.current = resolve;
      setState({ options: typeof options === 'string' ? { message: options } : options });
    });
  }, []);

  const settle = useCallback((result) => {
    const resolve = resolveRef.current;
    resolveRef.current = null;
    setState(null);
    if (resolve) resolve(result);
  }, []);

  const value = useMemo(() => confirm, [confirm]);

  return (
    <ConfirmContext.Provider value={value}>
      {children}
      {state && <ConfirmDialog options={state.options} onResolve={settle} />}
    </ConfirmContext.Provider>
  );
}

function ConfirmDialog({ options, onResolve }) {
  const {
    title = 'Please confirm',
    message = '',
    confirmLabel = 'Confirm',
    cancelLabel = 'Cancel',
    danger = false,
  } = options;
  const dialogRef = useModalDialog(() => onResolve(false));

  return (
    <div
      onClick={() => onResolve(false)}
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 1000,
        background: 'rgba(0,0,0,.55)',
        backdropFilter: 'blur(2px)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: 20,
      }}
    >
      <div
        ref={dialogRef}
        role="alertdialog"
        aria-modal="true"
        aria-labelledby="confirm-title"
        tabIndex={-1}
        onClick={(e) => e.stopPropagation()}
        style={{
          width: 440,
          maxWidth: '100%',
          background: 'var(--surface)',
          border: '1px solid var(--border)',
          borderRadius: 14,
          // A light ring + strong drop shadow so the card clearly separates from the
          // darkened page in both light and dark themes.
          boxShadow: '0 0 0 1px rgba(140,140,150,0.30), 0 24px 70px rgba(0,0,0,0.6)',
          overflow: 'hidden',
        }}
      >
        <div style={{ padding: '18px 22px 6px' }}>
          <div id="confirm-title" style={{ fontSize: 16, fontWeight: 600, color: 'var(--text)' }}>
            {title}
          </div>
        </div>
        <div
          style={{
            padding: '6px 22px 20px',
            fontSize: 13.5,
            lineHeight: 1.55,
            color: 'var(--text-2)',
            whiteSpace: 'pre-wrap',
          }}
        >
          {message}
        </div>
        <div
          style={{
            display: 'flex',
            justifyContent: 'flex-end',
            gap: 10,
            padding: '14px 22px',
            borderTop: '1px solid var(--border-2)',
            background: 'var(--surface-2)',
          }}
        >
          <Button variant="subtle" style={{ height: 34 }} onClick={() => onResolve(false)}>
            {cancelLabel}
          </Button>
          <Button
            variant={danger ? 'danger' : 'primary'}
            style={{ height: 34 }}
            data-autofocus
            onClick={() => onResolve(true)}
          >
            {confirmLabel}
          </Button>
        </div>
      </div>
    </div>
  );
}
