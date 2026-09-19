import { useEffect, useState } from 'react';

// Format a millisecond duration as H:MM:SS (or M:SS under an hour).
export function formatDuration(ms) {
  if (ms == null || !Number.isFinite(ms) || ms < 0) return '0:00';
  const total = Math.floor(ms / 1000);
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  const ss = String(s).padStart(2, '0');
  if (h > 0) return `${h}:${String(m).padStart(2, '0')}:${ss}`;
  return `${m}:${ss}`;
}

// Derive timing state from a serialized scan. `active` covers the base run AND the APK
// specialist/dynamic investigation phase that runs after status flips to 'completed'.
export function scanTiming(scan) {
  const status = scan?.status;
  const investigationDone = scan?.reasoning?.dynamic_investigation === 'done';
  const investigating = scan?.repoKind === 'apk' && status === 'completed' && !investigationDone;
  const active = ['prewarming_cache', 'running', 'post_processing'].includes(status) || investigating;

  let start = scan?.insertedAt ? new Date(scan.insertedAt).getTime() : null;
  if (scan?.lastResumedAt) {
    // A resumed run should time from the resume, not the original creation.
    const r = new Date(scan.lastResumedAt).getTime();
    if (Number.isFinite(r) && (start == null || r > start)) start = r;
  }
  const end = scan?.updatedAt ? new Date(scan.updatedAt).getTime() : null;
  const done = !active && ['completed', 'stopped', 'failed'].includes(status);
  return { active, start, end, done, failed: status === 'failed' };
}

// A rotating ring drawn in the current run colour.
function TimerRing() {
  return (
    <svg width="14" height="14" viewBox="0 0 14 14" style={{ animation: 'okspin 1.4s linear infinite', flex: 'none' }}>
      <circle cx="7" cy="7" r="5.4" fill="none" stroke="var(--run)" strokeOpacity="0.25" strokeWidth="1.6" />
      <path d="M7 1.6 a5.4 5.4 0 0 1 5.4 5.4" fill="none" stroke="var(--run)" strokeWidth="1.6" strokeLinecap="round" />
    </svg>
  );
}

// Live animated timer while a scan is active; a static "Total time" pill once it finishes.
export default function ScanTimer({ scan, label = 'Total time' }) {
  const { active, start, end, done, failed } = scanTiming(scan);
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    if (!active) return undefined;
    setNow(Date.now());
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, [active]);

  if (start == null || (!active && !done)) return null;
  const stop = active ? now : end ?? now;
  const ms = Math.max(0, stop - start);
  const digits = formatDuration(ms);

  if (active) {
    return (
      <span
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: 8,
          padding: '4px 11px',
          borderRadius: 20,
          border: '1px solid var(--run)',
          background: 'var(--run-bg)',
          animation: 'oktimerpulse 2.4s ease-in-out infinite',
        }}
        title="Elapsed time"
      >
        <TimerRing />
        <span
          key={Math.floor(ms / 1000)}
          className="mono"
          style={{
            fontSize: 12.5,
            fontWeight: 600,
            color: 'var(--run)',
            fontVariantNumeric: 'tabular-nums',
            letterSpacing: 0.5,
            animation: 'oktimertick .3s ease',
          }}
        >
          {digits}
        </span>
      </span>
    );
  }

  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 7,
        padding: '4px 11px',
        borderRadius: 20,
        border: '1px solid var(--border-2)',
        background: 'var(--surface-2)',
      }}
      title={failed ? 'Ran before failing' : 'Total run time'}
    >
      <span style={{ fontSize: 12.5, lineHeight: 1, filter: failed ? 'grayscale(1)' : 'none' }}>⏱</span>
      <span style={{ fontSize: 10.5, textTransform: 'uppercase', letterSpacing: 0.6, color: 'var(--text-3)' }}>
        {failed ? 'Ran for' : label}
      </span>
      <span
        className="mono"
        style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--text)', fontVariantNumeric: 'tabular-nums' }}
      >
        {digits}
      </span>
    </span>
  );
}
