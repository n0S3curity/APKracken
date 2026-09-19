import { useEffect, useMemo, useRef, useState } from 'react';
import { api, apiErrorMessages } from '../api/client.js';
import { useFetch } from '../lib/useFetch.js';
import { usePageChrome } from '../context/ui.jsx';
import { Spinner } from '../components/ui.jsx';
import { useConfirm } from '../components/ConfirmProvider.jsx';
import DeviceStreamMirror from '../components/DeviceStreamMirror.jsx';

export default function Device() {
  usePageChrome([{ label: 'Device', active: true }], null, []);
  const { data, reload } = useFetch(() => api.device(), [], { pollMs: 1500 });
  const { data: apkScansData } = useFetch(() => api.deviceApkScans(), [], { pollMs: 15000 });
  const confirm = useConfirm();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  const dev = data || {};
  const connected = !!dev.connected;
  const agentRunning = dev.agentRunning !== false;
  const details = dev.details || {};
  const apkScans = apkScansData?.scans || [];

  const act = async (fn) => {
    setBusy(true);
    setError(null);
    try {
      await fn();
      reload();
    } catch (e) {
      setError(apiErrorMessages(e)[0] || 'Action failed.');
    } finally {
      setBusy(false);
    }
  };

  const selectDevice = (serial) => act(() => api.updateDevice({ selectedSerial: serial }));
  const selectTested = (scanId) => act(() => api.updateDevice({ testedScanId: scanId }));
  const install = async () => {
    const label = dev.appInstalled ? 'Reinstall app' : 'Install app';
    const ok = await confirm({
      title: label,
      message: `${label} on the device (${dev.testedPackage || 'selected app'})? This installs the scanned APK and modifies the device.`,
      confirmLabel: dev.appInstalled ? 'Reinstall' : 'Install',
    });
    if (!ok) return;
    act(() => api.installDeviceApp());
  };

  return (
    <div style={{ padding: '26px 30px', height: '100%', overflowY: 'auto' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 4, flexWrap: 'wrap' }}>
        <h1 style={{ fontSize: 22, fontWeight: 600, margin: 0 }}>Device</h1>
        <ConnBadge agentRunning={agentRunning} connected={connected} />
        {dev.keepAwake && connected && (
          <span style={{ fontSize: 11.5, color: 'var(--text-3)' }} title="Screen kept awake while connected">
            ☕ stay-awake on
          </span>
        )}
      </div>
      <div className="mono" style={{ fontSize: 12, color: 'var(--text-3)', marginBottom: 18 }}>
        {connected
          ? `${details.brand || details.manufacturer || ''} ${details.model || dev.activeSerial} · Android ${details.android_release || '?'} (SDK ${details.sdk || '?'}) · ${dev.activeSerial}`
          : agentRunning
            ? 'No device connected — plug in an authorized device/emulator.'
            : 'Device agent is not running. Start the engine (scripts/start-engine.ps1).'}
      </div>

      {error && <div style={{ color: 'var(--fail)', fontSize: 12.5, marginBottom: 12 }}>{error}</div>}

      {!data && (
        <div style={{ padding: 30 }}>
          <Spinner />
        </div>
      )}

      {data && (
        <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) minmax(240px, 340px)', gap: 22, alignItems: 'start' }}>
          {/* LEFT: controls, status, logs */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 18, minWidth: 0 }}>
            {/* Device picker (only when >1 connected) */}
            {Array.isArray(dev.devices) && dev.devices.filter((d) => d.state === 'device').length > 1 && (
              <Panel title="Active device">
                <select
                  value={dev.selectedSerial || dev.activeSerial || ''}
                  onChange={(e) => selectDevice(e.target.value)}
                  disabled={busy}
                  style={selectStyle}
                >
                  {dev.devices
                    .filter((d) => d.state === 'device')
                    .map((d) => (
                      <option key={d.serial} value={d.serial}>
                        {d.model ? `${d.model} · ${d.serial}` : d.serial}
                      </option>
                    ))}
                </select>
              </Panel>
            )}

            {/* Tested application */}
            <Panel title="Tested application">
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center', marginBottom: 10 }}>
                <select
                  value={dev.testedScanId || ''}
                  onChange={(e) => selectTested(e.target.value)}
                  disabled={busy}
                  style={{ ...selectStyle, flex: 1, minWidth: 180 }}
                >
                  {apkScans.length === 0 && <option value="">No APK scans yet</option>}
                  {apkScans.map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.label}
                    </option>
                  ))}
                </select>
              </div>
              <div className="mono" style={{ fontSize: 12, color: 'var(--text-2)', marginBottom: 12 }}>
                {dev.testedPackage || '(package resolving…)'}
              </div>
              <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap', marginBottom: 14 }}>
                <StatusDot label="Installed" state={dev.appInstalled} />
                <StatusDot label="Running" state={dev.appRunning} running />
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <button
                  type="button"
                  onClick={install}
                  disabled={busy || !connected || dev.installBusy}
                  style={{
                    height: 34,
                    padding: '0 16px',
                    borderRadius: 8,
                    border: 0,
                    background: !connected || busy || dev.installBusy ? 'var(--surface-2)' : 'var(--accent)',
                    color: !connected || busy || dev.installBusy ? 'var(--text-3)' : '#fff',
                    fontSize: 13,
                    fontWeight: 600,
                    cursor: !connected || busy || dev.installBusy ? 'default' : 'pointer',
                  }}
                >
                  {dev.installBusy ? 'Installing…' : dev.appInstalled ? 'Reinstall app' : 'Install app'}
                </button>
                {dev.installStatus && (
                  <span className="mono" style={{ fontSize: 11.5, color: /fail|error|no APK/i.test(dev.installStatus) ? 'var(--fail)' : 'var(--text-3)' }}>
                    {dev.installStatus}
                  </span>
                )}
              </div>
            </Panel>

            {/* Logcat */}
            <Panel title={`Logcat${dev.testedPackage ? ` · ${dev.testedPackage}` : ''}`}>
              <Logcat text={dev.logcat} />
            </Panel>

            {/* Installed apps */}
            <Panel title={`Installed apps${Array.isArray(dev.installedApps) ? ` (${dev.installedApps.length})` : ''}`}>
              <InstalledApps apps={dev.installedApps} />
            </Panel>
          </div>

          {/* RIGHT: live screen mirror */}
          <div style={{ position: 'sticky', top: 0 }}>
            <Panel title="Screen mirror">
              <Mirror connected={connected} serial={dev.activeSerial} streamPort={dev.streamPort} />
            </Panel>
          </div>
        </div>
      )}
    </div>
  );
}

const selectStyle = {
  padding: '8px 10px',
  borderRadius: 8,
  border: '1px solid var(--border)',
  background: 'var(--surface)',
  color: 'var(--text)',
  fontSize: 13,
};

function Panel({ title, children }) {
  return (
    <div style={{ border: '1px solid var(--border)', borderRadius: 12, background: 'var(--surface)', padding: 16 }}>
      <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-2)', textTransform: 'uppercase', letterSpacing: 0.5, marginBottom: 12 }}>
        {title}
      </div>
      {children}
    </div>
  );
}

function ConnBadge({ agentRunning, connected }) {
  const [label, color] = !agentRunning
    ? ['agent offline', 'var(--text-3)']
    : connected
      ? ['connected', 'var(--ok)']
      : ['no device', 'var(--fail)'];
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 12, color }}>
      <span style={{ width: 8, height: 8, borderRadius: '50%', background: color, animation: connected ? 'okpulse 1.6s ease-in-out infinite' : 'none' }} />
      {label}
    </span>
  );
}

function StatusDot({ label, state, running }) {
  const [text, color] =
    state === true ? [running ? 'yes' : 'yes', 'var(--ok)'] : state === false ? ['no', running ? 'var(--text-3)' : 'var(--fail)'] : ['—', 'var(--text-3)'];
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 12.5 }}>
      <span style={{ width: 8, height: 8, borderRadius: '50%', background: color }} />
      <span style={{ color: 'var(--text-2)' }}>{label}:</span>
      <span style={{ color: 'var(--text)', fontWeight: 600 }}>{text}</span>
    </span>
  );
}

function Logcat({ text }) {
  const ref = useRef(null);
  useEffect(() => {
    const el = ref.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [text]);
  return (
    <pre
      ref={ref}
      style={{
        margin: 0,
        maxHeight: 260,
        overflow: 'auto',
        background: 'var(--code-bg)',
        border: '1px solid var(--border-2)',
        borderRadius: 8,
        padding: '10px 12px',
        fontSize: 11,
        lineHeight: 1.5,
        whiteSpace: 'pre-wrap',
        wordBreak: 'break-word',
        color: 'var(--text-2)',
        fontFamily: "'Geist Mono', ui-monospace, monospace",
      }}
    >
      {text && String(text).trim() ? String(text) : '(no logs — open the app on the device, or connect a device)'}
    </pre>
  );
}

function InstalledApps({ apps }) {
  const [q, setQ] = useState('');
  const list = Array.isArray(apps) ? apps : [];
  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return needle ? list.filter((p) => p.toLowerCase().includes(needle)) : list;
  }, [list, q]);
  if (list.length === 0) return <div style={{ fontSize: 12.5, color: 'var(--text-3)' }}>Connect a device to list installed apps.</div>;
  return (
    <div>
      <input
        value={q}
        onChange={(e) => setQ(e.target.value)}
        placeholder="Filter packages…"
        style={{ ...selectStyle, width: '100%', marginBottom: 10 }}
      />
      <div style={{ maxHeight: 240, overflow: 'auto', display: 'flex', flexDirection: 'column', gap: 2 }}>
        {filtered.map((p) => (
          <div key={p} className="mono" style={{ fontSize: 11.5, color: 'var(--text-2)', padding: '2px 0' }}>
            {p}
          </div>
        ))}
        {filtered.length === 0 && <div style={{ fontSize: 12, color: 'var(--text-3)' }}>No matches.</div>}
      </div>
    </div>
  );
}

// The device screen mirror: real-time H.264 (screenrecord → WebSocket → WebCodecs).
function Mirror({ connected, serial, streamPort }) {
  const [error, setError] = useState(null);
  const [attempt, setAttempt] = useState(0);

  if (!connected) {
    return (
      <div style={{ aspectRatio: '9 / 19', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-3)', fontSize: 12.5, background: 'var(--code-bg)', borderRadius: 10, textAlign: 'center', padding: 16 }}>
        No device connected
      </div>
    );
  }
  if (error) {
    return (
      <div style={{ padding: 20, background: 'var(--code-bg)', borderRadius: 10, textAlign: 'center' }}>
        <div style={{ color: 'var(--fail)', fontSize: 12.5, marginBottom: 10 }}>
          Live mirror unavailable{error ? ` — ${error}` : ''}. Make sure the engine is running.
        </div>
        <button
          type="button"
          onClick={() => {
            setError(null);
            setAttempt((a) => a + 1);
          }}
          style={{ fontSize: 12, padding: '6px 14px', borderRadius: 8, border: '1px solid var(--border)', background: 'var(--surface)', color: 'var(--text)', cursor: 'pointer' }}
        >
          Retry
        </button>
      </div>
    );
  }
  return (
    <DeviceStreamMirror
      key={attempt}
      serial={serial}
      streamPort={streamPort}
      onFallback={(msg) => setError(msg || 'stream failed')}
    />
  );
}
