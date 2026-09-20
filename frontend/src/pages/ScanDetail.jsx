import { useEffect, useRef, useState } from 'react';
import { Link, useParams, useNavigate } from 'react-router-dom';
import { api, ApiError } from '../api/client.js';
import { useFetch } from '../lib/useFetch.js';
import { usePageChrome } from '../context/ui.jsx';
import { CardLinkOverlay, Spinner, ErrorState, StatusBadge, Button } from '../components/ui.jsx';
import ScanTimer from '../components/ScanTimer.jsx';
import LinkifiedText from '../components/LinkifiedText.jsx';
import { useConfirm } from '../components/ConfirmProvider.jsx';
import {
  sevColor,
  findingSeverity,
  exposurePresentation,
  providerCapacityAutoscalePresentation,
  rateLimitPresentation,
  rateLimitRetryText,
  storageWarningPresentation,
} from '../lib/format.js';
import { isScanDeletable, postOutputSummary, findingIsExploitable } from '../lib/scanPresentation.js';
import { configuredModelCatalog, configuredModelProviders } from '../lib/modelProviders.js';
import { createLatestFieldMutationQueue } from '../lib/latestMutation.js';
import { duplicateScanPath } from '../lib/scanDuplication.js';
import { useUnsavedChangesPrompt } from '../lib/useUnsavedChangesPrompt.js';
import ModelConfiguration, {
  modelConfigurationForCatalog,
  modelConfigurationIsValid,
} from '../components/ModelConfiguration.jsx';
import { usePagination } from '../lib/usePagination.js';
import Pagination from '../components/Pagination.jsx';

export function scanActions(status) {
  const active = ['prewarming_cache', 'running', 'post_processing'].includes(status);
  return {
    canPause: active,
    canResume: ['paused', 'failed', 'stopped'].includes(status),
    canStop: ['queued', 'pending', 'prewarming_cache', 'running', 'rate_limited', 'paused', 'post_processing'].includes(
      status
    ),
    canDelete: isScanDeletable(status),
    stopLabel: ['queued', 'pending'].includes(status) ? 'Cancel' : status === 'rate_limited' ? 'Stop retrying' : 'Stop',
  };
}

export async function loadModelReferences(fetchProviders, fetchCatalog) {
  const [providerPayload, catalogResult] = await Promise.all([
    Promise.resolve().then(fetchProviders),
    Promise.resolve()
      .then(fetchCatalog)
      .then(
        (catalog) => ({ catalog, error: null }),
        (error) => ({ catalog: null, error })
      ),
  ]);
  return {
    providers: configuredModelProviders(providerPayload),
    catalog: configuredModelCatalog(catalogResult.catalog),
    catalogError: catalogResult.error,
  };
}

export default function ScanDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState(null);
  const [extrasOpen, setExtrasOpen] = useState(false);
  const [reviewError, setReviewError] = useState(null);
  const reviewMutations = useRef(createLatestFieldMutationQueue());
  const { data: scan, loading, error, reload } = useFetch(() => api.scan(id), [id], { pollMs: 1000 });
  const {
    data: vulns,
    loading: vulnsLoading,
    error: vulnsError,
    reload: reloadVulns,
    setData: setVulns,
  } = useFetch(
    () => api.scanVulnerabilities(id).then((records) => reviewMutations.current.overlayRecords(records)),
    [id],
    { pollMs: 1000 }
  );
  const {
    data: modelReferences,
    loading: modelReferencesLoading,
    error: modelReferencesError,
    reload: reloadModelReferences,
  } = useFetch(
    () =>
      loadModelReferences(
        () => api.modelProviders(),
        () => api.modelCatalog()
      ),
    [],
    { pollMs: 5000 }
  );

  useEffect(() => {
    reviewMutations.current.dispose();
    const queue = createLatestFieldMutationQueue();
    reviewMutations.current = queue;
    setReviewError(null);
    return () => queue.dispose();
  }, [id]);

  // Default view shows only findings proven exploitable — by the adjudicator, or by on-device
  // verification (dynamic_verified). Everything unproven collapses behind the toggle. This is
  // the "don't show me non-exploitable vulnerabilities" default.
  const [onlyExploitable, setOnlyExploitable] = useState(true);
  const allVulns = vulns || [];
  const exploitableVulns = allVulns.filter((v) => findingIsExploitable(v.jsonAnswer));
  const hiddenCount = allVulns.length - exploitableVulns.length;
  const visibleVulns = onlyExploitable ? exploitableVulns : allVulns;
  const findingPages = usePagination(visibleVulns, { pageSize: 20, resetKey: `${id}:${onlyExploitable}` });

  const setStatus = async (status) => {
    setBusy(true);
    setActionError(null);
    try {
      await api.updateScanStatus(id, status);
      reload();
    } catch (statusError) {
      setActionError(statusError);
    } finally {
      setBusy(false);
    }
  };

  const saveRunSettings = async (settings) => {
    await api.updateScan(id, settings);
    reload();
  };

  const confirm = useConfirm();

  // (Re)run the APK dynamic investigation phase — for "Start dynamic" (e.g. the device was
  // not connected on the first pass) and "Retry" (the dynamic phase errored).
  const rerunDynamic = async (label = 'Start dynamic') => {
    const confirmed = await confirm({
      title: label,
      message:
        'Re-run the dynamic investigation phase for this APK. Make sure the local model is running and ' +
        '(for live on-device proof) a device/emulator is connected — with no device it runs static-only. ' +
        'This replaces the current specialist / dynamic findings for this scan.',
      confirmLabel: 'Run',
    });
    if (!confirmed) return;
    setBusy(true);
    setActionError(null);
    try {
      await api.rerunDynamic(id);
      reload();
    } catch (rerunError) {
      setActionError(rerunError);
    } finally {
      setBusy(false);
    }
  };
  const deleteScan = async () => {
    const confirmed = await confirm({
      title: 'Delete scan',
      message: 'Permanently delete this scan and all findings, attempts, logs, and review data? This cannot be undone.',
      confirmLabel: 'Delete',
      danger: true,
    });
    if (!confirmed) return;
    setBusy(true);
    setActionError(null);
    try {
      await api.deleteScan(id);
      navigate('/scans', { replace: true });
    } catch (deleteError) {
      // The scan is still active. Offer to stop it and delete immediately, which
      // flips it to `stopped` (the engine worker aborts on that) and then removes it.
      if (deleteError?.status === 409) {
        const forceConfirmed = await confirm({
          title: 'Scan still active',
          message: 'This scan is still active. Stop the running work and delete it immediately?',
          confirmLabel: 'Stop & delete',
          danger: true,
        });
        if (!forceConfirmed) {
          setBusy(false);
          return;
        }
        try {
          await api.deleteScan(id, { force: true });
          navigate('/scans', { replace: true });
          return;
        } catch (forceError) {
          setActionError(forceError);
          setBusy(false);
          return;
        }
      }
      setActionError(deleteError);
      setBusy(false);
    }
  };

  // Optimistically update review fields. Per-record queues ensure rapid clicks
  // reach the server in order, and pending overlays survive background polls.
  const saveVuln = (vuln, patch) => {
    const fields = Object.keys(patch);
    setReviewError(null);
    setVulns((prev) => (prev || []).map((item) => (item.id === vuln.id ? { ...item, ...patch } : item)));
    for (const field of fields) {
      const value = patch[field];
      reviewMutations.current.enqueue({
        scope: vuln.id,
        field,
        value,
        mutate: () => api.updateVulnerability(vuln.id, { [field]: value }),
        onSuccess: (saved) => {
          if (!saved) return;
          setVulns((prev) =>
            (prev || []).map((item) => (item.id === vuln.id ? { ...item, [field]: saved[field] } : item))
          );
        },
        onError: (saveError) => {
          setReviewError(saveError);
          reloadVulns();
        },
      });
    }
  };
  const cycleInteresting = (v, e) => {
    e.stopPropagation();
    const cur = v.interesting ?? null;
    const next = cur === null ? 1 : cur === 1 ? 0 : null;
    saveVuln(v, { interesting: next });
  };

  usePageChrome(
    [
      { label: 'Scans', to: '/scans' },
      { label: scan?.repoDisplay || scan?.repoFull || '…', active: true },
    ],
    null,
    [scan?.repoDisplay]
  );

  if (loading)
    return (
      <div style={{ padding: 26 }}>
        <Spinner />
      </div>
    );
  if (error)
    return (
      <div style={{ padding: 26 }}>
        <ErrorState error={error} onRetry={reload} />
      </div>
    );
  if (!scan) return null;

  const list = vulns || [];
  const extraEntries = scan.extra && typeof scan.extra === 'object' ? Object.entries(scan.extra) : [];
  const actions = scanActions(scan.status);
  const agentSkills =
    Array.isArray(scan.agentSkills) && scan.agentSkills.length
      ? scan.agentSkills
      : (scan.agentSkillNames || []).map((name) => ({ name }));
  const postScripts =
    Array.isArray(scan.postScripts) && scan.postScripts.length
      ? scan.postScripts
      : scan.postScriptName
        ? [{ id: scan.postScriptId, name: scan.postScriptName, primary: true }]
        : [];
  const rateLimit = rateLimitPresentation(scan.reasoning);
  const providerAutoscale = providerCapacityAutoscalePresentation(scan.reasoning);
  const storageWarning = storageWarningPresentation(scan.reasoning);

  return (
    <div
      style={{
        position: 'relative',
        height: '100%',
        minHeight: 0,
        overflow: 'hidden',
      }}
    >
      <div
        style={{
          height: '100%',
          minWidth: 0,
          overflowY: 'auto',
          padding: '26px 30px',
        }}
      >
        <div
          style={{
            display: 'flex',
            alignItems: 'flex-start',
            justifyContent: 'space-between',
          }}
        >
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 11 }}>
              <span style={{ fontSize: 22, fontWeight: 600 }}>{scan.repoDisplay || scan.repoFull}</span>
              <span
                className="mono"
                style={{
                  fontSize: 9.5,
                  fontWeight: 600,
                  letterSpacing: '0.05em',
                  padding: '3px 7px',
                  borderRadius: 5,
                  color: scan.repoKind === 'local' ? 'var(--accent)' : 'var(--run)',
                  background: scan.repoKind === 'local' ? 'var(--accent-subtle)' : 'var(--run-bg)',
                }}
              >
                {(scan.repoKind || 'remote').toUpperCase()}
              </span>
              <StatusBadge status={scan.status} reasoning={scan.reasoning} size="sm" />
              <ScanTimer scan={scan} />
            </div>
            <div className="mono" style={{ fontSize: 12, color: 'var(--text-3)', marginTop: 7 }}>
              {scan.workflowName} · {scan.modelProvider ? `${scan.modelProvider} · ` : ''}
              {scan.model} · {scan.harness}
              {scan.thinkingEffort ? ` · ${scan.thinkingEffort}` : ''} ·{' '}
              {scan.repoKind === 'local' ? 'local snapshot' : `@${scan.commitShort}`}
            </div>
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <Button
              variant="ghost"
              style={{ height: 32 }}
              to={duplicateScanPath(scan.id)}
              title="Create a new scan from this configuration"
            >
              Duplicate scan
            </Button>
            {actions.canDelete && (
              <Button variant="danger" style={{ height: 32 }} onClick={() => !busy && deleteScan()} disabled={busy}>
                Delete
              </Button>
            )}
            {actions.canPause && (
              <Button variant="subtle" style={{ height: 32 }} onClick={() => !busy && setStatus('paused')}>
                {busy ? '…' : 'Pause'}
              </Button>
            )}
            {actions.canStop && (
              <Button variant="danger" style={{ height: 32 }} onClick={() => !busy && setStatus('stopped')}>
                {busy ? '…' : actions.stopLabel}
              </Button>
            )}
            {actions.canResume && (
              <Button
                variant="primary"
                style={{ height: 32 }}
                onClick={() => !busy && setStatus('pending')}
                title="Continue from completed steps and retry failed work"
              >
                {busy ? '…' : 'Resume'}
              </Button>
            )}
            {(() => {
              // Dynamic re-run controls, only for a completed APK scan that isn't mid-run.
              if (scan.repoKind !== 'apk' || scan.status !== 'completed') return null;
              const r = scan.reasoning || {};
              const running = r.dynamic_progress?.status === 'running' || r.dynamic_rerun_requested === true;
              if (running) return null;
              const hasError = !!r.dynamic_error;
              const ranBefore = !!r.dynamic_progress;
              return (
                <>
                  {hasError && (
                    <Button
                      variant="danger"
                      style={{ height: 32 }}
                      onClick={() => !busy && rerunDynamic('Retry dynamic')}
                      title="The dynamic phase failed — run it again"
                    >
                      {busy ? '…' : 'Retry'}
                    </Button>
                  )}
                  <Button
                    variant={hasError ? 'subtle' : 'primary'}
                    style={{ height: 32 }}
                    onClick={() => !busy && rerunDynamic(ranBefore ? 'Re-run dynamic' : 'Start dynamic')}
                    title="Run the on-device dynamic investigation phase (connect a device first for live proof)"
                  >
                    {busy ? '…' : ranBefore ? 'Re-run dynamic' : 'Start dynamic'}
                  </Button>
                </>
              );
            })()}
          </div>
        </div>

        {actionError && (
          <div style={{ marginTop: 14 }}>
            <ErrorState error={actionError} />
          </div>
        )}

        {storageWarning && (
          <div
            style={{
              marginTop: 14,
              padding: '10px 12px',
              borderRadius: 8,
              color: 'var(--pend)',
              background: 'var(--pend-bg)',
              fontSize: 12.5,
              lineHeight: 1.45,
            }}
          >
            <strong>Low storage.</strong> {storageWarning.message}
          </div>
        )}

        {providerAutoscale && (
          <div
            style={{
              marginTop: 14,
              padding: '10px 12px',
              borderRadius: 8,
              color: 'var(--run)',
              background: 'var(--run-bg)',
              fontSize: 12.5,
            }}
          >
            <strong>Workers adjusted.</strong> {providerAutoscale.message}
          </div>
        )}

        {scan.status === 'rate_limited' && (
          <div
            style={{
              marginTop: 14,
              padding: '10px 12px',
              borderRadius: 8,
              color: 'var(--pend)',
              background: 'var(--pend-bg)',
              fontSize: 12.5,
            }}
          >
            {rateLimit.accountRelated ? (
              <Link to="/accounts" style={{ color: 'inherit', fontWeight: 600 }}>
                {rateLimit.label}.
              </Link>
            ) : (
              <strong>{rateLimit.label}.</strong>
            )}{' '}
            {rateLimit.message} {rateLimitRetryText(scan.reasoning)} Completed work is preserved.
            {rateLimit.accountRelated && (
              <div style={{ marginTop: 6 }}>
                <Link to="/accounts" style={{ color: 'inherit', fontWeight: 600 }}>
                  View usage and provider limits in Accounts
                </Link>
              </div>
            )}
          </div>
        )}

        {scan.status === 'stopped' && scan.reasoning?.code === 'job_limit_reached' && (
          <div
            style={{
              marginTop: 14,
              padding: '10px 12px',
              borderRadius: 8,
              color: 'var(--pend)',
              background: 'var(--pend-bg)',
              fontSize: 12.5,
            }}
          >
            This scan reached its {scan.reasoning.limit}-job limit after starting {scan.reasoning.used} jobs. Increase
            or remove the limit in Run config, then resume.
          </div>
        )}

        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(120px, 1fr))',
            gap: 12,
            margin: '22px 0 24px',
          }}
        >
          <ScanStat label="Raw candidates" value={scan.rawCandidates ?? scan.findings} />
          <ScanStat label="Findings listed" value={scan.findings} color="var(--accent)" />
          <ScanStat label="Duplicates" value={scan.duplicateFindings ?? 0} />
          <ScanStat label="Exploitable" value={scan.exploitable} color="var(--fail)" />
          <ScanStat label="Post-scripts" value={postScripts.length} />
          <ScanStat label="Agent skills" value={scan.agentSkillCount || 0} />
          <ScanStat
            label={scan.repoKind === 'local' ? 'Revision' : 'Commit'}
            value={scan.repoKind === 'local' ? 'local snapshot' : scan.commitShort}
          />
        </div>

        {postScripts.length > 0 && <ConfiguredPostScripts postScripts={postScripts} />}

        <ScanRunSettings
          scan={scan}
          onSave={saveRunSettings}
          references={modelReferences}
          referencesLoading={modelReferencesLoading}
          referencesError={modelReferencesError}
          catalogError={modelReferences?.catalogError}
          onRetryReferences={reloadModelReferences}
        />

        <ScanStatusPanel scan={scan} />

        {agentSkills.length > 0 && <ConfiguredAgentSkills agentSkills={agentSkills} />}

        {extraEntries.length > 0 && (
          <div
            style={{
              border: '1px solid var(--border)',
              borderRadius: 10,
              padding: '13px 15px',
              background: 'var(--surface)',
              marginBottom: 24,
            }}
          >
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                gap: 12,
              }}
            >
              <div>
                <div
                  className="mono"
                  style={{
                    fontSize: 10,
                    letterSpacing: '0.05em',
                    color: 'var(--text-3)',
                    textTransform: 'uppercase',
                  }}
                >
                  Extras
                </div>
                <div
                  className="mono"
                  style={{
                    fontSize: 11.5,
                    color: 'var(--text-3)',
                    marginTop: 4,
                  }}
                >
                  {extraEntries.length} value
                  {extraEntries.length === 1 ? '' : 's'}
                </div>
              </div>
              <button
                type="button"
                aria-expanded={extrasOpen}
                aria-controls="scan-extra-values"
                onClick={() => setExtrasOpen((open) => !open)}
                style={{
                  height: 28,
                  padding: '0 10px',
                  borderRadius: 7,
                  border: '1px solid var(--border)',
                  background: 'var(--surface-2)',
                  color: 'var(--text-2)',
                  fontSize: 12.5,
                  cursor: 'pointer',
                }}
              >
                {extrasOpen ? 'Hide' : 'Show'}
              </button>
            </div>
            {extrasOpen && (
              <div
                id="scan-extra-values"
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
                  gap: 14,
                  maxHeight: 320,
                  overflowY: 'auto',
                  paddingRight: 4,
                  marginTop: 13,
                }}
              >
                {extraEntries.map(([k, v]) => (
                  <div key={k} style={{ minWidth: 0 }}>
                    <div className="mono" style={{ fontSize: 11.5, color: 'var(--text-3)' }}>
                      extra.{k}
                    </div>
                    <div
                      className="mono"
                      style={{
                        fontSize: 12.5,
                        color: 'var(--text)',
                        marginTop: 4,
                        whiteSpace: 'pre-wrap',
                        overflowWrap: 'anywhere',
                        lineHeight: 1.5,
                      }}
                    >
                      {formatExtraValue(v)}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {Array.isArray(scan.dependencies) && scan.dependencies.length > 0 && (
          <div
            style={{
              border: '1px solid var(--border)',
              borderRadius: 10,
              padding: '13px 15px',
              background: 'var(--surface)',
              marginBottom: 24,
            }}
          >
            <div
              className="mono"
              style={{
                fontSize: 10,
                letterSpacing: '0.05em',
                color: 'var(--text-3)',
                textTransform: 'uppercase',
                marginBottom: 8,
              }}
            >
              Dependencies
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {scan.dependencies.map((d, i) => (
                <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <span
                    className="mono"
                    style={{
                      fontSize: 9.5,
                      fontWeight: 600,
                      letterSpacing: '0.05em',
                      padding: '2px 6px',
                      borderRadius: 5,
                      flex: 'none',
                      color: d.kind === 'local' ? 'var(--accent)' : 'var(--run)',
                      background: d.kind === 'local' ? 'var(--accent-subtle)' : 'var(--run-bg)',
                    }}
                  >
                    {(d.kind || 'remote').toUpperCase()}
                  </span>
                  <span className="mono" style={{ fontSize: 12.5, color: 'var(--text)' }}>
                    {d.display || d.repoFull}
                  </span>
                  <span className="mono" style={{ fontSize: 11, color: 'var(--text-3)' }}>
                    {d.kind === 'remote' && d.commitSha ? `@${d.commitSha}` : 'local snapshot'}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {scan.reasoning?.dynamic_error && scan.reasoning?.dynamic_progress?.status !== 'running' && (
          <div
            style={{
              border: '1px solid var(--fail)',
              borderRadius: 12,
              background: 'var(--fail-bg, rgba(220,60,60,0.08))',
              padding: '12px 16px',
              marginBottom: 18,
              display: 'flex',
              gap: 12,
              alignItems: 'flex-start',
              flexWrap: 'wrap',
            }}
          >
            <div style={{ flex: 1, minWidth: 220 }}>
              <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--fail)' }}>Dynamic investigation failed</div>
              <div className="mono" style={{ fontSize: 11.5, color: 'var(--text-2)', marginTop: 4, wordBreak: 'break-word' }}>
                {String(scan.reasoning.dynamic_error).slice(0, 400)}
              </div>
            </div>
            <Button
              variant="danger"
              style={{ height: 30, flex: 'none' }}
              onClick={() => !busy && rerunDynamic('Retry dynamic')}
            >
              {busy ? '…' : 'Retry'}
            </Button>
          </div>
        )}

        {(() => {
          const dp = scan.reasoning?.dynamic_progress;
          if (!dp) return null;
          const running = dp.status === 'running';
          const pct = dp.total ? Math.round((dp.done / dp.total) * 100) : 0;
          const st = {
            pending: { icon: '○', color: 'var(--text-3)' },
            running: { icon: '◉', color: 'var(--fail)' },
            clean: { icon: '✓', color: 'var(--ok)' },
            vulnerable: { icon: '⚠', color: 'var(--fail)' },
            error: { icon: '✕', color: 'var(--text-3)' },
          };
          return (
            <div style={{ border: '1px solid var(--border)', borderRadius: 12, background: 'var(--surface)', padding: '14px 18px', marginBottom: 22 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10, flexWrap: 'wrap' }}>
                <span style={{ fontSize: 14, fontWeight: 600 }}>Dynamic investigation</span>
                <span style={{ fontSize: 11, padding: '2px 9px', borderRadius: 20, background: running ? 'var(--fail)' : 'var(--ok)', color: '#fff' }}>
                  {running ? 'running' : 'done'}
                </span>
                <span style={{ fontSize: 12, color: 'var(--text-2)' }}>
                  {dp.done} / {dp.total} components · {dp.vulnerable || 0} vulnerable · {dp.mode}
                </span>
              </div>
              <div style={{ height: 6, borderRadius: 4, background: 'var(--surface-2)', overflow: 'hidden', marginBottom: 12 }}>
                <div style={{ width: `${pct}%`, height: '100%', background: running ? 'var(--fail)' : 'var(--ok)', transition: 'width .4s' }} />
              </div>
              {running && dp.current && (
                <div style={{ fontSize: 12.5, marginBottom: 12 }}>
                  <span style={{ color: 'var(--fail)' }}>▶ investigating</span>{' '}
                  <span className="mono" style={{ color: 'var(--text)' }}>{dp.current.component}</span>{' '}
                  <span style={{ color: 'var(--text-3)' }}>· {dp.current.specialist}</span>
                </div>
              )}
              <div style={{ display: 'flex', gap: 14, flexWrap: 'wrap', fontSize: 11, color: 'var(--text-3)', marginBottom: 8, paddingBottom: 8, borderBottom: '1px solid var(--border-2)' }}>
                <span><span style={{ color: 'var(--text-3)' }}>○</span> pending</span>
                <span><span style={{ color: 'var(--fail)' }}>◉</span> investigating</span>
                <span><span style={{ color: 'var(--fail)' }}>⚠</span> vulnerable</span>
                <span><span style={{ color: 'var(--ok)' }}>✓</span> clean (no issue)</span>
                <span><span style={{ color: 'var(--text-3)' }}>✕</span> error</span>
              </div>
              <div style={{ maxHeight: 260, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 1 }}>
                {(dp.leads || []).map((l, i) => {
                  const s = st[l.state] || st.pending;
                  return (
                    <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, padding: '3px 0' }}>
                      <span style={{ color: s.color, width: 14, textAlign: 'center', flex: 'none' }}>{s.icon}</span>
                      <span style={{ color: 'var(--text-3)', width: 130, flex: 'none' }}>{l.specialist}</span>
                      <span className="mono" style={{ color: 'var(--text-2)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {l.component}
                      </span>
                      {l.state === 'vulnerable' && l.severity != null && (
                        <span style={{ marginLeft: 'auto', color: 'var(--fail)', fontWeight: 600, flex: 'none' }}>sev {l.severity}</span>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          );
        })()}

        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, marginBottom: 4, flexWrap: 'wrap' }}>
          <div style={{ fontSize: 15, fontWeight: 600 }}>Vulnerabilities</div>
          {hiddenCount > 0 && (
            <label style={{ display: 'inline-flex', alignItems: 'center', gap: 7, fontSize: 12, color: 'var(--text-2)', cursor: 'pointer' }}>
              <input type="checkbox" checked={onlyExploitable} onChange={(e) => setOnlyExploitable(e.target.checked)} style={{ accentColor: 'var(--accent)' }} />
              Show only exploitable (hiding {hiddenCount} unproven)
            </label>
          )}
        </div>
        <div style={{ fontSize: 12.5, color: 'var(--text-2)', marginBottom: 14 }}>
          Showing findings proven exploitable by the adjudicator or on-device verification. Unproven findings (needs-conditions, likely false positives, unverified) are hidden by default. Click a finding for the full trace.
        </div>

        {reviewError && (
          <div
            role="alert"
            style={{
              color: 'var(--fail)',
              background: 'var(--fail-bg)',
              borderRadius: 8,
              padding: '9px 11px',
              marginBottom: 12,
              fontSize: 12.5,
            }}
          >
            Could not save the review change. The latest server value is being reloaded. {reviewError.message}
          </div>
        )}

        {vulnsLoading && !vulns ? (
          <Spinner label="Loading vulnerabilities…" />
        ) : vulnsError ? (
          <ErrorState error={vulnsError} onRetry={reloadVulns} />
        ) : list.length === 0 ? (
          <div
            style={{
              border: '1px dashed var(--border)',
              borderRadius: 11,
              padding: '34px 18px',
              textAlign: 'center',
              color: 'var(--text-3)',
              fontSize: 13,
            }}
          >
            {scan.status === 'completed' || scan.status === 'stopped'
              ? 'No vulnerabilities were reported for this scan.'
              : 'Findings will appear here once the scan completes.'}
          </div>
        ) : (
          <div
            style={{
              border: '1px solid var(--border)',
              borderRadius: 11,
              overflow: 'hidden',
              background: 'var(--surface)',
            }}
          >
            <div
              className="scan-results-grid scan-results-header"
              style={{
                padding: '10px 16px',
                borderBottom: '1px solid var(--border-2)',
                background: 'var(--surface-2)',
              }}
            >
              <span
                className="mono"
                style={{
                  fontSize: 10,
                  letterSpacing: '0.05em',
                  color: 'var(--text-3)',
                  textTransform: 'uppercase',
                }}
              >
                Finding
              </span>
              <span
                className="mono"
                style={{
                  fontSize: 10,
                  letterSpacing: '0.05em',
                  color: 'var(--text-3)',
                  textTransform: 'uppercase',
                }}
              >
                CVSS · Severity
              </span>
              <span
                className="mono"
                style={{
                  fontSize: 10,
                  letterSpacing: '0.05em',
                  color: 'var(--text-3)',
                  textTransform: 'uppercase',
                }}
              >
                Post
              </span>
              <span
                className="mono"
                style={{
                  fontSize: 10,
                  letterSpacing: '0.05em',
                  color: 'var(--text-3)',
                  textTransform: 'uppercase',
                }}
              >
                Actor / Type
              </span>
            </div>
            {findingPages.pageItems.map((v) => {
              const chips = extractChips(v);
              const interesting = v.interesting ?? null;
              const dot = interestingDot(interesting);
              const severity = findingSeverity(v);
              return (
                <div
                  key={v.id}
                  className="scan-results-grid"
                  style={{
                    position: 'relative',
                    padding: '14px 16px',
                    borderBottom: '1px solid var(--border-2)',
                    cursor: 'pointer',
                    // Row color is the interesting indicator: highlight when interesting,
                    // fade when explicitly not interesting, normal when unmarked.
                    background: interesting === 1 ? 'var(--accent-subtle)' : 'transparent',
                    opacity: interesting === 0 ? 0.5 : 1,
                  }}
                >
                  <CardLinkOverlay
                    to={`/scans/${id}/vulnerabilities/${v.id}`}
                    label={`Open finding ${v.rank}: ${v.summary}`}
                  />
                  <div
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: 12,
                      minWidth: 0,
                    }}
                  >
                    <span
                      onClick={(e) => cycleInteresting(v, e)}
                      title={dot.title}
                      style={{
                        position: 'relative',
                        zIndex: 2,
                        width: 18,
                        flex: 'none',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        cursor: 'pointer',
                      }}
                    >
                      <span
                        style={{
                          width: 10,
                          height: 10,
                          borderRadius: '50%',
                          background: dot.bg,
                          border: `1.5px solid ${dot.border}`,
                        }}
                      />
                    </span>
                    <span
                      className="mono"
                      style={{
                        fontSize: 11,
                        color: 'var(--text-3)',
                        width: 24,
                        flex: 'none',
                      }}
                    >
                      #{v.rank}
                    </span>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div
                        title={v.summary}
                        style={{
                          fontWeight: 500,
                          fontSize: 13.5,
                          lineHeight: 1.35,
                          display: '-webkit-box',
                          WebkitLineClamp: 2,
                          WebkitBoxOrient: 'vertical',
                          overflow: 'hidden',
                        }}
                      >
                        {v.summary}
                      </div>
                      <div
                        className="mono"
                        style={{
                          fontSize: 11.5,
                          color: 'var(--text-3)',
                          marginTop: 4,
                          display: 'flex',
                          alignItems: 'center',
                          gap: 6,
                          minWidth: 0,
                        }}
                      >
                        <FpRowBadge verdict={v.jsonAnswer?.fp_verdict} />
                        <span
                          title={`${v.file_path}:${v.line}`}
                          style={{
                            whiteSpace: 'nowrap',
                            overflow: 'hidden',
                            textOverflow: 'ellipsis',
                          }}
                        >
                          {v.file_path}:{v.line}
                        </span>
                        {v.comments && v.comments.trim() && (
                          <span
                            title="Has a comment"
                            style={{
                              fontSize: 13,
                              color: 'var(--text-3)',
                              flex: 'none',
                            }}
                          >
                            ✎
                          </span>
                        )}
                      </div>
                    </div>
                  </div>
                  <FindingScoreCell vuln={v} severity={severity} />
                  <ChipList chips={chips} fallback={postOutputSummary(v)} />
                  <FindingActorTypeCell maliciousActor={v.malicious_actor} vulnerabilityType={v.vulnerability_type} />
                </div>
              );
            })}
            <Pagination
              {...findingPages}
              itemLabel="findings"
              style={{ padding: '0 16px 14px', borderTop: '1px solid var(--border-2)' }}
            />
          </div>
        )}
      </div>
    </div>
  );
}

function ScanRunSettings({
  scan,
  onSave,
  references,
  referencesLoading,
  referencesError,
  catalogError,
  onRetryReferences,
}) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(null);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState(null);
  const current = runSettingsDraft(scan);
  const activeDraft = mergeRunSettingsDraft(current, draft);
  const payload = draft ? runSettingsPayload(draft, current) : {};
  const dirty = Object.keys(payload).length > 0;
  const jobLimit = activeDraft.job_limit.trim();
  const jobLimitValid = !jobLimit || (/^\d+$/.test(jobLimit) && Number(jobLimit) >= 1 && Number(jobLimit) <= 1_000_000);
  const valid =
    jobLimitValid && !!references && modelConfigurationIsValid(activeDraft, references.providers, references.catalog);
  useUnsavedChangesPrompt(editing && (dirty || saving));

  const open = () => {
    const currentDraft = runSettingsDraft(scan);
    setDraft(
      references
        ? mergeRunSettingsDraft(
            currentDraft,
            modelConfigurationForCatalog(currentDraft, references.providers, references.catalog)
          )
        : currentDraft
    );
    setError(null);
    setEditing(true);
  };
  const cancel = () => {
    setEditing(false);
    setDraft(null);
    setError(null);
  };
  const save = async () => {
    if (!valid) {
      setError(
        jobLimitValid
          ? 'Choose a configured provider, available model, supported thinking effort, and compatible harness.'
          : 'Maximum model jobs must be a whole number from 1 to 1,000,000.'
      );
      return;
    }
    if (!dirty) {
      cancel();
      return;
    }
    setSaving(true);
    setError(null);
    try {
      await onSave(payload);
      setEditing(false);
      setDraft(null);
    } catch (e) {
      setError(formatApiError(e));
    } finally {
      setSaving(false);
    }
  };

  return (
    <div
      style={{
        border: '1px solid var(--border)',
        borderRadius: 10,
        padding: '13px 15px',
        background: 'var(--surface)',
        marginBottom: 24,
      }}
    >
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: 12,
          marginBottom: editing ? 13 : 0,
        }}
      >
        <div>
          <div
            className="mono"
            style={{
              fontSize: 10,
              letterSpacing: '0.05em',
              color: 'var(--text-3)',
              textTransform: 'uppercase',
            }}
          >
            Run config
          </div>
          {!editing && (
            <div className="mono" style={{ fontSize: 11.5, color: 'var(--text-3)', marginTop: 4 }}>
              {current.model_provider ? `${current.model_provider} · ` : ''}
              {current.model} · {current.harness}
              {current.thinking_effort ? ` · ${current.thinking_effort}` : ''}
            </div>
          )}
        </div>
        {editing ? (
          <div style={{ display: 'flex', gap: 8 }}>
            <Button
              variant="ghost"
              style={{ height: 30, padding: '0 12px', fontSize: 12.5 }}
              disabled={saving}
              onClick={cancel}
            >
              Cancel
            </Button>
            <Button
              variant="primary"
              style={{ height: 30, padding: '0 12px', fontSize: 12.5 }}
              disabled={saving || !valid || !dirty}
              onClick={save}
            >
              {saving ? 'Saving…' : 'Save'}
            </Button>
          </div>
        ) : (
          <Button
            variant="ghost"
            style={{ height: 30, padding: '0 12px', fontSize: 12.5 }}
            onClick={open}
            disabled={referencesLoading || !!referencesError || !references}
          >
            Edit
          </Button>
        )}
      </div>

      {editing ? (
        <>
          <ModelConfiguration
            value={activeDraft}
            onChange={(nextDraft) =>
              setDraft((currentDraft) => mergeRunSettingsDraft(currentDraft || current, nextDraft))
            }
            providers={references?.providers || []}
            catalog={references?.catalog || {}}
            catalogError={catalogError}
            disabled={saving}
          />
          <label style={{ display: 'block', maxWidth: 280, marginTop: 13 }}>
            <span
              className="mono"
              style={{
                display: 'block',
                fontSize: 10,
                color: 'var(--text-3)',
                marginBottom: 6,
              }}
            >
              MAXIMUM MODEL JOBS · OPTIONAL
            </span>
            <input
              className="mono"
              type="number"
              min="1"
              max="1000000"
              step="1"
              placeholder="unlimited"
              value={activeDraft.job_limit}
              disabled={saving}
              onChange={(event) =>
                setDraft((currentDraft) => ({
                  ...currentDraft,
                  job_limit: event.target.value,
                }))
              }
              style={{
                width: '100%',
                height: 36,
                padding: '0 10px',
                borderRadius: 7,
                border: `1px solid ${jobLimitValid ? 'var(--border)' : 'var(--fail)'}`,
                background: 'var(--surface)',
                color: 'var(--text)',
              }}
            />
            <span
              style={{
                display: 'block',
                fontSize: 11,
                color: 'var(--text-3)',
                marginTop: 6,
                lineHeight: 1.4,
              }}
            >
              {scan.jobsStarted || 0} logical jobs started. Internal retries do not consume extra jobs.
            </span>
          </label>
          {error && (
            <div className="mono" style={{ fontSize: 11.5, color: 'var(--fail)', marginTop: 10 }}>
              {error}
            </div>
          )}
        </>
      ) : referencesError ? (
        <div style={{ marginTop: 10 }}>
          <ErrorState error={referencesError} onRetry={onRetryReferences} />
        </div>
      ) : (
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))',
            gap: 12,
            marginTop: 13,
          }}
        >
          <RuntimeSetting label="model" value={current.model} />
          <RuntimeSetting label="model_provider" value={current.model_provider || '—'} />
          <RuntimeSetting label="thinking_effort" value={current.thinking_effort || '—'} />
          <RuntimeSetting label="harness" value={current.harness} />
          <RuntimeSetting
            label="model jobs"
            value={`${scan.jobsStarted || 0} / ${scan.jobLimit == null ? 'unlimited' : scan.jobLimit}`}
          />
        </div>
      )}
    </div>
  );
}

export function runSettingsDraft(scan = {}) {
  return {
    model: scan.model || '',
    model_provider: scan.modelProvider || 'openrouter',
    thinking_effort: scan.thinkingEffort || 'medium',
    harness: scan.harness || 'codex',
    job_limit: scan.jobLimit == null ? '' : `${scan.jobLimit}`,
  };
}

function runSettingsValue(value, fallback) {
  if (value === undefined) return fallback;
  if (value === null) return '';
  return typeof value === 'string' ? value : String(value);
}

export function mergeRunSettingsDraft(current = {}, patch = {}) {
  const base = {
    model: runSettingsValue(current?.model, ''),
    model_provider: runSettingsValue(current?.model_provider, 'openrouter'),
    thinking_effort: runSettingsValue(current?.thinking_effort, 'medium'),
    harness: runSettingsValue(current?.harness, 'codex'),
    job_limit: runSettingsValue(current?.job_limit, ''),
  };
  return {
    model: runSettingsValue(patch?.model, base.model),
    model_provider: runSettingsValue(patch?.model_provider, base.model_provider),
    thinking_effort: runSettingsValue(patch?.thinking_effort, base.thinking_effort),
    harness: runSettingsValue(patch?.harness, base.harness),
    job_limit: runSettingsValue(patch?.job_limit, base.job_limit),
  };
}

export function runSettingsPayload(draft, current) {
  const normalizedCurrent = mergeRunSettingsDraft({}, current);
  const normalizedDraft = mergeRunSettingsDraft(normalizedCurrent, draft);
  const payload = {};
  const model = normalizedDraft.model.trim();
  const jobLimit = normalizedDraft.job_limit.trim();
  if (model !== normalizedCurrent.model) payload.model = model;
  if (normalizedDraft.model_provider !== normalizedCurrent.model_provider)
    payload.model_provider = normalizedDraft.model_provider;
  if (normalizedDraft.thinking_effort !== normalizedCurrent.thinking_effort)
    payload.thinking_effort = normalizedDraft.thinking_effort;
  if (normalizedDraft.harness !== normalizedCurrent.harness) payload.harness = normalizedDraft.harness;
  if (normalizedDraft.job_limit !== normalizedCurrent.job_limit) payload.jobLimit = jobLimit ? Number(jobLimit) : null;
  return payload;
}

function formatApiError(error) {
  if (error instanceof ApiError && error.errors?.length) {
    return error.errors.map((e) => `${e.field}: ${e.message}`).join(' · ');
  }
  return error?.message || 'Failed to save run config.';
}

function RuntimeSetting({ label, value }) {
  return (
    <div style={{ minWidth: 0 }}>
      <div
        className="mono"
        style={{
          fontSize: 10,
          letterSpacing: '0.05em',
          color: 'var(--text-3)',
          textTransform: 'uppercase',
        }}
      >
        {label}
      </div>
      <div
        className="mono"
        title={value}
        style={{
          fontSize: 12.5,
          color: 'var(--text)',
          marginTop: 5,
          whiteSpace: 'nowrap',
          overflow: 'hidden',
          textOverflow: 'ellipsis',
        }}
      >
        {value}
      </div>
    </div>
  );
}

function scanErrorTimestamp(error) {
  for (const value of [error?.updatedAt, error?.insertedAt]) {
    if (!value) continue;
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) continue;
    return {
      dateTime: date.toISOString(),
      label: new Intl.DateTimeFormat(undefined, {
        dateStyle: 'medium',
        timeStyle: 'medium',
      }).format(date),
    };
  }
  return null;
}

const ACTIVITY_KIND_STYLE = {
  step: { label: '▶', color: 'var(--accent)' },
  thought: { label: '…', color: 'var(--text-2)' },
  tool: { label: '⚙', color: 'var(--run)' },
  observation: { label: '←', color: 'var(--text-3)' },
  finish: { label: '✓', color: 'var(--ok)' },
  done: { label: '●', color: 'var(--ok)' },
};

// Live feed of what the agent is doing right now (engine writes reasoning.agent_activity;
// both scan pages poll every second). Shows the current step + a scrolling event log.
export function AgentActivityFeed({ activity, live = false }) {
  const events = Array.isArray(activity?.events) ? activity.events : [];
  const scrollRef = useRef(null);
  useEffect(() => {
    const el = scrollRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [events.length]);
  if (!events.length && !activity?.step) return null;
  return (
    <div style={{ marginTop: 14 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 7 }}>
        <span
          style={{
            width: 7,
            height: 7,
            borderRadius: '50%',
            background: live ? 'var(--run)' : 'var(--text-3)',
            boxShadow: live ? '0 0 0 3px var(--run-bg)' : 'none',
            flex: 'none',
          }}
        />
        <span className="mono" style={{ fontSize: 11, color: 'var(--text-2)', fontWeight: 600 }}>
          LIVE AGENT ACTIVITY
        </span>
        {activity?.step && (
          <span className="mono" style={{ fontSize: 11, color: 'var(--text-3)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {activity.step}
          </span>
        )}
      </div>
      <div
        ref={scrollRef}
        style={{
          maxHeight: 230,
          overflowY: 'auto',
          border: '1px solid var(--border-2)',
          borderRadius: 8,
          background: 'var(--code-bg)',
          padding: '8px 10px',
          display: 'flex',
          flexDirection: 'column',
          gap: 4,
        }}
      >
        {events.map((ev, i) => {
          const kind = ACTIVITY_KIND_STYLE[ev.kind] || ACTIVITY_KIND_STYLE.thought;
          return (
            <div key={i} style={{ display: 'flex', gap: 8, alignItems: 'baseline', lineHeight: 1.4 }}>
              <span className="mono" style={{ color: kind.color, fontSize: 11, flex: 'none', width: 12, textAlign: 'center' }}>
                {kind.label}
              </span>
              <span
                className="mono"
                style={{
                  fontSize: 11.5,
                  color: ev.kind === 'tool' ? 'var(--text)' : 'var(--text-2)',
                  whiteSpace: 'pre-wrap',
                  wordBreak: 'break-word',
                  minWidth: 0,
                }}
              >
                {ev.text}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

export function ScanStatusPanel({ scan }) {
  const summary = scan.statusSummary || {};
  const rateLimited = scan.status === 'rate_limited';
  const completedLineages = summary.completedStepLineages ?? summary.stepCompletedAttempts ?? 0;
  const expectedLineages = summary.expectedStepLineages ?? summary.stepAttempts ?? 0;
  const activeJobs = summary.activeJobs || [];
  const recentErrors = summary.recentErrors || [];
  const currentFailedAttempts = summary.currentFailedAttempts ?? summary.failedAttempts ?? 0;
  const agentActivity = scan.reasoning?.agent_activity || null;
  const [expandedErrorIds, setExpandedErrorIds] = useState(() => new Set());
  const toggleError = (id) => {
    setExpandedErrorIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };
  if (!activeJobs.length && !recentErrors.length && !summary.totalAttempts && !agentActivity) return null;

  return (
    <div
      style={{
        border: '1px solid var(--border)',
        borderRadius: 10,
        padding: '13px 15px',
        background: 'var(--surface)',
        marginBottom: 24,
      }}
    >
      <div
        style={{
          display: 'flex',
          alignItems: 'flex-start',
          justifyContent: 'space-between',
          gap: 16,
        }}
      >
        <div>
          <div
            className="mono"
            style={{
              fontSize: 10,
              letterSpacing: '0.05em',
              color: 'var(--text-3)',
              textTransform: 'uppercase',
            }}
          >
            Status
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 14, marginTop: 8 }}>
            <RuntimeMetric label="Workflow" value={`${completedLineages}/${expectedLineages}`} />
            <RuntimeMetric label="Attempts" value={summary.totalAttempts || 0} />
            <RuntimeMetric label="Running" value={summary.runningAttempts || 0} color="var(--run)" />
            <RuntimeMetric
              label={rateLimited ? 'Attempt errors' : 'Failed'}
              value={currentFailedAttempts}
              color={currentFailedAttempts ? (rateLimited ? 'var(--pend)' : 'var(--fail)') : 'var(--text)'}
            />
            <RuntimeMetric label="Post" value={`${summary.postCompletedAttempts || 0}/${summary.postAttempts || 0}`} />
          </div>
        </div>
        {summary.progress && (
          <div style={{ minWidth: 160, flex: '0 0 220px' }}>
            <div
              className="mono"
              style={{
                fontSize: 11.5,
                color: 'var(--text-3)',
                marginBottom: 7,
              }}
            >
              {summary.progressLabel || 'progress'}
            </div>
            <div
              style={{
                height: 6,
                background: 'var(--surface-2)',
                borderRadius: 4,
                overflow: 'hidden',
              }}
            >
              <div
                style={{
                  height: '100%',
                  width: summary.progress,
                  background: 'var(--run)',
                }}
              />
            </div>
          </div>
        )}
      </div>

      {activeJobs.length > 0 && (
        <div style={{ marginTop: 14, display: 'flex', flexWrap: 'wrap', gap: 8 }}>
          {activeJobs.map((job) => (
            <span
              key={job.id}
              className="mono"
              style={{
                display: 'inline-flex',
                gap: 6,
                alignItems: 'center',
                maxWidth: '100%',
                padding: '4px 8px',
                borderRadius: 7,
                background: 'var(--run-bg)',
                color: 'var(--run)',
                fontSize: 11.5,
              }}
            >
              <span>{job.phaseLabel}</span>
              <span
                style={{
                  color: 'var(--text-2)',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap',
                }}
              >
                {job.title}
              </span>
            </span>
          ))}
        </div>
      )}

      {agentActivity && <AgentActivityFeed activity={agentActivity} live={scan.status === 'running'} />}

      {recentErrors.length > 0 && (
        <div style={{ marginTop: 15, display: 'grid', gap: 8 }}>
          {recentErrors.slice(0, 5).map((err) => {
            const expanded = expandedErrorIds.has(err.id);
            const previousRun = Boolean(err.previousRun);
            const timestamp = scanErrorTimestamp(err);
            return (
              <div
                key={err.id}
                style={{
                  border: `1px solid ${previousRun ? 'var(--border-2)' : 'var(--fail-bg)'}`,
                  borderRadius: 8,
                  padding: '9px 10px',
                  background: previousRun ? 'var(--surface-2)' : 'var(--fail-bg)',
                }}
              >
                <div
                  className="mono"
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    flexWrap: 'wrap',
                    gap: 12,
                    fontSize: 11,
                    color: previousRun ? 'var(--text-3)' : 'var(--fail)',
                    marginBottom: 6,
                  }}
                >
                  <span
                    style={{
                      minWidth: 0,
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      whiteSpace: 'nowrap',
                    }}
                  >
                    {previousRun ? 'Previous run · ' : ''}
                    {err.source} · {err.title}
                  </span>
                  <span
                    style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: 8,
                      flexWrap: 'wrap',
                      justifyContent: 'flex-end',
                      flex: 'none',
                    }}
                  >
                    {timestamp && (
                      <time
                        dateTime={timestamp.dateTime}
                        title={`Error occurred ${timestamp.label}`}
                        style={{ color: 'var(--text-3)', whiteSpace: 'nowrap' }}
                      >
                        {timestamp.label}
                      </time>
                    )}
                    <span>{err.phaseLabel}</span>
                    <button
                      type="button"
                      onClick={() => toggleError(err.id)}
                      style={{
                        height: 24,
                        padding: '0 8px',
                        borderRadius: 6,
                        border: '1px solid var(--border)',
                        background: 'var(--surface)',
                        color: 'var(--text-2)',
                        fontSize: 11.5,
                        cursor: 'pointer',
                      }}
                    >
                      {expanded ? 'Hide' : 'Show'}
                    </button>
                  </span>
                </div>
                {!previousRun && err.knownError && <KnownErrorBadge knownError={err.knownError} />}
                <ExpandableErrorMessage message={err.message} expanded={expanded} />
                {!previousRun && <ErrorFixLinks knownError={err.knownError} />}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// Post-script chips: any result key prefixed "_chip_" becomes a chip. The label is
// the key without the prefix; the value is shown below it. Capped at MAX_CHIPS.
const CHIP_PREFIX = '_chip_';
const MAX_CHIPS = 3;

export function FindingActorTypeCell({ maliciousActor, vulnerabilityType }) {
  const actor = typeof maliciousActor === 'string' && maliciousActor.trim() ? maliciousActor.trim() : '—';
  const type = typeof vulnerabilityType === 'string' && vulnerabilityType.trim() ? vulnerabilityType.trim() : 'finding';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-start', gap: 6, minWidth: 0 }}>
      <span
        className="mono"
        aria-label={`Malicious actor: ${actor}`}
        title={`Malicious actor: ${actor}`}
        style={{
          display: 'block',
          maxWidth: '100%',
          fontSize: 11.5,
          fontWeight: 600,
          color: 'var(--text)',
          whiteSpace: 'nowrap',
          overflow: 'hidden',
          textOverflow: 'ellipsis',
        }}
      >
        {actor}
      </span>
      <span
        className="mono"
        title={type}
        style={{
          display: 'inline-block',
          maxWidth: '100%',
          fontSize: 11.5,
          fontWeight: 700,
          padding: '4px 10px',
          borderRadius: 6,
          border: '1px solid var(--border)',
          background: 'var(--surface-2)',
          color: 'var(--text-2)',
          whiteSpace: 'nowrap',
          overflow: 'hidden',
          textOverflow: 'ellipsis',
          verticalAlign: 'middle',
        }}
      >
        {type}
      </span>
    </div>
  );
}

function chipValue(value) {
  if (value === null || value === undefined) return '—';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'object') return JSON.stringify(value);
  return String(value);
}

// Pull "_chip_*" keys from the primary post-script answer + every enrichment result.
// Map a numeric CVSS-style score (0–10) to a qualitative severity band.
function cvssBand(score) {
  if (score == null || Number.isNaN(Number(score))) return null;
  const s = Number(score);
  if (s >= 9) return 'critical';
  if (s >= 7) return 'high';
  if (s >= 4) return 'medium';
  if (s > 0) return 'low';
  return 'info';
}

// Findings-list score cell: CVSS score + severity band + confidence (the same values the
// vulnerability detail page shows). Falls back to the post-script severity for base findings.
// Compact false-positive verdict badge on a finding row.
function FpRowBadge({ verdict }) {
  const map = {
    exploitable: { t: 'exploitable', c: 'var(--ok)' },
    needs_conditions: { t: 'needs conditions', c: 'var(--pend)' },
    false_positive: { t: 'likely FP', c: 'var(--fail)' },
    error: { t: 'verify error', c: 'var(--text-3)' },
  };
  const m = map[verdict];
  if (!m) return null;
  return (
    <span style={{ flex: 'none', fontSize: 9.5, fontWeight: 700, color: '#fff', background: m.c, padding: '1px 6px', borderRadius: 9, textTransform: 'uppercase', letterSpacing: 0.3 }}>
      {m.t}
    </span>
  );
}

function FindingScoreCell({ vuln, severity }) {
  const ja = vuln.jsonAnswer && typeof vuln.jsonAnswer === 'object' ? vuln.jsonAnswer : {};
  const score = ja.severity_score != null && !Number.isNaN(Number(ja.severity_score)) ? Number(ja.severity_score) : null;
  const band = severity || cvssBand(score);
  const color = sevColor(band);
  const confidence = ja.confidence || null;
  const title = [band || 'unrated', score != null ? `CVSS ${score}/10` : null, confidence ? `confidence ${confidence}` : null]
    .filter(Boolean)
    .join(' · ');
  return (
    <div style={{ minWidth: 0, display: 'flex', flexDirection: 'column', gap: 4, alignItems: 'flex-start' }}>
      <span
        className="mono"
        title={title}
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: 7,
          maxWidth: '100%',
          fontSize: 11,
          fontWeight: 700,
          padding: '4px 9px',
          borderRadius: 6,
          border: '1px solid var(--border)',
          background: 'var(--surface-2)',
          color,
          textTransform: 'capitalize',
          whiteSpace: 'nowrap',
          overflow: 'hidden',
          textOverflow: 'ellipsis',
        }}
      >
        <span aria-hidden="true" style={{ width: 7, height: 7, borderRadius: 2, flex: 'none', background: color }} />
        {score != null ? `${score.toFixed(1)} · ` : ''}
        {band || 'Unrated'}
      </span>
      {confidence && (
        <span className="mono" style={{ fontSize: 10, color: 'var(--text-3)', whiteSpace: 'nowrap' }}>
          confidence: {confidence}
        </span>
      )}
      {(() => {
        const ex = exposurePresentation(vuln);
        const authority = ja.authorities;
        if (!ex && !authority) return null;
        return (
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
            {ex && (
              <span
                className="mono"
                title={ex.detail}
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: 4,
                  fontSize: 9.5,
                  fontWeight: 700,
                  padding: '2px 6px',
                  borderRadius: 5,
                  border: `1px solid ${ex.color}`,
                  color: ex.color,
                  whiteSpace: 'nowrap',
                }}
              >
                {ex.icon} {ex.short}
              </span>
            )}
            {authority && (
              <span
                className="mono"
                title={`ContentProvider authority: ${authority}`}
                style={{ fontSize: 10, color: 'var(--text-3)', cursor: 'help' }}
              >
                🔑
              </span>
            )}
          </span>
        );
      })()}
    </div>
  );
}

function extractChips(vuln) {
  const sources = [];
  if (vuln.postScriptAnswer && typeof vuln.postScriptAnswer === 'object') sources.push(vuln.postScriptAnswer);
  for (const e of vuln.enrichments || []) if (e?.result && typeof e.result === 'object') sources.push(e.result);

  const chips = [];
  const seen = new Set();
  for (const result of sources) {
    for (const [key, value] of Object.entries(result)) {
      if (!key.startsWith(CHIP_PREFIX)) continue;
      const label = key.slice(CHIP_PREFIX.length);
      if (!label || seen.has(label)) continue;
      seen.add(label);
      chips.push({ label, value: chipValue(value) });
    }
  }
  return chips;
}

function ChipList({ chips, fallback }) {
  if (!chips.length && !fallback)
    return (
      <span className="mono" style={{ fontSize: 11.5, color: 'var(--text-3)' }}>
        —
      </span>
    );
  const shown = chips.length ? chips.slice(0, MAX_CHIPS) : [fallback];
  const extra = chips.length ? chips.length - shown.length : 0;
  const hiddenLabels = chips
    .slice(MAX_CHIPS)
    .map((c) => c.label)
    .join(', ');
  return (
    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, minWidth: 0 }}>
      {shown.map((c, i) => (
        <div
          key={i}
          title={`${c.label}: ${c.value}`}
          style={{
            display: 'inline-flex',
            flexDirection: 'column',
            padding: '3px 9px',
            borderRadius: 8,
            border: '1px solid var(--border)',
            background: 'var(--surface-2)',
            maxWidth: 150,
            minWidth: 0,
          }}
        >
          <span
            className="mono"
            style={{
              fontSize: 8.5,
              letterSpacing: '0.04em',
              textTransform: 'uppercase',
              color: 'var(--text-3)',
              whiteSpace: 'nowrap',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              lineHeight: 1.45,
            }}
          >
            {c.label.replaceAll('_', ' ')}
          </span>
          <span
            style={{
              fontSize: 11.5,
              fontWeight: 600,
              color: 'var(--text)',
              whiteSpace: 'nowrap',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              lineHeight: 1.35,
            }}
          >
            {c.value}
          </span>
        </div>
      ))}
      {extra > 0 && (
        <span
          title={`${extra} more: ${hiddenLabels}`}
          className="mono"
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            fontSize: 11,
            fontWeight: 600,
            color: 'var(--text-2)',
            background: 'var(--surface-2)',
            border: '1px solid var(--border)',
            borderRadius: 8,
            padding: '0 9px',
          }}
        >
          +{extra}
        </span>
      )}
    </div>
  );
}

function ExpandableErrorMessage({ message, expanded }) {
  return (
    <div
      className="mono"
      style={{
        fontSize: 11.5,
        color: 'var(--text-2)',
        lineHeight: 1.45,
        whiteSpace: 'pre-wrap',
        overflowWrap: 'anywhere',
        ...(expanded
          ? { maxHeight: 240, overflowY: 'auto', paddingRight: 4 }
          : {
              display: '-webkit-box',
              WebkitLineClamp: 3,
              WebkitBoxOrient: 'vertical',
              overflow: 'hidden',
            }),
      }}
    >
      <LinkifiedText text={message} />
    </div>
  );
}

function KnownErrorBadge({ knownError }) {
  if (!knownError?.title) return null;
  return (
    <span
      className="mono"
      style={{
        display: 'inline-flex',
        marginBottom: 6,
        padding: '2px 7px',
        borderRadius: 999,
        border: '1px solid var(--fail)',
        background: 'var(--surface)',
        color: 'var(--fail)',
        fontSize: 10.5,
      }}
    >
      {knownError.title}
    </span>
  );
}

function ErrorFixLinks({ knownError }) {
  const links = knownError?.fixLinks || [];
  if (!links.length) return null;
  return (
    <div
      className="mono"
      style={{
        display: 'flex',
        flexWrap: 'wrap',
        gap: 8,
        marginTop: 7,
        fontSize: 11,
      }}
    >
      {links.map((link) =>
        link.internal || link.url?.startsWith('/') ? (
          <Link
            key={`${link.label}-${link.url}`}
            to={link.url}
            style={{
              color: 'var(--accent)',
              textDecoration: 'none',
              borderBottom: '1px solid var(--accent)',
            }}
          >
            {link.label || link.url}
          </Link>
        ) : (
          <a
            key={`${link.label}-${link.url}`}
            href={link.url}
            target="_blank"
            rel="noreferrer"
            style={{
              color: 'var(--accent)',
              textDecoration: 'none',
              borderBottom: '1px solid var(--accent)',
            }}
          >
            {link.label || link.url}
          </a>
        )
      )}
    </div>
  );
}

function RuntimeMetric({ label, value, color = 'var(--text)' }) {
  return (
    <div>
      <div
        className="mono"
        style={{
          fontSize: 10,
          letterSpacing: '0.05em',
          color: 'var(--text-3)',
          textTransform: 'uppercase',
        }}
      >
        {label}
      </div>
      <div style={{ fontSize: 17, fontWeight: 600, marginTop: 3, color }}>{value}</div>
    </div>
  );
}

// Left dot toggle for the 3-state interesting flag (1 / 0 / null). Clicking cycles
// it; the row background reflects the same state more prominently.
function interestingDot(intr) {
  const v = intr ?? null;
  if (v === 1)
    return {
      bg: 'var(--accent)',
      border: 'var(--accent)',
      title: 'Interesting — click to change',
    };
  if (v === 0)
    return {
      bg: 'var(--text-3)',
      border: 'var(--text-3)',
      title: 'Not interesting — click to change',
    };
  return {
    bg: 'transparent',
    border: 'var(--border)',
    title: 'Unmarked — click to flag',
  };
}

function ScanStat({ label, value, color = 'var(--text)' }) {
  return (
    <div
      style={{
        border: '1px solid var(--border)',
        borderRadius: 10,
        padding: '13px 15px',
        background: 'var(--surface)',
      }}
    >
      <div
        className="mono"
        style={{
          fontSize: 10,
          letterSpacing: '0.05em',
          color: 'var(--text-3)',
          textTransform: 'uppercase',
        }}
      >
        {label}
      </div>
      <div style={{ fontSize: 22, fontWeight: 600, marginTop: 6, color }}>{value}</div>
    </div>
  );
}

function ConfiguredPostScripts({ postScripts }) {
  const postScriptPages = usePagination(postScripts, { pageSize: 10 });

  return (
    <div
      style={{
        border: '1px solid var(--border)',
        borderRadius: 10,
        padding: '13px 15px',
        background: 'var(--surface)',
        marginBottom: 24,
      }}
    >
      <div
        className="mono"
        style={{
          fontSize: 10,
          letterSpacing: '0.05em',
          color: 'var(--text-3)',
          textTransform: 'uppercase',
          marginBottom: 8,
        }}
      >
        Configured post-scripts
      </div>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 7 }}>
        {postScriptPages.pageItems.map((postScript) => (
          <span
            key={postScript.id || postScript.name}
            className="mono"
            style={{
              fontSize: 11,
              color: postScript.primary ? 'var(--accent)' : 'var(--text-2)',
              background: 'var(--surface-2)',
              border: '1px solid var(--border-2)',
              borderRadius: 6,
              padding: '3px 8px',
            }}
          >
            {postScript.name}
            {postScript.primary ? ' · primary' : ''}
          </span>
        ))}
      </div>
      <Pagination {...postScriptPages} itemLabel="post-scripts" compact />
    </div>
  );
}

function ConfiguredAgentSkills({ agentSkills }) {
  const skillPages = usePagination(agentSkills, { pageSize: 10 });

  return (
    <div
      style={{
        border: '1px solid var(--border)',
        borderRadius: 10,
        padding: '13px 15px',
        background: 'var(--surface)',
        marginBottom: 24,
      }}
    >
      <div
        className="mono"
        style={{
          fontSize: 10,
          letterSpacing: '0.05em',
          color: 'var(--text-3)',
          textTransform: 'uppercase',
          marginBottom: 8,
        }}
      >
        Agent skills
      </div>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 7 }}>
        {skillPages.pageItems.map((skill) =>
          skill.sourceUrl ? (
            <a
              key={skill.id || skill.name}
              href={skill.sourceUrl}
              target="_blank"
              rel="noreferrer"
              className="mono"
              style={{
                fontSize: 11,
                color: 'var(--accent)',
                background: 'var(--surface-2)',
                border: '1px solid var(--border-2)',
                borderRadius: 6,
                padding: '3px 8px',
                textDecoration: 'none',
              }}
            >
              {skill.name}
            </a>
          ) : (
            <span
              key={skill.id || skill.name}
              className="mono"
              style={{
                fontSize: 11,
                color: 'var(--text-2)',
                background: 'var(--surface-2)',
                border: '1px solid var(--border-2)',
                borderRadius: 6,
                padding: '3px 8px',
              }}
            >
              {skill.name}
            </span>
          )
        )}
      </div>
      <Pagination {...skillPages} itemLabel="skills" compact />
    </div>
  );
}

function formatExtraValue(value) {
  if (typeof value === 'string') return value;
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}
