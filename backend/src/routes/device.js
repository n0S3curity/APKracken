// Android device state + control for the "Device" tab. The native engine is the device
// agent (only it has adb/USB); it polls state into public.device_state and performs
// install/keep-awake actions. The backend only reads/serves those rows and records user
// requests (selection, tested app, install) that the engine picks up. The live screen mirror
// is a separate real-time H.264 WebSocket the browser opens directly to the engine.
import { Router } from 'express';
import { prisma } from '../db.js';

const router = Router();

// Mirror the engine's schema so the API works even if the engine hasn't booted yet.
async function ensureTables() {
  await prisma.$executeRawUnsafe(`
    CREATE TABLE IF NOT EXISTS public.device_state (
      id integer PRIMARY KEY DEFAULT 1,
      selected_serial text, last_test_serial text,
      tested_scan_id bigint, tested_package text, tested_apk_path text,
      screen_wanted_at timestamptz,
      connected boolean NOT NULL DEFAULT false,
      active_serial text, details jsonb,
      app_installed boolean, app_running boolean,
      devices jsonb, installed_apps jsonb, installed_apps_at timestamptz,
      logcat text, keep_awake boolean NOT NULL DEFAULT false,
      install_token bigint NOT NULL DEFAULT 0, install_done_token bigint NOT NULL DEFAULT 0,
      install_status text, updated_at timestamptz NOT NULL DEFAULT now(),
      CONSTRAINT device_state_singleton CHECK (id = 1)
    )`);
  await prisma.$executeRawUnsafe(
    `INSERT INTO public.device_state (id) VALUES (1) ON CONFLICT (id) DO NOTHING`
  );
}

// Writing screen_wanted_at is the "tab is open" heartbeat — the engine only captures the
// screen + logcat while it is fresh, so an unopened tab costs the device almost nothing.
async function heartbeat() {
  await prisma.$executeRawUnsafe(`UPDATE public.device_state SET screen_wanted_at = now() WHERE id = 1`);
}

async function readStateRow() {
  const rows = await prisma.$queryRawUnsafe(`SELECT * FROM public.device_state WHERE id = 1`);
  return rows[0] || {};
}

function serializeDeviceState(s) {
  const updatedAt = s.updated_at ? new Date(s.updated_at) : null;
  const ageMs = updatedAt ? Date.now() - updatedAt.getTime() : null;
  // If the engine isn't ticking, the row is stale — don't claim the device is connected.
  const agentStale = ageMs === null || ageMs > 8000;
  const installToken = s.install_token != null ? Number(s.install_token) : 0;
  const installDone = s.install_done_token != null ? Number(s.install_done_token) : 0;
  return {
    agentRunning: !agentStale,
    connected: !!s.connected && !agentStale,
    activeSerial: s.active_serial ?? null,
    selectedSerial: s.selected_serial ?? null,
    lastTestSerial: s.last_test_serial ?? null,
    testedScanId: s.tested_scan_id != null ? s.tested_scan_id.toString() : null,
    testedPackage: s.tested_package ?? null,
    details: s.details ?? null,
    appInstalled: s.app_installed ?? null,
    appRunning: s.app_running ?? null,
    devices: Array.isArray(s.devices) ? s.devices : s.devices ?? [],
    installedApps: Array.isArray(s.installed_apps) ? s.installed_apps : s.installed_apps ?? [],
    installedAppsAt: s.installed_apps_at ?? null,
    logcat: s.logcat ?? null,
    keepAwake: !!s.keep_awake,
    installStatus: s.install_status ?? null,
    installBusy: installToken > installDone,
    updatedAt: s.updated_at ?? null,
    // The engine's real-time H.264 stream server (scrcpy-style) listens on the host; the
    // browser connects to it directly. Port is fixed by convention (engine + this must match).
    streamPort: Number(process.env.DEVICE_STREAM_PORT || 9010),
  };
}

// GET /api/device — current device state (+ heartbeat so the engine keeps the mirror live).
router.get('/', async (req, res, next) => {
  try {
    await ensureTables();
    await heartbeat();
    res.json(serializeDeviceState(await readStateRow()));
  } catch (e) {
    next(e);
  }
});

// PATCH /api/device — choose the active device and/or the tested app (scan).
router.patch('/', async (req, res, next) => {
  try {
    await ensureTables();
    const body = req.body || {};
    const sets = [];
    const params = [];
    if (body.selectedSerial !== undefined) {
      params.push(body.selectedSerial === null ? null : String(body.selectedSerial));
      sets.push(`selected_serial = $${params.length}`);
    }
    if (body.testedScanId !== undefined) {
      params.push(body.testedScanId === null ? null : BigInt(body.testedScanId));
      sets.push(`tested_scan_id = $${params.length}`);
      // Force the engine to re-resolve the package + apk path for the new scan.
      sets.push(`tested_package = NULL`, `tested_apk_path = NULL`);
    }
    if (!sets.length) return res.status(422).json({ errors: [{ field: 'body', message: 'Nothing to update.' }] });
    await prisma.$executeRawUnsafe(
      `UPDATE public.device_state SET ${sets.join(', ')}, updated_at = now() WHERE id = 1`,
      ...params
    );
    res.json(serializeDeviceState(await readStateRow()));
  } catch (e) {
    next(e);
  }
});

// POST /api/device/install — ask the engine to (re)install the tested app's APK.
router.post('/install', async (req, res, next) => {
  try {
    await ensureTables();
    await prisma.$executeRawUnsafe(
      `UPDATE public.device_state SET install_token = install_token + 1, install_status = 'queued', updated_at = now() WHERE id = 1`
    );
    res.json(serializeDeviceState(await readStateRow()));
  } catch (e) {
    next(e);
  }
});

// GET /api/device/apk-scans — scanned apps for the "tested application" dropdown.
router.get('/apk-scans', async (req, res, next) => {
  try {
    const scans = await prisma.scan.findMany({
      where: { repoKind: 'apk' },
      orderBy: { id: 'desc' },
      take: 60,
      select: { id: true, repoFull: true, status: true, insertedAt: true },
    });
    res.json({
      scans: scans.map((s) => ({
        id: s.id.toString(),
        label: s.repoFull,
        status: s.status,
      })),
    });
  } catch (e) {
    next(e);
  }
});

export default router;
