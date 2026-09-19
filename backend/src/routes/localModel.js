// Local model (llama.cpp) control from the UI. The native engine worker owns the
// llama-server process and shares state via public.local_model_config (created by the
// engine). The backend only reads/writes that row: config edits + a restart request
// (restart_token bump the engine acts on) + the status the engine publishes.
import { Router } from 'express';
import { prisma } from '../db.js';
import { ValidationError } from '../lib/validation.js';

const router = Router();

const REASONING_EFFORTS = ['low', 'medium', 'high'];

// Best-effort table creation so the API works even if the engine hasn't booted yet.
async function ensureTable() {
  await prisma.$executeRawUnsafe(`
    CREATE TABLE IF NOT EXISTS public.local_model_config (
      id integer PRIMARY KEY DEFAULT 1,
      base_url text NOT NULL DEFAULT 'http://127.0.0.1:8005/v1',
      model_name text NOT NULL DEFAULT 'local',
      reasoning_effort text NOT NULL DEFAULT 'medium',
      llama_dir text, model_file text, mmproj_file text,
      autostart boolean NOT NULL DEFAULT true,
      restart_token bigint NOT NULL DEFAULT 0,
      status text NOT NULL DEFAULT 'unknown', status_detail text, status_at timestamptz,
      updated_at timestamptz NOT NULL DEFAULT now(),
      CONSTRAINT local_model_config_singleton CHECK (id = 1)
    )`);
  await prisma.$executeRawUnsafe(
    `ALTER TABLE public.local_model_config ADD COLUMN IF NOT EXISTS desired_running boolean NOT NULL DEFAULT true`
  );
  await prisma.$executeRawUnsafe(
    `INSERT INTO public.local_model_config (id) VALUES (1) ON CONFLICT (id) DO NOTHING`
  );
}

async function readConfig() {
  await ensureTable();
  const rows = await prisma.$queryRawUnsafe(`
    SELECT base_url, model_name, reasoning_effort, llama_dir, model_file, mmproj_file,
           autostart, restart_token, status, status_detail, status_at, updated_at, desired_running
    FROM public.local_model_config WHERE id = 1`);
  const r = rows[0] || {};
  // Whether the engine's status heartbeat is fresh (< 30s old) — drives the live icon.
  const ageMs = r.status_at ? Date.now() - new Date(r.status_at).getTime() : null;
  const stale = ageMs === null || ageMs > 30_000;
  return {
    baseUrl: r.base_url ?? '',
    modelName: r.model_name ?? 'local',
    reasoningEffort: r.reasoning_effort ?? 'medium',
    llamaDir: r.llama_dir ?? '',
    modelFile: r.model_file ?? '',
    mmprojFile: r.mmproj_file ?? '',
    autostart: r.autostart ?? true,
    restartToken: r.restart_token != null ? Number(r.restart_token) : 0,
    status: stale ? 'unknown' : r.status ?? 'unknown',
    statusDetail: r.status_detail ?? null,
    statusAt: r.status_at ?? null,
    statusStale: stale,
    desiredRunning: r.desired_running ?? true,
    updatedAt: r.updated_at ?? null,
  };
}

// GET /api/local-model — config + live status.
router.get('/', async (req, res, next) => {
  try {
    res.json(await readConfig());
  } catch (e) {
    next(e);
  }
});

// PATCH /api/local-model — update the editable config fields.
router.patch('/', async (req, res, next) => {
  try {
    const body = req.body || {};
    const errors = [];
    const sets = [];
    const params = [];
    const put = (col, val) => {
      params.push(val);
      sets.push(`${col} = $${params.length}`);
    };

    if (body.baseUrl !== undefined) {
      const url = String(body.baseUrl).trim();
      if (!/^https?:\/\/[^\s]+$/i.test(url)) errors.push({ field: 'baseUrl', message: 'Enter a valid http(s) URL, e.g. http://127.0.0.1:8005/v1.' });
      else put('base_url', url);
    }
    if (body.modelName !== undefined) {
      const name = String(body.modelName).trim();
      if (!name) errors.push({ field: 'modelName', message: 'Model name is required.' });
      else put('model_name', name);
    }
    if (body.reasoningEffort !== undefined) {
      const eff = String(body.reasoningEffort).trim().toLowerCase();
      if (!REASONING_EFFORTS.includes(eff)) errors.push({ field: 'reasoningEffort', message: 'Choose low, medium, or high.' });
      else put('reasoning_effort', eff);
    }
    if (body.llamaDir !== undefined) put('llama_dir', String(body.llamaDir).trim() || null);
    if (body.modelFile !== undefined) put('model_file', String(body.modelFile).trim() || null);
    if (body.mmprojFile !== undefined) put('mmproj_file', String(body.mmprojFile).trim() || null);
    if (body.autostart !== undefined) {
      if (typeof body.autostart !== 'boolean') errors.push({ field: 'autostart', message: 'Choose enabled or disabled.' });
      else put('autostart', body.autostart);
    }

    if (errors.length) throw new ValidationError(errors);
    if (!sets.length) throw new ValidationError([{ field: 'config', message: 'Provide at least one field to update.' }]);

    await ensureTable();
    await prisma.$executeRawUnsafe(
      `UPDATE public.local_model_config SET ${sets.join(', ')}, updated_at = now() WHERE id = 1`,
      ...params
    );
    res.json(await readConfig());
  } catch (e) {
    next(e);
  }
});

// POST /api/local-model/restart — ask the engine to restart llama-server.
router.post('/restart', async (req, res, next) => {
  try {
    await ensureTable();
    await prisma.$executeRawUnsafe(
      `UPDATE public.local_model_config SET desired_running = true, restart_token = restart_token + 1, status = 'starting', status_detail = 'restart requested', updated_at = now() WHERE id = 1`
    );
    res.json(await readConfig());
  } catch (e) {
    next(e);
  }
});

// POST /api/local-model/stop — ask the engine to stop llama-server and keep it stopped.
router.post('/stop', async (req, res, next) => {
  try {
    await ensureTable();
    await prisma.$executeRawUnsafe(
      `UPDATE public.local_model_config SET desired_running = false, restart_token = restart_token + 1, status = 'stopping', status_detail = 'stop requested', updated_at = now() WHERE id = 1`
    );
    res.json(await readConfig());
  } catch (e) {
    next(e);
  }
});

// POST /api/local-model/start — ask the engine to start llama-server (from stopped).
router.post('/start', async (req, res, next) => {
  try {
    await ensureTable();
    await prisma.$executeRawUnsafe(
      `UPDATE public.local_model_config SET desired_running = true, restart_token = restart_token + 1, status = 'starting', status_detail = 'start requested', updated_at = now() WHERE id = 1`
    );
    res.json(await readConfig());
  } catch (e) {
    next(e);
  }
});

export default router;
