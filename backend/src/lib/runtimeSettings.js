import { readFile } from 'node:fs/promises';

import { parseEnvironmentText, PROJECT_ENV_FILE_PATH, updateEnvironmentFile } from './environmentFile.js';
import { ValidationError } from './validation.js';

export const ENGINE_RUNTIME_CONFIG_PATH =
  process.env.OPEN_KRITT_ENGINE_RUNTIME_CONFIG_PATH || '/engine-data/engine-runtime.env';

export const RUNTIME_SETTING_DEFINITIONS = Object.freeze({
  workerCount: Object.freeze({
    envKey: 'ENGINE_WORKER_COUNT',
    defaultValue: 2,
    min: 0,
    max: 128,
    recommendedMax: 10,
    apply: 'live',
  }),
  maxConcurrentScans: Object.freeze({
    envKey: 'ENGINE_MAX_CONCURRENT_SCANS',
    defaultValue: 1,
    min: 1,
    max: 128,
    recommendedMax: 4,
    apply: 'live',
  }),
  maxWorkersPerScan: Object.freeze({
    envKey: 'ENGINE_MAX_WORKERS_PER_SCAN',
    defaultValue: 0,
    min: 0,
    max: 128,
    recommendedMax: 10,
    apply: 'live',
  }),
  autoscaleScanWorkersOnProviderCapacity: Object.freeze({
    envKey: 'ENGINE_AUTOSCALE_SCAN_WORKERS_ON_PROVIDER_CAPACITY',
    defaultValue: true,
    type: 'boolean',
    apply: 'live',
  }),
  workspaceSetupConcurrency: Object.freeze({
    envKey: 'ENGINE_WORKSPACE_SETUP_CONCURRENCY',
    defaultValue: 2,
    min: 1,
    max: 32,
    recommendedMax: 4,
    apply: 'restart',
  }),
  retryCount: Object.freeze({
    envKey: 'ENGINE_RETRY_COUNT',
    defaultValue: 2,
    min: 0,
    max: 10,
    recommendedMax: 2,
    apply: 'live',
  }),
  harnessTimeoutSeconds: Object.freeze({
    envKey: 'ENGINE_HARNESS_TIMEOUT_SECONDS',
    defaultValue: 7200,
    min: 60,
    max: 86400,
    recommendedMax: 7200,
    apply: 'live',
  }),
});

async function environmentValues(filePath) {
  if (!filePath) return {};
  try {
    return parseEnvironmentText(await readFile(filePath, 'utf8'));
  } catch (error) {
    if (error?.code === 'ENOENT') return {};
    throw error;
  }
}

function parsedSettingValue(raw, definition) {
  if (raw === undefined) return { value: definition.defaultValue, valid: true };
  const text = `${raw}`.trim();
  if (definition.type === 'boolean') {
    if (/^(?:1|true|yes|on)$/i.test(text)) return { value: true, valid: true };
    if (/^(?:0|false|no|off)$/i.test(text)) return { value: false, valid: true };
    return { value: definition.defaultValue, valid: false };
  }
  if (!/^-?\d+$/.test(text)) return { value: definition.defaultValue, valid: false };
  const value = Number(text);
  if (!Number.isSafeInteger(value) || value < definition.min || value > definition.max) {
    return { value: definition.defaultValue, valid: false };
  }
  return { value, valid: true };
}

function resolvedSetting(definition, runtimeValues, projectValues, env) {
  const candidates = [
    ['runtime_config', runtimeValues[definition.envKey]],
    ['process_environment', env[definition.envKey]],
    ['project_environment', projectValues[definition.envKey]],
  ];
  const [source, raw] = candidates.find(([, value]) => value !== undefined) || ['default', undefined];
  const parsed = parsedSettingValue(raw, definition);
  return {
    value: parsed.value,
    source,
    valid: parsed.valid,
    envKey: definition.envKey,
    type: definition.type || 'integer',
    defaultValue: definition.defaultValue,
    min: definition.min,
    max: definition.max,
    recommendedMax: definition.recommendedMax,
    apply: definition.apply,
  };
}

export async function readRuntimeSettings({
  runtimeConfigPath = ENGINE_RUNTIME_CONFIG_PATH,
  environmentFilePath = PROJECT_ENV_FILE_PATH,
  env = process.env,
} = {}) {
  const [runtimeValues, projectValues] = await Promise.all([
    environmentValues(runtimeConfigPath),
    environmentValues(environmentFilePath),
  ]);
  const settings = Object.fromEntries(
    Object.entries(RUNTIME_SETTING_DEFINITIONS).map(([key, definition]) => [
      key,
      resolvedSetting(definition, runtimeValues, projectValues, env),
    ])
  );
  return {
    generatedAt: new Date().toISOString(),
    settings,
    persistence: {
      runtimeConfig: Boolean(runtimeConfigPath),
      projectEnvironment: Boolean(environmentFilePath),
    },
    capabilities: {
      dedicatedScanConcurrency: { available: true },
      perScanConcurrency: { available: true },
      automaticScanResume: { available: false, trackedBy: 'RETRY-01' },
    },
  };
}

export function validateRuntimeSettingsPatch(body) {
  const errors = [];
  const values = {};
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    throw new ValidationError([{ field: 'settings', message: 'Settings must be an object.' }]);
  }

  for (const key of Object.keys(body)) {
    if (!Object.prototype.hasOwnProperty.call(RUNTIME_SETTING_DEFINITIONS, key)) {
      errors.push({ field: key, message: 'This runtime setting is not supported.' });
      continue;
    }
    const definition = RUNTIME_SETTING_DEFINITIONS[key];
    const raw = body[key];
    if (definition.type === 'boolean') {
      if (typeof raw !== 'boolean') {
        errors.push({ field: key, message: 'Choose enabled or disabled.' });
      } else {
        values[key] = raw;
      }
      continue;
    }
    const text = typeof raw === 'number' || typeof raw === 'string' ? `${raw}`.trim() : '';
    if (!/^-?\d+$/.test(text)) {
      errors.push({ field: key, message: 'Enter a whole number.' });
      continue;
    }
    const value = Number(text);
    if (!Number.isSafeInteger(value) || value < definition.min || value > definition.max) {
      errors.push({
        field: key,
        message: `Enter a value from ${definition.min} to ${definition.max}.`,
      });
      continue;
    }
    values[key] = value;
  }

  if (Object.keys(body).length === 0) {
    errors.push({ field: 'settings', message: 'Provide at least one setting to update.' });
  }
  if (errors.length) throw new ValidationError(errors);
  return values;
}

export async function updateRuntimeSettings(
  body,
  {
    runtimeConfigPath = ENGINE_RUNTIME_CONFIG_PATH,
    environmentFilePath = PROJECT_ENV_FILE_PATH,
    env = process.env,
  } = {}
) {
  const values = validateRuntimeSettingsPatch(body);
  const environmentUpdates = Object.fromEntries(
    Object.entries(values).map(([key, value]) => [RUNTIME_SETTING_DEFINITIONS[key].envKey, `${value}`])
  );

  const runtimeUpdate = await updateEnvironmentFile(environmentUpdates, { environmentFilePath: runtimeConfigPath });
  try {
    await updateEnvironmentFile(environmentUpdates, { environmentFilePath });
  } catch (error) {
    if (runtimeUpdate?.changed) {
      await updateEnvironmentFile(runtimeUpdate.previous, { environmentFilePath: runtimeConfigPath }).catch(() => {});
    }
    throw error;
  }

  return readRuntimeSettings({ runtimeConfigPath, environmentFilePath, env });
}
