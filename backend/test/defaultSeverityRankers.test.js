import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  DEFAULT_SEVERITY_RANKERS,
  ensureDefaultSeverityRankers,
  isDefaultSeverityRankerName,
} from '../src/lib/defaultSeverityRankers.js';
import { serializeSeverityRanker } from '../src/lib/serialize.js';
import { validateSeverityRanker } from '../src/lib/validation.js';

test('ships valid conservative default severity rankers (blockchain + android)', () => {
  assert.equal(DEFAULT_SEVERITY_RANKERS.length, 2);
  for (const raw of DEFAULT_SEVERITY_RANKERS) {
    const ranker = validateSeverityRanker(raw);
    assert.match(ranker.content, /Critical:/);
    assert.match(ranker.content, /false positives last/i);
    assert.equal(isDefaultSeverityRankerName(ranker.name), true);
    assert.equal(
      serializeSeverityRanker({ id: 1n, ...ranker }, { isDefault: isDefaultSeverityRankerName(ranker.name) }).isDefault,
      true
    );
  }
  const names = DEFAULT_SEVERITY_RANKERS.map((r) => r.name);
  assert.ok(names.includes('Blockchain security triage'));
  const android = DEFAULT_SEVERITY_RANKERS.find((r) => r.name === 'Android mobile security triage');
  assert.ok(android, 'ships an Android mobile ranker');
  // Android-specific rank design: reachability-aware (exported vs chain-only).
  assert.match(android.content, /exported/i);
  assert.match(android.content, /chain/i);
});

test('default severity ranker installation is idempotent', async () => {
  const rows = [];
  const tx = {
    $executeRaw: async () => undefined,
    severityRanker: {
      findFirst: async ({ where }) => rows.find((row) => row.name === where.name) || null,
      create: async ({ data }) => {
        const row = { id: BigInt(rows.length + 1), ...data };
        rows.push(row);
        return row;
      },
    },
  };
  const client = { $transaction: async (callback) => callback(tx) };

  assert.deepEqual(await ensureDefaultSeverityRankers(client), [
    'Blockchain security triage',
    'Android mobile security triage',
  ]);
  assert.deepEqual(await ensureDefaultSeverityRankers(client), []);
  assert.equal(rows.length, 2);
});
