import assert from 'node:assert/strict';
import { test } from 'node:test';

import { consumeCodexManualReset, fetchExecutorAccounts } from '../src/lib/accounts.js';

test('executor account integration loads each provider independently with the distinct internal bearer token', async (t) => {
  const originalFetch = globalThis.fetch;
  t.after(() => {
    globalThis.fetch = originalFetch;
  });
  const requests = [];
  globalThis.fetch = async (url, options) => {
    const request = { url: String(url), options };
    requests.push(request);
    const provider = new URL(request.url).pathname.split('/').at(-1);
    return {
      ok: true,
      async json() {
        return { kind: provider, accounts: [] };
      },
    };
  };

  const accounts = await fetchExecutorAccounts({
    refresh: true,
    executorViewUrl: 'http://executor-view:8090',
    internalToken: 'backend-only-token',
  });

  assert.deepEqual(
    accounts.providers.map((provider) => provider.kind),
    ['codex', 'claude', 'openrouter']
  );
  assert.deepEqual(
    requests.map((request) => request.url),
    [
      'http://executor-view:8090/api/accounts/codex?refresh=1',
      'http://executor-view:8090/api/accounts/claude?refresh=1',
      'http://executor-view:8090/api/accounts/openrouter?refresh=1',
    ]
  );
  assert.ok(requests.every((request) => request.options.headers.Authorization === 'Bearer backend-only-token'));
  assert.ok(requests.every((request) => request.options.redirect === 'error'));
});

test('executor account integration fails closed when its internal token is unavailable', async (t) => {
  const originalFetch = globalThis.fetch;
  t.after(() => {
    globalThis.fetch = originalFetch;
  });
  let called = false;
  globalThis.fetch = async () => {
    called = true;
    throw new Error('must not make an unauthenticated internal request');
  };

  const accounts = await fetchExecutorAccounts({
    executorViewUrl: 'http://executor-view:8090',
    internalToken: '',
    internalTokenFile: '/definitely/missing/internal-token',
  });

  assert.equal(accounts, null);
  assert.equal(called, false);
});

test('Codex reset integration uses only the selected internal account endpoint', async (t) => {
  const originalFetch = globalThis.fetch;
  t.after(() => {
    globalThis.fetch = originalFetch;
  });
  let request;
  globalThis.fetch = async (url, options) => {
    request = { url: String(url), options };
    return {
      ok: true,
      status: 200,
      async json() {
        return { outcome: 'reset', windowsReset: 1 };
      },
    };
  };

  const result = await consumeCodexManualReset('account/one', {
    executorViewUrl: 'http://executor-view:8090',
    internalToken: 'backend-only-token',
  });

  assert.deepEqual(result, { outcome: 'reset', windowsReset: 1 });
  assert.equal(request.url, 'http://executor-view:8090/api/accounts/codex/account%2Fone/reset');
  assert.equal(request.options.method, 'POST');
  assert.equal(request.options.headers.Authorization, 'Bearer backend-only-token');
});
