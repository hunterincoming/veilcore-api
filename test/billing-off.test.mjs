// Paid plans switched off (the default, billing.js): nothing changes. Every billing route
// answers 404, a webhook is refused unread, and a holder keeps as many records as before.
//
// SPDX-License-Identifier: Apache-2.0

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { randomBytes } from 'node:crypto';
import { untilReady, testBody } from './helpers.mjs';

process.env.DB_PATH = ':memory:';
process.env.VEILCORE_OTS = 'off';
process.env.VEILCORE_OPERATOR_TOKEN = 'billing-off-operator-token-0123456789abcdef';
delete process.env.BILLING;
const require = createRequire(import.meta.url);
const { app } = require('../server.js');

const hex = (n = 32) => randomBytes(n).toString('hex');
let base, server;
before(async () => {
  server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  base = `http://127.0.0.1:${server.address().port}`;
  await untilReady(base);
});
after(() => server.close());

const call = async (method, path, holder, body) => {
  const res = await fetch(`${base}${path}`, {
    method,
    headers: { 'content-type': 'application/json', ...(holder ? { 'x-holder-key': holder } : {}) },
    ...(body === undefined ? {} : { body: JSON.stringify(path === '/api/records' ? testBody(method, path, holder, body) : body) }),
  });
  return { status: res.status, json: await res.json() };
};

test('off: /health does not list billing-v1', async () => {
  const h = await (await fetch(`${base}/health`)).json();
  assert.ok(!h.features.includes('billing-v1'));
});

test('off: billing routes answer 404 and a webhook is not read', async () => {
  const holder = hex();
  assert.equal((await call('POST', '/api/billing/checkout', holder, { plan: 'breeder' })).status, 404);
  assert.equal((await call('GET', '/api/billing/plan', holder)).status, 404);
  assert.equal((await call('POST', '/api/billing/paddle', undefined, { event_id: 'evt_01x', event_type: 'subscription.created' })).status, 404);
});

test('off: a holder dates far more than any free number, as before', async () => {
  const holder = hex();
  const rows = Array.from({ length: 40 }, () => ({ id: `VEIL-${hex(16).toUpperCase()}`, recordFingerprint: hex() }));
  const r = await call('PUT', '/api/records/dating', holder, rows);
  assert.equal(r.status, 200);
  assert.equal(r.json.dated.length, 40, JSON.stringify(r.json));
});

// An intended change in this branch, off as on: at the registry's own ceiling a save refuses only
// its new rows (each in `rejected`, status 200) and stores the rest; it used to refuse the whole
// save with a 413. An id held by another holder isn't counted as new, since it isn't written.
test('off: at the 10,000 ceiling only the new rows are refused, and ids held by others are not new', async () => {
  const { db } = require('../server.js');
  const { storedHolderKey } = require('../holder-key.js');
  const holder = hex();
  const stored = storedHolderKey(holder);
  const insert = db.prepare('INSERT INTO records (id, holder_key, body, updated_at, first_seen) VALUES (?, ?, ?, 1, 1)');
  const rows = [];
  db.transaction(() => {
    for (let i = 0; i < 10_000; i++) {
      const r = { id: `VEIL-${hex(16).toUpperCase()}`, recordFingerprint: hex() };
      insert.run(r.id, stored, JSON.stringify(r));
      if (i < 2) rows.push(r);
    }
  })();
  const other = hex();
  const theirs = { id: `VEIL-${hex(16).toUpperCase()}`, recordFingerprint: hex(), nonce: hex(), strainName: 'T' };
  const t = await call('PUT', '/api/records', other, [theirs]);
  assert.equal(t.json.ok, true, JSON.stringify(t));
  const fresh = { id: `VEIL-${hex(16).toUpperCase()}`, recordFingerprint: hex(), nonce: hex(), strainName: 'N' };
  const edited = { ...rows[0], nonce: hex(), strainName: 'E' };
  const r = await call('PUT', '/api/records', holder, [edited, { ...theirs, recordFingerprint: hex() }, fresh]);
  assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.deepEqual(r.json.rejected?.map((x) => x.id), [fresh.id], JSON.stringify(r.json));
  assert.equal(r.json.rejected[0].code, undefined, 'the registry ceiling, not a plan');
  assert.deepEqual(r.json.notWritten, [theirs.id]);
});
