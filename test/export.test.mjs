// The holder's export: everything the registry holds for a holder key, and nothing of
// anyone else's.
// SPDX-License-Identifier: Apache-2.0

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { testBody } from './helpers.mjs';

process.env.DB_PATH = ':memory:';
process.env.VEILCORE_OPERATOR_TOKEN = 'test-operator-token-at-least-32-chars';
process.env.VEILCORE_OTS = 'off';
const require = createRequire(import.meta.url);
const { app } = require('../server.js');

let base;
let server;
before(async () => {
  server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  base = `http://127.0.0.1:${server.address().port}`;
});
after(() => server.close());

const put = (path, holder, body) => fetch(`${base}${path}`, { method: 'PUT', headers: { 'content-type': 'application/json', 'x-holder-key': holder }, body: JSON.stringify(testBody('PUT', path, holder, body)) });

test('an export holds the holder\'s records and licences, and no one else\'s (proofs: see ots.test.mjs)', async () => {
  const A = 'aa'.repeat(32);
  const B = 'bb'.repeat(32);
  assert.equal((await put('/api/records', A, [{ id: 'rec-a1', strainName: 'Harbour Mist' }])).status, 200);
  assert.equal((await put('/api/records', B, [{ id: 'rec-b1', strainName: 'Other' }])).status, 200);
  const r = await fetch(`${base}/api/export`, { headers: { 'x-holder-key': A } });
  assert.equal(r.status, 200);
  assert.match(r.headers.get('content-disposition') ?? '', /veilcore-export\.json/);
  const out = await r.json();
  assert.equal(out.format, 'veilcore-registry-export/v1');
  assert.deepEqual(out.records.map((x) => x.id), ['rec-a1']);
  assert.ok(!JSON.stringify(out).includes('rec-b1'), 'nothing of another holder');
  assert.deepEqual(out.proofs, {}, 'no proofs for records that are not in a batch');
  assert.match(out.note, /never sent here/);
});

test('no holder key, no export', async () => {
  assert.equal((await fetch(`${base}/api/export`)).status, 401);
});
