// A deleted record stays deleted (tombstones.js, 17 Nov 2026).
//
// Before this the registry forgot a deleted id at once, so a save already on its way, another
// tab, or a restored backup put the row back with its proof code and check link. Now:
//   - a save or dating row of a deleted id is refused per row with code "deleted", for every
//     holder;
//   - a deleted record's proof code is never batched afterwards;
//   - /verify/:id says it was deleted by its holder, and whether it was anchored before.
// No network.
//
// SPDX-License-Identifier: Apache-2.0

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { randomBytes } from 'node:crypto';
import { untilReady, sealForTest, testBody } from './helpers.mjs';

const OPERATOR = 'tombstone-operator-token-0123456789abcdef0123';
const CONTRACT = '6a'.repeat(32);
process.env.DB_PATH = ':memory:';
process.env.VEILCORE_OTS = 'off';
process.env.VEILCORE_OPERATOR_TOKEN = OPERATOR;
process.env.VEILCORE_ANCHOR_NETWORK = 'mainnet';
process.env.VEILCORE_ANCHOR_CONTRACT = CONTRACT;
const require = createRequire(import.meta.url);
const { app, db } = require('../server.js');

const hex = (n = 32) => randomBytes(n).toString('hex');
const recordId = () => `VEIL-${hex(16).toUpperCase()}`;
let base, server;
before(async () => {
  server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  base = `http://127.0.0.1:${server.address().port}`;
  await untilReady(base);
});
after(() => server.close());

const call = async (method, path, holder, body, extra = {}) => {
  const res = await fetch(`${base}${path}`, {
    method,
    headers: {
      'content-type': 'application/json',
      'x-forwarded-for': `10.${randomBytes(3).join('.')}`,
      ...(holder ? { 'x-holder-key': holder } : {}),
      ...extra,
    },
    ...(body === undefined
      ? {}
      : { body: JSON.stringify(path === '/api/records/dating' || method === 'DELETE' ? body : testBody(method, path, holder, body)) }),
  });
  return { status: res.status, json: await res.json().catch(() => ({})) };
};
const operator = { 'x-operator-token': OPERATOR };
const date = (holder, rows) => call('PUT', '/api/records/dating', holder, rows);
const remove = (holder, ids) => call('DELETE', '/api/records', holder, { ids });

test('/health lists record-tombstones-v1', async () => {
  assert.ok((await call('GET', '/health')).json.features.includes('record-tombstones-v1'));
});

test('a deleted id is refused afterwards, as a save, a dating row, or from another holder', async () => {
  const holder = hex();
  const id = recordId();
  const fp = hex();
  assert.equal((await date(holder, [{ id, recordFingerprint: fp }])).json.ok, true);
  const gone = await remove(holder, [id]);
  assert.deepEqual(gone.json, { ok: true, removed: [id] });

  // The same holder's late save (another tab, a restored backup): refused by id, nothing stored.
  const box = sealForTest({ id, recordFingerprint: fp, nonce: hex(), strainName: 'Back' }, randomBytes(32));
  const save = await call('PUT', '/api/records', holder, [box]);
  assert.equal(save.json.ok, false, JSON.stringify(save.json));
  assert.equal(save.json.rejected[0].code, 'deleted');
  assert.equal(db.prepare('SELECT 1 FROM records WHERE id = ?').get(id), undefined);

  const again = await date(holder, [{ id, recordFingerprint: fp }]);
  assert.equal(again.json.rejected?.[0]?.code, 'deleted', JSON.stringify(again.json));
  const other = await date(hex(), [{ id, recordFingerprint: hex() }]);
  assert.equal(other.json.rejected?.[0]?.code, 'deleted', JSON.stringify(other.json));
  assert.equal(db.prepare('SELECT 1 FROM records WHERE id = ?').get(id), undefined);
});

test('a record deleted before its batch is never batched, and its check link says it was deleted', async () => {
  const holder = hex();
  const id = recordId();
  const fp = hex();
  await date(holder, [{ id, recordFingerprint: fp }]);
  await remove(holder, [id]);
  const pending = await call('GET', '/batches/pending', undefined, undefined, operator);
  assert.ok(!pending.json.records.includes(id));
  await call('POST', '/batches/seal', undefined, {}, operator);
  assert.equal((await call('GET', `/proof/${fp}`)).status, 404);

  const v = await call('GET', `/verify/${id}`);
  assert.equal(v.status, 404);
  assert.equal(v.json.found, false);
  assert.equal(v.json.deleted, true);
  assert.equal(v.json.deletedBy, 'record-holder');
  assert.equal(v.json.anchored, false);
  assert.match(v.json.deletedAt, /^\d{4}-\d\d-\d\dT/);
});

test('a record deleted after its batch was anchored: the check link still names the anchor', async () => {
  const holder = hex();
  const id = recordId();
  const fp = hex();
  await date(holder, [{ id, recordFingerprint: fp }]);
  const { batchId } = (await call('POST', '/batches/seal', undefined, {}, operator)).json;
  const tx = 'ab'.repeat(32);
  const anchored = await call('POST', `/batches/${batchId}/anchor`, undefined, { network: 'mainnet', contractAddress: CONTRACT, txHash: tx, blockHeight: 7 }, operator);
  assert.equal(anchored.status, 200, JSON.stringify(anchored.json));
  await remove(holder, [id]);
  const v = await call('GET', `/verify/${id}`);
  assert.equal(v.json.deleted, true);
  assert.equal(v.json.anchored, true);
  assert.equal(v.json.anchor.txHash, tx);
  assert.equal(v.json.anchorCheckedOnChain, false);
});

test('an id never stored still answers plain not found, and deleting someone else’s record leaves no tombstone', async () => {
  const id = recordId();
  assert.deepEqual((await call('GET', `/verify/${id}`)).json, { found: false });
  const owner = hex();
  await date(owner, [{ id, recordFingerprint: hex() }]);
  const r = await remove(hex(), [id]);
  assert.deepEqual(r.json.removed, []);
  assert.equal(r.json.ok, false);
  assert.equal(db.prepare('SELECT 1 FROM record_tombstones WHERE id = ?').get(id), undefined);
  assert.equal((await date(owner, [{ id, recordFingerprint: hex() }])).json.rejected?.[0]?.code, undefined);
});
