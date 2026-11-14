// A strain or line record on the check page (/verify): the registry says it is a strain, and
// under the parent-names grant answers its parent strains by name and deposit number, as the
// holder's browser sent them for this version. Never a linked record's id. Test data only.
// SPDX-License-Identifier: Apache-2.0

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { newNonce } from 'veilcore-records';
import { recomputeCommitment } from '../lineage/conformance.mjs';
import { untilReady, testBody, grantForTest } from './helpers.mjs';

process.env.DB_PATH = ':memory:';
process.env.VEILCORE_OTS = 'off';
process.env.VEILCORE_OPERATOR_TOKEN = 'op-secret-token-at-least-32-characters';
const require = createRequire(import.meta.url);
const { app } = require('../server.js');

const V = JSON.parse(readFileSync(new URL('./fixtures/strain-v1.json', import.meta.url), 'utf8'));

let base, server;
before(async () => {
  server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  base = `http://127.0.0.1:${server.address().port}`;
  await untilReady(base);
});
after(() => server.close());

const key = () => randomBytes(32).toString('hex');
const call = async (method, path, holder, body) => {
  const res = await fetch(`${base}${path}`, {
    method,
    headers: { 'content-type': 'application/json', 'x-forwarded-for': `10.${randomBytes(3).join('.')}`, ...(holder ? { 'x-holder-key': holder } : {}) },
    ...(body === undefined ? {} : { body: JSON.stringify(testBody(method, path, holder, body)) }),
  });
  const text = await res.text();
  let json; try { json = JSON.parse(text); } catch { json = text; }
  return { status: res.status, json };
};

/** A fresh strain record in the site's stored shape, sealed under the profile. */
const strain = async (i, over = {}) => {
  const r = {
    ...structuredClone(V.records[i].appRecord),
    id: `VEIL-${randomBytes(16).toString('hex').toUpperCase()}`,
    nonce: newNonce(),
    licenseIds: [],
    ...over,
  };
  delete r.keyBinding;
  r.recordFingerprint = await recomputeCommitment(r);
  return r;
};

test('/verify: a strain says so; its parent strains (name and deposit) only under parent-names', async () => {
  const holder = key();
  const rec = await strain(0);
  assert.equal((await call('PUT', '/api/records', holder, [rec])).json.count, 1);

  const bare = (await call('GET', `/verify/${rec.id}`)).json;
  assert.equal(bare.subjectKind, 'strain');
  for (const f of ['parents', 'parentStrains', 'sire', 'dam', 'individualId']) assert.equal(bare[f], undefined, f);

  const g = await call('PUT', `/api/records/${rec.id}/disclosure`, holder, grantForTest(rec, ['parent-names']));
  assert.equal(g.status, 200, JSON.stringify(g.json));
  const v = (await call('GET', `/verify/${rec.id}`)).json;
  assert.deepEqual(v.parents, ['Practice Wild Type']);
  assert.deepEqual(v.parentStrains, [{ name: 'Practice Wild Type', deposit: 'NBRC 99998 (test data)' }]);
  assert.equal(v.sire, undefined);
  // The strain's own deposits, designation and notes are never in the public answer.
  const text = JSON.stringify(v);
  for (const f of rec.strain.deposits) assert.ok(!text.includes(f), f);
});

test('/verify: a strain parent linked to a logged record is answered by name only, never its record id', async () => {
  const holder = key();
  const rec = await strain(3);
  assert.equal((await call('PUT', '/api/records', holder, [rec])).json.count, 1);
  const grant = grantForTest(rec, ['parent-names']);
  grant.values.parents = grant.values.parents.map((p) => ({ ...p, recordId: 'VEIL-00000000000000000000000000000021' }));
  // A linked record's id sent with the grant is dropped, never stored or answered.
  assert.equal((await call('PUT', `/api/records/${rec.id}/disclosure`, holder, grant)).status, 200);
  const v = (await call('GET', `/verify/${rec.id}`)).json;
  assert.deepEqual(v.parentStrains, [{ name: 'Practice Parent Line', deposit: '' }]);
  assert.ok(!JSON.stringify(v).includes('VEIL-00000000000000000000000000000021'));
});

test('/verify: a plant record never answers parentStrains', async () => {
  const holder = key();
  const r = { id: `pl-${randomBytes(6).toString('hex')}`, strainName: 'Plant P', bredBy: 'B', dateCreated: '2026-01-01',
    loggedAt: 1760000000000, nonce: newNonce(), notes: '', parents: [{ name: 'Mother', individualId: 'X-1' }], photoFingerprints: [], breedingMethod: '', refId: 'LOT-1' };
  r.recordFingerprint = await recomputeCommitment(r);
  assert.equal((await call('PUT', '/api/records', holder, [r])).json.count, 1);
  assert.equal((await call('PUT', `/api/records/${r.id}/disclosure`, holder, grantForTest(r, ['parent-names']))).status, 200);
  const v = (await call('GET', `/verify/${r.id}`)).json;
  assert.equal(v.parentStrains, undefined);
  assert.deepEqual(v.parents, ['Mother']);
});
