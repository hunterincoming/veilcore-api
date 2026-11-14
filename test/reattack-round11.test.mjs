// Independent re-attack of the round 11 fixes. Each test now asserts the attack is refused (they asserted the behaviour
// that is a problem, so a passing test is a demonstrated finding.
// SPDX-License-Identifier: Apache-2.0

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { canonicalise, sha256Hex, newNonce } from 'veilcore-records';
import { untilReady, testBody } from './helpers.mjs';

process.env.DB_PATH = ':memory:';
process.env.VEILCORE_OPERATOR_TOKEN = 'test-operator-token-at-least-32-chars';
const require = createRequire(import.meta.url);
const { app } = require('../server.js');

let base;
let server;
before(async () => {
  server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  base = `http://127.0.0.1:${server.address().port}`;
  await untilReady(base);
});
after(() => server.close());

const call = async (method, path, { holder, body } = {}) => {
  const res = await fetch(`${base}${path}`, {
    method,
    headers: { 'content-type': 'application/json', ...(holder ? { 'x-holder-key': holder } : {}) },
    body: body === undefined ? undefined : JSON.stringify(testBody(method, path, holder, body)),
  });
  const text = await res.text();
  let json;
  try { json = JSON.parse(text); } catch { json = text; }
  return { status: res.status, json, text };
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const key = () => [...crypto.getRandomValues(new Uint8Array(32))].map((b) => b.toString(16).padStart(2, '0')).join('');

const makeRecord = async (id, over = {}) => {
  const r = {
    id, strainName: 'Test Cultivar', bredBy: 'Breeder', dateCreated: '2026-01-01',
    loggedAt: Date.now(), nonce: newNonce(), notes: 'n', parents: [], photoFingerprints: [],
    breedingMethod: '', refId: '', ...over,
  };
  r.recordFingerprint = await sha256Hex(canonicalise({
    breedingMethod: r.breedingMethod, bredBy: r.bredBy, dateCreated: r.dateCreated, loggedAt: r.loggedAt,
    nonce: r.nonce, notes: r.notes, parents: r.parents, photoFingerprints: r.photoFingerprints,
    refId: r.refId, strainName: r.strainName,
  }));
  return r;
};

test('R1 a content swap on a record with no commitment restarts the registry date', async () => {
  const holder = key();
  const put1 = await call('PUT', '/api/records', { holder, body: [{ id: 'VEIL-PRECAN', strainName: 'Placeholder' }] });
  assert.equal(put1.json.count, 1);
  const first = (await call('GET', '/verify/VEIL-PRECAN')).json;
  await sleep(60);
  const swapAt = Date.now();
  await call('PUT', '/api/records', {
    holder, body: [{ id: 'VEIL-PRECAN', strainName: 'Prize Cultivar', bredBy: 'Someone Famous', loggedAt: '2021-01-01' }],
  });
  const v = (await call('GET', '/verify/VEIL-PRECAN')).json;
  assert.notEqual(v.registryFirstSeen, first.registryFirstSeen);
  assert.ok(Date.parse(v.registryFirstSeen) >= swapAt - 5, 'the date is when this content arrived');
});

test('R2 a holder past 500 records still saves, and re-sent records are not counted twice', async () => {
  const holder = key();
  const batch = [];
  for (let i = 0; i < 500; i++) batch.push(await makeRecord(`VEIL-BULK${i}`));
  assert.equal((await call('PUT', '/api/records', { holder, body: batch })).json.count, 500);
  const next = [await makeRecord('VEIL-BULK-NEW'), ...batch];
  const r = await call('PUT', '/api/records', { holder, body: next });
  assert.equal(r.status, 200);
  const mine = (await call('GET', '/api/records', { holder })).json;
  assert.equal(mine.some((x) => x.id === 'VEIL-BULK-NEW'), true);
  assert.equal(mine.length, 501);
});

test('R3 a record cannot claim to correct another holder\'s record', async () => {
  const victim = key();
  const attacker = key();
  const v = await makeRecord('VEIL-VICTIM-1');
  await call('PUT', '/api/records', { holder: victim, body: [v] });
  const a = await makeRecord('VEIL-ATTACK-1', { strainName: 'Test Cultivar' });
  a.supersedes = { recordId: 'VEIL-VICTIM-1', changedFields: ['strainName'], effectiveAt: '2026-10-01T00:00:00Z' };
  const put = await call('PUT', '/api/records', { holder: attacker, body: [a] });
  assert.equal(put.json.count, 0);
  assert.match(put.json.rejected[0].reason, /belongs to another holder/);
});

test('R4 a claim only inherits the sender\'s own record, not one re-stored under the same id', async () => {
  const sender = key();
  const recipient = key();
  const attacker = key();
  const rec = await makeRecord('VEIL-SRC-DEL', { strainName: 'Real' });
  await call('PUT', '/api/records', { holder: sender, body: [rec] });
  const offer = await call('POST', '/transfers', { holder: sender, body: { sourceRecord: rec.id, toHandle: 'r@x' } });
  await call('DELETE', '/api/records', { holder: sender, body: { ids: [rec.id] } });
  const fake = await makeRecord('VEIL-SRC-DEL', { strainName: 'Attacker content' });
  assert.equal((await call('PUT', '/api/records', { holder: attacker, body: [fake] })).json.count, 1);
  const claim = await call('POST', `/transfers/${offer.json.transferId}/claim`, {
    holder: recipient, body: { claimCode: offer.json.claimCode },
  });
  assert.notEqual(claim.status, 200);
  const attackerView = (await call('GET', '/api/records', { holder: attacker })).json;
  assert.equal(attackerView[0].attestation?.type, undefined, 'the attacker\'s record gets no receipt');
});
