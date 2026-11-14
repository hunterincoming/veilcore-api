// GET /records/:id/evidence: one record's evidence, for the holder's evidence bundle.
// The holder's own record and nothing of anyone else's; its proof, batch root, every anchor
// the batch has had, the batch's .ots file, and the lab signatures about the record.
// SPDX-License-Identifier: Apache-2.0

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { createHash, randomBytes } from 'node:crypto';
import { canonicalise, sha256Hex, newNonce, verifyInclusion, generateKeypair, signAttestation, verifyAttestation } from 'veilcore-records';
import { keyBoundFingerprint, keyBindingOf, identityFromSecret, keySaltOf } from '../lineage/key-binding.mjs';
import { inOneMinute, untilReady, testBody, openForTest, vaultKeyFor } from './helpers.mjs';

const ANCHOR_CONTRACT = '7a'.repeat(32);
process.env.DB_PATH = ':memory:';
process.env.VEILCORE_OPERATOR_TOKEN = 'test-operator-token-at-least-32-chars';
process.env.VEILCORE_OTS = 'off';
process.env.VEILCORE_ANCHOR_NETWORK = 'preprod';
process.env.VEILCORE_ANCHOR_CONTRACT = ANCHOR_CONTRACT;
const require = createRequire(import.meta.url);
const { app, db } = require('../server.js');
const OP = { 'x-operator-token': 'test-operator-token-at-least-32-chars' };

let base, server;
before(async () => {
  server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  base = `http://127.0.0.1:${server.address().port}`;
  await untilReady(base);
});
after(() => server.close());

const call = async (method, path, { holder, body, headers = {} } = {}) => {
  const res = await fetch(`${base}${path}`, {
    method,
    headers: { 'content-type': 'application/json', ...(holder ? { 'x-holder-key': holder } : {}), ...headers },
    ...(body === undefined ? {} : { body: JSON.stringify(testBody(method, path, holder, body)) }),
  });
  const text = await res.text();
  let json; try { json = JSON.parse(text); } catch { json = text; }
  return { status: res.status, json };
};
const evidence = (id, holder) => call('GET', `/records/${encodeURIComponent(id)}/evidence`, { holder });

const committedOf = (r) => ({ breedingMethod: r.breedingMethod ?? '', bredBy: r.bredBy, dateCreated: r.dateCreated,
  loggedAt: r.loggedAt, nonce: r.nonce, notes: r.notes, parents: r.parents ?? [],
  photoFingerprints: r.photoFingerprints ?? [], refId: r.refId ?? '', strainName: r.strainName,
  ...(r.keyBinding !== undefined ? { keyBinding: r.keyBinding } : {}) });

const sealed = async (over = {}) => {
  const r = { id: `VEIL-${randomBytes(8).toString('hex').toUpperCase()}`, strainName: 'Harbour Mist', bredBy: 'B',
    dateCreated: '2026-01-01', loggedAt: 1760000000000, nonce: newNonce(), notes: '', parents: [], photoFingerprints: [],
    breedingMethod: '', refId: '', ...over };
  const content = await sha256Hex(canonicalise(committedOf(r)));
  r.recordFingerprint = r.keyBinding ? keyBoundFingerprint(r.keyBinding, content) : content;
  return r;
};
const save = async (holder, rec) => {
  const put = await call('PUT', '/api/records', { holder, body: [rec] });
  assert.equal(put.status, 200, JSON.stringify(put.json));
  assert.equal(put.json.count, 1, JSON.stringify(put.json));
  assert.equal(put.json.integrityCheckedBy, 'holder');
};
const key = () => randomBytes(32).toString('hex');

test('no holder key: 401; another holder\'s record or none: the same 404', async () => {
  const A = key();
  const B = key();
  const rec = await sealed();
  await save(A, rec);
  assert.equal((await evidence(rec.id)).status, 401);
  const other = await evidence(rec.id, B);
  const none = await evidence('VEIL-NOPE', B);
  assert.equal(other.status, 404);
  assert.equal(none.status, 404);
  assert.deepEqual(other.json, none.json, 'the answer never says an id exists');
});

test('a record not in a batch yet: the record and its first-seen date, no proof, no batch', async () => {
  const A = key();
  const rec = await sealed();
  await save(A, rec);
  const r = await evidence(rec.id, A);
  assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.equal(r.json.format, 'veilcore-record-evidence/v1');
  assert.equal(r.json.recordId, rec.id);
  assert.equal(r.json.record.recordFingerprint, rec.recordFingerprint);
  assert.equal(r.json.record.nonce, undefined, 'stored sealed');
  assert.equal(openForTest(r.json.record, vaultKeyFor(A)).nonce, rec.nonce, 'the holder\'s own copy, nonce included');
  assert.match(r.json.registryFirstSeen, /^\d{4}-\d{2}-\d{2}T/);
  assert.equal(r.json.proof, null);
  assert.equal(r.json.batch, null);
  assert.deepEqual(r.json.attestations, []);
  assert.match(r.json.note, /not checked on any chain/);
  // The holder key works in any case, like every other holder route.
  assert.equal((await evidence(rec.id, A.toUpperCase())).status, 200);
});

test('sealed and anchored: a proof that folds to the batch root, the anchor, every earlier anchor, and the .ots', async () => {
  const A = key();
  const secret = key();
  const keyBinding = keyBindingOf(identityFromSecret(secret), keySaltOf(secret));
  const old = await sealed({ strainName: 'Old form' });
  const bound = await sealed({ strainName: 'Key-bound form', keyBinding });
  await save(A, old);
  await save(A, bound);

  const s = await call('POST', '/batches/seal', { headers: OP });
  assert.equal(s.status, 200, JSON.stringify(s.json));
  const batchId = s.json.batchId;
  const txHash = 'c3'.repeat(32);
  const anchored = await call('POST', `/batches/${batchId}/anchor`, {
    headers: OP,
    body: { network: 'preprod', contractAddress: ANCHOR_CONTRACT, txHash, blockHeight: 1234, anchoredAt: new Date().toISOString() },
  });
  assert.equal(anchored.status, 200, JSON.stringify(anchored.json));

  // An anchor this batch had before (kept by the registry when a later one replaced it).
  db.prepare('INSERT INTO batch_anchor_history (batch_id, anchor, replaced_at) VALUES (?,?,?)').run(
    batchId, JSON.stringify({ chain: 'midnight', network: 'preview', contractAddress: '11'.repeat(32), txHash: 'd4'.repeat(32) }), Date.now(),
  );

  for (const rec of [old, bound]) {
    const r = await evidence(rec.id, A);
    assert.equal(r.status, 200, JSON.stringify(r.json));
    const { proof, batch } = r.json;
    assert.equal(proof.commitment, rec.recordFingerprint);
    assert.equal(await verifyInclusion(proof), true, 'the proof folds to its root');
    assert.equal(batch.batchId, batchId);
    assert.equal(batch.root, proof.root, 'the batch root is the root the proof names');
    assert.equal(proof.anchor.txHash, txHash);
    assert.equal(batch.anchor.txHash, txHash);
    assert.equal(batch.anchor.network, 'preprod');
    assert.equal(batch.anchor.testNetwork, true);
    assert.equal(batch.earlierAnchors.length, 1);
    assert.equal(batch.earlierAnchors[0].txHash, 'd4'.repeat(32));
    assert.equal(batch.earlierAnchors[0].network, 'preview');
    assert.equal(batch.opentimestamps.available, false, 'OpenTimestamps is off in tests');
    assert.equal(batch.opentimestamps.ots, undefined);
  }

  // Once the batch has a stamp file, it comes in the answer itself, as the export carries it.
  const fakeOts = Buffer.concat([Buffer.from('\x00OpenTimestamps\x00\x00Proof\x00', 'latin1'), randomBytes(40)]);
  db.prepare("UPDATE batches SET ots = ?, ots_status = 'pending', ots_calendars = ? WHERE batch_id = ?")
    .run(fakeOts, JSON.stringify(['https://a.pool.opentimestamps.org']), batchId);
  const withOts = await evidence(bound.id, A);
  assert.equal(withOts.json.batch.opentimestamps.available, true);
  assert.equal(withOts.json.batch.opentimestamps.status, 'pending');
  assert.equal(Buffer.from(withOts.json.batch.opentimestamps.ots, 'base64').toString('hex'), fakeOts.toString('hex'));
  assert.ok(withOts.json.proof.anchors.some((a) => a.kind === 'opentimestamps'));
});

test('the lab signatures about this record, and none about any other', async () => {
  const A = key();
  const rec = await sealed({ strainName: 'Signed' });
  const other = await sealed({ strainName: 'Someone else' });
  await save(A, rec);
  await save(key(), other);
  const kp = await generateKeypair();
  const attest = async (subjectCommitment, documentHash, suffix = '', type = 'inspection') => {
    const signed = await signAttestation({
      attestationId: `att_${randomBytes(8).toString('hex')}${suffix}`, type, subjectCommitment, documentHash,
      hashAlgorithm: 'sha256', issuedAt: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
      attester: { publicKey: kp.publicKey, displayName: 'Test Lab' },
    }, kp.privateKey);
    const r = await call('POST', '/attestations', { body: signed });
    assert.equal(r.status, 200, JSON.stringify(r.json));
    return signed;
  };
  const fileSha = createHash('sha256').update('the lab report').digest('hex');
  const mine = await attest(rec.recordFingerprint, fileSha);
  await attest(other.recordFingerprint, fileSha);

  // Lab report signatures, of either form, private to the record's holder and the lab (8 Nov
  // 2026; hide-lab-reports.test.mjs): this holder holds the record, so the bundle has them all.
  // A stranger's /attestations/subject has none of them, nor the inspection, now by a lab key.
  await attest(rec.recordFingerprint, createHash('sha256').update('a bound report').digest('hex'), '_ld1', 'laboratory-report');
  await attest(rec.recordFingerprint, createHash('sha256').update('an older report').digest('hex'), '', 'laboratory-report');

  const r = await evidence(rec.id, A);
  assert.equal(r.status, 200);
  assert.equal(r.json.attestations.length, 3);
  assert.equal(r.json.attestationsTotal, 3);
  const pub = await call('GET', `/attestations/subject/${rec.recordFingerprint}`);
  assert.deepEqual([pub.json.attestations, pub.json.total], [[], 0]);
  const a = r.json.attestations.find((x) => x.attestationId === mine.attestationId);
  assert.equal(a.attestationId, mine.attestationId);
  assert.equal(a.subjectCommitment, rec.recordFingerprint);
  assert.equal(a.documentHash, fileSha);
  // As stored: the signature still checks, so the bundle's own page can check it.
  const { attestationId, type, subjectCommitment, documentHash, hashAlgorithm, issuedAt, attester, signature, signatureAlgorithm } = a;
  assert.equal(await verifyAttestation({ attestationId, type, subjectCommitment, documentHash, hashAlgorithm, issuedAt,
    attester: { publicKey: attester.publicKey, ...(attester.displayName ? { displayName: attester.displayName } : {}) },
    signature, signatureAlgorithm }), true);
});

test('evidence downloads are limited per holder key', async () => {
  const A = key();
  const rec = await sealed();
  await save(A, rec);
  const statuses = [];
  // In one minute, as a client hammering it would be (helpers.mjs).
  await inOneMinute(async () => {
    for (let i = 0; i < 22; i++) statuses.push((await evidence(rec.id, A)).status);
  });
  assert.ok(statuses.slice(0, 20).every((s) => s === 200), statuses.join(','));
  assert.equal(statuses[21], 429);
});
