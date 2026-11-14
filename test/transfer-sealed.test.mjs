// Transfers with sealed records (the site's CONTRACT.md for sealed records, #8): the offer
// is sealed by the sender's browser with a key that travels only in the delivery code; the
// registry stores and returns it unread, writes the recipient only a stub, and writes the
// sender's attestation in place. Codes made before sealing keep working while their source
// is still plain text. No network.
//
// SPDX-License-Identifier: Apache-2.0

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { createHash, randomBytes } from 'node:crypto';
import { canonicalise, sha256Hex, newNonce } from 'veilcore-records';
import { untilReady, sealForTest, vaultKeyFor, sealOfferForTest, openOfferForTest, offerFromRecord, handleTagFor } from './helpers.mjs';

process.env.DB_PATH = ':memory:';
process.env.VEILCORE_OTS = 'off';
const require = createRequire(import.meta.url);
const { app, db } = require('../server.js');
const { storedHolderKey } = require('../holder-key.js');
const { OFFER_MAX_BYTES } = require('../sealed.js');

const key = () => randomBytes(32).toString('hex');
/** The recipient as the sender's browser names it to the registry: a tag, never the name (CONTRACT.md #15). */
const LAB_TAG = handleTagFor(key(), 'lab@x');
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
    headers: { 'content-type': 'application/json', 'x-forwarded-for': `10.${randomBytes(3).join('.')}`, ...(holder ? { 'x-holder-key': holder } : {}) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const text = await res.text();
  let json; try { json = JSON.parse(text); } catch { json = text; }
  return { status: res.status, json };
};

const committedOf = (r) => ({ breedingMethod: r.breedingMethod ?? '', bredBy: r.bredBy, dateCreated: r.dateCreated,
  loggedAt: r.loggedAt, nonce: r.nonce, notes: r.notes, parents: r.parents ?? [],
  photoFingerprints: r.photoFingerprints ?? [], refId: r.refId ?? '', strainName: r.strainName });
const makeRecord = async (id, over = {}) => {
  const r = { id, strainName: `Name ${id}`, bredBy: 'Breeder B', dateCreated: '2026-01-01', loggedAt: 1760000000000,
    nonce: newNonce(), notes: 'TOP SECRET', parents: [{ name: 'Secret Mother' }], photoFingerprints: [], breedingMethod: 'secret',
    refId: '', taxon: 'Malus domestica', ...over };
  r.recordFingerprint = await sha256Hex(canonicalise(committedOf(r)));
  return r;
};
const bodyOf = (id) => JSON.parse(db.prepare('SELECT body FROM records WHERE id = ?').get(id).body);
const transferRow = (id) => db.prepare('SELECT * FROM transfers WHERE id = ?').get(id);
/** A source record stored sealed by `sender`, and an offer key with the sealed offer for it. */
const sealedSource = async (sender, id, over) => {
  const src = await makeRecord(id, over);
  assert.equal((await call('PUT', '/api/records', sender, [sealForTest(src, vaultKeyFor(sender))])).json.count, 1);
  const offerKey = randomBytes(32);
  return { src, offerKey, sealedOffer: (o = {}) => sealOfferForTest(offerFromRecord(src, o), offerKey, src.id, src.recordFingerprint) };
};
/** A row as older code stored it: in plain text. */
const legacySource = async (sender, id, over) => {
  const src = await makeRecord(id, over);
  db.prepare('INSERT INTO records (id, holder_key, body, updated_at, first_seen) VALUES (?,?,?,?,?)')
    .run(src.id, storedHolderKey(sender), JSON.stringify(src), 1, 1);
  return src;
};

test('a sealed offer is stored unread and returned to the claimant exactly as sent; the claim writes only a stub', async () => {
  const sender = key(), lab = key();
  const { src, offerKey, sealedOffer } = await sealedSource(sender, 'tx-sealed-1');
  const box = sealedOffer({ quantity: '10 clones', note: 'invoice 4411' });
  const o = await call('POST', '/transfers', sender, { sourceRecord: src.id, toHandle: LAB_TAG, sealedOffer: box });
  assert.equal(o.status, 200, JSON.stringify(o.json));
  const row = transferRow(o.json.transferId);
  assert.equal(row.offer_sealed, JSON.stringify(box));
  assert.equal(row.quantity, null);
  assert.equal(row.note, null);
  const sourceBefore = bodyOf(src.id);

  const c = await call('POST', `/transfers/${o.json.transferId}/claim`, lab, { claimCode: o.json.claimCode });
  assert.equal(c.status, 200, JSON.stringify(c.json));
  assert.equal(JSON.stringify(c.json.offerSealed), JSON.stringify(box), 'byte for byte');
  assert.equal(c.json.offerPlain, undefined);
  assert.equal(c.json.quantity, null);
  assert.equal(c.json.note, null);
  assert.equal(c.json.needsSealing, true);
  assert.equal(c.json.parentCommitment, src.recordFingerprint);
  // The claimant's browser opens it with the key from the code.
  const offer = openOfferForTest(c.json.offerSealed, offerKey, src.id, src.recordFingerprint);
  assert.deepEqual(offer, { strainName: src.strainName, bredBy: 'Breeder B', dateCreated: '2026-01-01', taxon: 'Malus domestica', refId: '', quantity: '10 clones', note: 'invoice 4411' });

  // The stub: public fields and where it came from. No nonce, nothing of the sender's, and
  // since round 5 no name: that is in the offer.
  const stub = bodyOf(c.json.recordId);
  assert.deepEqual(stub, {
    id: c.json.recordId, receivedFrom: src.id, receivedFromCommitment: src.recordFingerprint,
    receivedAt: stub.receivedAt, transferId: o.json.transferId,
  });
  assert.equal(typeof stub.receivedAt, 'number');

  // The sender's record: the attestation is written in place; the sealed body is untouched.
  const sourceAfter = bodyOf(src.id);
  assert.equal(sourceAfter.attestation.type, 'receipt-confirmed');
  assert.equal(sourceAfter.attestation.transferId, o.json.transferId);
  const { attestation: _a, ...rest } = sourceAfter;
  void _a;
  assert.deepEqual(rest, sourceBefore);
  assert.equal(JSON.stringify(rest.sealed), JSON.stringify(sourceBefore.sealed));
});

test('the claimant seals the received record; the registry keeps where it came from, whatever the client sends', async () => {
  const sender = key(), lab = key();
  const { src, offerKey, sealedOffer } = await sealedSource(sender, 'tx-sealed-2');
  const o = await call('POST', '/transfers', sender, { sourceRecord: src.id, toHandle: LAB_TAG, sealedOffer: sealedOffer() });
  const c = await call('POST', `/transfers/${o.json.transferId}/claim`, lab, { claimCode: o.json.claimCode });
  const stub = (await call('GET', '/api/records', lab)).json[0];
  const offer = openOfferForTest(c.json.offerSealed, offerKey, src.id, src.recordFingerprint);
  const received = { ...stub, bredBy: offer.bredBy, dateCreated: offer.dateCreated, notes: '', parents: [], photoFingerprints: [],
    breedingMethod: '', refId: '', nonce: newNonce(), loggedAt: stub.receivedAt };
  received.recordFingerprint = await sha256Hex(canonicalise(committedOf(received)));
  // A copy that claims to come from elsewhere: those fields are the registry's.
  const forged = { ...sealForTest(received, vaultKeyFor(lab)), receivedFrom: 'VEIL-OTHER', receivedFromCommitment: 'ee'.repeat(32), transferId: 'TR-OTHER' };
  const put = await call('PUT', '/api/records', lab, [forged]);
  assert.equal(put.json.count, 1, JSON.stringify(put.json));
  const stored = bodyOf(stub.id);
  assert.equal(stored.receivedFrom, src.id);
  assert.equal(stored.receivedFromCommitment, src.recordFingerprint);
  assert.equal(stored.transferId, o.json.transferId);
  assert.equal(stored.receivedAt, stub.receivedAt);
  assert.equal(stored.recordFingerprint, received.recordFingerprint);
  assert.ok(stored.sealed);
  // The sender's list finds the received record by its id, as before.
  assert.equal((await call('GET', '/transfers/sent', sender)).json.transfers[0].received_record, stub.id);
});

test('a sealed offer is checked for shape and size; quantity and note beside it are refused; a sealed source needs one', async () => {
  const sender = key();
  const { src, sealedOffer } = await sealedSource(sender, 'tx-sealed-3');
  const good = sealedOffer();
  const cases = [
    [{ ...good, v: 2 }, /sealedOffer\.v must be 1/],
    [{ ...good, alg: 'A128GCM' }, /sealedOffer\.alg must be "A256GCM"/],
    [{ ...good, kid: 'ab'.repeat(8) }, /sealedOffer\.kid is not part of a sealed box/],
    [{ ...good, iv: 'short' }, /sealedOffer\.iv must be 16 base64url/],
    [{ ...good, ct: 'not base64url!' }, /sealedOffer\.ct must be base64url/],
    [{ ...good, ct: 'A'.repeat(400_000) }, /sealedOffer\.ct may be at most|sealedOffer may be at most 393216 bytes/],
    ['a string', /sealedOffer must be an object/],
  ];
  for (const [sealedOfferValue, reason] of cases) {
    const r = await call('POST', '/transfers', sender, { sourceRecord: src.id, toHandle: LAB_TAG, sealedOffer: sealedOfferValue });
    assert.equal(r.status, 400, JSON.stringify(sealedOfferValue).slice(0, 60));
    assert.match(r.json.error, reason);
  }
  for (const extra of [{ quantity: '10' }, { note: 'n' }]) {
    const r = await call('POST', '/transfers', sender, { sourceRecord: src.id, toHandle: LAB_TAG, sealedOffer: good, ...extra });
    assert.equal(r.status, 400);
    assert.match(r.json.error, /quantity and note go inside sealedOffer/);
  }
  const none = await call('POST', '/transfers', sender, { sourceRecord: src.id, toHandle: LAB_TAG });
  assert.equal(none.status, 400);
  assert.match(none.json.error, /a sealed record is offered with sealedOffer/);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM transfers WHERE source_record = ?').get(src.id).n, 0, 'nothing refused was stored');
  // The boundary (round 2, A4: 384 KiB, the same as a record row). The box's JSON is
  // { v, alg, iv, ct }; a ct of length 4k+1 is not whole bytes, so the largest box that can
  // be made is 393,215 characters (accepted) and the next is 393,217 (refused).
  assert.equal(OFFER_MAX_BYTES, 384 * 1024);
  const overhead = JSON.stringify({ v: 1, alg: 'A256GCM', iv: good.iv, ct: '' }).length;
  const boxOfLength = (n) => ({ v: 1, alg: 'A256GCM', iv: good.iv, ct: 'A'.repeat(n - overhead) });
  assert.equal((OFFER_MAX_BYTES - overhead) % 4, 1, 'the exact limit is not a whole number of bytes');
  const over = await call('POST', '/transfers', sender, { sourceRecord: src.id, toHandle: LAB_TAG, sealedOffer: boxOfLength(OFFER_MAX_BYTES + 1) });
  assert.equal(over.status, 400);
  assert.match(over.json.error, /sealedOffer may be at most 393216 bytes/);
  const atLimit = await call('POST', '/transfers', sender, { sourceRecord: src.id, toHandle: LAB_TAG, sealedOffer: boxOfLength(OFFER_MAX_BYTES - 1) });
  assert.equal(atLimit.status, 200, JSON.stringify(atLimit.json));
  assert.equal(db.prepare('SELECT LENGTH(offer_sealed) AS n FROM transfers WHERE id = ?').get(atLimit.json.transferId).n, OFFER_MAX_BYTES - 1);
});

test('a code made before sealing, from a source still in plain text: the claim returns offerPlain, and the stub has no nonce', async () => {
  const sender = key(), lab = key();
  const src = await legacySource(sender, 'tx-legacy-1');
  const o = await call('POST', '/transfers', sender, { sourceRecord: src.id, toHandle: LAB_TAG, quantity: '3 clones', note: 'old note' });
  assert.equal(o.status, 200, JSON.stringify(o.json));
  const c = await call('POST', `/transfers/${o.json.transferId}/claim`, lab, { claimCode: o.json.claimCode });
  assert.equal(c.status, 200, JSON.stringify(c.json));
  assert.equal(c.json.offerSealed, undefined);
  assert.deepEqual(c.json.offerPlain, {
    strainName: src.strainName, bredBy: 'Breeder B', dateCreated: '2026-01-01', taxon: 'Malus domestica', refId: '', quantity: '3 clones', note: 'old note',
  });
  const stub = bodyOf(c.json.recordId);
  assert.deepEqual(Object.keys(stub).sort(), ['id', 'receivedAt', 'receivedFrom', 'receivedFromCommitment', 'transferId']);
  assert.ok(!JSON.stringify([stub, c.json]).includes('TOP SECRET'));
  assert.ok(!JSON.stringify([stub, c.json]).includes('Secret Mother'));
  // The sender's plaintext body is not rewritten either: only the attestation is added.
  const { attestation, ...rest } = bodyOf(src.id);
  assert.equal(attestation.type, 'receipt-confirmed');
  assert.deepEqual(rest, src);
});

test('an animal\'s legacy code: offerPlain names the animal, never its herd or pedigree', async () => {
  const sender = key(), lab = key();
  const src = await legacySource(sender, 'tx-legacy-animal', {
    profile: 'veilcore/profile/animal-individual/v1', refId: '0000000017', taxon: 'Cattle (Bos taurus)',
    animal: { breed: 'Japanese Black', idScheme: 'Japan cattle ID (10 digits)', sex: 'female', herd: 'Herd 7' },
    parents: [{ name: 'Sire S', role: 'sire' }],
  });
  const o = await call('POST', '/transfers', sender, { sourceRecord: src.id, toHandle: LAB_TAG });
  const c = await call('POST', `/transfers/${o.json.transferId}/claim`, lab, { claimCode: o.json.claimCode });
  assert.equal(c.status, 200, JSON.stringify(c.json));
  assert.equal(c.json.offerPlain.refId, '0000000017');
  assert.deepEqual(c.json.offerPlain.animal, { breed: 'Japanese Black', idScheme: 'Japan cattle ID (10 digits)', sex: 'female' });
  assert.equal(c.json.offerPlain.profile, 'veilcore/profile/animal-individual/v1');
  assert.ok(!JSON.stringify(c.json).includes('Herd 7'));
  assert.ok(!JSON.stringify(c.json).includes('Sire S'));
  assert.equal(bodyOf(c.json.recordId).profile, 'veilcore/profile/animal-individual/v1');
});

test('a code made before sealing whose source has since been sealed: 409, ask the sender for a new code', async () => {
  const sender = key(), lab = key();
  const src = await legacySource(sender, 'tx-legacy-2');
  const o = await call('POST', '/transfers', sender, { sourceRecord: src.id, toHandle: LAB_TAG });
  assert.equal(o.status, 200);
  // The sender's browser converts the row: same contents, same fingerprint, now sealed.
  assert.equal((await call('PUT', '/api/records', sender, [sealForTest(src, vaultKeyFor(sender))])).json.count, 1);
  const before = db.prepare('SELECT COUNT(*) AS n FROM records').get().n;
  const c = await call('POST', `/transfers/${o.json.transferId}/claim`, lab, { claimCode: o.json.claimCode });
  assert.equal(c.status, 409);
  assert.match(c.json.error, /ask the sender for a new code/);
  assert.equal(transferRow(o.json.transferId).claimed_by, null, 'still open');
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM records').get().n, before, 'no stub was written');
  assert.equal(bodyOf(src.id).attestation, undefined);
  // A new code, with a sealed offer, works.
  const offerKey = randomBytes(32);
  const o2 = await call('POST', '/transfers', sender, {
    sourceRecord: src.id, toHandle: LAB_TAG, sealedOffer: sealOfferForTest(offerFromRecord(src), offerKey, src.id, src.recordFingerprint),
  });
  assert.equal((await call('POST', `/transfers/${o2.json.transferId}/claim`, lab, { claimCode: o2.json.claimCode })).status, 200);
});

test('a claim code is stored as its SHA-256, never as sent; a code stored as sent by older code still claims', async () => {
  const sender = key(), lab = key();
  const { src, sealedOffer } = await sealedSource(sender, 'tx-code-1');
  const o = await call('POST', '/transfers', sender, { sourceRecord: src.id, toHandle: LAB_TAG, sealedOffer: sealedOffer() });
  assert.equal(o.status, 200, JSON.stringify(o.json));
  const code = o.json.claimCode;
  assert.match(code, /^[0-9a-f]{32}$/);
  const stored = transferRow(o.json.transferId).claim_code;
  assert.equal(stored, `sha256:${createHash('sha256').update(code).digest('hex')}`);
  assert.ok(!stored.includes(code));
  // A wrong code, and the stored digest itself, are refused; the code claims.
  for (const wrong of ['0'.repeat(32), stored, stored.slice(7)]) {
    const r = await call('POST', `/transfers/${o.json.transferId}/claim`, lab, { claimCode: wrong });
    assert.match(r.json.error, /claim code does not match/);
  }
  assert.equal((await call('POST', `/transfers/${o.json.transferId}/claim`, lab, { claimCode: code })).status, 200);

  // A row written before digests, with the code as sent.
  const { src: src2, sealedOffer: offer2 } = await sealedSource(sender, 'tx-code-2');
  const o2 = await call('POST', '/transfers', sender, { sourceRecord: src2.id, toHandle: LAB_TAG, sealedOffer: offer2() });
  db.prepare('UPDATE transfers SET claim_code = ? WHERE id = ?').run('c0dec0dec0dec0dec0dec0dec0dec0de', o2.json.transferId);
  assert.match((await call('POST', `/transfers/${o2.json.transferId}/claim`, lab, { claimCode: 'c0de' })).json.error, /does not match/);
  assert.equal((await call('POST', `/transfers/${o2.json.transferId}/claim`, lab, { claimCode: 'c0dec0dec0dec0dec0dec0dec0dec0de' })).status, 200);
});
