// Sample details sealed with the delivery's offer key (the site's CONTRACT.md #27, sealed
// records round 3). On a delivery made with a sealed offer, the sender's `sample` and the
// lab's `arrival` are each a box this registry stores and can't open: it checks their shape
// and size, refuses plain fields, takes an `_sc2_` receipt without recomputing it, and says
// publicly only that the lab signed over the details, plus what the holder's app worked out
// when the holder chose to publish it. Deliveries made before keep plain fields and `_sc1_`
// (sample-custody.test.mjs). No network.
//
// SPDX-License-Identifier: Apache-2.0

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { createHash, randomBytes } from 'node:crypto';
import { readFileSync, mkdtempSync, rmSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import Database from 'better-sqlite3';
import { canonicalise, sha256Hex, newNonce, generateKeypair, signAttestation } from 'veilcore-records';
import {
  custodyDigest, custodyDigestV2, custodyFields, receiptCustodyOf, receiptCustodyDigest, isCustodyBox, CUSTODY_SALT,
} from '../lineage/transfer.mjs';
import {
  untilReady, sealForTest, vaultKeyFor, sealOfferForTest, offerFromRecord, handleTagFor,
  sealCustodyForTest, openCustodyForTest, offerKidOf, custodyAad, grantForTest,
} from './helpers.mjs';

process.env.DB_PATH = ':memory:';
process.env.VEILCORE_OTS = 'off';
const require = createRequire(import.meta.url);
const { app, db } = require('../server.js');
const { storedHolderKey } = require('../holder-key.js');
const { CUSTODY_CT_MAX } = require('../sealed.js');

const V = JSON.parse(readFileSync(new URL('./fixtures/sealed-custody-vectors.json', import.meta.url), 'utf8'));
const key = () => randomBytes(32).toString('hex');
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
const makeRecord = async (id) => {
  const r = { id, strainName: `Name ${id}`, bredBy: 'B', dateCreated: '2026-01-01', loggedAt: 1760000000000,
    nonce: newNonce(), notes: '', parents: [], photoFingerprints: [], breedingMethod: '', refId: '' };
  r.recordFingerprint = await sha256Hex(canonicalise(committedOf(r)));
  return r;
};

/** What the sender and the lab typed (test data): none of it may be readable in the registry. */
const SAMPLE = { sampleId: 'PRIV-S-77', sealNumber: 'PRIV-SEAL-4471', takenFrom: 'PRIV-mother-M3', takenOn: '2026-10-14', witness: 'PRIV-witness-Joe' };
const ARRIVAL = { sampleId: 'PRIV-S-77', sealNumber: 'PRIV-SEAL-4417', sealIntact: 'yes', arrivedOn: '2026-10-15', condition: 'PRIV-cold-bag', labRef: 'PRIV-ACC-9' };

/** A sealed source, a sealed offer for it, and the delivery's offer key. */
const offered = async () => {
  const sender = key(), lab = key();
  const src = await makeRecord(`cs-${randomBytes(6).toString('hex')}`);
  assert.equal((await call('PUT', '/api/records', sender, [sealForTest(src, vaultKeyFor(sender))])).json.count, 1);
  const offerKey = randomBytes(32);
  const o = await call('POST', '/transfers', sender, {
    sourceRecord: src.id, toHandle: handleTagFor(sender, 'lab@x'),
    sealedOffer: sealOfferForTest(offerFromRecord(src), offerKey, src.id, src.recordFingerprint),
  });
  assert.equal(o.status, 200, JSON.stringify(o.json));
  return { sender, lab, src, offerKey, transferId: o.json.transferId, claimCode: o.json.claimCode };
};
const salt = () => randomBytes(32).toString('base64url');
const sampleBox = (d, s = salt(), fields = SAMPLE) => sealCustodyForTest({ ...fields, salt: s }, d.offerKey, d.transferId, 'sample');
const arrivalBox = (d, fields = ARRIVAL) => sealCustodyForTest(fields, d.offerKey, d.transferId, 'arrival');
const custodyPath = (d) => `/transfers/${d.transferId}/custody`;

/** Claimed by the lab, whose browser seals the received record from the offer. */
const claim = async (d) => {
  const c = await call('POST', `/transfers/${d.transferId}/claim`, d.lab, { claimCode: d.claimCode });
  assert.equal(c.status, 200, JSON.stringify(c.json));
  const stub = (await call('GET', '/api/records', d.lab)).json.find((r) => r.id === c.json.recordId);
  const received = { ...stub, bredBy: 'B', dateCreated: '2026-01-01', notes: '', parents: [], photoFingerprints: [],
    breedingMethod: '', refId: '', nonce: newNonce(), loggedAt: stub.receivedAt };
  received.recordFingerprint = await sha256Hex(canonicalise(committedOf(received)));
  assert.equal((await call('PUT', '/api/records', d.lab, [sealForTest(received, vaultKeyFor(d.lab))])).json.count, 1);
  return { ...d, claim: c.json, received };
};

/** The lab's receipt, signed as the site signs it, with `suffix` ('' or `_sc1_…` / `_sc2_…`) in its id. */
const receipt = async (d, suffix = '') => {
  const kp = await generateKeypair();
  const attestationId = `att_${randomBytes(8).toString('hex')}${suffix}`;
  const signed = await signAttestation({
    attestationId, type: 'chain-of-custody', subjectCommitment: d.src.recordFingerprint,
    documentHash: d.received.recordFingerprint, hashAlgorithm: 'sha256',
    issuedAt: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'), attester: { publicKey: kp.publicKey, displayName: 'Lab' },
  }, kp.privateKey);
  assert.equal((await call('POST', '/attestations', undefined, signed)).status, 200);
  return attestationId;
};
const attach = (d, id) => call('POST', `/transfers/${d.transferId}/receipt`, d.lab, { attestationId: id });
const row = (id) => db.prepare('SELECT * FROM transfers WHERE id = ?').get(id);

test('shared vectors: the same v2 digest as the site, and each side opens the box the other sealed', () => {
  // The site's custody-vectors.ts holds these same values (the cross-repo contract test compares them).
  const key = Buffer.from(V.offerKey, 'base64url');
  assert.equal(offerKidOf(key), V.kid);
  assert.equal(custodyAad(V.transferId, 'sample').toString('utf8'), V.aad.sample);
  assert.equal(custodyAad(V.transferId, 'arrival').toString('utf8'), V.aad.arrival);
  assert.equal(custodyDigestV2(V.transferId, V.salt, V.sample, V.arrival), V.digestV2);
  assert.equal(createHash('sha256').update(canonicalise({ format: 'veilcore/sample-custody/v2', transferId: V.transferId,
    salt: V.salt, sample: V.sample, arrival: V.arrival })).digest('hex'), V.digestV2);
  assert.ok(CUSTODY_SALT.test(V.salt));
  assert.deepEqual(receiptCustodyOf(`att_0123456789abcdef${V.receiptSuffix}`), { format: 2, digest: V.digestV2 });
  assert.equal(receiptCustodyDigest(`att_0123456789abcdef${V.receiptSuffix}`), null, 'the _sc1_ reader never takes an _sc2_ digest');
  // The site sealed the sample (padded); this side opens it, with the salt beside the fields.
  const sample = openCustodyForTest(V.sampleBoxSealedBySite, key, V.transferId, 'sample');
  const { salt: s, ...fields } = sample;
  assert.equal(s, V.salt);
  assert.deepEqual(custodyFields('sample', fields).fields, V.sample);
  assert.deepEqual(openCustodyForTest(V.arrivalBoxSealedByRegistryTest, key, V.transferId, 'arrival'), V.arrival);
  // Bound to the delivery and the side: another id or the other side doesn't open.
  assert.throws(() => openCustodyForTest(V.sampleBoxSealedBySite, key, V.transferId, 'arrival'));
  assert.throws(() => openCustodyForTest(V.sampleBoxSealedBySite, key, 'TR-00000000', 'sample'));
  assert.ok(isCustodyBox(V.sampleBoxSealedBySite));
  assert.ok(!isCustodyBox(V.sample));
});

test('a delivery with a sealed offer: plain sample details are refused at the offer and on the custody route', async () => {
  const sender = key();
  const src = await makeRecord(`cs-${randomBytes(6).toString('hex')}`);
  await call('PUT', '/api/records', sender, [sealForTest(src, vaultKeyFor(sender))]);
  const sealedOffer = sealOfferForTest(offerFromRecord(src), randomBytes(32), src.id, src.recordFingerprint);
  const withPlain = await call('POST', '/transfers', sender, { sourceRecord: src.id, toHandle: handleTagFor(sender, 'lab@x'), sealedOffer, sample: SAMPLE });
  assert.equal(withPlain.status, 400);
  assert.match(withPlain.json.error, /sealed too: send them as a box to POST \/transfers\/:id\/custody/);
  const d = await offered();
  const plainSample = await call('POST', custodyPath(d), d.sender, { sample: SAMPLE });
  assert.equal(plainSample.status, 400);
  assert.match(plainSample.json.error, /sealed: send sample as a box sealed with the delivery's offer key/);
  // Nothing of it was stored.
  assert.equal(row(d.transferId).sample_custody, null);
  assert.equal(row(d.transferId).sample_custody_sealed, null);
});

test('the boxes are stored and served unread; the registry checks their shape and size only', async () => {
  const d = await offered();
  const s = salt();
  const box = sampleBox(d, s);
  const set = await call('POST', custodyPath(d), d.sender, { sample: box });
  assert.equal(set.status, 200, JSON.stringify(set.json));
  assert.deepEqual(set.json, { transferId: d.transferId, sample: box, arrival: {} });
  const t = row(d.transferId);
  assert.equal(t.sample_custody, null);
  assert.equal(t.sample_custody_sealed, JSON.stringify(box));
  // Shape: every part of the box, and nothing else in it.
  for (const [bad, why] of [
    [{ ...box, kid: 'XYZ' }, /kid must be 16 lowercase hexadecimal/],
    [{ ...box, v: 2 }, /v must be 1/],
    [{ ...box, alg: 'A128GCM' }, /alg must be "A256GCM"/],
    [{ ...box, iv: 'short' }, /iv must be 16 base64url/],
    [{ ...box, ct: 'not base64url!' }, /ct must be base64url/],
    [{ ...box, salt: s }, /sample\.salt is not part of a sealed box/],
    [{ v: 1, alg: 'A256GCM', iv: box.iv, ct: box.ct }, /kid must be/],
    [{ ...box, ct: 'A'.repeat(CUSTODY_CT_MAX + 4) }, new RegExp(`at most ${CUSTODY_CT_MAX} characters`)],
  ]) {
    const r = await call('POST', custodyPath(d), d.sender, { sample: bad });
    assert.equal(r.status, 400, JSON.stringify(bad).slice(0, 80));
    assert.match(r.json.error, why);
  }
  assert.equal(CUSTODY_CT_MAX, 8000);
  // The largest box the size limit allows is taken.
  const big = { ...box, ct: 'A'.repeat(CUSTODY_CT_MAX) };
  assert.equal((await call('POST', custodyPath(d), d.sender, { sample: big })).status, 200);
  assert.equal((await call('POST', custodyPath(d), d.sender, { sample: box })).status, 200);

  // The lab gets the box with the claim, byte for byte, and opens it with the code's key.
  const c = await claim(d);
  assert.equal(JSON.stringify(c.claim.sample), JSON.stringify(box));
  assert.deepEqual(openCustodyForTest(c.claim.sample, d.offerKey, d.transferId, 'sample'), { ...SAMPLE, salt: s });
  // The sender can no longer change it; only the sender could before.
  assert.equal((await call('POST', custodyPath(d), d.sender, { sample: box })).status, 409);

  // The lab's side: sealed, plain refused, the same key as the sender's.
  assert.equal((await call('POST', custodyPath(d), d.lab, { arrival: ARRIVAL })).status, 400);
  const otherKey = sealCustodyForTest(ARRIVAL, randomBytes(32), d.transferId, 'arrival');
  const wrong = await call('POST', custodyPath(d), d.lab, { arrival: otherKey });
  assert.equal(wrong.status, 400);
  assert.match(wrong.json.error, /different key from the sample details/);
  const arr = arrivalBox(d);
  assert.equal((await call('POST', custodyPath(d), d.sender, { arrival: arr })).status, 403);
  const setA = await call('POST', custodyPath(d), d.lab, { arrival: arr });
  assert.equal(setA.status, 200, JSON.stringify(setA.json));
  assert.deepEqual(setA.json, { transferId: d.transferId, sample: box, arrival: arr });
  for (const who of [d.sender, d.lab]) {
    const g = await call('GET', custodyPath(d), who);
    assert.deepEqual(g.json, { transferId: d.transferId, sample: box, arrival: arr, receiptAttestationId: null });
  }
  assert.equal((await call('GET', custodyPath(d), key())).status, 403);
  const sent = (await call('GET', '/transfers/sent', d.sender)).json.transfers.find((x) => x.id === d.transferId);
  assert.deepEqual(sent.sample_custody, box);
  assert.deepEqual(sent.arrival_custody, arr);
  assert.deepEqual(openCustodyForTest(sent.arrival_custody, d.offerKey, d.transferId, 'arrival'), ARRIVAL);

  // Nothing typed is readable anywhere in what the registry stores about the delivery.
  const stored = JSON.stringify(db.prepare('SELECT * FROM transfers WHERE id = ?').get(d.transferId));
  for (const v of [...Object.values(SAMPLE), ...Object.values(ARRIVAL), s]) {
    if (v.startsWith('PRIV') || v === s) assert.equal(stored.includes(v), false, v);
  }
});

test('receipts: _sc2_ is taken without recomputing; _sc1_ on sealed details, or _sc2_ without them, is refused', async () => {
  const d = await claim(await offered());
  // No sealed sample yet: an _sc2_ receipt has nothing to cover.
  const early = await attach(d, await receipt(d, `_sc2_${'ab'.repeat(32)}`));
  assert.equal(early.status, 400);
  assert.match(early.json.error, /no sealed sample details for an _sc2_ receipt/);
  // The sender's box goes before the claim; here, straight into the table, as if it had.
  const s = salt();
  db.prepare('UPDATE transfers SET sample_custody_sealed = ? WHERE id = ?').run(JSON.stringify(sampleBox(d, s)), d.transferId);
  assert.equal((await call('POST', custodyPath(d), d.lab, { arrival: arrivalBox(d) })).status, 200);
  // The registry can't open the boxes, so it can't tell a right digest from a wrong one: both link.
  const digest = custodyDigestV2(d.transferId, s, SAMPLE, ARRIVAL);
  const good = await receipt(d, `_sc2_${digest}`);
  assert.equal((await attach(d, good)).status, 200);
  assert.equal((await attach(d, await receipt(d, `_sc2_${'cd'.repeat(32)}`))).status, 200, 'taken unread');
  // An _sc1_ receipt over sealed details: refused (its digest would be over nothing it can read).
  const v1 = await attach(d, await receipt(d, `_sc1_${'ef'.repeat(32)}`));
  assert.equal(v1.status, 400);
  assert.match(v1.json.error, /sealed, so its receipt carries them as _sc2_/);
  // A receipt with no suffix still links, covering none of them.
  assert.equal((await attach(d, await receipt(d))).status, 200);
  assert.equal((await attach(d, good)).status, 200);
  assert.equal(row(d.transferId).receipt_attestation_id, good);
});

test('/verify, /embed, /records/:id: "sealed", the receipt names sample details the holder\'s app can check; never covered or changed from the registry', async () => {
  const d0 = await offered();
  const s = salt();
  assert.equal((await call('POST', custodyPath(d0), d0.sender, { sample: sampleBox(d0, s) })).status, 200);
  const d = await claim(d0);
  assert.equal((await call('POST', custodyPath(d), d.lab, { arrival: arrivalBox(d) })).status, 200);
  const id = await receipt(d, `_sc2_${custodyDigestV2(d.transferId, s, SAMPLE, ARRIVAL)}`);
  assert.equal((await attach(d, id)).status, 200);

  // Without the lab-status grant: nothing.
  assert.equal('custody' in (await call('GET', `/verify/${d.src.id}`)).json, false);
  const grant = (values = {}) => call('PUT', `/api/records/${d.src.id}/disclosure`, d.sender, {
    ...grantForTest(d.src, ['existence', 'attestation-status']), values,
  });
  assert.equal((await grant()).status, 200);
  // A custody line names its receipt's id only when the holder shares that receipt (8 Nov 2026,
  // hide-lab-reports.test.mjs); this grant shares none.
  const sealedOnly = [{ custody: 'sealed', receiptNamesSampleDetails: true, sampleDetailsCheckedBy: 'holder' }];
  let v = (await call('GET', `/verify/${d.src.id}`)).json;
  assert.deepEqual(v.custody, sealedOnly);
  assert.deepEqual((await call('GET', `/records/${d.src.id}`)).json.custody, sealedOnly);
  let embed = await fetch(`${base}/embed/${d.src.id}`).then((r) => r.text());
  assert.match(embed, /The lab’s receipt names sample details\. They are stored locked, so this page can’t show or check them; the holder’s app can\./);
  assert.doesNotMatch(embed, /signed (its receipt )?over/);

  // The holder publishes what their app worked out: field names and a state, never values.
  for (const [bad, why] of [
    [[{ receiptAttestationId: id, covered: 'yes', differingFields: [] }], /covered must be one of/],
    [[{ receiptAttestationId: id, covered: 'covered', differingFields: ['PRIV-SEAL-4471'] }], /field names .* never their values/],
    [[{ receiptAttestationId: id, covered: 'covered', differingFields: [], sealNumber: 'PRIV-SEAL-4471' }], /not published/],
    [[{ receiptAttestationId: id, covered: 'covered', differingFields: ['sealNumber', 'sealNumber'] }], /each once/],
    ['covered', /must be a list/],
  ]) {
    const r = await grant({ custodySummary: bad });
    assert.equal(r.status, 400, JSON.stringify(bad));
    assert.match(r.json.error, why);
  }
  const summary = [{ receiptAttestationId: id, covered: 'covered', differingFields: ['sealNumber'] }];
  // Only with the attestation-status grant.
  const noKey = await call('PUT', `/api/records/${d.src.id}/disclosure`, d.sender, {
    show: ['existence'], forFingerprint: d.src.recordFingerprint, values: { custodySummary: summary },
  });
  assert.equal(noKey.status, 400);
  assert.equal((await grant({ custodySummary: summary })).status, 200);
  const withSummary = [{ ...sealedOnly[0], custodySummary: { covered: 'covered', differingFields: ['sealNumber'] }, custodySummaryBy: 'holder' }];
  v = (await call('GET', `/verify/${d.src.id}`)).json;
  assert.deepEqual(v.custody, withSummary);
  assert.deepEqual((await call('GET', `/records/${d.src.id}`)).json.custody, withSummary);
  embed = await fetch(`${base}/embed/${d.src.id}`).then((r) => r.text());
  assert.match(embed, /The holder’s app found differences between what was sent and what arrived/);
  // A summary for a receipt that isn't this delivery's is never answered.
  assert.equal((await grant({ custodySummary: [...summary, { receiptAttestationId: 'att_other', covered: 'changed', differingFields: [] }] })).status, 200);
  assert.deepEqual((await call('GET', `/verify/${d.src.id}`)).json.custody, withSummary);
  // Stale (sent for another fingerprint): the summary goes; the registry's own fact stays.
  assert.equal((await call('PUT', `/api/records/${d.src.id}/disclosure`, d.sender, {
    show: ['existence', 'attestation-status'], forFingerprint: 'ab'.repeat(32), values: { custodySummary: summary },
  })).status, 200);
  assert.deepEqual((await call('GET', `/verify/${d.src.id}`)).json.custody, sealedOnly);

  // None of what was typed is in any public answer.
  const all = JSON.stringify([v, (await call('GET', `/records/${d.src.id}`)).json]) + embed;
  for (const x of [...Object.values(SAMPLE), ...Object.values(ARRIVAL)]) if (x.startsWith('PRIV')) assert.equal(all.includes(x), false, x);
});

test('a delivery made before sealing keeps plain fields; a box is refused there', async () => {
  const sender = key(), lab = key();
  const src = await makeRecord(`cs-old-${randomBytes(6).toString('hex')}`);
  db.prepare('INSERT INTO records (id, holder_key, body, updated_at, first_seen) VALUES (?,?,?,?,?)')
    .run(src.id, storedHolderKey(sender), JSON.stringify(src), 1, 1);
  const o = await call('POST', '/transfers', sender, { sourceRecord: src.id, toHandle: handleTagFor(sender, 'lab@x'), sample: { sampleId: 'OLD-1' } });
  assert.equal(o.status, 200, JSON.stringify(o.json));
  const d = { sender, lab, transferId: o.json.transferId, offerKey: randomBytes(32) };
  const box = await call('POST', custodyPath(d), sender, { sample: sampleBox(d) });
  assert.equal(box.status, 400);
  assert.match(box.json.error, /made before sample details were sealed/);
  assert.equal((await call('POST', '/transfers', sender, { sourceRecord: src.id, toHandle: handleTagFor(sender, 'lab@y'), sample: sampleBox(d) })).status, 400);
  assert.deepEqual((await call('GET', custodyPath(d), sender)).json.sample, { sampleId: 'OLD-1' });
  // An _sc2_ receipt on it is refused: nothing sealed to cover.
  const c = await call('POST', `/transfers/${d.transferId}/claim`, lab, { claimCode: o.json.claimCode });
  assert.equal(c.status, 200);
  assert.deepEqual(c.json.sample, { sampleId: 'OLD-1' });
});

test('details written before sealing: a receipt over them reads "removed" once the purge has removed them', async () => {
  const sender = key(), lab = key();
  const src = await makeRecord(`cs-rm-${randomBytes(6).toString('hex')}`);
  db.prepare('INSERT INTO records (id, holder_key, body, updated_at, first_seen) VALUES (?,?,?,?,?)')
    .run(src.id, storedHolderKey(sender), JSON.stringify(src), 1, 1);
  const sample = { sampleId: 'OLD-2', sealNumber: '77' };
  const o = await call('POST', '/transfers', sender, { sourceRecord: src.id, toHandle: handleTagFor(sender, 'lab@x'), sample });
  assert.equal(o.status, 200, JSON.stringify(o.json));
  const d = await claim({ sender, lab, src, transferId: o.json.transferId, claimCode: o.json.claimCode });
  const arrival = { sampleId: 'OLD-2', sealNumber: '77', sealIntact: 'yes' };
  assert.equal((await call('POST', custodyPath(d), lab, { arrival })).status, 200);
  const id = await receipt(d, `_sc1_${custodyDigest(d.transferId, sample, arrival)}`);
  assert.equal((await attach(d, id)).status, 200);
  assert.equal((await call('PUT', `/api/records/${src.id}/disclosure`, sender, { show: ['attestation-status'] })).status, 200);
  assert.deepEqual((await call('GET', `/verify/${src.id}`)).json.custody, [{ covered: 'covered', differences: [] }], 'no id: the receipt is not shared');
  // What the purge's two-flag run does to such a delivery (below).
  db.prepare('UPDATE transfers SET sample_custody = NULL, arrival_custody = NULL, custody_removed = 1 WHERE id = ?').run(d.transferId);
  assert.deepEqual((await call('GET', `/verify/${src.id}`)).json.custody,
    [{ custody: 'removed', receiptNamesSampleDetails: true }], 'never "changed"');
});

test('the purge: the guarded --apply reports plain sample details; only the two-flag run removes them; sealed ones are untouched', () => {
  const purge = fileURLToPath(new URL('../scripts/purge-plaintext.mjs', import.meta.url));
  const dir = mkdtempSync(join(tmpdir(), 'veilcore-purge-custody-'));
  try {
    const file = join(dir, 'p.db');
    const f = new Database(file);
    for (const { sql } of db.prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name IN ('records', 'transfers')").all()) f.exec(sql);
    const converted = storedHolderKey(key()), fresh = storedHolderKey(key());
    f.prepare('INSERT INTO records (id, holder_key, body, updated_at, first_seen) VALUES (?,?,?,?,?)')
      .run('C-SEALED', converted, JSON.stringify({ id: 'C-SEALED', strainName: 'n', sealed: { v: 1, alg: 'A256GCM', kid: '0'.repeat(16), iv: 'A'.repeat(16), ct: 'A'.repeat(24) } }), 1, 1);
    const ins = f.prepare(`INSERT INTO transfers (id, source_record, from_holder, to_handle, created_at, sample_custody, arrival_custody, sample_custody_sealed)
                           VALUES (?,?,?,?,?,?,?,?)`);
    const tag = 'ab'.repeat(32);
    const box = JSON.stringify(V.sampleBoxSealedBySite);
    ins.run('TR-PLAIN001', 'C-SEALED', converted, tag, 1, JSON.stringify({ sealNumber: 'PLAIN-SEAL-1' }), JSON.stringify({ sealNumber: 'PLAIN-SEAL-2' }), null);
    ins.run('TR-PLAIN002', 'F-PLAIN', fresh, tag, 1, null, JSON.stringify({ condition: 'PLAIN-COND-3' }), null);
    ins.run('TR-SEALED01', 'C-SEALED', converted, tag, 1, null, null, box);
    f.close();
    const run = (...args) => execFileSync(process.execPath, [purge, '--db', file, ...args], { encoding: 'utf8' });
    const plainCustody = () => {
      const r = new Database(file, { readonly: true });
      try {
        return r.prepare('SELECT id, sample_custody, arrival_custody, sample_custody_sealed FROM transfers ORDER BY id').all();
      } finally {
        r.close();
      }
    };
    const dry = run();
    assert.match(dry, /sample details written before sealing: 2 deliveries with them in plain text \(reported, not removed; only --include-unconverted --i-understand-this-deletes-text removes them\)/);
    for (const v of ['PLAIN-SEAL-1', 'PLAIN-COND-3']) assert.ok(!dry.includes(v), 'counts only, never contents');
    const guarded = run('--apply');
    assert.match(guarded, /^applied:/);
    assert.match(guarded, /sample details written before sealing: 2 deliveries with them in plain text \(reported, not removed/);
    assert.equal(plainCustody().filter((t) => t.sample_custody || t.arrival_custody).length, 2, 'the guarded run removes none');
    const both = run('--apply', '--include-unconverted', '--i-understand-this-deletes-text');
    assert.match(both, /sample details written before sealing: 2 deliveries with them in plain text, 2 removed/);
    const after = plainCustody();
    assert.deepEqual(after.map((t) => [t.id, t.sample_custody, t.arrival_custody]),
      [['TR-PLAIN001', null, null], ['TR-PLAIN002', null, null], ['TR-SEALED01', null, null]]);
    assert.equal(after.find((t) => t.id === 'TR-SEALED01').sample_custody_sealed, box, 'a sealed box is never touched');
    const r = new Database(file, { readonly: true });
    assert.deepEqual(r.prepare('SELECT id FROM transfers WHERE custody_removed = 1 ORDER BY id').all().map((x) => x.id), ['TR-PLAIN001', 'TR-PLAIN002']);
    r.close();
    const bytes = readFileSync(file);
    for (const v of ['PLAIN-SEAL-1', 'PLAIN-SEAL-2', 'PLAIN-COND-3']) assert.ok(!bytes.includes(Buffer.from(v)), `${v} left in the file`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('/health lists sealed-custody-v1', async () => {
  const h = await call('GET', '/health');
  assert.ok(h.json.features.includes('sealed-custody-v1'));
});
