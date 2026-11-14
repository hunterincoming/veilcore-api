// Animal records (veilcore/profile/animal-individual/v1; the site's docs/animal-profile.md,
// SPEC 11.8; v1 is final). The registry turns the site's record shape into the profile's fields the
// way the site does, against the published vectors (test/fixtures/animal-individual-v1.json,
// copied byte for byte from the site's contract/vectors/); refuses an animal record in any
// other form; and answers a stranger only what the holder shared: the sire and dam under
// parent-names, the individual ID under the new individual-id grant. Plant records are
// unchanged. Every animal here is test data.
// SPDX-License-Identifier: Apache-2.0

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { createHash, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { canonicalise, sha256Hex, newNonce } from 'veilcore-records';
import { animalFieldsOf, validateAnimalFields, ANIMAL_PROFILE } from '../lineage/animal-profile.mjs';
import { checkRecord, recomputeCommitment } from '../lineage/conformance.mjs';
import { keyBoundFingerprint } from '../lineage/key-binding.mjs';
import { untilReady, testBody, plain, sealForTest, vaultKeyFor, openForTest, grantForTest, offerFromRecord, sealOfferForTest, openOfferForTest } from './helpers.mjs';

process.env.DB_PATH = ':memory:';
process.env.VEILCORE_OTS = 'off';
process.env.VEILCORE_OPERATOR_TOKEN = 'op-secret-token-at-least-32-characters';
const require = createRequire(import.meta.url);
const { app } = require('../server.js');

const V = JSON.parse(readFileSync(new URL('./fixtures/animal-individual-v1.json', import.meta.url), 'utf8'));
const PLANT = JSON.parse(readFileSync(new URL('./fixtures/key-bound-v1.json', import.meta.url), 'utf8'));

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

/** A fresh animal record in the site's stored shape, sealed under the profile. */
const animal = async (over = {}) => {
  const r = {
    ...structuredClone(V.records[0].appRecord),
    id: `VEIL-${randomBytes(16).toString('hex').toUpperCase()}`,
    nonce: newNonce(),
    licenseIds: [],
    ...over,
  };
  r.recordFingerprint = await recomputeCommitment(r);
  return r;
};

test('the vectors: the site shape gives exactly the published fields, canonical bytes and fingerprint', async () => {
  assert.equal(V.profile, ANIMAL_PROFILE);
  for (const v of V.records) {
    assert.deepEqual(validateAnimalFields(v.fields), [], v.name);
    assert.deepEqual(animalFieldsOf(v.appRecord), v.fields, v.name);
    assert.equal(canonicalise(v.fields), v.canonical, v.name);
    const content = await sha256Hex(v.canonical);
    assert.equal(content, v.contentHash, v.name);
    assert.equal(v.fields.keyBinding ? keyBoundFingerprint(v.fields.keyBinding, content) : content, v.fingerprint, v.name);
    assert.equal(await recomputeCommitment(v.appRecord), v.fingerprint, v.name);
    assert.deepEqual(await checkRecord({ ...v.appRecord, recordFingerprint: v.fingerprint }), { ok: true, verified: true }, v.name);
  }
});

test('the vectors: every refusal is refused', () => {
  assert.ok(V.refusals.length >= 20);
  for (const v of V.refusals) assert.ok(validateAnimalFields(v.fields).length > 0, v.name);
});

test('plant records recompute byte for byte as before', async () => {
  for (const v of PLANT.records) {
    assert.equal(await recomputeCommitment(v.fields), v.fingerprint, v.name);
  }
});

test('checkRecord: a malformed animal record is refused with a reason, never stored as verified', async () => {
  const good = await animal();
  const bad = { ...good, animal: { ...good.animal, sex: 'cow' } };
  const c = await checkRecord(bad);
  assert.equal(c.ok, false);
  assert.match(c.reason, /not a valid animal record \(sex must be female, male or unknown/);
  // A changed individual ID after sealing: the fingerprint no longer matches.
  const moved = await checkRecord({ ...good, refId: '0000000099' });
  assert.equal(moved.ok, false);
  assert.match(moved.reason, /does not match/);
  // A plant-shaped parent on an animal record.
  const plantParent = await checkRecord({ ...good, parents: [{ name: 'Seed parent' }] });
  assert.match(plantParent.reason, /role must be sire or dam/);
});

test('PUT /api/records: an animal record is stored sealed; its details in the clear are refused by name', async () => {
  // Since sealed records the registry can't see an animal's details, so it can't check
  // their shape (checkRecord above still does, for the site's own tests); it refuses them
  // in the clear instead, and says who checks the fingerprint.
  const holder = key();
  const ok = await animal();
  const r = await call('PUT', '/api/records', holder, [ok]);
  assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.equal(r.json.count, 1);
  assert.equal(r.json.integrityCheckedBy, 'holder');
  const stored = (await call('GET', '/api/records', holder)).json[0];
  assert.equal(stored.profile, ANIMAL_PROFILE, 'the profile is public');
  assert.equal(stored.animal, undefined, 'the details are not');
  assert.deepEqual(openForTest(stored, vaultKeyFor(holder)).animal, ok.animal);

  const bare = sealForTest(await animal({ id: 'VEIL-BAD-ANIMAL' }), vaultKeyFor(holder));
  const e = await call('PUT', '/api/records', holder, plain([{ ...bare, animal: { breed: 'Japanese Black' } }]));
  assert.deepEqual(e.json.rejected.map((x) => x.id), ['VEIL-BAD-ANIMAL']);
  assert.match(e.json.rejected[0].reason, /^animal is not stored in the clear/);
});

test('/verify: an animal says so; sire and dam only under parent-names; the ID only under individual-id', async () => {
  const holder = key();
  const rec = await animal();
  await call('PUT', '/api/records', holder, [rec]);

  const bare = (await call('GET', `/verify/${rec.id}`)).json;
  assert.equal(bare.subjectKind, 'animal');
  // The name is sealed (round 5, CONTRACT.md #28): not answered unless the holder shows it.
  assert.equal(bare.cultivar, undefined);
  for (const f of ['sire', 'dam', 'individualId', 'idScheme', 'parents']) assert.equal(bare[f], undefined, f);
  assert.deepEqual(bare.disclosed, []);

  const g = await call('PUT', `/api/records/${rec.id}/disclosure`, holder, grantForTest(rec, ['parent-names', 'individual-id']));
  assert.equal(g.status, 200, JSON.stringify(g.json));
  assert.deepEqual(g.json.show, ['parent-names', 'individual-id']);

  const v = (await call('GET', `/verify/${rec.id}`)).json;
  assert.deepEqual(v.sire, { name: 'Practice Sire', individualId: '0000000025' });
  assert.deepEqual(v.dam, { name: 'Practice Dam', individualId: '0000000033' });
  assert.deepEqual(v.parents, ['Practice Sire', 'Practice Dam']);
  assert.equal(v.individualId, '0000000017');
  assert.equal(v.idScheme, 'Japan cattle ID (10 digits)');
  assert.deepEqual(v.disclosed, ['parents', 'individualId']);
  // Herd, breed, notes and the date of birth are never in the public answer.
  const text = JSON.stringify(v);
  for (const secret of ['Test herd 7', 'Not a real animal', 'Japanese Black', '2024-03-15']) assert.ok(!text.includes(secret), secret);

  // ?show= narrows: only the ID.
  const narrow = (await call('GET', `/verify/${rec.id}?show=individualId`)).json;
  assert.equal(narrow.individualId, '0000000017');
  assert.equal(narrow.sire, undefined);
  assert.deepEqual(narrow.disclosed, ['individualId']);
});

test('/verify: a plant record never lists or answers individual-id, even when granted', async () => {
  const holder = key();
  const r = { id: `pl-${randomBytes(6).toString('hex')}`, strainName: 'Plant P', bredBy: 'B', dateCreated: '2026-01-01',
    loggedAt: 1760000000000, nonce: newNonce(), notes: '', parents: [{ name: 'Mother' }], photoFingerprints: [], breedingMethod: '', refId: 'LOT-1' };
  r.recordFingerprint = await recomputeCommitment(r);
  assert.equal((await call('PUT', '/api/records', holder, [r])).json.count, 1);
  // The site sends no individual-id values for a plant; the key is still never answered.
  assert.equal((await call('PUT', `/api/records/${r.id}/disclosure`, holder, grantForTest(r, ['parent-names', 'individual-id']))).status, 200);
  const v = (await call('GET', `/verify/${r.id}`)).json;
  assert.equal(v.subjectKind, undefined);
  assert.deepEqual(v.parents, ['Mother']);
  assert.equal(v.sire, undefined);
  assert.equal(v.individualId, undefined);
  assert.deepEqual(v.disclosed, ['parents']);
});

test('a lab code for an animal: the sealed offer names the animal (ID, scheme, species, breed, sex), not its pedigree; the lab seals', async () => {
  const sender = key(), lab = key();
  const src = await animal();
  assert.equal((await call('PUT', '/api/records', sender, [src])).json.count, 1);
  // The sender's browser seals what the lab is told (CONTRACT.md #8); the key travels in the code.
  const offerKey = randomBytes(32);
  const sealedOffer = sealOfferForTest(offerFromRecord(src), offerKey, src.id, src.recordFingerprint);
  const o = await call('POST', '/transfers', sender, { sourceRecord: src.id, toHandle: 'lab@x', sealedOffer });
  assert.equal(o.status, 200, JSON.stringify(o.json));
  const c = await call('POST', `/transfers/${o.json.transferId}/claim`, lab, { claimCode: o.json.claimCode });
  assert.equal(c.status, 200, JSON.stringify(c.json));
  const stub = (await call('GET', '/api/records', lab)).json.find((r) => r.id === c.json.recordId);
  assert.equal(stub.profile, ANIMAL_PROFILE);
  for (const f of ['refId', 'taxon', 'animal', 'bredBy', 'nonce', 'parents']) assert.equal(stub[f], undefined, `${f} is not in the stub`);
  const offer = openOfferForTest(c.json.offerSealed, offerKey, src.id, src.recordFingerprint);
  assert.equal(offer.refId, '0000000017');
  assert.equal(offer.taxon, 'Cattle (Bos taurus)');
  assert.deepEqual(offer.animal, { breed: 'Japanese Black', idScheme: 'Japan cattle ID (10 digits)', sex: 'female' });
  assert.equal(offer.parents, undefined, 'the pedigree stays with the sender');
  // The lab's browser builds the record it received and seals it (records.ts sealReceived).
  // The stub has no name (round 5): it comes from the sealed offer.
  assert.equal(stub.strainName, undefined);
  const received = {
    ...stub, strainName: offer.strainName, bredBy: offer.bredBy, dateCreated: offer.dateCreated, taxon: offer.taxon, refId: offer.refId,
    animal: { ...offer.animal, herd: '' }, notes: '', breedingMethod: '', parents: [], photoFingerprints: [],
    licenseIds: [], nonce: newNonce(), loggedAt: stub.receivedAt,
  };
  received.recordFingerprint = await recomputeCommitment(received);
  const put = await call('PUT', '/api/records', lab, [received]);
  assert.equal(put.json.count, 1, JSON.stringify(put.json));
  const kept = (await call('GET', '/api/records', lab)).json.find((r) => r.id === c.json.recordId);
  assert.equal(kept.receivedFromCommitment, src.recordFingerprint, 'the registry keeps where it came from');
});

test('the profile id is exactly the one the vectors name', () => {
  assert.equal(ANIMAL_PROFILE, 'veilcore/profile/animal-individual/v1');
  assert.equal(createHash('sha256').update(readFileSync(new URL('./fixtures/animal-individual-v1.json', import.meta.url))).digest('hex').length, 64);
});
