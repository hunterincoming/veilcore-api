// Sealed records, round 2 (the site's CONTRACT.md #15-#26, registry side). Two outside
// reviews attacked the sealed registry (sealed/report-Attack-review-can-anyone-read-private-
// data.md, findings P1-P8, and ...-data-loss-and-breakage.md, L1-L8). Each test here is one
// finding the registry fixes, built from the reviewers' own proofs of concept
// (review-privacy/poc.mjs, review-loss/*.loss.test.ts), and failed before the fix:
//   P2  the recipient handle was stored and listed as typed     -> a tag; pending list gone
//   P3  a holder-typed lab name survived sealing                -> registry-written attestation only
//   P7  the clear fields took any text                          -> known values, ids, dates, hex
//   L4  a received record could be stuck as a stub forever      -> GET /transfers/:id/offer
//   L5  records the old registry held could not be converted    -> 360,000-character box, 384 KiB row, 40 MB saves
//   L6  the purge dropped grants that need no values            -> never dropped
//   L7  the purge stripped holders who had not converted yet    -> skipped and listed, unless both flags
// P4 (backups made before sealing) is test/backup.test.mjs and docs/rotate-backup-key.md.
// No network.
//
// SPDX-License-Identifier: Apache-2.0

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { randomBytes } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import Database from 'better-sqlite3';
import { canonicalise, sha256Hex, newNonce, diffRecords } from 'veilcore-records';
import {
  untilReady, sealForTest, vaultKeyFor, sealOfferForTest, openOfferForTest, offerFromRecord, handleTagFor, paddedSize,
} from './helpers.mjs';

process.env.DB_PATH = ':memory:';
process.env.VEILCORE_OTS = 'off';
const require = createRequire(import.meta.url);
const { app, db } = require('../server.js');
const { storedHolderKey } = require('../holder-key.js');
const sealedJs = require('../sealed.js');

const key = () => randomBytes(32).toString('hex');
let base, server;
before(async () => {
  server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  base = `http://127.0.0.1:${server.address().port}`;
  await untilReady(base);
});
after(() => server.close());

/** A request as the site sends it, from an address of its own (this file writes a lot). */
const call = async (method, path, holder, body) => {
  const res = await fetch(`${base}${path}`, {
    method,
    headers: { 'content-type': 'application/json', 'x-forwarded-for': `10.${randomBytes(3).join('.')}`, ...(holder ? { 'x-holder-key': holder } : {}) },
    ...(body === undefined ? {} : { body: typeof body === 'string' ? body : JSON.stringify(body) }),
  });
  const text = await res.text();
  let json; try { json = JSON.parse(text); } catch { json = text; }
  return { status: res.status, json, headers: res.headers };
};
const put = (holder, rows) => call('PUT', '/api/records', holder, rows);

const committedOf = (r) => ({ breedingMethod: r.breedingMethod ?? '', bredBy: r.bredBy, dateCreated: r.dateCreated,
  loggedAt: r.loggedAt, nonce: r.nonce, notes: r.notes, parents: r.parents ?? [],
  photoFingerprints: r.photoFingerprints ?? [], refId: r.refId ?? '', strainName: r.strainName });
const makeRecord = async (id, over = {}) => {
  const r = { id, strainName: `Name ${id}`, bredBy: 'Breeder', dateCreated: '2026-01-01', loggedAt: 1760000000000,
    nonce: newNonce(), notes: 'private notes', parents: [], photoFingerprints: [], breedingMethod: '', refId: '', ...over };
  r.recordFingerprint = await sha256Hex(canonicalise(committedOf(r)));
  return r;
};
const sealedFor = (holder, r, opts) => sealForTest(r, vaultKeyFor(holder), 'records', opts);
const bodyOf = (id) => JSON.parse(db.prepare('SELECT body FROM records WHERE id = ?').get(id).body);
/** Everything the operator could read in the tables that hold holder data, as one string. */
const operatorView = () => ['records', 'licenses', 'transfers', 'disclosure_grants']
  .flatMap((t) => db.prepare(`SELECT * FROM ${t}`).all().map((r) => JSON.stringify(r))).join('\n');

/** A sealed source record of `sender`, and a sealed offer for it under a fresh offer key. */
const sealedSource = async (sender, id) => {
  const src = await makeRecord(id);
  assert.equal((await put(sender, [sealedFor(sender, src)])).json.count, 1);
  const offerKey = randomBytes(32);
  return { src, offerKey, sealedOffer: () => sealOfferForTest(offerFromRecord(src, { quantity: '3 clones' }), offerKey, src.id, src.recordFingerprint) };
};

// ---------------------------------------------------------------------------------------
// P2: who a delivery is sent to was readable, and partly public (CONTRACT.md #15)
// ---------------------------------------------------------------------------------------

test('P2: toHandle must be a tag; a name is refused with "toHandle is a tag, not a name" and nothing is stored', async () => {
  const sender = key();
  const { src, sealedOffer } = await sealedSource(sender, 'R2-P2-SRC');
  const NAME = 'dr.jane@secret-lab.example'; // the reviewer's proof of concept
  const tag = handleTagFor(sender, NAME);
  for (const bad of [NAME, tag.toUpperCase(), tag.slice(1), `${tag}0`, ` ${tag}`, 42, '', null, undefined]) {
    const r = await call('POST', '/transfers', sender, { sourceRecord: src.id, toHandle: bad, sealedOffer: sealedOffer() });
    assert.equal(r.status, 400, String(bad));
    assert.deepEqual(r.json, { error: 'toHandle is a tag, not a name' }, String(bad));
  }
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM transfers WHERE source_record = ?').get(src.id).n, 0, 'nothing refused was stored');

  const ok = await call('POST', '/transfers', sender, { sourceRecord: src.id, toHandle: tag, sealedOffer: sealedOffer() });
  assert.equal(ok.status, 200, JSON.stringify(ok.json));
  assert.equal(db.prepare('SELECT to_handle FROM transfers WHERE id = ?').get(ok.json.transferId).to_handle, tag);
  assert.ok(!operatorView().includes(NAME), 'the name is nowhere the registry can read');
  // The sender's own list carries the tag; the app shows the name from its own sealed data.
  assert.equal((await call('GET', '/transfers/sent', sender)).json.transfers[0].to_handle, tag);
});

test('P2: a claim writes no handle into any record; the attestation holds only what the registry sets', async () => {
  const sender = key(), lab = key();
  const { src, sealedOffer } = await sealedSource(sender, 'R2-P2-CLAIM');
  const tag = handleTagFor(sender, 'dr.jane@secret-lab.example');
  const o = await call('POST', '/transfers', sender, { sourceRecord: src.id, toHandle: tag, sealedOffer: sealedOffer() });
  const c = await call('POST', `/transfers/${o.json.transferId}/claim`, lab, { claimCode: o.json.claimCode });
  assert.equal(c.status, 200, JSON.stringify(c.json));
  const att = bodyOf(src.id).attestation;
  assert.deepEqual(Object.keys(att).sort(), [...sealedJs.REGISTRY_ATTESTATION_FIELDS].sort());
  assert.equal(att.addressedTo, undefined);
  const records = db.prepare('SELECT body FROM records').all().map((r) => r.body).join('\n');
  assert.ok(!records.includes(tag), 'the tag is in no record');
  assert.ok(!records.includes('secret-lab'), 'nor the name');
});

test('P2: GET /transfers/pending/:handle is removed: 410 { error: "removed" } for a name or a tag', async () => {
  const sender = key();
  const { src, sealedOffer } = await sealedSource(sender, 'R2-P2-PEND');
  const tag = handleTagFor(sender, 'dr.jane@secret-lab.example');
  assert.equal((await call('POST', '/transfers', sender, { sourceRecord: src.id, toHandle: tag, sealedOffer: sealedOffer() })).status, 200);
  for (const h of [encodeURIComponent('dr.jane@secret-lab.example'), tag]) {
    const r = await call('GET', `/transfers/pending/${h}`);
    assert.equal(r.status, 410);
    assert.deepEqual(r.json, { error: 'removed' });
  }
});

test('P2: the per-sender-and-handle limit counts by tag: the 21st open offer to one tag is refused, another tag is not', async () => {
  const sender = key();
  const { src, sealedOffer } = await sealedSource(sender, 'R2-P2-CAP');
  const tag = handleTagFor(sender, 'busy@lab');
  for (let i = 0; i < 20; i++) {
    const r = await call('POST', '/transfers', sender, { sourceRecord: src.id, toHandle: tag, sealedOffer: sealedOffer() });
    assert.equal(r.status, 200, `offer ${i + 1}: ${JSON.stringify(r.json)}`);
  }
  const over = await call('POST', '/transfers', sender, { sourceRecord: src.id, toHandle: tag, sealedOffer: sealedOffer() });
  assert.equal(over.status, 429);
  assert.match(over.json.error, /to this handle/);
  assert.equal((await call('POST', '/transfers', sender, { sourceRecord: src.id, toHandle: handleTagFor(sender, 'other@lab'), sealedOffer: sealedOffer() })).status, 200);
});

// ---------------------------------------------------------------------------------------
// P3: a holder-typed lab name survived sealing (CONTRACT.md #16)
// ---------------------------------------------------------------------------------------

test('P3: an older record\'s holder-typed lab name, and an older claim\'s handle, do not survive a sealed save', async () => {
  const holder = key();
  // The reviewer's proof of concept: a legacy plaintext row with an attestation its holder typed.
  const legacy = await makeRecord('R2-P3-LEGACY', { notes: 'OLD-NOTES' });
  const typed = { lab: 'SECRET-LAB-NAME-HOLDER-TYPED', attestedAt: 5 };
  db.prepare('INSERT INTO records (id, holder_key, body, updated_at, first_seen) VALUES (?,?,?,?,?)')
    .run(legacy.id, storedHolderKey(holder), JSON.stringify({ ...legacy, attestation: typed }), 1, 1);
  // The browser converts it, sending the attestation back as it read it (the site did).
  const r = await put(holder, [{ ...sealedFor(holder, legacy), attestation: typed }]);
  assert.equal(r.json.count, 1, JSON.stringify(r.json));
  const stored = bodyOf(legacy.id);
  assert.ok(stored.sealed);
  assert.equal(stored.attestation, undefined, 'nothing of a holder-typed attestation is kept');
  assert.ok(!JSON.stringify(stored).includes('SECRET-LAB-NAME'));

  // A receipt confirmation an older claim wrote, with the handle in it (addressedTo, and
  // attesterHandle before that) and a lab name added: only the registry's own fields stay.
  const old = await makeRecord('R2-P3-CLAIMED');
  const att = { attesterKey: 'ab'.repeat(32), addressedTo: 'lab@example.com', attesterHandle: 'lab@example.com', type: 'receipt-confirmed',
    confirms: 'a party holding the code the sender issued took delivery', transferId: 'TR-57AF56DB', attestedAt: 1791502600841, lab: 'Typed Lab' };
  db.prepare('INSERT INTO records (id, holder_key, body, updated_at, first_seen) VALUES (?,?,?,?,?)')
    .run(old.id, storedHolderKey(holder), JSON.stringify({ ...old, attestation: att }), 1, 1);
  assert.equal((await put(holder, [sealedFor(holder, old)])).json.count, 1);
  assert.deepEqual(bodyOf(old.id).attestation, {
    attesterKey: att.attesterKey, type: 'receipt-confirmed', confirms: att.confirms, transferId: att.transferId, attestedAt: att.attestedAt,
  });
});

// ---------------------------------------------------------------------------------------
// P7: the clear fields took free text (CONTRACT.md #18)
// ---------------------------------------------------------------------------------------

test('P7: profile, changedFields, effectiveAt, supersededBy and termsHash refuse free text; known values are accepted', async () => {
  const holder = key();
  const target = await makeRecord('R2-P7-ORIG');
  assert.equal((await put(holder, [sealedFor(holder, target)])).json.count, 1);
  const row = async (id, pub) => ({ ...sealedFor(holder, await makeRecord(id)), ...pub });
  // The reviewer's proof of concept, field by field.
  const refused = [
    [await row('R2-P7-PROFILE', { profile: 'SECRET-IN-PROFILE' }), /^profile must be one of veilcore\/profile\/plant-variety\/v1, /],
    [await row('R2-P7-FIELDS', { supersedes: { recordId: target.id, changedFields: ['SECRET-REASON-TEXT'] } }), /^supersedes\.changedFields may hold only known record field names$/],
    [await row('R2-P7-FIELDS2', { supersedes: { recordId: target.id, changedFields: ['notes', 7] } }), /^supersedes\.changedFields may hold only known record field names$/],
    [await row('R2-P7-FIELDS3', { supersedes: { recordId: target.id, changedFields: 'notes' } }), /^supersedes\.changedFields must be a list of at most \d+ field names$/],
    [await row('R2-P7-WHEN', { supersedes: { recordId: target.id, effectiveAt: 'SECRET-40-CHARS' } }), /^supersedes\.effectiveAt must be an ISO 8601 date and time/],
    [await row('R2-P7-WHEN2', { supersedes: { recordId: target.id, effectiveAt: '2026-02-31T00:00:00Z' } }), /^supersedes\.effectiveAt must be an ISO 8601/],
    [await row('R2-P7-WHEN3', { supersedes: { recordId: target.id, effectiveAt: '2026-10-01' } }), /^supersedes\.effectiveAt must be an ISO 8601/],
    [await row('R2-P7-RECID', { supersedes: { recordId: 'SECRET words in the id' } }), /^supersedes\.recordId must be a record id$/],
    [await row('R2-P7-BY', { supersededBy: 'SECRET words here' }), /^supersededBy must be a record id$/],
  ];
  const r = await put(holder, refused.map(([x]) => x));
  assert.equal(r.json.count, 0, JSON.stringify(r.json));
  for (const [x, reason] of refused) assert.match(r.json.rejected.find((j) => j.id === x.id).reason, reason, x.id);
  assert.ok(!JSON.stringify(r.json).includes('SECRET'), 'a refusal does not echo the text');
  assert.ok(!operatorView().includes('SECRET-IN-PROFILE') && !operatorView().includes('SECRET-REASON-TEXT'));
  assert.equal((await call('GET', '/verify/R2-P7-FIELDS')).status, 404);

  // What the site sends is accepted: every known profile, every known field name, the SDK's dates.
  const good = [];
  for (const [i, profile] of sealedJs.KNOWN_PROFILES.entries()) good.push(await row(`R2-P7-OK-P${i}`, { profile }));
  good.push(await row('R2-P7-OK-ALL', { supersedes: { recordId: target.id, changedFields: [...sealedJs.CHANGED_FIELD_NAMES], effectiveAt: '2026-10-16T09:30:00Z' } }));
  // Each correcting a record of its own: a record is corrected once (corrections.js).
  const target2 = await makeRecord('R2-P7-ORIG2');
  const target3 = await makeRecord('R2-P7-ORIG3');
  assert.equal((await put(holder, [sealedFor(holder, target2), sealedFor(holder, target3)])).json.count, 2);
  good.push(await row('R2-P7-OK-MS', { supersedes: { recordId: target2.id, changedFields: ['dateCreated'], effectiveAt: '2026-09-02T00:00:00.000Z' } }));
  good.push(await row('R2-P7-OK-OFF', { supersedes: { recordId: target3.id, effectiveAt: '2026-09-02T09:00:00+09:00' } }));
  const ok = await put(holder, good);
  assert.equal(ok.json.count, good.length, JSON.stringify(ok.json));

  // termsHash on an offer: 64 lowercase hex, or absent.
  const sender = key();
  const { src, sealedOffer } = await sealedSource(sender, 'R2-P7-TERMS');
  const offer = (termsHash) => call('POST', '/transfers', sender, { sourceRecord: src.id, toHandle: handleTagFor(sender, 'lab@x'), termsHash, sealedOffer: sealedOffer() });
  for (const bad of ['SECRET-TERMS-HASH-FREE-TEXT', 'AB'.repeat(32), 'ab'.repeat(31), 5]) {
    const t = await offer(bad);
    assert.equal(t.status, 400, String(bad));
    assert.equal(t.json.error, 'termsHash must be 64 lowercase hexadecimal characters');
  }
  assert.equal((await offer('ab'.repeat(32))).status, 200);
  assert.equal((await offer(undefined)).status, 200);
  assert.ok(!operatorView().includes('SECRET-TERMS-HASH'));
});

test('P7: words already in a legacy row\'s clear fields are never served to the public', async () => {
  const holder = key();
  const r = await makeRecord('R2-P7-LEGACY');
  db.prepare('INSERT INTO records (id, holder_key, body, updated_at, first_seen) VALUES (?,?,?,?,?)').run(r.id, storedHolderKey(holder), JSON.stringify({
    ...r, supersedes: { recordId: 'SECRET words', changedFields: ['notes', 'SECRET-REASON-TEXT'], effectiveAt: 'SECRET-40-CHARS' },
  }), 1, 1);
  const v = (await call('GET', `/verify/${r.id}`)).json;
  assert.ok(!JSON.stringify(v).includes('SECRET'), JSON.stringify(v));
  const pub = (await call('GET', `/records/${r.id}`)).json;
  assert.ok(!JSON.stringify(pub).includes('SECRET'), JSON.stringify(pub));
});

/**
 * The envelope the site's envelope.ts toEnvelope makes, for the fields diffRecords compares:
 * a plant record and an animal record, every field set. Mirrors the site's code (read only,
 * bboard-ui src/veilcore/envelope.ts); the cross-repo contract test checks the site's exported
 * list against sealed.js CHANGED_FIELD_NAMES directly.
 */
const envelopeOf = (r, holderId = 'h') => {
  const animal = r.profile === 'veilcore/profile/animal-individual/v1';
  return {
    formatVersion: '0.1', recordId: r.id, subjectType: animal ? 'animal-genetic-material' : 'plant-genetic-material',
    profile: r.profile ?? 'veilcore/profile/cannabis/v0.1', commitment: r.recordFingerprint, commitmentAlgorithm: 'sha256/canonical-json/v1',
    anchor: { chain: 'midnight', network: 'undeployed' }, sealedAt: new Date(r.loggedAt).toISOString().replace(/\.\d{3}Z$/, 'Z'),
    holder: { id: holderId },
    subject: { name: r.strainName, originator: r.bredBy || undefined, taxon: r.taxon, internalDesignation: animal ? undefined : r.refId || undefined, claimedCreationDate: r.dateCreated || undefined },
    identification: r.dnaFingerprint ? { method: 'molecular-marker', reportHash: r.dnaFingerprint, performedOn: r.dnaPairedAt ? new Date(r.dnaPairedAt).toISOString() : undefined } : undefined,
    parents: (r.parents ?? []).map((p) => ({ parentRecordId: p.recordId, name: p.name, ...(animal && p.role ? { role: p.role } : {}), declaredBy: 'holder', verified: false })),
    attestations: r.dnaFingerprint ? [{ attestationId: `${r.id}-dna`, type: 'genetic-fingerprint', attester: { id: 'unattested' }, documentHash: r.dnaFingerprint }] : [],
    profileData: animal
      ? { breed: r.animal?.breed || undefined, sex: r.animal?.sex, individualId: r.refId || undefined, idScheme: r.animal?.idScheme || undefined,
          herd: r.animal?.herd || undefined, parentIds: (r.parents ?? []).map((p) => ({ role: p.role, individualId: p.individualId ?? '' })), notes: r.notes || undefined, nonce: r.nonce }
      : { breedingMethod: r.breedingMethod || undefined, notes: r.notes || undefined, nonce: r.nonce },
  };
};

test('P7: every field name a site correction can report is in sealed.js CHANGED_FIELD_NAMES', () => {
  const plantA = { id: 'A', strainName: 'a', bredBy: 'b', dateCreated: '2020-01-01', taxon: 't', refId: 'r', notes: 'n', breedingMethod: 'm',
    loggedAt: 2_000_000_000_000, nonce: '1', parents: [{ name: 'p' }], dnaFingerprint: 'aa', dnaPairedAt: 1, profile: 'veilcore/profile/plant-variety/v1' };
  const plantB = { id: 'B', strainName: 'b2', bredBy: '', dateCreated: '2021-01-01', taxon: 'u', refId: '', notes: 'm', breedingMethod: '',
    loggedAt: 1_000_000_000_000, nonce: '2', parents: [{ name: 'q' }], profile: 'veilcore/profile/plant-variety/v1' };
  const animalA = { ...plantA, profile: 'veilcore/profile/animal-individual/v1', animal: { breed: 'x', sex: 'female', idScheme: 's', herd: 'h' }, parents: [{ name: 'p', role: 'sire', individualId: '1' }] };
  const animalB = { ...plantB, profile: 'veilcore/profile/animal-individual/v1', animal: { breed: 'y', sex: 'male', idScheme: 't', herd: '' }, parents: [{ name: 'q', role: 'dam', individualId: '2' }] };
  const legacy = { ...plantB, profile: undefined };
  const known = new Set(sealedJs.CHANGED_FIELD_NAMES);
  const reported = new Set();
  for (const [x, y] of [[plantA, plantB], [plantB, plantA], [animalA, animalB], [plantA, animalB], [animalB, plantA], [legacy, plantA]]) {
    for (const c of diffRecords(envelopeOf(x), envelopeOf(y))) reported.add(c.field);
  }
  assert.ok(reported.size > 15, [...reported].join(', '));
  for (const f of reported) assert.ok(known.has(f), `${f} is reported by a correction but not known to the registry`);
  assert.ok(Object.isFrozen(sealedJs.CHANGED_FIELD_NAMES));
  assert.equal(new Set(sealedJs.CHANGED_FIELD_NAMES).size, sealedJs.CHANGED_FIELD_NAMES.length, 'no duplicates');
});

// ---------------------------------------------------------------------------------------
// L5: records the old registry held could not be converted (CONTRACT.md #21)
// ---------------------------------------------------------------------------------------

test('L5: a record at the old registry\'s maximum (20,000 characters of Japanese notes) converts, padded as the browser pads it', async () => {
  const holder = key();
  const cjk = (n) => '育'.repeat(n);
  // The reviewer's record (review-loss/c.loss.test.ts): JSON of about 25,900 characters, which
  // the old registry took (64K characters), about 77 KB in UTF-8.
  const big = await makeRecord('R2-L5-CJK', { notes: cjk(20_000), breedingMethod: cjk(5_000), bredBy: cjk(500) });
  assert.ok(JSON.stringify(big).length > 25_000 && JSON.stringify(big).length < 65_536);
  db.prepare('INSERT INTO records (id, holder_key, body, updated_at, first_seen) VALUES (?,?,?,?,?)')
    .run(big.id, storedHolderKey(holder), JSON.stringify(big), 1, 1);
  const r = await put(holder, [sealedFor(holder, big, { pad: true })]);
  assert.equal(r.json.count, 1, JSON.stringify(r.json));
  assert.ok(bodyOf(big.id).sealed, 'converted');

  // The worst the old registry could hold: 65,536 characters of JSON, all three-byte UTF-8.
  const worst = await makeRecord('R2-L5-WORST');
  worst.notes = cjk(65_536 - JSON.stringify({ ...worst, notes: '' }).length);
  assert.equal(JSON.stringify(worst).length, 65_536);
  const w = sealedFor(holder, worst, { pad: true });
  assert.ok(w.sealed.ct.length > 250_000, String(w.sealed.ct.length));
  assert.equal((await put(holder, [w])).json.count, 1);

  // And the browser's own ceiling, 256 KiB padded: the largest box it can make fits.
  const max = await makeRecord('R2-L5-MAX', { notes: 'x'.repeat(256 * 1024 - 400) });
  const m = sealedFor(holder, max, { pad: true });
  assert.ok(m.sealed.ct.length <= sealedJs.SEALED_CT_MAX && m.sealed.ct.length > 349_000, String(m.sealed.ct.length));
  assert.equal((await put(holder, [m])).json.count, 1);
});

test('L5: a full save of a set at the old 16 MB ceiling, padded and sealed, fits in one request', async () => {
  const holder = key();
  // Records just over 16 KiB are padded to 24 KiB (half again): the worst case for a set.
  // 16 MB of them, sealed, is about 32 MB in one save; the old 24 MB limit refused it.
  const notesLen = 16 * 1024; // sealed with bredBy: just over 16 KiB, so padded to 24 KiB
  const rows = [];
  let plainBytes = 0;
  for (let i = 0; i < 1000; i++) {
    const r = { id: `R2-L5-SET-${i}`, strainName: `S${i}`, notes: randomBytes(notesLen).toString('base64').slice(0, notesLen), bredBy: 'b' };
    plainBytes += JSON.stringify(r).length;
    rows.push(sealedFor(holder, r, { pad: true }));
  }
  assert.ok(plainBytes <= 16 * 1024 * 1024, String(plainBytes));
  const body = JSON.stringify(rows);
  assert.ok(body.length > 30 * 1024 * 1024, `${body.length} bytes`);
  assert.equal(paddedSize(16 * 1024 + 1), 24 * 1024);
  const r = await call('PUT', '/api/records', holder, body);
  assert.equal(r.status, 200, JSON.stringify(r.json).slice(0, 200));
  assert.equal(r.json.count, 1000);
});

// ---------------------------------------------------------------------------------------
// L4: a received record could be stuck as a stub forever (CONTRACT.md #22)
// ---------------------------------------------------------------------------------------

test('L4: GET /transfers/:id/offer gives the claimant its sealed offer again, byte for byte; 404 to anyone else, the sender too', async () => {
  const sender = key(), lab = key(), stranger = key();
  const { src, offerKey, sealedOffer } = await sealedSource(sender, 'R2-L4-SRC');
  const box = sealedOffer();
  const o = await call('POST', '/transfers', sender, { sourceRecord: src.id, toHandle: handleTagFor(sender, 'lab@x'), sealedOffer: box });
  const id = o.json.transferId;
  // Before anyone claims it, nobody gets it: not the sender, not whoever holds the code.
  for (const who of [sender, lab, stranger]) assert.equal((await call('GET', `/transfers/${id}/offer`, who)).status, 404);
  const c = await call('POST', `/transfers/${id}/claim`, lab, { claimCode: o.json.claimCode });
  assert.equal(c.status, 200);
  // The tab was closed after the claim: the stub is all the lab has. It asks again.
  const again = await call('GET', `/transfers/${id}/offer`, lab);
  assert.equal(again.status, 200, JSON.stringify(again.json));
  assert.deepEqual(Object.keys(again.json).sort(), ['offerSealed', 'transferId']);
  assert.equal(again.json.transferId, id);
  assert.equal(JSON.stringify(again.json.offerSealed), JSON.stringify(box), 'byte for byte as the sender sent it');
  assert.equal(again.headers.get('cache-control'), 'no-store');
  // The stub carries what opening it needs (the offer's AAD: source id and fingerprint).
  const stub = bodyOf(c.json.recordId);
  assert.equal(openOfferForTest(again.json.offerSealed, offerKey, stub.receivedFrom, stub.receivedFromCommitment).quantity, '3 clones');
  for (const who of [sender, stranger]) {
    const r = await call('GET', `/transfers/${id}/offer`, who);
    assert.equal(r.status, 404, 'the sender gets what a stranger gets');
    assert.deepEqual(r.json, { error: 'no such transfer' });
  }
  assert.deepEqual((await call('GET', '/transfers/TR-NOPE0000/offer', lab)).json, { error: 'no such transfer' });
  assert.equal((await call('GET', `/transfers/${id}/offer`)).status, 401);
  // The claimant's key in upper case is the same holder.
  assert.equal((await call('GET', `/transfers/${id}/offer`, lab.toUpperCase())).status, 200);
});

test('L4: a code made before sealing gives offerPlain again while the source is plain; 409 once it is sealed', async () => {
  const sender = key(), lab = key();
  const src = await makeRecord('R2-L4-LEGACY', { taxon: 'Malus domestica', notes: 'TOP SECRET' });
  db.prepare('INSERT INTO records (id, holder_key, body, updated_at, first_seen) VALUES (?,?,?,?,?)')
    .run(src.id, storedHolderKey(sender), JSON.stringify(src), 1, 1);
  const o = await call('POST', '/transfers', sender, { sourceRecord: src.id, toHandle: handleTagFor(sender, 'lab@x'), quantity: '2', note: 'old note' });
  assert.equal(o.status, 200, JSON.stringify(o.json));
  const c = await call('POST', `/transfers/${o.json.transferId}/claim`, lab, { claimCode: o.json.claimCode });
  const again = await call('GET', `/transfers/${o.json.transferId}/offer`, lab);
  assert.equal(again.status, 200);
  assert.deepEqual(again.json, { transferId: o.json.transferId, offerPlain: c.json.offerPlain });
  assert.equal(again.json.offerPlain.note, 'old note');
  assert.ok(!JSON.stringify(again.json).includes('TOP SECRET'));
  // The sender's app seals the source since: nothing readable is left to pass on.
  assert.equal((await put(sender, [sealedFor(sender, src)])).json.count, 1);
  const gone = await call('GET', `/transfers/${o.json.transferId}/offer`, lab);
  assert.equal(gone.status, 409);
  assert.match(gone.json.error, /ask the sender for a new code/);
});

// ---------------------------------------------------------------------------------------
// L5, L6, L7: the purge guard (CONTRACT.md #24)
// ---------------------------------------------------------------------------------------

const purge = fileURLToPath(new URL('../scripts/purge-plaintext.mjs', import.meta.url));

test('L6, L7: the purge skips holders who have not converted, reports a converted holder\'s plain rows, keeps grants that need no values', () => {
  const dir = mkdtempSync(join(tmpdir(), 'veilcore-purge-'));
  try {
    const file = join(dir, 'p.db');
    // This registry's own tables, empty.
    const f = new Database(file);
    for (const { sql } of db.prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name IN ('records', 'licenses', 'transfers', 'disclosure_grants')").all()) f.exec(sql);
    const converted = storedHolderKey(key()), fresh = storedHolderKey(key());
    const ins = f.prepare('INSERT INTO records (id, holder_key, body, updated_at, first_seen) VALUES (?,?,?,?,?)');
    ins.run('C-SEALED', converted, JSON.stringify({ id: 'C-SEALED', strainName: 'n', sealed: { v: 1, alg: 'A256GCM', kid: '0'.repeat(16), iv: 'A'.repeat(16), ct: 'A'.repeat(24) } }), 1, 1);
    // L5: a record too large to convert. Its holder's app tried; it stays plain, and is reported.
    ins.run('C-TOOBIG', converted, JSON.stringify({ id: 'C-TOOBIG', strainName: 'n', notes: 'STUCK-TEXT' }), 1, 1);
    // L7: a holder who has not opened the sealing site yet.
    ins.run('F-PLAIN', fresh, JSON.stringify({ id: 'F-PLAIN', strainName: 'n', notes: 'FRESH-TEXT' }), 1, 1);
    // L6: a converted holder's grants made before grant values (review-loss/c.loss.test.ts):
    // keys that need no values are kept; on a sealed record the one that publishes values
    // goes; on a record still plain text the grant is left whole (round 3, L6).
    const g = f.prepare('INSERT INTO disclosure_grants (record_id, holder_key, show, updated_at) VALUES (?,?,?,?)');
    g.run('C-SEALED', converted, '["existence","descent-clean","breeding-method"]', 1);
    g.run('C-TOOBIG', converted, '["descent-clean","breeding-method"]', 1);
    f.close();

    const dry = execFileSync(process.execPath, [purge, '--db', file], { encoding: 'utf8' });
    assert.match(dry, /^dry run, nothing changed/);
    assert.match(dry, /records: 1 sealed, 0 with public fields only, 0 to reduce to public fields, 1 still plain under converted holders \(reported, not stripped\), 1 of holders not yet converted \(skipped\)/);
    assert.match(dry, new RegExp(`holders not yet converted \\(skipped; nothing of theirs is changed except recipient names typed before tags, which are replaced\\):\\n  holder ${fresh.slice(3, 15)}: 1 records, 0 licences`));
    assert.match(dry, new RegExp(`converted holders with rows still in plain text[^\\n]*\\n  holder ${converted.slice(3, 15)}: 1 records, 0 licences`));
    assert.match(dry, /disclosure grants without values: 1 keys that publish values to drop, 0 grants left with no keys to drop \(existence and descent-clean are kept\), 1 on records still in plain text/);
    assert.ok(!dry.includes(converted) && !dry.includes(fresh), 'a holder is named by a short prefix only');

    execFileSync(process.execPath, [purge, '--db', file, '--apply'], { encoding: 'utf8' });
    const after1 = new Database(file, { readonly: true });
    const body = (id) => JSON.parse(after1.prepare('SELECT body FROM records WHERE id = ?').get(id).body);
    assert.equal(body('C-TOOBIG').notes, 'STUCK-TEXT', 'reported, not stripped');
    assert.equal(body('F-PLAIN').notes, 'FRESH-TEXT', 'skipped');
    assert.equal(body('C-SEALED').strainName, 'n', 'a name its holder\'s app has not moved inside yet is kept');
    const shows = Object.fromEntries(after1.prepare('SELECT record_id, show FROM disclosure_grants').all().map((x) => [x.record_id, x.show]));
    assert.deepEqual(shows, { 'C-SEALED': '["existence","descent-clean"]', 'C-TOOBIG': '["descent-clean","breeding-method"]' },
      'keys that need no values are never dropped, and a grant on a record not yet converted is left whole');
    after1.close();

    execFileSync(process.execPath, [purge, '--db', file, '--apply', '--include-unconverted', '--i-understand-this-deletes-text'], { encoding: 'utf8' });
    const after2 = new Database(file, { readonly: true });
    const body2 = (id) => JSON.parse(after2.prepare('SELECT body FROM records WHERE id = ?').get(id).body);
    // The name goes too (round 5: a name is sealed, so publicPartOf keeps none).
    assert.deepEqual(body2('F-PLAIN'), { id: 'F-PLAIN', contentsRemoved: true }, 'stripped only with both flags');
    // The converted holder's sealed row kept its clear name through --apply (their app has not
    // sealed a name yet: no sealed row of theirs is without one); the two-flag run removes it.
    assert.equal(body2('C-SEALED').strainName, undefined);
    assert.equal(body2('C-TOOBIG').notes, 'STUCK-TEXT', 'a converted holder\'s plain row is never stripped');
    after2.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('/health lists claimant-offer-v1, for the site\'s deploy preflight', async () => {
  assert.ok((await call('GET', '/health')).json.features.includes('claimant-offer-v1'));
});

test('the attestation shape, the handle tag and the legacy tag are what the contract says', () => {
  assert.deepEqual(sealedJs.REGISTRY_ATTESTATION_FIELDS, ['attesterKey', 'type', 'confirms', 'transferId', 'attestedAt']);
  assert.equal(sealedJs.HANDLE_TAG_PROBLEM, 'toHandle is a tag, not a name');
  // Round 3 (P6): random, never a hash of the handle.
  assert.match(sealedJs.legacyHandleReplacement(), /^[0-9a-f]{64}$/);
  assert.notEqual(sealedJs.legacyHandleReplacement(), sealedJs.legacyHandleReplacement());
  assert.equal(sealedJs.legacyHandleTag, undefined);
  assert.equal(sealedJs.SEALED_CT_MAX, 360_000);
  assert.equal(sealedJs.RECORD_MAX_BYTES, 384 * 1024);
});
