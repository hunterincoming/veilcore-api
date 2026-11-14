// Sealed records (the site's CONTRACT.md for sealed records, 16 Oct 2026): the registry
// cannot read what a holder typed. What it refuses, what it still enforces, what the public
// is answered from, and, on a database file, that none of what a holder typed is anywhere in
// the bytes the registry leaves on disk: after a save, after a legacy row is converted, and
// after scripts/purge-plaintext.mjs --apply. No network.
//
// SPDX-License-Identifier: Apache-2.0

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { createHash, randomBytes } from 'node:crypto';
import { fork, execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import Database from 'better-sqlite3';
import { canonicalise, sha256Hex, newNonce } from 'veilcore-records';
import {
  untilReady, sealForTest, openForTest, vaultKeyFor, kidOf, grantForTest, sealOfferForTest, openOfferForTest, offerFromRecord,
  handleTagFor,
} from './helpers.mjs';

process.env.DB_PATH = ':memory:';
process.env.VEILCORE_OTS = 'off';
const require = createRequire(import.meta.url);
const { app, db } = require('../server.js');
const { storedHolderKey } = require('../holder-key.js');

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

const callAt = (at) => async (method, path, holder, body) => {
  const res = await fetch(`${at()}${path}`, {
    method,
    // A client address of its own per call: this file makes more writes than one address may in a minute.
    headers: { 'content-type': 'application/json', 'x-forwarded-for': `10.${randomBytes(3).join('.')}`, ...(holder ? { 'x-holder-key': holder } : {}) },
    ...(body === undefined ? {} : { body: typeof body === 'string' ? body : JSON.stringify(body) }),
  });
  const text = await res.text();
  let json; try { json = JSON.parse(text); } catch { json = text; }
  return { status: res.status, json, text };
};
const call = callAt(() => base);

const committedOf = (r) => ({ breedingMethod: r.breedingMethod ?? '', bredBy: r.bredBy, dateCreated: r.dateCreated,
  loggedAt: r.loggedAt, nonce: r.nonce, notes: r.notes, parents: r.parents ?? [],
  photoFingerprints: r.photoFingerprints ?? [], refId: r.refId ?? '', strainName: r.strainName });
/** A full record as the holder's browser holds it, with its fingerprint. */
const makeRecord = async (id, over = {}) => {
  const r = { id, strainName: `Name ${id}`, bredBy: 'Breeder', dateCreated: '2026-01-01', loggedAt: '2021-03-01T00:00:00Z',
    nonce: newNonce(), notes: 'private notes', parents: [{ name: 'Secret Mother', recordId: 'VEIL-PARENT' }],
    photoFingerprints: [], breedingMethod: 'secret method', refId: '', ...over };
  r.recordFingerprint = await sha256Hex(canonicalise(committedOf(r)));
  return r;
};
const sealedFor = (holder, r) => sealForTest(r, vaultKeyFor(holder));
const put = (holder, rows) => call('PUT', '/api/records', holder, rows);

// ---------------------------------------------------------------------------------------
// The wire validator (CONTRACT.md #6)
// ---------------------------------------------------------------------------------------

/** Every field the contract puts inside `sealed`, and one nobody has heard of. */
const PRIVATE_FIELDS = {
  nonce: newNonce(), bredBy: 'B', dateCreated: '2026-01-01', notes: 'n', loggedAt: 1760000000000, parents: [],
  breedingMethod: 'm', taxon: 'Malus domestica', animal: { breed: 'x' }, photoFingerprints: [], refId: 'r',
  dnaFingerprint: 'ab'.repeat(32), dnaFileName: 'f.pdf', dnaPairedAt: 1, dnaFileSha256: 'cd'.repeat(32), dnaResultId: 'LR-1',
  licenseIds: [], quantity: '1', deliveryNote: 'd', labRef: 'L', resultLock: {}, receiptRejected: true, colour: 'green',
};

test('every private field at the top level is refused, by name, and nothing of it is stored', async () => {
  const holder = key();
  const rows = [];
  for (const [field, value] of Object.entries(PRIVATE_FIELDS)) {
    rows.push({ ...sealedFor(holder, await makeRecord(`priv-${field}`)), [field]: value });
  }
  const r = await put(holder, rows);
  assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.equal(r.json.count, 0);
  assert.equal(r.json.ok, false);
  assert.equal(r.json.rejected.length, rows.length);
  for (const field of Object.keys(PRIVATE_FIELDS)) {
    const rej = r.json.rejected.find((x) => x.id === `priv-${field}`);
    assert.equal(rej.reason, `${field} is not stored in the clear; it belongs inside sealed`, field);
  }
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM records WHERE holder_key = ?').get(storedHolderKey(holder)).n, 0);
  // A plaintext record as older sites sent it: refused whole. There is no setting that lets it in.
  // It carries its name in the clear, so since round 5 the whole save is refused for that.
  const plainOld = await makeRecord('plain-old');
  const p = await put(holder, [plainOld]);
  assert.equal(p.status, 400);
  assert.equal(p.json.error, 'strainName belongs inside sealed');
  const { strainName: _n, ...nameless } = plainOld;
  void _n;
  const p2 = await put(holder, [nameless]);
  assert.equal(p2.json.count, 0);
  assert.match(p2.json.rejected[0].reason, /is not stored in the clear/);
});

test('sealed is required and must be a well-formed box: missing, oversized or malformed is refused', async () => {
  const holder = key();
  const ok = sealedFor(holder, await makeRecord('box-ok'));
  const { sealed: _s, ...noBox } = { ...ok, id: 'box-none' };
  void _s;
  const b = (id, sealed) => ({ ...ok, id, sealed: { ...ok.sealed, ...sealed } });
  const cases = [
    [noBox, /^sealed is required/],
    [{ ...ok, id: 'box-null', sealed: null }, /^sealed is required/],
    [{ ...ok, id: 'box-string', sealed: 'abc' }, /^sealed must be an object/],
    [b('box-big', { ct: 'A'.repeat(360_004) }), /^sealed\.ct may be at most 360000 characters/],
    [b('box-v', { v: 2 }), /^sealed\.v must be 1/],
    [b('box-alg', { alg: 'A128GCM' }), /^sealed\.alg must be "A256GCM"/],
    [b('box-kid-case', { kid: ok.sealed.kid.toUpperCase() }), /^sealed\.kid must be 16 lowercase hexadecimal/],
    [b('box-kid-short', { kid: ok.sealed.kid.slice(1) }), /^sealed\.kid must be 16/],
    [b('box-iv', { iv: ok.sealed.iv.slice(1) }), /^sealed\.iv must be 16 base64url characters/],
    [b('box-ct-pad', { ct: `${ok.sealed.ct}==` }), /^sealed\.ct must be base64url/],
    [b('box-ct-plus', { ct: ok.sealed.ct.replace(/^./, '+') }), /^sealed\.ct must be base64url/],
    [b('box-ct-short', { ct: 'AAAA' }), /^sealed\.ct is too short/],
    [b('box-extra', { aad: 'x' }), /^sealed\.aad is not part of a sealed box/],
    [{ ...ok, id: 'fp-upper', recordFingerprint: ok.recordFingerprint.toUpperCase() }, /^recordFingerprint must be 64 lowercase hex/],
    [{ ...ok, id: 'kb-short', keyBinding: 'ab' }, /^keyBinding must be 64 lowercase hex/],
    [{ ...ok, id: 'has spaces' }, /^id must be 1-128/],
    [{ ...ok, id: 'sup-reason', supersedes: { recordId: 'X', reason: 'why' } }, /^supersedes\.reason is not stored in the clear/],
  ];
  const r = await put(holder, [ok, ...cases.map(([row]) => row)]);
  assert.equal(r.json.count, 1, JSON.stringify(r.json));
  for (const [row, reason] of cases) {
    const rej = r.json.rejected.find((x) => x.id === row.id);
    assert.ok(rej, `${row.id} refused`);
    assert.match(rej.reason, reason, row.id);
  }
  // A name in the clear, whatever its value (round 5, CONTRACT.md #28): the whole save is
  // refused, and nothing in it is stored.
  for (const strainName of ['Visible Name', '', 7, null]) {
    const n = await put(holder, [{ ...ok, id: 'name-clear-ok' }, { ...ok, id: 'name-clear', strainName }]);
    assert.equal(n.status, 400, JSON.stringify(strainName));
    assert.deepEqual(n.json, { error: 'strainName belongs inside sealed' });
  }
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM records WHERE id LIKE 'name-clear%'").get().n, 0);
  // A whole record over 384 KiB is refused before anything else is looked at.
  const huge = b('box-huge', { ct: 'A'.repeat(400_000) });
  assert.match((await put(holder, [huge])).json.rejected[0].reason, /^a record may be at most 393216 bytes/);
  // A box at the limit is fine.
  assert.equal((await put(holder, [b('box-at-limit', { ct: 'A'.repeat(360_000) })])).json.count, 1);
});

test('one vault key per holder: a row sealed under a different kid is refused, records and licences alike', async () => {
  const holder = key();
  const mine = vaultKeyFor(holder);
  const other = randomBytes(32);
  assert.notEqual(kidOf(mine), kidOf(other));
  // In one save, the first row sets it.
  const first = await put(holder, [sealForTest(await makeRecord('kid-1'), mine), sealForTest(await makeRecord('kid-2'), other)]);
  assert.equal(first.json.count, 1);
  assert.deepEqual(first.json.rejected, [{ id: 'kid-2', reason: "sealed with a different vault key than this holder's other records; nothing was changed" }]);
  // Later saves are held to it.
  const later = await put(holder, [sealForTest(await makeRecord('kid-3'), other)]);
  assert.equal(later.json.count, 0);
  assert.match(later.json.rejected[0].reason, /different vault key/);
  const lic = await call('PUT', '/api/licenses', holder, [sealForTest({ id: 'LIC-K', terms: 't' }, other, 'licenses')]);
  assert.equal(lic.json.count, 0);
  assert.match(lic.json.rejected[0].reason, /different vault key/);
  assert.equal((await call('PUT', '/api/licenses', holder, [sealForTest({ id: 'LIC-K', terms: 't' }, mine, 'licenses')])).json.count, 1);
  // Once every row under the old key is deleted (a lost vault, CONTRACT.md #11), a new one starts.
  const solo = key();
  await put(solo, [sealForTest(await makeRecord('kid-solo'), other)]);
  assert.deepEqual((await call('DELETE', '/api/records', solo, { ids: ['kid-solo'] })).json.removed, ['kid-solo']);
  assert.equal((await put(solo, [sealForTest(await makeRecord('kid-solo-2'), vaultKeyFor(solo))])).json.count, 1);
});

test('a write that drops sealed is refused, and the sealed row stays as it was', async () => {
  const holder = key();
  const rec = await makeRecord('drop-1');
  const row = sealedFor(holder, rec);
  assert.equal((await put(holder, [row])).json.count, 1);
  const stored = () => db.prepare('SELECT body FROM records WHERE id = ?').get('drop-1').body;
  const before = stored();
  const { sealed: _s, ...bare } = row;
  void _s;
  for (const attempt of [bare, { ...bare, notes: 'now in the clear' }]) {
    const r = await put(holder, [attempt]);
    assert.equal(r.json.count, 0);
    assert.equal(r.json.rejected.length, 1);
  }
  // The record in plain text names itself in the clear: refused whole (round 5).
  assert.equal((await put(holder, [rec])).status, 400);
  assert.equal(stored(), before);
  // What is stored is what was sent: the box byte for byte, and the public fields.
  assert.deepEqual(JSON.parse(before), row);
  assert.deepEqual(openForTest((await call('GET', '/api/records', holder)).json[0], vaultKeyFor(holder)), rec);
});

test('first writer, supersede ownership and attestation preservation still hold; received fields are the registry\'s', async () => {
  const a = key(), b = key();
  const rec = await makeRecord('own-a');
  assert.equal((await put(a, [sealedFor(a, rec)])).json.count, 1);

  // Another holder, the same fingerprint under another id: refused.
  const copy = await put(b, [sealedFor(b, { ...rec, id: 'own-b-copy' })]);
  assert.equal(copy.json.count, 0);
  assert.match(copy.json.rejected[0].reason, /already registered by another holder/);
  // Pointers at another holder's record, either way: refused.
  const by = await put(b, [sealedFor(b, { ...(await makeRecord('own-b-1')), supersededBy: 'own-a' })]);
  assert.match(by.json.rejected[0].reason, /supersededBy names a record that belongs to another holder/);
  const of = await put(b, [sealedFor(b, { ...(await makeRecord('own-b-2')), supersedes: { recordId: 'own-a', changedFields: ['notes'] } })]);
  assert.match(of.json.rejected[0].reason, /supersedes names a record that belongs to another holder/);
  // The same id: not written, and said so.
  const squat = await put(b, [sealedFor(b, await makeRecord('own-a'))]);
  assert.deepEqual(squat.json.notWritten, ['own-a']);

  // A client's attestation and received-record fields are not stored.
  const typed = { ...sealedFor(a, await makeRecord('own-typed')), attestation: { type: 'receipt-confirmed' },
    receivedFrom: 'VEIL-ELSEWHERE', receivedFromCommitment: 'ef'.repeat(32), receivedAt: 1, transferId: 'TR-FAKE' };
  assert.equal((await put(a, [typed])).json.count, 1);
  const storedTyped = JSON.parse(db.prepare("SELECT body FROM records WHERE id = 'own-typed'").get().body);
  for (const f of ['attestation', 'receivedFrom', 'receivedFromCommitment', 'receivedAt', 'transferId']) assert.equal(storedTyped[f], undefined, f);

  // A claim's attestation survives a re-save from a stale copy and a forged one.
  const offerKey = randomBytes(32);
  const o = await call('POST', '/transfers', a, {
    sourceRecord: 'own-a', toHandle: LAB_TAG, sealedOffer: sealOfferForTest(offerFromRecord(rec), offerKey, rec.id, rec.recordFingerprint),
  });
  const lab = key();
  assert.equal((await call('POST', `/transfers/${o.json.transferId}/claim`, lab, { claimCode: o.json.claimCode })).status, 200);
  const att = JSON.parse(db.prepare("SELECT body FROM records WHERE id = 'own-a'").get().body).attestation;
  assert.equal(att.type, 'receipt-confirmed');
  await put(a, [sealedFor(a, rec)]);
  await put(a, [{ ...sealedFor(a, rec), attestation: { type: 'receipt-confirmed', addressedTo: 'someone-else' } }]);
  assert.deepEqual(JSON.parse(db.prepare("SELECT body FROM records WHERE id = 'own-a'").get().body).attestation, att);
});

// ---------------------------------------------------------------------------------------
// Public answers come from grant values only (CONTRACT.md #7)
// ---------------------------------------------------------------------------------------

const verify = async (id, q = '') => (await call('GET', `/verify/${id}${q}`)).json;
const embed = async (id) => (await call('GET', `/embed/${id}`)).text;
const publicRecord = async (id) => (await call('GET', `/records/${id}`)).json;

test('/verify, /embed and /records/:id answer only the grant\'s values, never the record\'s', async () => {
  const holder = key();
  const rec = await makeRecord('pub-1', { dnaFingerprint: 'ab'.repeat(32), dnaFileSha256: 'cd'.repeat(32), strainName: 'Sealed Name' });
  await put(holder, [sealedFor(holder, rec)]);
  // Values chosen by the holder, deliberately unlike what is sealed, so an answer read from
  // the record (if anything could) would show.
  const grant = {
    show: ['existence', 'attestation-status', 'sealed-at', 'parent-names', 'breeding-method', 'name'],
    forFingerprint: rec.recordFingerprint,
    values: { loggedAt: '2020-02-02T00:00:00Z', parents: [{ name: 'Published Mother', recordId: 'VEIL-HIDDEN' }],
      breedingMethod: 'published method', dnaPairBinding: '33'.repeat(32), name: 'Published Name' },
  };
  // The DNA report's plain values are never taken (round 5, CONTRACT.md #29).
  for (const plainValue of [{ dnaFileSha256: '22'.repeat(32) }, { dnaFingerprint: '11'.repeat(32) }]) {
    const refused = await call('PUT', `/api/records/${rec.id}/disclosure`, holder, { ...grant, values: { ...grant.values, ...plainValue } });
    assert.equal(refused.status, 400);
    assert.match(refused.json.error, /is no longer published: send dnaPairBinding/);
  }
  const g = await call('PUT', `/api/records/${rec.id}/disclosure`, holder, grant);
  assert.equal(g.status, 200, JSON.stringify(g.json));
  assert.equal(g.json.forFingerprint, rec.recordFingerprint);
  assert.deepEqual(g.json.values.parents, [{ name: 'Published Mother' }], 'a parent\'s record id is dropped');

  const v = await verify(rec.id);
  assert.deepEqual(v.parents, ['Published Mother']);
  assert.equal(v.breedingMethod, 'published method');
  assert.equal(v.sealedAt, '2020-02-02T00:00:00Z');
  assert.equal(v.loggedAtClaimedByHolder, '2020-02-02T00:00:00Z');
  assert.equal(v.dnaPairedByHolder, true);
  assert.equal(v.dnaPairBinding, '33'.repeat(32));
  assert.equal(v.dnaPairingFingerprint, undefined);
  assert.equal(v.dnaFileSha256, undefined);
  // The name only as the holder published it, never the sealed one.
  assert.equal(v.cultivar, 'Published Name');
  assert.equal((await publicRecord(rec.id)).cultivar, 'Published Name');
  assert.match(await embed(rec.id), /vc-title">Published Name</);
  assert.equal(v.unalteredSinceRegistryFirstSeen, true);
  assert.equal(v.fingerprintCheckedByRegistry, false, 'the registry says it did not check the fingerprint against the contents');
  assert.equal(v.staleGrant, undefined);
  assert.deepEqual(v.disclosed, ['own', 'dna', 'sealed', 'parents', 'method', 'name']);
  const text = JSON.stringify(v);
  for (const s of ['Secret Mother', 'secret method', 'VEIL-HIDDEN', 'VEIL-PARENT', '2021-03-01', 'ab'.repeat(32), 'cd'.repeat(32), 'Sealed Name']) assert.ok(!text.includes(s), s);
  assert.equal((await publicRecord(rec.id)).loggedAtClaimedByHolder, '2020-02-02T00:00:00Z');
  assert.match(await embed(rec.id), /Date stated by the holder: 2020-02-02/);

  // The holder reads their grant back, with what it publishes.
  const mine = (await call('GET', `/api/records/${rec.id}/disclosure`, holder)).json;
  assert.equal(mine.forFingerprint, rec.recordFingerprint);
  assert.equal(mine.values.breedingMethod, 'published method');
});

test('stale grant values are not answered: the key is listed under staleGrant until the holder sends them again', async () => {
  const holder = key();
  const rec = await makeRecord('stale-1');
  await put(holder, [sealedFor(holder, rec)]);
  await call('PUT', `/api/records/${rec.id}/disclosure`, holder, grantForTest(rec, ['existence', 'sealed-at', 'parent-names', 'breeding-method', 'attestation-status']));
  assert.deepEqual((await verify(rec.id)).parents, ['Secret Mother']);

  // The holder edits the record: a new fingerprint, so the values describe a record that is gone.
  const edited = await makeRecord('stale-1', { parents: [{ name: 'Different Mother' }], breedingMethod: 'changed' });
  assert.notEqual(edited.recordFingerprint, rec.recordFingerprint);
  await put(holder, [sealedFor(holder, edited)]);
  const v = await verify(rec.id);
  for (const f of ['parents', 'breedingMethod', 'sealedAt', 'loggedAtClaimedByHolder', 'dnaPairedByHolder']) assert.equal(v[f], undefined, f);
  assert.deepEqual(v.staleGrant, ['dna', 'sealed', 'parents', 'method']);
  assert.match(v.staleGrantReason, /changed since/);
  // Facts the registry holds itself do not go stale: existence, and the lab status (its
  // attestations and receipts). Only the DNA pairing under it, which the holder wrote, does.
  assert.deepEqual(v.disclosed, ['own', 'dna']);
  for (const f of ['dnaPairingFingerprint', 'dnaFileSha256']) assert.equal(v[f], undefined, f);
  assert.equal(typeof v.signedAttestation, 'boolean');
  assert.equal(v.unalteredSinceRegistryFirstSeen, true);
  assert.ok(!JSON.stringify(v).includes('Secret Mother'));
  // ?show= narrows staleGrant like everything else.
  assert.deepEqual((await verify(rec.id, '?show=own,parents')).staleGrant, ['parents']);
  const pub = await publicRecord(rec.id);
  assert.equal(pub.loggedAtClaimedByHolder, undefined);
  assert.deepEqual(pub.staleGrant, ['attestation-status', 'sealed-at', 'parent-names', 'breeding-method']);
  assert.doesNotMatch(await embed(rec.id), /Date stated by the holder/);

  // The browser lists its grants, sees the old fingerprint, and sends the grant again.
  const list = (await call('GET', '/api/disclosures', holder)).json;
  assert.deepEqual(list.map((x) => [x.recordId, x.forFingerprint]), [[rec.id, rec.recordFingerprint]]);
  assert.deepEqual(list[0].show, ['existence', 'attestation-status', 'sealed-at', 'parent-names', 'breeding-method']);
  assert.match(list[0].updatedAt, /^\d{4}-/);
  assert.notEqual(list[0].forFingerprint, edited.recordFingerprint);
  await call('PUT', `/api/records/${rec.id}/disclosure`, holder, grantForTest(edited, list[0].show));
  const again = await verify(rec.id);
  assert.deepEqual(again.parents, ['Different Mother']);
  assert.equal(again.staleGrant, undefined);
  assert.deepEqual((await call('GET', '/api/disclosures', holder)).json[0].forFingerprint, edited.recordFingerprint);

  // A grant sent without forFingerprint, as an older site sends one, answers no values.
  await call('PUT', `/api/records/${rec.id}/disclosure`, holder, { show: ['parent-names'] });
  assert.deepEqual((await verify(rec.id)).staleGrant, ['parents']);
});

test('grant values: only for granted keys, only known fields, within limits; GET /api/disclosures is the holder\'s own', async () => {
  const holder = key();
  const rec = await makeRecord('gv-1');
  await put(holder, [sealedFor(holder, rec)]);
  const send = (body) => call('PUT', `/api/records/${rec.id}/disclosure`, holder, { forFingerprint: rec.recordFingerprint, ...body });
  const refusals = [
    [{ show: ['existence'], values: { breedingMethod: 'm' } }, /values\.breedingMethod is accepted only with the breeding-method grant/],
    [{ show: ['parent-names'], values: { notes: 'n' } }, /values\.notes is not a value a grant publishes/],
    [{ show: ['parent-names'], values: { parents: [{ name: 'A', notes: 'x' }] } }, /values\.parents\[\]\.notes is not published/],
    [{ show: ['parent-names'], values: { parents: [{ role: 'sire' }] } }, /needs a name/],
    [{ show: ['parent-names'], values: { parents: 'A' } }, /values\.parents must be a list/],
    [{ show: ['breeding-method'], values: { breedingMethod: 'm'.repeat(5_001) } }, /at most 5000 characters/],
    [{ show: ['breeding-method'], values: { breedingMethod: 'm'.repeat(70_000) } }, /values may be at most 65536 bytes/],
    [{ show: ['sealed-at'], values: { loggedAt: { at: 1 } } }, /values\.loggedAt must be a string/],
    [{ show: ['sealed-at'], values: [] }, /values must be an object/],
    [{ show: ['sealed-at'], forFingerprint: 'AB'.repeat(32) }, /forFingerprint must be/],
  ];
  for (const [body, reason] of refusals) {
    const r = await send(body);
    assert.equal(r.status, 400, JSON.stringify(body).slice(0, 80));
    assert.match(r.json.error, reason);
  }
  assert.equal((await call('GET', `/api/records/${rec.id}/disclosure`, holder)).json.show.length, 0, 'nothing refused was stored');
  // Legacy grant names grant values too.
  assert.equal((await send({ show: ['method'], values: { breedingMethod: 'shown' } })).status, 200);
  assert.equal((await verify(rec.id)).breedingMethod, 'shown');
  // Another holder lists nothing of this one's.
  assert.deepEqual((await call('GET', '/api/disclosures', key())).json, []);
  assert.equal((await call('GET', '/api/disclosures')).status, 401);
});

// ---------------------------------------------------------------------------------------
// Legacy plaintext rows (CONTRACT.md #6): their holder gets them; the public, public fields
// ---------------------------------------------------------------------------------------

test('a legacy plaintext row is served whole to its own holder only; the public sees only public fields', async () => {
  const holder = key();
  const legacy = await makeRecord('legacy-1', { notes: 'LEGACY-NOTES', parents: [{ name: 'LEGACY-MOTHER' }], breedingMethod: 'LEGACY-METHOD' });
  db.prepare('INSERT INTO records (id, holder_key, body, updated_at, first_seen) VALUES (?,?,?,?,?)')
    .run(legacy.id, storedHolderKey(holder), JSON.stringify(legacy), 1, 1);
  // Its holder's browser reads it in full, to convert it.
  assert.deepEqual((await call('GET', '/api/records', holder)).json, [legacy]);
  assert.deepEqual((await call('GET', '/api/records', key())).json, []);
  // A grant made before values, asking for everything: nothing of the body is answered.
  db.prepare('INSERT INTO disclosure_grants (record_id, holder_key, show, updated_at) VALUES (?,?,?,?)')
    .run(legacy.id, storedHolderKey(holder), JSON.stringify(['existence', 'sealed-at', 'parent-names', 'breeding-method', 'attestation-status']), 1);
  for (const text of [JSON.stringify(await verify(legacy.id)), JSON.stringify(await publicRecord(legacy.id)), await embed(legacy.id)]) {
    for (const s of ['LEGACY-NOTES', 'LEGACY-MOTHER', 'LEGACY-METHOD', legacy.nonce, '2021-03-01']) assert.ok(!text.includes(s), s);
  }
  const v = await verify(legacy.id);
  assert.equal(v.cultivar, legacy.strainName);
  assert.equal(v.recordFingerprint, legacy.recordFingerprint);
  assert.deepEqual(v.staleGrant, ['dna', 'sealed', 'parents', 'method']);
  // Converted: the holder's browser saves it sealed.
  assert.equal((await put(holder, [sealedFor(holder, legacy)])).json.count, 1);
  const stored = JSON.parse(db.prepare('SELECT body FROM records WHERE id = ?').get(legacy.id).body);
  assert.ok(stored.sealed);
  assert.ok(!JSON.stringify(stored).includes('LEGACY-'));
});

// ---------------------------------------------------------------------------------------
// On disk: nothing a holder typed is in the database file
// ---------------------------------------------------------------------------------------

const child = fileURLToPath(new URL('./fixtures/sealed-server-child.mjs', import.meta.url));
const purge = fileURLToPath(new URL('../scripts/purge-plaintext.mjs', import.meta.url));

/** The registry on `file`, in its own process; `stop()` closes the database cleanly. */
const startOnFile = async (file) => {
  const proc = fork(child, [], { env: { ...process.env, DB_PATH: file }, stdio: ['ignore', 'pipe', 'pipe', 'ipc'] });
  let output = '';
  proc.stdout.on('data', (d) => { output += d; });
  proc.stderr.on('data', (d) => { output += d; });
  const { port } = await new Promise((ok, fail) => {
    const timer = setTimeout(() => { proc.kill('SIGKILL'); fail(new Error(`registry did not start in 30 s: ${output}`)); }, 30_000);
    proc.once('message', (m) => { clearTimeout(timer); ok(m); });
    proc.once('exit', (code) => { clearTimeout(timer); fail(new Error(`registry exited (${code}) before listening: ${output}`)); });
  });
  const at = `http://127.0.0.1:${port}`;
  await untilReady(at);
  return {
    call: callAt(() => at),
    output: () => output,
    // A child that doesn't close in 15 s is killed, so a failure inside it ends the test
    // instead of leaving it, and anything waiting on it, hung.
    stop: () => new Promise((ok, fail) => {
      const timer = setTimeout(() => { proc.kill('SIGKILL'); fail(new Error(`registry did not close: ${output}`)); }, 15_000);
      proc.once('exit', () => { clearTimeout(timer); ok(output); });
      proc.send('close');
    }),
  };
};

/** Every byte the database leaves on disk: the file, and any journal or WAL beside it. */
const diskBytes = (file) => ['', '-wal', '-journal', '-shm']
  .filter((s) => existsSync(file + s))
  .map((s) => readFileSync(file + s).toString('latin1'))
  .join('\n');
const assertAbsent = (bytes, sentinels, when) => {
  for (const [name, s] of Object.entries(sentinels)) assert.equal(bytes.includes(s), false, `${name} is in the database file ${when}`);
};
const sentinelsFor = (tag) => {
  const u = (f) => `SNTL-${tag}-${f}-${randomBytes(6).toString('hex')}`;
  return {
    bredBy: u('bredBy'), notes: u('notes'), parentName: u('parent'), parentRecordId: u('parentId'), breedingMethod: u('method'),
    refId: u('refId'), dnaFileName: u('dnaFile'), taxon: u('taxon'), licenceTerms: u('terms'), licenceParty: u('party'), name: u('name'),
    offerBredBy: u('offerBredBy'), offerNote: u('offerNote'), offerQuantity: u('offerQty'), supersedeReason: u('reason'),
  };
};
const sentinelRecord = async (id, s) => {
  const r = await makeRecord(id, {
    strainName: s.name, bredBy: s.bredBy, notes: s.notes, parents: [{ name: s.parentName, recordId: s.parentRecordId }], breedingMethod: s.breedingMethod,
    refId: s.refId, taxon: s.taxon,
  });
  r.dnaFileName = s.dnaFileName;
  r.dnaFingerprint = 'ab'.repeat(32);
  return r;
};

test('on disk: after saving, converting a legacy row, and purging, nothing a holder typed is in the database file', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'veilcore-sealed-'));
  const file = join(dir, 'veilcore.db');
  try {
    const holder = key();
    const lab = key();
    const vault = vaultKeyFor(holder);

    // 1. A sealed save: records, licences, a correction, a grant, a sealed offer claimed and
    // the lab's own sealed record.
    const A = sentinelsFor('save');
    let reg = await startOnFile(file);
    const rec = await sentinelRecord('DISK-1', A);
    const correction = { ...(await sentinelRecord('DISK-2', A)), supersedes: { recordId: 'DISK-1', changedFields: ['notes'], reason: A.supersedeReason } };
    let r = await reg.call('PUT', '/api/records', holder, [sealForTest({ ...rec, supersededBy: 'DISK-2' }, vault), sealForTest(correction, vault)]);
    assert.equal(r.json.count, 2, JSON.stringify(r.json));
    r = await reg.call('PUT', '/api/licenses', holder, [sealForTest({ id: 'DISK-LIC', recordId: 'DISK-1', terms: A.licenceTerms, licensee: A.licenceParty }, vault, 'licenses')]);
    assert.equal(r.json.count, 1);
    assert.equal((await reg.call('PUT', '/api/records/DISK-1/disclosure', holder, grantForTest(rec, ['existence']))).status, 200);
    const offerKey = randomBytes(32);
    const offer = { ...offerFromRecord(rec), bredBy: A.offerBredBy, note: A.offerNote, quantity: A.offerQuantity };
    const o = await reg.call('POST', '/transfers', holder, { sourceRecord: rec.id, toHandle: LAB_TAG, sealedOffer: sealOfferForTest(offer, offerKey, rec.id, rec.recordFingerprint) });
    assert.equal(o.status, 200, JSON.stringify(o.json));
    const c = await reg.call('POST', `/transfers/${o.json.transferId}/claim`, lab, { claimCode: o.json.claimCode });
    assert.equal(c.status, 200, JSON.stringify(c.json));
    const opened = openOfferForTest(c.json.offerSealed, offerKey, rec.id, rec.recordFingerprint);
    const received = { id: c.json.recordId, strainName: opened.strainName, bredBy: opened.bredBy, dateCreated: opened.dateCreated,
      notes: opened.note, loggedAt: 1, nonce: newNonce(), parents: [], photoFingerprints: [], breedingMethod: '', refId: '', quantity: opened.quantity };
    received.recordFingerprint = await sha256Hex(canonicalise(committedOf(received)));
    assert.equal((await reg.call('PUT', '/api/records', lab, [sealForTest(received, vaultKeyFor(lab))])).json.count, 1);
    // The holder reads it all back, and opens it.
    const back = (await reg.call('GET', '/api/records', holder)).json.find((x) => x.id === 'DISK-1');
    assert.equal(openForTest(back, vault).notes, A.notes);
    let log = await reg.stop();
    let bytes = diskBytes(file);
    assert.ok(bytes.includes(rec.recordFingerprint), 'the public fields are there: the right file was read');
    assert.ok(!bytes.includes(rec.strainName), 'the name is sealed (round 5)');
    assertAbsent(bytes, { ...A, nonce: rec.nonce, labNonce: received.nonce }, 'after a sealed save');
    // Nor in anything the registry printed, nor any key.
    assertAbsent(log, { ...A, holder, lab, vault: vault.toString('hex'), offerKey: offerKey.toString('hex') }, 'in the log');

    // 2. A legacy plaintext row, as older code wrote it, then converted by its holder.
    const B = sentinelsFor('legacy');
    const legacy = await sentinelRecord('DISK-LEGACY', B);
    {
      const raw = new Database(file);
      raw.prepare('INSERT INTO records (id, holder_key, body, updated_at, first_seen) VALUES (?,?,?,?,?)')
        .run(legacy.id, storedHolderKey(holder), JSON.stringify(legacy), 1, 1);
      raw.close();
    }
    assert.ok(diskBytes(file).includes(B.notes), 'control: a plaintext row is visible in the bytes');
    reg = await startOnFile(file);
    const served = (await reg.call('GET', '/api/records', holder)).json.find((x) => x.id === legacy.id);
    assert.equal(served.notes, B.notes, 'served whole to its own holder, so the browser can convert it');
    assert.ok(!JSON.stringify((await reg.call('GET', `/verify/${legacy.id}`)).json).includes(B.notes));
    assert.equal((await reg.call('PUT', '/api/records', holder, [sealForTest(legacy, vault)])).json.count, 1);
    log = await reg.stop();
    bytes = diskBytes(file);
    assertAbsent(bytes, { ...A, ...B, nonce: legacy.nonce }, 'after the legacy row was converted');
    assertAbsent(log, B, 'in the log');

    // 3. The purge, with its guard (CONTRACT.md #24). `holder` is converted (has sealed rows);
    // one of their records is still plain (their app could not convert it): it is reported,
    // never stripped. `other` never opened the sealing site: skipped, unless both flags are
    // given. Older rows also carry what round 2 removes: a lab name a holder typed into an
    // attestation, the recipient's handle an older claim wrote, a handle stored as typed.
    const other = key();
    const C = sentinelsFor('purge'); // the unconverted holder's
    const D = sentinelsFor('stuck'); // the converted holder's row that stays plain
    const HANDLE = `sntl-${randomBytes(6).toString('hex')}@lab.example`;
    const LAB_NAME = `SNTL-labname-${randomBytes(6).toString('hex')}`;
    const OLD_NAME = `SNTL-oldname-${randomBytes(6).toString('hex')}`;
    const left = await sentinelRecord('DISK-LEFT', C);
    const stuck = await sentinelRecord('DISK-STUCK', D);
    {
      const raw = new Database(file);
      const hk = storedHolderKey(holder);
      const ok = storedHolderKey(other);
      raw.prepare('INSERT INTO records (id, holder_key, body, updated_at, first_seen) VALUES (?,?,?,?,?)')
        .run(left.id, ok, JSON.stringify({ ...left, supersedes: { recordId: 'DISK-1', reason: C.supersedeReason } }), 1, 1);
      raw.prepare('INSERT INTO records (id, holder_key, body, updated_at, first_seen) VALUES (?,?,?,?,?)')
        .run(stuck.id, hk, JSON.stringify({ ...stuck, attestation: { type: 'receipt-confirmed', addressedTo: HANDLE, lab: D.licenceParty, attestedAt: 1 } }), 1, 1);
      // The converted holder's sealed record, as older code left it: a holder-typed lab name
      // and the addressed handle in its attestation (attack review P2, P3).
      raw.prepare("UPDATE records SET body = json_set(body, '$.attestation.lab', ?, '$.attestation.addressedTo', ?) WHERE id = 'DISK-1'").run(LAB_NAME, HANDLE);
      // A sealed row as a site before round 5 saved it: the name in the clear beside the box.
      raw.prepare("UPDATE records SET body = json_set(body, '$.strainName', ?) WHERE id = 'DISK-2'").run(OLD_NAME);
      raw.prepare('INSERT INTO licenses (id, holder_key, record_id, body, updated_at) VALUES (?,?,?,?,?)')
        .run('DISK-LIC-OLD', ok, left.id, JSON.stringify({ id: 'DISK-LIC-OLD', recordId: left.id, terms: C.licenceTerms }), 1);
      const tr = raw.prepare(`INSERT INTO transfers (id, source_record, from_holder, to_handle, claim_code, created_at, quantity, note)
                              VALUES (?,?,?,?,?,?,?,?)`);
      tr.run('TR-OLDNOTE', 'DISK-1', hk, HANDLE, 'c'.repeat(32), 1, D.offerQuantity, D.offerNote);
      tr.run('TR-OTHERNOTE', left.id, ok, 'other@lab', 'c'.repeat(32), 1, C.offerQuantity, C.offerNote);
      const g = raw.prepare('INSERT INTO disclosure_grants (record_id, holder_key, show, updated_at) VALUES (?,?,?,?)');
      g.run('DISK-2', hk, '["existence","parent-names"]', 1);
      g.run(left.id, ok, '["parent-names"]', 1);
      raw.close();
    }
    const run = (...flags) => execFileSync(process.execPath, [purge, '--db', file, ...flags], { encoding: 'utf8' });
    const label = (k) => storedHolderKey(k).replace(/^h1:/, '').slice(0, 12);
    const beforeDry = createHash('sha256').update(readFileSync(file)).digest('hex');
    const dry = run();
    assert.match(dry, /dry run, nothing changed/);
    assert.match(dry, /holders: 2 converted/); // the holder, and the lab that sealed its received record
    // Sealed: DISK-1, DISK-2, DISK-LEGACY (converted) and the lab's record (its stub replaced).
    assert.match(dry, /records: 4 sealed, 0 with public fields only, 0 to reduce to public fields, 1 still plain under converted holders \(reported, not stripped\), 1 of holders not yet converted \(skipped\)/);
    assert.match(dry, /sealed records: 1 whose clear fields are to be cut/);
    // DISK-2's old clear name is the only copy of it (its box was sealed before names went
    // inside): reported, never removed by the guarded run (round 6, the fifth review's finding
    // 8). Only the two-flag run removes it. The unconverted holder's plain row keeps its own.
    assert.match(dry, /record names in the clear: 1 on sealed rows locked before names went inside the lock \(reported, not removed/);
    assert.doesNotMatch(dry, /or backup/);
    assert.match(dry, /licences: 1 sealed, 0 to empty, 0 still plain under converted holders \(reported, not stripped\), 1 of holders not yet converted \(skipped\)/);
    assert.match(dry, /transfers: 1 with a plain-text quantity or note, to empty, 2 recipient handles stored as typed, to replace with random values \(for every sender, converted or not\), 1 quantities or notes of senders not yet converted \(skipped\)/);
    assert.match(dry, /disclosure grants without values: 1 keys that publish values to drop, 0 grants left with no keys to drop \(existence and descent-clean are kept\), 0 on records still in plain text \(skipped: the app converts them with their values\), 1 of holders not yet converted \(skipped\)/);
    // Which holders: named by the start of their stored digest, never a key.
    assert.match(dry, new RegExp(`converted holders with rows still in plain text[^\\n]*\\n  holder ${label(holder)}: 1 records, 0 licences`));
    assert.match(dry, new RegExp(`holders not yet converted \\(skipped; nothing of theirs is changed except recipient names typed before tags, which are replaced\\):\\n  holder ${label(other)}: 1 records, 1 licences`));
    assertAbsent(dry, { ...C, ...D, id: left.id, holder, other, lab, HANDLE, LAB_NAME, OLD_NAME }, 'in what the purge prints');
    assert.equal(createHash('sha256').update(readFileSync(file)).digest('hex'), beforeDry, 'a dry run changes nothing');
    assert.ok(diskBytes(file).includes(C.notes) && diskBytes(file).includes(LAB_NAME), 'control: visible before the purge');

    // One of the two flags alone: refused, nothing changed.
    assert.throws(() => execFileSync(process.execPath, [purge, '--db', file, '--apply', '--include-unconverted'], { stdio: 'pipe' }), /i-understand-this-deletes-text/);
    assert.equal(createHash('sha256').update(readFileSync(file)).digest('hex'), beforeDry);

    // --apply: the converted holder is cleaned; the stuck row keeps its text; `other` is untouched.
    assert.match(run('--apply'), /^applied:/);
    let disk = diskBytes(file);
    assertAbsent(disk, { ...A, ...B, HANDLE, LAB_NAME, offerNote: D.offerNote, offerQuantity: D.offerQuantity }, 'after --apply');
    assert.ok(disk.includes(OLD_NAME), 'the only copy of a name locked before names went inside the lock is kept by the guarded run');
    assert.ok(disk.includes(C.name), 'an unconverted holder\'s plain row keeps its name');
    assert.ok(disk.includes(D.notes) && disk.includes(D.licenceParty), 'a converted holder\'s row that is still plain is reported, not stripped');
    assert.ok(disk.includes(C.notes) && disk.includes(C.licenceTerms) && disk.includes(C.offerNote), 'an unconverted holder is skipped');
    {
      const raw = new Database(file, { readonly: true });
      const body = (id) => JSON.parse(raw.prepare('SELECT body FROM records WHERE id = ?').get(id).body);
      assert.deepEqual(Object.keys(body('DISK-1').attestation).sort(), ['attestedAt', 'attesterKey', 'confirms', 'transferId', 'type']);
      assert.deepEqual(body('DISK-STUCK').attestation, { type: 'receipt-confirmed', lab: D.licenceParty, attestedAt: 1 });
      const t = raw.prepare("SELECT to_handle, quantity, note FROM transfers WHERE id = 'TR-OLDNOTE'").get();
      assert.deepEqual({ ...t, to_handle: undefined }, { to_handle: undefined, quantity: null, note: null });
      assert.match(t.to_handle, /^[0-9a-f]{64}$/, 'the handle is replaced with a tag-shaped value');
      assert.notEqual(t.to_handle, createHash('sha256').update(`veilcore:legacy-handle:v1\0${HANDLE}`).digest('hex'), 'not a hash of it (round 3, P6)');
      // A recipient's name is replaced for every sender, converted or not (round 4, F6); the
      // unconverted sender's own quantity and note stay.
      const other = raw.prepare("SELECT to_handle, quantity, note FROM transfers WHERE id = 'TR-OTHERNOTE'").get();
      assert.match(other.to_handle, /^[0-9a-f]{64}$/);
      assert.deepEqual([other.quantity, other.note], [C.offerQuantity, C.offerNote]);
      assert.equal(raw.prepare("SELECT show FROM disclosure_grants WHERE record_id = 'DISK-2'").get().show, '["existence"]', 'existence needs no values: kept');
      assert.ok(raw.prepare('SELECT 1 FROM disclosure_grants WHERE record_id = ?').get(left.id), 'an unconverted holder\'s grant is kept');
      raw.close();
    }

    // Both flags: the unconverted holder's plain rows go too.
    const all = run('--apply', '--include-unconverted', '--i-understand-this-deletes-text');
    assert.match(all, /1 reduced to public fields/);
    assert.match(all, /holders not yet converted, whose plain rows were stripped/);
    disk = diskBytes(file);
    assertAbsent(disk, { ...A, ...B, ...C, nonce: left.nonce, HANDLE, LAB_NAME, OLD_NAME }, 'after the purge with both flags');
    assert.ok(disk.includes(D.notes), 'still: a converted holder\'s plain row is never stripped');
    // Run again: nothing left to do.
    assert.match(run(), /records: 4 sealed, 1 with public fields only, 0 to reduce to public fields, 1 still plain under converted holders/);

    // What is left of a purged row: its public fields, and a mark saying what happened.
    reg = await startOnFile(file);
    assert.deepEqual((await reg.call('GET', '/api/records', other)).json.find((x) => x.id === left.id), {
      id: left.id, recordFingerprint: left.recordFingerprint, supersedes: { recordId: 'DISK-1' }, contentsRemoved: true,
    });
    assert.deepEqual((await reg.call('GET', '/api/licenses', other)).json.find((x) => x.id === 'DISK-LIC-OLD'), { id: 'DISK-LIC-OLD', contentsRemoved: true });
    const mine = (await reg.call('GET', '/api/records', holder)).json;
    assert.equal(openForTest(mine.find((x) => x.id === 'DISK-1'), vault).notes, A.notes, 'sealed rows still open');
    assert.deepEqual((await reg.call('GET', '/api/disclosures', holder)).json.map((g) => [g.recordId, g.show]), [['DISK-1', ['existence']], ['DISK-2', ['existence']]]);
    assert.deepEqual((await reg.call('GET', '/api/disclosures', other)).json, [], 'its grant had only keys that need values');
    await reg.stop();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
