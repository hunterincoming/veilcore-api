// Attack review 4 (17 Oct 2026), the registry's part. Each test is ported from the proof
// that showed the problem (scratchpad attack4/poc), turned round: it failed before the fix.
//
//   F1  changes to agreements were silently lost: PUT /api/licenses had no rev check, so two
//       tabs or devices replaced each other's changes (a revocation undone by a royalty
//       entry). Licences now carry the same public `rev` and "older copy" refusal as records.
//   F3  the embed said "Record exists and its commitment matches its contents." for any
//       random box stored under any fingerprint. It now says what /verify says.
//   F6  the default purge left recipient names typed before tags (transfers.to_handle and
//       the sender's `addressedTo`) for senders who had not converted. Now always replaced.
//   F10 the export note: it lists what the export leaves out and where those live.
//   F11 an `_sc2_` receipt was answered `signedOverSampleDetails: true`, unchecked. Now the
//       answer says the receipt names sample details and the holder's app can check them
//       (test/custody-sealed.test.mjs covers the public answers).
// SPDX-License-Identifier: Apache-2.0

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import Database from 'better-sqlite3';
import { untilReady, vaultKeyFor, sealForTest, openForTest } from './helpers.mjs';

process.env.DB_PATH = ':memory:';
process.env.VEILCORE_OTS = 'off';
const require = createRequire(import.meta.url);
const { app } = require('../server.js');

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
  return { status: res.status, json, text };
};

// ---- F1: agreements refuse an older copy, as records do ------------------------------------

/** A licence row as the round 4 site sends it: `rev` inside the box and beside it. */
const licenceRow = (holder, licence, rev) => {
  const row = sealForTest({ ...licence, ...(rev === undefined ? {} : { rev }) }, vaultKeyFor(holder), 'licenses');
  return rev === undefined ? row : { ...row, rev };
};
const putLicences = (holder, rows) => call('PUT', '/api/licenses', holder, rows);
const storedLicence = async (holder, id) =>
  (await call('GET', '/api/licenses', holder)).json.find((r) => r.id === id);

test('F1 (two devices): the second device\'s change from the same copy is refused as an older copy; the first change stays', async () => {
  const holder = key();
  const id = `LIC-${randomBytes(16).toString('hex').toUpperCase()}`;
  const lic = { id, type: 'license', state: 'active', terms: { licensee: 'Licensee Co' }, royaltyLog: [] };
  assert.equal((await putLicences(holder, [licenceRow(holder, lic, 1)])).json.ok, true);
  // Device A logs a payment: rev 2.
  const a = { ...lic, royaltyLog: [{ note: 'PAYMENT-FROM-DEVICE-A' }] };
  assert.equal((await putLicences(holder, [licenceRow(holder, a, 2)])).json.ok, true);
  // Device B, still on rev 1, logs another: also rev 2, another box. Refused, by id.
  const b = { ...lic, royaltyLog: [{ note: 'PAYMENT-FROM-DEVICE-B' }] };
  const out = await putLicences(holder, [licenceRow(holder, b, 2)]);
  assert.equal(out.status, 200);
  assert.equal(out.json.ok, false);
  assert.deepEqual(
    { id: out.json.rejected[0].id, code: out.json.rejected[0].code, status: out.json.rejected[0].status, storedRev: out.json.rejected[0].storedRev },
    { id, code: 'older-copy', status: 409, storedRev: 2 },
  );
  assert.match(out.json.rejected[0].reason, /another copy at rev 2 of this license/);
  const row = await storedLicence(holder, id);
  assert.equal(row.rev, 2, 'the holder reads the rev back');
  const opened = JSON.stringify(openForTest(row, vaultKeyFor(holder), 'licenses'));
  assert.match(opened, /PAYMENT-FROM-DEVICE-A/);
  assert.doesNotMatch(opened, /PAYMENT-FROM-DEVICE-B/);
});

test('F1 (two tabs): a revocation is not undone by a stale tab\'s royalty entry', async () => {
  const holder = key();
  const id = `LIC-${randomBytes(16).toString('hex').toUpperCase()}`;
  const lic = { id, type: 'license', state: 'active', terms: { licensee: 'L' }, royaltyLog: [] };
  assert.equal((await putLicences(holder, [licenceRow(holder, lic, 3)])).json.ok, true);
  assert.equal((await putLicences(holder, [licenceRow(holder, { ...lic, state: 'revoked', revokedReason: 'REVOKED-IN-TAB-A' }, 4)])).json.ok, true);
  // A lower rev, and no rev at all, are older copies too.
  const lower = await putLicences(holder, [licenceRow(holder, { ...lic, royaltyLog: [{ note: 'ROYALTY-IN-TAB-B' }] }, 3)]);
  assert.match(lower.json.rejected[0].reason, /holds rev 4 of this license and this save is rev 3/);
  const none = await putLicences(holder, [licenceRow(holder, { ...lic, royaltyLog: [{ note: 'ROYALTY-IN-TAB-B' }] })]);
  assert.match(none.json.rejected[0].reason, /this save is without a rev/);
  const opened = JSON.stringify(openForTest(await storedLicence(holder, id), vaultKeyFor(holder), 'licenses'));
  assert.match(opened, /REVOKED-IN-TAB-A/);
  assert.doesNotMatch(opened, /ROYALTY-IN-TAB-B/);
});

test('F1: the very same box again is taken (one request sent twice); other rows of a save are not held up; a bad rev is refused', async () => {
  const holder = key();
  const one = `LIC-${randomBytes(16).toString('hex').toUpperCase()}`;
  const two = `LIC-${randomBytes(16).toString('hex').toUpperCase()}`;
  const row = licenceRow(holder, { id: one, type: 'license', terms: {} }, 5);
  assert.equal((await putLicences(holder, [row])).json.ok, true);
  assert.equal((await putLicences(holder, [row])).json.ok, true, 'the same request again');
  const both = await putLicences(holder, [licenceRow(holder, { id: one, type: 'license', terms: { x: 1 } }, 4), licenceRow(holder, { id: two, type: 'license', terms: {} }, 1)]);
  assert.deepEqual(both.json.rejected.map((r) => [r.id, r.code]), [[one, 'older-copy']]);
  assert.equal((await storedLicence(holder, two)).rev, 1);
  const bad = await putLicences(holder, [{ ...licenceRow(holder, { id: two, type: 'license', terms: {} }), rev: -1 }]);
  assert.match(bad.json.rejected[0].reason, /rev must be a whole number from 0 up/);
  // Rows without a rev save as before until one is stored with a rev.
  const fresh = `LIC-${randomBytes(16).toString('hex').toUpperCase()}`;
  assert.equal((await putLicences(holder, [licenceRow(holder, { id: fresh, type: 'license', terms: {} })])).json.ok, true);
  assert.equal((await putLicences(holder, [licenceRow(holder, { id: fresh, type: 'license', terms: { y: 1 } })])).json.ok, true);
});

test('F1: /health lists license-rev-v1, beside record-rev-v1', async () => {
  const h = (await call('GET', '/health')).json;
  assert.ok(h.features.includes('license-rev-v1'));
  assert.ok(h.features.includes('record-rev-v1'));
});

// ---- F3: the embed no longer vouches for contents it can't read ------------------------------

test('F3: a random box under a random fingerprint: the embed says the registry can\'t check its contents, the holder\'s app does', async () => {
  const hk = key();
  const id = `VEIL-${randomBytes(16).toString('hex').toUpperCase()}`;
  const row = {
    id, recordFingerprint: randomBytes(32).toString('hex'),
    sealed: { v: 1, alg: 'A256GCM', kid: randomBytes(8).toString('hex'), iv: randomBytes(12).toString('base64url'), ct: randomBytes(40).toString('base64url') },
  };
  assert.equal((await call('PUT', '/api/records', hk, [row])).status, 200);
  const html = await (await fetch(`${base}/embed/${id}`)).text();
  const facts = [...html.matchAll(/<div class="vc-fact">([^<]*)<\/div>/g)].map((m) => m[1]);
  assert.ok(!facts.some((f) => /matches its contents/.test(f)), facts.join(' | '));
  assert.ok(facts.some((f) => /Record exists\. Its contents are locked, so this registry can(&#39;|’|’)t check them against its proof code; the holder(&#39;|’|’)s app does\./.test(f)), facts.join(' | '));
  const v = (await call('GET', `/verify/${id}`)).json;
  assert.notEqual(v.fingerprintCheckedByRegistry, true);
});

test('F3: no "matches its contents" claim is left in what the registry serves', () => {
  for (const f of ['lineage/embed.mjs', 'server.js', 'lineage/routes.mjs', 'lineage/transfer.mjs']) {
    const src = readFileSync(new URL(`../${f}`, import.meta.url), 'utf8');
    for (const line of src.split('\n')) {
      if (/^\s*(\/\/|\*)/.test(line)) continue; // comments explain what used to be said
      assert.doesNotMatch(line, /commitment matches its contents|fingerprint matches its contents/, `${f}: ${line.trim()}`);
    }
  }
});

// ---- F6: the purge replaces every recipient name typed before tags ---------------------------

const PURGE = fileURLToPath(new URL('../scripts/purge-plaintext.mjs', import.meta.url));
test('F6: a sender who has not been back since sealing: the default --apply still replaces the recipient\'s name, in the delivery and in the sender\'s record', () => {
  const dir = mkdtempSync(join(tmpdir(), 'veilcore-attack4-'));
  const file = join(dir, 'registry.db');
  try {
    const d = new Database(file);
    d.exec(`CREATE TABLE records (id TEXT PRIMARY KEY, holder_key TEXT NOT NULL, body TEXT NOT NULL, updated_at INTEGER NOT NULL, first_seen INTEGER);
CREATE TABLE licenses (id TEXT PRIMARY KEY, holder_key TEXT NOT NULL, record_id TEXT, body TEXT NOT NULL, updated_at INTEGER NOT NULL);
CREATE TABLE disclosure_grants (record_id TEXT PRIMARY KEY, holder_key TEXT NOT NULL, show TEXT NOT NULL, updated_at INTEGER NOT NULL, grant_values TEXT, for_fingerprint TEXT);
CREATE TABLE transfers (id TEXT PRIMARY KEY, source_record TEXT NOT NULL, from_holder TEXT NOT NULL, to_handle TEXT NOT NULL, claim_code TEXT, claimed_by TEXT, claimed_at INTEGER, created_at INTEGER NOT NULL, terms_hash TEXT, quantity TEXT, note TEXT, source_fingerprint TEXT, received_record TEXT, receipt_attestation_id TEXT, sample_custody TEXT, arrival_custody TEXT, offer_sealed TEXT, sample_custody_sealed TEXT, arrival_custody_sealed TEXT, custody_removed INTEGER);`);
    const NAME = 'Jane Doe at Example Hill Labs';
    const sender = 'h1:' + 'a'.repeat(64);
    d.prepare('INSERT INTO records VALUES (?,?,?,?,?)').run('VEIL-OLD1', sender, JSON.stringify({
      id: 'VEIL-OLD1', strainName: 'Old plant', nonce: 'n', bredBy: 'me', notes: 'KEEP-THESE-NOTES', recordFingerprint: 'f'.repeat(64),
      attestation: { type: 'receipt-confirmed', addressedTo: NAME, transferId: 'TR-OLD00001', attestedAt: 1 },
    }), 1, 1);
    d.prepare('INSERT INTO transfers (id, source_record, from_holder, to_handle, created_at, claimed_by, quantity, note) VALUES (?,?,?,?,?,?,?,?)')
      .run('TR-OLD00001', 'VEIL-OLD1', sender, NAME, 1, 'h1:' + 'b'.repeat(64), '3 clones', 'SENDER-NOTE');
    d.close();
    const out = execFileSync(process.execPath, [PURGE, '--db', file, '--apply'], { encoding: 'utf8' });
    assert.match(out, /1 recipient handles stored as typed, now random values \(for every sender, converted or not\)/);
    assert.match(out, /recipient names an older claim wrote into a sender's plain record: 1 removed/);
    const after = new Database(file, { readonly: true });
    const t = after.prepare('SELECT to_handle, quantity, note FROM transfers').get();
    const r = after.prepare('SELECT body FROM records').get();
    after.close();
    assert.match(t.to_handle, /^[0-9a-f]{64}$/);
    assert.ok(!r.body.includes(NAME), 'the sender\'s record no longer names the recipient');
    // The guard holds for everything else: the unconverted sender's own text stays.
    assert.match(r.body, /KEEP-THESE-NOTES/);
    assert.deepEqual([t.quantity, t.note], ['3 clones', 'SENDER-NOTE']);
    const body = JSON.parse(r.body);
    assert.deepEqual(body.attestation, { type: 'receipt-confirmed', transferId: 'TR-OLD00001', attestedAt: 1 });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---- F10: the export says what it holds and what it leaves out -------------------------------

test('F10: the export note lists what is not in it and where those live, and the readable list is complete', async () => {
  const holder = key();
  const out = await call('GET', '/api/export', holder);
  assert.equal(out.status, 200);
  const note = out.json.note;
  assert.doesNotMatch(note, /^Everything this registry holds/);
  assert.match(note, /except: deliveries \(with their locked offers and sample details\), lab reports, royalty obligations, and requests to prove a record's key/);
  assert.match(note, /the app shows each delivery, its sample details and lab reports/);
  assert.match(note, /prove requests are deleted after 7 days/);
  assert.match(note, /which holder account received it/);
  assert.match(note, /how many times and when each record and licence was saved/);
  assert.match(note, /size bucket/);
  assert.match(note, /key binding/);
  assert.match(note, /off-site backups made before then hold them until its backup key is rotated/);
  assert.match(note, /a delivery made before tags has the name as typed until the registry's purge replaces it/);
});

// ---- F11: the public answer never says "signed over" as a checked fact ----------------------

test('F11: the registry no longer answers signedOverSampleDetails', () => {
  for (const f of ['lineage/transfer.mjs', 'server.js', 'lineage/embed.mjs']) {
    const src = readFileSync(new URL(`../${f}`, import.meta.url), 'utf8');
    for (const line of src.split('\n')) {
      if (/^\s*(\/\/|\*)/.test(line)) continue;
      assert.doesNotMatch(line, /signedOverSampleDetails|signed (its receipt )?over the sample details/, `${f}: ${line.trim()}`);
    }
  }
  assert.match(readFileSync(new URL('../lineage/transfer.mjs', import.meta.url), 'utf8'), /receiptNamesSampleDetails: true, sampleDetailsCheckedBy: 'holder'/);
});
