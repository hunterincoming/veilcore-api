// Holder keys at rest (deep dive, 8 Oct 2026, MEDIUM). Holder keys were stored as sent in
// records, licenses, disclosure_grants, transfers and obligations_v2, so a copy of the
// database let anyone act as every holder. They are stored as digests now, and a database
// written by the old code is converted once at startup.
//
// The database here was written by the code at cfb2ee9 through its own routes
// (test/fixtures/registry-before-8oct.sql). No network.
//
// SPDX-License-Identifier: Apache-2.0

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import Database from 'better-sqlite3';
import { untilReady, testBody } from './helpers.mjs';

const H = (s) => createHash('sha256').update(s).digest('hex');
const BREEDER = H('fixture:breeder'), LAB = H('fixture:lab'), OTHER = H('fixture:other');
const UPPER = H('fixture:upper').toUpperCase();
const RAW_KEYS = [BREEDER, LAB, OTHER, UPPER];
const OPEN_TRANSFER = { id: 'TR-2F83F0FA', code: '785e24dfbc403f5cb1082bfdc48c05c1' };
const MOTHER_FP = '986c2325af714176efa3de6bec82a4ab5d6a4602fd691dfe2b1c8ff705f85754';
const ROYALTY = H('royalty'), OTHER_CLAIM = H('other-claim');

const dir = mkdtempSync(join(tmpdir(), 'veilcore-migration-'));
const file = join(dir, 'registry.db');
{
  const old = new Database(file);
  old.exec(readFileSync(new URL('./fixtures/registry-before-8oct.sql', import.meta.url), 'utf8'));
  old.close();
}
process.env.DB_PATH = file;
process.env.VEILCORE_OTS = 'off';
const require = createRequire(import.meta.url);
const { app, db } = require('../server.js');
const { migrateHolderKeys, storedHolderKey, HOLDER_KEY_COLUMNS, STORED_PREFIX } = require('../holder-key.js');

let base, server;
before(async () => {
  server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  base = `http://127.0.0.1:${server.address().port}`;
  await untilReady(base);
});
after(() => { server.close(); db.close(); rmSync(dir, { recursive: true, force: true }); });

const call = async (method, path, { holder, body } = {}) => {
  const res = await fetch(`${base}${path}`, {
    method,
    headers: { 'content-type': 'application/json', ...(holder ? { 'x-holder-key': holder } : {}) },
    body: body === undefined ? undefined : JSON.stringify(testBody(method, path, holder, body)),
  });
  const text = await res.text();
  let json; try { json = JSON.parse(text); } catch { json = text; }
  return { status: res.status, json };
};

const storedValues = () => {
  const out = [];
  for (const [t, c] of HOLDER_KEY_COLUMNS) {
    for (const r of db.prepare(`SELECT ${c} AS v FROM ${t} WHERE ${c} IS NOT NULL`).all()) out.push({ at: `${t}.${c}`, v: r.v });
  }
  return out;
};

test('MEDIUM: after startup no holder key is stored in plain text, in any table or anywhere in the file', () => {
  const values = storedValues();
  assert.ok(values.length >= 10, `the fixture has keys in every table (${values.length})`);
  for (const { at, v } of values) {
    assert.ok(v.startsWith(STORED_PREFIX), `${at} is a digest`);
    for (const k of RAW_KEYS) assert.ok(!v.includes(k) && !v.includes(k.toLowerCase()), `${at} does not contain a key`);
  }
  // The file itself: no key in any page, including pages freed by the conversion.
  const bytes = readFileSync(file).toString('latin1');
  for (const k of RAW_KEYS) assert.equal(bytes.includes(k), false, `${k.slice(0, 8)}... is not in the database file`);
  // Each key maps to its own digest.
  assert.ok(values.some(({ at, v }) => at === 'records.holder_key' && v === storedHolderKey(BREEDER)));
  assert.ok(values.some(({ at, v }) => at === 'records.holder_key' && v === storedHolderKey(UPPER)), 'an upper-case key is hashed in lower case');
  assert.equal(storedHolderKey(UPPER), storedHolderKey(UPPER.toLowerCase()), 'one key, one digest (round 3)');
  assert.ok(values.some(({ at, v }) => at === 'transfers.claimed_by' && v === storedHolderKey(LAB)));
  assert.ok(values.some(({ at, v }) => at === 'obligations_v2.beneficiary_key' && v === storedHolderKey(OTHER)));
});

test('MEDIUM: every holder still reaches everything with the key they always had', async () => {
  const mine = (await call('GET', '/api/records', { holder: BREEDER })).json;
  assert.deepEqual(mine.map((r) => r.id).sort(), ['OLD-DAUGHTER', 'OLD-MOTHER']);
  assert.deepEqual((await call('GET', '/api/records', { holder: UPPER })).json.map((r) => r.id), ['OLD-UPPER']);
  assert.deepEqual((await call('GET', '/api/records', { holder: UPPER.toLowerCase() })).json.map((r) => r.id), ['OLD-UPPER'],
    'the same key in lower case is the same holder (round 3)');
  const received = (await call('GET', '/api/records', { holder: LAB })).json;
  assert.equal(received.length, 1);
  assert.equal(received[0].receivedFrom, 'OLD-DAUGHTER');
  assert.deepEqual((await call('GET', '/api/licenses', { holder: BREEDER })).json.map((l) => l.id), ['LIC-1']);
  assert.deepEqual((await call('GET', '/api/records/OLD-MOTHER/disclosure', { holder: BREEDER })).json.show, ['existence', 'parent-names']);
  // The grant still applies; made before grant values, its parent names are not answered
  // (the registry no longer reads them from the record) until the holder's app sends them.
  const verified = (await call('GET', '/verify/OLD-MOTHER')).json;
  assert.deepEqual(verified.disclosed, ['own'], 'the grant still applies');
  assert.deepEqual(verified.staleGrant, ['parents']);
  assert.equal(verified.parents, undefined);
  const ex = (await call('GET', '/api/export', { holder: BREEDER })).json;
  assert.equal(ex.records.length, 2);
  assert.deepEqual(ex.disclosures, { 'OLD-MOTHER': ['existence', 'parent-names'] });
  assert.equal((await call('GET', '/transfers/sent', { holder: BREEDER })).json.transfers.length, 3);
  // A holder can still save over their own record, and nobody else can.
  const daughter = mine.find((r) => r.id === 'OLD-DAUGHTER');
  assert.equal((await call('PUT', '/api/records', { holder: BREEDER, body: [daughter] })).json.count, 1);
  assert.deepEqual((await call('PUT', '/api/records', { holder: OTHER, body: [daughter] })).json.notWritten ?? [], [],
    'a fingerprint clash is refused before the write');
  // Lineage: the breeder accepts OTHER's proposal and releases their own obligation.
  const proposals = (await call('GET', '/lineage/obligations/proposals', { holder: BREEDER })).json.proposals;
  assert.equal(proposals.length, 1);
  assert.equal((await call('POST', '/lineage/obligations/accept', { holder: BREEDER, body: { record: MOTHER_FP, obligation: OTHER_CLAIM, beneficiary: proposals[0].beneficiary } })).status, 200);
  assert.equal((await call('DELETE', `/lineage/obligations/${MOTHER_FP}`, { holder: BREEDER, body: { obligation: ROYALTY } })).status, 200);
  assert.equal((await call('DELETE', `/lineage/obligations/${MOTHER_FP}`, { holder: LAB, body: { obligation: OTHER_CLAIM } })).status, 403);
  assert.equal((await call('DELETE', `/lineage/obligations/${MOTHER_FP}`, { holder: OTHER, body: { obligation: OTHER_CLAIM } })).status, 200);
  // The open transfer is claimed with its code; the claimant's record is stored under a digest.
  const claim = await call('POST', `/transfers/${OPEN_TRANSFER.id}/claim`, { holder: LAB, body: { claimCode: OPEN_TRANSFER.code } });
  assert.equal(claim.status, 200, JSON.stringify(claim.json));
  assert.equal(db.prepare('SELECT holder_key FROM records WHERE id = ?').get(claim.json.recordId).holder_key, storedHolderKey(LAB));
  assert.equal(db.prepare('SELECT claimed_by FROM transfers WHERE id = ?').get(OPEN_TRANSFER.id).claimed_by, storedHolderKey(LAB));
});

test('LOW: transfers from before 8 Oct get the fingerprint they carried; a code-less one is refused', async () => {
  const fp = (id) => JSON.parse(db.prepare('SELECT body FROM records WHERE id = ?').get(id).body).recordFingerprint;
  const row = (id) => db.prepare('SELECT source_fingerprint, claimed_by FROM transfers WHERE id = ?').get(id);
  // Claimed before: from the record the claim made, i.e. what the lab received.
  const claimed = db.prepare("SELECT id FROM transfers WHERE source_record = 'OLD-DAUGHTER'").get().id;
  assert.equal(row(claimed).source_fingerprint, fp('OLD-DAUGHTER'));
  // And the record that claim created (round 2): the only child it is consent for.
  const receivedId = db.prepare('SELECT received_record FROM transfers WHERE id = ?').get(claimed).received_record;
  assert.equal(JSON.parse(db.prepare('SELECT body FROM records WHERE id = ?').get(receivedId).body).transferId, claimed);
  // Open before: from the source as it stood.
  assert.equal(row(OPEN_TRANSFER.id).source_fingerprint, fp('OLD-MOTHER'));
  const legacy = await call('POST', '/transfers/TR-LEGACY0/claim', { holder: OTHER, body: {} });
  assert.equal(legacy.status, 400);
  assert.match(legacy.json.error, /before claim codes/);
  assert.equal(row('TR-LEGACY0').claimed_by, null);
});

test('MEDIUM: an attestation stored with unsigned padding keeps only its signed fields, and still verifies', async () => {
  const body = db.prepare("SELECT body FROM attestations WHERE attestation_id = 'ATT-OLD-1'").get().body;
  assert.ok(body.length < 1024, `${body.length} bytes`);
  assert.doesNotMatch(body, /padding|extra/);
  const { verifyAttestation } = await import('veilcore-records');
  assert.equal(await verifyAttestation(JSON.parse(body)), true);
  // A lab report signature: listed for the breeder, who sent a delivery of the record, and
  // for nobody else, not even as a count (8 Nov 2026, hide-lab-reports.test.mjs).
  assert.equal((await call('GET', `/attestations/subject/${MOTHER_FP}`, { holder: BREEDER })).json.attestations[0].attestationId, 'ATT-OLD-1');
  const stranger = (await call('GET', `/attestations/subject/${MOTHER_FP}`)).json;
  assert.deepEqual([stranger.attestations, stranger.total], [[], 0]);
});

test('MEDIUM: new writes store digests only', async () => {
  const k = H('fixture:new-holder');
  assert.equal((await call('PUT', '/api/licenses', { holder: k, body: [{ id: 'LIC-NEW' }] })).json.count, 1);
  assert.equal((await call('PUT', '/api/records', { holder: k, body: [{ id: 'NEW-1', strainName: 'n' }] })).json.count, 1);
  for (const { at, v } of storedValues()) {
    assert.ok(v.startsWith(STORED_PREFIX), at);
    assert.ok(!v.includes(k), at);
  }
});

test('MEDIUM: the migration is safe to run again, and on an empty or missing schema', () => {
  const before = JSON.stringify(storedValues());
  assert.deepEqual(migrateHolderKeys(db, { log: () => {} }), {}, 'nothing left to convert');
  assert.equal(JSON.stringify(storedValues()), before, 'and nothing changed');

  const empty = new Database(':memory:');
  assert.deepEqual(migrateHolderKeys(empty, { log: () => {} }), {}, 'no tables at all');
  empty.exec('CREATE TABLE records (id TEXT PRIMARY KEY, holder_key TEXT NOT NULL, body TEXT NOT NULL, updated_at INTEGER NOT NULL)');
  empty.exec('CREATE TABLE transfers (id TEXT PRIMARY KEY, source_record TEXT NOT NULL, claimed_by TEXT)');
  assert.deepEqual(migrateHolderKeys(empty, { log: () => {} }), {}, 'empty tables, and a transfers table with no from_holder column');
  empty.prepare('INSERT INTO transfers VALUES (?,?,?)').run('T1', 'R1', null);
  empty.prepare('INSERT INTO records VALUES (?,?,?,?)').run('R1', 'abc', '{}', 0);
  assert.deepEqual(migrateHolderKeys(empty, { log: () => {} }), { 'records.holder_key': 1 }, 'a null claimant stays null');
  assert.equal(empty.prepare('SELECT claimed_by FROM transfers').get().claimed_by, null);
  assert.equal(empty.prepare('SELECT holder_key FROM records').get().holder_key, storedHolderKey('abc'));
  assert.deepEqual(migrateHolderKeys(empty, { log: () => {} }), {});
  empty.close();
});
