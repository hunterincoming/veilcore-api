// Lineage layer, attacked. Security pass 30 Sep 2026.
//
// Before this pass, "authentication" was any non-empty x-holder-key header, never
// compared with anything: anyone could attach an obligation to anyone's record,
// overwrite a real one, delete any record's obligation, and declare any parent. Each
// test below is one of those attacks, now refused, plus the flows that must still work.
//
// SPDX-License-Identifier: Apache-2.0

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import Database from 'better-sqlite3';
import { createLineage, partyId, beneficiaryIdFor } from '../lineage/routes.mjs';
import holderKeys from '../holder-key.js';

const { storedHolderKey } = holderKeys;

const fp = (s) => createHash('sha256').update(s).digest('hex');
const BREEDER = 'key-breeder', GROWER = 'key-grower', STRANGER = 'key-stranger', BUYER = 'key-buyer';
const MOTHER = fp('mother'), DAUGHTER = fp('daughter'), STRANGER_REC = fp('stranger-record');
const ROYALTY = fp('royalty-8pct'), FAKE = fp('fake-claim');

/** A registry with the records table the server creates, and some stored records. */
const registry = (records = [[MOTHER, BREEDER], [DAUGHTER, GROWER], [STRANGER_REC, STRANGER]]) => {
  const db = new Database(':memory:');
  db.exec(`CREATE TABLE records (id TEXT PRIMARY KEY, holder_key TEXT NOT NULL, body TEXT NOT NULL, updated_at INTEGER NOT NULL);
           CREATE TABLE transfers (id TEXT PRIMARY KEY, source_record TEXT NOT NULL, from_holder TEXT, claimed_by TEXT, source_fingerprint TEXT, received_record TEXT);`);
  records.forEach(([fingerprint, holder], i) =>
    db.prepare('INSERT INTO records VALUES (?,?,?,?)').run(`R${i}`, holder, JSON.stringify({ recordFingerprint: fingerprint }), 0));
  return { db, L: createLineage(db) };
};
const refused = (fn, status) => {
  try { fn(); } catch (e) { if (status === 403) assert.equal(e.name === 'Forbidden' || e.constructor.name === 'Forbidden', true, e.message); return e.message; }
  assert.fail('expected a refusal');
};

test('a stranger cannot put a record in force against someone else', () => {
  const { L } = registry();
  const r = L.encumber(MOTHER, FAKE, STRANGER);
  assert.equal(r.status, 'proposed', 'a claim on someone else\'s record is only a proposal');
  assert.equal(L.verifyDescent(MOTHER, []).ok, true, 'the record stays clean');
});

test('a stranger cannot delete anyone\'s obligation (the live bug)', () => {
  const { L } = registry();
  L.encumber(MOTHER, ROYALTY, BREEDER);
  refused(() => L.discharge(MOTHER, ROYALTY, STRANGER), 403);
  assert.equal(L.verifyDescent(MOTHER, []).ok, false, 'still in force');
});

test('a stranger cannot overwrite a real obligation', () => {
  const { L } = registry();
  L.encumber(MOTHER, ROYALTY, BREEDER);
  L.encumber(MOTHER, ROYALTY, STRANGER); // their own proposal, a separate entry
  L.discharge(MOTHER, ROYALTY, STRANGER); // withdrawing it
  assert.equal(L.verifyDescent(MOTHER, []).ok, false, 'the breeder\'s obligation is untouched');
});

test('licensing flow: a holder encumbers their own record in one step, and releases it', () => {
  const { L } = registry();
  const r = L.encumber(MOTHER, ROYALTY, BREEDER);
  assert.equal(r.status, 'open');
  assert.equal(L.verifyDescent(MOTHER, []).ok, false);
  L.discharge(MOTHER, ROYALTY, BREEDER);
  assert.equal(L.verifyDescent(MOTHER, []).ok, true);
  assert.equal(L.root(), L.emptyRoot);
});

test('consent flow: beneficiary proposes, holder accepts, only beneficiary releases', () => {
  const { L } = registry();
  const { beneficiary } = L.encumber(DAUGHTER, ROYALTY, BREEDER);
  assert.deepEqual(L.proposalsFor(GROWER).map((p) => [p.record, p.beneficiary]), [[DAUGHTER, beneficiary]]);
  refused(() => L.acceptObligation(DAUGHTER, ROYALTY, beneficiary, STRANGER), 403);
  L.acceptObligation(DAUGHTER, ROYALTY, beneficiary, GROWER);
  assert.equal(L.verifyDescent(DAUGHTER, []).ok, false);
  refused(() => L.discharge(DAUGHTER, ROYALTY, GROWER), 403);
  L.discharge(DAUGHTER, ROYALTY, BREEDER);
  assert.equal(L.verifyDescent(DAUGHTER, []).ok, true);
});

test('several obligations on one record: releasing one leaves the other', () => {
  const { L } = registry();
  L.encumber(MOTHER, ROYALTY, BREEDER);
  const { beneficiary } = L.encumber(MOTHER, ROYALTY, STRANGER);
  L.acceptObligation(MOTHER, ROYALTY, beneficiary, BREEDER);
  L.discharge(MOTHER, ROYALTY, BREEDER);
  assert.equal(L.verifyDescent(MOTHER, []).ok, false);
});

test('descent: a child\'s proposal is not an edge until the parent confirms', () => {
  const { L } = registry();
  const p = L.proposeParent(DAUGHTER, MOTHER, GROWER);
  assert.equal(p.confirmed, false);
  assert.deepEqual(L.ancestorsOf(DAUGHTER), []);
  refused(() => L.confirmParent(DAUGHTER, MOTHER, STRANGER), 403);
  L.confirmParent(DAUGHTER, MOTHER, BREEDER);
  assert.deepEqual(L.ancestorsOf(DAUGHTER), [MOTHER]);
});

test('substitution: a seller cannot name a clean stranger as their parent', () => {
  const { L } = registry();
  L.encumber(MOTHER, ROYALTY, BREEDER); // the real mother owes a royalty
  L.proposeParent(DAUGHTER, STRANGER_REC, GROWER); // the seller names someone clean
  assert.deepEqual(L.ancestorsOf(DAUGHTER), [], 'unconfirmed, so no edge');
  refused(() => L.proposeParent(DAUGHTER, MOTHER, STRANGER), 403); // nor can a stranger declare for the child
});

test('an obligation upstream blocks the descendant; a spoofed chain is refused', () => {
  const { L } = registry();
  L.proposeParent(DAUGHTER, MOTHER, GROWER);
  L.confirmParent(DAUGHTER, MOTHER, BREEDER);
  assert.equal(L.verifyDescent(DAUGHTER, [MOTHER]).ok, true);
  L.encumber(MOTHER, ROYALTY, BREEDER);
  assert.equal(L.verifyDescent(DAUGHTER, [MOTHER]).ok, false);
  assert.equal(L.verifyDescent(DAUGHTER, [STRANGER_REC]).ok, false);
  assert.equal(L.verifyDescent(DAUGHTER, []).ok, false, 'omission refused');
});

test('a claimed transfer counts as the parent\'s consent', () => {
  const { db, L } = registry();
  // As the transfer module stores it since 8 Oct 2026: keys as digests, the fingerprint the
  // source carried when it was offered, and the record the claim created (R1, DAUGHTER).
  db.prepare('INSERT INTO transfers VALUES (?,?,?,?,?,?)')
    .run('TR-1', 'R0', storedHolderKey(BREEDER), storedHolderKey(GROWER), MOTHER, 'R1'); // breeder's R0 (MOTHER) -> grower's R1
  const p = L.proposeParent(DAUGHTER, MOTHER, GROWER);
  assert.equal(p.confirmed, true);
  assert.deepEqual(L.ancestorsOf(DAUGHTER), [MOTHER]);
});

test('a fingerprint stored by two holders: nobody may consent for it', () => {
  const { db, L } = registry([[MOTHER, BREEDER], [MOTHER, STRANGER], [DAUGHTER, GROWER]]);
  refused(() => L.proposeParent(MOTHER, DAUGHTER, BREEDER), 403);
  // Not in force, and since round D not even proposed: nobody could ever accept it, and a
  // proposal is written only against a record one holder can decide on.
  assert.match(refused(() => L.encumber(MOTHER, ROYALTY, BREEDER)), /more than one holder/);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM obligations_v2').get().n, 0);
});

test('empty and malformed commitments are refused', () => {
  const { L } = registry();
  refused(() => L.encumber('00'.repeat(32), ROYALTY, BREEDER));
  refused(() => L.encumber(MOTHER, 'zz', BREEDER));
  refused(() => L.proposeParent(DAUGHTER, DAUGHTER, GROWER));
});

test('round 3 P5: no listing; one holder\'s obligations are stored under per-record ids, never the party id', () => {
  const { db, L } = registry([[MOTHER, BREEDER], [DAUGHTER, BREEDER]]);
  assert.equal(L.listing, undefined, 'the lineage layer has no listing of every obligation');
  const a = L.encumber(MOTHER, ROYALTY, BREEDER);
  const b = L.encumber(DAUGHTER, ROYALTY, BREEDER);
  assert.notEqual(a.beneficiary, b.beneficiary, 'two records of one holder: two ids that do not link them');
  assert.equal(a.beneficiary, beneficiaryIdFor(BREEDER, MOTHER));
  const ids = db.prepare('SELECT beneficiary_id FROM obligations_v2').all().map((r) => r.beneficiary_id);
  assert.equal(ids.includes(partyId(BREEDER)), false, 'the per-holder party id is not stored');
  for (const k of [BREEDER, GROWER, STRANGER]) assert.equal(JSON.stringify([a, b]).includes(k), false);
});

test('round 3 P5: the browser\'s own per-record beneficiary id is stored; a bad one or the party id is refused', () => {
  const { db, L } = registry();
  const mine = fp('hmac-of-mother-under-the-vault-key');
  assert.match(refused(() => L.encumber(MOTHER, ROYALTY, BREEDER, partyId(BREEDER))), /per-record id, not your party id/);
  assert.match(refused(() => L.encumber(MOTHER, ROYALTY, BREEDER, 'Not-Hex')), /64 lowercase hexadecimal/);
  assert.equal(L.encumber(MOTHER, ROYALTY, BREEDER, mine).beneficiary, mine);
  assert.equal(db.prepare('SELECT beneficiary_id FROM obligations_v2 WHERE record = ?').get(MOTHER).beneficiary_id, mine);
  // The same obligation again under another id is the same caller's: refused.
  assert.match(refused(() => L.encumber(MOTHER, ROYALTY, BREEDER, fp('another'))), /already in force/);
  // Someone else can't take that id for the same obligation.
  assert.match(refused(() => L.encumber(MOTHER, ROYALTY, STRANGER, mine)), /beneficiary id is already used/);
  // Releasing needs no id: whoever made it, by their key.
  refused(() => L.discharge(MOTHER, ROYALTY, STRANGER), 403);
  L.discharge(MOTHER, ROYALTY, BREEDER);
  assert.equal(L.verifyDescent(MOTHER, []).ok, true);
});

test('migration: old single-obligation rows become open self-claims, and survive restarts', () => {
  const db = new Database(':memory:');
  db.exec(`CREATE TABLE records (id TEXT PRIMARY KEY, holder_key TEXT NOT NULL, body TEXT NOT NULL, updated_at INTEGER NOT NULL);
           CREATE TABLE obligations (record TEXT PRIMARY KEY, obligation TEXT NOT NULL, holder_key TEXT NOT NULL, created_at INTEGER NOT NULL);`);
  db.prepare('INSERT INTO records VALUES (?,?,?,?)').run('R0', BREEDER, JSON.stringify({ recordFingerprint: MOTHER }), 0);
  db.prepare('INSERT INTO obligations VALUES (?,?,?,?)').run(MOTHER, ROYALTY, BREEDER, 1);
  const L = createLineage(db);
  assert.equal(L.verifyDescent(MOTHER, []).ok, false, 'migrated obligation in force');
  L.discharge(MOTHER, ROYALTY, BREEDER); // the original holder can still release it
  assert.equal(L.verifyDescent(MOTHER, []).ok, true);
  L.encumber(MOTHER, ROYALTY, BREEDER);
  const L2 = createLineage(db);
  assert.equal(L2.root(), L.root(), 'state survives a restart');
});
