// Round 3: fixes an independent attacker reproduced, and the lab's signed receipt.
//
//   1. One holder key in two spellings was two holders (self-claim guard, party ids).
//   2. A copy of the database started against the live results folder deleted live files.
//   3. One sender could fill the whole lab-results store.
//   4. `replaces` could name a withdrawn result.
//   5. The export note said lab files never reach the registry.
//   +  POST /transfers/:id/receipt: the lab's chain-of-custody attestation, checked against
//      exactly what this delivery handed over.
//
// SPDX-License-Identifier: Apache-2.0

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { createHash, randomBytes } from 'node:crypto';
import { mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import Database from 'better-sqlite3';
import { canonicalise, sha256Hex, newNonce, generateKeypair, signAttestation, signRetraction } from 'veilcore-records';
import { createLabResults, folderFiles } from '../lineage/lab-results.mjs';
import { partyId } from '../lineage/routes.mjs';
import { untilReady, testBody } from './helpers.mjs';

process.env.DB_PATH = ':memory:';
process.env.VEILCORE_OTS = 'off';
const require = createRequire(import.meta.url);
const { app, db } = require('../server.js');
const { storedHolderKey, legacyStoredHolderKey } = require('../holder-key.js');

const key = () => randomBytes(32).toString('hex');
/** Mixed case: every other hex letter in capitals. */
const mixed = (k) => [...k].map((c, i) => (i % 2 ? c.toUpperCase() : c)).join('');

let base, server;
before(async () => {
  server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  base = `http://127.0.0.1:${server.address().port}`;
  await untilReady(base);
});
after(() => server.close());

const call = async (method, path, holder, body, headers = {}) => {
  const res = await fetch(`${base}${path}`, {
    method,
    headers: { 'content-type': 'application/json', ...(holder ? { 'x-holder-key': holder } : {}), ...headers },
    ...(body === undefined ? {} : { body: JSON.stringify(testBody(method, path, holder, body)) }),
  });
  const text = await res.text();
  let json; try { json = JSON.parse(text); } catch { json = text; }
  return { status: res.status, json };
};
const upload = async (transferId, holder, bytes, replaces) => {
  const q = replaces ? `?replaces=${replaces}` : '';
  const res = await fetch(`${base}/transfers/${transferId}/results${q}`, {
    method: 'POST',
    headers: { 'content-type': 'application/octet-stream', 'x-holder-key': holder },
    body: bytes,
  });
  return { status: res.status, json: await res.json() };
};
const ageFile = (n = 200) => Buffer.concat([Buffer.from('age-encryption.org/v1\n-> X25519 abc\n'), randomBytes(n)]);
/** The bytes ageFile adds, so a test can ask for a file of an exact size. */
const HDR = ageFile(0).length;

const committedOf = (r) => ({ breedingMethod: r.breedingMethod ?? '', bredBy: r.bredBy, dateCreated: r.dateCreated,
  loggedAt: r.loggedAt, nonce: r.nonce, notes: r.notes, parents: r.parents ?? [],
  photoFingerprints: r.photoFingerprints ?? [], refId: r.refId ?? '', strainName: r.strainName });

/** A sealed record saved by `sender`. */
const plant = async (sender) => {
  const r = { id: `r3-${randomBytes(6).toString('hex')}`, strainName: 'S', bredBy: 'B', dateCreated: '2026-01-01',
    loggedAt: '2026-01-01T00:00:00Z', nonce: newNonce(), notes: '', parents: [], photoFingerprints: [], breedingMethod: '', refId: '' };
  r.recordFingerprint = await sha256Hex(canonicalise(committedOf(r)));
  const put = await call('PUT', '/api/records', sender, [r]);
  assert.equal(put.status, 200, JSON.stringify(put.json));
  return r;
};
const offer = async (sender, source) => {
  const o = await call('POST', '/transfers', sender, { sourceRecord: source.id, toHandle: 'lab@x' });
  assert.equal(o.status, 200, JSON.stringify(o.json));
  return o.json;
};

/** A delivery claimed by `lab`, whose received record the lab then seals, as the app does. */
const claimedDelivery = async ({ sender = key(), lab = key(), source } = {}) => {
  source ??= await plant(sender);
  const o = await offer(sender, source);
  const c = await call('POST', `/transfers/${o.transferId}/claim`, lab, { claimCode: o.claimCode });
  assert.equal(c.status, 200, JSON.stringify(c.json));
  // The registry wrote a stub; the lab's browser completes it from the offer and seals it.
  const stub = (await call('GET', '/api/records', lab)).json.find((r) => r.id === c.json.recordId);
  const received = { ...stub, bredBy: 'B', dateCreated: '2026-01-01', notes: '', parents: [], photoFingerprints: [],
    breedingMethod: '', refId: '', nonce: newNonce(), loggedAt: stub.receivedAt };
  const sealed = { ...received, recordFingerprint: await sha256Hex(canonicalise(committedOf(received))) };
  const put = await call('PUT', '/api/records', lab, [sealed]);
  assert.equal(put.json.count, 1, JSON.stringify(put.json));
  assert.equal(put.json.integrityCheckedBy, 'holder');
  return { sender, lab, source, transferId: o.transferId, received: sealed };
};

/** Sign and post an attestation; its id. */
const attest = async (kp, subjectCommitment, documentHash, type = 'chain-of-custody') => {
  const attestationId = `att_${randomBytes(8).toString('hex')}`;
  const signed = await signAttestation({
    attestationId, type, subjectCommitment, documentHash, hashAlgorithm: 'sha256',
    issuedAt: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'), attester: { publicKey: kp.publicKey, displayName: 'Lab' },
  }, kp.privateKey);
  const r = await call('POST', '/attestations', undefined, signed);
  assert.equal(r.status, 200, JSON.stringify(r.json));
  return attestationId;
};
/** The lab's receipt for a delivery, as the site's ClaimTransfer signs it. */
const receiptFor = (kp, d) => attest(kp, d.source.recordFingerprint, d.received.recordFingerprint);
const attach = (d, holder, attestationId, headers) =>
  call('POST', `/transfers/${d.transferId}/receipt`, holder, { attestationId }, headers);

// =====================================================================================
// 1. One key, one holder, in any case
// =====================================================================================

test('1: a sender cannot claim their own code with their key in upper, lower or mixed case', async () => {
  for (const [offerAs, claimAs] of [
    [(k) => k, (k) => k.toUpperCase()],
    [(k) => k.toUpperCase(), (k) => k],
    [(k) => k, mixed],
    [mixed, (k) => k.toUpperCase()],
    [(k) => k.toUpperCase(), (k) => k.toUpperCase()],
  ]) {
    const sender = key();
    const source = await plant(offerAs(sender));
    const o = await offer(offerAs(sender), source);
    const r = await call('POST', `/transfers/${o.transferId}/claim`, claimAs(sender), { claimCode: o.claimCode });
    assert.equal(r.status, 409, `offered as ${offerAs(sender).slice(0, 6)}, claimed as ${claimAs(sender).slice(0, 6)}`);
    assert.equal(r.json.error, 'This is your own code. Send it to the lab instead.');
    assert.equal((await call('POST', `/transfers/${o.transferId}/claim`, key(), { claimCode: o.claimCode })).status, 200, 'the lab still can');
  }
});

test('1: every spelling of a key reaches the same records, transfers, results and party id', async () => {
  const sender = key();
  const source = await plant(sender.toUpperCase());
  for (const k of [sender, sender.toUpperCase(), mixed(sender)]) {
    assert.deepEqual((await call('GET', '/api/records', k)).json.map((r) => r.id), [source.id]);
  }
  assert.equal(db.prepare('SELECT holder_key FROM records WHERE id = ?').get(source.id).holder_key, storedHolderKey(sender));
  const lab = key();
  const o = await offer(mixed(sender), source);
  assert.equal((await call('POST', `/transfers/${o.transferId}/claim`, lab.toUpperCase(), { claimCode: o.claimCode })).status, 200);
  assert.equal((await call('GET', '/transfers/sent', sender)).json.transfers.length, 1);
  assert.equal((await upload(o.transferId, mixed(lab), ageFile())).status, 200, 'the lab in another spelling is still the claimant');
  assert.equal((await call('GET', `/transfers/${o.transferId}/results`, sender.toUpperCase())).json.results.length, 1);
  assert.equal(partyId(sender.toUpperCase()), partyId(sender));
  assert.equal(partyId(mixed(sender)), partyId(sender));
});

test('1: an obligation is one party’s whatever the spelling: no second copy, and either spelling releases it', async () => {
  const holder = key();
  const rec = await plant(holder);
  const obligation = createHash('sha256').update(`r3-ob-${holder}`).digest('hex');
  const add = (k) => call('POST', '/lineage/obligations', k, { record: rec.recordFingerprint, obligation });
  assert.equal((await add(holder.toUpperCase())).status, 200);
  const again = await add(holder);
  assert.notEqual(again.status, 200, 'the same obligation again under the lower-case spelling is refused');
  assert.match(again.json.error, /already/);
  // A stranger cannot propose it many times over with spellings of one key.
  const stranger = key();
  assert.equal((await add(stranger)).status, 200);
  assert.notEqual((await add(stranger.toUpperCase())).status, 200);
  assert.equal((await call('DELETE', `/lineage/obligations/${rec.recordFingerprint}`, mixed(holder), { obligation })).status, 200);
});

test('1: rows written under a capitalised key before this change move over when that key next arrives', async () => {
  const k = key();
  const upper = k.toUpperCase();
  const legacy = legacyStoredHolderKey(upper);
  assert.notEqual(legacy, storedHolderKey(upper));
  db.prepare('INSERT INTO records (id, holder_key, body, updated_at, first_seen) VALUES (?, ?, ?, 1, 1)')
    .run('r3-legacy', legacy, JSON.stringify({ id: 'r3-legacy', strainName: 'old' }));
  // An obligation in its old party id (the key hashed as sent), and the same one already
  // under the new id, proposed: the old row, in force, is kept in force under the new id.
  const legacyParty = createHash('sha256').update(`veilcore:party:${upper}`).digest('hex');
  const ins = db.prepare(`INSERT INTO obligations_v2 (record, obligation, beneficiary_key, beneficiary_id, status, created_at)
                          VALUES (?, ?, ?, ?, ?, 1)`);
  ins.run('ab'.repeat(32), 'cd'.repeat(32), legacy, legacyParty, 'open');
  ins.run('ab'.repeat(32), 'cd'.repeat(32), storedHolderKey(k), partyId(k), 'proposed');
  ins.run('ab'.repeat(32), 'ef'.repeat(32), legacy, legacyParty, 'proposed');

  assert.deepEqual((await call('GET', '/api/records', upper)).json.map((r) => r.id), ['r3-legacy']);
  assert.equal(db.prepare('SELECT holder_key FROM records WHERE id = ?').get('r3-legacy').holder_key, storedHolderKey(k));
  assert.deepEqual((await call('GET', '/api/records', k)).json.map((r) => r.id), ['r3-legacy'], 'and now in lower case too');
  const rows = db.prepare('SELECT obligation, beneficiary_id, status FROM obligations_v2 WHERE record = ? ORDER BY obligation').all('ab'.repeat(32));
  assert.deepEqual(rows, [
    { obligation: 'cd'.repeat(32), beneficiary_id: partyId(k), status: 'open' },
    { obligation: 'ef'.repeat(32), beneficiary_id: partyId(k), status: 'proposed' },
  ]);
});

// =====================================================================================
// The lab's signed receipt
// =====================================================================================

test('receipt: the lab attaches its receipt; the sender reads it from /transfers/sent and the results list', async () => {
  const d = await claimedDelivery();
  const kp = await generateKeypair();
  const id = await receiptFor(kp, d);
  const r = await attach(d, d.lab, id);
  assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.deepEqual(r.json, { transferId: d.transferId, receiptAttestationId: id });
  const sent = (await call('GET', '/transfers/sent', d.sender)).json.transfers.find((t) => t.id === d.transferId);
  assert.equal(sent.receipt_attestation_id, id);
  const forSender = await call('GET', `/transfers/${d.transferId}/results`, d.sender);
  assert.equal(forSender.json.receiptAttestationId, id);
  const forLab = await call('GET', `/transfers/${d.transferId}/results`, d.lab);
  assert.equal(forLab.status, 200);
  assert.equal('receiptAttestationId' in forLab.json, false, 'only the sender is told');
  // Not set yet on another delivery: null in the sent list, absent from the results list.
  const other = await claimedDelivery({ sender: d.sender });
  const sent2 = (await call('GET', '/transfers/sent', d.sender)).json.transfers.find((t) => t.id === other.transferId);
  assert.equal(sent2.receipt_attestation_id, null);
  assert.equal('receiptAttestationId' in (await call('GET', `/transfers/${other.transferId}/results`, d.sender)).json, false);
});

test('receipt: only the claimant may attach one, checked as a claim checks the claimant', async () => {
  const d = await claimedDelivery();
  const id = await receiptFor(await generateKeypair(), d);
  assert.equal((await attach(d, key(), id)).status, 403, 'a stranger');
  assert.equal((await attach(d, d.sender, id)).status, 403, 'the sender');
  assert.equal((await attach(d, undefined, id)).status, 401, 'no key');
  assert.equal((await call('POST', '/transfers/TR-NOPE0000/receipt', d.lab, { attestationId: id })).status, 404);
  // The key in the body, as the contract allows; it must agree with the header if both are sent.
  const viaBody = await call('POST', `/transfers/${d.transferId}/receipt`, undefined, { holderKey: d.lab, attestationId: id });
  assert.equal(viaBody.status, 200, JSON.stringify(viaBody.json));
  assert.equal((await call('POST', `/transfers/${d.transferId}/receipt`, undefined, { holderKey: d.sender, attestationId: id })).status, 403);
  assert.equal((await call('POST', `/transfers/${d.transferId}/receipt`, d.lab, { holderKey: key(), attestationId: id })).status, 400);
  assert.equal((await call('POST', `/transfers/${d.transferId}/receipt`, undefined, { holderKey: 'short', attestationId: id })).status, 400);
  // The claimant in another spelling of their key is still the claimant.
  assert.equal((await attach(d, d.lab.toUpperCase(), id)).status, 200);
  // Unclaimed: nobody can.
  const sender = key();
  const o = await offer(sender, await plant(sender));
  assert.equal((await call('POST', `/transfers/${o.transferId}/receipt`, key(), { attestationId: id })).status, 409);
});

test('receipt: a stranger’s attestation, another delivery’s, or another plant’s cannot be attached', async () => {
  const d = await claimedDelivery();
  // Another lab's delivery of the SAME plant: same subject, another received record.
  const sibling = await claimedDelivery({ sender: d.sender, source: d.source });
  const siblingReceipt = await receiptFor(await generateKeypair(), sibling);
  const r1 = await attach(d, d.lab, siblingReceipt);
  assert.equal(r1.status, 400);
  assert.match(r1.json.error, /different delivery/);
  // A stranger's receipt for their own delivery of another plant.
  const elsewhere = await claimedDelivery();
  const strangers = await receiptFor(await generateKeypair(), elsewhere);
  const r2 = await attach(d, d.lab, strangers);
  assert.equal(r2.status, 400);
  assert.match(r2.json.error, /different plant/);
  // A stranger's key signing this delivery's received record against another plant.
  const mixedUp = await attest(await generateKeypair(), elsewhere.source.recordFingerprint, d.received.recordFingerprint);
  assert.equal((await attach(d, d.lab, mixedUp)).status, 400);
  // Not a receipt at all: a lab report over the same two values.
  const report = await attest(await generateKeypair(), d.source.recordFingerprint, d.received.recordFingerprint, 'laboratory-report');
  const r3 = await attach(d, d.lab, report);
  assert.equal(r3.status, 400);
  assert.match(r3.json.error, /chain-of-custody/);
  // Unknown, and malformed.
  assert.equal((await attach(d, d.lab, 'att_nope')).status, 404);
  assert.equal((await attach(d, d.lab, 'x'.repeat(201))).status, 400);
  assert.equal((await attach(d, d.lab, 42)).status, 400);
  // None of those was stored.
  assert.equal(db.prepare('SELECT receipt_attestation_id FROM transfers WHERE id = ?').get(d.transferId).receipt_attestation_id, null);
});

test('receipt: a withdrawn one is refused; a record not yet sealed has nothing to match', async () => {
  const d = await claimedDelivery();
  const kp = await generateKeypair();
  const id = await receiptFor(kp, d);
  const ret = await signRetraction({ attestationId: id, attesterPublicKey: kp.publicKey, reason: 'issued-in-error', retractedAt: new Date().toISOString() }, kp.privateKey);
  assert.equal((await call('POST', `/attestations/${id}/retract`, undefined, ret)).status, 200);
  const r = await attach(d, d.lab, id);
  assert.equal(r.status, 409);
  assert.match(r.json.error, /withdrawn/);

  // Claimed but not sealed: refused with a reason, and the claim itself carries it.
  const sender = key(), lab = key();
  const source = await plant(sender);
  const o = await offer(sender, source);
  const early = await attest(await generateKeypair(), source.recordFingerprint, 'ab'.repeat(32));
  const c = await call('POST', `/transfers/${o.transferId}/claim`, lab, { claimCode: o.claimCode, receiptAttestationId: early });
  assert.equal(c.status, 200, 'the claim is never refused over a receipt');
  assert.match(c.json.receiptError, /seal the received record first/);
  assert.equal(c.json.receiptAttestationId, undefined);
  assert.equal((await call('POST', `/transfers/${o.transferId}/receipt`, lab, { attestationId: early })).status, 409);
});

test('receipt: replaced only by another valid one from the same claimant', async () => {
  const d = await claimedDelivery();
  const kp = await generateKeypair();
  const first = await receiptFor(kp, d);
  const second = await receiptFor(kp, d);
  assert.equal((await attach(d, d.lab, first)).status, 200);
  assert.equal((await attach(d, d.lab, second)).status, 200);
  const stored = () => db.prepare('SELECT receipt_attestation_id FROM transfers WHERE id = ?').get(d.transferId).receipt_attestation_id;
  assert.equal(stored(), second);
  // An invalid one leaves the valid one in place; nobody else can replace it.
  const other = await claimedDelivery();
  assert.equal((await attach(d, d.lab, await receiptFor(kp, other))).status, 400);
  assert.equal((await attach(d, key(), first)).status, 403);
  assert.equal((await attach(d, d.sender, first)).status, 403);
  assert.equal(stored(), second);
  // Attaching the same one again is fine.
  assert.equal((await attach(d, d.lab, second)).status, 200);
});

// =====================================================================================
// 2-5. Lab results
// =====================================================================================

/** A database with just enough of the transfers table for the store's own checks. */
const bareDb = () => {
  const d = new Database(':memory:');
  d.exec('CREATE TABLE transfers (id TEXT PRIMARY KEY, from_holder TEXT, claimed_by TEXT, received_record TEXT)');
  return d;
};
const claimed = (d, sender, lab) => {
  const id = `TR-${randomBytes(4).toString('hex').toUpperCase()}`;
  d.prepare('INSERT INTO transfers (id, from_holder, claimed_by) VALUES (?, ?, ?)').run(id, storedHolderKey(sender), storedHolderKey(lab));
  return id;
};

test('2: a copy of the database started against the live folder deletes nothing live', () => {
  const dir = mkdtempSync(join(tmpdir(), 'lab-results-r3-'));
  try {
    const live = bareDb();
    const sender = key(), lab = key();
    const tid = claimed(live, sender, lab);
    const r = createLabResults(live, { files: folderFiles(dir) });
    const before = r.add({ transferId: tid, holder: lab, bytes: ageFile() }).id;
    // The copy: same store id, so the folder guard lets it in.
    const copy = new Database(live.serialize());
    // Written by the live database after the copy was made, and one being written now.
    const after = r.add({ transferId: claimed(live, sender, lab), holder: lab, bytes: ageFile() }).id;
    const inFlight = `${after}.tmp-ABCDEF`;
    writeFileSync(join(dir, inFlight), 'being written');
    const listing = () => readdirSync(dir).filter((n) => !n.startsWith('.')).sort();
    const was = listing();

    const c = createLabResults(copy, { files: folderFiles(dir) });
    assert.deepEqual(listing(), was, 'nothing deleted at start');
    c.sweep();
    assert.deepEqual(listing(), was, 'nor by its sweep');
    assert.deepEqual(was, [before, after, inFlight].sort());
    assert.ok(r.file({ transferId: tid, resultId: before, holder: sender }).bytes);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('3: one sender\u2019s deliveries can hold only so much, and the last 10% is kept for small senders', () => {
  const d = bareDb();
  const limits = {
    maxTotalBytes: 10_000, perSenderBytes: 3_500, reserveShare: 0.1, reserveSenderBytes: 1_500,
    perReceiverDailyBytes: Infinity, perReceiverDailyCount: Infinity,
  };
  const r = createLabResults(d, { limits });
  const add = (sender, lab, size) => r.add({ transferId: claimed(d, sender, lab), holder: lab, bytes: ageFile(size - HDR) });
  // The attack: a sender sending to a second key of their own, over and over.
  const greedy = key(), ownLab = key();
  const mine = [];
  for (let i = 0; i < 3; i++) mine.push(add(greedy, ownLab, 1_000).id);
  assert.ok(mine.every(Boolean));
  const over = add(greedy, ownLab, 1_000);
  assert.equal(over.code, 507);
  assert.match(over.error, /this breeder sent/);
  assert.equal(add(greedy.toUpperCase(), key(), 1_000).code, 507, 'another lab, the same sender in another spelling');
  // Others take the store to exactly 90%: 3,000 + 1,600 + 4,400.
  const medium = key();
  for (let i = 0; i < 2; i++) assert.ok(add(medium, key(), 800).id);
  for (let i = 0; i < 4; i++) assert.ok(add(key(), key(), 1_100).id);
  // Past 90%, only a sender who stays under 1,500 gets in, though the store has room.
  assert.deepEqual(add(medium, key(), 200), { error: 'storage full', code: 507 }, 'medium would reach 1,800');
  assert.ok(add(key(), key(), 300).id, 'a small sender still can');
  assert.ok(add(key(), key(), 600).id);
  assert.deepEqual(add(key(), key(), 200), { error: 'storage full', code: 507 }, 'and the total cap still holds');
  // A withdrawn result frees the sender's room.
  const t = d.prepare('SELECT transfer_id FROM lab_results WHERE id = ?').get(mine[0]).transfer_id;
  r.remove({ transferId: t, resultId: mine[0], holder: ownLab });
  assert.equal(d.prepare('SELECT COALESCE(SUM(size), 0) AS n FROM lab_results WHERE withdrawn_at IS NULL').get().n, 8_900);
  assert.ok(add(greedy, ownLab, 100).id, 'room again, under the total and its own cap');
});

test('3: LAB_RESULTS_MAX_BYTES_PER_SENDER is documented', () => {
  const readme = require('node:fs').readFileSync(new URL('../README.md', import.meta.url), 'utf8');
  assert.match(readme, /LAB_RESULTS_MAX_BYTES_PER_SENDER/);
});

test('4: replaces cannot name a withdrawn result (400)', async () => {
  const d = await claimedDelivery();
  const first = (await upload(d.transferId, d.lab, ageFile())).json.id;
  assert.equal((await call('DELETE', `/transfers/${d.transferId}/results/${first}`, d.lab)).status, 200);
  const r = await upload(d.transferId, d.lab, ageFile(), first);
  assert.equal(r.status, 400);
  assert.match(r.json.error, /withdrawn/);
  assert.equal((await upload(d.transferId, d.lab, ageFile())).status, 200, 'sent on its own, it is accepted');
});

test('5: the export says what happens to lab reports', async () => {
  const k = key();
  await plant(k);
  const out = (await call('GET', '/api/export', k)).json;
  assert.doesNotMatch(out.note, /lab files were never sent/i);
  assert.match(out.note, /stored here encrypted/);
  assert.match(out.note, /cannot read them/);
  assert.match(out.note, /180 days/);
});
