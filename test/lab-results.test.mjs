// Lab results (lineage/lab-results.mjs): only the receiver adds, only the sender reads,
// and nothing readable is ever stored. No network beyond this process.
//
// SPDX-License-Identifier: Apache-2.0

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { createHash, randomBytes } from 'node:crypto';
import { copyFileSync, mkdtempSync, readdirSync as readdirAll, readFileSync, rmSync, utimesSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import Database from 'better-sqlite3';
import { canonicalise, sha256Hex, newNonce, generateKeypair, signAttestation } from 'veilcore-records';
import { RESULT_LIMITS, createLabResults, folderFiles, memoryFiles } from '../lineage/lab-results.mjs';
import { untilReady, testBody, rememberSigner, labKeyProofHeader } from './helpers.mjs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

process.env.DB_PATH = ':memory:';
process.env.VEILCORE_OTS = 'off';
const require = createRequire(import.meta.url);
const { app } = require('../server.js');
const key = () => randomBytes(32).toString('hex');
/** A folder's result files and temporaries, without the store id file (.veilcore-store-id). */
const readdirSync = (dir) => readdirAll(dir).filter((n) => !n.startsWith('.'));

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
    headers: { 'content-type': 'application/json', ...(holder ? { 'x-holder-key': holder } : {}) },
    ...(body === undefined ? {} : { body: JSON.stringify(testBody(method, path, holder, body)) }),
  });
  return { status: res.status, json: await res.json() };
};
const upload = async (transferId, holder, bytes, attestationId, replaces) => {
  const params = new URLSearchParams({ ...(attestationId ? { attestationId } : {}), ...(replaces ? { replaces } : {}) });
  const q = params.size ? `?${params}` : '';
  const res = await fetch(`${base}/transfers/${transferId}/results${q}`, {
    method: 'POST',
    headers: { 'content-type': 'application/octet-stream', ...(holder ? { 'x-holder-key': holder } : {}), ...(attestationId ? await labKeyProofHeader(transferId, attestationId) : {}) },
    body: bytes,
  });
  return { status: res.status, json: await res.json() };
};
const ageFile = (n = 200) => Buffer.concat([Buffer.from('age-encryption.org/v1\n-> X25519 abc\n'), randomBytes(n)]);

/** A sender with a sealed record, an offer, and a lab that claimed it. */
const delivery = async () => {
  const committed = { breedingMethod: '', bredBy: 'B', dateCreated: '2026-01-01', loggedAt: '2026-01-01T00:00:00Z',
    nonce: newNonce(), notes: '', parents: [], photoFingerprints: [], refId: '', strainName: 'S' };
  const src = { id: `lr-${randomBytes(4).toString('hex')}`, ...committed, recordFingerprint: await sha256Hex(canonicalise(committed)) };
  const sender = key(), lab = key();
  assert.equal((await call('PUT', '/api/records', sender, [src])).status, 200);
  const o = await call('POST', '/transfers', sender, { sourceRecord: src.id, toHandle: 'lab@x' });
  return { sender, lab, transferId: o.json.transferId, claimCode: o.json.claimCode, fingerprint: src.recordFingerprint };
};
/** A lab report signature about `subjectCommitment`, posted as the site posts it; its id. */
const labSignature = async (kp, subjectCommitment, type = 'laboratory-report') => {
  const signed = await signAttestation({
    attestationId: `att_${randomBytes(8).toString('hex')}_ld1`, type, subjectCommitment, documentHash: createHash('sha256').update(randomBytes(8)).digest('hex'),
    hashAlgorithm: 'sha256', issuedAt: '2026-11-08T12:00:00Z', attester: { publicKey: kp.publicKey, displayName: 'Lab' },
  }, kp.privateKey);
  const r = await call('POST', '/attestations', null, signed);
  assert.equal(r.status, 200, JSON.stringify(r.json));
  rememberSigner(signed.attestationId, kp);
  return signed.attestationId;
};

test('the lab that received the delivery sends a locked result; the sender lists it and downloads exactly those bytes', async () => {
  const d = await delivery();
  assert.equal((await upload(d.transferId, d.lab, ageFile())).status, 409, 'not before it is received');
  assert.equal((await call('POST', `/transfers/${d.transferId}/claim`, d.lab, { claimCode: d.claimCode })).status, 200);

  const file = ageFile();
  const sig = await labSignature(await generateKeypair(), d.fingerprint);
  const up = await upload(d.transferId, d.lab, file, sig);
  assert.equal(up.status, 200);
  assert.match(up.json.id, /^LR-[0-9A-F]{32}$/);
  assert.equal(up.json.sha256, createHash('sha256').update(file).digest('hex'));

  for (const who of [d.sender, d.lab]) {
    const l = await call('GET', `/transfers/${d.transferId}/results`, who);
    assert.equal(l.status, 200);
    assert.deepEqual(l.json.results.map((r) => [r.id, r.size, r.attestationId, r.withdrawnAt, r.replaces]), [
      [up.json.id, file.length, sig, undefined, undefined],
    ]);
  }
  const res = await fetch(`${base}/transfers/${d.transferId}/results/${up.json.id}`, { headers: { 'x-holder-key': d.sender } });
  assert.equal(res.status, 200);
  assert.deepEqual(Buffer.from(await res.arrayBuffer()), file);
});

test('nobody else can add, list, download or remove', async () => {
  const d = await delivery();
  await call('POST', `/transfers/${d.transferId}/claim`, d.lab, { claimCode: d.claimCode });
  const stranger = key();
  assert.equal((await upload(d.transferId, stranger, ageFile())).status, 403);
  assert.equal((await upload(d.transferId, d.sender, ageFile())).status, 403, 'the sender cannot plant a result');
  assert.equal((await upload(d.transferId, undefined, ageFile())).status, 401);
  const { json } = await upload(d.transferId, d.lab, ageFile());
  assert.equal((await call('GET', `/transfers/${d.transferId}/results`, stranger)).status, 403);
  const get = (h) => fetch(`${base}/transfers/${d.transferId}/results/${json.id}`, { headers: { 'x-holder-key': h } });
  assert.equal((await get(stranger)).status, 403);
  assert.equal((await get(d.lab)).status, 403, 'the lab already has its own report');
  assert.equal((await call('DELETE', `/transfers/${d.transferId}/results/${json.id}`, stranger)).status, 403);
  assert.equal((await call('DELETE', `/transfers/${d.transferId}/results/${json.id}`, d.sender)).status, 200);
  assert.deepEqual((await call('GET', `/transfers/${d.transferId}/results`, d.sender)).json.results, []);
});

test('a readable file is refused: only locked (age) files are stored', async () => {
  const d = await delivery();
  await call('POST', `/transfers/${d.transferId}/claim`, d.lab, { claimCode: d.claimCode });
  const pdf = Buffer.concat([Buffer.from('%PDF-1.7\n'), randomBytes(100)]);
  const r = await upload(d.transferId, d.lab, pdf);
  assert.equal(r.status, 400);
  assert.match(r.json.error, /locked/);
  assert.equal((await upload(d.transferId, d.lab, Buffer.alloc(0))).status, 400);
  assert.equal((await upload(d.transferId, d.lab, ageFile(), 'bad id with spaces')).status, 400);
});

test('size and count limits hold', async () => {
  const d = await delivery();
  await call('POST', `/transfers/${d.transferId}/claim`, d.lab, { claimCode: d.claimCode });
  assert.equal((await upload(d.transferId, d.lab, ageFile(RESULT_LIMITS.maxBytes))).status, 413);
  for (let i = 0; i < RESULT_LIMITS.perTransfer; i++) assert.equal((await upload(d.transferId, d.lab, ageFile())).status, 200);
  assert.equal((await upload(d.transferId, d.lab, ageFile())).status, 409);
  assert.equal((await call('GET', `/transfers/T-NOPE/results`, d.sender)).status, 404);
});

test('the lab can withdraw a result: the file goes, the breeder still sees that it was withdrawn', async () => {
  const d = await delivery();
  await call('POST', `/transfers/${d.transferId}/claim`, d.lab, { claimCode: d.claimCode });
  const { json } = await upload(d.transferId, d.lab, ageFile());
  const w = await call('DELETE', `/transfers/${d.transferId}/results/${json.id}`, d.lab);
  assert.equal(w.status, 200);
  assert.equal(w.json.withdrawn, true);
  const [line] = (await call('GET', `/transfers/${d.transferId}/results`, d.sender)).json.results;
  assert.equal(line.id, json.id);
  assert.equal(typeof line.withdrawnAt, 'number');
  const res = await fetch(`${base}/transfers/${d.transferId}/results/${json.id}`, { headers: { 'x-holder-key': d.sender } });
  assert.equal(res.status, 410);
  assert.match((await res.json()).error, /withdrew/);
  // Withdrawing twice is fine; the sender can still clear the line away.
  assert.equal((await call('DELETE', `/transfers/${d.transferId}/results/${json.id}`, d.lab)).status, 200);
  assert.equal((await call('DELETE', `/transfers/${d.transferId}/results/${json.id}`, d.sender)).status, 200);
  assert.deepEqual((await call('GET', `/transfers/${d.transferId}/results`, d.sender)).json.results, []);
});

test('a corrected result names the one it replaces, which must be on the same delivery', async () => {
  const d = await delivery();
  await call('POST', `/transfers/${d.transferId}/claim`, d.lab, { claimCode: d.claimCode });
  const first = (await upload(d.transferId, d.lab, ageFile())).json;
  const fixed = await upload(d.transferId, d.lab, ageFile(), undefined, first.id);
  assert.equal(fixed.status, 200);
  await call('DELETE', `/transfers/${d.transferId}/results/${first.id}`, d.lab);
  const list = (await call('GET', `/transfers/${d.transferId}/results`, d.sender)).json.results;
  assert.deepEqual(list.map((r) => [r.id, r.replaces, !!r.withdrawnAt]), [[first.id, undefined, true], [fixed.json.id, first.id, false]]);

  // Not a result on this delivery: refused.
  const other = await delivery();
  await call('POST', `/transfers/${other.transferId}/claim`, other.lab, { claimCode: other.claimCode });
  const elsewhere = (await upload(other.transferId, other.lab, ageFile())).json;
  assert.equal((await upload(d.transferId, d.lab, ageFile(), undefined, elsewhere.id)).status, 400);
  assert.equal((await upload(d.transferId, d.lab, ageFile(), undefined, `LR-${'0'.repeat(32)}`)).status, 400);
  assert.equal((await upload(d.transferId, d.lab, ageFile(), undefined, 'nonsense')).status, 400);
});

test('a sender cannot claim their own delivery code', async () => {
  const d = await delivery();
  const r = await call('POST', `/transfers/${d.transferId}/claim`, d.sender, { claimCode: d.claimCode });
  assert.equal(r.status, 409);
  assert.equal(r.json.error, 'This is your own code. Send it to the lab instead.');
  // The lab still can.
  assert.equal((await call('POST', `/transfers/${d.transferId}/claim`, d.lab, { claimCode: d.claimCode })).status, 200);
});

// ---- the store itself, without the server ----

/** A database with just enough of the transfers table for these checks. */
const bareDb = () => {
  const db = new Database(':memory:');
  db.exec('CREATE TABLE transfers (id TEXT PRIMARY KEY, from_holder TEXT, claimed_by TEXT, received_record TEXT)');
  return db;
};
const claimed = (db, sender, lab, id = `TR-${randomBytes(4).toString('hex').toUpperCase()}`) => {
  db.prepare('INSERT INTO transfers (id, from_holder, claimed_by) VALUES (?, ?, ?)').run(id, sender, lab);
  return id;
};

test('locked files are kept in a folder, not in the database, and written whole', () => {
  const dir = mkdtempSync(join(tmpdir(), 'lab-results-'));
  try {
    const db = bareDb();
    const sender = key(), lab = key();
    const tid = claimed(db, sender, lab);
    const r = createLabResults(db, { files: folderFiles(dir) });
    const file = ageFile(5000);
    const { id } = r.add({ transferId: tid, holder: lab, bytes: file });
    assert.deepEqual(readdirSync(dir), [id], 'one file, named by its id, no temporary left behind');
    assert.deepEqual(readFileSync(join(dir, id)), file);
    const cols = db.prepare("SELECT name FROM pragma_table_info('lab_results')").all().map((c) => c.name);
    assert.equal(cols.includes('ciphertext'), false);
    assert.ok(!db.serialize().includes(file.subarray(40, 200)), 'the file bytes are not in the database');
    assert.deepEqual(r.file({ transferId: tid, resultId: id, holder: sender }).bytes, file);

    // The lab withdraws: the file is deleted.
    r.remove({ transferId: tid, resultId: id, holder: lab });
    assert.deepEqual(readdirSync(dir), []);

    // A file whose row is missing, and a half-written temporary, are cleared at start, but
    // only once old enough that they can't be live (round 3): 180 days, and an hour.
    const second = r.add({ transferId: tid, holder: lab, bytes: ageFile() }).id;
    const stray = join(dir, `LR-${'A'.repeat(32)}`), half = join(dir, `${second}.tmp-ABC`);
    writeFileSync(stray, 'stray');
    writeFileSync(half, 'half');
    createLabResults(db, { files: folderFiles(dir) });
    assert.deepEqual(readdirSync(dir).sort(), [stray, half, join(dir, second)].map((p) => p.slice(dir.length + 1)).sort(), 'young: kept');
    const ago = (ms) => (Date.now() - ms) / 1000;
    utimesSync(stray, ago(RESULT_LIMITS.keepMs - 86_400_000), ago(RESULT_LIMITS.keepMs - 86_400_000));
    utimesSync(half, ago(RESULT_LIMITS.staleTempMs - 60_000), ago(RESULT_LIMITS.staleTempMs - 60_000));
    createLabResults(db, { files: folderFiles(dir) });
    assert.equal(readdirSync(dir).length, 3, 'a day short of 180 days, and a minute short of an hour: still kept');
    utimesSync(stray, ago(RESULT_LIMITS.keepMs + 86_400_000), ago(RESULT_LIMITS.keepMs + 86_400_000));
    utimesSync(half, ago(RESULT_LIMITS.staleTempMs + 60_000), ago(RESULT_LIMITS.staleTempMs + 60_000));
    createLabResults(db, { files: folderFiles(dir) });
    assert.deepEqual(readdirSync(dir), [second]);

    // A lost file says so plainly.
    rmSync(join(dir, second));
    const lost = r.file({ transferId: tid, resultId: second, holder: sender });
    assert.equal(lost.code, 410);
    assert.match(lost.error, /send it again/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a database from the first version, with files inside it, has them moved out', () => {
  const dir = mkdtempSync(join(tmpdir(), 'lab-results-'));
  try {
    const db = bareDb();
    const sender = key(), lab = key();
    const tid = claimed(db, sender, lab);
    db.exec(`CREATE TABLE lab_results (id TEXT PRIMARY KEY, transfer_id TEXT NOT NULL, ciphertext BLOB NOT NULL,
      size INTEGER NOT NULL, sha256 TEXT NOT NULL, attestation_id TEXT, created_at INTEGER NOT NULL)`);
    const file = ageFile();
    const id = `LR-${'B'.repeat(32)}`;
    db.prepare('INSERT INTO lab_results VALUES (?, ?, ?, ?, ?, ?, ?)').run(id, tid, file, file.length, 'x', null, Date.now());
    const r = createLabResults(db, { files: folderFiles(dir) });
    assert.deepEqual(readFileSync(join(dir, id)), file);
    assert.equal(db.prepare("SELECT 1 FROM pragma_table_info('lab_results') WHERE name = 'ciphertext'").get(), undefined);
    assert.deepEqual(r.file({ transferId: tid, resultId: id, holder: sender }).bytes, file);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('results are deleted after 180 days, file and all', () => {
  let t = 10_000_000;
  const files = memoryFiles();
  const db = bareDb();
  const sender = key(), lab = key();
  const tid = claimed(db, sender, lab);
  const r = createLabResults(db, { files, now: () => t });
  const { id } = r.add({ transferId: tid, holder: lab, bytes: ageFile() });
  t += RESULT_LIMITS.keepMs - 1;
  assert.equal(r.sweep(), 0);
  assert.equal(r.list({ transferId: tid, holder: sender }).results.length, 1);
  t += 2;
  assert.equal(r.file({ transferId: tid, resultId: id, holder: sender }).code, 404, 'past its time: gone even before the sweep');
  assert.equal(r.sweep(), 1);
  assert.deepEqual(r.list({ transferId: tid, holder: sender }).results, []);
  assert.deepEqual(files.ids(), []);
});

test('storage full: past the total cap uploads get 507; a withdrawn result frees its space', () => {
  const db = bareDb();
  const sender = key(), lab = key();
  const tid = claimed(db, sender, lab);
  const r = createLabResults(db, { limits: { maxTotalBytes: 1000 } });
  const a = r.add({ transferId: tid, holder: lab, bytes: ageFile(600) });
  assert.ok(a.id);
  assert.deepEqual(r.add({ transferId: tid, holder: lab, bytes: ageFile(600) }), { error: 'storage full', code: 507 });
  r.remove({ transferId: tid, resultId: a.id, holder: lab });
  assert.ok(r.add({ transferId: tid, holder: lab, bytes: ageFile(600) }).id);
});

test('each lab has a daily allowance, by count and by size', () => {
  let t = 50_000_000;
  const db = bareDb();
  const sender = key(), lab = key();
  const r = createLabResults(db, { now: () => t, limits: { perReceiverDailyCount: 3, perReceiverDailyBytes: 10_000 } });
  const add = (n = 100) => r.add({ transferId: claimed(db, sender, lab), holder: lab, bytes: ageFile(n) });
  for (let i = 0; i < 3; i++) assert.ok(add().id);
  assert.equal(add().code, 429, 'a fourth file within the day');
  t += 86_400_001;
  assert.ok(add().id, 'the next day');
  assert.equal(add(20_000).code, 429, 'over the day’s bytes');
  // Another lab is not affected.
  const otherLab = key();
  assert.ok(r.add({ transferId: claimed(db, sender, otherLab), holder: otherLab, bytes: ageFile() }).id);
});

test('withdrawn results do not use up the delivery’s five, but there is still an end', () => {
  const db = bareDb();
  const sender = key(), lab = key();
  const tid = claimed(db, sender, lab);
  const r = createLabResults(db, { limits: { perTransfer: 2, rowsPerTransfer: 4 } });
  const a = r.add({ transferId: tid, holder: lab, bytes: ageFile() }).id;
  r.add({ transferId: tid, holder: lab, bytes: ageFile() });
  assert.equal(r.add({ transferId: tid, holder: lab, bytes: ageFile() }).code, 409);
  r.remove({ transferId: tid, resultId: a, holder: lab });
  const c = r.add({ transferId: tid, holder: lab, bytes: ageFile() }).id;
  assert.ok(c);
  r.remove({ transferId: tid, resultId: c, holder: lab });
  assert.ok(r.add({ transferId: tid, holder: lab, bytes: ageFile() }).id); // the fourth row
  assert.equal(r.add({ transferId: tid, holder: lab, bytes: ageFile() }).code, 409);
});

test('the registry keeps result files out of the database it backs up', () => {
  // backup.mjs refuses a database over 128 MB. Fifteen 15 MB reports would pass that; kept
  // as files, they leave the database the size of its rows.
  const db = bareDb();
  const sender = key(), lab = key();
  const r = createLabResults(db, { limits: { perReceiverDailyBytes: Infinity, perReceiverDailyCount: Infinity } });
  for (let i = 0; i < 12; i++) {
    const tid = claimed(db, sender, lab);
    assert.ok(r.add({ transferId: tid, holder: lab, bytes: ageFile(RESULT_LIMITS.maxBytes - 100) }).id);
  }
  assert.ok(db.serialize().length < 1024 * 1024, `database is ${db.serialize().length} bytes`);
});

test('the sender sees which record the lab\u2019s claim created; nobody else does', async () => {
  const d = await delivery();
  const sent = async () => (await call('GET', '/transfers/sent', d.sender)).json.transfers.find((t) => t.id === d.transferId);
  assert.equal((await sent()).received_record, null, 'not claimed yet');
  const claim = await call('POST', `/transfers/${d.transferId}/claim`, d.lab, { claimCode: d.claimCode });
  assert.equal(claim.status, 200);
  const recordId = claim.json.recordId;
  assert.match(recordId, /^VEIL-/);
  assert.equal((await sent()).received_record, recordId);
  // The lab's own sent list never holds this delivery.
  assert.equal((await call('GET', '/transfers/sent', d.lab)).json.transfers.some((t) => t.id === d.transferId), false);

  await upload(d.transferId, d.lab, ageFile());
  const forSender = await call('GET', `/transfers/${d.transferId}/results`, d.sender);
  assert.equal(forSender.json.receivedRecord, recordId);
  const forLab = await call('GET', `/transfers/${d.transferId}/results`, d.lab);
  assert.equal(forLab.status, 200);
  assert.equal('receivedRecord' in forLab.json, false, 'only the sender is told');
  assert.equal((await call('GET', `/transfers/${d.transferId}/results`, key())).status, 403);
});

test('a results folder belongs to one database: a second one pointed at it is refused and deletes nothing', () => {
  const dir = mkdtempSync(join(tmpdir(), 'lab-results-'));
  try {
    const first = bareDb();
    const sender = key(), lab = key();
    const tid = claimed(first, sender, lab);
    const r = createLabResults(first, { files: folderFiles(dir) });
    const { id } = r.add({ transferId: tid, holder: lab, bytes: ageFile() });
    const inFlight = join(dir, `${id}.tmp-FFFF`);
    writeFileSync(inFlight, 'being written by the first');

    const second = bareDb();
    assert.throws(() => createLabResults(second, { files: folderFiles(dir) }), /another database/);
    assert.deepEqual(readdirSync(dir).sort(), [id, `${id}.tmp-FFFF`].sort(), 'its files and its temporary are untouched');

    // The same database (a restart) is fine, and so is a fresh folder for the second.
    createLabResults(first, { files: folderFiles(dir) });
    assert.ok(r.file({ transferId: tid, resultId: id, holder: sender }).bytes);
    const other = mkdtempSync(join(tmpdir(), 'lab-results-'));
    try {
      createLabResults(second, { files: folderFiles(other) });
    } finally {
      rmSync(other, { recursive: true, force: true });
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('the move out of the database survives being stopped halfway, and leaves the database small', () => {
  // The store is in memory: what is tested is the move, not the folder (the tests above and
  // the cut-short write below are the folder's). On disk this wrote 45 MB to the system's
  // temporary folder each run, and failed for want of space rather than for a fault.
  const db = bareDb();
  const sender = key(), lab = key();
  const tid = claimed(db, sender, lab);
  db.exec(`CREATE TABLE lab_results (id TEXT PRIMARY KEY, transfer_id TEXT NOT NULL, ciphertext BLOB NOT NULL,
    size INTEGER NOT NULL, sha256 TEXT NOT NULL, attestation_id TEXT, created_at INTEGER NOT NULL)`);
  const blobs = ['C', 'D', 'E'].map((c) => [`LR-${c.repeat(32)}`, ageFile(15 * 1024 * 1024)]);
  for (const [id, file] of blobs) {
    db.prepare('INSERT INTO lab_results VALUES (?, ?, ?, ?, ?, ?, ?)').run(id, tid, file, file.length, 'x', null, Date.now());
  }
  // The second write fails (a full disk, a stop): nothing is lost, the files stay in the database.
  const real = memoryFiles();
  let writes = 0;
  const failing = { ...real, put: (id, b) => { if (++writes === 2) throw new Error('disk full'); real.put(id, b); } };
  assert.throws(() => createLabResults(db, { files: failing }), /disk full/);
  assert.ok(db.prepare("SELECT 1 FROM pragma_table_info('lab_results') WHERE name = 'ciphertext'").get());
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM lab_results').get().n, 3);

  // The next start moves them all and gives the space back (backup.mjs measures the file).
  const r = createLabResults(db, { files: real });
  for (const [id, file] of blobs) assert.deepEqual(r.file({ transferId: tid, resultId: id, holder: sender }).bytes, file);
  const size = db.pragma('page_count', { simple: true }) * db.pragma('page_size', { simple: true });
  assert.ok(size < 1024 * 1024, `database is ${size} bytes after the move`);
});

test('a write the disk cuts short is not kept: no file under the result\u2019s name, no temporary', { skip: process.platform === 'win32' && 'needs a POSIX shell for ulimit' }, () => {
  // A full disk lets one write() put down part of a file and return without an error; the
  // next one fails. A file-size limit does the same, so the child runs under one (1024
  // blocks: 512 KB or 1 MB, by the shell) and stores a 4 MB file.
  const dir = mkdtempSync(join(tmpdir(), 'lab-results-short-'));
  try {
    const child = fileURLToPath(new URL('./fixtures/short-write-child.mjs', import.meta.url));
    const out = execFileSync('/bin/sh', ['-c', 'ulimit -f 1024 && exec "$0" "$@"', process.execPath, child, dir], { encoding: 'utf8' });
    const r = JSON.parse(out.trim().split('\n').pop());
    assert.match(r.error ?? '', /EFBIG|ENOSPC/, `the store said it was written: ${out}`);
    assert.deepEqual(r.left, [], 'nothing left in the folder');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('result ids from the request never reach the file system unchecked', () => {
  const dir = mkdtempSync(join(tmpdir(), 'lab-results-'));
  try {
    const f = folderFiles(dir);
    for (const bad of ['../x', `LR-${'A'.repeat(32)}/../../etc`, `lr-${'a'.repeat(32)}`, '.veilcore-store-id']) {
      assert.throws(() => f.get(bad), /bad result id/);
      assert.throws(() => f.remove(bad), /bad result id/);
      assert.throws(() => f.put(bad, Buffer.from('x')), /bad result id/);
    }
    const db = bareDb();
    const sender = key(), lab = key();
    const tid = claimed(db, sender, lab);
    const r = createLabResults(db, { files: f });
    assert.equal(r.file({ transferId: tid, resultId: '../../etc/passwd', holder: sender }).code, 404);
    assert.equal(r.remove({ transferId: tid, resultId: '../.veilcore-store-id', holder: sender }).code, 404);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
