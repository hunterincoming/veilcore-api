// The registry's own seal timer, the `ots-behind` alert and the second Bitcoin explorer
// (reliability audit, 19 Nov 2026, Tier 1 items 3b, 5 and 7).
//
// The point of the timer: with the sponsor down (nobody calls POST /batches/seal), new records
// are still sealed, stamped on Bitcoin and timestamped by the TSA. The last test runs the real
// server with no sponsor at all and shows that. Calendars and explorers are never contacted:
// global fetch answers for them; the TSA is a local openssl one on 127.0.0.1.
//
// SPDX-License-Identifier: Apache-2.0

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { createHash, X509Certificate } from 'node:crypto';
import { createServer } from 'node:http';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { canonicalise, sha256Hex, newNonce } from 'veilcore-records';
import { createBatches } from '../lineage/batches.mjs';
import { checkBitcoinBlockAgreed, explorersFrom, DEFAULT_EXPLORERS, upgradeAnswer, rootDigest } from '../lineage/ots.mjs';
import { untilReady, waitFor, testBody } from './helpers.mjs';

const require = createRequire(import.meta.url);
const Database = require('better-sqlite3');
const { sealTimerSettings, createSealTimer } = require('../seal-timer.js');

const sha = (b) => createHash('sha256').update(b).digest();
const H = (name) => sha(name).toString('hex');

/** An in-memory registry database with `n` pending records. */
const memory = (n = 0) => {
  const db = new Database(':memory:');
  db.exec('CREATE TABLE records (id TEXT PRIMARY KEY, body TEXT)');
  const batches = createBatches(db);
  const add = (k) => db.prepare('INSERT INTO records VALUES (?, ?)').run(`r${k}`, JSON.stringify({ recordFingerprint: H(`rec-${k}-${Math.random()}`) }));
  for (let k = 0; k < n; k++) add(k);
  let next = n;
  return { db, batches, add: (m = 1) => { for (let i = 0; i < m; i++) add(next++); } };
};

// ---- settings --------------------------------------------------------------------------

test('settings: off unless VEILCORE_SEAL_TIMER=on; the sponsor’s numbers by default; a bad setting keeps it off', () => {
  assert.deepEqual(sealTimerSettings({}), { on: false, everyMs: 3_600_000, atPending: 25, checkMs: 300_000, problems: [] });
  assert.equal(sealTimerSettings({ VEILCORE_SEAL_TIMER: 'on' }).on, true);
  assert.equal(sealTimerSettings({ VEILCORE_SEAL_TIMER: 'off' }).on, false);
  const odd = sealTimerSettings({ VEILCORE_SEAL_TIMER: 'yes' });
  assert.equal(odd.on, false);
  assert.match(odd.problems[0], /on or off/);
  const bad = sealTimerSettings({ VEILCORE_SEAL_TIMER: 'on', VEILCORE_SEAL_EVERY_MINUTES: '1' });
  assert.equal(bad.on, false, 'a minute is under the five-minute floor: off, said why');
  assert.match(bad.problems[0], /VEILCORE_SEAL_EVERY_MINUTES/);
  const set = sealTimerSettings({ VEILCORE_SEAL_TIMER: 'on', VEILCORE_SEAL_EVERY_MINUTES: '30', VEILCORE_SEAL_AT_PENDING: '5', VEILCORE_SEAL_CHECK_MS: '60000' });
  assert.deepEqual(set, { on: true, everyMs: 1_800_000, atPending: 5, checkMs: 60_000, problems: [] });
});

// ---- when it seals ---------------------------------------------------------------------

test('seals when due: nothing pending is nothing; under the count and inside the hour waits; past either seals', async () => {
  const m = memory();
  let t = 1_800_000_000_000;
  const sealed = [];
  const timer = createSealTimer({ batches: m.batches, db: m.db, everyMs: 3_600_000, atPending: 3, now: () => t, afterSeal: (id) => sealed.push(id) });
  assert.deepEqual(await timer.sealIfDue(), { sealed: false, pending: 0 });

  // No batch yet: the first pending record is due at once.
  m.add(1);
  const first = await timer.sealIfDue();
  assert.equal(first.sealed, true, JSON.stringify(first));
  assert.equal(first.recordCount, 1);
  assert.deepEqual(sealed, [first.batchId], 'afterSeal (the TSA run) once per seal');

  // The newest batch's sealing time is the clock, read from the database.
  t = m.db.prepare('SELECT MAX(sealed_at) AS t FROM batches').get().t + 10 * 60_000;
  m.add(2);
  const wait = await timer.sealIfDue();
  assert.equal(wait.sealed, false);
  assert.equal(wait.notDue, true);
  assert.equal(wait.pending, 2);
  m.add(1); // three pending: the count is reached
  const byCount = await timer.sealIfDue();
  assert.equal(byCount.sealed, true);
  assert.equal(byCount.recordCount, 3);

  t = m.db.prepare('SELECT MAX(sealed_at) AS t FROM batches').get().t + 59 * 60_000;
  m.add(1);
  assert.equal((await timer.sealIfDue()).sealed, false, 'one record, 59 minutes: not yet');
  t += 60_000;
  assert.equal((await timer.sealIfDue()).sealed, true, 'the hour is up');
  assert.equal(sealed.length, 3);
});

test('a restart, or a batch the sponsor sealed, counts: the hour runs from the newest batch in the database', async () => {
  const m = memory(1);
  const sponsorSealed = await m.batches.seal(); // as the sponsor's POST /batches/seal would
  assert.ok(sponsorSealed.batchId);
  const t = m.db.prepare('SELECT MAX(sealed_at) AS t FROM batches').get().t + 5 * 60_000;
  // A fresh timer, as after a restart.
  const timer = createSealTimer({ batches: m.batches, db: m.db, everyMs: 3_600_000, atPending: 25, now: () => t });
  m.add(1);
  const out = await timer.sealIfDue();
  assert.equal(out.sealed, false);
  assert.equal(out.notDue, true);
  assert.equal(out.nextSealAt, new Date(t - 5 * 60_000 + 3_600_000).toISOString());
});

test('exactly once: the timer and the sponsor’s seal call at the same moment make one batch, never two, never a 409', async () => {
  const m = memory(40);
  const timer = createSealTimer({ batches: m.batches, db: m.db, everyMs: 3_600_000, atPending: 1 });
  // Twenty callers at once: the timer's tick and the operator route share sealIfDue.
  const outs = await Promise.all(Array.from({ length: 20 }, () => timer.sealIfDue()));
  const sealed = outs.filter((o) => o.sealed);
  assert.equal(sealed.length, 1, JSON.stringify(outs));
  assert.equal(sealed[0].recordCount, 40);
  assert.ok(outs.every((o) => o.sealed || (o.pending === 0 && !o.error)), 'the rest found nothing pending, none was refused');
  assert.equal(m.db.prepare('SELECT COUNT(*) AS n FROM batch_proofs').get().n, 40);
  assert.equal(m.db.prepare('SELECT COUNT(DISTINCT batch_id) AS n FROM batch_proofs').get().n, 1);
});

test('one failed seal does not stop the next; afterSeal failing never undoes a seal', async () => {
  const m = memory(1);
  let boom = true;
  const real = m.batches.seal.bind(m.batches);
  const batches = Object.assign(Object.create(m.batches), {
    pending: () => m.batches.pending(),
    seal: async () => { if (boom) throw new Error('disk full'); return real(); },
  });
  const logs = [];
  const timer = createSealTimer({ batches, db: m.db, atPending: 1, afterSeal: () => { throw new Error('TSA down'); }, log: (l, msg) => logs.push(msg) });
  const failed = await timer.sealIfDue();
  assert.deepEqual(failed, { sealed: false, error: 'the seal failed', code: 500 });
  assert.equal(timer.status().lastError, 'the seal failed');
  boom = false;
  const ok = await timer.sealIfDue();
  assert.equal(ok.sealed, true);
  assert.equal(timer.status().lastError, null);
  assert.equal(timer.status().lastSealedBatch, ok.batchId);
});

test('batches are anchored oldest first: sealed while the sponsor is down, they wait in order for it', async () => {
  const m = memory();
  let t = 1_800_000_000_000;
  const timer = createSealTimer({ batches: m.batches, db: m.db, everyMs: 3_600_000, atPending: 1000, now: () => t });
  const ids = [];
  for (let h = 0; h < 4; h++) {
    m.add(1);
    t = (m.db.prepare('SELECT MAX(sealed_at) AS t FROM batches').get().t ?? 0) + 3_600_000;
    ids.push((await timer.sealIfDue()).batchId);
    await new Promise((r) => setTimeout(r, 2)); // distinct sealing times
  }
  // What the sponsor reads (GET /batches, the whole list) and how it picks (anchorer.ts pickBatch:
  // unanchored, sorted by sealed_at, the first).
  const waiting = m.batches.list().filter((b) => !b.anchor).sort((a, b) => a.sealed_at - b.sealed_at).map((b) => b.batch_id);
  assert.deepEqual(waiting, ids);
});

// ---- ots-behind --------------------------------------------------------------------------

test('ots-behind: a batch sent for a Bitcoin stamp over a day ago and still not in a block; not one never sent, nor older than a week', () => {
  const m = memory();
  const now = 1_800_000_000_000;
  const put = (id, status, hoursAgo) => m.db.prepare('INSERT INTO batches (batch_id, root, sealed_at, record_count, ots_status) VALUES (?,?,?,?,?)')
    .run(id, H(id), now - hoursAgo * 3_600_000, 1, status);
  put('B-BTC', 'bitcoin', 48);
  put('B-OFF', null, 48);
  put('B-YOUNG', 'pending', 23);
  put('B-OLD', 'pending', 8 * 24);
  assert.equal(m.batches.otsBehind(now), false);
  put('B-LATE', 'pending', 25);
  assert.equal(m.batches.otsBehind(now), true);
  m.db.prepare("UPDATE batches SET ots_status = 'bitcoin' WHERE batch_id = 'B-LATE'").run();
  assert.equal(m.batches.otsBehind(now), false);
  for (const s of ['requested', 'failed']) {
    put(`B-${s}`, s, 30);
    assert.equal(m.batches.otsBehind(now), true, s);
    m.db.prepare('DELETE FROM batches WHERE batch_id = ?').run(`B-${s}`);
  }
});

// ---- two Bitcoin explorers ---------------------------------------------------------------

const headerFor = (merkleRoot, time) => {
  const h = Buffer.alloc(80);
  h.writeUInt32LE(0x20000000, 0);
  merkleRoot.copy(h, 36);
  h.writeUInt32LE(time, 68);
  return h;
};
const hashOf = (h) => Buffer.from(sha(sha(h))).reverse().toString('hex');
/** An Esplora explorer per host: { height: header } or 'down'. */
const explorers = (byHost) => async (url) => {
  const { host, pathname } = new URL(url);
  const known = byHost[host];
  if (known === 'down' || known === undefined) throw new TypeError('fetch failed');
  const bh = /\/block-height\/(\d+)$/.exec(pathname);
  if (bh && known[bh[1]]) return new Response(hashOf(known[bh[1]]));
  const hd = /\/block\/([0-9a-f]{64})\/header$/.exec(pathname);
  if (hd) for (const h of Object.values(known)) if (hashOf(h) === hd[1]) return new Response(h.toString('hex'));
  return new Response('not found', { status: 404 });
};
const E = ['https://blockstream.info/api', 'https://mempool.space/api'];

test('explorers: blockstream.info and mempool.space by default; a list from VEILCORE_BTC_EXPLORER; never none', () => {
  assert.deepEqual(DEFAULT_EXPLORERS, E);
  assert.deepEqual(explorersFrom(undefined), E);
  assert.deepEqual(explorersFrom(''), E);
  assert.deepEqual(explorersFrom('https://one.example/api'), ['https://one.example/api'], 'one address: only that one, as before');
  assert.deepEqual(explorersFrom(' https://a.example/api/ , https://b.example/api,https://a.example/api'), ['https://a.example/api', 'https://b.example/api']);
  assert.deepEqual(explorersFrom('http://plain.example/api'), E, 'not https: left out, and the defaults rather than none');
});

test('a block is believed only when both explorers give the same header holding the root; one lying is a mismatch, one down waits', async () => {
  const root = sha('merkle');
  const good = headerFor(root, 1_790_000_000);
  const lie = headerFor(sha('other'), 1_790_000_000);
  const both = await checkBitcoinBlockAgreed(976_480, root, { explorers: E, fetchImpl: explorers({ 'blockstream.info': { 976480: good }, 'mempool.space': { 976480: good } }) });
  assert.equal(both.height, 976_480);
  assert.equal(both.time, new Date(1_790_000_000 * 1000).toISOString());
  assert.deepEqual(both.explorers, ['blockstream.info', 'mempool.space']);

  await assert.rejects(
    checkBitcoinBlockAgreed(976_480, root, { explorers: E, fetchImpl: explorers({ 'blockstream.info': { 976480: good }, 'mempool.space': { 976480: lie } }) }),
    (e) => e.mismatch === true && /mempool\.space/.test(e.message),
  );
  // One down never hides the other's lie.
  await assert.rejects(
    checkBitcoinBlockAgreed(976_480, root, { explorers: E, fetchImpl: explorers({ 'blockstream.info': 'down', 'mempool.space': { 976480: lie } }) }),
    (e) => e.mismatch === true,
  );
  // One down, the other honest: not believed yet, and not a mismatch either (asked again later).
  await assert.rejects(
    checkBitcoinBlockAgreed(976_480, root, { explorers: E, fetchImpl: explorers({ 'blockstream.info': { 976480: good }, 'mempool.space': 'down' }) }),
    (e) => e.mismatch === undefined && /mempool\.space gave no usable header/.test(e.message),
  );
  // Two headers that both hold the root but are different blocks: not believed.
  const other = headerFor(root, 1_790_000_600);
  await assert.rejects(
    checkBitcoinBlockAgreed(976_480, root, { explorers: E, fetchImpl: explorers({ 'blockstream.info': { 976480: good }, 'mempool.space': { 976480: other } }) }),
    (e) => e.mismatch === undefined && /disagree/.test(e.message),
  );
});

test('an upgrade with a lying second explorer stays pending: the proof is not marked as in Bitcoin', async () => {
  // A stored calendar answer: append(nonce), sha256, pending attestation for the calendar.
  const vu = (n) => { const o = []; do { let b = n % 128; n = Math.floor(n / 128); if (n > 0) b |= 0x80; o.push(b); } while (n > 0); return Buffer.from(o); };
  const cal = 'https://alice.btc.calendar.opentimestamps.org';
  const pendingAtt = Buffer.concat([Buffer.from([0x00]), Buffer.from('83dfe30d2ef90c8e', 'hex'), vu(cal.length + 1), vu(cal.length), Buffer.from(cal)]);
  const nonce = Buffer.alloc(16, 3);
  const answer = Buffer.concat([Buffer.from([0xf0]), vu(16), nonce, Buffer.from([0x08]), pendingAtt]);
  const digest = rootDigest(H('a root'));
  const msg = sha(Buffer.concat([digest, nonce]));
  const salt = Buffer.alloc(8, 0x5a);
  const merkle = sha(Buffer.concat([salt, msg]));
  const btcAtt = Buffer.concat([Buffer.from([0x00]), Buffer.from('0588960d73d71901', 'hex'), vu(vu(976480).length), vu(976480)]);
  const upgrade = Buffer.concat([Buffer.from([0xf1]), vu(8), salt, Buffer.from([0x08]), btcAtt]);
  const good = headerFor(merkle, 1_790_000_000);
  const lie = headerFor(sha('x'), 1_790_000_000);
  const fetchFor = (second) => async (url) => {
    if (String(url).includes('/timestamp/')) return new Response(upgrade);
    return explorers({ 'blockstream.info': { 976480: good }, 'mempool.space': { 976480: second } })(url);
  };
  const calendars = ['https://a.pool.opentimestamps.org'];
  const honest = await upgradeAnswer(answer, digest, { calendars, explorers: E, fetchImpl: fetchFor(good) });
  assert.equal(honest.bitcoin?.height, 976_480, JSON.stringify(honest.errors));
  const lied = await upgradeAnswer(answer, digest, { calendars, explorers: E, fetchImpl: fetchFor(lie) });
  assert.equal(lied.bitcoin, null);
  assert.match(lied.errors.join(' '), /does not match block 976480 \(header from mempool\.space\)/);
});

// ---- the sponsor is down: the real server, with no sponsor ------------------------------

let dir;
let tsa;
let base;
let server;
let app;
let db;
const realFetch = globalThis.fetch;
const ssl = (...args) => execFileSync('openssl', args, { cwd: dir, stdio: ['ignore', 'pipe', 'pipe'] });
const OP = { 'x-operator-token': 'test-operator-token-at-least-32-chars' };
const calendarCalls = [];

before(async () => {
  // A local RFC 3161 TSA (openssl ts), as in tsa.test.mjs.
  dir = mkdtempSync(join(tmpdir(), 'seal-timer-'));
  writeFileSync(join(dir, 'ext.cnf'), 'extendedKeyUsage = critical,timeStamping\nbasicConstraints = CA:FALSE\n');
  ssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key', '-out', 'ca.pem', '-days', '2', '-subj', '/CN=Test TSA Root');
  ssl('req', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'tsa.key', '-out', 'tsa.csr', '-subj', '/CN=Test TSA');
  ssl('x509', '-req', '-in', 'tsa.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial', '-out', 'tsa.pem', '-days', '2', '-extfile', 'ext.cnf');
  writeFileSync(join(dir, 'tsa.cnf'), `[ tsa ]\ndefault_tsa = t\n[ t ]\ndir = ${dir}\nserial = ${dir}/serial\nsigner_cert = ${dir}/tsa.pem\nsigner_key = ${dir}/tsa.key\nsigner_digest = sha256\ndefault_policy = 1.2.3.4.1\ndigests = sha256\ness_cert_id_alg = sha256\naccuracy = secs:1\nordering = no\ntsa_name = no\ness_cert_id_chain = no\ncerts = ${dir}/tsa.pem\n`);
  writeFileSync(join(dir, 'serial'), '01\n');
  tsa = { calls: 0 };
  tsa.server = createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      tsa.calls++;
      writeFileSync(join(dir, 'q.tsq'), Buffer.concat(chunks));
      ssl('ts', '-reply', '-config', 'tsa.cnf', '-queryfile', 'q.tsq', '-out', 'r.tsr');
      res.setHeader('content-type', 'application/timestamp-reply');
      res.end(readFileSync(join(dir, 'r.tsr')));
    });
  });
  await new Promise((r) => tsa.server.listen(0, '127.0.0.1', r));
  const pin = new X509Certificate(readFileSync(join(dir, 'tsa.pem'))).fingerprint256.replace(/:/g, '').toLowerCase();

  process.env.DB_PATH = ':memory:';
  process.env.VEILCORE_OPERATOR_TOKEN = OP['x-operator-token'];
  process.env.VEILCORE_OTS = 'on'; // npm test turns it off; this file needs it
  process.env.VEILCORE_ANCHOR_NETWORK = 'preprod';
  process.env.VEILCORE_ANCHOR_CONTRACT = '7a'.repeat(32);
  process.env.VEILCORE_TSA_URL = `http://127.0.0.1:${tsa.server.address().port}/`;
  process.env.VEILCORE_TSA_SIGNER_SHA256 = pin;
  process.env.VEILCORE_SEAL_TIMER = 'on';
  process.env.VEILCORE_SEAL_AT_PENDING = '1';
  process.env.VEILCORE_SEAL_CHECK_MS = '1000';
  ({ app, db } = require('../server.js'));
  server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  base = `http://127.0.0.1:${server.address().port}`;
  // Every OpenTimestamps calendar answers honestly; nothing else leaves this machine.
  globalThis.fetch = async (url, init) => {
    const u = String(url);
    if (u.startsWith('http://127.0.0.1')) return realFetch(url, init);
    calendarCalls.push(u);
    if (u.endsWith('/digest')) {
      const uri = u.replace(/\/digest$/, '');
      const vu = (n) => { const o = []; do { let b = n % 128; n = Math.floor(n / 128); if (n > 0) b |= 0x80; o.push(b); } while (n > 0); return Buffer.from(o); };
      const p = Buffer.from(uri);
      const att = Buffer.concat([Buffer.from([0x00]), Buffer.from('83dfe30d2ef90c8e', 'hex'), vu(p.length + vu(p.length).length), vu(p.length), p]);
      return new Response(Buffer.concat([Buffer.from([0xf0]), vu(16), sha(`n:${uri}:${Math.random()}`).subarray(0, 16), Buffer.from([0x08]), att]));
    }
    throw new Error(`not expected in this test: ${u}`);
  };
  await untilReady(base, realFetch);
});
after(() => {
  globalThis.fetch = realFetch;
  server?.close();
  tsa?.server.close();
  if (dir) rmSync(dir, { recursive: true, force: true });
});

const call = async (method, path, { holder, body, headers = {} } = {}) => {
  const res = await realFetch(`${base}${path}`, {
    method,
    headers: { 'content-type': 'application/json', ...(holder ? { 'x-holder-key': holder } : {}), ...headers },
    body: body === undefined ? undefined : JSON.stringify(testBody(method, path, holder, body)),
  });
  const text = await res.text();
  let json;
  try { json = JSON.parse(text); } catch { json = undefined; }
  return { status: res.status, json };
};
let seq = 0;
const makeRecord = async () => {
  const r = {
    id: `st-${process.pid}-${seq++}`, strainName: 'Timer Cultivar', bredBy: 'B', dateCreated: '2026-01-01',
    loggedAt: '2026-01-01T00:00:00Z', nonce: newNonce(), notes: '', parents: [], photoFingerprints: [],
    breedingMethod: '', refId: '',
  };
  r.recordFingerprint = await sha256Hex(canonicalise({
    breedingMethod: r.breedingMethod, bredBy: r.bredBy, dateCreated: r.dateCreated, loggedAt: r.loggedAt,
    nonce: r.nonce, notes: r.notes, parents: r.parents, photoFingerprints: r.photoFingerprints,
    refId: r.refId, strainName: r.strainName,
  }));
  return r;
};

test('SPONSOR DOWN: with nobody calling /batches/seal, a new record is sealed, stamped on Bitcoin and timestamped by the TSA', async () => {
  const holder = H('timer-holder');
  const rec = await makeRecord();
  assert.equal((await call('PUT', '/api/records', { holder, body: [rec] })).status, 200);

  // No sponsor runs in this test. The registry seals on its own...
  const proof = await waitFor('the record to be in a batch', async () => {
    const r = await call('GET', `/proof/${rec.recordFingerprint}`);
    return r.status === 200 ? r.json : null;
  }, { within: 30_000 });
  const batchId = proof.batchId;
  assert.ok(batchId, JSON.stringify(proof));

  // ...asks every Bitcoin calendar at once...
  const listed = await waitFor('the batch to hold calendar answers', async () => {
    const b = (await call('GET', '/batches')).json.batches.find((x) => x.batch_id === batchId);
    return b?.opentimestamps?.status === 'pending' ? b : null;
  }, { within: 30_000 });
  assert.equal(listed.anchor, null, 'not on Midnight: that is the sponsor’s, and it is down');
  assert.ok(calendarCalls.filter((u) => u.endsWith('/digest')).length >= 4);

  // ...and gets the TSA's token straight away, not at the hourly upkeep (its first run is a minute after start).
  const tst = await waitFor('the TSA token', async () => {
    const r = await realFetch(`${base}/batches/${batchId}/root.tst`);
    return r.status === 200 ? Buffer.from(await r.arrayBuffer()) : null;
  }, { within: 30_000 });
  assert.ok(tst.length > 100);
  assert.ok(tsa.calls >= 1);

  // The proof the holder fetches carries both dates already.
  const full = (await call('GET', `/proof/${rec.recordFingerprint}`)).json;
  const kinds = (full.anchors ?? []).map((a) => a.kind);
  assert.ok(kinds.includes('rfc3161'), JSON.stringify(kinds));
  assert.ok(kinds.some((k) => k === 'opentimestamps' || k === 'bitcoin'), JSON.stringify(kinds));
});

test('the sponsor coming back: its seal call finds nothing to seal and its answer is the one every sponsor build reads as "nothing this run"', async () => {
  // Nothing pending now (the test above sealed it all).
  await waitFor('nothing pending', async () => (await call('GET', '/batches/pending', { headers: OP })).json.count === 0, { within: 30_000 });
  const s = await call('POST', '/batches/seal', { headers: OP });
  assert.equal(s.status, 400);
  assert.equal(s.json.error, 'nothing pending', 'sponsor registry.ts seal(): body.error === "nothing pending" means undefined, not a failure');
});

test('the sponsor’s seal call racing the timer: each record in exactly one batch, and no 409', async () => {
  const holder = H('race-holder');
  const recs = [];
  for (let i = 0; i < 5; i++) recs.push(await makeRecord());
  assert.equal((await call('PUT', '/api/records', { holder, body: recs })).status, 200);
  const answers = await Promise.all(Array.from({ length: 6 }, () => call('POST', '/batches/seal', { headers: OP })));
  assert.ok(answers.every((a) => a.status === 200 || (a.status === 400 && a.json.error === 'nothing pending')), JSON.stringify(answers));
  await waitFor('every record batched', async () => (await call('GET', '/batches/pending', { headers: OP })).json.count === 0, { within: 30_000 });
  const ids = new Set();
  for (const r of recs) ids.add((await call('GET', `/proof/${r.recordFingerprint}`)).json.batchId);
  assert.equal(ids.size, 1, 'all five sealed together, once');
  const rows = db.prepare('SELECT COUNT(*) AS n FROM batch_proofs WHERE commitment IN (' + recs.map(() => '?').join(',') + ')').get(...recs.map((r) => r.recordFingerprint));
  assert.equal(rows.n, 5);
});

test('/alerts says ots-behind when a batch has waited over a day for Bitcoin', async () => {
  const fine = await call('GET', '/alerts');
  assert.ok(!fine.json.problems.includes('ots-behind'), JSON.stringify(fine.json));
  db.prepare('INSERT INTO batches (batch_id, root, sealed_at, record_count, ots_status, tsa_token) VALUES (?,?,?,?,?,?)')
    .run('B-20261101-AAAA', H('late root'), Date.now() - 30 * 3_600_000, 1, 'pending', Buffer.from('x'));
  const late = await call('GET', '/alerts');
  assert.equal(late.status, 503);
  assert.ok(late.json.problems.includes('ots-behind'), JSON.stringify(late.json));
  db.prepare("UPDATE batches SET ots_status = 'bitcoin' WHERE batch_id = 'B-20261101-AAAA'").run();
  assert.ok(!(await call('GET', '/alerts')).json.problems.includes('ots-behind'));
});
