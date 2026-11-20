// A timestamp of its own for each record (lineage/record-stamps.mjs), in seconds.
//
// What these tests hold the registry to:
//   - taking a proof code (PUT /api/records/dating, or PUT /api/records with a proof code new to
//     the record) queues it for an RFC 3161 token, and never waits for the TSA: a TSA that
//     hangs or refuses changes nothing about the answer or how fast it comes;
//   - the token stamps the proof code's 32 raw bytes, is verified before it is kept, and is
//     served at /proof/:commitment/instant (and as DER, which `openssl ts -verify` accepts);
//   - one request at a time, at least the set interval apart, with a pause that grows after a
//     failure; a proof code that waits too long, fails too often or finds the queue full falls
//     back to its batch's token ("batch"), and one whose record was deleted is dropped;
//   - a proof code already stamped is not asked for again, and a resave with the same proof
//     code queues nothing.
// No network beyond 127.0.0.1 (a local openssl TSA, as test/tsa.test.mjs).
// SPDX-License-Identifier: Apache-2.0

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createRequire } from 'node:module';
import { randomBytes } from 'node:crypto';
import { verifyTimestampToken } from 'veilcore-records';
import { createRecordStamps, recordStampSettings } from '../lineage/record-stamps.mjs';
import { tsaConfig } from '../lineage/tsa.mjs';
import { createBatches } from '../lineage/batches.mjs';
import { untilReady, waitFor, testBody } from './helpers.mjs';

const require = createRequire(import.meta.url);
const Database = require('better-sqlite3');

const hex = (n = 32) => randomBytes(n).toString('hex');
const recordId = () => `VEIL-${hex(16).toUpperCase()}`;

// ---- the queue on its own, with a stand-in TSA and a clock held by the test ---------------------

const clock = () => {
  let t = 1_000_000;
  const timers = [];
  return {
    now: () => t,
    advance: (ms) => {
      t += ms;
    },
    setTimer: (fn, ms) => {
      const handle = { fn, at: t + ms };
      timers.push(handle);
      return handle;
    },
    clearTimer: (h) => {
      const i = timers.indexOf(h);
      if (i >= 0) timers.splice(i, 1);
    },
    /** Run every timer due by now. */
    async fire() {
      const due = timers.filter((h) => h.at <= t);
      for (const h of due) timers.splice(timers.indexOf(h), 1);
      for (const h of due) await h.fn();
    },
    pending: () => timers.length,
  };
};

const fakeTsa = () => {
  const asked = [];
  let mode = 'ok';
  return {
    asked,
    set: (m) => {
      mode = m;
    },
    request: async (commitment, svc) => {
      asked.push(commitment);
      if (svc?.down) return { error: 'could not reach the TSA, or it was too slow' };
      if (mode === 'fail') return { error: 'TSA answered HTTP 429' };
      if (mode === 'throw') throw new Error('boom');
      return { token: Buffer.from(`token-for-${commitment}`).toString('base64'), genTime: '2026-11-19T14:03:12Z', signerSubject: 'CN=Test TSA' };
    },
  };
};

const CFG = { url: 'https://tsa.example/', pins: [], qualified: null };

test('settings: on unless VEILCORE_TSA_RECORDS=off; out-of-range numbers use the defaults', () => {
  assert.deepEqual(recordStampSettings({}), { on: true, minIntervalMs: 2000, maxWaitMs: 1_800_000, maxQueue: 1000 });
  assert.equal(recordStampSettings({ VEILCORE_TSA_RECORDS: 'OFF' }).on, false);
  assert.equal(recordStampSettings({ VEILCORE_TSA_RECORD_MIN_INTERVAL_MS: '15000' }).minIntervalMs, 15000);
  assert.equal(recordStampSettings({ VEILCORE_TSA_RECORD_MIN_INTERVAL_MS: '-1' }).minIntervalMs, 2000);
  assert.equal(recordStampSettings({ VEILCORE_TSA_RECORD_MAX_QUEUE: 'lots' }).maxQueue, 1000);
});

test('no TSA set: nothing is queued and nothing is asked', async () => {
  const db = new Database(':memory:');
  const tsa = fakeTsa();
  const s = createRecordStamps(db, { request: tsa.request });
  assert.equal(s.enqueue([{ id: 'VEIL-1', commitment: 'ab'.repeat(32) }]), 0);
  assert.equal(s.instantFor('ab'.repeat(32)), null);
  assert.deepEqual(tsa.asked, []);
  db.close();
});

test('one request at a time, at least the interval apart; a stamped proof code is never asked again', async () => {
  const db = new Database(':memory:');
  const c = clock();
  const tsa = fakeTsa();
  const s = createRecordStamps(db, { request: tsa.request, now: c.now, setTimer: c.setTimer, clearTimer: c.clearTimer, minIntervalMs: 15_000 });
  s.configure(CFG);
  const a = 'aa'.repeat(32);
  const b = 'bb'.repeat(32);
  assert.equal(s.enqueue([{ id: 'VEIL-A', commitment: a }, { id: 'VEIL-B', commitment: b }]), 2);
  assert.deepEqual(s.instantFor(a), { status: 'queued' });
  await c.fire();
  assert.deepEqual(tsa.asked, [a], 'the first at once, the second waits for the interval');
  assert.equal(s.instantFor(a).status, 'stamped');
  assert.equal(s.instantFor(b).status, 'queued');
  c.advance(14_999);
  await c.fire();
  assert.deepEqual(tsa.asked, [a]);
  c.advance(1);
  await c.fire();
  assert.deepEqual(tsa.asked, [a, b]);
  // Queued again (a resend): left as it is, not asked again.
  assert.equal(s.enqueue([{ id: 'VEIL-A', commitment: a }]), 0);
  c.advance(60_000);
  await c.fire();
  assert.deepEqual(tsa.asked, [a, b]);
  const got = s.instantFor(a);
  assert.equal(got.tokens.length, 1);
  const [tok] = got.tokens;
  assert.equal(tok.kind, 'rfc3161');
  assert.equal(tok.tsa, CFG.url);
  assert.equal(tok.genTime, '2026-11-19T14:03:12Z');
  assert.equal(tok.signer, 'CN=Test TSA');
  assert.match(got.note, /nothing earlier/);
  assert.equal(Buffer.from(tok.token, 'base64').toString(), `token-for-${a}`);
  db.close();
});

test('a failing TSA: the pause doubles, and after three tries the batch’s token dates it instead', async () => {
  const db = new Database(':memory:');
  const c = clock();
  const tsa = fakeTsa();
  const s = createRecordStamps(db, { request: tsa.request, now: c.now, setTimer: c.setTimer, clearTimer: c.clearTimer, minIntervalMs: 0, backoffMs: 1_000 });
  s.configure(CFG);
  tsa.set('fail');
  const a = 'a1'.repeat(32);
  s.enqueue([{ id: 'VEIL-A', commitment: a }]);
  await c.fire();
  assert.equal(tsa.asked.length, 1);
  c.advance(999);
  await c.fire();
  assert.equal(tsa.asked.length, 1, 'waits 1 s after the first failure');
  c.advance(1);
  await c.fire();
  assert.equal(tsa.asked.length, 2);
  c.advance(1_999);
  await c.fire();
  assert.equal(tsa.asked.length, 2, 'then 2 s');
  c.advance(1);
  tsa.set('throw');
  await c.fire();
  assert.equal(tsa.asked.length, 3);
  assert.deepEqual(s.instantFor(a), { status: 'batch' }, 'three tries, then its batch');
  db.close();
});

test('waited too long, or the queue is full: its batch’s token instead; a deleted record’s proof code is dropped', async () => {
  const db = new Database(':memory:');
  const c = clock();
  const tsa = fakeTsa();
  const held = new Set(['VEIL-A', 'VEIL-B']);
  const s = createRecordStamps(db, {
    request: tsa.request,
    now: c.now,
    setTimer: c.setTimer, clearTimer: c.clearTimer,
    minIntervalMs: 0,
    maxWaitMs: 60_000,
    maxQueue: 2,
    stillHeld: (id) => held.has(id),
  });
  s.configure(CFG);
  const [a, b, d] = ['a2', 'b2', 'd2'].map((x) => x.repeat(32));
  assert.equal(s.enqueue([{ id: 'VEIL-A', commitment: a }, { id: 'VEIL-B', commitment: b }, { id: 'VEIL-D', commitment: d }]), 3);
  assert.deepEqual(s.instantFor(d), { status: 'batch' }, 'the queue held two');
  held.delete('VEIL-B');
  c.advance(60_001);
  await c.fire();
  assert.deepEqual(tsa.asked, [], 'nothing asked: one waited too long, one was deleted');
  assert.deepEqual(s.instantFor(a), { status: 'batch' });
  assert.equal(s.instantFor(b), null, 'dropped');
  // Not a proof code: refused, nothing stored.
  assert.equal(s.enqueue([{ id: 'VEIL-X', commitment: 'nothex' }]), 0);
  db.close();
});

test('several TSAs: a token from each, and one that is down never holds up the others', async () => {
  const db = new Database(':memory:');
  const c = clock();
  const tsa = fakeTsa();
  const s = createRecordStamps(db, { request: tsa.request, now: c.now, setTimer: c.setTimer, clearTimer: c.clearTimer, minIntervalMs: 0, backoffMs: 1_000 });
  const one = { url: 'https://one.example/', pins: [], qualified: { scheme: 'eIDAS' } };
  const two = { url: 'https://two.example/', pins: [], qualified: null };
  const down = { url: 'http://down.example/', pins: ['ab'.repeat(32)], qualified: null, down: true };
  s.configure({ ...one, services: [one, down, two] });
  const a = 'a4'.repeat(32);
  assert.equal(s.enqueue([{ id: 'VEIL-A', commitment: a }]), 3, 'one row per TSA');
  await c.fire();
  const got = s.instantFor(a);
  assert.equal(got.status, 'stamped');
  assert.deepEqual(got.tokens.map((t) => t.tsa), [one.url, two.url], 'both answering TSAs, each its own token');
  assert.deepEqual(got.tokens[0].qualified, { scheme: 'eIDAS' });
  assert.equal(got.tokens[1].qualified, undefined);
  assert.equal(got.stillAsking, 1, 'the one that is down is still being asked');
  c.advance(10_000);
  await c.fire();
  c.advance(10_000);
  await c.fire();
  assert.equal(s.instantFor(a).stillAsking, undefined, 'given up on: its batch dates it');
  db.close();
});

test('the TSA setting takes a list; a single address reads as before; pins can be per service', () => {
  const pin = 'ab'.repeat(32);
  const pin2 = 'cd'.repeat(32);
  const single = tsaConfig({ VEILCORE_TSA_URL: 'https://freetsa.org/tsr' });
  assert.equal(single.url, 'https://freetsa.org/tsr');
  assert.equal(single.services.length, 1);
  const list = tsaConfig({
    VEILCORE_TSA_URL: 'https://freetsa.org/tsr, https://timestamp.sectigo.com http://timestamp.digicert.com',
    VEILCORE_TSA_SIGNER_SHA256: `timestamp.digicert.com=${pin2}`,
    VEILCORE_TSA_QUALIFIED_SCHEME: 'eIDAS',
    VEILCORE_TSA_AUTHORIZATION: 'Basic x',
  });
  assert.equal(list.error, undefined, list.error);
  assert.deepEqual(list.services.map((x) => x.url), ['https://freetsa.org/tsr', 'https://timestamp.sectigo.com/', 'http://timestamp.digicert.com/']);
  assert.deepEqual(list.services.map((x) => x.pins), [[], [], [pin2]], 'a scoped pin pins only its own service');
  assert.deepEqual(list.services.map((x) => x.qualified?.scheme ?? null), ['eIDAS', null, null], 'stated for the first only');
  assert.deepEqual(list.services.map((x) => x.authorization ?? null), ['Basic x', null, null], 'sent to the first only');
  assert.match(tsaConfig({ VEILCORE_TSA_URL: 'https://freetsa.org/tsr http://timestamp.digicert.com' }).error, /http TSA needs/);
  assert.deepEqual(tsaConfig({ VEILCORE_TSA_URL: 'https://a.example/ https://b.example/', VEILCORE_TSA_SIGNER_SHA256: pin }).services.map((x) => x.pins), [[pin], [pin]], 'a plain pin still pins every service');
  assert.match(tsaConfig({ VEILCORE_TSA_URL: 'https://a.example/', VEILCORE_TSA_SIGNER_SHA256: `b.example=${pin}` }).error, /doesn't list/);
  assert.match(tsaConfig({ VEILCORE_TSA_URL: 'https://a.example/ https://a.example/' }).error, /twice/);
});

test('several TSAs on a batch: the first one’s token where it always was, the others beside it, each asked at once', async () => {
  const db = new Database(':memory:');
  const batches = createBatches(db);
  const ROOT = 'c4'.repeat(32);
  db.prepare(`INSERT INTO batches (batch_id, root, sealed_at, record_count) VALUES ('B-2', ?, ?, 1)`).run(ROOT, Date.now());
  const one = { url: 'https://one.example/', pins: [], qualified: null };
  const two = { url: 'https://two.example/', pins: [], qualified: null };
  let release;
  const slow = new Promise((r) => {
    release = r;
  });
  const request = async (root, svc) => {
    if (svc.url === one.url) await slow; // the first is slow: the second must not wait for it
    return { token: Buffer.from(`t-${svc.url}`).toString('base64'), genTime: new Date().toISOString(), signerSubject: 'CN=x' };
  };
  const run = batches.tsaMaintenance({ ...one, services: [one, two] }, { request });
  await waitFor('the second TSA answered first', () => batches.tsaFor('B-2', two.url)?.token);
  assert.equal(batches.tsaFor('B-2').token, null, 'the first is still being asked');
  release();
  await run;
  assert.equal(batches.tsaFor('B-2').token.toString(), `t-${one.url}`);
  // A record's proof names both, each its own rfc3161 anchor with its own file.
  db.prepare(`INSERT INTO batch_proofs (commitment, batch_id, proof) VALUES (?, 'B-2', '{}')`).run('d4'.repeat(32));
  const tsas = batches.proofFor('d4'.repeat(32)).anchors.filter((x) => x.kind === 'rfc3161');
  assert.deepEqual(tsas.map((x) => x.tsa), [one.url, two.url]);
  assert.equal(tsas[1].tst, `/batches/B-2/root.tst?tsa=${encodeURIComponent(two.url)}`);
  assert.deepEqual(await batches.tsaMaintenance({ ...one, services: [one, two] }, { request }), [], 'each is stamped once');
  db.close();
});

test('queued rows from before a restart are taken up again', async () => {
  const db = new Database(':memory:');
  const c = clock();
  const tsa = fakeTsa();
  const first = createRecordStamps(db, { request: tsa.request, now: c.now, setTimer: () => ({}), clearTimer: () => {} });
  first.configure(CFG);
  const a = 'a3'.repeat(32);
  first.enqueue([{ id: 'VEIL-A', commitment: a }]);
  assert.deepEqual(tsa.asked, [], 'the first process never ran its timer');
  const second = createRecordStamps(db, { request: tsa.request, now: c.now, setTimer: c.setTimer, clearTimer: c.clearTimer, minIntervalMs: 0 });
  second.configure(CFG);
  await c.fire();
  assert.deepEqual(tsa.asked, [a]);
  assert.equal(second.instantFor(a).status, 'stamped');
  db.close();
});

// ---- the registry, with a real (local, openssl) TSA -----------------------------------------------

let dir;
let tsa; // { url, server, mode: 'ok' | 'hang' | 'refuse', asked }
const ssl = (...args) => execFileSync('openssl', args, { cwd: dir, stdio: ['ignore', 'pipe', 'pipe'] });
let base;
let server;
let app;
let db;

before(async () => {
  dir = mkdtempSync(join(tmpdir(), 'rec-tsa-'));
  writeFileSync(join(dir, 'ext.cnf'), 'extendedKeyUsage = critical,timeStamping\nbasicConstraints = CA:FALSE\n');
  ssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key', '-out', 'ca.pem', '-days', '2', '-subj', '/CN=Test TSA Root');
  ssl('req', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'tsa.key', '-out', 'tsa.csr', '-subj', '/CN=Test TSA');
  ssl('x509', '-req', '-in', 'tsa.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial', '-out', 'tsa.pem', '-days', '2', '-extfile', 'ext.cnf');
  writeFileSync(join(dir, 'tsa.cnf'), `[ tsa ]\ndefault_tsa = t\n[ t ]\ndir = ${dir}\nserial = ${dir}/serial\nsigner_cert = ${dir}/tsa.pem\nsigner_key = ${dir}/tsa.key\nsigner_digest = sha256\ndefault_policy = 1.2.3.4.1\ndigests = sha256\ness_cert_id_alg = sha256\naccuracy = secs:1\nordering = no\ntsa_name = no\ness_cert_id_chain = no\ncerts = ${dir}/tsa.pem\n`);
  writeFileSync(join(dir, 'serial'), '01\n');
  tsa = { mode: 'ok', asked: 0, hanging: [] };
  tsa.server = createServer((req, res) => {
    tsa.asked++;
    const chunks = [];
    req.on('data', (ch) => chunks.push(ch));
    req.on('end', () => {
      if (tsa.mode === 'hang') return void tsa.hanging.push(res);
      if (tsa.mode === 'refuse') {
        res.statusCode = 503;
        return void res.end();
      }
      writeFileSync(join(dir, 'q.tsq'), Buffer.concat(chunks));
      ssl('ts', '-reply', '-config', 'tsa.cnf', '-queryfile', 'q.tsq', '-out', 'r.tsr');
      res.setHeader('content-type', 'application/timestamp-reply');
      res.end(readFileSync(join(dir, 'r.tsr')));
    });
  });
  await new Promise((r) => tsa.server.listen(0, '127.0.0.1', r));
  tsa.url = `http://127.0.0.1:${tsa.server.address().port}/`;
  const pin = execFileSync('openssl', ['x509', '-in', join(dir, 'tsa.pem'), '-noout', '-fingerprint', '-sha256']).toString().split('=')[1].trim().replace(/:/g, '').toLowerCase();

  process.env.DB_PATH = ':memory:';
  process.env.VEILCORE_OTS = 'off';
  process.env.VEILCORE_TSA_URL = tsa.url;
  process.env.VEILCORE_TSA_SIGNER_SHA256 = pin;
  process.env.VEILCORE_TSA_RECORD_MIN_INTERVAL_MS = '0';
  ({ app, db } = require('../server.js'));
  server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  base = `http://127.0.0.1:${server.address().port}`;
  await untilReady(base);
  // The TSA timer turns per-record stamps on just after the batch module loads.
  await waitFor('per-record timestamps on', async () => (await fetch(`${base}/health`)).ok);
});

after(() => {
  for (const r of tsa.hanging) r.destroy();
  tsa.server.closeAllConnections?.();
  tsa.server.close();
  server?.close();
  rmSync(dir, { recursive: true, force: true });
});

const call = async (method, path, holder, body) => {
  const res = await fetch(`${base}${path}`, {
    method,
    headers: {
      'content-type': 'application/json',
      'x-forwarded-for': `10.${randomBytes(3).join('.')}`,
      ...(holder ? { 'x-holder-key': holder } : {}),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(path === '/api/records/dating' ? body : testBody(method, path, holder, body)) }),
  });
  const text = await res.text();
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    json = text;
  }
  return { status: res.status, json, headers: res.headers };
};

const stampedSoon = (fp) =>
  waitFor(`a timestamp for ${fp.slice(0, 8)}`, async () => {
    const r = await call('GET', `/proof/${fp}/instant`);
    return r.status === 200 ? r : r.status === 202 ? false : { failed: r };
  }, { within: 30_000 });

test('/health lists record-timestamp-v1, for the site’s deploy preflights', async () => {
  const h = (await call('GET', '/health')).json;
  assert.ok(h.features.includes('record-timestamp-v1'), JSON.stringify(h));
});

test('a dated proof code gets its own token in seconds: verified, and checkable with openssl', async () => {
  tsa.mode = 'ok';
  const holder = hex();
  const id = recordId();
  const fp = hex();
  const t0 = Date.now();
  const dated = await call('PUT', '/api/records/dating', holder, [{ id, recordFingerprint: fp }]);
  assert.deepEqual(dated.json, { ok: true, dated: [id] });
  const got = await stampedSoon(fp);
  assert.equal(got.failed, undefined, JSON.stringify(got.failed?.json));
  const j = got.json;
  assert.equal(j.status, 'stamped');
  assert.equal(j.tokens.length, 1);
  const [tok] = j.tokens;
  assert.equal(tok.kind, 'rfc3161');
  assert.equal(tok.tsa, tsa.url);
  assert.ok(Math.abs(Date.parse(tok.genTime) - t0) < 60_000, tok.genTime);
  const v = await verifyTimestampToken(tok.token, Buffer.from(fp, 'hex'));
  assert.equal(v.ok, true, JSON.stringify(v.checks));
  // The DER file, as openssl reads it, against the proof code's raw bytes.
  const der = Buffer.from(await (await fetch(`${base}/proof/${fp}/instant.tst`)).arrayBuffer());
  writeFileSync(join(dir, 'pc.bin'), Buffer.from(fp, 'hex'));
  writeFileSync(join(dir, 'instant.tst'), der);
  const ok = ssl('ts', '-verify', '-data', 'pc.bin', '-in', 'instant.tst', '-token_in', '-CAfile', 'ca.pem', '-untrusted', 'tsa.pem').toString();
  assert.match(ok, /Verification: OK/);
});

test('a saved record with a new proof code is stamped; saving it again with the same one asks nothing more', async () => {
  tsa.mode = 'ok';
  const holder = hex();
  const id = recordId();
  const fp = hex();
  const saved = await call('PUT', '/api/records', holder, [{ id, recordFingerprint: fp, nonce: hex(), strainName: 'S' }]);
  assert.equal(saved.json.ok, true, JSON.stringify(saved.json));
  assert.equal((await stampedSoon(fp)).status, 200);
  const before = tsa.asked;
  const again = await call('PUT', '/api/records', holder, [{ id, recordFingerprint: fp, nonce: hex(), strainName: 'S', rev: 1 }]);
  assert.equal(again.json.ok, true, JSON.stringify(again.json));
  await new Promise((r) => setTimeout(r, 300));
  assert.equal(tsa.asked, before, 'the same proof code is not stamped twice');
});

test('a TSA that hangs or refuses never holds up or fails taking a proof code', async () => {
  tsa.mode = 'hang';
  const holder = hex();
  const rows = Array.from({ length: 3 }, () => ({ id: recordId(), recordFingerprint: hex() }));
  const t0 = performance.now();
  const r = await call('PUT', '/api/records/dating', holder, rows);
  const took = performance.now() - t0;
  assert.equal(r.status, 200);
  assert.deepEqual(r.json.dated, rows.map((x) => x.id));
  assert.ok(took < 2_000, `answered in ${Math.round(took)} ms`);
  await waitFor('the TSA asked', () => tsa.asked > 0 && tsa.hanging.length > 0);
  assert.equal((await call('GET', `/proof/${rows[0].recordFingerprint}/instant`)).status, 202, 'queued, still asking');
  // The proof code is in the next batch whatever the TSA does.
  const pending = db.prepare(`SELECT COUNT(*) AS n FROM records WHERE holder_key IS NOT NULL AND json_extract(body, '$.recordFingerprint') = ?`).get(rows[0].recordFingerprint);
  assert.equal(pending.n, 1);
  // Refusing, the same.
  tsa.mode = 'refuse';
  const t1 = performance.now();
  const r2 = await call('PUT', '/api/records/dating', hex(), [{ id: recordId(), recordFingerprint: hex() }]);
  assert.equal(r2.status, 200);
  assert.ok(performance.now() - t1 < 2_000);
  for (const res of tsa.hanging.splice(0)) res.destroy();
});

test('the instant route: a proof code it never queued is 404 none; not a proof code is 400', async () => {
  assert.deepEqual((await call('GET', `/proof/${hex()}/instant`)).json, { status: 'none' });
  assert.equal((await call('GET', '/proof/XYZ/instant')).status, 400);
  assert.equal((await call('GET', `/proof/${hex()}/instant.tst`)).status, 404);
});
