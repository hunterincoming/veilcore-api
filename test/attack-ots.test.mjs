// Attack on branch `ots` (4 Oct 2026): OpenTimestamps stamping, root.bin / root.bin.ots,
// POST /batches/:id/opentimestamps, GET /api/export, the anchor network.
//
// Each "FIXED [...]" test is one finding from that attack. It fails on the code that was
// attacked (commit 80bdecc) and passes on the fix. "HELD" tests are attacks that were
// refused all along.
//
// Calendars and the block explorer are never contacted: global fetch is replaced for any
// URL that is not this in-process server, and stampRoot is given a fetchImpl where it is
// called directly. The installed python-opentimestamps parser is the oracle for "is this
// .ots valid".
//
// SPDX-License-Identifier: Apache-2.0

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { canonicalise, sha256Hex, newNonce } from 'veilcore-records';
import { stampRoot, otsFile, DEFAULT_CALENDARS } from '../lineage/ots.mjs';
import { createBatches } from '../lineage/batches.mjs';
import Database from 'better-sqlite3';
import { performance } from 'node:perf_hooks';
import { inOneMinute, untilReady, waitFor, testBody } from './helpers.mjs';

const ANCHOR_CONTRACT = '7a'.repeat(32);
process.env.DB_PATH = ':memory:';
process.env.VEILCORE_OPERATOR_TOKEN = 'test-operator-token-at-least-32-chars';
process.env.VEILCORE_OTS = 'off';
process.env.VEILCORE_ANCHOR_NETWORK = 'preprod';
process.env.VEILCORE_ANCHOR_CONTRACT = ANCHOR_CONTRACT;
const require = createRequire(import.meta.url);
const { app, db } = require('../server.js');

const OP = { 'x-operator-token': 'test-operator-token-at-least-32-chars' };
const H = (name) => createHash('sha256').update(name).digest('hex');
const sha = (b) => createHash('sha256').update(b).digest();
const EXPLORER = 'https://blockstream.info/api';

// ---- the OpenTimestamps project's own parser ----
const py = fileURLToPath(new URL('./fixtures/ots_reference.py', import.meta.url));
let hasReference = true;
try { execFileSync('python3', ['-c', 'import opentimestamps'], { stdio: 'ignore' }); } catch { hasReference = false; }
const ref = (...args) => execFileSync('python3', [py, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
/** Parse a .ots with the reference library: { ok, parsed } or { ok: false, error }. */
const refParse = (ots) => {
  try { return { ok: true, parsed: JSON.parse(ref('parse', Buffer.from(ots).toString('hex'))) }; } catch (e) {
    return { ok: false, error: String(e.stderr ?? e.message).trim().split('\n').pop() };
  }
};

// ---- hand-built calendar answers ----
const vu = (n) => { const o = []; do { let b = n % 128; n = Math.floor(n / 128); if (n > 0) b |= 0x80; o.push(b); } while (n > 0); return Buffer.from(o); };
const PENDING_TAG = Buffer.from('83dfe30d2ef90c8e', 'hex');
const BITCOIN_TAG = Buffer.from('0588960d73d71901', 'hex');
const attestation = (tag, payload) => Buffer.concat([Buffer.from([0x00]), tag, vu(payload.length), payload]);
const pending = (uri) => { const u = Buffer.from(uri); return attestation(PENDING_TAG, Buffer.concat([vu(u.length), u])); };
const bitcoin = (height) => attestation(BITCOIN_TAG, vu(height));
const append = (bytes) => Buffer.concat([Buffer.from([0xf0]), vu(bytes.length), bytes]);
const prepend = (bytes) => Buffer.concat([Buffer.from([0xf1]), vu(bytes.length), bytes]);
/** The calendar a request went to: its URL without the /digest path. */
const calendarOf = (url) => String(url).replace(/\/digest$/, '');
/** What a real calendar returns: append(its own random nonce), sha256, pending attestation. */
const honestAnswer = (uri) => Buffer.concat([append(sha(`nonce:${uri}:${Math.random()}`).subarray(0, 16)), Buffer.from([0x08]), pending(uri)]);

/** Answers the attacked code accepted as well-formed but the reference parser refuses. */
const POISON = {
  'pending URI with a character the reference refuses (?)': pending('https://evil.example/?x=1'),
  'two 3000-byte appends (op result > 4096 bytes)': Buffer.concat([append(Buffer.alloc(3000, 1)), append(Buffer.alloc(3000, 2)), pending('https://evil.example')]),
  'eight hexlify ops (32 bytes doubles past 4096)': Buffer.concat([Buffer.alloc(8, 0xf3), pending('https://evil.example')]),
  '257 nested sha256 ops (reference limit is 256)': Buffer.concat([Buffer.alloc(256, 0x08), pending('https://evil.example')]),
};

// ---- a Bitcoin block, as a calendar upgrade and an Esplora explorer present it ----
const headerFor = (merkleRoot, time) => {
  const h = Buffer.alloc(80);
  h.writeUInt32LE(0x20000000, 0);
  merkleRoot.copy(h, 36);
  h.writeUInt32LE(time, 68);
  return h;
};
const blockHashOf = (h) => Buffer.from(sha(sha(h))).reverse().toString('hex');
/**
 * A fake chain: answers /timestamp/<commitment> with a path to a block at the next height,
 * and the explorer's /block-height and /block/:hash/header for those blocks. `lie` makes the
 * explorer's header commit to something else.
 */
const fakeChain = ({ firstHeight = 940_000, time = 1_790_000_000, lie = false } = {}) => {
  const headers = new Map();
  let next = firstHeight;
  return (url) => {
    const ts = /\/timestamp\/([0-9a-f]+)$/.exec(url);
    if (ts) {
      const salt = Buffer.alloc(8, 0x5a);
      const height = next++;
      const root = sha(Buffer.concat([salt, Buffer.from(ts[1], 'hex')]));
      headers.set(height, headerFor(lie ? sha(root) : root, time));
      return new Response(Buffer.concat([prepend(salt), Buffer.from([0x08]), bitcoin(height)]));
    }
    const bh = /\/block-height\/(\d+)$/.exec(url);
    if (bh && headers.has(Number(bh[1]))) return new Response(blockHashOf(headers.get(Number(bh[1]))));
    const hd = /\/block\/([0-9a-f]{64})\/header$/.exec(url);
    if (hd) for (const h of headers.values()) if (blockHashOf(h) === hd[1]) return new Response(h.toString('hex'));
    return new Response('not found', { status: 404 });
  };
};

// ---- server, with calendar traffic intercepted ----
const realFetch = globalThis.fetch;
let calendarHandler = null; // (url, init) => Response | throws
const calendarCalls = [];
let base;
let server;
before(async () => {
  server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  base = `http://127.0.0.1:${server.address().port}`;
  globalThis.fetch = async (url, init) => {
    const u = String(url);
    if (u.startsWith(base)) return realFetch(url, init);
    calendarCalls.push({ url: u, init });
    if (!calendarHandler) throw new Error('calendar traffic not expected in this test');
    return calendarHandler(u, init);
  };
  await untilReady(base, realFetch);
});
after(() => { globalThis.fetch = realFetch; server.close(); });
const withCalendars = async (handler, fn) => {
  calendarHandler = handler;
  try { return await fn(); } finally { calendarHandler = null; }
};

const call = async (method, path, { holder, body, headers = {} } = {}) => {
  const res = await fetch(`${base}${path}`, {
    method,
    headers: { 'content-type': 'application/json', ...(holder ? { 'x-holder-key': holder } : {}), ...headers },
    body: body === undefined ? undefined : JSON.stringify(testBody(method, path, holder, body)),
  });
  const buf = Buffer.from(await res.arrayBuffer());
  let json;
  try { json = JSON.parse(buf.toString('utf8')); } catch { json = undefined; }
  return { status: res.status, json, buf, headers: res.headers };
};

let seq = 0;
const makeRecord = async (over = {}) => {
  const r = {
    id: `atk-${process.pid}-${seq++}`, strainName: 'Attack Cultivar', bredBy: 'B', dateCreated: '2026-01-01',
    loggedAt: '2026-01-01T00:00:00Z', nonce: newNonce(), notes: '', parents: [], photoFingerprints: [],
    breedingMethod: '', refId: '', ...over,
  };
  r.recordFingerprint = await sha256Hex(canonicalise({
    breedingMethod: r.breedingMethod, bredBy: r.bredBy, dateCreated: r.dateCreated, loggedAt: r.loggedAt,
    nonce: r.nonce, notes: r.notes, parents: r.parents, photoFingerprints: r.photoFingerprints,
    refId: r.refId, strainName: r.strainName,
  }));
  return r;
};

/** Store one record under `holder` and seal it into a new batch (OTS off). */
const sealedBatch = async (holder = H('sealer')) => {
  const rec = await makeRecord();
  const put = await call('PUT', '/api/records', { holder, body: [rec] });
  assert.equal(put.status, 200, JSON.stringify(put.json));
  const s = await call('POST', '/batches/seal', { headers: OP });
  assert.equal(s.status, 200, JSON.stringify(s.json));
  return { ...s.json, fingerprint: rec.recordFingerprint, holder };
};
/** Stamp a batch through the operator route, every default calendar answering honestly. */
const stampHonestly = (batchId, query = '') =>
  withCalendars((url) => new Response(honestAnswer(calendarOf(url))), () => call('POST', `/batches/${batchId}/opentimestamps${query}`, { headers: OP }));
const listed = async (batchId) => (await call('GET', '/batches')).json.batches.find((b) => b.batch_id === batchId);

const ZAP_CSP = "default-src 'none'; frame-ancestors 'none'; form-action 'none'; base-uri 'none'";
const assertHardenedHeaders = (h, where) => {
  assert.equal(h.get('content-security-policy'), ZAP_CSP, where);
  assert.equal(h.get('x-frame-options'), 'DENY', where);
  assert.equal(h.get('x-content-type-options'), 'nosniff', where);
  assert.match(h.get('strict-transport-security') ?? '', /max-age=31536000/, where);
  assert.equal(h.get('x-powered-by'), null, where);
};

// Exports from this address are limited to 10 a minute, and this file makes 7.

// =====================================================================================
// 1 (HIGH) GET /api/export was a cheap single-client denial of service
// =====================================================================================

test('FIXED [HIGH] /api/export: constant SQL work, a per-holder limit, and no-store', async () => {
  const holder = H('export-dos');
  const N = 2000; // linear before; constant now
  const recs = [];
  for (let i = 0; i < N; i++) recs.push(await makeRecord());
  for (let i = 0; i < N; i += 500) {
    assert.equal((await call('PUT', '/api/records', { holder, body: recs.slice(i, i + 500) })).status, 200);
  }
  assert.equal((await call('POST', '/batches/seal', { headers: OP })).status, 200);

  const origPrepare = db.prepare.bind(db);
  let prepares = 0;
  db.prepare = (...a) => { prepares++; return origPrepare(...a); };
  let ex, ms;
  // The first export counts towards "three a minute" below: the clock is held from here so
  // the turn of a minute can't fall between them (helpers.mjs).
  await inOneMinute(async () => {
    const t = performance.now();
    try { ex = await call('GET', '/api/export', { holder }); } finally { db.prepare = origPrepare; }
    ms = Math.round(performance.now() - t);
    assert.equal(ex.status, 200);
    assert.equal(Object.keys(ex.json.proofs).length, N, 'every proof still exported');
    assert.equal(ex.json.batches.length, 1);
    assert.ok(prepares <= 4, `one export prepared ${prepares} statements for ${N} records (was ${2 * N + 4})`);
    assert.equal(ex.headers.get('cache-control'), 'no-store');
    assert.equal((await call('GET', '/api/records', { holder })).headers.get('cache-control'), 'no-store');

    // Three a minute per holder key, then a JSON 429.
    assert.equal((await call('GET', '/api/export', { holder })).status, 200);
    assert.equal((await call('GET', '/api/export', { holder })).status, 200);
    const limited = await call('GET', '/api/export', { holder });
    assert.equal(limited.status, 429);
    assert.match(limited.json.error, /limited/);
  });
  console.log(`# export of ${N} sealed records: ${ms} ms, ${(ex.buf.length / 1e6).toFixed(1)} MB, ${prepares} prepares`);
});

// =====================================================================================
// 2 (MEDIUM) one bad calendar answer poisoned the whole merged .ots
// =====================================================================================

test('FIXED [MEDIUM] answers the reference parser would refuse are refused per calendar; the rest still make a valid .ots', { skip: !hasReference }, async () => {
  const ROOT = 'ab'.repeat(32);
  const digest = sha(Buffer.from(ROOT, 'hex'));
  const good = Buffer.from(ref('fresh', digest.toString('hex'), 'https://honest.example'), 'hex');
  for (const [name, bad] of Object.entries(POISON)) {
    const out = await stampRoot(ROOT, {
      calendars: ['https://honest.example', 'https://evil.example'],
      fetchImpl: async (url) => new Response(url.startsWith('https://evil') ? bad : good),
    });
    assert.deepEqual(out.calendars, ['https://honest.example'], name);
    assert.equal(out.failures.length, 1, name);
    assert.match(out.failures[0], /^https:\/\/evil\.example: /, name);
    const parsed = refParse(out.ots);
    assert.equal(parsed.ok, true, `${name}: ${parsed.error}`);
    assert.deepEqual(parsed.parsed.attestations, ['PendingAttestation:https://honest.example']);
  }
});

test('FIXED [MEDIUM] a pending URI must belong to the calendar asked; only sha256/append/prepend are replayed', async () => {
  const ROOT = 'ab'.repeat(32);
  const cases = [
    ['https://evil.example', pending('https://alice.btc.calendar.opentimestamps.org'), /does not belong/],
    ['https://evil.example', pending('http://evil.example'), /does not belong/],
    ['https://evil.example', pending('https://evil.example:8443'), /does not belong/],
    ['https://evil.example', Buffer.concat([Buffer.from([0x02]), pending('https://evil.example')]), /operation 0x2 not accepted/],
    ['https://evil.example', Buffer.concat([Buffer.from([0x08]), attestation(Buffer.alloc(8, 1), Buffer.alloc(4))]), /attestation type not accepted/],
    ['https://evil.example', Buffer.concat([append(Buffer.alloc(16, 1)), Buffer.from([0x08])]), /truncated/],
  ];
  for (const [calendar, answer, why] of cases) {
    await assert.rejects(stampRoot(ROOT, { calendars: [calendar], fetchImpl: async () => new Response(answer) }), why);
  }
  // How the public aggregators really answer: a.pool names the calendar behind it.
  const ok = await stampRoot(ROOT, {
    calendars: ['https://a.pool.opentimestamps.org'],
    fetchImpl: async () => new Response(honestAnswer('https://alice.btc.calendar.opentimestamps.org')),
  });
  assert.deepEqual(ok.calendars, ['https://a.pool.opentimestamps.org']);
  for (const [calendar, uri] of [
    ['https://b.pool.opentimestamps.org', 'https://bob.btc.calendar.opentimestamps.org'],
    ['https://a.pool.eternitywall.com', 'https://finney.calendar.eternitywall.com'],
    ['https://ots.btc.catallaxy.com', 'https://btc.calendar.catallaxy.com'],
  ]) {
    const r = await stampRoot(ROOT, { calendars: [calendar], fetchImpl: async () => new Response(honestAnswer(uri)) });
    assert.deepEqual(r.calendars, [calendar], uri);
  }
  // ...but not another operator's calendar, even one the reference client trusts.
  await assert.rejects(stampRoot(ROOT, {
    calendars: ['https://a.pool.eternitywall.com'],
    fetchImpl: async () => new Response(honestAnswer('https://alice.btc.calendar.opentimestamps.org')),
  }), /does not belong/);
});

test('FIXED [MEDIUM] end to end: a poisoned calendar is left out of the served .ots, the others kept', { skip: !hasReference }, async () => {
  const b = await sealedBatch();
  const poisoned = DEFAULT_CALENDARS[3];
  const st = await withCalendars(
    (url) => new Response(url.startsWith(poisoned) ? POISON['pending URI with a character the reference refuses (?)'] : honestAnswer(calendarOf(url))),
    () => call('POST', `/batches/${b.batchId}/opentimestamps`, { headers: OP }),
  );
  assert.equal(st.status, 200);
  assert.equal(st.json.calendars.length, 3);
  assert.equal(st.json.failures.length, 1);
  const served = await call('GET', `/batches/${b.batchId}/root.bin.ots`);
  const parsed = refParse(served.buf);
  assert.equal(parsed.ok, true, parsed.error);
  assert.equal(parsed.parsed.attestations.length, 3);
  assert.match((await listed(b.batchId)).opentimestamps.error, /some calendars did not answer/);
});

test('FIXED [LOW] answers are merged op by op, as Timestamp.merge does: identical first ops no longer erase a calendar', { skip: !hasReference }, async () => {
  const same = (uri) => Buffer.concat([Buffer.from([0x08]), pending(uri)]);
  const out = await stampRoot('cd'.repeat(32), {
    calendars: ['https://one.example', 'https://two.example'],
    fetchImpl: async (url) => new Response(same(calendarOf(url))),
  });
  const parsed = refParse(out.ots);
  assert.equal(parsed.ok, true);
  assert.deepEqual(parsed.parsed.attestations, ['PendingAttestation:https://one.example', 'PendingAttestation:https://two.example']);
});

// =====================================================================================
// 3 (MEDIUM) a calendar's promise was presented as an anchor, never upgraded; a calendar
// could plant a Bitcoin attestation
// =====================================================================================

test('FIXED [MEDIUM] proofs and exports say "pending"; an upgrade checks the block and then says "bitcoin" with its height', { skip: !hasReference }, async () => {
  const b = await sealedBatch(H('upgrade-holder'));
  assert.equal((await stampHonestly(b.batchId)).status, 200);
  let entry = (await call('GET', `/proof/${b.fingerprint}`)).json.anchors.find((a) => a.kind === 'opentimestamps');
  assert.equal(entry.status, 'pending');
  assert.match(entry.note, /not a Bitcoin timestamp/);
  assert.equal(entry.bitcoinBlockHeight, undefined);
  assert.equal((await listed(b.batchId)).opentimestamps.status, 'pending');

  // Not yet confirmed: the calendars answer 404 and nothing changes.
  const notYet = await withCalendars(() => new Response('Pending confirmation in Bitcoin blockchain', { status: 404 }),
    () => call('POST', `/batches/${b.batchId}/opentimestamps/upgrade`, { headers: OP }));
  assert.equal(notYet.status, 200);
  assert.equal(notYet.json.status, 'pending');

  // Confirmed.
  const up = await withCalendars(fakeChain(), () => call('POST', `/batches/${b.batchId}/opentimestamps/upgrade`, { headers: OP }));
  assert.equal(up.status, 200, JSON.stringify(up.json));
  assert.equal(up.json.status, 'bitcoin');
  assert.equal(up.json.bitcoinBlockHeight, 940_000);
  assert.equal(up.json.bitcoinBlockTime, new Date(1_790_000_000 * 1000).toISOString());
  // Each upgrade asked the calendar named in the stored answer, at /timestamp/<commitment>.
  entry = (await call('GET', `/proof/${b.fingerprint}`)).json.anchors.find((a) => a.kind === 'opentimestamps');
  assert.equal(entry.status, 'bitcoin');
  assert.equal(entry.bitcoinBlockHeight, 940_000);
  const served = await call('GET', `/batches/${b.batchId}/root.bin.ots`);
  assert.equal(served.headers.get('x-opentimestamps-status'), 'bitcoin');
  const parsed = refParse(served.buf);
  assert.equal(parsed.ok, true, parsed.error);
  assert.ok(parsed.parsed.attestations.includes('BitcoinBlockHeaderAttestation:940000'), JSON.stringify(parsed.parsed));
  const ex = (await call('GET', '/api/export', { holder: b.holder })).json;
  const eb = ex.batches.find((x) => x.batchId === b.batchId);
  assert.equal(eb.opentimestamps.status, 'bitcoin');
  assert.equal(eb.opentimestamps.bitcoinBlockHeight, 940_000);
  assert.match(ex.note, /pending.*still needs the calendars/);
});

test('FIXED [MEDIUM] an upgrade whose block header does not match is not stored', async () => {
  const b = await sealedBatch();
  await stampHonestly(b.batchId);
  const before = (await call('GET', `/batches/${b.batchId}/root.bin.ots`)).buf;
  const up = await withCalendars(fakeChain({ lie: true }), () => call('POST', `/batches/${b.batchId}/opentimestamps/upgrade`, { headers: OP }));
  assert.equal(up.json.status, 'pending');
  assert.ok(up.json.errors.every((e) => /does not match block/.test(e)), JSON.stringify(up.json.errors));
  assert.deepEqual((await call('GET', `/batches/${b.batchId}/root.bin.ots`)).buf, before);
});

test('FIXED [MEDIUM] a fresh answer carrying a Bitcoin attestation is refused, and nothing is stored', async () => {
  const b = await sealedBatch();
  const r = await withCalendars(() => new Response(Buffer.concat([Buffer.from([0x08]), bitcoin(1)])),
    () => call('POST', `/batches/${b.batchId}/opentimestamps`, { headers: OP }));
  assert.equal(r.status, 502);
  assert.match(r.json.error, /cannot carry a Bitcoin attestation/);
  assert.equal((await call('GET', `/batches/${b.batchId}/root.bin.ots`)).status, 404);
  assert.equal((await listed(b.batchId)).opentimestamps.status, 'failed');
});

// =====================================================================================
// 4 (LOW) calendar bodies were read in full before the size cap
// =====================================================================================

test('FIXED [LOW] a calendar body is read only to the cap, and a large Content-Length is refused unread', async () => {
  let pulled = 0;
  const LIMIT = 8 * 1024 * 1024;
  const stream = () => new ReadableStream({
    pull(c) { if (pulled >= LIMIT) return c.close(); pulled += 1024; c.enqueue(new Uint8Array(1024)); },
  });
  await assert.rejects(stampRoot('ab'.repeat(32), { calendars: ['https://big.example'], fetchImpl: async () => new Response(stream()) }), /answer too large/);
  assert.ok(pulled < 64 * 1024, `${pulled} bytes read before refusing`);

  pulled = 0;
  await assert.rejects(stampRoot('ab'.repeat(32), {
    calendars: ['https://big.example'],
    fetchImpl: async () => new Response(stream(), { headers: { 'content-length': String(LIMIT) } }),
  }), /answer too large/);
  assert.ok(pulled <= 16 * 1024, `${pulled} bytes read despite Content-Length`);
});

// =====================================================================================
// 5 (LOW) calendar redirects were followed
// =====================================================================================

test('FIXED [LOW] calendar requests refuse redirects and anything but https', async () => {
  const inits = [];
  await stampRoot('ab'.repeat(32), {
    calendars: ['https://one.example'],
    fetchImpl: async (url, init) => { inits.push(init); return new Response(honestAnswer(calendarOf(url))); },
  });
  assert.equal(inits[0].redirect, 'error');
  let called = false;
  await assert.rejects(stampRoot('ab'.repeat(32), {
    calendars: ['http://127.0.0.1:9', 'file:///etc/passwd'],
    fetchImpl: async () => { called = true; return new Response(''); },
  }), /only https calendars/);
  assert.equal(called, false, 'nothing fetched');
});

// =====================================================================================
// 6 (LOW) a restamp replaced the stored .ots unconditionally
// =====================================================================================

test('FIXED [LOW] a restamp is refused without ?force=1, and with it the new answers are merged in, not swapped in', { skip: !hasReference }, async () => {
  const b = await sealedBatch();
  await stampHonestly(b.batchId);
  const first = (await call('GET', `/batches/${b.batchId}/root.bin.ots`)).buf;
  assert.equal(refParse(first).parsed.attestations.length, 4);

  const refused = await stampHonestly(b.batchId);
  assert.equal(refused.status, 409);
  assert.match(refused.json.error, /force=1/);

  // Three calendars down; force. The four earlier attestations stay.
  const forced = await withCalendars(
    (url) => { if (!url.startsWith(DEFAULT_CALENDARS[0])) throw new Error('down'); return new Response(honestAnswer(calendarOf(url))); },
    () => call('POST', `/batches/${b.batchId}/opentimestamps?force=1`, { headers: OP }),
  );
  assert.equal(forced.status, 200);
  const second = (await call('GET', `/batches/${b.batchId}/root.bin.ots`)).buf;
  const parsed = refParse(second);
  assert.equal(parsed.ok, true);
  assert.equal(parsed.parsed.attestations.length, 5, JSON.stringify(parsed.parsed.attestations));
});

// =====================================================================================
// 7 (LOW) a failed background stamp was invisible
// =====================================================================================

test('FIXED [LOW] a failed background stamp is recorded on the batch, shown in /batches, and retried', async () => {
  const holder = H('silent-fail');
  assert.equal((await call('PUT', '/api/records', { holder, body: [await makeRecord()] })).status, 200);
  delete process.env.VEILCORE_OTS; // production setting
  let s;
  try {
    s = await withCalendars(() => { throw new Error('calendar down'); }, async () => {
      const out = await call('POST', '/batches/seal', { headers: OP });
      // The stamp runs in the background after the seal answers: wait for it to finish.
      await waitFor('the background stamp to finish', async () => (await listed(out.json.batchId)).opentimestamps.status !== 'requested');
      return out;
    });
  } finally { process.env.VEILCORE_OTS = 'off'; }
  assert.equal(s.json.opentimestamps, 'requested');
  const failed = (await listed(s.json.batchId)).opentimestamps;
  assert.equal(failed.status, 'failed');
  assert.match(failed.error, /no OpenTimestamps calendar answered .*connection failed/);

  // What the timer runs: the failed stamp is retried, and now succeeds.
  const run = await withCalendars((url) => new Response(honestAnswer(calendarOf(url))),
    () => call('POST', '/batches/opentimestamps/maintenance', { headers: OP }));
  assert.equal(run.status, 200);
  assert.ok(run.json.stamped.some((x) => x.batchId === s.json.batchId && x.status === 'pending'), JSON.stringify(run.json.stamped));
  assert.equal((await listed(s.json.batchId)).opentimestamps.status, 'pending');
  assert.equal((await call('POST', '/batches/opentimestamps/maintenance')).status, 401);
});

// =====================================================================================
// 8 (LOW) the anchor network defaulted, and disagreed with /.well-known
// =====================================================================================

test('FIXED [LOW] an anchor must name its network and contract, and they must be what /.well-known publishes', async () => {
  const b = await sealedBatch();
  const tx = 'ee'.repeat(32);
  const post = (body) => call('POST', `/batches/${b.batchId}/anchor`, { headers: OP, body });
  assert.equal((await post({ txHash: tx, contractAddress: ANCHOR_CONTRACT })).status, 400, 'no network');
  assert.equal((await post({ txHash: tx, network: 'preprod' })).status, 400, 'no contract');
  assert.equal((await post({ txHash: tx, network: 'preview', contractAddress: ANCHOR_CONTRACT })).status, 400, 'other network');
  assert.equal((await post({ txHash: tx, network: 'preprod', contractAddress: 'ab'.repeat(32) })).status, 400, 'other contract');
  assert.equal((await post({ txHash: tx, network: 'preprod', contractAddress: ANCHOR_CONTRACT.toUpperCase() })).status, 200);
  const proof = (await call('GET', `/proof/${b.fingerprint}`)).json;
  const wk = (await call('GET', '/.well-known/veilcore-registry')).json;
  assert.deepEqual(wk.anchors, [{ chain: 'midnight', network: 'preprod', contractAddress: ANCHOR_CONTRACT }]);
  assert.equal(proof.anchor.network, wk.anchors[0].network);
  assert.equal(proof.anchor.contractAddress.toLowerCase(), wk.anchors[0].contractAddress);
});

test('HELD: anchors already stored keep their network (existing rows are not relabelled)', async () => {
  const b = await sealedBatch();
  db.prepare('UPDATE batches SET anchor = ? WHERE batch_id = ?').run(JSON.stringify({ chain: 'midnight', network: 'preview', txHash: 'aa'.repeat(32) }), b.batchId);
  assert.equal((await call('GET', `/proof/${b.fingerprint}`)).json.anchor.network, 'preview');
});

// =====================================================================================
// Operator error text
// =====================================================================================

test('FIXED [LOW] calendar failures are summarised for the operator, never echoed (no internal addresses, no stack)', async () => {
  const b = await sealedBatch();
  const r = await withCalendars(() => { throw new Error('ECONNREFUSED 10.0.0.5:443'); },
    () => call('POST', `/batches/${b.batchId}/opentimestamps`, { headers: OP }));
  assert.equal(r.status, 502);
  assert.match(r.json.error, /no OpenTimestamps calendar answered/);
  assert.match(r.json.error, /connection failed/);
  assert.ok(!r.json.error.includes('10.0.0.5'), r.json.error);
  assert.ok(!/\n\s+at /.test(r.json.error), 'no stack');
  const t = await withCalendars(() => { const e = new Error('The operation was aborted due to timeout'); e.name = 'TimeoutError'; throw e; },
    () => call('POST', `/batches/${b.batchId}/opentimestamps`, { headers: OP }));
  assert.match(t.json.error, /timed out/);
});

// =====================================================================================
// What held
// =====================================================================================

test('HELD: the OpenTimestamps operator routes need the token, and take no calendar URL from the request', async () => {
  const b = await sealedBatch();
  const before = calendarCalls.length;
  assert.equal((await call('POST', `/batches/${b.batchId}/opentimestamps`)).status, 401);
  assert.equal((await call('POST', `/batches/${b.batchId}/opentimestamps`, { headers: { 'x-operator-token': 'wrong' } })).status, 401);
  assert.equal((await call('POST', `/batches/${b.batchId}/opentimestamps/upgrade`)).status, 401);
  assert.equal(calendarCalls.length, before);
  await withCalendars((url) => new Response(honestAnswer(calendarOf(url))),
    () => call('POST', `/batches/${b.batchId}/opentimestamps?calendars=http://169.254.169.254`, { headers: OP, body: { calendars: ['http://169.254.169.254'] } }));
  assert.deepEqual(calendarCalls.slice(before).map((c) => c.url).sort(), DEFAULT_CALENDARS.map((c) => `${c}/digest`).sort());
});

test('HELD: unknown or hostile batch ids get a JSON 404 with the hardened headers; nothing is stamped', async () => {
  for (const id of ['B-NOPE', "x' OR '1'='1", '..', '%2e%2e%2f..%2fetc', 'pending', '%00']) {
    for (const path of [`/batches/${id}/root.bin`, `/batches/${id}/root.bin.ots`]) {
      const r = await call('GET', path);
      assert.equal(r.status, 404, path);
      assert.ok(r.json?.error, path);
      assertHardenedHeaders(r.headers, path);
    }
  }
  const before = calendarCalls.length;
  const r = await call('POST', '/batches/B-NOPE/opentimestamps', { headers: OP });
  assert.equal(r.status, 404);
  assert.deepEqual(r.json, { error: 'no such batch' });
  assert.equal((await call('POST', '/batches/B-NOPE/opentimestamps/upgrade', { headers: OP })).status, 404);
  assert.equal(calendarCalls.length, before);
});

test('HELD: root.bin, root.bin.ots and /api/export keep the ZAP-hardened headers; root.bin does not swallow root.bin.ots', async () => {
  const b = await sealedBatch(H('headers'));
  const noOts = await call('GET', `/batches/${b.batchId}/root.bin.ots`);
  assert.equal(noOts.status, 404);
  assert.match(noOts.json.error, /no OpenTimestamps proof yet/);
  await stampHonestly(b.batchId);
  const bin = await call('GET', `/batches/${b.batchId}/root.bin`);
  assert.equal(bin.buf.toString('hex'), b.root);
  assert.equal(bin.headers.get('content-type'), 'application/octet-stream');
  assertHardenedHeaders(bin.headers, 'root.bin');
  const ots = await call('GET', `/batches/${b.batchId}/root.bin.ots`);
  assert.equal(ots.headers.get('content-type'), 'application/vnd.opentimestamps.v1');
  assert.ok(ots.buf.subarray(0, 31).toString('latin1').includes('OpenTimestamps'));
  assertHardenedHeaders(ots.headers, 'root.bin.ots');
  const ex = await call('GET', '/api/export', { holder: b.holder });
  assertHardenedHeaders(ex.headers, '/api/export');
});

test('HELD: the export carries no holder key, no other holder\'s records, and an .ots that matches the served one', async () => {
  const A = H('export-a');
  const B = H('export-b');
  const ra = await makeRecord({ notes: 'A private' });
  const rb = await makeRecord({ notes: 'B private' });
  assert.equal((await call('PUT', '/api/records', { holder: A, body: [ra] })).status, 200);
  assert.equal((await call('PUT', '/api/records', { holder: B, body: [rb] })).status, 200);
  const s = (await call('POST', '/batches/seal', { headers: OP })).json; // A and B share a batch
  await stampHonestly(s.batchId);
  const ex = await call('GET', '/api/export', { holder: A });
  const text = ex.buf.toString('utf8');
  assert.ok(!text.includes(A), 'own holder key not echoed');
  assert.ok(!text.includes(B), 'other holder key absent');
  assert.ok(!text.includes('B private') && !text.includes(rb.id) && !text.includes(rb.nonce), 'nothing of B\'s body');
  const batch = ex.json.batches.find((x) => x.batchId === s.batchId);
  const served = (await call('GET', `/batches/${s.batchId}/root.bin.ots`)).buf;
  assert.equal(Buffer.from(batch.opentimestamps.ots, 'base64').toString('hex'), served.toString('hex'));
  assert.equal(batch.opentimestamps.status, 'pending');
  assert.deepEqual(Object.keys(batch).sort(), ['anchor', 'batchId', 'opentimestamps', 'recordCount', 'rfc3161', 'root', 'sealedAt']);
  assert.deepEqual(Object.keys(ex.json.proofs), [ra.recordFingerprint]);
});

test('FIXED [LOW] a seal never reuses a batch id: with half of today\u2019s ids taken, every seal still gets a free one', async () => {
  // A batch id is the day and four random hex digits. A repeat made the batch insert fail
  // as "another seal got there first", with no batch written (15 Oct 2026).
  const db = new Database(':memory:');
  db.exec('CREATE TABLE records (id TEXT PRIMARY KEY, body TEXT)');
  const b = createBatches(db);
  const day = new Date().toISOString().slice(0, 10).replace(/-/g, '');
  const used = db.prepare('INSERT INTO batches (batch_id, root, sealed_at, record_count) VALUES (?, ?, ?, ?)');
  db.transaction(() => {
    for (let i = 0; i < 0x10000; i += 2) used.run(`B-${day}-${i.toString(16).padStart(4, '0').toUpperCase()}`, 'ab'.repeat(32), 1, 1);
  })();
  const ids = new Set();
  for (let k = 0; k < 20; k++) {
    db.prepare('INSERT INTO records VALUES (?, ?)').run(`r${k}`, JSON.stringify({ recordFingerprint: createHash('sha256').update(`r${k}`).digest('hex') }));
    const s = await b.seal();
    assert.ok(s.batchId, `seal ${k}: ${JSON.stringify(s)}`);
    ids.add(s.batchId);
  }
  assert.equal(ids.size, 20);
});

// =====================================================================================
// Migration and the timer
// =====================================================================================

test('HELD: a database from main (no OpenTimestamps columns) keeps every batch, proof and anchor', async () => {
  const old = new Database(':memory:');
  old.exec(`
    CREATE TABLE records (id TEXT PRIMARY KEY, holder_key TEXT NOT NULL, body TEXT NOT NULL, updated_at INTEGER NOT NULL);
    CREATE TABLE batches (batch_id TEXT PRIMARY KEY, root TEXT NOT NULL, sealed_at INTEGER NOT NULL, record_count INTEGER NOT NULL, anchor TEXT);
    CREATE TABLE batch_proofs (commitment TEXT PRIMARY KEY, batch_id TEXT NOT NULL, proof TEXT NOT NULL);`);
  const anchor = { chain: 'midnight', network: 'preview', txHash: 'aa'.repeat(32) };
  old.prepare('INSERT INTO batches VALUES (?,?,?,?,?)').run('B-OLD', 'ab'.repeat(32), 1, 1, JSON.stringify(anchor));
  old.prepare('INSERT INTO batch_proofs VALUES (?,?,?)').run('cc'.repeat(32), 'B-OLD', JSON.stringify({ commitment: 'cc'.repeat(32), root: 'ab'.repeat(32), batchId: 'B-OLD', path: [] }));
  const b = createBatches(old);
  createBatches(old); // a second start adds nothing twice
  const [row] = b.list();
  assert.equal(row.batch_id, 'B-OLD');
  // Served with `testNetwork` added (mainnet readiness, 6 Oct 2026); the stored row is untouched.
  assert.deepEqual(row.anchor, { ...anchor, testNetwork: true });
  assert.equal(old.prepare('SELECT anchor FROM batches WHERE batch_id = ?').get('B-OLD').anchor, JSON.stringify(anchor));
  assert.equal(row.opentimestamps.status, 'none');
  const proof = b.proofFor('cc'.repeat(32));
  assert.deepEqual(proof.anchor, { ...anchor, testNetwork: true });
  assert.equal(proof.anchors, undefined, 'no OpenTimestamps entry for a batch never stamped');
  assert.deepEqual(b.otsFor('B-OLD').status, 'none');
  // The timer leaves batches sealed before stamping alone; only the operator stamps them.
  assert.deepEqual(await b.otsMaintenance(), { stamped: [], upgraded: [] });
});

test('HELD: a database from the first ots commit: a valid stored .ots is kept as one answer, an invalid one dropped and flagged', { skip: !hasReference }, async () => {
  const old = new Database(':memory:');
  old.exec(`
    CREATE TABLE records (id TEXT PRIMARY KEY, holder_key TEXT NOT NULL, body TEXT NOT NULL, updated_at INTEGER NOT NULL);
    CREATE TABLE batches (batch_id TEXT PRIMARY KEY, root TEXT NOT NULL, sealed_at INTEGER NOT NULL, record_count INTEGER NOT NULL, anchor TEXT, ots BLOB, ots_calendars TEXT);`);
  const rootA = 'ab'.repeat(32);
  const rootB = 'cd'.repeat(32);
  const good = otsFile(sha(Buffer.from(rootA, 'hex')), [honestAnswer('https://a.pool.opentimestamps.org')]);
  const poisoned = Buffer.concat([good.subarray(0, 31 + 1 + 1 + 32), POISON['257 nested sha256 ops (reference limit is 256)']]);
  old.prepare('INSERT INTO batches VALUES (?,?,?,?,NULL,?,?)').run('B-A', rootA, 1, 1, good, '["https://a.pool.opentimestamps.org"]');
  old.prepare('INSERT INTO batches VALUES (?,?,?,?,NULL,?,?)').run('B-B', rootB, 2, 1, poisoned, '["https://evil.example"]');
  const b = createBatches(old);
  const a = b.otsFor('B-A');
  assert.equal(a.status, 'pending');
  assert.equal(refParse(a.ots).ok, true);
  const bb = b.list().find((x) => x.batch_id === 'B-B');
  assert.equal(bb.opentimestamps.status, 'failed');
  assert.match(bb.opentimestamps.error, /failed validation/);
  assert.equal(b.otsFor('B-B').ots, null);
});

test('FIXED [LOW] the timer retries a failed stamp on its own, and does not run with VEILCORE_OTS=off', async () => {
  const child = fileURLToPath(new URL('./fixtures/ots-timer-child.mjs', import.meta.url));
  const run = (env) => {
    const e = { ...process.env, ...env };
    if (env.VEILCORE_OTS === undefined) delete e.VEILCORE_OTS;
    const out = execFileSync(process.execPath, [child], { env: e, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    return JSON.parse(out.trim().split('\n').pop());
  };
  const on = run({ VEILCORE_OTS: undefined, WANT_CALLS: '8' });
  assert.ok(on.calls >= 8, `seal asked 4 calendars, the timer retried at least once: ${on.calls} requests`);
  const off = run({ VEILCORE_OTS: 'off' });
  assert.equal(off.calls, 0);
});

test('INFO: VEILCORE_OTS=off stops the automatic stamp and the timer; the operator route still calls out', async () => {
  const b = await sealedBatch();
  assert.equal(process.env.VEILCORE_OTS, 'off');
  assert.equal((await listed(b.batchId)).opentimestamps.status, 'none');
  const before = calendarCalls.length;
  await withCalendars(() => { throw new Error('down'); }, () => call('POST', `/batches/${b.batchId}/opentimestamps`, { headers: OP }));
  assert.equal(calendarCalls.length - before, 4);
});
