// The public mirror and the witness's checker (scripts/mirror). The mirror runs against this
// registry, in memory, seeded with two real batches from the live registry
// (fixtures/mirror-live.json); a "rewrite" is made by changing the database underneath it, as
// an operator could. The checker's Midnight and Bitcoin lookups are answered by stubs: no
// network beyond 127.0.0.1.
// SPDX-License-Identifier: Apache-2.0

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { createHash } from 'node:crypto';
import { execFile, execFileSync } from 'node:child_process';
import { cpSync, existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { basename, join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { untilReady } from './helpers.mjs';
import { parseOtsFile, otsFile, serialiseTimestamp, rootDigest } from '../lineage/ots.mjs';
import { mirror, listAll, RECHECK_ALL, RECHECK_SLICES } from '../scripts/mirror/mirror.mjs';
import { check, checkTsa, checkOts, checkMidnight, stateHoldsRoot, OK, MISMATCH, UNCHECKED } from '../scripts/mirror/check.mjs';
import { compareRecords, otsChange, batchRecord, printable, MAINNET_CONTRACT } from '../scripts/mirror/common.mjs';
import { indexersFrom } from '../scripts/mirror/witness.mjs';

process.env.DB_PATH = ':memory:';
process.env.VEILCORE_OTS = 'off';
const require = createRequire(import.meta.url);
const { app, db } = require('../server.js');

const live = JSON.parse(readFileSync(new URL('./fixtures/mirror-live.json', import.meta.url)));
const [BTC, PENDING] = live.batches; // B-20261118-EB89 (Bitcoin, token), B-20261118-C44A (pending)
const WITNESS = fileURLToPath(new URL('../scripts/mirror/witness.mjs', import.meta.url));
const SDK = (await import('veilcore-records')).verifyTimestampToken;

let base;
let server;
const dirs = [];
const tmp = (p) => { const d = mkdtempSync(join(tmpdir(), p)); dirs.push(d); return d; };
before(async () => {
  server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  base = `http://127.0.0.1:${server.address().port}`;
  await untilReady(base);
});
after(() => { server.close(); for (const d of dirs) rmSync(d, { recursive: true, force: true }); });

// ---- seeding the registry ----
/** An anchor as stored: the registry adds testNetwork when it serves one. */
const stored = (a) => Object.fromEntries(Object.entries(a).filter(([k]) => k !== 'testNetwork'));
const clear = () => db.exec('DELETE FROM batches; DELETE FROM batch_anchor_history');
const seed = (e, { id = e.row.batch_id, ots = e.ots, status = e.row.opentimestamps.status, tst = e.tst, sealedAt = e.row.sealed_at } = {}) => {
  const r = e.row;
  const h = status === 'bitcoin' ? r.opentimestamps : {};
  db.prepare(`INSERT INTO batches (batch_id, root, sealed_at, record_count, anchor, ots, ots_status, ots_bitcoin_height, ots_bitcoin_time, tsa_token)
    VALUES (?,?,?,?,?,?,?,?,?,?)`).run(id, r.root, sealedAt, r.record_count,
    r.anchor ? JSON.stringify(stored(r.anchor)) : null,
    ots ? Buffer.from(ots, 'base64') : null, ots ? status : null, h.bitcoinBlockHeight ?? null, h.bitcoinBlockTime ?? null,
    tst ? Buffer.from(tst, 'base64') : null);
};
const set = (id, col, v) => db.prepare(`UPDATE batches SET ${col} = ? WHERE batch_id = ?`).run(v, id);
const sha256hex = (b) => createHash('sha256').update(b).digest('hex');
const files = (d) => readdirSync(d, { recursive: true }).filter((f) => statSync(join(d, f)).isFile()).sort();

/** The same proof with every Bitcoin attestation (and the path to it) taken out: what it was while pending. */
const prune = (ts) => {
  const out = { msg: ts.msg, attestations: new Map([...ts.attestations].filter(([, a]) => a.kind !== 'bitcoin')), ops: new Map() };
  for (const [k, { op, ts: sub }] of ts.ops) {
    const p = prune(sub);
    if (p.attestations.size || p.ops.size) out.ops.set(k, { op, ts: p });
  }
  return out;
};
const root = BTC.row.root;
const btcOts = Buffer.from(BTC.ots, 'base64');
const pendingOts = otsFile(rootDigest(root), [serialiseTimestamp(prune(parseOtsFile(btcOts, rootDigest(root))))]);

// ---- the registry's paging ----

test('GET /batches pages newest first by a cursor; without limit it lists every batch, as before', async () => {
  clear();
  const t = Date.UTC(2026, 10, 1);
  for (const [i, id] of ['B-A', 'B-B', 'B-C', 'B-D', 'B-E'].entries()) seed(PENDING, { id, sealedAt: t + (i < 2 ? 0 : i) * 1000 });
  const all = await (await fetch(`${base}/batches`)).json();
  assert.deepEqual(Object.keys(all), ['batches'], 'the unpaged answer is unchanged: no next');
  assert.deepEqual(all.batches.map((b) => b.batch_id), ['B-E', 'B-D', 'B-C', 'B-B', 'B-A'], 'a tie in sealing time is ordered by id');
  const seen = [];
  let url = `${base}/batches?limit=2`;
  for (;;) {
    const p = await (await fetch(url)).json();
    seen.push(...p.batches.map((b) => b.batch_id));
    if (p.next === null) break;
    url = `${base}/batches?limit=2&before=${p.next}`;
  }
  assert.deepEqual(seen, ['B-E', 'B-D', 'B-C', 'B-B', 'B-A']);
  for (const q of ['limit=0', 'limit=501', 'limit=abc', 'limit=2&before=B-NOPE', 'limit=2&before=../x', 'before=B-A']) {
    assert.equal((await fetch(`${base}/batches?${q}`)).status, 400, q);
  }
});

test('the mirror pages through every batch, and a registry that ignores paging still gives all of them', async () => {
  clear();
  for (const [i, id] of ['B-1', 'B-2', 'B-3'].entries()) seed(PENDING, { id, sealedAt: Date.UTC(2026, 10, 1) + i });
  const asked = [];
  const spy = (u, i) => { asked.push(new URL(u).search); return fetch(u, i); };
  assert.deepEqual((await listAll(base, { fetchImpl: spy, pageSize: 1 })).map((e) => e.rec.batchId), ['B-3', 'B-2', 'B-1']);
  assert.deepEqual(asked, ['?limit=1', '?limit=1&before=B-3', '?limit=1&before=B-2']);

  const rows = (await (await fetch(`${base}/batches`)).json()).batches;
  const old = async () => new Response(JSON.stringify({ batches: rows })); // before paging: no next
  assert.equal((await listAll('https://registry.test', { fetchImpl: old })).length, 3);
  const loop = async () => new Response(JSON.stringify({ batches: rows.slice(0, 1), next: 'B-3' }));
  await assert.rejects(listAll('https://registry.test', { fetchImpl: loop }), /cursor that goes nowhere/);
  const twice = async (u) => new Response(JSON.stringify(new URL(u).searchParams.get('before')
    ? { batches: [{ ...rows[0], record_count: 99 }], next: null } : { batches: rows.slice(0, 1), next: rows[0].batch_id }));
  await assert.rejects(listAll('https://registry.test', { fetchImpl: twice }), /listed B-3 twice, differently/);
});

// ---- mirroring ----

test('a first run copies every batch; a second changes nothing on disk', async () => {
  clear(); seed(BTC); seed(PENDING);
  const out = tmp('mirror-');
  const s = await mirror({ api: base, out });
  assert.deepEqual(s.added.sort(), [BTC.row.batch_id, PENDING.row.batch_id].sort());
  assert.equal(s.conflicts.length, 0);
  const b = join(out, 'batches', BTC.row.batch_id);
  assert.deepEqual(readdirSync(b).sort(), ['batch.json', 'root.bin', 'root.bin.ots', 'root.tst']);
  assert.equal(readFileSync(join(b, 'root.bin')).toString('hex'), root);
  assert.ok(readFileSync(join(b, 'root.bin.ots')).equals(btcOts));
  assert.ok(readFileSync(join(b, 'root.tst')).equals(Buffer.from(BTC.tst, 'base64')));
  assert.deepEqual(readdirSync(join(out, 'batches', PENDING.row.batch_id)).sort(), ['batch.json', 'root.bin', 'root.bin.ots']);
  const index = JSON.parse(readFileSync(join(out, 'index.json')));
  assert.equal(index.format, 'veilcore-mirror/1');
  assert.deepEqual(index.batches.map((x) => x.batchId), [BTC.row.batch_id, PENDING.row.batch_id], 'oldest first, so new batches append');
  assert.equal(index.batches[0].files['root.bin.ots'], createHash('sha256').update(btcOts).digest('hex'));

  // A run works on a copy and swaps it in, keeping times to the millisecond.
  const state = () => Object.fromEntries(files(out).map((f) => [f, [Math.floor(statSync(join(out, f)).mtimeMs), sha256hex(readFileSync(join(out, f)))]]));
  const before = state();
  const again = await mirror({ api: base, out, full: true });
  assert.equal(again.unchanged, 2);
  assert.deepEqual(state(), before, 'nothing rewritten');
});

test('pending -> Bitcoin is a normal update, told apart by the new proof keeping everything the old one proved', async () => {
  clear();
  seed(BTC, { ots: pendingOts.toString('base64'), status: 'pending', tst: null });
  const out = tmp('mirror-');
  await mirror({ api: base, out });
  const f = join(out, 'batches', BTC.row.batch_id, 'root.bin.ots');
  assert.ok(readFileSync(f).equals(pendingOts));
  assert.equal(otsChange(root, pendingOts, btcOts).kind, 'upgraded');

  set(BTC.row.batch_id, 'ots', btcOts); set(BTC.row.batch_id, 'ots_status', 'bitcoin');
  set(BTC.row.batch_id, 'ots_bitcoin_height', 976480); set(BTC.row.batch_id, 'ots_bitcoin_time', BTC.row.opentimestamps.bitcoinBlockTime);
  set(BTC.row.batch_id, 'tsa_token', Buffer.from(BTC.tst, 'base64'));
  const s = await mirror({ api: base, out });
  assert.equal(s.conflicts.length, 0);
  assert.deepEqual(s.updated[0].what, ['OpenTimestamps status pending -> bitcoin', 'root.bin.ots upgraded', 'root.tst added']);
  assert.ok(readFileSync(f).equals(btcOts));

  // Final now, but still fetched again and compared on an ordinary run (RECHECK_ALL), so a
  // swapped token or proof is caught without waiting for a full run.
  const asked = [];
  await mirror({ api: base, out, fetchImpl: (u, i) => { asked.push(new URL(u).pathname); return fetch(u, i); } });
  for (const f of ['root.bin', 'root.bin.ots', 'root.tst']) assert.ok(asked.some((p) => p.endsWith(f)), f);
  set(BTC.row.batch_id, 'tsa_token', Buffer.from('3000', 'hex'));
  assert.match((await mirror({ api: base, out })).conflicts[0].reasons.join(), /root\.tst changed/, 'caught without --full');
});

/** Mirror, change the registry with `rewrite`, mirror again: the second run must refuse. */
const refused = async (rewrite, pattern, { seedWith = () => { seed(BTC); } } = {}) => {
  clear(); seedWith();
  const out = tmp('mirror-');
  await mirror({ api: base, out });
  const snapshot = Object.fromEntries(files(out).map((f) => [f, readFileSync(join(out, f))]));
  rewrite();
  const s = await mirror({ api: base, out, full: true });
  assert.equal(s.conflicts.length, 1, 'one batch in conflict');
  assert.match(s.conflicts[0].reasons.join('; '), pattern);
  for (const [f, b] of Object.entries(snapshot)) {
    if (f !== 'index.json') assert.ok(readFileSync(join(out, f)).equals(b), `${f} kept as it was`);
  }
  const kept = join(out, s.conflicts[0].keptIn);
  assert.ok(existsSync(join(kept, 'conflict.json')), 'the other version is kept beside it');
  const index = JSON.parse(readFileSync(join(out, 'index.json')));
  assert.deepEqual(index.batches.find((b) => b.batchId === s.conflicts[0].batchId).conflicts, [s.conflicts[0].keptIn]);
  // Seen again: reported again, not written twice.
  const s2 = await mirror({ api: base, out, full: true });
  assert.equal(s2.conflicts.length, 1);
  assert.equal(readdirSync(join(out, 'conflicts', s.conflicts[0].batchId)).length, 1);
  return { out, kept };
};

test('append-only: a changed root is refused, the old copy kept and the new one kept beside it', async () => {
  const { kept } = await refused(() => set(BTC.row.batch_id, 'root', 'ee'.repeat(32)), /root changed/);
  assert.equal(JSON.parse(readFileSync(join(kept, 'batch.json'))).root, 'ee'.repeat(32));
});

test('append-only: a mainnet anchor replaced by another transaction is refused', async () => {
  await refused(() => set(BTC.row.batch_id, 'anchor', JSON.stringify({ ...BTC.row.anchor, txHash: 'ab'.repeat(32) })), /anchor changed/);
});

test('append-only: an anchor removed, a token changed or gone, a batch gone are each refused', async () => {
  await refused(() => set(BTC.row.batch_id, 'anchor', null), /anchor .* was removed/);
  await refused(() => set(BTC.row.batch_id, 'tsa_token', Buffer.from('3000', 'hex')), /root\.tst changed/);
  await refused(() => set(BTC.row.batch_id, 'tsa_token', null), /root\.tst was there and is gone/);
  await refused(() => db.prepare('DELETE FROM batches WHERE batch_id = ?').run(BTC.row.batch_id), /no longer lists/);
});

test('append-only: a proof that loses its Bitcoin attestation is refused, even though it parses', async () => {
  await refused(() => set(BTC.row.batch_id, 'ots', pendingOts), /drops something the old one proved/);
});

test('a test-network anchor followed by a mainnet one is an update only when the registry keeps the old one', async () => {
  const preview = { chain: 'midnight', network: 'preview', contractAddress: 'f7'.repeat(32), txHash: 'c1'.repeat(32), blockHeight: 5, anchoredAt: '2026-11-18T19:00:00.000Z' };
  const seedPreview = () => { seed(BTC); set(BTC.row.batch_id, 'anchor', JSON.stringify(preview)); };
  const mainnet = JSON.stringify(stored(BTC.row.anchor));
  await refused(() => set(BTC.row.batch_id, 'anchor', mainnet), /anchor changed/, { seedWith: seedPreview });

  clear(); seedPreview();
  const out = tmp('mirror-');
  await mirror({ api: base, out });
  db.prepare('INSERT INTO batch_anchor_history (batch_id, anchor, replaced_at) VALUES (?,?,?)').run(BTC.row.batch_id, JSON.stringify(preview), Date.now());
  set(BTC.row.batch_id, 'anchor', mainnet);
  const s = await mirror({ api: base, out });
  assert.equal(s.conflicts.length, 0);
  assert.match(s.updated[0].what.join(), /anchored again on mainnet/);
  const kept = JSON.parse(readFileSync(join(out, 'batches', BTC.row.batch_id, 'batch.json')));
  assert.equal(kept.anchor.network, 'mainnet');
  assert.equal(kept.earlierAnchors[0].txHash, preview.txHash);
  // ...and once kept, an earlier anchor may not disappear.
  const dropped = compareRecords(kept, { ...kept, earlierAnchors: undefined });
  assert.match(dropped.conflicts.join(), /earlier anchor was removed/);
});

test('the command exits 2 and says so loudly when the registry rewrote history', async () => {
  clear(); seed(BTC);
  const out = tmp('mirror-');
  const run = () => new Promise((res) => execFile(process.execPath, [WITNESS, 'mirror', out, '--registry', base], (err, stdout, stderr) => res({ code: err?.code ?? 0, stdout, stderr })));
  assert.equal((await run()).code, 0);
  set(BTC.row.batch_id, 'record_count', 99);
  const r = await run();
  assert.equal(r.code, 2);
  assert.match(r.stderr, /THE REGISTRY CHANGED HISTORY/);
  assert.match(r.stderr, /recordCount changed from 4 to 99/);
});

// ---- the checker ----

/** A mirror of the two live batches, made once, for the checker tests to copy. */
let liveMirror;
const fresh = async () => {
  if (!liveMirror) { clear(); seed(BTC); seed(PENDING); liveMirror = tmp('live-'); await mirror({ api: base, out: liveMirror }); }
  const d = tmp('copy-'); cpSync(liveMirror, d, { recursive: true }); return d;
};

/** An Esplora explorer that knows one block, whose header holds `merkle`. */
const explorer = (height, merkle, { down = false } = {}) => {
  const header = Buffer.alloc(80);
  merkle.copy(header, 36);
  header.writeUInt32LE(Math.floor(Date.parse('2026-11-18T20:44:53Z') / 1000), 68);
  const sha = (b) => createHash('sha256').update(b).digest();
  const hash = Buffer.from(sha(sha(header))).reverse().toString('hex');
  return async (u) => {
    if (down) throw new Error('down');
    if (u.endsWith(`/block-height/${height}`)) return new Response(hash);
    if (u.endsWith(`/block/${hash}/header`)) return new Response(header.toString('hex'));
    return new Response('', { status: 404 });
  };
};
const btcMerkle = () => {
  const out = [];
  const walk = (ts) => { for (const a of ts.attestations.values()) if (a.kind === 'bitcoin') out.push(ts.msg); for (const { ts: s } of ts.ops.values()) walk(s); };
  walk(parseOtsFile(btcOts, rootDigest(root)));
  return out[0];
};

test('Bitcoin: the block header holding the proof\'s Merkle root is OK; another is a mismatch; no answer is couldn\'t check', async () => {
  const d = await fresh();
  const dir = join(d, 'batches', BTC.row.batch_id);
  const rec = JSON.parse(readFileSync(join(dir, 'batch.json')));
  const E = ['https://explorer.test/api'];
  assert.equal((await checkOts({ dir, rec, explorers: E, fetchImpl: explorer(976480, btcMerkle()) })).status, OK);
  const bad = await checkOts({ dir, rec, explorers: E, fetchImpl: explorer(976480, Buffer.alloc(32, 7)) });
  assert.equal(bad.status, MISMATCH);
  assert.match(bad.detail, /does not hold the Merkle root/);
  assert.equal((await checkOts({ dir, rec, explorers: E, fetchImpl: explorer(1, btcMerkle(), { down: true }) })).status, UNCHECKED);
  assert.match((await checkOts({ dir, rec, explorers: [], fetchImpl: null })).detail, /names Bitcoin block 976480.*offline.*ots verify/);
  // The registry claiming a block the proof doesn't name.
  assert.equal((await checkOts({ dir, rec: { ...rec, opentimestamps: { status: 'bitcoin', bitcoinBlockHeight: 5 } }, explorers: [] })).status, MISMATCH);
  // A proof for another root.
  assert.equal((await checkOts({ dir, rec: { ...rec, root: 'ee'.repeat(32) }, explorers: [] })).status, MISMATCH);
  const pdir = join(d, 'batches', PENDING.row.batch_id);
  assert.match((await checkOts({ dir: pdir, rec: JSON.parse(readFileSync(join(pdir, 'batch.json'))), explorers: E })).detail, /^pending/);
});

test('RFC 3161: the live token stamps its root; without the TSA\'s certificate that is couldn\'t check, never OK', async () => {
  const d = await fresh();
  const dir = join(d, 'batches', BTC.row.batch_id);
  const rec = JSON.parse(readFileSync(join(dir, 'batch.json')));
  for (const sdk of [SDK, null]) {
    const v = await checkTsa({ dir, rec, sdk });
    assert.equal(v.status, UNCHECKED, v.detail);
    assert.match(v.detail, /stamps this root and its signature verifies \(dated .*2026.*whose signature it is was not checked/);
  }
  // The same token beside another root: a mismatch, with the SDK and with openssl alone.
  const other = tmp('tsa-');
  writeFileSync(join(other, 'root.bin'), Buffer.alloc(32, 0xee));
  cpSync(join(dir, 'root.tst'), join(other, 'root.tst'));
  for (const sdk of [SDK, null]) assert.equal((await checkTsa({ dir: other, rec: { ...rec, root: 'ee'.repeat(32) }, sdk })).status, MISMATCH);
  assert.equal((await checkTsa({ dir: join(d, 'batches', PENDING.row.batch_id), rec, sdk: SDK })).status, UNCHECKED);
});

test('RFC 3161: with the TSA\'s root certificate the chain is checked: OK for its own token, mismatch for another CA', async () => {
  const w = tmp('ca-');
  const ssl = (...a) => execFileSync('openssl', a, { cwd: w, stdio: ['ignore', 'pipe', 'pipe'] });
  writeFileSync(join(w, 'ext.cnf'), 'extendedKeyUsage = critical,timeStamping\nbasicConstraints = CA:FALSE\n');
  ssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key', '-out', 'ca.pem', '-days', '2', '-subj', '/CN=Test TSA Root');
  ssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'x.key', '-out', 'other-ca.pem', '-days', '2', '-subj', '/CN=Another Root');
  ssl('req', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'tsa.key', '-out', 'tsa.csr', '-subj', '/CN=Test TSA');
  ssl('x509', '-req', '-in', 'tsa.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial', '-out', 'tsa.pem', '-days', '2', '-extfile', 'ext.cnf');
  writeFileSync(join(w, 'tsa.cnf'), `[ tsa ]\ndefault_tsa = t\n[ t ]\nserial = ${w}/serial\nsigner_cert = ${w}/tsa.pem\nsigner_key = ${w}/tsa.key\nsigner_digest = sha256\ndefault_policy = 1.2.3.4.1\ndigests = sha256\ness_cert_id_alg = sha256\naccuracy = secs:1\nordering = no\ntsa_name = no\ness_cert_id_chain = no\ncerts = ${w}/tsa.pem\n`);
  writeFileSync(join(w, 'serial'), '01\n');
  writeFileSync(join(w, 'root.bin'), Buffer.from(root, 'hex'));
  ssl('ts', '-query', '-data', 'root.bin', '-sha256', '-cert', '-out', 'q.tsq');
  ssl('ts', '-reply', '-config', 'tsa.cnf', '-queryfile', 'q.tsq', '-out', 'r.tsr');
  ssl('ts', '-reply', '-in', 'r.tsr', '-token_out', '-out', 'root.tst');
  const rec = { root, sealedAt: '2026-01-01T00:00:00.000Z' };
  for (const sdk of [SDK, null]) {
    assert.equal((await checkTsa({ dir: w, rec, sdk, tsaCa: join(w, 'ca.pem') })).status, OK);
    assert.equal((await checkTsa({ dir: w, rec, sdk, tsaCa: join(w, 'other-ca.pem') })).status, MISMATCH);
  }
  // A token can't be older than the batch it stamps.
  assert.match((await checkTsa({ dir: w, rec: { root, sealedAt: '2099-01-01T00:00:00.000Z' }, sdk: SDK, tsaCa: join(w, 'ca.pem') })).detail, /before the batch was sealed/);
});

// Midnight, against a stubbed indexer (none is reachable from where these tests run).
const A = live.anchorState; // a real VeilCore contract state right after anchorBatch(A.root)
const TX = '12'.repeat(32);
const anchored = (over = {}) => ({ root: A.root, anchor: { chain: 'midnight', network: 'mainnet', contractAddress: MAINNET_CONTRACT, txHash: TX, blockHeight: 100, anchoredAt: '2026-11-18T20:00:00.000Z', ...over } });
const indexer = ({ state = A.stateHex, entryPoint = 'anchorBatch', status = 'SUCCESS', height = 100, calls = 1, http = 200, address = MAINNET_CONTRACT } = {}) => {
  const seen = [];
  const f = async (url, init) => {
    seen.push({ url, body: JSON.parse(init.body) });
    if (http !== 200) return new Response('', { status: http });
    const tx = { hash: TX, block: { height, timestamp: Date.parse('2026-11-18T20:00:00Z') }, identifiers: [], transactionResult: { status },
      contractActions: Array.from({ length: calls }, () => ({ address, state, entryPoint })) };
    return new Response(JSON.stringify({ data: { byHash: [tx], byId: [] } }));
  };
  f.seen = seen;
  return f;
};
const mid = (rec, fetchImpl, indexers = ['https://indexer.test/graphql']) => checkMidnight({ rec, indexers, fetchImpl });

test('Midnight: the transaction wrote this root on VeilCore\'s contract in the recorded block: OK', async () => {
  const f = indexer();
  const v = await mid(anchored(), f);
  assert.equal(v.status, OK, v.detail);
  assert.match(v.detail, /block 100 at 2026-11-18T20:00:00.000Z/);
  assert.match(f.seen[0].body.query, /VEILCORE_ANCHOR_CHECK/);
  assert.deepEqual(f.seen[0].body.variables, { byHash: { hash: TX }, byId: { identifier: TX } });
  assert.equal((await mid(anchored(), indexer({ entryPoint: Buffer.from('anchorBatch').toString('hex') }))).status, OK, 'entry point as hex');
  assert.equal((await mid(anchored(), indexer(), ['https://a.test', 'https://b.test'])).status, OK);
  assert.match((await mid(anchored({ anchoredAt: '2026-11-01T00:00:00Z' }), indexer())).detail, /note: the registry shows/);
});

test('Midnight: every way the chain disagrees with the registry is a mismatch', async () => {
  const cases = [
    [indexer({ state: A.otherStateHex }), /does not hold this batch root/],
    [indexer({ height: 101 }), /recorded block 100; Midnight says block 101/],
    [indexer({ entryPoint: 'anchorbatch' }), /not a date stamp/],
    [indexer({ status: 'FAILURE' }), /did not succeed/],
    [indexer({ calls: 2 }), /more than one call/],
    [indexer({ address: 'cd'.repeat(32) }), /no call on VeilCore's contract/],
  ];
  for (const [f, why] of cases) {
    const v = await mid(anchored(), f);
    assert.equal(v.status, MISMATCH, String(why));
    assert.match(v.detail, why);
  }
  assert.match((await mid(anchored({ contractAddress: 'cd'.repeat(32) }), indexer())).detail, /not VeilCore's mainnet contract/);
  let n = 0;
  const two = async (u, i) => (n++ ? indexer({ height: 100 }) : indexer({ height: 100 }))(u, i);
  assert.equal((await mid(anchored(), two, ['https://a.test', 'https://b.test'])).status, OK);
  const split = async (u, i) => indexer({ height: u.includes('a.test') ? 100 : 101, state: A.stateHex })(u, i);
  assert.equal((await mid(anchored({ blockHeight: undefined }), split, ['https://a.test', 'https://b.test'])).status, MISMATCH);
});

test('Midnight: no indexer, an indexer down, a test network, no anchor: couldn\'t check, and a key in the URL never shows', async () => {
  assert.match((await mid(anchored(), indexer(), [])).detail, /no Midnight indexer given/);
  const down = await mid(anchored(), indexer({ http: 503 }), ['https://midnight-mainnet.blockfrost.io/api/v0?project_id=not-a-real-id-7f3a']);
  assert.equal(down.status, UNCHECKED);
  assert.doesNotMatch(down.detail, /not-a-real-id/);
  assert.match((await mid(anchored({ network: 'preview' }), indexer())).detail, /test network/);
  assert.equal((await mid({ root: A.root, anchor: null }, indexer())).status, UNCHECKED);
  assert.ok(stateHoldsRoot(A.stateHex, A.root));
  assert.ok(!stateHoldsRoot(`0${A.stateHex}`, A.root), 'only byte-aligned');
  assert.deepEqual(indexersFrom([], { BLOCKFROST_PROJECT_ID: 'k1', MIDNIGHT_INDEXER_URL: 'https://x.test/g, https://y.test/g' }),
    ['https://x.test/g', 'https://y.test/g', 'https://midnight-mainnet.blockfrost.io/api/v0?project_id=k1']);
});

test('the whole mirror: OK only when every part is; a tampered file or a kept conflict is a mismatch', async () => {
  const d = await fresh();
  const merkle = btcMerkle();
  const opts = { explorers: ['https://explorer.test/api'], indexers: [], sdk: SDK, fetchImpl: explorer(976480, merkle) };
  let r = await check(d, opts);
  const byId = Object.fromEntries(r.results.map((x) => [x.batchId, x]));
  assert.equal(byId[BTC.row.batch_id].parts.files.status, OK);
  assert.equal(byId[BTC.row.batch_id].parts.bitcoin.status, OK);
  assert.equal(byId[BTC.row.batch_id].overall, UNCHECKED, 'the token chain and Midnight were not checked');

  writeFileSync(join(d, 'batches', BTC.row.batch_id, 'root.tst'), Buffer.from('3000', 'hex'));
  r = await check(d, opts);
  assert.equal(r.results.find((x) => x.batchId === BTC.row.batch_id).overall, MISMATCH);
  assert.match(r.results.find((x) => x.batchId === BTC.row.batch_id).parts.files.detail, /root\.tst does not match/);

  const idx = JSON.parse(readFileSync(join(d, 'index.json')));
  idx.batches[1].conflicts = ['conflicts/x/2026-11-18-abc'];
  writeFileSync(join(d, 'index.json'), JSON.stringify(idx));
  r = await check(d, opts);
  assert.match(r.results[1].parts.files.detail, /once served a different version/);
});

// ---- review fixes (18 Nov 2026) ----

test('a run that dies half way leaves the mirror exactly as it was, and check finds nothing wrong', async () => {
  clear(); seed(BTC); seed(PENDING, { tst: null });
  const out = tmp('mirror-');
  await mirror({ api: base, out });
  const snapshot = Object.fromEntries(files(out).map((f) => [f, readFileSync(join(out, f))]));
  set(PENDING.row.batch_id, 'tsa_token', Buffer.from(BTC.tst, 'base64')); // would be "added"...
  const dying = (u, i) => (u.includes(`${BTC.row.batch_id}/root.tst`) ? new Response('x', { status: 502 }) : fetch(u, i));
  await assert.rejects(mirror({ api: base, out, fetchImpl: dying }), (e) => e.message.includes(`${base}/batches/${BTC.row.batch_id}/root.tst answered 502`));
  assert.deepEqual(files(out), Object.keys(snapshot));
  for (const [f, b] of Object.entries(snapshot)) assert.ok(readFileSync(join(out, f)).equals(b), f);
  assert.deepEqual(readdirSync(join(out, '..')).filter((d) => d.startsWith(`${basename(out)}.`)), [], 'no work folder left');
  const r = await check(out, { explorers: [], sdk: null });
  assert.ok(!r.results.some((x) => x.overall === MISMATCH));
  await assert.rejects(mirror({ api: base, out, fetchImpl: async () => { throw Object.assign(new Error('fetch failed'), { cause: { code: 'ECONNREFUSED' } }); } }), /veilcore-registry: ECONNREFUSED/);
});

test('a new batch that contradicts itself is a mismatch in check (exit 2), never silently skipped', async () => {
  clear(); seed(BTC);
  const out = tmp('mirror-');
  const lying = (u, i) => (u.endsWith(`${BTC.row.batch_id}/root.bin`) ? new Response(Buffer.alloc(32, 0xbb)) : fetch(u, i));
  const s = await mirror({ api: base, out, fetchImpl: lying });
  assert.equal(s.added.length, 0);
  const r = await check(out, { explorers: [], sdk: null });
  const bad = r.results.find((x) => x.batchId === BTC.row.batch_id);
  assert.equal(bad.overall, MISMATCH);
  assert.match(bad.parts.files.detail, /never added/);
  const cli = await new Promise((res) => execFile(process.execPath, [WITNESS, 'check', out, '--offline'], (err, stdout) => res({ code: err?.code ?? 0, stdout })));
  assert.equal(cli.code, 2);
});

test('registry text is checked before it is kept, and nothing printed can start a workflow command', async () => {
  const evil = { ...BTC.row, batch_id: 'B-EVIL', anchor: { ...BTC.row.anchor, network: 'mainnet\n::error title=x::History rewritten\n```' } };
  assert.throws(() => batchRecord(evil), /network is not a short plain name/);
  for (const [k, v, why] of [['txHash', 'zz'.repeat(32), /txHash/], ['contractAddress', 'AB'.repeat(32), /contractAddress/], ['blockHeight', '5', /blockHeight/], ['anchoredAt', 'yesterday', /anchoredAt/]]) {
    assert.throws(() => batchRecord({ ...BTC.row, anchor: { ...BTC.row.anchor, [k]: v } }), why);
  }
  // A malformed batch from the registry is filed as a conflict, and the run says so (exit 2).
  clear(); seed(BTC);
  db.prepare('UPDATE batches SET anchor = ? WHERE batch_id = ?').run(JSON.stringify({ ...stored(BTC.row.anchor), network: 'mainnet\n::error::x' }), BTC.row.batch_id);
  const out = tmp('mirror-');
  const cli = await new Promise((res) => execFile(process.execPath, [WITNESS, 'mirror', out, '--registry', base], (err, stdout, stderr) => res({ code: err?.code ?? 0, all: stdout + stderr })));
  assert.equal(cli.code, 2);
  assert.match(cli.all, /does not check: .*network is not a short plain name/);
  assert.ok(!cli.all.split('\n').some((l) => l.startsWith('::')), 'no line starts a workflow command');
  assert.equal(printable('a\n::error::b\u001b[2J c'), 'a?::error::b?[2J?c');
});

test('anchors compare field by field: an added field is ignored, the same instant written two ways is equal, a change is named', () => {
  const rec = batchRecord(BTC.row);
  assert.deepEqual(compareRecords(rec, { ...BTC.row, anchor: { ...BTC.row.anchor, somethingNew: 1, anchoredAt: BTC.row.anchor.anchoredAt.replace('.000Z', 'Z') } }), { conflicts: [], updates: [] });
  assert.deepEqual(compareRecords(rec, { ...BTC.row, anchor: { ...BTC.row.anchor, blockHeight: 1 } }).conflicts, [`the anchor changed: blockHeight ${BTC.row.anchor.blockHeight} -> 1`]);
  assert.equal(batchRecord({ ...BTC.row, sealed_at: new Date(BTC.row.sealed_at).toISOString() }).sealedAt, rec.sealedAt);
});

test('past RECHECK_ALL batches, each run fetches final files again for one slice in turn', async () => {
  const n = RECHECK_ALL + 1;
  const rows = Array.from({ length: n }, (_, i) => ({ batch_id: `B-${String(i).padStart(4, '0')}`, root: createHash('sha256').update(String(i)).digest('hex'), sealed_at: Date.UTC(2026, 0, 1) + i, record_count: 1, anchor: null, opentimestamps: { status: 'none' } }));
  const byId = new Map(rows.map((r) => [r.batch_id, r]));
  let asked = [];
  const reg = async (u) => {
    const p = new URL(u).pathname;
    if (p === '/.well-known/veilcore-registry') return new Response('{}');
    if (p === '/batches') return new Response(JSON.stringify({ batches: rows }));
    asked.push(p);
    const m = /^\/batches\/([^/]+)\/root\.bin$/.exec(p);
    return m ? new Response(Buffer.from(byId.get(m[1]).root, 'hex')) : new Response('', { status: 404 });
  };
  const out = tmp('mirror-');
  await mirror({ api: 'https://registry.test', out, fetchImpl: reg });
  const seen = new Set();
  for (let slot = 0; slot < RECHECK_SLICES; slot++) {
    asked = [];
    await mirror({ api: 'https://registry.test', out, fetchImpl: reg, now: new Date(slot * 6 * 3_600_000) });
    const bins = asked.filter((p) => p.endsWith('root.bin'));
    assert.ok(bins.length >= Math.floor(n / RECHECK_SLICES) && bins.length <= Math.ceil(n / RECHECK_SLICES), String(bins.length));
    for (const b of bins) seen.add(b);
  }
  assert.equal(seen.size, n, 'every batch rechecked within one round of slices');
});

test('Bitcoin: every explorer is asked; one down never hides another\'s mismatch; a block before sealing is a mismatch', async () => {
  const d = await fresh();
  const dir = join(d, 'batches', BTC.row.batch_id);
  const rec = JSON.parse(readFileSync(join(dir, 'batch.json')));
  const good = explorer(976480, btcMerkle());
  const liar = explorer(976480, Buffer.alloc(32, 7));
  const down = explorer(1, btcMerkle(), { down: true });
  const two = (a, b) => async (u) => (u.startsWith('https://a.test') ? a(u) : b(u));
  const E2 = ['https://a.test/api', 'https://b.test/api'];
  const v = await checkOts({ dir, rec, explorers: E2, fetchImpl: two(down, liar) });
  assert.equal(v.status, MISMATCH, v.detail);
  assert.match(v.detail, /from b\.test/);
  assert.equal((await checkOts({ dir, rec, explorers: E2, fetchImpl: two(down, good) })).status, UNCHECKED);
  assert.equal((await checkOts({ dir, rec, explorers: E2, fetchImpl: two(good, good) })).status, OK);
  const late = await checkOts({ dir, rec: { ...rec, sealedAt: '2026-11-19T00:00:00.000Z' }, explorers: E2, fetchImpl: two(good, good) });
  assert.equal(late.status, MISMATCH);
  assert.match(late.detail, /before the batch was sealed/);
});

test('Midnight: one indexer without the transaction is couldn\'t check; two without it is a mismatch; OK says how the root was found', async () => {
  const none = async () => new Response(JSON.stringify({ data: { byHash: [], byId: [] } }));
  assert.equal((await mid(anchored(), none)).status, UNCHECKED);
  assert.match((await mid(anchored(), none)).detail, /may be behind, or on another network/);
  assert.equal((await mid(anchored(), none, ['https://a.test', 'https://b.test'])).status, MISMATCH);
  const mixed = async (u, i) => (u.includes('a.test') ? none() : indexer()(u, i));
  assert.equal((await mid(anchored(), mixed, ['https://a.test', 'https://b.test'])).status, UNCHECKED);
  assert.match((await mid(anchored(), indexer())).detail, /root bytes found in contract state \(cell not decoded\)/);
  const exact = await checkMidnight({ rec: anchored(), indexers: ['https://i.test'], fetchImpl: indexer(), rootOf: () => A.root });
  assert.match(exact.detail, /the contract cell holds this root/);
  const early = await mid({ ...anchored(), sealedAt: '2026-11-19T00:00:00.000Z' }, indexer());
  assert.equal(early.status, MISMATCH);
  assert.match(early.detail, /before the batch was sealed/);
});

test('RFC 3161: a token that carries no certificate is couldn\'t check without --tsa-ca, not a mismatch', async () => {
  const w = tmp('nocert-');
  const ssl = (...a) => execFileSync('openssl', a, { cwd: w, stdio: ['ignore', 'pipe', 'pipe'] });
  writeFileSync(join(w, 'ext.cnf'), 'extendedKeyUsage = critical,timeStamping\nbasicConstraints = CA:FALSE\n');
  ssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key', '-out', 'ca.pem', '-days', '2', '-subj', '/CN=Root');
  ssl('req', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'tsa.key', '-out', 'tsa.csr', '-subj', '/CN=TSA');
  ssl('x509', '-req', '-in', 'tsa.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial', '-out', 'tsa.pem', '-days', '2', '-extfile', 'ext.cnf');
  writeFileSync(join(w, 'tsa.cnf'), `[ tsa ]\ndefault_tsa = t\n[ t ]\nserial = ${w}/serial\nsigner_cert = ${w}/tsa.pem\nsigner_key = ${w}/tsa.key\nsigner_digest = sha256\ndefault_policy = 1.2.3.4.1\ndigests = sha256\ness_cert_id_alg = sha256\nordering = no\ntsa_name = no\ness_cert_id_chain = no\n`);
  writeFileSync(join(w, 'serial'), '01\n');
  writeFileSync(join(w, 'root.bin'), Buffer.from(root, 'hex'));
  ssl('ts', '-query', '-data', 'root.bin', '-sha256', '-no_nonce', '-out', 'q.tsq'); // no -cert: the token carries none
  ssl('ts', '-reply', '-config', 'tsa.cnf', '-queryfile', 'q.tsq', '-out', 'r.tsr');
  ssl('ts', '-reply', '-in', 'r.tsr', '-token_out', '-out', 'root.tst');
  const rec = { root, sealedAt: '2026-01-01T00:00:00.000Z' };
  for (const sdk of [SDK, null]) {
    const v = await checkTsa({ dir: w, rec, sdk });
    assert.equal(v.status, UNCHECKED, v.detail);
    assert.match(v.detail, /carries no certificate/);
  }
});
