// A record is corrected once (corrections.js, 8 Nov 2026).
//
// The site refuses to correct a record that already has a correction, but two devices saving
// at nearly the same moment both passed that check and the registry stored both. These pin
// the registry's side: a unique index on the holder and the corrected record; a second
// correction refused by id with code "already-corrected" and status 409; the same correction
// again (by id, or by fingerprint under another id) taken as a retry; two saves racing, in
// one process and in two on one file, leaving exactly one; and a database that already
// holds two corrections of one record starting up with nothing deleted and each case said.
//
// SPDX-License-Identifier: Apache-2.0

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { randomBytes } from 'node:crypto';
import { fork } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import Database from 'better-sqlite3';
import { untilReady, testBody, kidOf, vaultKeyFor, sealForTest } from './helpers.mjs';

process.env.DB_PATH = ':memory:';
process.env.VEILCORE_OTS = 'off';
const require = createRequire(import.meta.url);
const { app, db } = require('../server.js');
const { ensureOneCorrection, isSecondCorrection, INDEX_NAME } = require('../corrections.js');
const { storedHolderKey, legacyStoredHolderKey, migrateHolderKeys } = require('../holder-key.js');

const key = () => randomBytes(32).toString('hex');
const hex = () => randomBytes(32).toString('hex');
const rid = (p = 'oc') => `${p}-${randomBytes(6).toString('hex')}`;

let base, server;
before(async () => {
  server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  base = `http://127.0.0.1:${server.address().port}`;
  await untilReady(base);
});
after(() => server.close());

/** A row's `rev` goes in the clear beside its box too, as the site sends it (record-rev-v1). */
const withRev = (path, sent, out) => (path === '/api/records' && Array.isArray(sent)
  ? out.map((row, i) => (Number.isSafeInteger(sent[i]?.rev) && !sent[i].sealed ? { ...row, rev: sent[i].rev } : row))
  : out);
const callAt = (at) => async (method, path, holder, body) => {
  const res = await fetch(`${at()}${path}`, {
    method,
    headers: { 'content-type': 'application/json', ...(holder ? { 'x-holder-key': holder } : {}) },
    ...(body === undefined ? {} : { body: JSON.stringify(withRev(path, body, testBody(method, path, holder, body))) }),
  });
  const text = await res.text();
  let json; try { json = JSON.parse(text); } catch { json = text; }
  return { status: res.status, json };
};
const call = callAt(() => base);

const original = (extra = {}) => ({ id: rid('orig'), recordFingerprint: hex(), notes: 'first', ...extra });
const correctionOf = (r, extra = {}) => ({
  id: rid('corr'),
  recordFingerprint: hex(),
  notes: 'fixed',
  supersedes: { recordId: r.id, changedFields: ['notes'], effectiveAt: '2026-11-08T09:30:00Z', reason: 'typo' },
  ...extra,
});
const mine = async (holder) => (await call('GET', '/api/records?limit=100', holder)).json;
const rowsOf = (list) => (Array.isArray(list) ? list : list.records ?? list.items ?? []);
const correctionsOf = async (holder, recordId) =>
  rowsOf(await mine(holder)).filter((r) => r.supersedes?.recordId === recordId).map((r) => r.id);

test('the index is in place, and /health names one-correction-v1', async () => {
  const idx = db.prepare("SELECT sql FROM sqlite_master WHERE type = 'index' AND name = ?").get(INDEX_NAME);
  assert.ok(idx, 'the one-correction index exists');
  assert.match(idx.sql, /UNIQUE INDEX/);
  const health = await call('GET', '/health');
  assert.ok(health.json.features.includes('one-correction-v1'));
});

test('a second correction of a record is refused by id: 409, already-corrected, and nothing of it is kept', async () => {
  const h = key();
  const r = original();
  const c1 = correctionOf(r);
  const first = await call('PUT', '/api/records', h, [c1, { ...r, supersededBy: c1.id }]);
  assert.equal(first.status, 200);
  assert.equal(first.json.ok, true, JSON.stringify(first.json));

  // Another device: its own correction of the same record, and the record marked with it.
  const c2 = correctionOf(r, { notes: 'fixed differently' });
  const second = await call('PUT', '/api/records', h, [c2, { ...r, supersededBy: c2.id }]);
  assert.equal(second.status, 200);
  assert.equal(second.json.ok, false);
  const refusedC2 = second.json.rejected.find((x) => x.id === c2.id);
  assert.deepEqual(
    { code: refusedC2.code, status: refusedC2.status, recordId: refusedC2.recordId, correctionId: refusedC2.correctionId },
    { code: 'already-corrected', status: 409, recordId: r.id, correctionId: c1.id },
  );
  assert.match(refusedC2.reason, /already corrected/);
  // The record is not left pointing at a correction this registry does not hold: its link to
  // c1 is permanent, so the save that would change it is refused.
  const refusedR = second.json.rejected.find((x) => x.id === r.id);
  assert.equal(refusedR?.code, 'supersededby-locked');
  assert.equal(refusedR.supersededBy, c1.id);

  assert.deepEqual(await correctionsOf(h, r.id), [c1.id]);
  const stored = rowsOf(await mine(h)).find((x) => x.id === r.id);
  assert.equal(stored.supersededBy, c1.id);
});

test('the same correction again is a retry: by id (the whole set re-sent) and by fingerprint under another id', async () => {
  const h = key();
  const r = original();
  const c1 = correctionOf(r);
  assert.equal((await call('PUT', '/api/records', h, [c1, { ...r, supersededBy: c1.id }])).json.ok, true);
  // The browser re-sends the whole set on every save.
  const again = await call('PUT', '/api/records', h, [c1, { ...r, supersededBy: c1.id }]);
  assert.equal(again.json.ok, true, JSON.stringify(again.json));
  assert.equal(again.json.rejected, undefined);

  // The same content (fingerprint) under another id: answered with the one held, not stored.
  const copy = { ...c1, id: rid('corr') };
  const dup = await call('PUT', '/api/records', h, [copy]);
  assert.equal(dup.status, 200);
  assert.equal(dup.json.rejected, undefined, JSON.stringify(dup.json));
  assert.deepEqual(dup.json.existing, [{ id: copy.id, existingId: c1.id, recordId: r.id }]);
  // Counted as saved: the one held is this correction, so the site's bookkeeping is right.
  assert.equal(dup.json.ok, true);
  assert.equal(dup.json.count, 1);
  assert.deepEqual(await correctionsOf(h, r.id), [c1.id]);
});

test('a correction can correct a correction (a chain), and a removed correction frees the record', async () => {
  const h = key();
  const r = original();
  const c1 = correctionOf(r);
  assert.equal((await call('PUT', '/api/records', h, [c1, { ...r, supersededBy: c1.id }])).json.ok, true);
  const c2 = correctionOf(c1);
  const chain = await call('PUT', '/api/records', h, [c2, { ...c1, supersededBy: c2.id }]);
  assert.equal(chain.json.ok, true, JSON.stringify(chain.json));

  // The holder removes c2 (made by mistake, never seen): c1 may be corrected again.
  const del = await call('DELETE', '/api/records', h, { ids: [c2.id] });
  assert.deepEqual(del.json.removed, [c2.id]);
  const c3 = correctionOf(c1);
  const after = await call('PUT', '/api/records', h, [c3, { ...c1, supersededBy: c3.id }]);
  assert.equal(after.json.ok, true, JSON.stringify(after.json));
});

test('per holder: a correction someone else stored first, naming an id, does not stop its holder correcting it', async () => {
  const intruder = key();
  const h = key();
  const r = original();
  // Before r exists, another holder stores a "correction" naming its id (ids were guessable).
  const squat = correctionOf(r);
  assert.equal((await call('PUT', '/api/records', intruder, [squat])).json.ok, true);
  assert.equal((await call('PUT', '/api/records', h, [r])).json.ok, true);
  const c1 = correctionOf(r);
  const res = await call('PUT', '/api/records', h, [c1, { ...r, supersededBy: c1.id }]);
  assert.equal(res.json.ok, true, JSON.stringify(res.json));
});

test('a correction in a chain is never left pointing at a correction this registry refused', async () => {
  const h = key();
  const r = original();
  const c1 = correctionOf(r);
  const c2 = correctionOf(c1);
  assert.equal((await call('PUT', '/api/records', h, [c1, { ...r, supersededBy: c1.id }])).json.ok, true);
  assert.equal((await call('PUT', '/api/records', h, [c2, { ...c1, supersededBy: c2.id }])).json.ok, true);
  // Another device corrects c1 (the middle of the chain) again, and marks c1 with it.
  const c2b = correctionOf(c1, { notes: 'other device' });
  const res = await call('PUT', '/api/records', h, [{ ...c1, supersededBy: c2b.id }, c2b]);
  assert.equal(res.json.ok, false);
  const by = Object.fromEntries(res.json.rejected.map((x) => [x.id, x]));
  assert.equal(by[c2b.id]?.code, 'already-corrected');
  assert.equal(by[c1.id]?.code, 'supersededby-locked', 'c1 is refused too, though it is itself a correction');
  assert.equal(by[c1.id].supersededBy, c2.id);
  const held = rowsOf(await mine(h));
  assert.equal(held.find((x) => x.id === c1.id).supersededBy, c2.id);
  assert.equal(held.some((x) => x.id === c2b.id), false);
  const pub = await call('GET', `/verify/${c1.id}`);
  assert.notEqual(pub.json?.supersededBy, c2b.id);

  // The same where c1 holds no link yet (its correction was saved alone): the lock has nothing
  // to keep, and c1 is refused because the correction it would name was not stored.
  const d = original();
  const d1 = correctionOf(d);
  const d2 = correctionOf(d1);
  assert.equal((await call('PUT', '/api/records', h, [d, d1])).json.ok, true);
  assert.equal((await call('PUT', '/api/records', h, [d2])).json.ok, true);
  const d2b = correctionOf(d1, { notes: 'other device' });
  const res2 = await call('PUT', '/api/records', h, [{ ...d1, supersededBy: d2b.id }, d2b]);
  const by2 = Object.fromEntries(res2.json.rejected.map((x) => [x.id, x]));
  assert.equal(by2[d2b.id]?.code, 'already-corrected');
  assert.equal(by2[d1.id]?.code, 'already-corrected');
  assert.equal(by2[d1.id].correctionId, d2.id);
  assert.equal(rowsOf(await mine(h)).find((x) => x.id === d1.id).supersededBy, undefined);

  // A whole chain sent in one save, in any order, is taken: each link written after the one it names.
  const s = original();
  const s1 = correctionOf(s);
  const s2 = correctionOf(s1);
  const s3 = correctionOf(s2);
  const chain = await call('PUT', '/api/records', h, [
    { ...s1, supersededBy: s2.id }, { ...s, supersededBy: s1.id }, s3, { ...s2, supersededBy: s3.id },
  ]);
  assert.equal(chain.json.ok, true, JSON.stringify(chain.json));
  assert.equal(chain.json.count, 4);
});

test('an extra correction names the correction its record holds now, after the kept one was removed and another made', () => {
  const mem = new Database(':memory:');
  mem.exec(`CREATE TABLE records (id TEXT PRIMARY KEY, holder_key TEXT NOT NULL, body TEXT NOT NULL,
    updated_at INTEGER NOT NULL, first_seen INTEGER)`);
  const put = mem.prepare('INSERT INTO records (id, holder_key, body, updated_at, first_seen) VALUES (?, ?, ?, ?, ?)');
  for (const [id, t] of [['c2', 2], ['c3', 3]]) put.run(id, 'h1:z', JSON.stringify({ id, supersedes: { recordId: 'a' } }), t, t);
  ensureOneCorrection(mem, { log: () => {} });
  // c2 kept, c3 marked. c2 is removed, and a new correction c8 is made before the next start.
  mem.prepare("DELETE FROM records WHERE id = 'c2'").run();
  put.run('c8', 'h1:z', JSON.stringify({ id: 'c8', supersedes: { recordId: 'a' } }), 8, 8);
  const lines = [];
  const out = ensureOneCorrection(mem, { log: (l) => lines.push(l) });
  assert.deepEqual(out.stillMarked, [{ id: 'c3', recordId: 'a', kept: 'c8' }]);
  assert.ok(lines.some((l) => l.includes('c3 (corrects a; kept: c8)')), lines.join('\n'));
  assert.ok(!lines.join('\n').includes('c2'), 'never names the removed one');
  mem.close();
});

test('two saves racing in one process: exactly one correction is stored, the other is refused', async () => {
  const h = key();
  for (let round = 0; round < 10; round++) {
    const r = original({ rev: 1 });
    assert.equal((await call('PUT', '/api/records', h, [r])).json.ok, true);
    const a = correctionOf(r, { rev: 1 });
    const b = correctionOf(r, { rev: 1, notes: 'other device' });
    const [ra, rb] = await Promise.all([
      call('PUT', '/api/records', h, [a, { ...r, rev: 2, supersededBy: a.id }]),
      call('PUT', '/api/records', h, [b, { ...r, rev: 2, supersededBy: b.id }]),
    ]);
    const answers = [[a, ra], [b, rb]];
    const won = answers.filter(([c, res]) => res.status === 200 && res.json.ok === true && !res.json.rejected);
    const lost = answers.filter(([c, res]) => res.json.rejected?.some((x) => x.id === c.id && x.code === 'already-corrected' && x.status === 409));
    assert.equal(won.length, 1, JSON.stringify([ra.json, rb.json]));
    assert.equal(lost.length, 1, JSON.stringify([ra.json, rb.json]));
    assert.deepEqual(await correctionsOf(h, r.id), [won[0][0].id]);
    const stored = rowsOf(await mine(h)).find((x) => x.id === r.id);
    assert.equal(stored.supersededBy, won[0][0].id);
  }
});

const child = fileURLToPath(new URL('./fixtures/sealed-server-child.mjs', import.meta.url));
const startOn = async (file) => {
  const proc = fork(child, [], { env: { ...process.env, DB_PATH: file }, stdio: ['ignore', 'pipe', 'pipe', 'ipc'] });
  let output = '';
  proc.stdout.on('data', (d) => { output += d; });
  proc.stderr.on('data', (d) => { output += d; });
  const { port } = await new Promise((ok, fail) => {
    proc.once('message', ok);
    proc.once('exit', (code) => fail(new Error(`registry exited (${code}) before listening: ${output}`)));
  });
  const at = `http://127.0.0.1:${port}`;
  await untilReady(at);
  return {
    call: callAt(() => at),
    output: () => output,
    stop: () => new Promise((ok) => {
      proc.once('exit', () => ok(output));
      proc.send('close');
    }),
  };
};

test('two connections that each looked first and found nothing: SQLite refuses the second insert', () => {
  const dir = mkdtempSync(join(tmpdir(), 'oc-conn-'));
  try {
    const file = join(dir, 'r.db');
    const setup = new Database(file);
    setup.exec(`CREATE TABLE records (id TEXT PRIMARY KEY, holder_key TEXT NOT NULL, body TEXT NOT NULL,
      updated_at INTEGER NOT NULL, first_seen INTEGER)`);
    ensureOneCorrection(setup, { log: () => {} });
    setup.close();
    const one = new Database(file);
    const two = new Database(file);
    const body = (id) => JSON.stringify({ id, supersedes: { recordId: 'orig-1' } });
    const look = 'SELECT 1 FROM records WHERE holder_key = ? AND json_extract(body, \'$.supersedes.recordId\') = ?';
    // A check before the write passes on both: neither has written yet.
    assert.equal(one.prepare(look).get('h1:x', 'orig-1'), undefined);
    assert.equal(two.prepare(look).get('h1:x', 'orig-1'), undefined);
    const insert = 'INSERT INTO records (id, holder_key, body, updated_at, first_seen) VALUES (?, ?, ?, 1, 1)';
    one.prepare(insert).run('c-a', 'h1:x', body('c-a'));
    assert.throws(() => two.prepare(insert).run('c-b', 'h1:x', body('c-b')), (e) => isSecondCorrection(e));
    // Another holder's correction of an id of the same spelling is theirs to make.
    two.prepare(insert).run('c-c', 'h1:y', body('c-c'));
    one.close();
    two.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('two registries on one file, racing: exactly one correction is stored, never two', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'oc-race-'));
  const file = join(dir, 'race.db');
  const a = await startOn(file);
  const b = await startOn(file);
  try {
    const h = key();
    for (let round = 0; round < 8; round++) {
      const r = original({ rev: 1 });
      assert.equal((await a.call('PUT', '/api/records', h, [r])).json.ok, true);
      const ca = correctionOf(r, { rev: 1 });
      const cb = correctionOf(r, { rev: 1, notes: 'other device' });
      const [ra, rb] = await Promise.all([
        a.call('PUT', '/api/records', h, [ca, { ...r, rev: 2, supersededBy: ca.id }]),
        b.call('PUT', '/api/records', h, [cb, { ...r, rev: 2, supersededBy: cb.id }]),
      ]);
      const ok = [ra, rb].filter((x) => x.status === 200 && x.json.ok === true);
      assert.equal(ok.length, 1, JSON.stringify([ra, rb]));
      // The other was refused by the index (409 entry), or found the file busy and changed
      // nothing; either way it did not store a second correction.
      const other = ok[0] === ra ? [cb, rb] : [ca, ra];
      const refused = other[1].json.rejected?.some((x) => x.id === other[0].id && x.code === 'already-corrected');
      assert.ok(refused || other[1].status >= 500, JSON.stringify(other[1]));
      const held = (await a.call('GET', '/api/records?limit=100', h)).json;
      assert.equal(rowsOf(held).filter((x) => x.supersedes?.recordId === r.id).length, 1);
    }
  } finally {
    await a.stop();
    await b.stop();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a database already holding two corrections of one record: nothing deleted, each case said, then held to one', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'oc-migrate-'));
  const file = join(dir, 'old.db');
  try {
    const h = key();
    const stored = storedHolderKey(h);
    // A registry from before the rule, as its tables were.
    const old = new Database(file);
    old.exec(`CREATE TABLE records (id TEXT PRIMARY KEY, holder_key TEXT NOT NULL, body TEXT NOT NULL,
      updated_at INTEGER NOT NULL, first_seen INTEGER)`);
    const put = old.prepare('INSERT INTO records (id, holder_key, body, updated_at, first_seen) VALUES (?, ?, ?, ?, ?)');
    const sealedLike = { v: 1, alg: 'A256GCM', kid: kidOf(vaultKeyFor(h)), iv: 'AAAAAAAAAAAAAAAA', ct: 'AAAA' };
    // Two corrections of orig-a; the original names the LATER one, so that one is kept.
    put.run('orig-a', stored, JSON.stringify({ id: 'orig-a', supersededBy: 'corr-a2', sealed: sealedLike }), 1, 1);
    put.run('corr-a1', stored, JSON.stringify({ id: 'corr-a1', supersedes: { recordId: 'orig-a' }, sealed: sealedLike }), 2, 2);
    put.run('corr-a2', stored, JSON.stringify({ id: 'corr-a2', supersedes: { recordId: 'orig-a' }, sealed: sealedLike }), 3, 3);
    // Three of orig-b, and the original names none of them: the first seen is kept.
    put.run('orig-b', stored, JSON.stringify({ id: 'orig-b', sealed: sealedLike }), 1, 1);
    for (const [id, t] of [['corr-b1', 5], ['corr-b2', 4], ['corr-b3', 6]]) {
      put.run(id, stored, JSON.stringify({ id, supersedes: { recordId: 'orig-b' }, sealed: sealedLike }), t, t);
    }
    old.close();

    const lines = [];
    const db2 = new Database(file);
    const out = ensureOneCorrection(db2, { log: (l) => lines.push(l) });
    assert.deepEqual(out.marked, [
      { recordId: 'orig-a', kept: 'corr-a2', others: ['corr-a1'] },
      { recordId: 'orig-b', kept: 'corr-b2', others: ['corr-b1', 'corr-b3'] },
    ]);
    assert.equal(db2.prepare('SELECT COUNT(*) AS n FROM records').get().n, 7, 'nothing deleted');
    assert.ok(lines.some((l) => l.includes('record orig-a had 2 corrections; kept corr-a2')));
    assert.ok(lines.some((l) => l.includes('3 extra corrections from before the rule')));
    assert.ok(!lines.join('\n').includes(stored), 'the log names record ids, never a holder');
    // Run again: nothing new is marked, the same rows are still said.
    const again = ensureOneCorrection(db2, { log: () => {} });
    assert.deepEqual(again.marked, []);
    assert.equal(again.stillMarked.length, 3);
    db2.close();

    // The registry on that file starts, and holds the record to one correction from now on.
    const reg = await startOn(file);
    try {
      assert.match(reg.output(), /3 extra corrections from before the rule/);
      const third = await reg.call('PUT', '/api/records', h, [{
        id: 'corr-a9', recordFingerprint: hex(), notes: 'x',
        supersedes: { recordId: 'orig-a', changedFields: ['notes'], effectiveAt: '2026-11-08T09:30:00Z' },
      }]);
      assert.equal(third.json.rejected?.[0]?.code, 'already-corrected', JSON.stringify(third.json));
      assert.equal(third.json.rejected[0].correctionId, 'corr-a2');
      // The holder removes the extra one; the one kept is unaffected.
      const del = await reg.call('DELETE', '/api/records', h, { ids: ['corr-a1', 'corr-b1', 'corr-b3'] });
      assert.deepEqual(del.json.removed.sort(), ['corr-a1', 'corr-b1', 'corr-b3']);
    } finally {
      await reg.stop();
    }
    const db3 = new Database(file);
    const clean = ensureOneCorrection(db3, { log: () => {} });
    assert.deepEqual(clean.stillMarked, []);
    db3.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('an extra correction whose kept one is removed takes its place, so the record is still held to one', () => {
  const mem = new Database(':memory:');
  mem.exec(`CREATE TABLE records (id TEXT PRIMARY KEY, holder_key TEXT NOT NULL, body TEXT NOT NULL,
    updated_at INTEGER NOT NULL, first_seen INTEGER)`);
  const put = mem.prepare('INSERT INTO records (id, holder_key, body, updated_at, first_seen) VALUES (?, ?, ?, ?, ?)');
  for (const [id, t] of [['k1', 1], ['k2', 2], ['k3', 3]]) put.run(id, 'h1:z', JSON.stringify({ id, supersedes: { recordId: 'o' } }), t, t);
  ensureOneCorrection(mem, { log: () => {} });
  mem.prepare("DELETE FROM records WHERE id = 'k1'").run();
  const out = ensureOneCorrection(mem, { log: () => {} });
  assert.deepEqual(out.stillMarked.map((s) => s.id), ['k3']);
  assert.equal(out.stillMarked[0].kept, 'k2', 'the extra names the one now kept, not the removed one');
  assert.equal(mem.prepare("SELECT correction_conflict AS c FROM records WHERE id = 'k2'").get().c, null);
  assert.throws(
    () => put.run('k4', 'h1:z', JSON.stringify({ id: 'k4', supersedes: { recordId: 'o' } }), 4, 4),
    (e) => isSecondCorrection(e),
  );
  mem.close();
});

// ---- a holder key in two spellings (holder-key.js) ---------------------------------------
//
// Rows written under an older spelling of a holder key (plain text before 8 Oct, or the digest
// of an upper-case key before round 3) are moved to today's digest when the key arrives, or at
// start. If each spelling held a correction of the same record, the move would put two under
// one holder and the index would refuse it: a 500 on every request from that holder, or a
// failed start. Settled as the start-up check does instead; nothing deleted.

/** Every hex letter in capitals. */
const upper = (k) => k.toUpperCase();

test('two spellings of one key, each with a correction of one record: the request converts them, keeps the one named, marks the other', async () => {
  const h = key();
  const H = upper(h);
  const vault = vaultKeyFor(h);
  // Today: the record and its correction, saved as the site saves them.
  const r = original();
  const named = correctionOf(r);
  assert.equal((await call('PUT', '/api/records', h, [named, { ...r, supersededBy: named.id }])).json.ok, true);
  // Before round 3: a correction of the same record under the digest of the key as sent in
  // capitals, seen earlier than the one named.
  const older = correctionOf(r);
  const raw = db.prepare('INSERT INTO records (id, holder_key, body, updated_at, first_seen) VALUES (?, ?, ?, ?, ?)');
  raw.run(older.id, legacyStoredHolderKey(H), JSON.stringify(sealForTest(older, vault)), 1, 1);

  // The holder's next request, with the key in capitals, converts the old rows first.
  const real = console.log;
  const lines = [];
  console.log = (...a) => { lines.push(a.join(' ')); };
  let res;
  try { res = await call('GET', '/api/records?limit=100', H); } finally { console.log = real; }
  assert.equal(res.status, 200, JSON.stringify(res.json));
  const ids = rowsOf(res.json).map((x) => x.id);
  assert.ok(ids.includes(older.id) && ids.includes(named.id), 'nothing deleted, both under one holder now');
  const flag = db.prepare('SELECT holder_key, correction_conflict AS c FROM records WHERE id = ?');
  assert.deepEqual(flag.get(older.id), { holder_key: storedHolderKey(h), c: named.id });
  assert.equal(flag.get(named.id).c, null);
  assert.ok(lines.some((l) => l.includes(`record ${r.id} had a correction under each of two spellings`) && l.includes(`kept ${named.id}`)), lines.join('\n'));
  assert.ok(!lines.join('\n').includes(h) && !lines.join('\n').includes(storedHolderKey(h)), 'record ids only in the log');

  // Held to one from now on.
  const third = await call('PUT', '/api/records', h, [correctionOf(r)]);
  assert.equal(third.json.rejected?.[0]?.code, 'already-corrected');
  assert.equal(third.json.rejected[0].correctionId, named.id);
});

test('two plain-text spellings, each with a correction of one record: the start-up conversion keeps the first seen, marks the other', () => {
  const mem = new Database(':memory:');
  mem.exec(`CREATE TABLE records (id TEXT PRIMARY KEY, holder_key TEXT NOT NULL, body TEXT NOT NULL,
    updated_at INTEGER NOT NULL, first_seen INTEGER)`);
  ensureOneCorrection(mem, { log: () => {} });
  const h = key();
  const put = mem.prepare('INSERT INTO records (id, holder_key, body, updated_at, first_seen) VALUES (?, ?, ?, ?, ?)');
  // From before 8 Oct: keys in plain text, one row in capitals, one as the app sends it, and a
  // third already converted. The record names none of them.
  put.run('orig-p', h, JSON.stringify({ id: 'orig-p' }), 1, 1);
  put.run('corr-late', h, JSON.stringify({ id: 'corr-late', supersedes: { recordId: 'orig-p' } }), 9, 9);
  put.run('corr-first', upper(h), JSON.stringify({ id: 'corr-first', supersedes: { recordId: 'orig-p' } }), 2, 2);
  put.run('corr-mid', storedHolderKey(h), JSON.stringify({ id: 'corr-mid', supersedes: { recordId: 'orig-p' } }), 5, 5);
  const lines = [];
  const converted = migrateHolderKeys(mem, { log: (l) => lines.push(l), vacuum: false });
  assert.equal(converted['records.holder_key'], 3);
  const rows = mem.prepare('SELECT id, holder_key, correction_conflict AS c FROM records ORDER BY id').all();
  assert.equal(rows.length, 4, 'nothing deleted');
  assert.ok(rows.every((x) => x.holder_key === storedHolderKey(h)), 'every row converted to the one digest');
  const by = Object.fromEntries(rows.map((x) => [x.id, x.c]));
  assert.deepEqual(by, { 'corr-first': null, 'corr-late': 'corr-first', 'corr-mid': 'corr-first', 'orig-p': null });
  assert.ok(lines.some((l) => l.includes('record orig-p had a correction under each of two spellings')), lines.join('\n'));
  // The start-up check names both, and the record is held to one.
  const check = ensureOneCorrection(mem, { log: () => {} });
  assert.deepEqual(check.stillMarked.map((x) => x.id), ['corr-late', 'corr-mid']);
  assert.throws(
    () => put.run('corr-new', storedHolderKey(h), JSON.stringify({ id: 'corr-new', supersedes: { recordId: 'orig-p' } }), 10, 10),
    (e) => isSecondCorrection(e),
  );
  mem.close();
});

// ---- a record's link to its correction is permanent (the site review's B1) ---------------

test('a stored supersededBy is never removed or changed: the lost-answer sequence is refused', async () => {
  const h = key();
  const r = original({ rev: 1 });
  assert.equal((await call('PUT', '/api/records', h, [r])).json.ok, true);
  // The holder corrects r: both halves stored (the answer is lost on the way back).
  const c = correctionOf(r, { rev: 1 });
  assert.equal((await call('PUT', '/api/records', h, [c, { ...r, rev: 2, supersededBy: c.id }])).json.ok, true);
  // The browser put r back as it was, then changed it: r goes out at rev 3 with no link.
  const stale = await call('PUT', '/api/records', h, [{ ...r, rev: 3, notes: 'dna paired' }]);
  assert.equal(stale.status, 200);
  assert.equal(stale.json.ok, false);
  const refusal = stale.json.rejected.find((x) => x.id === r.id);
  assert.deepEqual({ code: refusal.code, status: refusal.status, supersededBy: refusal.supersededBy },
    { code: 'supersededby-locked', status: 409, supersededBy: c.id });
  assert.match(refusal.reason, /remove that link/);
  // Nor changed to another id.
  const other = await call('PUT', '/api/records', h, [{ ...r, rev: 3, supersededBy: rid('corr') }]);
  assert.equal(other.json.rejected?.[0]?.code, 'supersededby-locked');
  assert.match(other.json.rejected[0].reason, /change that to/);
  // The registry still holds r at rev 2, pointing at its correction.
  let held = rowsOf(await mine(h)).find((x) => x.id === r.id);
  assert.equal(held.supersededBy, c.id);
  assert.equal(held.rev, 2);
  // The same link at a higher rev is an ordinary change, and is taken.
  const keep = await call('PUT', '/api/records', h, [{ ...r, rev: 3, supersededBy: c.id, notes: 'dna paired' }]);
  assert.equal(keep.json.ok, true, JSON.stringify(keep.json));
  held = rowsOf(await mine(h)).find((x) => x.id === r.id);
  assert.equal(held.rev, 3);
});

test('the one exception: once the correction the link names is removed, the link may go', async () => {
  const h = key();
  const r = original({ rev: 1 });
  const c = correctionOf(r, { rev: 1 });
  assert.equal((await call('PUT', '/api/records', h, [r])).json.ok, true);
  assert.equal((await call('PUT', '/api/records', h, [c, { ...r, rev: 2, supersededBy: c.id }])).json.ok, true);
  // The site takes a correction back this way: the correction is removed, then r saved without it.
  assert.deepEqual((await call('DELETE', '/api/records', h, { ids: [c.id] })).json.removed, [c.id]);
  const back = await call('PUT', '/api/records', h, [{ ...r, rev: 3 }]);
  assert.equal(back.json.ok, true, JSON.stringify(back.json));
  assert.equal(rowsOf(await mine(h)).find((x) => x.id === r.id).supersededBy, undefined);
  // And r can be corrected again.
  const c2 = correctionOf(r, { rev: 1 });
  assert.equal((await call('PUT', '/api/records', h, [c2, { ...r, rev: 4, supersededBy: c2.id }])).json.ok, true);
});

// ---- a strain's envelope paths (the site review's B2) ------------------------------------

test('a correction of a strain record\'s method is stored, and every strain profileData path is a known name', async () => {
  const sealedJs = require('../sealed.js');
  const strainPaths = ['profileData.group', 'profileData.designation', 'profileData.deposits', 'profileData.method',
    'profileData.generation', 'profileData.parentDeposits'];
  for (const p of strainPaths) assert.ok(sealedJs.CHANGED_FIELD_NAMES.includes(p), p);
  const h = key();
  const strain = 'veilcore/profile/strain/v1';
  const s = original({ profile: strain });
  const fix = correctionOf(s, {
    profile: strain,
    supersedes: { recordId: s.id, changedFields: ['profileData.method'], effectiveAt: '2026-11-08T09:30:00Z', reason: 'method' },
  });
  const res = await call('PUT', '/api/records', h, [s]);
  assert.equal(res.json.ok, true, JSON.stringify(res.json));
  const fixed = await call('PUT', '/api/records', h, [fix, { ...s, supersededBy: fix.id }]);
  assert.equal(fixed.json.ok, true, JSON.stringify(fixed.json));
  assert.deepEqual(rowsOf(await mine(h)).find((x) => x.id === fix.id).supersedes.changedFields, ['profileData.method']);
  // Every other strain path, in one correction of another record.
  const t = original({ profile: strain });
  const all = correctionOf(t, {
    profile: strain,
    supersedes: { recordId: t.id, changedFields: strainPaths, effectiveAt: '2026-11-08T09:30:00Z' },
  });
  const both = await call('PUT', '/api/records', h, [t, all, { ...t, supersededBy: all.id }]);
  assert.equal(both.json.ok, true, JSON.stringify(both.json));
});

// ---- a correction and its record, stored together or not at all (joint review, round 3) ----

test('a correction whose record is refused in the same save is not stored: record-refused', async () => {
  const h = key();
  const r = original({ rev: 1 });
  assert.equal((await call('PUT', '/api/records', h, [r])).json.ok, true);
  // Another tab saves a change to r a moment before device A's correction arrives.
  assert.equal((await call('PUT', '/api/records', h, [{ ...r, rev: 2, notes: 'dna paired' }])).json.ok, true);
  const c = correctionOf(r, { rev: 1 });
  const a = await call('PUT', '/api/records', h, [c, { ...r, rev: 2, supersededBy: c.id }]);
  assert.equal(a.json.ok, false);
  const by = Object.fromEntries(a.json.rejected.map((x) => [x.id, x]));
  assert.equal(by[r.id]?.code, 'older-copy');
  assert.deepEqual({ code: by[c.id]?.code, status: by[c.id]?.status, recordId: by[c.id]?.recordId, recordCode: by[c.id]?.recordCode },
    { code: 'record-refused', status: 409, recordId: r.id, recordCode: 'older-copy' });
  assert.equal(a.json.count, 0);
  // Nothing of the correction is held, and r is free to be corrected once A has read it again.
  assert.deepEqual(await correctionsOf(h, r.id), []);
  const c2 = correctionOf(r);
  // Sealed once, so it can be sent again as the very same box (the browser re-sends its set).
  const c2Box = { ...sealForTest(c2, vaultKeyFor(h)), rev: 1 };
  const again = await call('PUT', '/api/records', h, [c2Box, { ...r, rev: 3, notes: 'dna paired', supersededBy: c2.id }]);
  assert.equal(again.json.ok, true, JSON.stringify(again.json));
  // A stored correction re-sent beside a stale copy of its record is not refused for it.
  const stale = await call('PUT', '/api/records', h, [c2Box, { ...r, rev: 2, supersededBy: c2.id }]);
  assert.equal(stale.json.rejected.find((x) => x.id === r.id)?.code, 'older-copy');
  assert.equal(stale.json.rejected.some((x) => x.id === c2.id), false, JSON.stringify(stale.json));
  // Refused only on writing (the index): the writes are made again with that row decided first,
  // so a correction of it in the same save is refused too, and nothing of either is kept.
  const q = original();
  const q0 = correctionOf(q);
  assert.equal((await call('PUT', '/api/records', h, [q0, { ...q, supersededBy: q0.id }])).json.ok, true);
  const q1 = correctionOf(q, { notes: 'other device' });
  const q2 = correctionOf(q1);
  const chain = await call('PUT', '/api/records', h, [{ ...q1, supersededBy: q2.id }, q2]);
  const byq = Object.fromEntries(chain.json.rejected.map((x) => [x.id, x]));
  assert.equal(byq[q1.id]?.code, 'already-corrected');
  assert.deepEqual({ code: byq[q2.id]?.code, recordId: byq[q2.id]?.recordId, recordCode: byq[q2.id]?.recordCode },
    { code: 'record-refused', recordId: q1.id, recordCode: 'already-corrected' });
  assert.equal(chain.json.count, 0);
  const ids = rowsOf(await mine(h)).map((x) => x.id);
  assert.ok(!ids.includes(q1.id) && !ids.includes(q2.id), 'neither half of the chain is kept');
});

test('the race across two registries: a correction is never stored while its record is left unlinked', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'oc-pair-'));
  const file = join(dir, 'pair.db');
  const a = await startOn(file);
  const b = await startOn(file);
  try {
    const h = key();
    const seen = { stored: 0, refused: 0 };
    for (let round = 0; round < 12; round++) {
      const r = original({ rev: 1 });
      assert.equal((await a.call('PUT', '/api/records', h, [r])).json.ok, true);
      const c = correctionOf(r, { rev: 1 });
      // Device A corrects r while another tab, on the other registry, saves a change to it.
      // Either may arrive first: in odd rounds the other tab's save goes out a moment earlier.
      const late = (ms) => new Promise((ok) => setTimeout(ok, ms));
      await Promise.all([
        late(round % 2 ? 5 : 0).then(() => a.call('PUT', '/api/records', h, [c, { ...r, rev: 2, supersededBy: c.id }])),
        b.call('PUT', '/api/records', h, [{ ...r, rev: 2, notes: 'dna paired' }]),
      ]);
      const held = rowsOf((await a.call('GET', '/api/records?limit=100', h)).json);
      const stored = held.find((x) => x.id === r.id);
      const corrections = held.filter((x) => x.supersedes?.recordId === r.id).map((x) => x.id);
      if (corrections.length) {
        assert.deepEqual(corrections, [c.id]);
        assert.equal(stored.supersededBy, c.id, `round ${round}: the correction is stored, so the record names it`);
        seen.stored++;
      } else {
        assert.equal(stored.supersededBy, undefined);
        seen.refused++;
      }
    }
    assert.equal(seen.stored + seen.refused, 12);
    console.log(`# race outcomes: correction stored ${seen.stored}, refused with its record ${seen.refused}`);
  } finally {
    await a.stop();
    await b.stop();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a record already cut off from its correction is linked again, by an older copy too, and only the link is taken', async () => {
  const h = key();
  const vault = vaultKeyFor(h);
  const stored = storedHolderKey(h);
  // As an older registry could leave it: r at rev 2 with no link, and c correcting r.
  const r = original({ rev: 2, notes: 'dna paired' });
  const c = correctionOf(r);
  const raw = db.prepare('INSERT INTO records (id, holder_key, body, updated_at, first_seen) VALUES (?, ?, ?, ?, ?)');
  const { rev, ...rNoRev } = r;
  raw.run(r.id, stored, JSON.stringify({ ...sealForTest(rNoRev, vault), rev: 2 }), 1, 1);
  raw.run(c.id, stored, JSON.stringify(sealForTest(c, vault)), 2, 2);
  const boxBefore = JSON.parse(db.prepare('SELECT body FROM records WHERE id = ?').get(r.id).body).sealed;

  // A device whose copy of r is older (rev 1) names c: the content is refused, the link taken.
  const res = await call('PUT', '/api/records', h, [{ ...r, rev: 1, notes: 'first', supersededBy: c.id }]);
  assert.equal(res.json.rejected?.[0]?.code, 'older-copy');
  assert.deepEqual(res.json.relinked, [{ id: r.id, supersededBy: c.id }]);
  const after = JSON.parse(db.prepare('SELECT body FROM records WHERE id = ?').get(r.id).body);
  assert.equal(after.supersededBy, c.id);
  assert.equal(after.rev, 2, 'the stored copy is otherwise kept');
  assert.deepEqual(after.sealed, boxBefore);

  // Only a link to the correction this holder holds of r: another id, or a link already held, is not taken.
  const s = original({ rev: 2 });
  raw.run(s.id, stored, JSON.stringify({ ...sealForTest({ id: s.id, recordFingerprint: s.recordFingerprint, notes: 'x' }, vault), rev: 2 }), 1, 1);
  const wrong = await call('PUT', '/api/records', h, [{ ...s, rev: 1, supersededBy: c.id }]);
  assert.equal(wrong.json.rejected?.[0]?.code, 'older-copy');
  assert.equal(wrong.json.relinked, undefined);
  const twice = await call('PUT', '/api/records', h, [{ ...r, rev: 1, supersededBy: c.id }]);
  assert.equal(twice.json.relinked, undefined);
  // And r, linked, is held to its correction: a new one is refused, naming c.
  const c3 = correctionOf(r);
  const third = await call('PUT', '/api/records', h, [c3]);
  assert.equal(third.json.rejected?.[0]?.correctionId, c.id);
});
