// The evidence re-stamp (lineage/restamp.mjs): the entry rule, the root rebuilt from a fixture
// written by a second implementation (fixtures/restamp_v1_reference.py), the one-item checker,
// the manifest check, and the store with the calendars faked. No calendar or explorer is
// contacted: the real stampRoot runs against a fetch that answers for them.
//
// SPDX-License-Identifier: Apache-2.0

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import {
  KINDS, entryFor, itemBytes, rootOf, checkRestampItem, checkManifest, restampSettings, collectEntries, createRestamps,
} from '../lineage/restamp.mjs';
import { stampRoot, parseOtsFile, rootDigest } from '../lineage/ots.mjs';

const require = createRequire(import.meta.url);
const Database = require('better-sqlite3');
const fixture = JSON.parse(readFileSync(new URL('./fixtures/restamp-v1.json', import.meta.url), 'utf8'));
const sha = (b) => createHash('sha256').update(b).digest();

/** The item as the collector meets it: hex strings for roots, bytes for tokens, objects for the rest. */
const itemOf = (it) => (it.kind === 'rfc3161' ? Buffer.from(it.item, 'hex') : it.item);
const bytesOf = (it) => (it.bytesHex !== undefined ? Buffer.from(it.bytesHex, 'hex') : Buffer.from(it.bytesText, 'utf8'));

/** A database holding the fixture's items in the registry's own column names, in `order`. */
const fixtureDb = (order = fixture.items) => {
  const db = new Database(':memory:');
  db.exec(`
    CREATE TABLE batches (batch_id TEXT, root TEXT, tsa_token BLOB);
    CREATE TABLE batch_timestamps (token BLOB);
    CREATE TABLE record_timestamps (token BLOB);
    CREATE TABLE attestations (body TEXT);
    CREATE TABLE retractions (body TEXT);
    CREATE TABLE attesters (public_key TEXT, display_name TEXT, role TEXT, accreditation TEXT, registered_at INTEGER);
  `);
  let tokens = 0;
  for (const it of order) {
    if (it.kind === 'batch-root') db.prepare('INSERT INTO batches VALUES (?, ?, NULL)').run(`B-${it.item.slice(0, 4)}`, it.item);
    if (it.kind === 'rfc3161') {
      // One token where each kind of token lives: a batch's own, then another TSA's.
      if (tokens++ === 0) db.prepare('INSERT INTO batch_timestamps VALUES (?)').run(itemOf(it));
      else db.prepare('INSERT INTO record_timestamps VALUES (?)').run(itemOf(it));
    }
    if (it.kind === 'attestation') db.prepare('INSERT INTO attestations VALUES (?)').run(JSON.stringify(it.item));
    if (it.kind === 'withdrawal') db.prepare('INSERT INTO retractions VALUES (?)').run(JSON.stringify(it.item));
    if (it.kind === 'enrolment') {
      db.prepare('INSERT INTO attesters VALUES (?, ?, ?, NULL, ?)').run(it.item.publicKey, it.item.displayName, it.item.role, it.item.registeredAt);
    }
  }
  return db;
};

// ---- the rules -------------------------------------------------------------------------

test('settings: off unless VEILCORE_RESTAMP is manual or on; yearly by default; a bad setting keeps it off', () => {
  assert.deepEqual(restampSettings({}), { mode: 'off', everyMs: 365 * 86_400_000, problems: [] });
  assert.equal(restampSettings({ VEILCORE_RESTAMP: 'off' }).mode, 'off');
  assert.equal(restampSettings({ VEILCORE_RESTAMP: 'manual' }).mode, 'manual');
  assert.equal(restampSettings({ VEILCORE_RESTAMP: ' ON ' }).mode, 'on');
  assert.equal(restampSettings({ VEILCORE_RESTAMP: 'on', VEILCORE_RESTAMP_EVERY_DAYS: '30' }).everyMs, 30 * 86_400_000);
  for (const env of [{ VEILCORE_RESTAMP: 'yes' }, { VEILCORE_RESTAMP: 'on', VEILCORE_RESTAMP_EVERY_DAYS: '0' }, { VEILCORE_RESTAMP: 'on', VEILCORE_RESTAMP_EVERY_DAYS: '1.5' }]) {
    const s = restampSettings(env);
    assert.equal(s.mode, 'off', JSON.stringify(env));
    assert.equal(s.problems.length, 1);
  }
});

test('item bytes: what the registry serves gives the bytes the reference implementation hashed', () => {
  for (const it of fixture.items) {
    assert.deepEqual(itemBytes(it.kind, itemOf(it)), bytesOf(it), it.kind);
    assert.equal(entryFor(it.kind, bytesOf(it)), it.entry, it.kind);
  }
  // The enrolment is the exact message the key signed: registeredAt becomes issuedAt.
  const enrol = fixture.items.find((i) => i.kind === 'enrolment');
  assert.match(itemBytes('enrolment', enrol.item).toString('utf8'), /^\{"displayName":"Fixture Lab","issuedAt":1793534400000,"publicKey":"3{64}","role":"laboratory","type":"veilcore\/attester-registration\/v1"\}$/);
});

test('entries: the rule is SHA-256 of "veilcore:restamp:v1:<kind>:<SHA-256 of the item>", and the kind is part of it', () => {
  const root = Buffer.alloc(32, 0xaa);
  const byHand = sha(Buffer.from(`veilcore:restamp:v1:batch-root:${sha(root).toString('hex')}`, 'utf8')).toString('hex');
  assert.equal(entryFor('batch-root', root), byHand);
  // The same bytes as another kind are another entry.
  assert.notEqual(entryFor('rfc3161', root), byHand);
  assert.throws(() => entryFor('record', root), /unknown kind/);
  assert.deepEqual(KINDS, ['batch-root', 'attestation', 'withdrawal', 'enrolment', 'rfc3161']);
});

test('the root, rebuilt from the fixture: the same as the reference, in any order the rows were stored', async () => {
  assert.equal(await rootOf(fixture.entries), fixture.root);
  for (const order of [fixture.items, [...fixture.items].reverse()]) {
    const { byKind, skipped } = collectEntries(fixtureDb(order));
    const all = [...new Set(KINDS.flatMap((k) => [...byKind[k]]))].sort();
    assert.deepEqual(all, fixture.entries);
    assert.equal(await rootOf(all), fixture.root);
    assert.deepEqual(Object.fromEntries(KINDS.map((k) => [k, byKind[k].size])), { 'batch-root': 2, attestation: 1, withdrawal: 1, enrolment: 1, rfc3161: 2 });
    assert.deepEqual(Object.values(skipped), [0, 0, 0, 0, 0]);
  }
});

test('collecting: a row that cannot be put in canonical form is left out and counted, never guessed at', () => {
  const db = fixtureDb();
  db.prepare('INSERT INTO attestations VALUES (?)').run('{not json');
  db.prepare('INSERT INTO batches VALUES (?, ?, NULL)').run('B-bad', 'NOT-HEX');
  const { byKind, skipped } = collectEntries(db);
  assert.equal(byKind.attestation.size, 1);
  assert.equal(skipped.attestation, 1);
  assert.equal(skipped['batch-root'], 1);
  // A registry with none of the tables yet gives nothing, and does not throw.
  assert.equal(Object.values(collectEntries(new Database(':memory:')).byKind).reduce((n, s) => n + s.size, 0), 0);
});

// ---- the store, with the calendars faked -----------------------------------------------

const vu = (n) => { const o = []; do { let b = n & 0x7f; n >>>= 7; if (n) b |= 0x80; o.push(b); } while (n); return Buffer.from(o); };
const pendingAnswer = (uri) => {
  const u = Buffer.from(uri);
  const payload = Buffer.concat([vu(u.length), u]);
  return Buffer.concat([Buffer.from([0xf0, 16]), sha(`nonce:${uri}`).subarray(0, 16), Buffer.from([0x08, 0x00]), Buffer.from('83dfe30d2ef90c8e', 'hex'), vu(payload.length), payload]);
};
const calendars = ['https://a.pool.opentimestamps.org'];
const fakeCalendars = async (url) => new Response(pendingAnswer('https://alice.btc.calendar.opentimestamps.org'), { status: url.endsWith('/digest') ? 200 : 404 });
const store = (db, extra = {}) => {
  let t = Date.parse('2026-11-25T12:00:00Z');
  const asked = [];
  const r = createRestamps(db, {
    calendars,
    now: () => t,
    otsOn: () => true,
    stamp: (root, o) => { asked.push(root); return stampRoot(root, { ...o, fetchImpl: fakeCalendars }); },
    upgrade: async (answer) => ({ answer, bitcoin: { height: 925_000, time: '2026-11-25T15:00:00.000Z' }, pending: 0, errors: [] }),
    ...extra,
  });
  return { r, asked, later: (ms) => { t += ms; } };
};

test('a re-stamp: stored, stamped, published as hashes only, rebuilt and checked from what is published', async () => {
  const db = fixtureDb();
  const { r, asked } = store(db);
  const out = await r.run();
  assert.equal(out.error, undefined);
  assert.equal(out.root, fixture.root);
  assert.equal(out.status, 'pending');
  assert.deepEqual(asked, [fixture.root], 'the root itself is what OpenTimestamps stamps');
  assert.match(out.restampId, /^RS-20261125-[0-9A-F]{4}$/);

  // The .ots commits to root.bin, the 32 raw bytes, as a batch's does.
  const ots = r.otsFor(out.restampId);
  assert.ok(parseOtsFile(ots.ots, rootDigest(fixture.root)));

  // The manifest: enough to rebuild the root, and nothing an item could be read from.
  const m = r.manifest(out.restampId);
  assert.deepEqual(m.entries, fixture.entries);
  assert.deepEqual(await checkManifest(m), { ok: true, root: fixture.root });
  const published = JSON.stringify(m);
  for (const secret of ['ab'.repeat(64), 'cd'.repeat(64), 'Fixture Lab', 'att-fixture-1', 'ee'.repeat(20)]) {
    assert.equal(published.includes(secret), false, `the manifest holds ${secret.slice(0, 12)}`);
  }

  // One item, checked on its own with its proof.
  for (const it of fixture.items) {
    const { proof } = await r.proofFor(out.restampId, it.entry);
    const ok = await checkRestampItem({ kind: it.kind, bytes: itemBytes(it.kind, itemOf(it)), proof, root: fixture.root });
    assert.deepEqual(ok, { ok: true, entry: it.entry, root: fixture.root }, it.kind);
  }
  assert.equal((await r.proofFor(out.restampId, '00'.repeat(32))).code, 404);
  assert.equal((await r.proofFor(out.restampId, 'NOT')).code, 400);
});

test('the checker refuses an edited item, another kind, another root and an edited path', async () => {
  const db = fixtureDb();
  const { r } = store(db);
  const { restampId } = await r.run();
  const att = fixture.items.find((i) => i.kind === 'attestation');
  const { proof } = await r.proofFor(restampId, att.entry);
  const bytes = itemBytes('attestation', att.item);
  const edited = itemBytes('attestation', { ...att.item, issuedAt: '2020-01-01T00:00:00Z' });
  assert.equal((await checkRestampItem({ kind: 'attestation', bytes: edited, proof })).reason, 'the proof is for a different item');
  assert.equal((await checkRestampItem({ kind: 'withdrawal', bytes, proof })).ok, false);
  assert.equal((await checkRestampItem({ kind: 'attestation', bytes, proof, root: '00'.repeat(32) })).reason, 'the proof leads to a different root');
  const bent = { ...proof, path: proof.path.map((s, i) => (i === 0 ? { ...s, siblingIsLeft: !s.siblingIsLeft } : s)) };
  assert.equal((await checkRestampItem({ kind: 'attestation', bytes, proof: bent })).reason, 'the path does not lead to the root');
  assert.equal((await checkRestampItem({ kind: 'attestation', bytes, proof: null })).ok, false);
});

test('the manifest check refuses an edited, reordered or miscounted list', async () => {
  const db = fixtureDb();
  const { r } = store(db);
  const m = r.manifest((await r.run()).restampId);
  const swap = [...m.entries];
  [swap[0], swap[1]] = [swap[1], swap[0]];
  assert.equal((await checkManifest({ ...m, entries: swap })).ok, false);
  assert.equal((await checkManifest({ ...m, entries: [...m.entries.slice(0, -1), '00'.repeat(32)].sort() })).ok, false);
  assert.equal((await checkManifest({ ...m, counts: { ...m.counts, rfc3161: 3 } })).ok, false);
  assert.equal((await checkManifest({ ...m, format: 'something-else' })).ok, false);
});

test('when it runs: nothing new is refused, a new item makes a new one, due after the period, upkeep reaches Bitcoin', async () => {
  const db = fixtureDb();
  const { r, later } = store(db);
  assert.equal(r.due(365 * 86_400_000), true, 'none yet: due');
  const first = await r.run();
  assert.equal(r.due(365 * 86_400_000), false);
  const again = await r.run();
  assert.equal(again.code, 409);
  assert.match(again.error, /nothing new since RS-/);

  db.prepare('INSERT INTO batches VALUES (?, ?, NULL)').run('B-new', '77'.repeat(32));
  later(1000);
  const second = await r.run();
  assert.notEqual(second.root, first.root);
  assert.equal(second.counts['batch-root'], 3);
  assert.deepEqual(r.list().map((x) => x.restampId), [second.restampId, first.restampId], 'newest first');
  later(365 * 86_400_000);
  assert.equal(r.due(365 * 86_400_000), true);

  await r.upkeep();
  const now = r.list()[0];
  assert.equal(now.status, 'bitcoin');
  assert.equal(now.bitcoinBlockHeight, 925_000);
});

test('refused with OpenTimestamps off, with nothing to stamp, and a failed stamp is kept and retried', async () => {
  const off = store(fixtureDb(), { otsOn: () => false }).r;
  assert.match((await off.run()).error, /VEILCORE_OTS=off/);
  assert.equal((await store(new Database(':memory:')).r.run()).error, 'nothing to re-stamp yet');

  let down = true;
  const db = fixtureDb();
  const { r } = store(db, {
    stamp: (root, o) => stampRoot(root, { ...o, fetchImpl: async (url) => (down ? new Response('', { status: 503 }) : fakeCalendars(url)) }),
  });
  const out = await r.run();
  assert.equal(out.status, 'failed');
  assert.match(out.stampError, /no OpenTimestamps calendar answered/);
  down = false;
  await r.upkeep();
  assert.equal(r.list()[0].status, 'bitcoin', 'stamped on the retry, then upgraded in the same pass');
});

test('scripts/restamp-check.mjs: one item checked from files alone, and an edited one refused', async () => {
  const { execFileSync } = await import('node:child_process');
  const { mkdtempSync, writeFileSync, rmSync } = await import('node:fs');
  const { join } = await import('node:path');
  const { tmpdir } = await import('node:os');
  const { fileURLToPath } = await import('node:url');
  const script = fileURLToPath(new URL('../scripts/restamp-check.mjs', import.meta.url));
  const { r } = store(fixtureDb());
  const { restampId } = await r.run();
  const dir = mkdtempSync(join(tmpdir(), 'restamp-check-'));
  try {
    const att = fixture.items.find((i) => i.kind === 'attestation');
    writeFileSync(join(dir, 'attestation.json'), JSON.stringify(att.item, null, 2));
    writeFileSync(join(dir, 'proof.json'), JSON.stringify((await r.proofFor(restampId, att.entry)).proof));
    writeFileSync(join(dir, 'manifest.json'), JSON.stringify(r.manifest(restampId)));
    const run = (item, ...more) => execFileSync(process.execPath, [script, '--kind', 'attestation', '--item', item, '--proof', join(dir, 'proof.json'), '--manifest', join(dir, 'manifest.json'), ...more], { stdio: 'pipe' }).toString();
    const plain = run(join(dir, 'attestation.json'));
    assert.match(plain, new RegExp(`IN THE RE-STAMP: attestation entry ${att.entry}`));
    assert.match(plain, /root\.bin not checked/);
    // --root-bin: the file root.bin.ots stamps must be this root, or nothing is said about a date.
    writeFileSync(join(dir, 'root.bin'), Buffer.from(fixture.root, 'hex'));
    assert.match(run(join(dir, 'attestation.json'), '--root-bin', join(dir, 'root.bin')), /root\.bin is this root/);
    writeFileSync(join(dir, 'other.bin'), Buffer.alloc(32, 7));
    assert.throws(() => run(join(dir, 'attestation.json'), '--root-bin', join(dir, 'other.bin')),
      (e) => e.status === 1 && /root\.bin is not the root the proof leads to/.test(String(e.stderr)));
    writeFileSync(join(dir, 'edited.json'), JSON.stringify({ ...att.item, reason: undefined, issuedAt: '2020-01-01T00:00:00Z' }));
    assert.throws(() => run(join(dir, 'edited.json')), (e) => e.status === 1 && /the proof is for a different item/.test(String(e.stderr)));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
