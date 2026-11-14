// Round 3 of the outside attack reviews (16 Oct 2026), registry side: one test per finding
// fixed here, each the attacker's own proof turned round.
//
//   P5  royalty obligations: a stranger with two record links grouped them by holder, and
//       the open listing gave every holder's royalty portfolio.
//   P6  the purge swapped each old recipient name for a plain SHA-256 of it, which a copy
//       of the database reversed from a short list of likely names.
//   L6  the guarded purge cut the published keys from grants on records still waiting to be
//       converted, and conversion then copied the cut list into the sealed record.
//   L2  "older copy": a stale tab, or two saves arriving out of order, overwrote the newer
//       copy of a record here (the browser re-sends the whole set). An optional public
//       `rev` lets the registry refuse the older one.
//   +   the purge's VACUUM against a live server: the server's busy timeout is set (and
//       pinned), and the purge rebuilds the file only when given --vacuum.
//
// SPDX-License-Identifier: Apache-2.0

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { createHash, createHmac, hkdfSync, randomBytes } from 'node:crypto';
import { execFileSync, fork } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import Database from 'better-sqlite3';
import { canonicalise, sha256Hex, newNonce } from 'veilcore-records';
import { untilReady, testBody, vaultKeyFor, sealForTest, openForTest, plain } from './helpers.mjs';

process.env.DB_PATH = ':memory:';
process.env.VEILCORE_OTS = 'off';
const require = createRequire(import.meta.url);
const { app, db } = require('../server.js');
const { partyIdOf } = require('../holder-key.js');

const key = () => randomBytes(32).toString('hex');

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
    headers: { 'content-type': 'application/json', 'x-forwarded-for': `10.${randomBytes(3).join('.')}`, ...(holder ? { 'x-holder-key': holder } : {}) },
    ...(body === undefined ? {} : { body: JSON.stringify(testBody(method, path, holder, body)) }),
  });
  const text = await res.text();
  let json; try { json = JSON.parse(text); } catch { json = text; }
  return { status: res.status, json, text };
};

const committedOf = (r) => ({ breedingMethod: r.breedingMethod ?? '', bredBy: r.bredBy, dateCreated: r.dateCreated,
  loggedAt: r.loggedAt, nonce: r.nonce, notes: r.notes, parents: r.parents ?? [],
  photoFingerprints: r.photoFingerprints ?? [], refId: r.refId ?? '', strainName: r.strainName });
/** A sealed record saved by `holder`, as the site saves it. */
const plant = async (holder, name = 'Code') => {
  const r = { id: `a3-${randomBytes(6).toString('hex')}`, strainName: name, bredBy: 'B', dateCreated: '2026-01-01',
    loggedAt: '2026-01-01T00:00:00Z', nonce: newNonce(), notes: 'private', parents: [], photoFingerprints: [], breedingMethod: '', refId: '' };
  r.recordFingerprint = await sha256Hex(canonicalise(committedOf(r)));
  const put = await call('PUT', '/api/records', holder, [r]);
  assert.equal(put.status, 200, JSON.stringify(put.json));
  assert.equal(put.json.ok, true, JSON.stringify(put.json));
  return r;
};

/**
 * The per-record beneficiary id as the site makes it (README, "Obligations"; the site's
 * vault.ts beneficiaryId): HMAC-SHA256 keyed with HKDF-SHA256(vault key, no salt, info
 * "veilcore:vault:beneficiary:v1"), of "veilcore:beneficiary:v1\0" + the fingerprint.
 */
const beneficiaryFor = (holder, fingerprint) => {
  const k = Buffer.from(hkdfSync('sha256', vaultKeyFor(holder), Buffer.alloc(0), 'veilcore:vault:beneficiary:v1', 32));
  return createHmac('sha256', k).update(`veilcore:beneficiary:v1\0${fingerprint}`, 'utf8').digest('hex');
};

// ---------------------------------------------------------------------------------------
// P5: royalty obligations grouped by holder
// ---------------------------------------------------------------------------------------

test('P5: a stranger with two record links cannot list obligations, group them by holder, or see a portfolio', async () => {
  const holder = key();
  const a = await plant(holder, 'Code-A');
  const b = await plant(holder, 'Code-B');
  const clean = await plant(holder, 'Code-C');
  const agreement = () => randomBytes(32).toString('hex');
  // What countersignLicense does for an offspring royalty: one with the browser's own
  // per-record id (the new wire), one without (an older site): both per record.
  const oa = agreement(), ob = agreement();
  const ra = await call('POST', '/lineage/obligations', holder, { record: a.recordFingerprint, obligation: oa, beneficiary: beneficiaryFor(holder, a.recordFingerprint) });
  const rb = await call('POST', '/lineage/obligations', holder, { record: b.recordFingerprint, obligation: ob });
  assert.equal(ra.status, 200, JSON.stringify(ra.json));
  assert.equal(rb.status, 200, JSON.stringify(rb.json));
  assert.equal(ra.json.status, 'open');
  assert.equal(ra.json.beneficiary, beneficiaryFor(holder, a.recordFingerprint));

  // The attacker's probe: GET /lineage/obligations, filter by the two fingerprints from
  // /verify, compare beneficiaries; then group the whole list by beneficiary.
  const listing = await call('GET', '/lineage/obligations');
  assert.equal(listing.status, 410);
  for (const s of [a.recordFingerprint, b.recordFingerprint, oa, ob, partyIdOf(holder)]) {
    assert.equal(listing.text.includes(s), false, 'the refusal carries nothing from the obligation set');
  }
  assert.equal((await call('GET', '/lineage/obligations?limit=1000&offset=0')).status, 410);

  // What is stored: two ids, neither the holder's party id, so even a leaked row set does
  // not group the two by id.
  const ids = db.prepare('SELECT record, beneficiary_id FROM obligations_v2 WHERE record IN (?, ?)')
    .all(a.recordFingerprint, b.recordFingerprint).map((r) => r.beneficiary_id);
  assert.equal(ids.length, 2);
  assert.notEqual(ids[0], ids[1]);
  assert.equal(ids.includes(partyIdOf(holder)), false, 'the per-holder party id is not stored for new obligations');

  // Every public check the site makes still works, per record (HeritableRights.tsx:
  // /lineage/root, /lineage/ancestors/:record, then /lineage/verify).
  assert.equal((await call('GET', '/lineage/root')).status, 200);
  assert.equal((await call('GET', `/lineage/ancestors/${a.recordFingerprint}`)).status, 200);
  const va = await call('POST', '/lineage/verify', undefined, { record: a.recordFingerprint, chain: [] });
  assert.deepEqual([va.json.ok, va.json.reason], [false, 'this record carries an unmet obligation']);
  const vc = await call('POST', '/lineage/verify', undefined, { record: clean.recordFingerprint, chain: [] });
  assert.equal(vc.json.ok, true);
  // The verify answer names no beneficiary and no other record.
  for (const s of [b.recordFingerprint, ids[0], ids[1], partyIdOf(holder)]) assert.equal(JSON.stringify(va.json).includes(s), false);

  // Revoking (revokeLicense: DELETE with the obligation only) still releases it.
  const del = await call('DELETE', `/lineage/obligations/${a.recordFingerprint}`, holder, { obligation: oa });
  assert.equal(del.status, 200, JSON.stringify(del.json));
  assert.equal((await call('POST', '/lineage/verify', undefined, { record: a.recordFingerprint, chain: [] })).json.ok, true);
  // And nobody else can, even knowing the beneficiary id.
  assert.equal((await call('DELETE', `/lineage/obligations/${b.recordFingerprint}`, key(), { obligation: ob })).status, 403);
});

test('P5: a beneficiary that is the party id, or not 64 lowercase hex, is refused', async () => {
  const holder = key();
  const a = await plant(holder);
  const obligation = randomBytes(32).toString('hex');
  const party = await call('POST', '/lineage/obligations', holder, { record: a.recordFingerprint, obligation, beneficiary: partyIdOf(holder) });
  assert.equal(party.status, 400);
  assert.match(party.json.error, /per-record id, not your party id/);
  const upper = await call('POST', '/lineage/obligations', holder, { record: a.recordFingerprint, obligation, beneficiary: 'AB'.repeat(32) });
  assert.equal(upper.status, 400);
  assert.match(upper.json.error, /64 lowercase hexadecimal/);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM obligations_v2 WHERE record = ?').get(a.recordFingerprint).n, 0);
});

test('P5: the export note says obligations are readable here, per record, and not exported', async () => {
  const holder = key();
  await plant(holder);
  const out = await call('GET', '/api/export', holder);
  assert.equal(out.status, 200);
  assert.match(out.json.note, /except: deliveries \(with their locked offers and sample details\), lab reports, royalty obligations, and requests to prove a record's key/);
  assert.match(out.json.note, /reads which record carries one and when it was made/);
  assert.match(out.json.note, /never lists them/);
});

// The comment the privacy report quoted as false (server.js, PUT /api/licenses).
test('P5: the licence comment no longer says which record a licence is about is not stored anywhere', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../server.js', import.meta.url), 'utf8');
  assert.equal(src.includes('no route needs it'), false);
  assert.match(src, /registers an obligation on the record's fingerprint/);
});

// ---------------------------------------------------------------------------------------
// The purge, on a database file (scripts/purge-plaintext.mjs)
// ---------------------------------------------------------------------------------------

const PURGE = fileURLToPath(new URL('../scripts/purge-plaintext.mjs', import.meta.url));
const purge = (file, ...flags) => execFileSync(process.execPath, [PURGE, '--db', file, ...flags], { stdio: 'pipe' }).toString();
const sealedBox = () => ({ v: 1, alg: 'A256GCM', kid: 'ab'.repeat(8), iv: 'A'.repeat(16), ct: 'B'.repeat(40) });
/**
 * A database file in the shape the purge reads (the tables and columns server.js and
 * lineage/transfer.mjs create that it touches), in a folder of its own. `converted` gets a
 * sealed record, so the purge touches them.
 */
const purgeDb = (converted) => {
  const dir = mkdtempSync(join(tmpdir(), 'veilcore-attack3-'));
  const file = join(dir, 'registry.db');
  const d = new Database(file);
  d.exec(`CREATE TABLE records (id TEXT PRIMARY KEY, holder_key TEXT NOT NULL, body TEXT NOT NULL, updated_at INTEGER NOT NULL);
          CREATE TABLE licenses (id TEXT PRIMARY KEY, holder_key TEXT NOT NULL, record_id TEXT, body TEXT NOT NULL, updated_at INTEGER NOT NULL);
          CREATE TABLE disclosure_grants (record_id TEXT PRIMARY KEY, holder_key TEXT NOT NULL, show TEXT NOT NULL, updated_at INTEGER NOT NULL, grant_values TEXT, for_fingerprint TEXT);
          CREATE TABLE transfers (id TEXT PRIMARY KEY, source_record TEXT NOT NULL, from_holder TEXT NOT NULL, to_handle TEXT NOT NULL,
            claim_code TEXT, created_at INTEGER, quantity TEXT, note TEXT);`);
  d.prepare('INSERT INTO records VALUES (?, ?, ?, 1)').run('A3-SEALED', converted,
    JSON.stringify({ id: 'A3-SEALED', strainName: 'S', recordFingerprint: 'cd'.repeat(32), sealed: sealedBox() }));
  return { dir, file, d };
};

test('P6: the purge replaces an old recipient name with random bytes, which the attacker\'s guess list does not reverse', () => {
  const holder = `h1:${'11'.repeat(32)}`;
  const { dir, file, d } = purgeDb(holder);
  try {
    const NAME = 'Jane Doe at Example Hill Labs';
    const ins = d.prepare(`INSERT INTO transfers (id, source_record, from_holder, to_handle, claim_code, created_at, quantity, note)
                           VALUES (?, 'A3-SEALED', ?, ?, 'sha256:x', 1, '3 clones', 'secret note')`);
    ins.run('TR-OLD1', holder, NAME);
    ins.run('TR-OLD2', holder, NAME);
    d.close();
    assert.match(purge(file, '--apply'), /2 recipient handles stored as typed, now random values/);
    const raw = new Database(file, { readonly: true });
    const rows = raw.prepare("SELECT to_handle, quantity, note FROM transfers ORDER BY id").all();
    raw.close();
    // purge-handle-reverse.mjs, turned round: hash each likely name the old way.
    const guesses = ['Example Hill Labs', 'Jane Doe', 'jane doe at example hill labs', NAME, 'Example Coast Labs', 'Example Genomics Lab'];
    const oldWay = (g) => createHash('sha256').update(`veilcore:legacy-handle:v1\0${g}`, 'utf8').digest('hex');
    for (const r of rows) {
      assert.match(r.to_handle, /^[0-9a-f]{64}$/, 'tag-shaped, so the column keeps its meaning');
      assert.deepEqual([r.quantity, r.note], [null, null]);
      for (const g of guesses) assert.notEqual(r.to_handle, oldWay(g), `reversed to ${g}`);
      for (const g of guesses) assert.notEqual(r.to_handle, createHash('sha256').update(g).digest('hex'));
    }
    assert.notEqual(rows[0].to_handle, rows[1].to_handle, 'a fresh value per delivery: two to one recipient do not match');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('P6: no "one-way" claim is left about the legacy handle in the code or the README', async () => {
  const { readFileSync } = await import('node:fs');
  const at = (f) => readFileSync(new URL(`../${f}`, import.meta.url), 'utf8');
  assert.doesNotMatch(at('sealed.js'), /One-way, and the same handle/);
  assert.match(at('sealed.js'), /32\s+\* random bytes as 64 lowercase hex/);
  assert.doesNotMatch(at('scripts/purge-plaintext.mjs'), /becomes the tag/);
  assert.match(at('README.md'), /replaced with 32 random bytes as hex/);
});

test('L6: the purge leaves a grant alone while its record is still plain text; grants on sealed records are cut as before', () => {
  const holder = `h1:${'22'.repeat(32)}`;
  const other = `h1:${'33'.repeat(32)}`;
  const { dir, file, d } = purgeDb(holder);
  try {
    // purge.test.ts #1: a converted holder (one sealed record) whose older record still waits
    // for the backup, with a grant made before grant values that publishes parent names.
    d.prepare('INSERT INTO records VALUES (?, ?, ?, 1)').run('A3-OLD', holder,
      JSON.stringify({ id: 'A3-OLD', strainName: 'Old', recordFingerprint: 'ef'.repeat(32), parents: [{ name: 'Mother' }], notes: 'typed' }));
    // A holder who has not converted, with the same kind of grant (stripped only by the two-flag run).
    d.prepare('INSERT INTO records VALUES (?, ?, ?, 1)').run('A3-OTHER', other,
      JSON.stringify({ id: 'A3-OTHER', strainName: 'O', recordFingerprint: '12'.repeat(32), parents: [{ name: 'Dam' }] }));
    const grant = d.prepare('INSERT INTO disclosure_grants (record_id, holder_key, show, updated_at) VALUES (?, ?, ?, 1)');
    grant.run('A3-OLD', holder, JSON.stringify(['existence', 'parent-names', 'breeding-method']));
    grant.run('A3-SEALED', holder, JSON.stringify(['existence', 'parent-names']));
    grant.run('A3-OTHER', other, JSON.stringify(['existence', 'parent-names']));
    d.close();
    const show = (id) => {
      const raw = new Database(file, { readonly: true });
      try { return JSON.parse(raw.prepare('SELECT show FROM disclosure_grants WHERE record_id = ?').get(id)?.show ?? 'null'); } finally { raw.close(); }
    };

    const dry = purge(file);
    assert.match(dry, /1 keys that publish values to drop, 0 grants left with no keys to drop \(existence and descent-clean are kept\), 1 on records still in plain text \(skipped: the app converts them with their values\), 1 of holders not yet converted \(skipped\)/);
    purge(file, '--apply');
    assert.deepEqual(show('A3-OLD'), ['existence', 'parent-names', 'breeding-method'], 'kept whole: the record has not been converted');
    assert.deepEqual(show('A3-SEALED'), ['existence'], 'a sealed record\'s old grant is cut, as before (its app re-sends the keys with values)');
    assert.deepEqual(show('A3-OTHER'), ['existence', 'parent-names'], 'an unconverted holder is skipped');

    // The two-flag run strips the unconverted holder's plain record, so its grant is cut; the
    // converted holder's plain record is never stripped, so its grant is still kept.
    const all = purge(file, '--apply', '--include-unconverted', '--i-understand-this-deletes-text');
    assert.match(all, /1 on records still in plain text \(skipped/);
    assert.deepEqual(show('A3-OLD'), ['existence', 'parent-names', 'breeding-method']);
    assert.deepEqual(show('A3-OTHER'), ['existence']);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------------------
// The purge against a live server: busy timeout, and VACUUM only with --vacuum
// ---------------------------------------------------------------------------------------

test('busy timeout: the server waits 5 s for a lock, set in server.js rather than left to a library default', () => {
  assert.equal(db.pragma('busy_timeout', { simple: true }), 5000);
  assert.match(readFileSync(new URL('../server.js', import.meta.url), 'utf8'), /db\.pragma\(`busy_timeout = \$\{SQLITE_BUSY_TIMEOUT_MS\}`\)/);
});

test('busy timeout: a save made while another connection holds the write lock waits for it, and is stored', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'veilcore-attack3-busy-'));
  const file = join(dir, 'registry.db');
  const proc = fork(fileURLToPath(new URL('./fixtures/sealed-server-child.mjs', import.meta.url)), [],
    { env: { ...process.env, DB_PATH: file }, stdio: ['ignore', 'pipe', 'pipe', 'ipc'] });
  let output = '';
  proc.stdout.on('data', (b) => { output += b; });
  proc.stderr.on('data', (b) => { output += b; });
  try {
    const { port } = await new Promise((ok, fail) => {
      proc.once('message', ok);
      proc.once('exit', (code) => fail(new Error(`registry exited (${code}): ${output}`)));
    });
    const at = `http://127.0.0.1:${port}`;
    await untilReady(at);
    // Another connection on the file (as the purge is) takes the write lock and holds it.
    const other = new Database(file);
    other.exec('BEGIN IMMEDIATE');
    const holder = key();
    const r = { id: 'A3-BUSY', strainName: 'S', notes: 'n', recordFingerprint: 'ab'.repeat(32) };
    const saving = fetch(`${at}/api/records`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json', 'x-holder-key': holder },
      body: JSON.stringify(testBody('PUT', '/api/records', holder, [r])),
    });
    await new Promise((ok) => setTimeout(ok, 400));
    other.exec('COMMIT');
    other.close();
    const res = await saving;
    assert.equal(res.status, 200, `a lock held for 0.4 s is waited for, not a 500: ${await res.clone().text()}`);
    assert.equal((await res.json()).ok, true);
  } finally {
    await new Promise((ok) => { proc.once('exit', ok); proc.send('close'); });
    rmSync(dir, { recursive: true, force: true });
  }
});

test('the purge rebuilds the file (VACUUM) only with --vacuum, and --vacuum needs --apply', () => {
  const holder = `h1:${'44'.repeat(32)}`;
  const fresh = `h1:${'55'.repeat(32)}`;
  const { dir, file, d } = purgeDb(holder);
  try {
    const SECRET = 'A3-TYPED-TEXT-';
    // An unconverted holder's large plain record: the two-flag run cuts it to its public
    // fields, which frees pages.
    d.prepare('INSERT INTO records VALUES (?, ?, ?, 1)').run('A3-BIG', fresh,
      JSON.stringify({ id: 'A3-BIG', strainName: 'B', notes: SECRET.repeat(4000) }));
    d.close();
    const pages = () => { const raw = new Database(file, { readonly: true }); try { return raw.pragma('freelist_count', { simple: true }); } finally { raw.close(); } };

    // --vacuum alone: refused, nothing changed.
    const before = readFileSync(file);
    assert.throws(() => purge(file, '--vacuum'), (e) => /--vacuum rebuilds the file after --apply/.test(String(e.stderr)) && e.status === 2);
    assert.ok(readFileSync(file).equals(before));

    // --apply alone: the changes, no rebuild; what was removed is still overwritten.
    const out = purge(file, '--apply', '--include-unconverted', '--i-understand-this-deletes-text');
    assert.match(out, /file not rebuilt: what was removed is overwritten with zeros, but the file keeps its free pages; to rebuild it, run again with --apply --vacuum in a maintenance window/);
    assert.ok(pages() > 0, 'free pages are left: no VACUUM ran');
    assert.equal(readFileSync(file).includes(SECRET), false, 'secure_delete zeroed what was removed');

    // --apply --vacuum: rebuilt.
    assert.match(purge(file, '--apply', '--vacuum'), /file rebuilt \(VACUUM\)/);
    assert.equal(pages(), 0, 'no free pages after VACUUM');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------------------
// L2: a public `rev`, and an older copy refused
// ---------------------------------------------------------------------------------------

/** A record row as the site sends it with the round 3 wire: `rev` inside the box and beside it. */
const revRow = (holder, record, rev) => ({ ...sealForTest({ ...record, rev }, vaultKeyFor(holder)), rev });
const putRows = (holder, rows) => call('PUT', '/api/records', holder, plain(rows));

test('L2: with a public rev, an older copy is refused by id (code "older-copy", status 409) and the newer one stays', async () => {
  const holder = key();
  const r = { id: `a3-rev-${randomBytes(4).toString('hex')}`, strainName: 'S', notes: 'v1', recordFingerprint: randomBytes(32).toString('hex') };
  const opened = async () => openForTest((await call('GET', '/api/records', holder)).json.find((x) => x.id === r.id), vaultKeyFor(holder));

  assert.equal((await putRows(holder, [revRow(holder, r, 1)])).json.ok, true);
  // The phone edits twice.
  const v3 = revRow(holder, { ...r, notes: 'phone, second edit' }, 3);
  assert.equal((await putRows(holder, [revRow(holder, { ...r, notes: 'phone, first edit' }, 2)])).json.ok, true);
  assert.equal((await putRows(holder, [v3])).json.ok, true);
  // A stale laptop tab edits once (rev 2), or the first of two saves arrives last.
  const stale = await putRows(holder, [revRow(holder, { ...r, notes: 'laptop, stale' }, 2)]);
  assert.equal(stale.status, 200, 'a per-row refusal, as every other: the rest of the save is unaffected');
  assert.equal(stale.json.ok, false);
  assert.deepEqual(stale.json.rejected, [{
    id: r.id,
    reason: 'older copy: this registry holds rev 3 of this record and this save is rev 2; nothing was changed',
    code: 'older-copy',
    status: 409,
    storedRev: 3,
  }]);
  assert.equal(stale.json.count, 0);
  assert.equal((await opened()).notes, 'phone, second edit', 'the newer copy is what the registry still holds');
  // A save without a rev, once the row has one, can't show it is newer: refused too.
  const none = await putRows(holder, [sealForTest({ ...r, notes: 'no rev' }, vaultKeyFor(holder))]);
  assert.equal(none.json.rejected[0].code, 'older-copy');
  assert.match(none.json.rejected[0].reason, /this save is without a rev/);
  // The same rev again is stored only as the very same box (the same request sent twice).
  assert.equal((await putRows(holder, [v3])).json.ok, true);
  // Another box at the same rev: a second tab or device that changed the row from the same
  // copy as the one stored. Refused as an older copy, so the first change isn't lost.
  const sameRev = await putRows(holder, [revRow(holder, { ...r, notes: 'other tab, same base' }, 3)]);
  assert.equal(sameRev.json.ok, false);
  assert.deepEqual(
    { code: sameRev.json.rejected[0].code, status: sameRev.json.rejected[0].status, storedRev: sameRev.json.rejected[0].storedRev },
    { code: 'older-copy', status: 409, storedRev: 3 },
  );
  assert.match(sameRev.json.rejected[0].reason, /another copy at rev 3/);
  assert.equal((await opened()).notes, 'phone, second edit');
  assert.equal((await putRows(holder, [revRow(holder, { ...r, notes: 'v4' }, 4)])).json.ok, true);
  assert.equal((await opened()).notes, 'v4');
  // The holder reads the rev back; a stranger's answers never carry it.
  const row = (await call('GET', '/api/records', holder)).json.find((x) => x.id === r.id);
  assert.equal(row.rev, 4);
  for (const path of [`/records/${r.id}`, `/verify/${r.id}`]) {
    const pub = await call('GET', path);
    assert.equal(pub.status, 200);
    assert.equal('rev' in pub.json, false, `${path} does not answer rev`);
  }
});

test('L2: a refused older copy does not stop the other rows of the same save', async () => {
  const holder = key();
  const a = { id: `a3-ra-${randomBytes(4).toString('hex')}`, strainName: 'A', recordFingerprint: randomBytes(32).toString('hex') };
  const b = { id: `a3-rb-${randomBytes(4).toString('hex')}`, strainName: 'B', recordFingerprint: randomBytes(32).toString('hex') };
  await putRows(holder, [revRow(holder, a, 5), revRow(holder, b, 1)]);
  const both = await putRows(holder, [revRow(holder, a, 4), revRow(holder, b, 2)]);
  assert.equal(both.json.count, 1);
  assert.deepEqual(both.json.rejected.map((x) => [x.id, x.code]), [[a.id, 'older-copy']]);
  const revs = Object.fromEntries((await call('GET', '/api/records', holder)).json.map((x) => [x.id, x.rev]));
  assert.deepEqual(revs, { [a.id]: 5, [b.id]: 2 });
});

test('L2: rows without a rev save as before; a rev that is not a whole number from 0 up is refused', async () => {
  const holder = key();
  const r = { id: `a3-norev-${randomBytes(4).toString('hex')}`, strainName: 'S', recordFingerprint: randomBytes(32).toString('hex') };
  const box = () => sealForTest(r, vaultKeyFor(holder));
  assert.equal((await putRows(holder, [box()])).json.ok, true);
  assert.equal((await putRows(holder, [box()])).json.ok, true, 'no rev stored, none sent: as before round 3');
  for (const bad of [-1, 1.5, '3', 2 ** 53]) {
    const res = await putRows(holder, [{ ...box(), rev: bad }]);
    assert.deepEqual(res.json.rejected, [{ id: r.id, reason: 'rev must be a whole number from 0 up' }], String(bad));
  }
  assert.equal((await putRows(holder, [{ ...box(), rev: 0 }])).json.ok, true, 'a first rev on a row that had none');
});
