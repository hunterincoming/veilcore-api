// Dating first (the site's CONTRACT.md #38, 17 Oct 2026).
//
// A record is dated the moment it is sealed in the browser: its proof code goes into the next
// batch through PUT /api/records/dating, before its locked copy can be uploaded (that waits for
// a checked backup of the vault key, round 3 L1). Before this, a holder who hadn't checked a
// backup never got a record into a batch at all: "Record dated: waiting for a batch", forever.
//
// What these tests hold the registry to:
//   - a dating row is { id, recordFingerprint, keyBinding? } and nothing else; it is stored as
//     that plus `bodyPending: true`, and goes into the next batch like any other proof code;
//   - it carries no vault key id, so it ties no vault key to the holder (no lockout): a locked
//     copy sealed under any key is still taken afterwards;
//   - the locked copy that follows must carry the same proof code (refused otherwise), and keeps
//     the date the registry first saw the proof code;
//   - the first-holder rules for ids and proof codes hold here too;
//   - nothing in it is readable beyond the proof code and key binding: a public read shows no
//     more than for any record, the purge leaves it alone, and it can't be sent to a lab.
// No network.
//
// SPDX-License-Identifier: Apache-2.0

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { randomBytes } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import Database from 'better-sqlite3';
import { untilReady, sealForTest, testBody } from './helpers.mjs';

const OPERATOR = 'dating-first-operator-token-0123456789abcdef';
process.env.DB_PATH = ':memory:';
process.env.VEILCORE_OTS = 'off';
process.env.VEILCORE_OPERATOR_TOKEN = OPERATOR;
const require = createRequire(import.meta.url);
const { app, db } = require('../server.js');

const hex = (n = 32) => randomBytes(n).toString('hex');
const key = () => hex();
const recordId = () => `VEIL-${hex(16).toUpperCase()}`;
let base, server;
before(async () => {
  server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  base = `http://127.0.0.1:${server.address().port}`;
  await untilReady(base);
});
after(() => server.close());

const call = async (method, path, holder, body, extra = {}) => {
  const res = await fetch(`${base}${path}`, {
    method,
    headers: {
      'content-type': 'application/json',
      'x-forwarded-for': `10.${randomBytes(3).join('.')}`,
      ...(holder ? { 'x-holder-key': holder } : {}),
      ...extra,
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
  return { status: res.status, json };
};
const date = (holder, rows) => call('PUT', '/api/records/dating', holder, rows);
const stored = (id) => {
  const row = db.prepare('SELECT body, first_seen FROM records WHERE id = ?').get(id);
  return row ? { body: JSON.parse(row.body), firstSeen: row.first_seen } : undefined;
};
const operator = { 'x-operator-token': OPERATOR };

test('/health lists dating-first-v1, for the site’s deploy preflights', async () => {
  const h = (await call('GET', '/health')).json;
  assert.ok(h.features.includes('dating-first-v1'), JSON.stringify(h));
});

test('a dating row is stored as its proof code alone, and goes into the next batch', async () => {
  const holder = key();
  const id = recordId();
  const fp = hex();
  const kb = hex();
  const r = await date(holder, [{ id, recordFingerprint: fp, keyBinding: kb }]);
  assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.deepEqual(r.json, { ok: true, dated: [id] });
  // Exactly that, and the registry's own mark: no box, no kid, no name, nothing typed.
  assert.deepEqual(stored(id).body, { id, recordFingerprint: fp, keyBinding: kb, bodyPending: true });
  // The holder reads it back as it is stored.
  const mine = await call('GET', '/api/records', holder);
  assert.deepEqual(mine.json, [{ id, recordFingerprint: fp, keyBinding: kb, bodyPending: true }]);
  // In the next batch, like any record's proof code.
  const pending = await call('GET', '/batches/pending', undefined, undefined, operator);
  assert.ok(pending.json.records.includes(id), JSON.stringify(pending.json));
  const sealed = await call('POST', '/batches/seal', undefined, {}, operator);
  assert.equal(sealed.status, 200, JSON.stringify(sealed.json));
  const proof = await call('GET', `/proof/${fp}`);
  assert.equal(proof.status, 200, JSON.stringify(proof.json));
  assert.equal(proof.json.batchId, sealed.json.batchId ?? proof.json.batchId);
  assert.match(String(proof.json.batchId), /^B-/);
});

test('a dating row ties no vault key to the holder: a locked copy under any key is taken after it', async () => {
  const holder = key();
  const a = recordId();
  const fpA = hex();
  assert.equal((await date(holder, [{ id: a, recordFingerprint: fpA }])).json.ok, true);
  // This browser's key never reached a backup; the holder restores another device's key, or
  // starts a new one. A row sealed under that key is accepted: nothing was bound by the dating row.
  const other = randomBytes(32);
  const b = recordId();
  const box = sealForTest({ id: b, recordFingerprint: hex(), nonce: hex(), strainName: 'X' }, other);
  const saved = await call('PUT', '/api/records', holder, [box]);
  assert.equal(saved.json.ok, true, JSON.stringify(saved.json));
  // And the first record's own locked copy, under that same key, matching its proof code.
  const boxA = sealForTest({ id: a, recordFingerprint: fpA, nonce: hex(), strainName: 'A' }, other);
  const savedA = await call('PUT', '/api/records', holder, [boxA]);
  assert.equal(savedA.json.ok, true, JSON.stringify(savedA.json));
});

test('the locked copy must carry the proof code the record was dated with, and keeps its first-seen date', async () => {
  const holder = key();
  const id = recordId();
  const fp = hex();
  await date(holder, [{ id, recordFingerprint: fp }]);
  const first = stored(id).firstSeen;
  await new Promise((r) => setTimeout(r, 15));

  // Another proof code under the same id: refused, nothing changed.
  const wrong = await call('PUT', '/api/records', holder, [{ id, recordFingerprint: hex(), nonce: hex(), strainName: 'W' }]);
  assert.equal(wrong.json.ok, false);
  assert.match(wrong.json.rejected[0].reason, /dated with a different proof code/);
  // No proof code at all: refused too.
  const none = await call('PUT', '/api/records', holder, [{ id, nonce: hex(), strainName: 'W' }]);
  assert.match(none.json.rejected[0].reason, /dated with a different proof code/);
  assert.equal(stored(id).body.bodyPending, true);

  // The same proof code: taken, the mark goes, and the first-seen date is the dating row's.
  const ok = await call('PUT', '/api/records', holder, [{ id, recordFingerprint: fp, nonce: hex(), strainName: 'R' }]);
  assert.equal(ok.json.ok, true, JSON.stringify(ok.json));
  const after = stored(id);
  assert.equal(after.body.bodyPending, undefined);
  assert.ok(after.body.sealed, 'stored locked');
  assert.equal(after.firstSeen, first, 'first seen when it was dated, not when the locked copy arrived');
  // Dating it again changes nothing.
  const again = await date(holder, [{ id, recordFingerprint: fp }]);
  assert.deepEqual(again.json, { ok: true, dated: [id] });
  assert.ok(stored(id).body.sealed, 'the locked copy is kept');
});

test('dating rows: only { id, recordFingerprint, keyBinding? }, and the first-holder rules', async () => {
  const holder = key();
  const intruder = key();
  const id = recordId();
  const fp = hex();
  for (const [row, reason] of [
    [{ id, recordFingerprint: fp, sealed: { v: 1 } }, /sealed is not part of a dating row/],
    [{ id, recordFingerprint: fp, strainName: 'Name' }, /strainName is not part of a dating row/],
    [{ id, recordFingerprint: fp, kid: '0123456789abcdef' }, /kid is not part of a dating row/],
    [{ id, recordFingerprint: fp, profile: 'veilcore/profile/animal-individual/v1' }, /profile is not part of a dating row/],
    [{ id, recordFingerprint: fp.toUpperCase() }, /64 lowercase hexadecimal/],
    [{ id, recordFingerprint: fp, keyBinding: 'nope' }, /keyBinding must be 64/],
    [{ id: 'bad id!', recordFingerprint: fp }, /id must be/],
  ]) {
    const r = await date(holder, [row]);
    assert.equal(r.json.ok, false, JSON.stringify(row));
    assert.match(r.json.rejected[0].reason, reason);
  }
  assert.equal(stored(id), undefined, 'nothing was stored');
  assert.equal((await date(holder, { id, recordFingerprint: fp })).status, 400, 'an array');
  assert.equal((await date(undefined, [{ id, recordFingerprint: fp }])).status, 401, 'a holder key');

  assert.deepEqual((await date(holder, [{ id, recordFingerprint: fp }])).json, { ok: true, dated: [id] });
  // The same again: changes nothing. Another proof code under the id: refused.
  assert.deepEqual((await date(holder, [{ id, recordFingerprint: fp }])).json, { ok: true, dated: [id] });
  const moved = await date(holder, [{ id, recordFingerprint: hex() }]);
  assert.match(moved.json.rejected[0].reason, /different proof code/);
  assert.equal(stored(id).body.recordFingerprint, fp);
  // Someone else can't take the id, or the proof code under another id.
  const taken = await date(intruder, [{ id, recordFingerprint: hex() }]);
  assert.deepEqual(taken.json.notWritten, [id]);
  const copied = await date(intruder, [{ id: recordId(), recordFingerprint: fp }]);
  assert.match(copied.json.rejected[0].reason, /already registered by another holder/);
});

test('a dating row shows the public no more than any record, can’t be sent to a lab, and can be deleted', async () => {
  const holder = key();
  const id = recordId();
  const fp = hex();
  await date(holder, [{ id, recordFingerprint: fp, keyBinding: hex() }]);
  const pub = await call('GET', `/verify/${id}`);
  assert.equal(pub.status, 200);
  assert.equal(pub.json.recordFingerprint, fp);
  assert.doesNotMatch(JSON.stringify(pub.json), /bodyPending|cultivar/);
  const resolved = await call('GET', `/records/${id}`);
  assert.doesNotMatch(JSON.stringify(resolved.json), /bodyPending/);

  const offer = await call('POST', '/transfers', holder, { sourceRecord: id, toHandle: hex() });
  assert.equal(offer.status, 409, JSON.stringify(offer.json));
  assert.match(offer.json.error, /locked copy isn't on VeilCore yet/);

  const gone = await call('DELETE', '/api/records', holder, { ids: [id] });
  assert.deepEqual(gone.json.removed, [id]);
});

test('the purge leaves a dating row as it is: there is nothing in it to remove', () => {
  const dir = mkdtempSync(join(tmpdir(), 'dating-purge-'));
  try {
    const file = join(dir, 'r.db');
    const f = new Database(file);
    f.exec('CREATE TABLE records (id TEXT PRIMARY KEY, holder_key TEXT, body TEXT, updated_at INTEGER, first_seen INTEGER)');
    const body = { id: 'VEIL-D', recordFingerprint: hex(), bodyPending: true };
    f.prepare('INSERT INTO records VALUES (?,?,?,?,?)').run('VEIL-D', 'h1', JSON.stringify(body), 1, 1);
    f.close();
    const purge = fileURLToPath(new URL('../scripts/purge-plaintext.mjs', import.meta.url));
    execFileSync(process.execPath, [purge, '--db', file, '--apply', '--include-unconverted', '--i-understand-this-deletes-text'], {
      encoding: 'utf8',
    });
    const after = JSON.parse(new Database(file, { readonly: true }).prepare('SELECT body FROM records').get().body);
    assert.deepEqual(after, body);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
