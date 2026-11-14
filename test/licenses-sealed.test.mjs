// Licences with sealed records (the site's CONTRACT.md for sealed records, #5): a licence is
// { id, sealed } and nothing else. Its terms, its parties and the record it is about are all
// in the box; the registry stores no record id for it. Licences stored in plain text before
// are served to their own holder until re-saved. No network.
//
// SPDX-License-Identifier: Apache-2.0

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { randomBytes } from 'node:crypto';
import { sha256Hex, newNonce } from 'veilcore-records';
import { untilReady, sealForTest, openForTest, vaultKeyFor } from './helpers.mjs';

process.env.DB_PATH = ':memory:';
process.env.VEILCORE_OTS = 'off';
const require = createRequire(import.meta.url);
const { app, db } = require('../server.js');
const { storedHolderKey } = require('../holder-key.js');

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
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const text = await res.text();
  let json; try { json = JSON.parse(text); } catch { json = text; }
  return { status: res.status, json };
};
const licence = (id, over = {}) => ({ id, recordId: 'VEIL-1', licensee: 'Grower G', terms: { royalty: '5%', territory: 'NJ' }, ...over });
const sealed = (holder, l) => sealForTest(l, vaultKeyFor(holder), 'licenses');
const row = (id) => db.prepare('SELECT holder_key, record_id, body FROM licenses WHERE id = ?').get(id);

test('a licence is stored as { id, sealed } exactly, with no record id, and opens again for its holder', async () => {
  const holder = key();
  const l = licence('LIC-S1');
  const wire = sealed(holder, l);
  const r = await call('PUT', '/api/licenses', holder, [wire]);
  assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.deepEqual(r.json, { ok: true, count: 1 });
  const stored = row('LIC-S1');
  assert.equal(stored.record_id, null, 'which record it is about is sealed');
  assert.deepEqual(JSON.parse(stored.body), wire);
  assert.ok(!stored.body.includes('Grower G'));
  const back = (await call('GET', '/api/licenses', holder)).json;
  assert.deepEqual(back, [wire]);
  assert.deepEqual(openForTest(back[0], vaultKeyFor(holder), 'licenses'), l);
  // Paged reads return the same rows.
  assert.deepEqual((await call('GET', '/api/licenses?limit=10', holder)).json.licenses, [wire]);
});

test('anything beside id and sealed is refused by name; a missing or malformed box is refused', async () => {
  const holder = key();
  const ok = sealed(holder, licence('LIC-OK'));
  const cases = [
    [{ ...ok, id: 'LIC-REC', recordId: 'VEIL-1' }, /^recordId is not stored in the clear; a license is \{ id, rev, sealed \}/],
    [{ ...ok, id: 'LIC-TERMS', terms: 'x' }, /^terms is not stored in the clear/],
    [{ ...ok, id: 'LIC-STATUS', status: 'active' }, /^status is not stored in the clear/],
    [{ id: 'LIC-NOBOX' }, /^sealed is required/],
    [{ ...ok, id: 'LIC-V', sealed: { ...ok.sealed, v: 0 } }, /^sealed\.v must be 1/],
    [{ ...ok, id: 'LIC-BIG', sealed: { ...ok.sealed, ct: 'A'.repeat(360_004) } }, /^sealed\.ct may be at most 360000/],
    [{ ...ok, id: 'LIC-HUGE', sealed: { ...ok.sealed, ct: 'A'.repeat(400_000) } }, /^a license may be at most 393216 bytes/],
    [{ ...ok, id: 'bad id!' }, /^id must be 1-128/],
  ];
  const r = await call('PUT', '/api/licenses', holder, [ok, ...cases.map(([c]) => c), 'not an object', null]);
  assert.equal(r.json.count, 1);
  assert.equal(r.json.ok, false);
  for (const [c, reason] of cases) {
    const rej = r.json.rejected.find((x) => x.id === c.id);
    assert.ok(rej, c.id);
    assert.match(rej.reason, reason, c.id);
  }
  assert.equal(r.json.rejected.filter((x) => x.id === null).length, 2, 'non-objects are refused too');
  assert.deepEqual((await call('GET', '/api/licenses', holder)).json.map((l) => l.id), ['LIC-OK']);
  // A licence as older sites sent it, in plain text: refused.
  const plain = await call('PUT', '/api/licenses', holder, [licence('LIC-PLAIN')]);
  assert.equal(plain.json.count, 0);
  assert.match(plain.json.rejected[0].reason, /is not stored in the clear/);
});

test('a licence in plain text from before is served to its holder only, converts when re-saved sealed, and no one else can take its id', async () => {
  const holder = key();
  const old = licence('LIC-OLD', { terms: { royalty: 'LEGACY-TERMS' } });
  db.prepare('INSERT INTO licenses (id, holder_key, record_id, body, updated_at) VALUES (?,?,?,?,?)')
    .run(old.id, storedHolderKey(holder), old.recordId, JSON.stringify(old), 1);
  assert.deepEqual((await call('GET', '/api/licenses', holder)).json, [old]);
  assert.deepEqual((await call('GET', '/api/licenses', key())).json, []);
  // Another holder can't overwrite it.
  const thief = key();
  const t = await call('PUT', '/api/licenses', thief, [sealed(thief, licence('LIC-OLD'))]);
  assert.deepEqual(t.json.notWritten, ['LIC-OLD']);
  // Its holder's browser converts it.
  assert.equal((await call('PUT', '/api/licenses', holder, [sealed(holder, old)])).json.count, 1);
  const stored = row('LIC-OLD');
  assert.equal(stored.record_id, null);
  assert.ok(!stored.body.includes('LEGACY-TERMS'));
  assert.deepEqual(openForTest(JSON.parse(stored.body), vaultKeyFor(holder), 'licenses'), old);
});

test('licences and records share the holder\'s one vault key, whichever is saved first', async () => {
  const holder = key();
  const mine = vaultKeyFor(holder);
  const other = randomBytes(32);
  assert.equal((await call('PUT', '/api/licenses', holder, [sealForTest(licence('LIC-FIRST'), mine, 'licenses')])).json.count, 1);
  const r = { id: 'VEIL-AFTER', strainName: 'S', bredBy: 'B', dateCreated: '2026-01-01', loggedAt: 1, nonce: newNonce(), notes: '', parents: [], photoFingerprints: [], breedingMethod: '', refId: '' };
  r.recordFingerprint = await sha256Hex(r.nonce); // any fingerprint: the registry can't check it
  const wrong = await call('PUT', '/api/records', holder, [sealForTest(r, other)]);
  assert.match(wrong.json.rejected[0].reason, /different vault key/);
  assert.equal((await call('PUT', '/api/records', holder, [sealForTest(r, mine)])).json.count, 1);
});

// Round 2 (L5): a set of small licences grows several times over once padded and sealed, so
// the limit is 4 MB (server.js LICENCE_BODY_LIMIT; it was 704 KB).
test('the licence PUT body limit grew with sealing: 4 MB is accepted, one byte more is refused', async () => {
  const LIMIT = 4 * 1024 * 1024;
  const holder = key();
  const vault = vaultKeyFor(holder);
  // A holder's licences that came to just under 512 KB in plain text, the old limit, still go in one save sealed.
  const big = Array.from({ length: 8 }, (_, i) => licence(`LIC-BIG-${i}`, { terms: { extra: 'x'.repeat(64_500 + i) } }));
  const plainBytes = JSON.stringify(big).length;
  assert.ok(plainBytes > 500 * 1024 && plainBytes < 512 * 1024, String(plainBytes));
  const wire = big.map((l) => sealForTest(l, vault, 'licenses'));
  const sealedBytes = JSON.stringify(wire).length;
  assert.ok(sealedBytes > 512 * 1024 && sealedBytes < LIMIT, `sealed ${sealedBytes} bytes`);
  const ok = await call('PUT', '/api/licenses', holder, wire);
  assert.equal(ok.status, 200, JSON.stringify(ok.json).slice(0, 200));
  assert.equal(ok.json.count, 8);

  // The edge, with rows the registry would store: exactly LIMIT bytes, then LIMIT + 1.
  const kid = wire[0].sealed.kid;
  const rowsOfSize = (bytes) => {
    const rows = Array.from({ length: 15 }, (_, i) => ({
      id: `LIC-EDGE-${i}`, sealed: { v: 1, alg: 'A256GCM', kid, iv: 'A'.repeat(16), ct: 'B'.repeat(279_000) },
    }));
    const short = bytes - JSON.stringify(rows).length;
    // A base64url length of 1 mod 4 is no whole number of bytes: that byte goes in the id instead.
    const ct = 279_000 + short;
    if (ct % 4 === 1) rows[14].id += 'X';
    rows[14].sealed.ct = 'B'.repeat(ct % 4 === 1 ? ct - 1 : ct);
    const text = JSON.stringify(rows);
    assert.equal(Buffer.byteLength(text), bytes);
    return text;
  };
  const raw = async (text) => {
    const res = await fetch(`${base}/api/licenses`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json', 'x-forwarded-for': `10.${randomBytes(3).join('.')}`, 'x-holder-key': holder },
      body: text,
    });
    return { status: res.status, json: await res.json() };
  };
  const at = await raw(rowsOfSize(LIMIT));
  assert.equal(at.status, 200, JSON.stringify(at.json).slice(0, 200));
  assert.equal(at.json.count, 15, JSON.stringify(at.json.rejected));
  const over = await raw(rowsOfSize(LIMIT + 1));
  assert.equal(over.status, 413);
  // Other routes keep 512 KB.
  const grant = await fetch(`${base}/api/records/VEIL-NONE/disclosure`, {
    method: 'PUT',
    headers: { 'content-type': 'application/json', 'x-forwarded-for': `10.${randomBytes(3).join('.')}`, 'x-holder-key': holder },
    body: JSON.stringify({ show: [], pad: 'x'.repeat(600 * 1024) }),
  });
  assert.equal(grant.status, 413);
});

test('DELETE /api/licenses removes only the holder\'s own licences (a locked one can be taken off VeilCore)', async () => {
  const holder = key();
  const other = key();
  assert.equal((await call('PUT', '/api/licenses', holder, [sealed(holder, licence('LIC-DEL-1')), sealed(holder, licence('LIC-DEL-2'))])).json.count, 2);
  assert.equal((await call('PUT', '/api/licenses', other, [sealed(other, licence('LIC-DEL-OTHER'))])).json.count, 1);
  assert.equal((await call('DELETE', '/api/licenses', undefined, { ids: ['LIC-DEL-1'] })).status, 401);
  assert.equal((await call('DELETE', '/api/licenses', holder, { ids: [] })).status, 400);
  const r = await call('DELETE', '/api/licenses', holder, { ids: ['LIC-DEL-1', 'LIC-DEL-OTHER', 'LIC-NONE'] });
  assert.equal(r.status, 200);
  assert.deepEqual(r.json, { ok: false, removed: ['LIC-DEL-1'], notRemoved: ['LIC-DEL-OTHER', 'LIC-NONE'], reason: 'no such license under this holder key' });
  assert.deepEqual((await call('GET', '/api/licenses', holder)).json.map((l) => l.id), ['LIC-DEL-2']);
  assert.deepEqual((await call('GET', '/api/licenses', other)).json.map((l) => l.id), ['LIC-DEL-OTHER']);
  assert.equal(row('LIC-DEL-1'), undefined);
});
