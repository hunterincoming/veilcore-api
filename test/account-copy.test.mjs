// The account copy (lineage/account-copy.mjs): one locked copy, several ways in. Saved, read,
// checked and deleted only with the copy's own write token; a way in's token reads that way in
// and nothing else (security review S3); never a copy without a way in; limits per copy, not per
// address, once a copy exists (S9).
//
// SPDX-License-Identifier: Apache-2.0

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { randomBytes } from 'node:crypto';
import Database from 'better-sqlite3';
import { copyFingerprint, createAccountCopies, tokenHash } from '../lineage/account-copy.mjs';
import { untilReady } from './helpers.mjs';

process.env.DB_PATH = ':memory:';
process.env.VEILCORE_OTS = 'off';
const require = createRequire(import.meta.url);
const { app } = require('../server.js');

let base, server;
before(async () => {
  server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  base = `http://127.0.0.1:${server.address().port}`;
  await untilReady(base);
});
after(() => server.close());

const call = async (method, path, body) => {
  const res = await fetch(`${base}${path}`, {
    method,
    headers: { 'content-type': 'application/json' },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  return { status: res.status, json: await res.json().catch(() => undefined), headers: res.headers };
};
const b64 = (n) => randomBytes(n).toString('base64url');
const hex = (n) => randomBytes(n).toString('hex');
const newSlot = (kind = 'passkey') => {
  const token = b64(32);
  return { token, body: { slotId: hex(16), kind, tokenHash: tokenHash(token), iv: b64(12), ct: b64(48) } };
};
const newCopy = () => ({ id: hex(16), token: b64(32), iv: b64(12), ct: b64(300), slot: newSlot() });
const make = (c) => call('PUT', `/account-copy/${c.id}`, { token: c.token, prev: 'none', iv: c.iv, ct: c.ct, slot: c.slot.body });

test('the registry says it serves the account copy', async () => {
  const h = await call('GET', '/health');
  assert.equal(h.status, 200);
  assert.ok(h.json.features.includes('account-copy-v1'));
  // The copies made before it stay readable (and deletable) for moving them over.
  assert.ok(h.json.features.includes('passkey-vault-v1'));
});

test('a copy is made with its first way in, read, checked, replaced and deleted with its token', async () => {
  const c = newCopy();
  const put = await make(c);
  assert.equal(put.status, 200);
  assert.equal(put.json.fingerprint, copyFingerprint(c.iv, c.ct));

  const got = await call('POST', `/account-copy/${c.id}/read`, { token: c.token });
  assert.equal(got.status, 200);
  assert.equal(got.json.ct, c.ct);
  assert.equal(got.headers.get('cache-control'), 'no-store');
  assert.deepEqual(
    got.json.slots.map((s) => [s.slotId, s.kind]),
    [[c.slot.body.slotId, 'passkey']],
  );

  const head = await call('POST', `/account-copy/${c.id}/head`, { token: c.token });
  assert.equal(head.status, 200);
  assert.equal(head.json.fingerprint, copyFingerprint(c.iv, c.ct));
  assert.equal(head.json.ct, undefined, 'the head check never carries the copy');

  const next = { iv: b64(12), ct: b64(400) };
  assert.equal((await call('PUT', `/account-copy/${c.id}`, { token: c.token, prev: copyFingerprint(c.iv, c.ct), ...next })).status, 200);
  assert.equal((await call('POST', `/account-copy/${c.id}/read`, { token: c.token })).json.ct, next.ct);

  // The way in reads its own sealed account key, and says which copy it opens.
  const slot = await call('POST', `/account-slot/${c.slot.body.slotId}/read`, { token: c.slot.token });
  assert.equal(slot.status, 200);
  assert.deepEqual(slot.json, { copyId: c.id, kind: 'passkey', iv: c.slot.body.iv, ct: c.slot.body.ct });

  assert.equal((await call('POST', `/account-copy/${c.id}/delete`, { token: c.token })).status, 200);
  assert.equal((await call('POST', `/account-copy/${c.id}/head`, { token: c.token })).status, 404);
  // Deleting the copy deletes its ways in.
  assert.equal((await call('POST', `/account-slot/${c.slot.body.slotId}/read`, { token: c.slot.token })).status, 404);
});

test('a new copy needs a way in, and a way in opens one copy only', async () => {
  const c = newCopy();
  const none = await call('PUT', `/account-copy/${c.id}`, { token: c.token, prev: 'none', iv: c.iv, ct: c.ct });
  assert.equal(none.status, 400);
  assert.match(none.json.error, /first way in/);
  assert.equal((await make(c)).status, 200);
  const other = { ...newCopy(), slot: c.slot };
  assert.equal((await make(other)).status, 409);
  // A first save that names a previous copy (one the registry dropped) is refused, not made.
  const d = newCopy();
  assert.equal(
    (await call('PUT', `/account-copy/${d.id}`, { token: d.token, prev: '0'.repeat(64), iv: d.iv, ct: d.ct, slot: d.slot.body })).status,
    409,
  );
});

test('two devices: a save over a newer copy is refused, never silently kept', async () => {
  const c = newCopy();
  await make(c);
  const a = { iv: b64(12), ct: b64(310) };
  assert.equal((await call('PUT', `/account-copy/${c.id}`, { token: c.token, prev: copyFingerprint(c.iv, c.ct), ...a })).status, 200);
  // Device B still names the first copy.
  const b = { iv: b64(12), ct: b64(320) };
  assert.equal((await call('PUT', `/account-copy/${c.id}`, { token: c.token, prev: copyFingerprint(c.iv, c.ct), ...b })).status, 409);
  assert.equal((await call('POST', `/account-copy/${c.id}/read`, { token: c.token })).json.ct, a.ct);
});

test('S3: a way in’s token reads that way in, and can’t read, save, delete or change the copy', async () => {
  const c = newCopy();
  await make(c);
  const t = c.slot.token;
  assert.equal((await call('POST', `/account-copy/${c.id}/read`, { token: t })).status, 403);
  assert.equal((await call('POST', `/account-copy/${c.id}/head`, { token: t })).status, 403);
  assert.equal((await call('POST', `/account-copy/${c.id}/delete`, { token: t })).status, 403);
  assert.equal(
    (await call('PUT', `/account-copy/${c.id}`, { token: t, prev: copyFingerprint(c.iv, c.ct), iv: b64(12), ct: b64(100) })).status,
    403,
  );
  const s = newSlot();
  assert.equal((await call('PUT', `/account-copy/${c.id}/slots/${s.body.slotId}`, { token: t, ...s.body })).status, 403);
  assert.equal((await call('POST', `/account-copy/${c.id}/slots/${c.slot.body.slotId}/delete`, { token: t })).status, 403);
  // And the copy's token doesn't read a way in.
  assert.equal((await call('POST', `/account-slot/${c.slot.body.slotId}/read`, { token: c.token })).status, 403);
  assert.equal((await call('POST', `/account-copy/${c.id}/read`, { token: c.token })).status, 200);
});

test('ways in are added and removed with the copy’s token, never the last one', async () => {
  const c = newCopy();
  await make(c);
  const s = newSlot('recovery');
  const add = await call('PUT', `/account-copy/${c.id}/slots/${s.body.slotId}`, { token: c.token, ...s.body });
  assert.equal(add.status, 200);
  assert.equal((await call('PUT', `/account-copy/${c.id}/slots/${s.body.slotId}`, { token: c.token, ...s.body })).status, 409);
  const odd = newSlot('wizard');
  assert.equal((await call('PUT', `/account-copy/${c.id}/slots/${odd.body.slotId}`, { token: c.token, ...odd.body })).status, 400);
  assert.deepEqual(
    (await call('POST', `/account-copy/${c.id}/head`, { token: c.token })).json.slots.map((x) => x.kind).sort(),
    ['passkey', 'recovery'],
  );
  assert.equal((await call('POST', `/account-copy/${c.id}/slots/${c.slot.body.slotId}/delete`, { token: c.token })).status, 200);
  const last = await call('POST', `/account-copy/${c.id}/slots/${s.body.slotId}/delete`, { token: c.token });
  assert.equal(last.status, 409);
  assert.equal((await call('POST', `/account-slot/${s.body.slotId}/read`, { token: s.token })).status, 200);
});

test('nothing in a URL: a token in a query string is not a token', async () => {
  const c = newCopy();
  await make(c);
  assert.equal((await call('POST', `/account-copy/${c.id}/read?token=${c.token}`, {})).status, 403);
});

test('S9: saves are limited per copy, new copies per address', () => {
  const db = new Database(':memory:');
  const copies = createAccountCopies(db, { limits: { perCopyWritesDaily: 3, perClientNewDaily: 2 } });
  const c = newCopy();
  let prev = 'none';
  let box = { iv: c.iv, ct: c.ct };
  for (let i = 0; i < 3; i++) {
    const out = copies.put(c.id, { token: c.token, prev, ...box, slot: c.slot.body }, '203.0.113.9');
    assert.equal(out.saved, true, JSON.stringify(out));
    prev = out.fingerprint;
    box = { iv: b64(12), ct: b64(100) };
  }
  assert.equal(copies.put(c.id, { token: c.token, prev, ...box }, '203.0.113.9').code, 429);
  // Another copy from the same address still saves: the cap is the copy's, not the address's.
  const d = newCopy();
  assert.equal(copies.put(d.id, { token: d.token, prev: 'none', iv: d.iv, ct: d.ct, slot: d.slot.body }, '203.0.113.9').saved, true);
  const e = newCopy();
  assert.equal(copies.put(e.id, { token: e.token, prev: 'none', iv: e.iv, ct: e.ct, slot: e.slot.body }, '203.0.113.9').code, 429);
});

test('too large a copy is refused with 413; a slot’s sealed key is small', () => {
  const db = new Database(':memory:');
  const copies = createAccountCopies(db, { limits: { maxCt: 1000 } });
  const c = newCopy();
  assert.equal(copies.put(c.id, { token: c.token, prev: 'none', iv: c.iv, ct: 'A'.repeat(1001), slot: c.slot.body }).code, 413);
  const big = { ...c.slot.body, ct: 'A'.repeat(600) };
  assert.match(copies.put(c.id, { token: c.token, prev: 'none', iv: c.iv, ct: c.ct, slot: big }).error, /first way in/);
});

test('the registry stores hashes of tokens, never the tokens', () => {
  const db = new Database(':memory:');
  const copies = createAccountCopies(db);
  const c = newCopy();
  copies.put(c.id, { token: c.token, prev: 'none', iv: c.iv, ct: c.ct, slot: c.slot.body });
  const dump = JSON.stringify([db.prepare('SELECT * FROM account_copies').all(), db.prepare('SELECT * FROM account_slots').all()]);
  assert.ok(!dump.includes(c.token));
  assert.ok(!dump.includes(c.slot.token));
});
