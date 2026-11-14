// Passkey copies of backups (lineage/passkey-vault.mjs): saved, read and deleted only with the
// token the passkey makes; the registry holds ciphertext and nothing that names anyone.
//
// SPDX-License-Identifier: Apache-2.0

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { randomBytes } from 'node:crypto';
import Database from 'better-sqlite3';
import { boxFingerprint, createPasskeyVault } from '../lineage/passkey-vault.mjs';
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
  return { status: res.status, json: await res.json() };
};
const newCopy = () => ({
  id: randomBytes(16).toString('hex'),
  token: randomBytes(32).toString('base64url'),
  iv: randomBytes(12).toString('base64url'),
  ct: randomBytes(200).toString('base64url'),
});

test('a copy is saved, read back, replaced and deleted with its token', async () => {
  const c = newCopy();
  const put = await call('PUT', `/vault/${c.id}`, { token: c.token, prev: 'none', iv: c.iv, ct: c.ct });
  assert.equal(put.status, 200);
  const got = await call('POST', `/vault/${c.id}/read`, { token: c.token });
  assert.equal(got.status, 200);
  assert.equal(got.json.ct, c.ct);
  assert.equal(got.json.iv, c.iv);

  const next = { iv: randomBytes(12).toString('base64url'), ct: randomBytes(300).toString('base64url') };
  assert.equal((await call('PUT', `/vault/${c.id}`, { token: c.token, prev: boxFingerprint(c.iv, c.ct), ...next })).status, 200);
  assert.equal((await call('POST', `/vault/${c.id}/read`, { token: c.token })).json.ct, next.ct);

  assert.equal((await call('POST', `/vault/${c.id}/delete`, { token: c.token })).status, 200);
  assert.equal((await call('POST', `/vault/${c.id}/read`, { token: c.token })).status, 404);
});

test('without the token nobody reads, replaces or deletes a copy', async () => {
  const c = newCopy();
  await call('PUT', `/vault/${c.id}`, { token: c.token, prev: 'none', iv: c.iv, ct: c.ct });
  const other = randomBytes(32).toString('base64url');
  assert.equal((await call('POST', `/vault/${c.id}/read`, { token: other })).status, 403);
  assert.equal((await call('POST', `/vault/${c.id}/read`, {})).status, 403);
  assert.equal((await call('PUT', `/vault/${c.id}`, { token: other, prev: boxFingerprint(c.iv, c.ct), iv: c.iv, ct: 'A'.repeat(40) })).status, 403);
  assert.equal((await call('POST', `/vault/${c.id}/delete`, { token: other })).status, 403);
  assert.equal((await call('POST', `/vault/${c.id}/read`, { token: c.token })).json.ct, c.ct);
});

test('bad shapes are refused, and nothing is stored', async () => {
  const c = newCopy();
  assert.equal((await call('PUT', `/vault/NOT-HEX`, { token: c.token, prev: 'none', iv: c.iv, ct: c.ct })).status, 400);
  assert.equal((await call('PUT', `/vault/${c.id}`, { token: c.token, iv: c.iv, ct: c.ct })).status, 400);
  assert.equal((await call('PUT', `/vault/${c.id}`, { token: 'short', iv: c.iv, ct: c.ct })).status, 400);
  assert.equal((await call('PUT', `/vault/${c.id}`, { token: c.token, iv: 'x', ct: c.ct })).status, 400);
  assert.equal((await call('PUT', `/vault/${c.id}`, { token: c.token, iv: c.iv, ct: 'not base64!' })).status, 400);
  assert.equal((await call('POST', `/vault/${c.id}/read`, { token: c.token })).status, 404);
});

test('a copy up to about 2 MB is taken; a bigger one is refused', async () => {
  const c = newCopy();
  const big = 'A'.repeat(2_700_000);
  assert.equal((await call('PUT', `/vault/${c.id}`, { token: c.token, prev: 'none', iv: c.iv, ct: big })).status, 200);
  const tooBig = 'A'.repeat(2_800_001);
  assert.equal((await call('PUT', `/vault/${c.id}`, { token: c.token, prev: boxFingerprint(c.iv, big), iv: c.iv, ct: tooBig })).status, 413);
});

test('one client can start only so many copies a day', () => {
  let t = Date.UTC(2026, 9, 21, 12);
  const v = createPasskeyVault(new Database(':memory:'), { now: () => t, limits: { perClientNewDaily: 2 } });
  const put = () => {
    const c = newCopy();
    return v.put(c.id, { token: c.token, prev: 'none', iv: c.iv, ct: c.ct }, '2001:db8:1:5::/64');
  };
  assert.equal(put().saved, true);
  assert.equal(put().saved, true);
  // Another /64 in the same /48: the same client.
  const c = newCopy();
  assert.equal(v.put(c.id, { token: c.token, prev: 'none', iv: c.iv, ct: c.ct }, '2001:db8:1:ffff::/64').code, 429);
  t += 86_400_000;
  assert.equal(put().saved, true);
});

test('a save over a copy this device has not seen is refused (two devices, one passkey)', async () => {
  const c = newCopy();
  await call('PUT', `/vault/${c.id}`, { token: c.token, prev: 'none', iv: c.iv, ct: c.ct });
  const first = boxFingerprint(c.iv, c.ct);
  // Device A saves over the first copy.
  const a = { iv: randomBytes(12).toString('base64url'), ct: randomBytes(100).toString('base64url') };
  assert.equal((await call('PUT', `/vault/${c.id}`, { token: c.token, prev: first, ...a })).status, 200);
  // Device B, which last saw the first copy, can't overwrite A's.
  const b = { iv: randomBytes(12).toString('base64url'), ct: randomBytes(100).toString('base64url') };
  assert.equal((await call('PUT', `/vault/${c.id}`, { token: c.token, prev: first, ...b })).status, 409);
  // Nor can a first-save claim.
  assert.equal((await call('PUT', `/vault/${c.id}`, { token: c.token, prev: 'none', ...b })).status, 409);
  // Once it has read A's, it can.
  assert.equal((await call('PUT', `/vault/${c.id}`, { token: c.token, prev: boxFingerprint(a.iv, a.ct), ...b })).status, 200);
});
