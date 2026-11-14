// The license invite mailbox (lineage/license-invites.mjs): the issuer invites, the licensee
// accepts with a commitment, the issuer posts its issue, the licensee its activation. The
// registry only carries messages. No network beyond this process.
//
// SPDX-License-Identifier: Apache-2.0

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { randomBytes } from 'node:crypto';
import Database from 'better-sqlite3';
import { commitHashOf, createLicenseInvites, inviteTokenHash, wider } from '../lineage/license-invites.mjs';
import { untilReady } from './helpers.mjs';

process.env.DB_PATH = ':memory:';
process.env.VEILCORE_OTS = 'off';
const require = createRequire(import.meta.url);
const { app } = require('../server.js');
const hex = () => randomBytes(32).toString('hex');
const newToken = () => {
  const token = randomBytes(16).toString('base64url');
  return { token, hash: inviteTokenHash(token) };
};

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

const newInvite = async (label = 'Green Valley Farms') => {
  const accept = newToken(), issuer = newToken();
  const identity = hex();
  const r = await call('POST', '/license-invites', {
    identity, label, acceptTokenHash: accept.hash, issuerTokenHash: issuer.hash,
  });
  assert.equal(r.status, 200, JSON.stringify(r.json));
  return { id: r.json.id, identity, accept: accept.token, issuer: issuer.token };
};

/** The licensee's commitment, the head it names and its nonce, and their hash: what it commits to first. */
const committed = () => {
  const commitment = hex(), issuerRecord = hex(), licenseeNonce = hex();
  return { commitment, issuerRecord, licenseeNonce, commitHash: commitHashOf(commitment, issuerRecord, licenseeNonce) };
};
const post = (id, step, body) => call('POST', `/license-invites/${id}/${step}`, body);

test('issuer invites, licensee commits, issuer answers, licensee reveals, issue, activation: each side reads the other', async () => {
  const inv = await newInvite('  Green Valley Farms  ');
  assert.match(inv.id, /^LI-[0-9A-F]{32}$/);
  const first = await call('GET', `/license-invites/${inv.id}`);
  assert.equal(first.status, 200);
  assert.equal(first.json.label, 'Green Valley Farms');
  assert.equal(first.json.identity, inv.identity);
  assert.equal(first.json.commitment, null);
  for (const k of ['acceptTokenHash', 'issuerTokenHash', 'accept_token_hash', 'issuer_token_hash']) {
    assert.equal(k in first.json, false, `${k} is never handed back`);
  }
  const c = committed();
  const issuerNonce = hex(), issueTx = hex(), activateTx = hex();
  assert.equal((await post(inv.id, 'accept', { commitHash: c.commitHash, token: inv.accept })).status, 200);
  // Committed only: nothing of the commitment itself is there yet.
  assert.equal((await call('GET', `/license-invites/${inv.id}`)).json.commitment, null);
  assert.equal((await post(inv.id, 'nonce', { issuerNonce, token: inv.issuer })).status, 200);
  assert.equal((await post(inv.id, 'reveal', { ...c, token: inv.accept })).status, 200);
  assert.equal((await post(inv.id, 'issued', { txId: issueTx, token: inv.issuer })).status, 200);
  assert.equal((await post(inv.id, 'activated', { txId: activateTx, token: inv.accept })).status, 200);

  const done = (await call('GET', `/license-invites/${inv.id}`)).json;
  assert.equal(done.commitHash, c.commitHash);
  assert.equal(done.issuerNonce, issuerNonce);
  assert.equal(done.commitment, c.commitment);
  assert.equal(done.issuerRecord, c.issuerRecord);
  assert.equal(done.licenseeNonce, c.licenseeNonce);
  assert.equal(done.issueTx, issueTx);
  assert.equal(done.activateTx, activateTx);
});

test('knowing the id is not enough to write: each step needs its own token from the link', async () => {
  const inv = await newInvite();
  const c = committed();
  for (const token of [undefined, newToken().token, inv.issuer]) {
    assert.equal((await post(inv.id, 'accept', { commitHash: c.commitHash, token })).status, 403);
  }
  assert.equal((await post(inv.id, 'accept', { commitHash: c.commitHash, token: inv.accept })).status, 200);
  // The licensee's token cannot post the issuer's steps, nor the issuer's the licensee's.
  assert.equal((await post(inv.id, 'nonce', { issuerNonce: hex(), token: inv.accept })).status, 403);
  assert.equal((await post(inv.id, 'nonce', { issuerNonce: hex(), token: inv.issuer })).status, 200);
  assert.equal((await post(inv.id, 'reveal', { ...c, token: inv.issuer })).status, 403);
  assert.equal((await post(inv.id, 'issued', { txId: hex(), token: inv.accept })).status, 403);
});

test('a reveal must match what was committed to, and every step is taken once', async () => {
  const inv = await newInvite();
  const c = committed();
  assert.equal((await post(inv.id, 'accept', { commitHash: c.commitHash, token: inv.accept })).status, 200);
  assert.equal((await post(inv.id, 'accept', { commitHash: c.commitHash, token: inv.accept })).status, 200);
  assert.equal((await post(inv.id, 'accept', { commitHash: hex(), token: inv.accept })).status, 409);
  const n = hex();
  assert.equal((await post(inv.id, 'nonce', { issuerNonce: n, token: inv.issuer })).status, 200);
  assert.equal((await post(inv.id, 'nonce', { issuerNonce: hex(), token: inv.issuer })).status, 409);
  // Any other commitment, head or nonce than the one committed to is refused.
  for (const k of ['commitment', 'issuerRecord', 'licenseeNonce']) {
    assert.equal((await post(inv.id, 'reveal', { ...c, [k]: hex(), token: inv.accept })).status, 409, k);
  }
  assert.equal((await post(inv.id, 'reveal', { ...c, token: inv.accept })).status, 200);
  const tx = hex();
  assert.equal((await post(inv.id, 'issued', { txId: tx, token: inv.issuer })).status, 200);
  assert.equal((await post(inv.id, 'issued', { txId: hex(), token: inv.issuer })).status, 409);
  assert.equal((await post(inv.id, 'activated', { txId: hex(), token: inv.accept })).status, 200);
  assert.equal((await post(inv.id, 'activated', { txId: hex(), token: inv.accept })).status, 409);
});

test('steps come in order: no answer before a commit, no reveal before the answer, no issue before the reveal', async () => {
  const inv = await newInvite();
  const c = committed();
  assert.equal((await post(inv.id, 'nonce', { issuerNonce: hex(), token: inv.issuer })).status, 409);
  assert.equal((await post(inv.id, 'accept', { commitHash: c.commitHash, token: inv.accept })).status, 200);
  assert.equal((await post(inv.id, 'reveal', { ...c, token: inv.accept })).status, 409);
  assert.equal((await post(inv.id, 'issued', { txId: hex(), token: inv.issuer })).status, 409);
  assert.equal((await post(inv.id, 'activated', { txId: hex(), token: inv.accept })).status, 409);
});

test('refuses bad input: ids, hex, equal tokens, a label that is too long or not text', async () => {
  const t = newToken();
  const bad = async (body) => (await call('POST', '/license-invites', body)).status;
  assert.equal(await bad({ identity: 'xyz', acceptTokenHash: t.hash, issuerTokenHash: newToken().hash }), 400);
  assert.equal(await bad({ identity: hex(), acceptTokenHash: t.hash, issuerTokenHash: t.hash }), 400);
  assert.equal(await bad({ identity: hex(), label: 'x'.repeat(81), acceptTokenHash: t.hash, issuerTokenHash: newToken().hash }), 400);
  assert.equal(await bad({ identity: hex(), label: { a: 1 }, acceptTokenHash: t.hash, issuerTokenHash: newToken().hash }), 400);
  assert.equal((await call('GET', '/license-invites/LI-NOPE')).status, 404);
  assert.equal((await call('GET', `/license-invites/LI-${'0'.repeat(32)}`)).status, 404);
  const inv = await newInvite();
  assert.equal((await call('POST', `/license-invites/${inv.id}/accept`, { commitment: 'zz', issuerRecord: hex(), token: inv.accept })).status, 400);
});

test('a label keeps only text: direction marks and invisible characters are removed', async () => {
  const inv = await newInvite('Green‮ Valley⁠ Farms');
  assert.equal((await call('GET', `/license-invites/${inv.id}`)).json.label, 'Green Valley Farms');
});

test('invites expire after 30 days, and one address may make 50 a day', () => {
  let t = 1_000_000;
  const db = new Database(':memory:');
  const box = createLicenseInvites(db, { now: () => t });
  const body = () => ({ identity: hex(), acceptTokenHash: newToken().hash, issuerTokenHash: newToken().hash });
  const { id } = box.invite(body(), 'a');
  assert.ok(box.get(id));
  t += 30 * 86_400_000 + 1;
  assert.equal(box.get(id), null);
  for (let i = 0; i < 50; i++) assert.ok(box.invite(body(), 'b').id);
  assert.equal(box.invite(body(), 'b').code, 429);
  assert.ok(box.invite(body(), 'c').id, 'another address is not affected');
});

test('/health advertises license-invites-v1', async () => {
  const h = await call('GET', '/health');
  assert.ok(h.json.features.includes('license-invites-v1'));
});

test('an IPv6 client is counted by its /48; a stranger can make only a few invites for one record, never lock it', () => {
  assert.equal(wider('2001:db8:1:2::/64'), '2001:db8:1::/48');
  assert.equal(wider('203.0.113.9'), '203.0.113.9');
  const db = new Database(':memory:');
  const box = createLicenseInvites(db);
  const body = (identity = hex()) => ({ identity, acceptTokenHash: newToken().hash, issuerTokenHash: newToken().hash });
  for (let i = 0; i < 50; i++) assert.ok(box.invite(body(), `2001:db8:7:${i.toString(16)}::/64`).id);
  assert.equal(box.invite(body(), '2001:db8:7:ffff::/64').code, 429);
  // Ten a day for one record from one address; the record's owner, elsewhere, is never refused.
  const record = hex();
  for (let i = 0; i < 10; i++) assert.ok(box.invite(body(record), '198.51.100.1').id);
  assert.equal(box.invite(body(record), '198.51.100.1').code, 429);
  for (let i = 0; i < 10; i++) assert.ok(box.invite(body(record), `198.51.100.${i + 2}`).id);
  assert.ok(box.invite(body(record), '192.0.2.77').id, 'the owner can still invite');
});
