// The deal channel (lineage/deals.mjs): opened by both sides with one id and token hash,
// written and read only with the token, each message dated in the next batch.
//
// SPDX-License-Identifier: Apache-2.0

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { randomBytes } from 'node:crypto';
import Database from 'better-sqlite3';
import { createDeals, dealTokenHash, messageFingerprint } from '../lineage/deals.mjs';
import { commitHashOf, inviteTokenHash } from '../lineage/license-invites.mjs';
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
const newDeal = () => {
  const token = randomBytes(16).toString('base64url');
  return { dealId: randomBytes(16).toString('hex'), token, writeTokenHash: dealTokenHash(token) };
};
const hex = () => randomBytes(32).toString('hex');
/** A license invite taken as far as the reveal: what opening a deal needs. */
const revealedInvite = async () => {
  const accept = randomBytes(16).toString('base64url');
  const issuer = randomBytes(16).toString('base64url');
  const inv = await call('POST', '/license-invites', {
    identity: hex(), label: 'x', acceptTokenHash: inviteTokenHash(accept), issuerTokenHash: inviteTokenHash(issuer),
  });
  const id = inv.json.id;
  const c = { commitment: hex(), issuerRecord: hex(), licenseeNonce: hex() };
  await call('POST', `/license-invites/${id}/accept`, { commitHash: commitHashOf(c.commitment, c.issuerRecord, c.licenseeNonce), token: accept });
  await call('POST', `/license-invites/${id}/nonce`, { issuerNonce: hex(), token: issuer });
  await call('POST', `/license-invites/${id}/reveal`, { ...c, token: accept });
  return { id, accept, issuer };
};
/** Open a deal the way the site does: with its license's invite. */
const opened = async (d = newDeal()) => {
  const inv = await revealedInvite();
  const r = await call('POST', '/deals', { dealId: d.dealId, writeTokenHash: d.writeTokenHash, inviteId: inv.id, token: inv.issuer });
  return { ...d, inv, status: r.status, json: r.json };
};
const msg = () => ({ iv: randomBytes(12).toString('base64url'), ct: randomBytes(200).toString('base64url') });

test('a deal is opened only with a revealed license invite, once per invite; both sides can open it again', async () => {
  const d = newDeal();
  // No invite, or a stranger's token: refused.
  assert.equal((await call('POST', '/deals', { dealId: d.dealId, writeTokenHash: d.writeTokenHash })).status, 403);
  const inv = await revealedInvite();
  const body = { dealId: d.dealId, writeTokenHash: d.writeTokenHash, inviteId: inv.id };
  assert.equal((await call('POST', '/deals', { ...body, token: randomBytes(16).toString('base64url') })).status, 403);
  assert.equal((await call('POST', '/deals', { ...body, token: inv.issuer })).json.opened, true);
  // The other side, or a new device: the same deal, no invite needed.
  assert.equal((await call('POST', '/deals', { dealId: d.dealId, writeTokenHash: d.writeTokenHash })).json.opened, false);
  assert.equal((await call('POST', '/deals', { dealId: d.dealId, writeTokenHash: newDeal().writeTokenHash })).status, 409);
  // One invite, one deal; and the licensee's link can't open one (only the issuer opens it).
  const e = newDeal();
  assert.equal((await call('POST', '/deals', { dealId: e.dealId, writeTokenHash: e.writeTokenHash, inviteId: inv.id, token: inv.issuer })).status, 409);
  const other = await revealedInvite();
  assert.equal((await call('POST', '/deals', { dealId: e.dealId, writeTokenHash: e.writeTokenHash, inviteId: other.id, token: other.accept })).status, 403);
});

test('messages are written and read only with the token, in order, the same message once', async () => {
  const d = await opened();
  const m1 = msg(), m2 = msg();
  assert.equal((await call('POST', `/deals/${d.dealId}/messages`, { ...m1, token: newDeal().token })).status, 403);
  const a = await call('POST', `/deals/${d.dealId}/messages`, { ...m1, token: d.token });
  assert.equal(a.status, 200);
  assert.equal(a.json.seq, 1);
  assert.equal(a.json.fingerprint, messageFingerprint(m1.iv, m1.ct));
  assert.equal((await call('POST', `/deals/${d.dealId}/messages`, { ...m1, token: d.token })).json.duplicate, true);
  assert.equal((await call('POST', `/deals/${d.dealId}/messages`, { ...m2, token: d.token })).json.seq, 2);
  assert.equal((await call('POST', `/deals/${d.dealId}/read`, { token: newDeal().token })).status, 403);
  const all = (await call('POST', `/deals/${d.dealId}/read`, { token: d.token })).json.messages;
  assert.deepEqual(all.map((m) => m.ct), [m1.ct, m2.ct]);
  const later = (await call('POST', `/deals/${d.dealId}/read`, { token: d.token, after: 1 })).json.messages;
  assert.deepEqual(later.map((m) => m.seq), [2]);
  // A message from one deal can't be posted into another.
  const e = await opened();
  assert.equal((await call('POST', `/deals/${e.dealId}/messages`, { ...m1, token: e.token })).status, 409);
});

test('refuses bad input', async () => {
  assert.equal((await call('POST', '/deals', { dealId: 'xyz', writeTokenHash: newDeal().writeTokenHash })).status, 400);
  assert.equal((await call('POST', `/deals/${'0'.repeat(32)}/messages`, { ...msg(), token: newDeal().token })).status, 404);
  const d = await opened();
  assert.equal((await call('POST', `/deals/${d.dealId}/messages`, { iv: 'short', ct: msg().ct, token: d.token })).status, 400);
  assert.equal((await call('POST', `/deals/${d.dealId}/messages`, { iv: msg().iv, ct: 'A'.repeat(30_000), token: d.token })).status, 400);
});

test('limits: messages per deal, new deals per client per day, empty deals swept after a week', () => {
  let t = 1_000_000_000;
  const db = new Database(':memory:');
  const invites = { revealedFor: () => true };
  let n = 0;
  const open = (box, d, client) => box.open({ ...d, inviteId: `LI-${String(++n).padStart(32, '0')}`, token: 'x' }, client);
  const box = createDeals(db, { now: () => t, invites, limits: { maxMessages: 3, perClientDaily: 2 } });
  const d = newDeal();
  assert.ok(open(box, d, 'a').dealId);
  for (let i = 0; i < 3; i++) assert.ok(box.post(d.dealId, { ...msg(), token: d.token }).seq);
  assert.equal(box.post(d.dealId, { ...msg(), token: d.token }).code, 409);
  const e = newDeal();
  assert.ok(open(box, e, 'b').dealId);
  const empty = newDeal();
  assert.ok(open(box, empty, 'b').dealId);
  assert.equal(open(box, newDeal(), 'b').code, 429);
  for (let i = 0; i < 2; i++) assert.ok(box.post(e.dealId, { ...msg(), token: e.token }).seq);
  // A week on, the deal nobody wrote to is gone; the others stay.
  t += 8 * 86_400_000;
  open(box, newDeal(), 'c');
  assert.equal(box.post(empty.dealId, { ...msg(), token: empty.token }).code, 404);
  assert.equal(box.list(d.dealId, d.token).messages.length, 3);
});

test('/health advertises deals-v1', async () => {
  assert.ok((await call('GET', '/health')).json.features.includes('deals-v1'));
});

test('one client can post only so many messages to one deal a day (attack pass 21 Oct, finding 7)', () => {
  let t = Date.UTC(2026, 9, 21, 12);
  const db = new Database(':memory:');
  const invites = { revealedFor: () => true };
  const deals = createDeals(db, { now: () => t, invites, limits: { perClientPerDealDaily: 3 } });
  const d = newDeal();
  assert.equal(deals.open({ dealId: d.dealId, writeTokenHash: d.writeTokenHash, inviteId: 'LI-x', token: 'x' }).opened, true);
  const post = (client) =>
    deals.post(d.dealId, { token: d.token, iv: randomBytes(12).toString('base64url'), ct: randomBytes(40).toString('base64url') }, client);
  for (let i = 0; i < 3; i++) assert.ok(post('2001:db8:9:1::/64').seq);
  assert.equal(post('2001:db8:9:2::/64').code, 429); // same /48
  assert.ok(post('2001:db8:a:1::/64').seq); // another client
  t += 86_400_000;
  assert.ok(post('2001:db8:9:1::/64').seq);
});
