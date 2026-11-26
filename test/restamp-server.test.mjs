// The evidence re-stamp through the registry's routes, with VEILCORE_RESTAMP=manual: the
// operator makes one, anyone lists it, downloads its manifest, root and .ots, and checks one
// item with its proof. Calendars are never contacted: fetch answers for them. That the
// registry changes nothing with the setting unset is restamp-off.test.mjs.
//
// SPDX-License-Identifier: Apache-2.0

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { createHash } from 'node:crypto';
import { untilReady } from './helpers.mjs';

process.env.DB_PATH = ':memory:';
process.env.VEILCORE_OPERATOR_TOKEN = 'test-operator-token-at-least-32-chars';
process.env.VEILCORE_RESTAMP = 'manual';
process.env.VEILCORE_OTS = 'on'; // npm test sets off; a re-stamp is its stamp

const sha = (b) => createHash('sha256').update(b).digest();
const vu = (n) => { const o = []; do { let b = n & 0x7f; n >>>= 7; if (n) b |= 0x80; o.push(b); } while (n); return Buffer.from(o); };
const pendingAnswer = (uri) => {
  const u = Buffer.from(uri);
  const payload = Buffer.concat([vu(u.length), u]);
  return Buffer.concat([Buffer.from([0x08, 0x00]), Buffer.from('83dfe30d2ef90c8e', 'hex'), vu(payload.length), payload]);
};
// Calendars answer; this registry itself is reached as usual; nothing else is.
const realFetch = globalThis.fetch;
const calendarsAsked = [];
globalThis.fetch = async (url, init) => {
  const u = new URL(String(url));
  if (u.hostname === '127.0.0.1') return realFetch(url, init);
  if (u.pathname === '/digest') {
    calendarsAsked.push(u.origin);
    const named = { 'a.pool.opentimestamps.org': 'alice.btc.calendar.opentimestamps.org', 'b.pool.opentimestamps.org': 'bob.btc.calendar.opentimestamps.org' }[u.hostname] ?? u.hostname;
    return new Response(pendingAnswer(`https://${named}`));
  }
  throw new Error(`unexpected request to ${u.origin}`);
};

const require = createRequire(import.meta.url);
const { app, db } = require('../server.js');
const OP = { 'x-operator-token': process.env.VEILCORE_OPERATOR_TOKEN };
let base, server;
before(async () => {
  server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  base = `http://127.0.0.1:${server.address().port}`;
  await untilReady(base);
});
after(() => { server.close(); globalThis.fetch = realFetch; });

test('manual: the operator makes a re-stamp; anyone rebuilds its root and checks one item, from what is published', async () => {
  const { entryFor, itemBytes, checkRestampItem, checkManifest } = await import('../lineage/restamp.mjs');
  assert.equal((await fetch(`${base}/restamps`, { method: 'POST' })).status, 401, 'operator only');
  assert.equal((await fetch(`${base}/restamps`)).status, 200);
  assert.deepEqual((await (await fetch(`${base}/restamps`)).json()).restamps, []);
  assert.equal((await fetch(`${base}/restamps`, { method: 'POST', headers: OP })).status, 409, 'nothing to re-stamp yet');

  // A sealed batch, in the registry's own table.
  const root = sha('a batch').toString('hex');
  db.prepare('INSERT INTO batches (batch_id, root, sealed_at, record_count) VALUES (?, ?, ?, ?)').run('B-20261125-0001', root, Date.now(), 1);

  const made = await fetch(`${base}/restamps`, { method: 'POST', headers: OP });
  assert.equal(made.status, 200);
  const r = await made.json();
  assert.equal(r.status, 'pending');
  assert.deepEqual(r.counts, { 'batch-root': 1, attestation: 0, withdrawal: 0, enrolment: 0, rfc3161: 0 });
  assert.ok(calendarsAsked.length >= 1);
  assert.equal((await fetch(`${base}/restamps`, { method: 'POST', headers: OP })).status, 409, 'nothing new since');

  const listed = (await (await fetch(`${base}/restamps`)).json()).restamps;
  assert.equal(listed.length, 1);
  const manifest = await (await fetch(`${base}${listed[0].manifest}`)).json();
  assert.deepEqual(await checkManifest(manifest), { ok: true, root: r.root });
  assert.deepEqual(Buffer.from(await (await fetch(`${base}${listed[0].rootBin}`)).arrayBuffer()), Buffer.from(r.root, 'hex'));
  const ots = await fetch(`${base}${listed[0].ots}`);
  assert.equal(ots.status, 200);
  assert.equal(ots.headers.get('x-opentimestamps-status'), 'pending');

  const entry = entryFor('batch-root', itemBytes('batch-root', root));
  const proof = await (await fetch(`${base}/restamps/${r.restampId}/proof/${entry}`)).json();
  assert.deepEqual(await checkRestampItem({ kind: 'batch-root', bytes: itemBytes('batch-root', root), proof, root: r.root }), { ok: true, entry, root: r.root });
  assert.equal((await fetch(`${base}/restamps/${r.restampId}/proof/${'00'.repeat(32)}`)).status, 404);
  assert.equal((await fetch(`${base}/restamps/not-an-id/manifest.json`)).status, 404);
});
