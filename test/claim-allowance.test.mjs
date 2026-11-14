// Round 2 (8 Oct 2026, HIGH 1b): what a claim copies into the claimant's set counts against
// the daily write allowance of the address claiming, like any other write. No network.
//
// SPDX-License-Identifier: Apache-2.0

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { randomBytes } from 'node:crypto';
import { canonicalise, sha256Hex, newNonce } from 'veilcore-records';
import { inOneMinute, untilReady, testBody } from './helpers.mjs';

process.env.DB_PATH = ':memory:';
process.env.VEILCORE_OTS = 'off';
process.env.WRITE_BYTES_PER_DAY = String(4 * 1024);
const require = createRequire(import.meta.url);
const { app } = require('../server.js');
const key = () => randomBytes(32).toString('hex');

let base, server;
before(async () => {
  server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  base = `http://127.0.0.1:${server.address().port}`;
  await untilReady(base);
});
after(() => server.close());

// Each call from the address given: the sender's from fresh ones, so only the claimant's
// address spends its allowance (one proxy hop is trusted, as on Railway).
const call = async (method, path, holder, body, from = `10.${randomBytes(3).join('.')}`) => {
  const res = await fetch(`${base}${path}`, {
    method,
    headers: { 'content-type': 'application/json', 'x-holder-key': holder, 'x-forwarded-for': from },
    body: JSON.stringify(testBody(method, path, holder, body)),
  });
  return { status: res.status, json: await res.json() };
};

test('HIGH 1b: copied bytes are charged to the claiming address', async () => {
  // Since sealed records a claim writes only a stub (profile, where it came from; since
  // round 5 no name), so the copy is mostly the source's id: 128 characters, the most an id may
  // have, and its fingerprint. About 330 bytes a stub.
  const committed = { breedingMethod: '', bredBy: 'B', dateCreated: '2026-01-01', loggedAt: '2026-01-01T00:00:00Z', nonce: newNonce(),
    notes: '', parents: [], photoFingerprints: [], refId: '', strainName: 'S'.repeat(500) };
  const src = { id: `allow-src-${'x'.repeat(118)}`, ...committed, recordFingerprint: await sha256Hex(canonicalise(committed)) };
  const sender = key(), claimant = key();
  const lab = '10.200.0.1';
  let refused = null, claims = 0;
  // The allowance is per day: all of it on one day, even across midnight UTC (helpers.mjs).
  await inOneMinute(async () => {
    assert.equal((await call('PUT', '/api/records', sender, [src])).json.count, 1);
    for (let k = 0; k < 40 && !refused; k++) {
      const o = await call('POST', '/transfers', sender, { sourceRecord: src.id, toHandle: `h${k}@x` });
      assert.equal(o.status, 200, JSON.stringify(o.json));
      const c = await call('POST', `/transfers/${o.json.transferId}/claim`, claimant, { claimCode: o.json.claimCode }, lab);
      if (c.status === 200) claims++; else refused = c;
    }
  });
  assert.ok(refused, 'refused once the allowance is spent');
  assert.equal(refused.status, 429);
  assert.match(refused.json.error, /allowance/);
  // A claim's request is about 60 bytes, so without the copy charged ~68 would fit in 4 KB.
  assert.ok(claims >= 6 && claims <= 14, `about ten ~330-byte stubs fit in 4 KB (${claims})`);
});
