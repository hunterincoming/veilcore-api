// Child process for attack-ots.test.mjs: the server with a fast OpenTimestamps timer and
// every calendar down. Prints how many calendar requests were made after a seal: once
// there are WANT_CALLS of them (the timer is on), or after 700 ms of watching (it is off).
// SPDX-License-Identifier: Apache-2.0
import { createRequire } from 'node:module';
import { canonicalise, sha256Hex, newNonce } from 'veilcore-records';
import { untilReady, waitFor, sealForTest, vaultKeyFor } from '../helpers.mjs';

process.env.DB_PATH = ':memory:';
process.env.VEILCORE_OPERATOR_TOKEN = 'child-operator-token-at-least-32-chars';
process.env.VEILCORE_OTS_INTERVAL_MS = '100';
const realFetch = globalThis.fetch;
let calls = 0;
globalThis.fetch = async (url, init) => {
  if (String(url).startsWith('http://127.0.0.1')) return realFetch(url, init);
  calls++;
  throw new Error('down');
};
const require = createRequire(import.meta.url);
const { app } = require('../../server.js');
const server = app.listen(0);
await new Promise((r) => server.once('listening', r));
const base = `http://127.0.0.1:${server.address().port}`;
await untilReady(base, realFetch);
const r = { id: 'timer-1', strainName: 'S', bredBy: 'B', dateCreated: '2026-01-01', loggedAt: '2026-01-01T00:00:00Z', nonce: newNonce(), notes: '', parents: [], photoFingerprints: [], breedingMethod: '', refId: '' };
r.recordFingerprint = await sha256Hex(canonicalise({ breedingMethod: '', bredBy: 'B', dateCreated: r.dateCreated, loggedAt: r.loggedAt, nonce: r.nonce, notes: '', parents: [], photoFingerprints: [], refId: '', strainName: 'S' }));
await realFetch(`${base}/api/records`, { method: 'PUT', headers: { 'content-type': 'application/json', 'x-holder-key': 'cd'.repeat(32) }, body: JSON.stringify([sealForTest(r, vaultKeyFor('cd'.repeat(32)))]) });
await realFetch(`${base}/batches/seal`, { method: 'POST', headers: { 'x-operator-token': 'child-operator-token-at-least-32-chars' } });
// On, the retries are waited for however long a busy machine takes to run the timer (a
// fixed 700 ms was sometimes too short). Off, there is nothing to wait for: watch for a
// while, and any request at all is a failure.
if (process.env.WANT_CALLS) await waitFor(`${process.env.WANT_CALLS} calendar requests`, () => calls >= Number(process.env.WANT_CALLS));
else await new Promise((res) => setTimeout(res, 700));
console.log(JSON.stringify({ calls }));
server.close();
process.exit(0);
