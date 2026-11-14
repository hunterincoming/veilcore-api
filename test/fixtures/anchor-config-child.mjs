// Child process for mainnet-readiness.test.mjs: the server under whatever VEILCORE_ANCHOR_*
// the parent passes. Seals one batch, tries to anchor it, and prints what /.well-known and
// the anchor route answered.
// SPDX-License-Identifier: Apache-2.0
import { createRequire } from 'node:module';
import { canonicalise, sha256Hex, newNonce } from 'veilcore-records';
import { untilReady, sealForTest, vaultKeyFor } from '../helpers.mjs';

process.env.DB_PATH = ':memory:';
process.env.VEILCORE_OPERATOR_TOKEN = 'child-operator-token-at-least-32-chars';
process.env.VEILCORE_OTS = 'off';
const require = createRequire(import.meta.url);
const { app } = require('../../server.js');
const server = app.listen(0);
await new Promise((r) => server.once('listening', r));
const base = `http://127.0.0.1:${server.address().port}`;
await untilReady(base);
const committed = { breedingMethod: '', bredBy: 'B', dateCreated: '2026-01-01', loggedAt: 1759600000000, nonce: newNonce(), notes: '', parents: [], photoFingerprints: [], refId: '', strainName: 'S' };
const r = { id: 'child-1', ...committed, recordFingerprint: await sha256Hex(canonicalise(committed)) };
await fetch(`${base}/api/records`, { method: 'PUT', headers: { 'content-type': 'application/json', 'x-holder-key': 'cd'.repeat(32) }, body: JSON.stringify([sealForTest(r, vaultKeyFor('cd'.repeat(32)))]) });
const sealed = await (await fetch(`${base}/batches/seal`, { method: 'POST', headers: { 'x-operator-token': 'child-operator-token-at-least-32-chars' } })).json();
const anchor = await fetch(`${base}/batches/${sealed.batchId}/anchor`, {
  method: 'POST',
  headers: { 'content-type': 'application/json', 'x-operator-token': 'child-operator-token-at-least-32-chars' },
  body: JSON.stringify(JSON.parse(process.env.CHILD_ANCHOR_BODY)),
});
const wellKnown = await (await fetch(`${base}/.well-known/veilcore-registry`)).json();
console.log(JSON.stringify({ anchorStatus: anchor.status, anchor: await anchor.json(), anchors: wellKnown.anchors }));
server.close();
process.exit(0);
