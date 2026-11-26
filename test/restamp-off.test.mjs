// With VEILCORE_RESTAMP unset, deploying the re-stamp changes nothing: no table is made, no
// calendar is asked, and every re-stamp route says it is off, the operator's too.
//
// SPDX-License-Identifier: Apache-2.0

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { untilReady } from './helpers.mjs';

process.env.DB_PATH = ':memory:';
process.env.VEILCORE_OPERATOR_TOKEN = 'test-operator-token-at-least-32-chars';
delete process.env.VEILCORE_RESTAMP;
process.env.VEILCORE_OTS = 'off';

const require = createRequire(import.meta.url);
const { app, db } = require('../server.js');
let base, server;
before(async () => {
  server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  base = `http://127.0.0.1:${server.address().port}`;
  await untilReady(base);
});
after(() => server.close());

test('off by default: no re-stamp table, and every route answers 404 saying it is off', async () => {
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM sqlite_master WHERE name LIKE 'restamp%'").get().n, 0);
  const op = { 'x-operator-token': process.env.VEILCORE_OPERATOR_TOKEN };
  for (const [method, path, headers] of [['POST', '/restamps', op], ['GET', '/restamps'], ['GET', '/restamps/RS-20261125-ABCD/manifest.json'], ['GET', '/restamps/RS-20261125-ABCD/root.bin.ots']]) {
    const res = await fetch(`${base}${path}`, { method, headers });
    assert.equal(res.status, 404, `${method} ${path}`);
    assert.match((await res.json()).error, /re-stamps are off on this registry/);
  }
});
