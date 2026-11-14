// Startup checks (deep dive, 8 Oct 2026): a short operator token does not enable the
// operator routes, and a database that will not survive a redeploy is warned about.
// No network.
//
// SPDX-License-Identifier: Apache-2.0

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { untilReady } from './helpers.mjs';

const SHORT = 'short-but-set-token';
process.env.DB_PATH = ':memory:';
process.env.VEILCORE_OTS = 'off';
process.env.VEILCORE_OPERATOR_TOKEN = SHORT;

// Everything the server logs while it starts, to check the token itself is never printed.
const logged = [];
const realError = console.error, realWarn = console.warn, realLog = console.log;
console.error = (...a) => { logged.push(a.join(' ')); };
console.warn = (...a) => { logged.push(a.join(' ')); };
console.log = (...a) => { logged.push(a.join(' ')); };
const require = createRequire(import.meta.url);
const { app } = require('../server.js');
const { operatorToken, persistenceWarning, OPERATOR_TOKEN_MIN } = require('../startup-checks.js');

let base, server;
before(async () => {
  server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  base = `http://127.0.0.1:${server.address().port}`;
  await untilReady(base);
  console.error = realError; console.warn = realWarn; console.log = realLog;
});
after(() => server.close());

test('LOW: an operator token shorter than 32 characters enables nothing, and is never printed', async () => {
  const r = await fetch(`${base}/batches/seal`, { method: 'POST', headers: { 'x-operator-token': SHORT } });
  assert.equal(r.status, 503, 'the short token is refused as if unset');
  assert.match((await r.json()).error, /at least 32 characters/);
  assert.ok(logged.some((l) => /VEILCORE_OPERATOR_TOKEN/.test(l) && /32/.test(l)), 'the reason is logged');
  assert.ok(!logged.some((l) => l.includes(SHORT)), 'the token itself is not');
});

test('LOW: operatorToken() accepts 32 characters or more, and nothing shorter', () => {
  const quiet = () => {};
  assert.equal(OPERATOR_TOKEN_MIN, 32);
  assert.equal(operatorToken({}, quiet), null);
  assert.equal(operatorToken({ VEILCORE_OPERATOR_TOKEN: '' }, quiet), null);
  assert.equal(operatorToken({ VEILCORE_OPERATOR_TOKEN: 'a'.repeat(31) }, quiet), null);
  assert.equal(operatorToken({ VEILCORE_OPERATOR_TOKEN: `  ${'a'.repeat(31)}  ` }, quiet), null, 'padding does not count');
  assert.equal(operatorToken({ VEILCORE_OPERATOR_TOKEN: 'a'.repeat(32) }, quiet), 'a'.repeat(32));
});

test('data: a database that a redeploy would wipe is warned about on Railway, and only there', () => {
  // Off Railway (a laptop, CI) nothing is said.
  assert.equal(persistenceWarning({}, 'veilcore.db'), null);
  assert.equal(persistenceWarning({ RAILWAY_ENVIRONMENT_NAME: 'production' }, ':memory:'), null);
  // On Railway with no volume: the default relative path is on the container's disk.
  assert.match(persistenceWarning({ RAILWAY_ENVIRONMENT_NAME: 'production' }, 'veilcore.db'), /lost on every redeploy/);
  // A volume, but the database is not on it.
  assert.match(persistenceWarning({ RAILWAY_ENVIRONMENT_NAME: 'production', RAILWAY_VOLUME_MOUNT_PATH: '/data' }, 'veilcore.db'), /not on the volume mounted at \/data/);
  assert.match(persistenceWarning({ RAILWAY_VOLUME_MOUNT_PATH: '/data' }, '/database/veilcore.db'), /not on the volume/);
  assert.match(persistenceWarning({ RAILWAY_VOLUME_MOUNT_PATH: '/data' }, '/data2/veilcore.db'), /not on the volume/, 'a sibling directory is not the volume');
  // On the volume: nothing to say.
  assert.equal(persistenceWarning({ RAILWAY_ENVIRONMENT_NAME: 'production', RAILWAY_VOLUME_MOUNT_PATH: '/data' }, '/data/veilcore.db'), null);
  assert.equal(persistenceWarning({ RAILWAY_VOLUME_MOUNT_PATH: '/data/' }, '/data/sub/veilcore.db'), null);
});
