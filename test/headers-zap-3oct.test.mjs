// Security headers, after an OWASP ZAP active scan of a local copy (3 October 2026).
// ZAP reported directives with no default-src fallback missing from the JSON routes'
// CSP, and no CSP at all on the embed fragment. The embed stays frameable by design.
//
// SPDX-License-Identifier: Apache-2.0

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

process.env.DB_PATH = ':memory:';
process.env.VEILCORE_OPERATOR_TOKEN = 'test-operator-token-at-least-32-chars';
const require = createRequire(import.meta.url);
const { app } = require('../server.js');

let base;
let server;
before(async () => {
  server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  base = `http://127.0.0.1:${server.address().port}`;
});
after(() => server.close());

test('JSON routes: nothing loads, nothing frames, no form posts, no base change', async () => {
  for (const path of ['/health', '/batches', '/.well-known/veilcore-registry', '/no-such-route']) {
    const r = await fetch(`${base}${path}`);
    const csp = r.headers.get('content-security-policy');
    assert.equal(csp, "default-src 'none'; frame-ancestors 'none'; form-action 'none'; base-uri 'none'", path);
    assert.equal(r.headers.get('x-frame-options'), 'DENY', path);
  }
});

test('the embed fragment has a CSP but stays frameable', async () => {
  const r = await fetch(`${base}/embed/no-such-record`);
  const csp = r.headers.get('content-security-policy');
  assert.equal(csp, "default-src 'none'; form-action 'none'; base-uri 'none'; frame-ancestors *");
  assert.equal(r.headers.get('x-frame-options'), null);
});

test('embed.js is a script for other sites and carries no page CSP', async () => {
  const r = await fetch(`${base}/embed.js`);
  assert.equal(r.headers.get('content-security-policy'), null);
});
