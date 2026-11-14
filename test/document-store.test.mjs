// A document record stored and checked: a sealed document record is accepted (its profile is
// known), the check page (/verify) says it is a document, and nothing about its files, title,
// issuer or the records it is about is ever in the public answer. The registry can't read a
// sealed record's fields, so the holder's browser checks their form (integrityCheckedBy:
// holder); where the registry does see them, recomputing refuses a malformed one
// (document-profile.test.mjs). Test data only.
// SPDX-License-Identifier: Apache-2.0

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { newNonce } from 'veilcore-records';
import { recomputeCommitment } from '../lineage/conformance.mjs';
import { untilReady, testBody, grantForTest } from './helpers.mjs';

process.env.DB_PATH = ':memory:';
process.env.VEILCORE_OTS = 'off';
process.env.VEILCORE_OPERATOR_TOKEN = 'op-secret-token-at-least-32-characters';
const require = createRequire(import.meta.url);
const { app } = require('../server.js');

const V = JSON.parse(readFileSync(new URL('./fixtures/document-v1.json', import.meta.url), 'utf8'));

let base, server;
before(async () => {
  server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  base = `http://127.0.0.1:${server.address().port}`;
  await untilReady(base);
});
after(() => server.close());

const key = () => randomBytes(32).toString('hex');
const call = async (method, path, holder, body) => {
  const res = await fetch(`${base}${path}`, {
    method,
    headers: { 'content-type': 'application/json', 'x-forwarded-for': `10.${randomBytes(3).join('.')}`, ...(holder ? { 'x-holder-key': holder } : {}) },
    ...(body === undefined ? {} : { body: JSON.stringify(testBody(method, path, holder, body)) }),
  });
  const text = await res.text();
  let json; try { json = JSON.parse(text); } catch { json = text; }
  return { status: res.status, json };
};

/** A fresh document record in the site's stored shape, sealed under the profile. */
const doc = async (i, over = {}) => {
  const r = {
    ...structuredClone(V.records[i].appRecord),
    id: `VEIL-${randomBytes(16).toString('hex').toUpperCase()}`,
    nonce: newNonce(),
    licenseIds: [],
    ...over,
  };
  delete r.keyBinding;
  r.recordFingerprint = await recomputeCommitment(r);
  return r;
};

test('a document record is stored, and /verify says it is a document and nothing more', async () => {
  const holder = key();
  const rec = await doc(0);
  const put = await call('PUT', '/api/records', holder, [rec]);
  assert.equal(put.json.count, 1, JSON.stringify(put.json));
  const v = (await call('GET', `/verify/${rec.id}`)).json;
  assert.equal(v.subjectKind, 'document');
  const text = JSON.stringify(v);
  for (const f of rec.document.files) {
    assert.ok(!text.includes(f.sha256), 'a file fingerprint');
    assert.ok(!text.includes(f.name), 'a file name');
  }
  for (const s of [rec.strainName, rec.document.issuer, rec.refId, rec.document.about[0].name]) assert.ok(!text.includes(s), s);
});
