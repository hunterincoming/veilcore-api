// Records that name their own key (lineage/key-binding.mjs, the site's
// docs/identity-in-record.md, SPEC 3.6.1): the registry recomputes the new fingerprint
// form, keeps older records exactly as they were, stores and returns keyBinding, and
// tells a check page whether a record is bound without ever sending the binding.
// Vectors: fixtures/key-bound-v1.json, a copy of the site repo's
// contract/vectors/key-bound-v1.json, checked here by this registry's code and by an
// independent Python checker (fixtures/key_binding_reference.py).
// SPDX-License-Identifier: Apache-2.0

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { canonicalise, sha256Hex } from 'veilcore-records';
import { checkRecord, recomputeCommitment } from '../lineage/conformance.mjs';
import {
  identityFromSecret, keySaltOf, keyBindingOf, keyBoundFingerprint, keyMatchesRecord,
} from '../lineage/key-binding.mjs';
import { untilReady, testBody } from './helpers.mjs';

process.env.DB_PATH = ':memory:';
process.env.VEILCORE_OTS = 'off';
const require = createRequire(import.meta.url);
const { app } = require('../server.js');

const here = (p) => fileURLToPath(new URL(p, import.meta.url));
const V = JSON.parse(readFileSync(here('./fixtures/key-bound-v1.json'), 'utf8'));
const H = (name) => createHash('sha256').update(name).digest('hex');

let base, server;
before(async () => {
  server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  base = `http://127.0.0.1:${server.address().port}`;
  // The commitment checker loads asynchronously; a save before it is ready is refused.
  await untilReady(base);
});
after(() => server.close());

const call = async (method, path, { holder, body } = {}) => {
  const res = await fetch(`${base}${path}`, {
    method,
    headers: { 'content-type': 'application/json', ...(holder ? { 'x-holder-key': holder } : {}) },
    body: body === undefined ? undefined : JSON.stringify(testBody(method, path, holder, body)),
  });
  return { status: res.status, json: await res.json().catch(() => undefined) };
};

test('vectors: keys, bindings and salts from the record secret', () => {
  for (const k of V.keys) {
    assert.equal(identityFromSecret(k.recordSecret), k.identity);
    assert.equal(keySaltOf(k.recordSecret), k.keySalt);
    assert.equal(keyBindingOf(k.identity, k.keySalt), k.keyBinding);
  }
});

test('vectors: every record recomputes, older and bound, through the registry’s own check', async () => {
  for (const r of V.records) {
    assert.equal(await sha256Hex(canonicalise(r.fields)), r.contentHash, r.name);
    assert.equal(canonicalise(r.fields), r.canonical, r.name);
    assert.equal(await recomputeCommitment(r.fields), r.fingerprint, r.name);
    assert.deepEqual(await checkRecord({ ...r.fields, recordFingerprint: r.fingerprint }), { ok: true, verified: true }, r.name);
    if (r.fields.keyBinding) assert.equal(keyBoundFingerprint(r.fields.keyBinding, r.contentHash), r.fingerprint);
  }
});

test('vectors: a key matches only the record that named it (the swapped chain= is refused)', () => {
  for (const c of V.checks) assert.equal(keyMatchesRecord(c.identity, c), c.matches, c.name);
  assert.ok(V.checks.some((c) => /swapped/.test(c.name) && c.matches === false));
});

test('vectors: a malformed keyBinding is refused, not sealed', async () => {
  for (const r of V.refusals) {
    const check = await checkRecord({ ...r.fields, recordFingerprint: 'ab'.repeat(32) });
    assert.equal(check.ok, false, r.name);
    assert.match(check.reason, /keyBinding must be 64 lowercase hex/, r.name);
  }
});

let python = true;
try { execFileSync('python3', ['-c', 'import hashlib, json'], { stdio: 'ignore' }); } catch { python = false; }
test('vectors: an independent Python checker agrees', { skip: !python && 'python3 not installed' }, () => {
  const out = JSON.parse(execFileSync('python3', ['-I', here('./fixtures/key_binding_reference.py'), here('./fixtures/key-bound-v1.json')], { encoding: 'utf8' }));
  assert.equal(out.ok, true, JSON.stringify(out.failures));
  assert.equal(out.checked, V.keys.length + V.records.length + V.checks.length + V.refusals.length);
});

test('records written before keys were named in records still verify byte for byte', async () => {
  const fixture = JSON.parse(readFileSync(here('./fixtures/site-records-0.13.json'), 'utf8'));
  const sealed = fixture.records.filter((r) => r.recordFingerprint);
  assert.ok(sealed.length > 3);
  for (const r of sealed) {
    assert.equal(r.keyBinding, undefined);
    assert.equal(await recomputeCommitment(r), r.recordFingerprint, r.id);
  }
});

const bound = V.records.find((r) => r.name.startsWith('a record naming key 0'));
const older = V.records.find((r) => r.fields.keyBinding === undefined);

test('a bound record is stored and returned with its keyBinding; /verify says it is bound and never sends the binding', async () => {
  const holder = H('kb-holder');
  const rec = { id: 'VEIL-KEYBOUND00000000000000000001', ...bound.fields, recordFingerprint: bound.fingerprint };
  const old = { id: 'VEIL-KEYBOUND00000000000000000002', ...older.fields, nonce: '6f'.repeat(32) };
  old.recordFingerprint = await recomputeCommitment(old);
  const put = await call('PUT', '/api/records', { holder, body: [rec, old] });
  assert.equal(put.status, 200, JSON.stringify(put.json));
  assert.equal(put.json.count, 2);
  assert.equal(put.json.integrityCheckedBy, 'holder');

  const mine = (await call('GET', '/api/records', { holder })).json;
  assert.equal(mine.find((m) => m.id === rec.id).keyBinding, bound.fields.keyBinding);

  const v = await call('GET', `/verify/${rec.id}`);
  assert.equal(v.json.keyBound, true);
  assert.equal(v.json.recordFingerprint, bound.fingerprint);
  assert.ok(!JSON.stringify(v.json).includes(bound.fields.keyBinding), 'the binding is not public');
  assert.equal((await call('GET', `/verify/${old.id}`)).json.keyBound, false);
});

test('swapping the key after sealing, or dropping it: the registry does not claim to check; the holder\'s browser does', async () => {
  // Since sealed records the registry can't open a record, so it can't recompute its
  // fingerprint. It used to refuse these two ("commitment does not match"); now it stores
  // them and says who checks (integrityCheckedBy: "holder"): the site recomputes every
  // fingerprint after opening a record and refuses to save one that does not match.
  const holder = H('kb-holder');
  const other = V.keys[1].keyBinding;
  const swapped = { id: 'VEIL-KEYBOUND00000000000000000003', ...bound.fields, keyBinding: other, recordFingerprint: bound.fingerprint };
  const { keyBinding: _dropped, ...rest } = bound.fields;
  void _dropped;
  const dropped = { id: 'VEIL-KEYBOUND00000000000000000004', ...rest, recordFingerprint: bound.fingerprint };
  const put = await call('PUT', '/api/records', { holder, body: [swapped, dropped] });
  assert.equal(put.status, 200, JSON.stringify(put.json));
  assert.equal(put.json.integrityCheckedBy, 'holder');
  assert.equal(put.json.verified, undefined, 'no count of records the registry verified');
  assert.equal(put.json.rejected, undefined);
  // What the holder's browser checks, and would refuse on.
  assert.match((await checkRecord(swapped)).reason, /commitment does not match/);
  assert.match((await checkRecord(dropped)).reason, /commitment does not match/);
});
