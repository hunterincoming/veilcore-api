// Round 6: /verify names the lab report file saved to a record NOW, when the holder shares
// whether one is saved. Round 5 of sealing (17 Oct, CONTRACT.md #29): it names it only in the
// bound form, dnaPairBinding = H("veilcore:v1:dnapair", the file's SHA-256, the record's
// identity, its pairing salt). The salt is only in the holder's link, so the file's SHA-256
// and its pairing fingerprint, which anyone holding the same file could compare, are never
// answered. The check page used to read which file was saved from the link
// (`rs=`, as of when the link was made), so the certificate's QR code (no `rs`) said no lab
// had signed anything beside two withdrawn lab signatures, and an older link described a
// file the breeder had since replaced.
//
// SPDX-License-Identifier: Apache-2.0

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { createHash, randomBytes } from 'node:crypto';
import { canonicalise, sha256Hex, newNonce } from 'veilcore-records';
import { untilReady, testBody, grantForTest, dnaPairBindingForTest, pairIdentityFor, pairSaltFor } from './helpers.mjs';

process.env.DB_PATH = ':memory:';
process.env.VEILCORE_OTS = 'off';
const require = createRequire(import.meta.url);
const { app, db } = require('../server.js');

const H = (name) => createHash('sha256').update(name).digest('hex');

let base, server;
before(async () => {
  server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  base = `http://127.0.0.1:${server.address().port}`;
  await untilReady(base);
});
after(() => server.close());

const call = async (method, path, holder, body) => {
  const res = await fetch(`${base}${path}`, {
    method,
    headers: { 'content-type': 'application/json', ...(holder ? { 'x-holder-key': holder } : {}) },
    ...(body === undefined ? {} : { body: JSON.stringify(testBody(method, path, holder, body)) }),
  });
  return { status: res.status, json: await res.json() };
};

const committedOf = (r) => ({ breedingMethod: r.breedingMethod ?? '', bredBy: r.bredBy, dateCreated: r.dateCreated,
  loggedAt: r.loggedAt, nonce: r.nonce, notes: r.notes, parents: r.parents ?? [],
  photoFingerprints: r.photoFingerprints ?? [], refId: r.refId ?? '', strainName: r.strainName });

const sealed = async (over = {}) => {
  const r = { id: `VEIL-${randomBytes(16).toString('hex').toUpperCase()}`, strainName: 'Harbour Mist', bredBy: 'B',
    dateCreated: '2026-01-01', loggedAt: 1, nonce: newNonce(), notes: '', parents: [], photoFingerprints: [],
    breedingMethod: '', refId: '', ...over };
  r.recordFingerprint = await sha256Hex(canonicalise(committedOf(r)));
  return r;
};

/** A saved lab report, as the app stores it: the pairing fingerprint and the file's SHA-256. */
const v1 = { dnaFingerprint: H('pairing v1'), dnaFileName: 'Lab report v1.pdf', dnaFileSha256: H('file v1'), dnaResultId: 'LR-AAAA' };
const v2 = { dnaFingerprint: H('pairing v2'), dnaFileName: 'Lab report v2.pdf', dnaFileSha256: H('file v2'), dnaResultId: 'LR-BBBB' };

// Since sealed records the registry answers from what the holder's app sends with the grant
// (grantForTest: the values read from the record as last saved), and the app sends its
// grants again after every save (disclosure.ts syncGrants).
const lastSaved = new Map();
const save = async (holder, rec) => {
  const put = await call('PUT', '/api/records', holder, [rec]);
  assert.equal(put.status, 200, JSON.stringify(put.json));
  assert.equal(put.json.count, 1, JSON.stringify(put.json));
  lastSaved.set(rec.id, rec);
};
const share = async (holder, id, show) => {
  const r = await call('PUT', `/api/records/${id}/disclosure`, holder, grantForTest(lastSaved.get(id), show));
  assert.equal(r.status, 200, JSON.stringify(r.json));
};

const bindingOf = (rec, sha) => dnaPairBindingForTest(sha, pairIdentityFor(rec), pairSaltFor(rec));
const PLAIN = ['dnaPairingFingerprint', 'dnaFileSha256'];

test('shared: /verify names the file saved now, bound, and follows the holder when they save another', async () => {
  const holder = H('pairing-holder-1');
  const rec = await sealed();
  await save(holder, { ...rec, ...v1 });
  await share(holder, rec.id, ['attestation-status']);

  let v = (await call('GET', `/verify/${rec.id}`)).json;
  assert.equal(v.dnaPairedByHolder, true);
  assert.equal(v.dnaPairBinding, bindingOf(rec, v1.dnaFileSha256));
  // Never the file's SHA-256 or its pairing fingerprint: anyone with the same file could compare those.
  for (const k of PLAIN) assert.equal(v[k], undefined, k);
  const text = JSON.stringify(v);
  for (const plainValue of [v1.dnaFileSha256, v1.dnaFingerprint]) assert.ok(!text.includes(plainValue));
  // Nothing a stranger can use: no result id, no file name.
  assert.equal(v.dnaResultId, undefined);
  assert.equal(v.dnaFileName, undefined);

  // The breeder saves the lab's corrected report: an old link reads the current one. The
  // pairing is not part of the fingerprint, so the grant is not stale: the app sends it again.
  await save(holder, { ...rec, ...v2 });
  await share(holder, rec.id, ['attestation-status']);
  v = (await call('GET', `/verify/${rec.id}`)).json;
  assert.equal(v.dnaPairBinding, bindingOf(rec, v2.dnaFileSha256));
  // Whatever a link asks for (an old `rs`, a fingerprint), the answer is the record's.
  v = (await call('GET', `/verify/${rec.id}?rs=${v1.dnaFileSha256}&fp=${rec.recordFingerprint}`)).json;
  assert.equal(v.dnaPairBinding, bindingOf(rec, v2.dnaFileSha256));
  // With the file and the salt from the link, the binding is checked; with another file, or
  // without the salt, it can't be matched.
  assert.equal(dnaPairBindingForTest(v2.dnaFileSha256, pairIdentityFor(rec), pairSaltFor(rec)), v.dnaPairBinding);
  assert.notEqual(dnaPairBindingForTest(v1.dnaFileSha256, pairIdentityFor(rec), pairSaltFor(rec)), v.dnaPairBinding);
  assert.notEqual(dnaPairBindingForTest(v2.dnaFileSha256, pairIdentityFor(rec), H('another salt')), v.dnaPairBinding);
});

test('privacy: nothing about the saved file unless the holder shares whether a lab report is saved', async () => {
  const holder = H('pairing-holder-2');
  const rec = await sealed();
  await save(holder, { ...rec, ...v1 });
  const FIELDS = ['dnaPairedByHolder', 'dnaPairBinding', ...PLAIN];

  // No grant stored at all.
  let v = (await call('GET', `/verify/${rec.id}`)).json;
  assert.equal(v.found, true);
  for (const k of FIELDS) assert.equal(v[k], undefined, k);

  // Other facts shared, not this one.
  await share(holder, rec.id, ['existence', 'sealed-at']);
  v = (await call('GET', `/verify/${rec.id}`)).json;
  for (const k of FIELDS) assert.equal(v[k], undefined, k);
  assert.ok(!v.disclosed.includes('dna'));

  // Shared, but the link narrows it away with ?show=.
  await share(holder, rec.id, ['existence', 'attestation-status']);
  v = (await call('GET', `/verify/${rec.id}?show=own`)).json;
  for (const k of FIELDS) assert.equal(v[k], undefined, k);

  // Shared and not narrowed.
  v = (await call('GET', `/verify/${rec.id}?show=own,dna`)).json;
  assert.equal(v.dnaPairBinding, bindingOf(rec, v1.dnaFileSha256));
  assert.ok(v.disclosed.includes('dna'));

  // The holder turns it off again: gone.
  await share(holder, rec.id, ['existence']);
  v = (await call('GET', `/verify/${rec.id}`)).json;
  for (const k of FIELDS) assert.equal(v[k], undefined, k);
});

test('nothing saved, a grant stored with the plain values before round 5, and values that are not 64 hex characters', async () => {
  const holder = H('pairing-holder-3');

  const none = await sealed();
  await save(holder, none);
  await share(holder, none.id, ['attestation-status']);
  let v = (await call('GET', `/verify/${none.id}`)).json;
  assert.equal(v.dnaPairedByHolder, false);
  assert.equal(v.dnaPairBinding, undefined);

  // A grant stored before round 5 with the plain values: only "a report is saved" is answered,
  // never the values, until the holder's app sends the bound form.
  const legacy = await sealed();
  await save(holder, { ...legacy, ...v1 });
  db.prepare('INSERT INTO disclosure_grants (record_id, holder_key, show, updated_at, grant_values, for_fingerprint) VALUES (?,?,?,?,?,?)')
    .run(legacy.id, db.prepare('SELECT holder_key FROM records WHERE id = ?').get(legacy.id).holder_key, '["attestation-status"]', 1,
      JSON.stringify({ dnaFingerprint: v1.dnaFingerprint, dnaFileSha256: v1.dnaFileSha256 }), legacy.recordFingerprint);
  v = (await call('GET', `/verify/${legacy.id}`)).json;
  assert.equal(v.dnaPairedByHolder, true);
  for (const k of [...PLAIN, 'dnaPairBinding']) assert.equal(v[k], undefined, k);
  assert.ok(!JSON.stringify(v).includes(v1.dnaFileSha256));
  // The new form replaces it.
  await share(holder, legacy.id, ['attestation-status']);
  assert.equal((await call('GET', `/verify/${legacy.id}`)).json.dnaPairBinding, bindingOf(legacy, v1.dnaFileSha256));

  // Only 64 lowercase hex is taken as a binding; anything else is refused, never echoed.
  const odd = await sealed();
  await save(holder, odd);
  for (const bad of ['see <b>attached</b>', 'X'.repeat(64), 'ab'.repeat(32).toUpperCase(), 7]) {
    const r = await call('PUT', `/api/records/${odd.id}/disclosure`, holder, {
      show: ['attestation-status'], forFingerprint: odd.recordFingerprint, values: { dnaPairBinding: bad },
    });
    assert.equal(r.status, 400, JSON.stringify(bad));
    assert.match(r.json.error, /dnaPairBinding must be 64 lowercase hexadecimal characters/);
  }
  // The plain values are refused outright.
  for (const plainValue of [{ dnaFileSha256: v1.dnaFileSha256 }, { dnaFingerprint: v1.dnaFingerprint }]) {
    const r = await call('PUT', `/api/records/${odd.id}/disclosure`, holder, {
      show: ['attestation-status'], forFingerprint: odd.recordFingerprint, values: plainValue,
    });
    assert.equal(r.status, 400);
    assert.match(r.json.error, /no longer published/);
  }
});
