// The public registry, attacked over HTTP. Security pass 1 Oct 2026.
//
// Each test is one attack from that pass, now refused, plus the flow that must still
// work. The server runs in-process on an in-memory database.
//
// SPDX-License-Identifier: Apache-2.0

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { createHash } from 'node:crypto';
import { generateKeypair, signAttestation, canonicalise, sha256Hex, newNonce } from 'veilcore-records';
import { registrationPayload } from '../lineage/attesters.mjs';
import { inOneMinute, untilReady, testBody, grantForTest } from './helpers.mjs';

process.env.DB_PATH = ':memory:';
const require = createRequire(import.meta.url);
const { app } = require('../server.js');

/** A holder key, as the app makes one: 64 hex characters. Derived from a name for readability. */
const H = (name) => createHash('sha256').update(name).digest('hex');

let base;
let server;
before(async () => {
  server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  base = `http://127.0.0.1:${server.address().port}`;
  // The verification and attester modules load asynchronously at startup.
  await untilReady(base);
});
after(() => server.close());

const call = async (method, path, { holder, body, headers = {} } = {}) => {
  const res = await fetch(`${base}${path}`, {
    method,
    headers: {
      'content-type': 'application/json',
      ...(holder ? { 'x-holder-key': holder } : {}),
      ...headers,
    },
    body: body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(testBody(method, path, holder, body)),
  });
  const text = await res.text();
  let json;
  try { json = JSON.parse(text); } catch { json = text; }
  return { status: res.status, json, headers: res.headers };
};

/** A record whose commitment verifies, as the app makes one. */
const makeRecord = async (id, notes = 'private notes') => {
  const r = {
    id,
    strainName: 'Test Cultivar',
    bredBy: 'Breeder',
    dateCreated: '2026-01-01',
    loggedAt: '2020-01-01T00:00:00Z', // a holder can claim any date
    nonce: newNonce(),
    notes,
    parents: [{ name: 'Secret Mother' }],
    photoFingerprints: [],
    breedingMethod: 'secret method',
    refId: '',
  };
  const committed = {
    breedingMethod: r.breedingMethod, bredBy: r.bredBy, dateCreated: r.dateCreated, loggedAt: r.loggedAt,
    nonce: r.nonce, notes: r.notes, parents: r.parents, photoFingerprints: r.photoFingerprints,
    refId: r.refId, strainName: r.strainName,
  };
  r.recordFingerprint = await sha256Hex(canonicalise(committed));
  return r;
};

test('a stranger reading /records/:id gets the public view, not the holder\'s record', async () => {
  const rec = await makeRecord('rec-public-view', 'do not leak');
  assert.equal((await call('PUT', '/api/records', { holder: H('holder-a'), body: [rec] })).json.count, 1);
  const { status, json } = await call('GET', `/records/${rec.id}`);
  assert.equal(status, 200);
  assert.equal(json.recordFingerprint, rec.recordFingerprint);
  for (const secretField of ['nonce', 'notes', 'parents', 'breedingMethod', 'bredBy'])
    assert.equal(json[secretField], undefined, `${secretField} must not be public`);
  // The holder's own date is theirs to show (round D): absent until they grant sealed-at.
  assert.equal(json.loggedAtClaimedByHolder, undefined);
  assert.ok(json.registryFirstSeen, 'the registry reports when it first saw the record');
  await call('PUT', `/api/records/${rec.id}/disclosure`, { holder: H('holder-a'), body: grantForTest(rec, ['sealed-at']) });
  assert.equal((await call('GET', `/records/${rec.id}`)).json.loggedAtClaimedByHolder, rec.loggedAt);
});

test('a copy of someone else\'s record cannot be stored under another key', async () => {
  const rec = await makeRecord('rec-original');
  await call('PUT', '/api/records', { holder: H('holder-b'), body: [rec] });
  const copy = { ...rec, id: 'rec-copy' };
  const out = await call('PUT', '/api/records', { holder: H('attacker'), body: [copy] });
  assert.equal(out.json.count, 0);
  assert.match(out.json.rejected[0].reason, /already registered by another holder/);
  // The real holder can still update their own.
  assert.equal((await call('PUT', '/api/records', { holder: H('holder-b'), body: [rec] })).json.count, 1);
});

test('/verify reports only what the registry can stand behind', async () => {
  const rec = { ...(await makeRecord('rec-claims')), attestation: { lab: 'Fake Lab' }, dnaFingerprint: 'ab'.repeat(32) };
  await call('PUT', '/api/records', { holder: H('holder-c'), body: [rec] });
  // Since round D a fact beyond the base needs the holder's grant; ?show= only narrows it.
  await call('PUT', `/api/records/${rec.id}/disclosure`, { holder: H('holder-c'), body: grantForTest(rec, ['own', 'dna', 'sealed']) });
  const { json } = await call('GET', `/verify/${rec.id}?show=own,dna,sealed`);
  assert.equal(json.attested, false, 'a holder-typed attestation is not an attestation');
  assert.equal(json.priorPossession, false, 'no ledger anchor, so no prior-possession claim');
  assert.equal(json.dnaPairedByHolder, true);
  assert.equal(json.dnaPaired, undefined, 'the old field implied more than the holder pairing it');
});

const registration = async (kp, fields) => {
  const reg = { publicKey: kp.publicKey, issuedAt: Date.now(), ...fields };
  const priv = await crypto.subtle.importKey('pkcs8', Buffer.from(kp.privateKey, 'hex'), { name: 'Ed25519' }, false, ['sign']);
  const sig = await crypto.subtle.sign('Ed25519', priv, new TextEncoder().encode(registrationPayload(reg)));
  return { ...reg, signature: Buffer.from(sig).toString('hex') };
};

test('nobody can register or rename a lab without its key', async () => {
  const lab = await generateKeypair();
  const unsigned = await call('POST', '/attesters', { body: { publicKey: lab.publicKey, displayName: 'Real Lab', issuedAt: Date.now() } });
  assert.equal(unsigned.status, 400);
  assert.equal((await call('POST', '/attesters', { body: await registration(lab, { displayName: 'Real Lab' }) })).status, 200);

  const attacker = await generateKeypair();
  const forged = await registration(attacker, { displayName: 'Fake Name' });
  const relabel = await call('POST', '/attesters', { body: { ...forged, publicKey: lab.publicKey } });
  assert.equal(relabel.status, 400, 'signed by a different key');
  assert.equal((await call('GET', `/attesters/${lab.publicKey}`)).json.displayName, 'Real Lab');

  // Replaying the lab's own older registration cannot roll back a newer one.
  const older = await registration(lab, { displayName: 'Real Lab', issuedAt: Date.now() - 60_000 });
  assert.equal((await call('POST', '/attesters', { body: older })).status, 400);
});

test('a lab\'s attestation cannot be overwritten by reusing its id', async () => {
  const lab = await generateKeypair();
  const subject = 'cd'.repeat(32);
  const mine = await signAttestation({
    attestationId: 'att-1oct-1', attester: { publicKey: lab.publicKey }, documentHash: 'ef'.repeat(32),
    hashAlgorithm: 'sha256', issuedAt: '2026-10-01T00:00:00Z', subjectCommitment: subject, type: 'material-received',
  }, lab.privateKey);
  assert.equal((await call('POST', '/attestations', { body: mine })).status, 200);
  const attacker = await generateKeypair();
  const theirs = await signAttestation({ ...mine, attester: { publicKey: attacker.publicKey }, signature: undefined }, attacker.privateKey);
  const out = await call('POST', '/attestations', { body: theirs });
  assert.equal(out.status, 400);
  const left = (await call('GET', `/attestations/subject/${subject}`)).json.attestations;
  assert.equal(left.length, 1);
  assert.equal(left[0].attester.publicKey, lab.publicKey);
});

test('registry-only views need the operator token', async () => {
  const out = await call('GET', '/batches/pending');
  assert.ok(out.status === 401 || out.status === 503);
});

test('a bad request gets a message, never a stack trace', async () => {
  const out = await call('PUT', '/api/records', { holder: H('h'), body: '{"not json' });
  assert.equal(out.status, 400);
  assert.doesNotMatch(JSON.stringify(out.json), /node_modules|at .*\.js:\d+/);
  assert.equal(out.headers.get('x-powered-by'), null);
});

test('writes are rate limited', async () => {
  let limited = false;
  // In one minute, as a client hammering it would be (helpers.mjs).
  await inOneMinute(async () => {
    for (let i = 0; i < 130 && !limited; i++) {
      const r = await call('DELETE', '/api/records', { holder: H('flood'), body: { ids: ['x'] } });
      limited = r.status === 429;
    }
  });
  assert.equal(limited, true);
});
