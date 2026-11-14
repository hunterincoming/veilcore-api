// A lab signature the holder shares is shown by proof code too (12 Nov 2026).
//
// The site's claim check page names the plant a claim's numbers are about only by its proof
// code (the claim link's `attested.about`), and /verify needs the record id. With lab
// signatures private (hide-lab-reports.test.mjs) that page could no longer read the lab report a
// v1 binding names, so it could not name the lab even when the holder shared the report on
// their check link. Now GET /attestations/subject/:commitment lists and counts, for everyone,
// what the proof code's holder shares (server.js sharedOnFingerprint), exactly as /verify
// answers it, and nothing else private:
//   · only while the share stands: unsharing, a grant without attestation-status, deleting the
//     record or editing it (its proof code changes) takes it off at once;
//   · only for the record's CURRENT proof code: an edited or corrected record's old one answers
//     nothing here;
//   · only from the proof code's first holder: a takeover shares nothing;
//   · a delivery changes nothing: the recipient's record has its own proof code and can't
//     share signatures about the sender's.
// No network.
//
// SPDX-License-Identifier: Apache-2.0

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { createHash, randomBytes } from 'node:crypto';
import { canonicalise, sha256Hex, newNonce, generateKeypair, signAttestation, signRetraction } from 'veilcore-records';
import { untilReady, testBody, labKeyProof } from './helpers.mjs';
import { registrationPayload } from '../lineage/attesters.mjs';

process.env.DB_PATH = ':memory:';
process.env.VEILCORE_OTS = 'off';
process.env.VEILCORE_OPERATOR_TOKEN = 'test-operator-token-at-least-32-chars';
const require = createRequire(import.meta.url);
const { app, db } = require('../server.js');
const { asStored } = require('../holder-key.js');

const key = () => randomBytes(32).toString('hex');
const sha = (v) => createHash('sha256').update(v).digest('hex');
let base, server;
before(async () => {
  server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  base = `http://127.0.0.1:${server.address().port}`;
  await untilReady(base);
});
after(() => server.close());

const call = async (method, path, holder, body, headers = {}) => {
  const res = await fetch(`${base}${path}`, {
    method,
    headers: { 'content-type': 'application/json', 'x-forwarded-for': `10.${randomBytes(3).join('.')}`, ...(holder ? { 'x-holder-key': holder } : {}), ...headers },
    ...(body === undefined ? {} : { body: JSON.stringify(testBody(method, path, holder, body)) }),
  });
  const text = await res.text();
  let json; try { json = JSON.parse(text); } catch { json = text; }
  return { status: res.status, json, text, headers: res.headers };
};

const LAB_NAME = 'Proof Code Labs';
const lab = async () => {
  const kp = await generateKeypair();
  const reg = { publicKey: kp.publicKey, issuedAt: Date.now(), displayName: LAB_NAME, role: 'laboratory' };
  const priv = await crypto.subtle.importKey('pkcs8', Buffer.from(kp.privateKey, 'hex'), { name: 'Ed25519' }, false, ['sign']);
  const sig = await crypto.subtle.sign('Ed25519', priv, new TextEncoder().encode(registrationPayload(reg)));
  assert.equal((await call('POST', '/attesters', null, { ...reg, signature: Buffer.from(sig).toString('hex') })).status, 200);
  return kp;
};
const fresh = async (strainName = 'P') => {
  const committed = { breedingMethod: '', bredBy: 'B', dateCreated: '2026-01-01', loggedAt: '2026-01-01T00:00:00Z',
    nonce: newNonce(), notes: '', parents: [], photoFingerprints: [], refId: '', strainName };
  return { id: `pc-${randomBytes(4).toString('hex')}`, ...committed, recordFingerprint: await sha256Hex(canonicalise(committed)) };
};
/** A breeder's plant sent to a lab that claimed it; the lab signs a report and sends it back. */
const handled = async () => {
  const src = await fresh();
  const sender = key(), labHolder = key();
  assert.equal((await call('PUT', '/api/records', sender, [src])).status, 200);
  const o = await call('POST', '/transfers', sender, { sourceRecord: src.id, toHandle: 'lab@x' });
  assert.equal(o.status, 200, JSON.stringify(o.json));
  assert.equal((await call('POST', `/transfers/${o.json.transferId}/claim`, labHolder, { claimCode: o.json.claimCode })).status, 200);
  const kp = await lab();
  const reports = [];
  for (let i = 0; i < 2; i++) {
    const signed = await signAttestation({
      attestationId: `att_${randomBytes(8).toString('hex')}_ld1`, type: 'laboratory-report', subjectCommitment: src.recordFingerprint,
      documentHash: sha(randomBytes(16)), hashAlgorithm: 'sha256', issuedAt: '2026-11-12T09:00:00Z',
      attester: { publicKey: kp.publicKey, displayName: LAB_NAME },
    }, kp.privateKey);
    assert.equal((await call('POST', '/attestations', null, signed)).status, 200);
    const res = await fetch(`${base}/transfers/${o.json.transferId}/results?attestationId=${signed.attestationId}`, {
      method: 'POST',
      headers: { 'content-type': 'application/octet-stream', 'x-holder-key': labHolder, 'x-lab-key-proof': await labKeyProof(kp, o.json.transferId, signed.attestationId) },
      body: Buffer.concat([Buffer.from('age-encryption.org/v1\n-> X25519 abc\n'), randomBytes(64)]),
    });
    assert.equal(res.status, 200, await res.text());
    reports.push(signed);
  }
  return { sender, labHolder, kp, recordId: src.id, record: src, fp: src.recordFingerprint, reports, transferId: o.json.transferId };
};
const share = (h, list, show = ['existence', 'attestation-status'], recordId = h.recordId, fp = h.fp) =>
  call('PUT', `/api/records/${recordId}/disclosure`, h.sender, { show, forFingerprint: fp, values: { sharedAttestations: list } });
const page = async (fp, holder = null) => (await call('GET', `/attestations/subject/${fp}`, holder));
const ids = (list) => list.map((a) => a.attestationId).sort();
/** What a stranger reads by proof code: the ids listed, and the total. */
const byCode = async (fp) => {
  const p = (await page(fp)).json;
  return { ids: ids(p.attestations), total: p.total };
};

test('/health lists shared-by-proof-code-v1, for the site’s deploy preflights', async () => {
  const h = await call('GET', '/health');
  assert.ok(h.json.features.includes('shared-by-proof-code-v1'), JSON.stringify(h.json));
});

test('nothing private by proof code until the holder shares it; then exactly that one, whole, not cached', async () => {
  const h = await handled();
  const [shown, kept] = h.reports;
  assert.deepEqual(await byCode(h.fp), { ids: [], total: 0 });
  assert.equal((await share(h, [shown.attestationId])).status, 200);
  const p = await page(h.fp);
  assert.deepEqual(ids(p.json.attestations), [shown.attestationId]);
  assert.equal(p.json.total, 1);
  assert.equal(p.headers.get('cache-control'), 'no-store', 'a share can be taken back');
  assert.equal(p.json.attestations[0].registeredAs?.displayName, LAB_NAME, 'whole, so a page can name the lab');
  assert.ok(!p.text.includes(kept.attestationId), 'the report not shared is not there');
  // The same as /verify answers.
  const v = (await call('GET', `/verify/${h.recordId}`)).json;
  assert.deepEqual(v.sharedAttestations.map((a) => a.attestationId), [shown.attestationId]);
  // The holder still reads both, the shared one once.
  assert.deepEqual(ids((await page(h.fp, h.sender)).json.attestations), ids(h.reports));
  assert.equal((await page(h.fp, h.sender)).json.total, 2);
  // A withdrawal by the lab is shown with it.
  const ret = await signRetraction({ attestationId: shown.attestationId, attesterPublicKey: h.kp.publicKey, reason: 'superseded', retractedAt: new Date().toISOString() }, h.kp.privateKey);
  assert.equal((await call('POST', `/attestations/${shown.attestationId}/retract`, null, ret)).status, 200);
  assert.ok((await page(h.fp)).json.attestations[0].retraction);
});

test('unshare: an empty list, a grant without attestation-status, or no grant at all takes it off at once', async () => {
  const h = await handled();
  const id = h.reports[0].attestationId;
  assert.equal((await share(h, [id])).status, 200);
  assert.deepEqual((await byCode(h.fp)).ids, [id]);
  assert.equal((await share(h, [])).status, 200);
  assert.deepEqual(await byCode(h.fp), { ids: [], total: 0 });
  assert.equal((await share(h, [id])).status, 200);
  assert.equal((await call('PUT', `/api/records/${h.recordId}/disclosure`, h.sender, { show: ['existence'], forFingerprint: h.fp })).status, 200);
  assert.deepEqual(await byCode(h.fp), { ids: [], total: 0 });
  // Shared again, then the record deleted: gone, and nobody can take the proof code to bring it back.
  assert.equal((await share(h, [id])).status, 200);
  assert.deepEqual((await byCode(h.fp)).ids, [id]);
  assert.equal((await call('DELETE', '/api/records', h.sender, { ids: [h.recordId] })).status, 200);
  assert.deepEqual(await byCode(h.fp), { ids: [], total: 0 });
});

test('a ?show= narrowing on a check link does not matter here: only the holder’s grant does', async () => {
  const h = await handled();
  const id = h.reports[0].attestationId;
  assert.equal((await share(h, [id])).status, 200);
  assert.deepEqual((await byCode(`${h.fp}?show=existence`)).ids, [id]);
});

test('an edit: the old proof code answers nothing, and the record’s new one has nothing to share', async () => {
  const h = await handled();
  const id = h.reports[0].attestationId;
  assert.equal((await share(h, [id])).status, 200);
  const edited = await fresh('Edited');
  assert.equal((await call('PUT', '/api/records', h.sender, [{ ...edited, id: h.recordId }])).json.count, 1);
  assert.deepEqual(await byCode(h.fp), { ids: [], total: 0 }, 'the share was for the record as it was');
  assert.deepEqual(await byCode(edited.recordFingerprint), { ids: [], total: 0 });
  // /verify agrees: the signature is about the record before it changed.
  assert.equal((await call('GET', `/verify/${h.recordId}`)).json.sharedAttestations, undefined);
});

test('a correction: the corrected record’s proof code answers nothing here, and the correction’s has nothing', async () => {
  const h = await handled();
  const id = h.reports[0].attestationId;
  assert.equal((await share(h, [id])).status, 200);
  assert.deepEqual((await byCode(h.fp)).ids, [id]);
  const stored = (await call('GET', '/api/records', h.sender)).json.find((r) => r.id === h.recordId);
  const correction = { ...(await fresh('Corrected')),
    supersedes: { recordId: h.recordId, changedFields: ['notes'], effectiveAt: '2026-11-12T10:00:00Z', reason: 'typo' } };
  const put = await call('PUT', '/api/records', h.sender, [correction, { ...stored, supersededBy: correction.id }]);
  assert.equal(put.json.ok, true, JSON.stringify(put.json));
  assert.deepEqual(await byCode(h.fp), { ids: [], total: 0 }, 'a corrected record shares nothing by proof code');
  assert.deepEqual(await byCode(correction.recordFingerprint), { ids: [], total: 0 });
  // Its own check link is unchanged: it still answers what the holder shared there.
  assert.deepEqual((await call('GET', `/verify/${h.recordId}`)).json.sharedAttestations?.map((a) => a.attestationId), [id]);
  // And the correction can't share a signature about the record it replaced.
  const g = await share(h, [id], ['existence', 'attestation-status'], correction.id, correction.recordFingerprint);
  assert.equal(g.status, 400, JSON.stringify(g.json));
  // The holder still reads it with their key.
  assert.deepEqual(ids((await page(h.fp, h.sender)).json.attestations), ids(h.reports));
});

test('a delivery: the sender’s share stands; the recipient can neither share it nor take the proof code', async () => {
  const h = await handled();
  const id = h.reports[0].attestationId;
  assert.equal((await share(h, [id])).status, 200);
  // The breeder sends the plant on to a buyer, who claims it and gets a record of their own.
  const o = await call('POST', '/transfers', h.sender, { sourceRecord: h.recordId, toHandle: 'buyer@x' });
  assert.equal(o.status, 200, JSON.stringify(o.json));
  const buyer = key();
  assert.equal((await call('POST', `/transfers/${o.json.transferId}/claim`, buyer, { claimCode: o.json.claimCode })).status, 200);
  assert.deepEqual((await byCode(h.fp)).ids, [id], 'a delivery changes nothing');
  const received = (await call('GET', '/api/records', buyer)).json.find((r) => r.transferId === o.json.transferId);
  assert.ok(received, 'the claim made the buyer a record');
  // The buyer seals the record their claim made (as the app does), with its own proof code...
  const committed = { breedingMethod: '', bredBy: 'B', dateCreated: '2026-01-01', loggedAt: received.receivedAt,
    nonce: newNonce(), notes: '', parents: [], photoFingerprints: [], refId: '', strainName: 'Received' };
  const mine = { ...received, ...committed, recordFingerprint: await sha256Hex(canonicalise(committed)) };
  assert.equal((await call('PUT', '/api/records', buyer, [mine])).json.count, 1);
  assert.notEqual(mine.recordFingerprint, h.fp);
  // ...and can't share the breeder's signatures on it.
  const g = await call('PUT', `/api/records/${received.id}/disclosure`, buyer, {
    show: ['existence', 'attestation-status'], forFingerprint: mine.recordFingerprint, values: { sharedAttestations: [h.reports[1].attestationId] },
  });
  assert.equal(g.status, 400, JSON.stringify(g.json));
  assert.match(g.json.error, /not a signature about this record that this holder key can see/);
  assert.deepEqual(await byCode(mine.recordFingerprint), { ids: [], total: 0 });
  // ...nor store the breeder's proof code to answer for it.
  const taken = await fresh('Taken');
  const put = await call('PUT', '/api/records', buyer, [{ ...taken, recordFingerprint: h.fp }]);
  assert.equal(put.json.count, 0, JSON.stringify(put.json));
  assert.deepEqual((await byCode(h.fp)).ids, [id]);
  // The breeder hands the plant over and deletes their record: the share goes with it.
  assert.equal((await call('DELETE', '/api/records', h.sender, { ids: [h.recordId] })).status, 200);
  assert.deepEqual(await byCode(h.fp), { ids: [], total: 0 });
});

test('a record under a taken-over proof code shares nothing, even with a grant written by hand', async () => {
  const h = await handled();
  const id = h.reports[0].attestationId;
  // As if the proof code had been taken before the first-holder guard: the breeder's record
  // gone, and another key's record holding the proof code with a grant naming the report.
  assert.equal((await call('DELETE', '/api/records', h.sender, { ids: [h.recordId] })).status, 200);
  // The taker is the lab itself: a key that can read the report (it signed it and tied it on),
  // so only the first-holder test stands between its grant and the report being shown.
  const stranger = asStored(h.labHolder);
  const taken = await fresh('Taken');
  db.prepare('INSERT INTO records (id, holder_key, body, updated_at, first_seen) VALUES (?,?,?,?,?)')
    .run(taken.id, stranger, JSON.stringify({ id: taken.id, recordFingerprint: h.fp }), Date.now(), Date.now());
  db.prepare('INSERT INTO disclosure_grants (record_id, holder_key, show, updated_at, grant_values, for_fingerprint) VALUES (?,?,?,?,?,?)')
    .run(taken.id, stranger, JSON.stringify(['existence', 'attestation-status']), Date.now(), JSON.stringify({ sharedAttestations: [id] }), h.fp);
  assert.deepEqual(await byCode(h.fp), { ids: [], total: 0 });
  // The taker's row gone, the first holder may store it again, and share again.
  db.prepare('DELETE FROM disclosure_grants WHERE record_id = ?').run(taken.id);
  db.prepare('DELETE FROM records WHERE id = ?').run(taken.id);
  const again = await fresh();
  assert.equal((await call('PUT', '/api/records', h.sender, [{ ...again, recordFingerprint: h.fp }])).json.count, 1);
  assert.equal((await share(h, [id], undefined, again.id)).status, 200);
  assert.deepEqual((await byCode(h.fp)).ids, [id]);
});

test('another holder’s grant on a record of theirs never lists a signature about this proof code', async () => {
  const h = await handled();
  const other = await handled();
  assert.equal((await share(other, [other.reports[0].attestationId])).status, 200);
  assert.deepEqual(await byCode(h.fp), { ids: [], total: 0 });
  assert.deepEqual((await byCode(other.fp)).ids, [other.reports[0].attestationId]);
});

test('L2: two records of one holder with one proof code: listed only while every one of them shares it', async () => {
  const h = await handled();
  const id = h.reports[0].attestationId;
  // The holder keeps a second record with the same contents, so the same proof code.
  const twin = { ...h.record, id: `pc-${randomBytes(4).toString('hex')}` };
  assert.equal(twin.recordFingerprint, h.fp);
  assert.equal((await call('PUT', '/api/records', h.sender, [twin])).json.count, 1);
  // Shared on one only: not by proof code (the twin doesn't share it).
  assert.equal((await share(h, [id])).status, 200);
  assert.deepEqual(await byCode(h.fp), { ids: [], total: 0 });
  // Shared on both: listed.
  assert.equal((await share(h, [id], undefined, twin.id)).status, 200);
  assert.deepEqual((await byCode(h.fp)).ids, [id]);
  // Unshared on either one: off by proof code at once, whichever is newer.
  assert.equal((await share(h, [], undefined, twin.id)).status, 200);
  assert.deepEqual(await byCode(h.fp), { ids: [], total: 0 });
  assert.equal((await share(h, [id], undefined, twin.id)).status, 200);
  assert.equal((await share(h, [])).status, 200);
  assert.deepEqual(await byCode(h.fp), { ids: [], total: 0 });
  // Each record's own check link still answers its own choice.
  assert.deepEqual((await call('GET', `/verify/${twin.id}`)).json.sharedAttestations?.map((a) => a.attestationId), [id]);
  assert.equal((await call('GET', `/verify/${h.recordId}`)).json.sharedAttestations, undefined);
});
