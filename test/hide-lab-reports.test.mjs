// Lab report signatures are shown only to the delivery's sender and lab (8 Nov 2026).
//
// The leak, live on mainnet: when a lab sends a report back on a delivery, the site signs a
// `laboratory-report` attestation about the plant's own record. The registry served it to
// anyone with the record's proof code, no key: the lab's registered name and whether it is
// vetted, when it signed, and whether the report was later replaced or withdrawn. So anyone
// could read which records a lab had handled. Only the older form (plain SHA-256) was held
// back, and then only its hash and signature.
//
// Now every lab report signature, of either form, is listed and counted only for the delivery's
// sender (the holder) and lab, by holder key (server.js labDocReader). For anyone else every
// route answers as if it weren't stored: /attestations/subject (list and total), /verify (the
// signed and vetted summary), /embed, /records/:id, and the per-record ceilings on
// POST /attestations.
//
// The same rule for a lab's receipts (chain-of-custody) and for a genetic-fingerprint or
// inspection from a lab key, with the record's holder also a reader; and the holder's own
// choice to publish some on /verify (the grant's sharedAttestations). No network.
//
// SPDX-License-Identifier: Apache-2.0

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { createHash, randomBytes } from 'node:crypto';
import { canonicalise, sha256Hex, newNonce, generateKeypair, signAttestation, signRetraction, verifyAttestation } from 'veilcore-records';
import { untilReady, testBody, rememberSigner, labKeyProofHeader, labKeyProof } from './helpers.mjs';
import { ATTESTATION_LIMITS, registrationPayload } from '../lineage/attesters.mjs';

process.env.DB_PATH = ':memory:';
process.env.VEILCORE_OTS = 'off';
process.env.VEILCORE_OPERATOR_TOKEN = 'test-operator-token-at-least-32-chars';
const require = createRequire(import.meta.url);
const { app, db } = require('../server.js');

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
  return { status: res.status, json, text };
};

const LAB_NAME = 'Hidden Client Labs';

/** A vetted lab key: its name was matched by the operator, so /verify would say "vetted lab". */
const vettedLab = async () => {
  const kp = await generateKeypair();
  const reg = { publicKey: kp.publicKey, issuedAt: Date.now(), displayName: LAB_NAME, role: 'laboratory' };
  const priv = await crypto.subtle.importKey('pkcs8', Buffer.from(kp.privateKey, 'hex'), { name: 'Ed25519' }, false, ['sign']);
  const sig = await crypto.subtle.sign('Ed25519', priv, new TextEncoder().encode(registrationPayload(reg)));
  assert.equal((await call('POST', '/attesters', null, { ...reg, signature: Buffer.from(sig).toString('hex') })).status, 200);
  const vet = await call('POST', `/attesters/${kp.publicKey}/vetting`, null, {
    vetted: true,
    check: { source: 'licence-listing', sourceUrl: 'https://agriculture.example.gov/testing-labs', licenceNo: 'TL-0042', emailDomain: 'hiddenclient.example', checkedAt: new Date().toISOString().slice(0, 10), checkedBy: 'AB' },
  }, { 'x-operator-token': 'test-operator-token-at-least-32-chars' });
  assert.equal(vet.status, 200, JSON.stringify(vet.json));
  return kp;
};

/** A sender with a sealed record, an offer, and a lab that claimed it (as round6.test.mjs). */
const delivery = async () => {
  const committed = { breedingMethod: '', bredBy: 'B', dateCreated: '2026-01-01', loggedAt: '2026-01-01T00:00:00Z',
    nonce: newNonce(), notes: '', parents: [], photoFingerprints: [], refId: '', strainName: 'S' };
  const src = { id: `hl-${randomBytes(4).toString('hex')}`, ...committed, recordFingerprint: await sha256Hex(canonicalise(committed)) };
  const sender = key(), lab = key();
  assert.equal((await call('PUT', '/api/records', sender, [src])).status, 200);
  const o = await call('POST', '/transfers', sender, { sourceRecord: src.id, toHandle: 'lab@x' });
  assert.equal(o.status, 200, JSON.stringify(o.json));
  assert.equal((await call('POST', `/transfers/${o.json.transferId}/claim`, lab, { claimCode: o.json.claimCode })).status, 200);
  // Public checks read under the attestation-status grant, as a holder who shares their link.
  const g = await call('PUT', `/api/records/${src.id}/disclosure`, sender, { show: ['existence', 'attestation-status'] });
  assert.equal(g.status, 200, JSON.stringify(g.json));
  return { sender, lab, transferId: o.json.transferId, fingerprint: src.recordFingerprint, recordId: src.id };
};

const signs = async (kp, subjectCommitment, { type = 'laboratory-report', suffix = '_ld1', displayName = LAB_NAME } = {}) => {
  const signed = await signAttestation({
    attestationId: `att_${randomBytes(8).toString('hex')}${suffix}`, type, subjectCommitment, documentHash: sha(randomBytes(16)),
    hashAlgorithm: 'sha256', issuedAt: '2026-11-08T09:00:00Z', attester: { publicKey: kp.publicKey, displayName },
  }, kp.privateKey);
  const r = await call('POST', '/attestations', null, signed);
  assert.equal(r.status, 200, JSON.stringify(r.json));
  rememberSigner(signed.attestationId, kp);
  return signed;
};
const sendsBack = async (d, attestationId) => {
  const res = await fetch(`${base}/transfers/${d.transferId}/results?attestationId=${attestationId}`, {
    method: 'POST',
    headers: { 'content-type': 'application/octet-stream', 'x-holder-key': d.lab, ...(await labKeyProofHeader(d.transferId, attestationId)) },
    body: Buffer.concat([Buffer.from('age-encryption.org/v1\n-> X25519 abc\n'), randomBytes(64)]),
  });
  assert.equal(res.status, 200, await res.text());
};
const page = async (fp, holder, q = '') => (await call('GET', `/attestations/subject/${fp}${q}`, holder)).json;
const withdraw = async (kp, attestationId) => {
  const ret = await signRetraction({ attestationId, attesterPublicKey: kp.publicKey, reason: 'superseded', retractedAt: new Date().toISOString() }, kp.privateKey);
  assert.equal((await call('POST', `/attestations/${attestationId}/retract`, null, ret)).status, 200);
};

test('an outsider gets no lab report signature and no count, on every route; the lab is never named', async () => {
  const d = await delivery();
  const lab = await vettedLab();
  const report = await signs(lab, d.fingerprint);
  await sendsBack(d, report.attestationId);
  // An older-form one too (plain SHA-256), and the first report withdrawn as replaced.
  const older = await signs(lab, d.fingerprint, { suffix: '' });
  await sendsBack(d, older.attestationId);
  await withdraw(lab, report.attestationId);

  for (const who of [null, key()]) {
    const r = await page(d.fingerprint, who);
    assert.deepEqual([r.attestations, r.total], [[], 0], 'not listed, not counted');
    const deep = await page(d.fingerprint, who, '?offset=1&limit=1');
    assert.deepEqual([deep.attestations, deep.total], [[], 0], 'and no page further on shows one');
  }
  // /verify: a vetted lab's report used to turn on "attested by a vetted lab".
  const v = (await call('GET', `/verify/${d.recordId}`)).json;
  assert.equal(v.found ?? true, true);
  assert.equal(v.signedAttestation, false);
  assert.equal(v.attestedByVettedLab, false);
  assert.equal(v.attested, false);
  // Nothing anywhere public names the lab, its key, the report ids, or the date it signed.
  const embed = (await call('GET', `/embed/${encodeURIComponent(d.recordId)}`)).text;
  assert.match(embed, /vc-/, 'the embed answered');
  const pub = [JSON.stringify(v), embed, (await call('GET', `/records/${encodeURIComponent(d.recordId)}`)).text];
  for (const text of pub) {
    for (const secret of [LAB_NAME, lab.publicKey, report.attestationId, older.attestationId, '2026-11-08T09:00:00Z']) {
      assert.ok(!text.includes(secret), `public answer leaks ${secret.slice(0, 24)}`);
    }
  }
});

test('the holder (delivery sender) and the lab still see every report: name, vetting, date, withdrawal', async () => {
  const d = await delivery();
  const lab = await vettedLab();
  const report = await signs(lab, d.fingerprint);
  await sendsBack(d, report.attestationId);
  const older = await signs(lab, d.fingerprint, { suffix: '' });
  await sendsBack(d, older.attestationId);
  await withdraw(lab, report.attestationId);

  for (const who of [d.sender, d.lab]) {
    const r = await page(d.fingerprint, who);
    assert.equal(r.total, 2);
    assert.deepEqual(r.attestations.map((a) => a.attestationId).sort(), [report.attestationId, older.attestationId].sort());
    for (const a of r.attestations) {
      assert.equal(a.type, 'laboratory-report');
      assert.equal(a.issuedAt, '2026-11-08T09:00:00Z');
      assert.equal(a.vettedAttester, true);
      assert.equal(a.registeredAs.displayName, LAB_NAME);
      assert.equal(a.documentWithheld, undefined, 'served whole');
      const { strength, vettedAttester, registeredAs, retraction, ...asSigned } = a;
      void strength; void vettedAttester; void registeredAs; void retraction;
      assert.equal(await verifyAttestation(asSigned), true);
    }
    assert.ok(r.attestations.find((a) => a.attestationId === report.attestationId).retraction, 'the withdrawal is shown');
    assert.equal(r.attestations.find((a) => a.attestationId === older.attestationId).retraction, null);
  }
  // The holder's evidence bundle carries them, and counts them.
  const ev = (await call('GET', `/records/${encodeURIComponent(d.recordId)}/evidence`, d.sender)).json;
  assert.equal(ev.attestationsTotal, 2);
  assert.equal(ev.attestations.length, 2);
});

test('the lab of one delivery does not see another lab’s report on the same plant', async () => {
  const d = await delivery();
  const labA = await vettedLab();
  const a = await signs(labA, d.fingerprint);
  await sendsBack(d, a.attestationId);
  // A second delivery of the same record, to another lab, which sends nothing back yet.
  const o = await call('POST', '/transfers', d.sender, { sourceRecord: d.recordId, toHandle: 'other@x' });
  assert.equal(o.status, 200, JSON.stringify(o.json));
  const otherLab = key();
  assert.equal((await call('POST', `/transfers/${o.json.transferId}/claim`, otherLab, { claimCode: o.json.claimCode })).status, 200);
  assert.deepEqual([(await page(d.fingerprint, otherLab)).total, (await page(d.fingerprint, otherLab)).attestations], [0, []]);
  assert.equal((await page(d.fingerprint, d.sender)).total, 1, 'the breeder sees both deliveries’ reports');
});

test('other signatures stay public, and pages and totals count only what the reader can see', async () => {
  const d = await delivery();
  const lab = await vettedLab();
  const inspector = await generateKeypair();
  const insp = await signs(inspector, d.fingerprint, { type: 'inspection', suffix: '', displayName: 'Field Inspector' });
  for (let i = 0; i < 3; i++) {
    const r = await signs(lab, d.fingerprint);
    await sendsBack(d, r.attestationId);
  }
  const out = await page(d.fingerprint, null);
  assert.equal(out.total, 1);
  assert.deepEqual(out.attestations.map((a) => a.attestationId), [insp.attestationId]);
  assert.deepEqual((await page(d.fingerprint, null, '?offset=1')).attestations, []);
  // /verify still says there is a signature: the inspector's, which is public. Not a vetted one.
  const v = (await call('GET', `/verify/${d.recordId}`)).json;
  assert.equal(v.signedAttestation, true);
  assert.equal(v.attestedByVettedLab, false, 'only the vetted lab’s report could have said so');
  // The holder: all four, paged in the same order, vetted signers first.
  const mine = await page(d.fingerprint, d.sender);
  assert.equal(mine.total, 4);
  assert.equal(mine.attestations.length, 4);
  assert.equal(mine.attestations.at(-1).attestationId, insp.attestationId, 'vetted signers first');
  const second = await page(d.fingerprint, d.sender, '?offset=3&limit=1');
  assert.deepEqual([second.total, second.attestations.map((a) => a.attestationId)], [4, [insp.attestationId]]);
});

test('the per-record ceilings another signer meets do not depend on whether a lab report is stored', async () => {
  const d = await delivery();
  const lab = await generateKeypair(); // not vetted: its report would have counted against the unvetted ceiling
  const r = await signs(lab, d.fingerprint);
  await sendsBack(d, r.attestationId);
  // A stranger fills the unvetted ceiling to one short, as hardening-roundD.test.mjs does.
  const ins = db.prepare('INSERT INTO attestations (attestation_id, subject_commitment, attester_key, body, created_at) VALUES (?,?,?,?,?)');
  db.transaction(() => {
    for (let i = 0; i < ATTESTATION_LIMITS.unvettedPerSubject - 1; i++) {
      const pk = randomBytes(32).toString('hex');
      const id = `hl-junk-${d.fingerprint.slice(0, 8)}-${i}`;
      ins.run(id, d.fingerprint, pk, JSON.stringify({ attestationId: id, type: 'inspection', subjectCommitment: d.fingerprint, signature: 'ff', attester: { publicKey: pk } }), Date.now());
    }
  })();
  // The 100th is accepted, exactly as on a record with no lab report: before, the lab's report
  // filled that place and this was refused, which told the stranger a lab had signed.
  const stranger = await generateKeypair();
  const hundredth = await signAttestation({ attestationId: `att_${randomBytes(8).toString('hex')}`, type: 'inspection', subjectCommitment: d.fingerprint,
    documentHash: sha('x'), hashAlgorithm: 'sha256', issuedAt: '2026-11-08T10:00:00Z', attester: { publicKey: stranger.publicKey } }, stranger.privateKey);
  assert.equal((await call('POST', '/attestations', null, hundredth)).status, 200);
  const next = await signAttestation({ ...hundredth, attestationId: `att_${randomBytes(8).toString('hex')}`, signature: undefined }, stranger.privateKey);
  const refused = await call('POST', '/attestations', null, next);
  assert.equal(refused.status, 400);
  assert.match(refused.json.error, new RegExp(`${ATTESTATION_LIMITS.unvettedPerSubject} attestations from keys nobody has vetted`));
  // And the lab's own ceiling is separate: another lab report is still accepted.
  const more = await signs(lab, d.fingerprint);
  assert.ok(more.attestationId);
});

test('BLOCKER 12 Nov: throwaway keys whose signatures turn private later can’t fill a record’s ceilings and keep a vetted lab out', async () => {
  // The attack, at full size: a fresh key posts 100 genetic-fingerprint signatures on the
  // victim's record (the public unvetted ceiling), then one lab report about a subject of its
  // own. That report makes the key a lab key, its 100 signatures turn private, and counted by
  // the live test they left the public places and took 100 private ones. Ten rounds filled the
  // 1000 private places, which vetted labs shared, and the lab's report here was refused.
  const d = await delivery();
  const post = async (signed) => (await call('POST', '/attestations', null, signed)).status;
  let accepted = 0;
  for (let round = 0; round < 10; round++) {
    const k = await generateKeypair();
    for (let i = 0; i < ATTESTATION_LIMITS.unvettedPerSubject; i++) {
      const fp = await signAttestation({
        attestationId: `att_${randomBytes(8).toString('hex')}`, type: 'genetic-fingerprint', subjectCommitment: d.fingerprint,
        documentHash: sha(randomBytes(16)), hashAlgorithm: 'sha256', issuedAt: '2026-11-12T09:00:00Z', attester: { publicKey: k.publicKey },
      }, k.privateKey);
      const s = await post(fp);
      assert.ok(s === 200 || s === 400, `status ${s}`);
      if (s === 200) accepted++;
    }
    await signs(k, key(), { displayName: 'Throwaway' });
  }
  // Each signature keeps the place it took when stored: the first key's 100 fill the public
  // unvetted places for good, and turning private later frees none of them.
  assert.equal(accepted, ATTESTATION_LIMITS.unvettedPerSubject);
  // A vetted lab still signs its report and receipt on the record, and sends the result back.
  const lab = await vettedLab();
  const report = await signs(lab, d.fingerprint);
  await sendsBack(d, report.attestationId);
  await signs(lab, d.fingerprint, { type: 'chain-of-custody', suffix: '' });
  // Stored places, as counted.
  const places = db.prepare(`SELECT ceiling_private AS p, ceiling_vetted AS v, COUNT(*) AS n FROM attestations
    WHERE subject_commitment = ? GROUP BY 1, 2 ORDER BY 1, 2`).all(d.fingerprint).map((r) => [r.p, r.v, r.n]);
  assert.deepEqual(places, [[0, 0, ATTESTATION_LIMITS.unvettedPerSubject], [1, 1, 2]]);
});

test('a vetted lab is never counted with unvetted keys: a full unvetted private ceiling leaves its place open', async () => {
  const d = await delivery();
  // 100 private signatures from keys nobody vetted (lab reports): the unvetted private ceiling.
  for (let i = 0; i < ATTESTATION_LIMITS.unvettedPrivatePerSubject; i++) await signs(await generateKeypair(), d.fingerprint, { displayName: 'Junk' });
  const one = await generateKeypair();
  const signed = await signAttestation({ attestationId: `att_${randomBytes(8).toString('hex')}_ld1`, type: 'laboratory-report', subjectCommitment: d.fingerprint,
    documentHash: sha('y'), hashAlgorithm: 'sha256', issuedAt: '2026-11-12T09:00:00Z', attester: { publicKey: one.publicKey } }, one.privateKey);
  const refused = await call('POST', '/attestations', null, signed);
  assert.equal(refused.status, 400);
  assert.match(refused.json.error, /from keys nobody has vetted/);
  const lab = await vettedLab();
  await signs(lab, d.fingerprint);
});

test('existing rows get their stored ceiling once, as submit would have put them then', async () => {
  const { default: Database } = await import('better-sqlite3');
  const { createAttesters } = await import('../lineage/attesters.mjs');
  const old = new Database(':memory:');
  // The table as it was before the ceiling columns.
  old.exec(`CREATE TABLE attesters (public_key TEXT PRIMARY KEY, attester_id TEXT NOT NULL, display_name TEXT, role TEXT,
      accreditation TEXT, registered_at INTEGER NOT NULL);
    CREATE TABLE attestations (attestation_id TEXT PRIMARY KEY, subject_commitment TEXT NOT NULL, attester_key TEXT NOT NULL,
      body TEXT NOT NULL, created_at INTEGER NOT NULL);`);
  const ins = old.prepare('INSERT INTO attestations VALUES (?,?,?,?,?)');
  const row = (id, type, k, role) => ins.run(id, 's', k, JSON.stringify({ attestationId: id, type, subjectCommitment: 's', attester: { publicKey: k, ...(role ? { role } : {}) } }), 1);
  row('fp-before', 'genetic-fingerprint', 'k1');   // before k1's first lab report: was public
  row('rep', 'laboratory-report', 'k1');           // always private
  row('fp-after', 'genetic-fingerprint', 'k1');    // after it: private
  row('insp-role', 'inspection', 'k2', 'Laboratory'); // signed role: private
  row('insp-reg', 'inspection', 'k3');             // registered role: private
  row('fp-other', 'genetic-fingerprint', 'k4');    // nothing says lab: public
  row('cust', 'chain-of-custody', 'k4');           // private; k4's earlier fingerprint stays public
  old.prepare('INSERT INTO attesters (public_key, attester_id, role, registered_at) VALUES (?,?,?,?)').run('k3', 'x', 'laboratory', 1);
  createAttesters(old);
  const got = Object.fromEntries(old.prepare('SELECT attestation_id AS id, ceiling_private AS p, ceiling_vetted AS v FROM attestations').all().map((r) => [r.id, [r.p, r.v]]));
  assert.deepEqual(got, {
    'fp-before': [0, 0], rep: [1, 0], 'fp-after': [1, 0], 'insp-role': [1, 0], 'insp-reg': [1, 0], 'fp-other': [0, 0], cust: [1, 0],
  });
  // Run again on start: nothing changes.
  old.prepare("UPDATE attestations SET ceiling_private = 0 WHERE attestation_id = 'fp-after'").run();
  createAttesters(old);
  assert.equal(old.prepare("SELECT ceiling_private AS p FROM attestations WHERE attestation_id = 'fp-after'").get().p, 0, 'backfilled once, not on every start');
  old.close();
});

// ---------------------------------------------------------------------------------------
// Receipts, and a lab key's other signatures (8 Nov 2026, the maintainer's rule: nothing about
// who handled what is public unless the holder chooses to share it).
// ---------------------------------------------------------------------------------------

const committedOf = (r) => ({ breedingMethod: r.breedingMethod ?? '', bredBy: r.bredBy, dateCreated: r.dateCreated,
  loggedAt: r.loggedAt, nonce: r.nonce, notes: r.notes, parents: r.parents ?? [],
  photoFingerprints: r.photoFingerprints ?? [], refId: r.refId ?? '', strainName: r.strainName });

/** As delivery(), and the lab seals the record its claim made, as the app does (round3.test.mjs). */
const sealedDelivery = async () => {
  const d = await delivery();
  const stub = (await call('GET', '/api/records', d.lab)).json.find((r) => r.transferId === d.transferId);
  assert.ok(stub, 'the claim made the lab a record');
  const received = { ...stub, bredBy: 'B', dateCreated: '2026-01-01', notes: '', parents: [], photoFingerprints: [],
    breedingMethod: '', refId: '', nonce: newNonce(), loggedAt: stub.receivedAt };
  const sealed = { ...received, recordFingerprint: await sha256Hex(canonicalise(committedOf(received))) };
  const put = await call('PUT', '/api/records', d.lab, [sealed]);
  assert.equal(put.json.count, 1, JSON.stringify(put.json));
  return { ...d, received: sealed };
};
const signsAs = async (kp, subjectCommitment, documentHash, type, attester = {}) => {
  const signed = await signAttestation({
    attestationId: `att_${randomBytes(8).toString('hex')}`, type, subjectCommitment, documentHash,
    hashAlgorithm: 'sha256', issuedAt: '2026-11-08T11:00:00Z', attester: { publicKey: kp.publicKey, displayName: LAB_NAME, ...attester },
  }, kp.privateKey);
  const r = await call('POST', '/attestations', null, signed);
  assert.equal(r.status, 200, JSON.stringify(r.json));
  rememberSigner(signed.attestationId, kp);
  return signed;
};
const share = (d, list, show = ['existence', 'attestation-status']) =>
  call('PUT', `/api/records/${d.recordId}/disclosure`, d.sender, { show, forFingerprint: d.fingerprint, values: { sharedAttestations: list } });
const ids = (list) => list.map((a) => a.attestationId).sort();

test('a lab’s receipt is private: the lab sees it before and after tying it on, the sender after; nobody else', async () => {
  const d = await sealedDelivery();
  const lab = await vettedLab();
  const receipt = await signsAs(lab, d.fingerprint, d.received.recordFingerprint, 'chain-of-custody');
  // Signed, not yet tied to the delivery: the lab finds its own receipt (the site's labReceipt).
  assert.deepEqual(ids((await page(d.fingerprint, d.lab)).attestations), [receipt.attestationId]);
  assert.equal((await call('POST', `/transfers/${d.transferId}/receipt`, d.lab, { attestationId: receipt.attestationId })).status, 200);
  for (const who of [d.sender, d.lab]) assert.deepEqual(ids((await page(d.fingerprint, who)).attestations), [receipt.attestationId]);
  for (const who of [null, key()]) assert.deepEqual([(await page(d.fingerprint, who)).total, (await page(d.fingerprint, who)).attestations], [0, []]);
  const v = (await call('GET', `/verify/${d.recordId}`)).json;
  assert.equal(v.signedAttestation, false);
  assert.equal(v.attestedByVettedLab, false);
  assert.ok(!JSON.stringify(v).includes(LAB_NAME));
  assert.ok(!(await call('GET', `/embed/${encodeURIComponent(d.recordId)}`)).text.includes(LAB_NAME));
});

test('a genetic-fingerprint or inspection from a lab key is private; from any other key, public', async () => {
  const d = await delivery();
  // Lab keys three ways: registered as a laboratory (and vetted), the role in what it signed,
  // and a key with nothing but a lab report signed here.
  const registered = await vettedLab();
  const selfSaid = await generateKeypair();
  const reporter = await generateKeypair();
  await signs(reporter, H64());
  const priv = [
    await signsAs(registered, d.fingerprint, sha('a'), 'genetic-fingerprint'),
    await signsAs(selfSaid, d.fingerprint, sha('b'), 'inspection', { role: 'laboratory' }),
    await signsAs(reporter, d.fingerprint, sha('c'), 'genetic-fingerprint'),
  ];
  const someone = await generateKeypair();
  const pub = await signsAs(someone, d.fingerprint, sha('d'), 'inspection', { displayName: 'A neighbour' });
  const out = await page(d.fingerprint, null);
  assert.deepEqual([ids(out.attestations), out.total], [[pub.attestationId], 1]);
  const v = (await call('GET', `/verify/${d.recordId}`)).json;
  assert.equal(v.signedAttestation, true, 'the public one');
  assert.equal(v.attestedByVettedLab, false, 'the vetted lab’s genetic-fingerprint is not counted');
  // The record's holder sees all four.
  assert.deepEqual(ids((await page(d.fingerprint, d.sender)).attestations), ids([...priv, pub]));
});
const H64 = () => randomBytes(32).toString('hex');

test('the record’s holder sees a lab’s signature with no delivery; a lab sees only its own on that plant', async () => {
  const d = await sealedDelivery();
  const labA = await vettedLab();
  const report = await signs(labA, d.fingerprint);
  await sendsBack(d, report.attestationId);
  // labA's genetic-fingerprint on the plant: the lab that claimed sees it (its key signed a
  // report on its delivery), as does the breeder.
  const gf = await signsAs(labA, d.fingerprint, sha('gf'), 'genetic-fingerprint');
  // Another lab key's signature on the same plant, tied to no delivery of this lab's.
  const labB = await generateKeypair();
  const other = await signsAs(labB, d.fingerprint, sha('other'), 'genetic-fingerprint', { role: 'laboratory' });
  assert.deepEqual(ids((await page(d.fingerprint, d.lab)).attestations), ids([report, gf]));
  assert.deepEqual(ids((await page(d.fingerprint, d.sender)).attestations), ids([report, gf, other]));
});

test('tying someone else’s signature to your own delivery is refused, and a tie stored anyway shows you nothing', async () => {
  const d = await delivery();
  const lab = await vettedLab();
  const report = await signs(lab, d.fingerprint);
  await sendsBack(d, report.attestationId);
  // An attacker with the id (say from a holder's shared list) sends their own "result" on a
  // delivery of a plant of their own, naming it: refused (lab-results.mjs signatureProblem).
  const own = await delivery();
  const res = await fetch(`${base}/transfers/${own.transferId}/results?attestationId=${report.attestationId}`, {
    method: 'POST', headers: { 'content-type': 'application/octet-stream', 'x-holder-key': own.lab },
    body: Buffer.concat([Buffer.from('age-encryption.org/v1\n-> X25519 abc\n'), randomBytes(64)]),
  });
  assert.equal(res.status, 400);
  assert.match((await res.json()).error, /different plant/);
  // A row stored before that check (or by any other path) still counts for nothing: the tie
  // must be on a delivery of the plant the signature is about (server.js privateReaderFor).
  db.prepare(`INSERT INTO lab_results (id, transfer_id, size, sha256, attestation_id, created_at, receiver)
    VALUES (?,?,?,?,?,?,?)`).run(`LR-${randomBytes(16).toString('hex').toUpperCase()}`, own.transferId, 1, sha('x'), report.attestationId, Date.now(), 'x');
  for (const who of [own.lab, own.sender]) assert.deepEqual((await page(d.fingerprint, who)).attestations, []);
});

const upload = async (d, attestationId, holder = d.lab, proof = true) => {
  const res = await fetch(`${base}/transfers/${d.transferId}/results?attestationId=${encodeURIComponent(attestationId)}`, {
    method: 'POST', headers: { 'content-type': 'application/octet-stream', 'x-holder-key': holder, ...(proof ? await labKeyProofHeader(d.transferId, attestationId) : {}) },
    body: Buffer.concat([Buffer.from('age-encryption.org/v1\n-> X25519 abc\n'), randomBytes(64)]),
  });
  return { status: res.status, json: await res.json() };
};

test('a result names only a lab report signature by that lab’s key about the plant the delivery sent', async () => {
  const d = await sealedDelivery();
  const lab = await generateKeypair();
  const other = await generateKeypair();
  // Not stored; not a lab report; about another plant; withdrawn.
  assert.equal((await upload(d, 'att_not_stored')).status, 404);
  const receiptLike = await signsAs(lab, d.fingerprint, sha('r'), 'inspection');
  assert.equal((await upload(d, receiptLike.attestationId)).status, 400);
  const elsewhere = await signs(lab, H64());
  assert.match((await upload(d, elsewhere.attestationId)).json.error, /different plant/);
  const gone = await signs(lab, d.fingerprint);
  await withdraw(lab, gone.attestationId);
  assert.equal((await upload(d, gone.attestationId)).status, 409);
  // The receipt sets the lab's key: once the lab has signed one, another key's report is refused.
  const receipt = await signsAs(lab, d.fingerprint, d.received.recordFingerprint, 'chain-of-custody');
  const strangers = await signs(other, d.fingerprint);
  assert.equal((await upload(d, strangers.attestationId)).status, 403, 'a receipt signed, not yet tied on');
  assert.equal((await call('POST', `/transfers/${d.transferId}/receipt`, d.lab, { attestationId: receipt.attestationId })).status, 200);
  assert.equal((await upload(d, strangers.attestationId)).status, 403, 'and tied on');
  const ok = await signs(lab, d.fingerprint);
  assert.equal((await upload(d, ok.attestationId)).status, 200);
  // Only the lab that claimed uploads at all (as before).
  assert.equal((await upload(d, ok.attestationId, d.sender)).status, 403);
});

test('with no receipt, the first report’s key is the lab’s; another key’s report after it is refused', async () => {
  const d = await delivery();
  const lab = await generateKeypair();
  const first = await signs(lab, d.fingerprint);
  assert.equal((await upload(d, first.attestationId)).status, 200, 'the site allows a report before the receipt');
  const other = await signs(await generateKeypair(), d.fingerprint);
  assert.equal((await upload(d, other.attestationId)).status, 403);
  assert.equal((await upload(d, (await signs(lab, d.fingerprint)).attestationId)).status, 200);
});

test('custody lines name a receipt’s id only when the holder shares that receipt', async () => {
  const d = await sealedDelivery();
  const lab = await vettedLab();
  const receipt = await signsAs(lab, d.fingerprint, d.received.recordFingerprint, 'chain-of-custody');
  assert.equal((await call('POST', `/transfers/${d.transferId}/receipt`, d.lab, { attestationId: receipt.attestationId })).status, 200);
  const report = await signs(lab, d.fingerprint);
  await sendsBack(d, report.attestationId);
  const reads = async () => ({
    verify: (await call('GET', `/verify/${d.recordId}`)).json,
    record: (await call('GET', `/records/${encodeURIComponent(d.recordId)}`)).json,
    embed: (await call('GET', `/embed/${encodeURIComponent(d.recordId)}`)).text,
  });
  // Granted attestation-status, nothing shared: the custody line is there, without the id.
  let r = await reads();
  assert.ok(r.verify.custody?.length, JSON.stringify(r.verify));
  assert.ok(r.record.custody?.length);
  for (const line of [...r.verify.custody, ...r.record.custody]) assert.equal(line.receiptAttestationId, undefined);
  for (const text of [JSON.stringify(r.verify), JSON.stringify(r.record), r.embed]) assert.ok(!text.includes(receipt.attestationId));
  // The report shared, not the receipt: still no receipt id.
  assert.equal((await share(d, [report.attestationId])).status, 200);
  r = await reads();
  for (const text of [JSON.stringify(r.verify), JSON.stringify(r.record), r.embed]) assert.ok(!text.includes(receipt.attestationId));
  // The receipt shared: its id on each line, and the receipt itself on /verify.
  assert.equal((await share(d, [report.attestationId, receipt.attestationId])).status, 200);
  r = await reads();
  assert.deepEqual(r.verify.custody.map((l) => l.receiptAttestationId), [receipt.attestationId]);
  assert.deepEqual(r.record.custody.map((l) => l.receiptAttestationId), [receipt.attestationId]);
  assert.deepEqual(r.verify.sharedAttestations.map((a) => a.attestationId), [report.attestationId, receipt.attestationId]);
});

// ---------------------------------------------------------------------------------------
// The holder chooses: values.sharedAttestations under attestation-status, answered by /verify.
// ---------------------------------------------------------------------------------------


test('/verify answers exactly the signatures the holder shares, and nothing else', async () => {
  const d = await sealedDelivery();
  const lab = await vettedLab();
  const r1 = await signs(lab, d.fingerprint);
  await sendsBack(d, r1.attestationId);
  const r2 = await signs(lab, d.fingerprint);
  await sendsBack(d, r2.attestationId);
  const receipt = await signsAs(lab, d.fingerprint, d.received.recordFingerprint, 'chain-of-custody');
  assert.equal((await call('POST', `/transfers/${d.transferId}/receipt`, d.lab, { attestationId: receipt.attestationId })).status, 200);

  const put = await share(d, [r1.attestationId, receipt.attestationId]);
  assert.equal(put.status, 200, JSON.stringify(put.json));
  const v = (await call('GET', `/verify/${d.recordId}`)).json;
  assert.deepEqual(v.sharedAttestations.map((a) => a.attestationId), [r1.attestationId, receipt.attestationId]);
  for (const a of v.sharedAttestations) {
    assert.equal(a.registeredAs.displayName, LAB_NAME);
    assert.equal(a.vettedAttester, true);
    const { strength, vettedAttester, registeredAs, retraction, ...asSigned } = a;
    void strength; void vettedAttester; void registeredAs; void retraction;
    assert.equal(await verifyAttestation(asSigned), true);
  }
  assert.ok(!JSON.stringify(v).includes(r2.attestationId), 'the unshared report is not there');
  // By proof code, exactly the shared ones too (12 Nov 2026, shared-by-proof-code.test.mjs),
  // and nothing else private: not the unshared report.
  const byCode = await page(d.fingerprint, null);
  assert.deepEqual(ids(byCode.attestations), ids([r1, receipt]));
  assert.equal(byCode.total, 2);
  assert.equal(v.signedAttestation, false, 'the summary still counts only public signatures');
  // ?show= without attestation-status, or a grant without it: none.
  assert.equal((await call('GET', `/verify/${d.recordId}?show=existence`)).json.sharedAttestations, undefined);
  assert.equal((await share(d, [r1.attestationId], ['existence'])).status, 400, 'only with the attestation-status grant');
  assert.equal((await call('PUT', `/api/records/${d.recordId}/disclosure`, d.sender, { show: ['existence'], forFingerprint: d.fingerprint })).status, 200);
  assert.equal((await call('GET', `/verify/${d.recordId}`)).json.sharedAttestations, undefined);
  // The lab withdraws one: still shared, with its withdrawal shown.
  assert.equal((await share(d, [r1.attestationId])).status, 200);
  await withdraw(lab, r1.attestationId);
  assert.ok((await call('GET', `/verify/${d.recordId}`)).json.sharedAttestations[0].retraction);
});

test('a grant can’t name another holder’s signatures, an unknown id, or one about another record', async () => {
  const d = await delivery();
  const lab = await vettedLab();
  const theirs = await delivery();
  const theirReport = await signs(lab, theirs.fingerprint);
  await sendsBack(theirs, theirReport.attestationId);
  const mine = await signs(lab, d.fingerprint);
  await sendsBack(d, mine.attestationId);
  const answers = [];
  for (const bad of [theirReport.attestationId, 'att_does_not_exist']) {
    const r = await share(d, [mine.attestationId, bad]);
    assert.equal(r.status, 400, JSON.stringify(r.json));
    assert.match(r.json.error, /not a signature about this record that this holder key can see/);
    answers.push(r.json.error.replace(bad.slice(0, 80), 'ID'));
  }
  assert.equal(answers[0], answers[1], 'the same answer whether the id exists or not');
  // Nothing was stored by the refusals; and even a grant stored by hand can't publish theirs.
  assert.equal((await call('GET', `/verify/${d.recordId}`)).json.sharedAttestations, undefined);
  db.prepare('UPDATE disclosure_grants SET grant_values = ? WHERE record_id = ?')
    .run(JSON.stringify({ sharedAttestations: [theirReport.attestationId, mine.attestationId] }), d.recordId);
  db.prepare('UPDATE disclosure_grants SET show = ?, for_fingerprint = ? WHERE record_id = ?')
    .run(JSON.stringify(['existence', 'attestation-status']), d.fingerprint, d.recordId);
  assert.deepEqual((await call('GET', `/verify/${d.recordId}`)).json.sharedAttestations.map((a) => a.attestationId), [mine.attestationId]);
  // Shape: too many, repeated, not strings.
  for (const v of [Array.from({ length: 51 }, (_, i) => `a${i}`), [mine.attestationId, mine.attestationId], [42]]) {
    assert.equal((await share(d, v)).status, 400);
  }
});

// ---------------------------------------------------------------------------------------
// Fingerprint takeover (verifier, 9 Nov 2026): a fingerprint released by a deletion or an
// edit could be stored by anyone with the old proof code, who then counted as its holder.
// ---------------------------------------------------------------------------------------

/** A fresh sealed record body (not stored), with its fingerprint. */
const fresh = async (strainName = 'T') => {
  const committed = { breedingMethod: '', bredBy: 'B', dateCreated: '2026-01-01', loggedAt: '2026-01-01T00:00:00Z',
    nonce: newNonce(), notes: '', parents: [], photoFingerprints: [], refId: '', strainName };
  return { id: `hl-${randomBytes(4).toString('hex')}`, ...committed, recordFingerprint: await sha256Hex(canonicalise(committed)) };
};
/** A lab report and a receipt on the delivery's plant, both tied on. */
const handled = async () => {
  const d = await sealedDelivery();
  const lab = await vettedLab();
  const receipt = await signsAs(lab, d.fingerprint, d.received.recordFingerprint, 'chain-of-custody');
  assert.equal((await call('POST', `/transfers/${d.transferId}/receipt`, d.lab, { attestationId: receipt.attestationId })).status, 200);
  const report = await signs(lab, d.fingerprint);
  await sendsBack(d, report.attestationId);
  return { d, lab, receipt, report };
};
const takesOver = (who, fp) => fresh('Taken').then((r) => call('PUT', '/api/records', who, [{ ...r, recordFingerprint: fp }]));

test('PROBE A: after the holder deletes the record, a stranger can’t store its fingerprint or read its lab signatures', async () => {
  const { d } = await handled();
  assert.equal((await call('DELETE', '/api/records', d.sender, { ids: [d.recordId] })).status, 200);
  const stranger = key();
  const put = await takesOver(stranger, d.fingerprint);
  assert.equal(put.json.count, 0, JSON.stringify(put.json));
  assert.match(put.json.rejected[0].reason, /already registered by another holder/);
  assert.deepEqual([(await page(d.fingerprint, stranger)).total, (await page(d.fingerprint, stranger)).attestations], [0, []]);
  // The breeder, its first holder, still sees both, record deleted or not.
  assert.equal((await page(d.fingerprint, d.sender)).total, 2);
  // And may store it again.
  const again = await fresh();
  assert.equal((await call('PUT', '/api/records', d.sender, [{ ...again, recordFingerprint: d.fingerprint }])).json.count, 1);
});

test('the first holder saves its record again, and again: the first-holder row is kept, nothing fails', async () => {
  const { d } = await handled();
  const mine = (await call('GET', '/api/records', d.sender)).json.find((r) => r.id === d.recordId);
  for (let i = 0; i < 2; i++) assert.equal((await call('PUT', '/api/records', d.sender, [mine])).json.count, 1);
  const row = db.prepare('SELECT holder_key, first_at FROM fingerprint_holders WHERE fingerprint = ?').get(d.fingerprint);
  assert.ok(row && row.first_at <= Date.now());
  assert.equal((await page(d.fingerprint, d.sender)).total, 2);
});

test('PROBE B: after the holder edits the record, a stranger can’t date the old fingerprint or read its lab signatures', async () => {
  const { d } = await handled();
  // The breeder edits: the record's fingerprint changes, releasing the old one.
  const edited = await fresh('Edited');
  assert.equal((await call('PUT', '/api/records', d.sender, [{ ...edited, id: d.recordId }])).json.count, 1);
  const stranger = key();
  const dating = await call('PUT', '/api/records/dating', stranger, [{ id: `hl-${randomBytes(4).toString('hex')}`, recordFingerprint: d.fingerprint }]);
  assert.ok(!(dating.json.dated ?? []).length, JSON.stringify(dating.json));
  assert.match(JSON.stringify(dating.json), /already registered by another holder/);
  assert.equal((await takesOver(stranger, d.fingerprint)).json.count, 0);
  assert.deepEqual((await page(d.fingerprint, stranger)).attestations, []);
  // The stranger can't publish them on a /verify of their own either.
  const own = await fresh();
  assert.equal((await call('PUT', '/api/records', stranger, [own])).status, 200);
  const g = await call('PUT', `/api/records/${own.id}/disclosure`, stranger, {
    show: ['attestation-status'], forFingerprint: own.recordFingerprint, values: { sharedAttestations: [(await page(d.fingerprint, d.sender)).attestations[0].attestationId] },
  });
  assert.equal(g.status, 400);
});

test('a holder or sender counts only from before the signature: a takeover that got past the guard reads nothing', async () => {
  const { d } = await handled();
  // As if the fingerprint had been taken before the guard existed: the record and its
  // first-holder row gone, and a stranger stores it, then offers a delivery of it.
  db.prepare('DELETE FROM fingerprint_holders WHERE fingerprint = ?').run(d.fingerprint);
  assert.equal((await call('DELETE', '/api/records', d.sender, { ids: [d.recordId] })).status, 200);
  db.prepare('DELETE FROM fingerprint_holders WHERE fingerprint = ?').run(d.fingerprint);
  const stranger = key();
  const taken = await fresh();
  assert.equal((await call('PUT', '/api/records', stranger, [{ ...taken, recordFingerprint: d.fingerprint }])).json.count, 1);
  assert.equal((await call('POST', '/transfers', stranger, { sourceRecord: taken.id, toHandle: 'me@x' })).status, 200);
  assert.deepEqual([(await page(d.fingerprint, stranger)).total, (await page(d.fingerprint, stranger)).attestations], [0, []]);
  // The breeder, who sent a delivery before the lab signed, still does.
  assert.equal((await page(d.fingerprint, d.sender)).total, 2);
});

test('the first-holder table is backfilled from the earliest holder, records and deliveries alike', async () => {
  const Database = (await import('better-sqlite3')).default;
  const { setupFingerprintHolders } = require('../fingerprint-holders.js');
  const { asStored } = require('../holder-key.js');
  const m = new Database(':memory:');
  m.exec(`CREATE TABLE records (id TEXT PRIMARY KEY, holder_key TEXT NOT NULL, body TEXT NOT NULL, updated_at INTEGER NOT NULL, first_seen INTEGER);
          CREATE TABLE transfers (id TEXT PRIMARY KEY, from_holder TEXT, created_at INTEGER, source_fingerprint TEXT);`);
  const [fpTaken, fpPlain, fpGone] = [H64(), H64(), H64()];
  const [breeder, taker, other, gone] = [asStored(key()), asStored(key()), asStored(key()), key()];
  const rec = m.prepare('INSERT INTO records VALUES (?,?,?,?,?)');
  rec.run('r1', taker, JSON.stringify({ recordFingerprint: fpTaken }), 2000, 2000); // taken over later...
  m.prepare('INSERT INTO transfers VALUES (?,?,?,?)').run('t1', breeder, 1000, fpTaken); // ...the breeder sent it first
  rec.run('r2', other, JSON.stringify({ recordFingerprint: fpPlain }), 500, 500);
  m.prepare('INSERT INTO transfers VALUES (?,?,?,?)').run('t2', gone, 300, fpGone); // record deleted; plain-text key from older code
  rec.run('r3', other, JSON.stringify({ strainName: 'no fingerprint' }), 1, 1);
  assert.equal(setupFingerprintHolders(m, asStored), 3);
  const row = (fp) => m.prepare('SELECT holder_key, first_at FROM fingerprint_holders WHERE fingerprint = ?').get(fp);
  assert.deepEqual(row(fpTaken), { holder_key: breeder, first_at: 1000 });
  assert.deepEqual(row(fpPlain), { holder_key: other, first_at: 500 });
  assert.deepEqual(row(fpGone), { holder_key: asStored(gone), first_at: 300 });
  // Once only; then the triggers keep it, first holder kept.
  assert.equal(setupFingerprintHolders(m, asStored), 0);
  const fpNew = H64();
  rec.run('r4', other, JSON.stringify({ recordFingerprint: fpNew }), 3000, 3000);
  m.prepare('UPDATE records SET body = ? WHERE id = ?').run(JSON.stringify({ recordFingerprint: fpNew }), 'r1');
  assert.deepEqual(row(fpNew), { holder_key: other, first_at: 3000 });
  m.close();
});

test('PROBE C: a lab that claimed another delivery of the plant can’t tie a leaked report id as its first report', async () => {
  // Lab A's delivery: report signed and tied.
  const a = await delivery();
  const labA = await vettedLab();
  const reportA = await signs(labA, a.fingerprint);
  await sendsBack(a, reportA.attestationId);
  // The breeder sends the same plant to lab B, which has no receipt or report yet.
  const o = await call('POST', '/transfers', a.sender, { sourceRecord: a.recordId, toHandle: 'b@x' });
  const labBHolder = key();
  assert.equal((await call('POST', `/transfers/${o.json.transferId}/claim`, labBHolder, { claimCode: o.json.claimCode })).status, 200);
  const b = { ...a, lab: labBHolder, transferId: o.json.transferId };
  // A's report: signed before B's claim, and by another delivery's lab key.
  const r = await upload(b, reportA.attestationId);
  assert.equal(r.status, 403, JSON.stringify(r.json));
  // A's later signature, made after B claimed: still another delivery's lab key.
  const later = await signs(labA, a.fingerprint);
  assert.match((await upload(b, later.attestationId)).json.error, /another delivery's lab key/);
  assert.deepEqual((await page(a.fingerprint, labBHolder)).attestations, []);
  // B's own first report, signed after its claim by a key of its own: accepted.
  const labB = await generateKeypair();
  assert.equal((await upload(b, (await signs(labB, a.fingerprint)).attestationId)).status, 200);
  assert.deepEqual(ids((await page(a.fingerprint, labBHolder)).attestations).length, 1);
});

test('/health lists private-lab-signatures-v1, for the site’s deploy preflights', async () => {
  // The site's check page reads shared lab signatures from /verify; its deploy refuses a
  // registry that doesn't list this, so the two can't go live in the wrong order.
  const h = await call('GET', '/health');
  assert.equal(h.status, 200);
  assert.ok(h.json.features.includes('private-lab-signatures-v1'), JSON.stringify(h.json));
});

test('a lab key’s private genetic-fingerprint or inspection can be shared on /verify like a report', async () => {
  const d = await sealedDelivery();
  const lab = await vettedLab();
  const gf = await signsAs(lab, d.fingerprint, sha('gf-share'), 'genetic-fingerprint');
  const insp = await signsAs(lab, d.fingerprint, sha('insp-share'), 'inspection');
  assert.deepEqual((await page(d.fingerprint, null)).attestations, [], 'both private');
  const put = await share(d, [gf.attestationId, insp.attestationId]);
  assert.equal(put.status, 200, JSON.stringify(put.json));
  const v = (await call('GET', `/verify/${d.recordId}`)).json;
  assert.deepEqual(v.sharedAttestations.map((a) => a.attestationId), [gf.attestationId, insp.attestationId]);
  assert.equal(v.sharedAttestations[0].registeredAs.displayName, LAB_NAME);
});

// ---------------------------------------------------------------------------------------
// Final review fixes (12 Nov 2026).
// ---------------------------------------------------------------------------------------

test('L1: a lab with no receipt or result can’t tie another lab’s report as its first; the first report needs its key’s proof', async () => {
  // Lab A claimed a delivery of the plant; so did lab B. Neither has a receipt or a result yet.
  const a = await delivery();
  const o = await call('POST', '/transfers', a.sender, { sourceRecord: a.recordId, toHandle: 'b@x' });
  const labBHolder = key();
  assert.equal((await call('POST', `/transfers/${o.json.transferId}/claim`, labBHolder, { claimCode: o.json.claimCode })).status, 200);
  const b = { ...a, lab: labBHolder, transferId: o.json.transferId };
  // After both claims, lab A signs its report and has not tied it on yet.
  const labA = await vettedLab();
  const reportA = await signs(labA, a.fingerprint);
  // B ties A's report id as its first result: no proof, or a proof from B's own key, is refused.
  const bare = await upload(b, reportA.attestationId, b.lab, false);
  assert.equal(bare.status, 403, JSON.stringify(bare.json));
  assert.match(bare.json.error, /x-lab-key-proof/);
  const labB = await generateKeypair();
  const forged = await fetch(`${base}/transfers/${b.transferId}/results?attestationId=${reportA.attestationId}`, {
    method: 'POST',
    headers: { 'content-type': 'application/octet-stream', 'x-holder-key': b.lab, 'x-lab-key-proof': await labKeyProof(labB, b.transferId, reportA.attestationId) },
    body: Buffer.concat([Buffer.from('age-encryption.org/v1\n-> X25519 abc\n'), randomBytes(64)]),
  });
  assert.equal(forged.status, 403);
  // A's own proof is for A's delivery, not B's: replayed on B's delivery it fails.
  const replayed = await fetch(`${base}/transfers/${b.transferId}/results?attestationId=${reportA.attestationId}`, {
    method: 'POST',
    headers: { 'content-type': 'application/octet-stream', 'x-holder-key': b.lab, 'x-lab-key-proof': await labKeyProof(labA, a.transferId, reportA.attestationId) },
    body: Buffer.concat([Buffer.from('age-encryption.org/v1\n-> X25519 abc\n'), randomBytes(64)]),
  });
  assert.equal(replayed.status, 403);
  // B reads nothing of A's.
  assert.deepEqual((await page(a.fingerprint, labBHolder)).attestations, []);
  // A ties its own report with its key's proof; B its own, with its own.
  assert.equal((await upload(a, reportA.attestationId)).status, 200);
  const reportB = await signs(labB, a.fingerprint);
  assert.equal((await upload(b, reportB.attestationId, b.lab, false)).status, 403, 'B’s own first report needs its proof too');
  assert.equal((await upload(b, reportB.attestationId)).status, 200);
  assert.deepEqual(ids((await page(a.fingerprint, labBHolder)).attestations), [reportB.attestationId]);
  // After the first, the key is set: B's next report needs no proof.
  assert.equal((await upload(b, (await signs(labB, a.fingerprint)).attestationId, b.lab, false)).status, 200);
});

test('L1: a delivery with a receipt sets the key from the receipt, so its reports need no proof', async () => {
  const d = await sealedDelivery();
  const lab = await generateKeypair();
  const receipt = await signsAs(lab, d.fingerprint, d.received.recordFingerprint, 'chain-of-custody');
  assert.equal((await call('POST', `/transfers/${d.transferId}/receipt`, d.lab, { attestationId: receipt.attestationId })).status, 200);
  assert.equal((await upload(d, (await signs(lab, d.fingerprint)).attestationId, d.lab, false)).status, 200);
});

test('B1: the embed shows the signatures the holder shares, under the same grant, and never says nobody confirmed it', async () => {
  const d = await sealedDelivery();
  const lab = await vettedLab();
  const report = await signs(lab, d.fingerprint);
  await sendsBack(d, report.attestationId);
  const embed = async (q = '') => {
    const res = await fetch(`${base}/embed/${encodeURIComponent(d.recordId)}${q}`);
    return { text: await res.text(), cache: res.headers.get('cache-control') };
  };
  // Nothing shared: no lab named, and the empty case says why, not that nobody confirmed it.
  let e = await embed();
  assert.equal(e.cache, 'no-store');
  assert.ok(!e.text.includes(LAB_NAME));
  assert.ok(!e.text.includes('Nobody other than the holder'));
  assert.match(e.text, /No signature is shown here\. A lab\u2019s signatures are private unless the holder shows them\./);
  // Shared: named, as /verify names it.
  assert.equal((await share(d, [report.attestationId])).status, 200);
  e = await embed();
  assert.ok(e.text.includes(`Signed by ${LAB_NAME}.`), e.text);
  assert.ok(!e.text.includes('No signature is shown here'));
  // A ?show= without attestation-status, or a grant without it: not shown.
  assert.ok(!(await embed('?show=existence')).text.includes(LAB_NAME));
  assert.equal((await call('PUT', `/api/records/${d.recordId}/disclosure`, d.sender, { show: ['existence'], forFingerprint: d.fingerprint })).status, 200);
  assert.ok(!(await embed()).text.includes(LAB_NAME));
});

test('L4: /verify is never cached, with or without shared signatures', async () => {
  const d = await sealedDelivery();
  const lab = await vettedLab();
  const report = await signs(lab, d.fingerprint);
  await sendsBack(d, report.attestationId);
  const cacheOf = async (path) => (await fetch(`${base}${path}`)).headers.get('cache-control');
  assert.equal(await cacheOf(`/verify/${d.recordId}`), 'no-store');
  assert.equal((await share(d, [report.attestationId])).status, 200);
  assert.ok((await call('GET', `/verify/${d.recordId}`)).json.sharedAttestations?.length);
  assert.equal(await cacheOf(`/verify/${d.recordId}`), 'no-store');
  assert.equal(await cacheOf('/verify/no-such-record'), 'no-store');
});

test('L5: rows served to the holder mark the private ones, a lab key’s genetic-fingerprint and inspection included', async () => {
  const d = await sealedDelivery();
  const lab = await vettedLab();
  const report = await signs(lab, d.fingerprint);
  await sendsBack(d, report.attestationId);
  const gf = await signsAs(lab, d.fingerprint, sha('gf-mark'), 'genetic-fingerprint');
  const insp = await signsAs(lab, d.fingerprint, sha('insp-mark'), 'inspection');
  const breeder = await generateKeypair();
  const open = await signsAs(breeder, d.fingerprint, sha('open'), 'genetic-fingerprint', { displayName: 'A Breeder', role: 'breeder' });
  const mine = (await page(d.fingerprint, d.sender)).attestations;
  const mark = Object.fromEntries(mine.map((a) => [a.attestationId, a.private]));
  assert.deepEqual(mark, { [report.attestationId]: true, [gf.attestationId]: true, [insp.attestationId]: true, [open.attestationId]: undefined });
  // A stranger reads only the public one, unmarked.
  const theirs = (await page(d.fingerprint, null)).attestations;
  assert.deepEqual(theirs.map((a) => [a.attestationId, a.private]), [[open.attestationId, undefined]]);
  // Shared (13 Nov 2026): a stranger reads it on /verify, on the embed and by proof code, never
  // marked: the mark would tell them the key is a lab's. The holder's own view still marks it.
  assert.equal((await share(d, [gf.attestationId])).status, 200);
  const shown = (await call('GET', `/verify/${d.recordId}`)).json.sharedAttestations;
  assert.deepEqual(shown.map((a) => [a.attestationId, Object.hasOwn(a, 'private')]), [[gf.attestationId, false]]);
  const byCode = (await page(d.fingerprint, null)).attestations;
  assert.deepEqual(byCode.map((a) => [a.attestationId, Object.hasOwn(a, 'private')]).sort(),
    [[gf.attestationId, false], [open.attestationId, false]].sort());
  // A stranger with a holder key of their own: the share lets the row through, not their reader.
  const strangerKey = (await page(d.fingerprint, key())).attestations;
  assert.ok(strangerKey.every((a) => !Object.hasOwn(a, 'private')), 'unmarked for a key that is not a party');
  const embed = (await call('GET', `/embed/${encodeURIComponent(d.recordId)}`)).text;
  assert.doesNotMatch(embed, /"private"\s*:\s*true/);
  const again = Object.fromEntries((await page(d.fingerprint, d.sender)).attestations.map((a) => [a.attestationId, a.private]));
  assert.equal(again[gf.attestationId], true, 'still marked for the holder');
  assert.equal(again[report.attestationId], true);
  // The lab's own view marks its own signatures too.
  const labView = (await page(d.fingerprint, d.lab)).attestations;
  assert.ok(labView.some((a) => a.attestationId === report.attestationId && a.private === true));
});
