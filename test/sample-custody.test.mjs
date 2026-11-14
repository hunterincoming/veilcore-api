// The sample's chain of custody on a delivery (lineage/transfer.mjs custodyFields): the
// breeder writes the label and seal when making the lab code, the lab confirms or corrects
// them on arrival, and the lab's signed receipt covers both through its id.
//
// Every delivery in this file is one made before sample details were sealed (the site's
// CONTRACT.md #27): its source is a plain-text row as older code stored it and its offer has
// no sealed offer, so its sample details stay plain fields and its receipts carry `_sc1_`,
// checked as before. Deliveries made with a sealed offer seal them: custody-sealed.test.mjs.
//
// SPDX-License-Identifier: Apache-2.0

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { randomBytes } from 'node:crypto';
import { canonicalise, sha256Hex, newNonce, generateKeypair, signAttestation } from 'veilcore-records';
import { custodyDigest, custodyDifferences, custodyFields, isCalendarDate, receiptCustodyDigest, CUSTODY_FIELDS } from '../lineage/transfer.mjs';
import { untilReady, testBody, grantForTest, handleTagFor } from './helpers.mjs';

process.env.DB_PATH = ':memory:';
process.env.VEILCORE_OTS = 'off';
const require = createRequire(import.meta.url);
const { app, db } = require('../server.js');
const { storedHolderKey } = require('../holder-key.js');

const key = () => randomBytes(32).toString('hex');

let base, server;
before(async () => {
  server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  base = `http://127.0.0.1:${server.address().port}`;
  await untilReady(base);
});
after(() => server.close());

/** An offer as the site sent it before sealing: no sealed offer; the recipient as a tag. */
const olderOffer = (holder, body) => ({ ...body, toHandle: handleTagFor(holder, body.toHandle) });

const call = async (method, path, holder, body) => {
  const res = await fetch(`${base}${path}`, {
    method,
    // A client address of its own per call: this file makes more writes than one address may in a minute.
    headers: { 'content-type': 'application/json', 'x-forwarded-for': `10.${randomBytes(3).join('.')}`, ...(holder ? { 'x-holder-key': holder } : {}) },
    ...(body === undefined ? {} : { body: JSON.stringify(method === 'POST' && path === '/transfers' ? olderOffer(holder, body) : testBody(method, path, holder, body)) }),
  });
  const text = await res.text();
  let json; try { json = JSON.parse(text); } catch { json = text; }
  return { status: res.status, json };
};

const committedOf = (r) => ({ breedingMethod: r.breedingMethod ?? '', bredBy: r.bredBy, dateCreated: r.dateCreated,
  loggedAt: r.loggedAt, nonce: r.nonce, notes: r.notes, parents: r.parents ?? [],
  photoFingerprints: r.photoFingerprints ?? [], refId: r.refId ?? '', strainName: r.strainName });

const plant = async (sender) => {
  const r = { id: `sc-${randomBytes(6).toString('hex')}`, strainName: 'S', bredBy: 'B', dateCreated: '2026-01-01',
    loggedAt: '2026-01-01T00:00:00Z', nonce: newNonce(), notes: '', parents: [], photoFingerprints: [], breedingMethod: '', refId: '' };
  r.recordFingerprint = await sha256Hex(canonicalise(committedOf(r)));
  // Stored as older code stored it, in plain text: a new save is always sealed.
  db.prepare('INSERT INTO records (id, holder_key, body, updated_at, first_seen) VALUES (?,?,?,?,?)')
    .run(r.id, storedHolderKey(sender), JSON.stringify(r), Date.now(), Date.now());
  return r;
};

const SAMPLE = { sampleId: 'BLU-07', sealNumber: '4471', takenFrom: 'Mother M3, bench 2', takenOn: '2026-10-14', witness: 'J. Doe' };

/** An offer with `sample`, claimed by `lab`, whose received record the lab seals. */
const claimed = async (sample = SAMPLE) => {
  const sender = key(), lab = key();
  const source = await plant(sender);
  const o = await call('POST', '/transfers', sender, { sourceRecord: source.id, toHandle: 'lab@x', ...(sample ? { sample } : {}) });
  assert.equal(o.status, 200, JSON.stringify(o.json));
  const c = await call('POST', `/transfers/${o.json.transferId}/claim`, lab, { claimCode: o.json.claimCode });
  assert.equal(c.status, 200, JSON.stringify(c.json));
  // The registry wrote a stub; the lab's browser completes it from the offer and seals it.
  const stub = (await call('GET', '/api/records', lab)).json.find((r) => r.id === c.json.recordId);
  const received = { ...stub, bredBy: 'B', dateCreated: '2026-01-01', notes: '', parents: [], photoFingerprints: [],
    breedingMethod: '', refId: '', nonce: newNonce(), loggedAt: stub.receivedAt };
  const sealed = { ...received, recordFingerprint: await sha256Hex(canonicalise(committedOf(received))) };
  const put = await call('PUT', '/api/records', lab, [sealed]);
  assert.equal(put.json.count, 1, JSON.stringify(put.json));
  assert.equal(put.json.integrityCheckedBy, 'holder');
  return { sender, lab, source, transferId: o.json.transferId, claim: c.json, received: sealed };
};

/** The lab's receipt, signed as the site signs it: with the custody digest in its id, or without. */
const receipt = async (d, digest) => {
  const kp = await generateKeypair();
  const attestationId = `att_${randomBytes(8).toString('hex')}${digest ? `_sc1_${digest}` : ''}`;
  const signed = await signAttestation({
    attestationId, type: 'chain-of-custody', subjectCommitment: d.source.recordFingerprint,
    documentHash: d.received.recordFingerprint, hashAlgorithm: 'sha256',
    issuedAt: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'), attester: { publicKey: kp.publicKey, displayName: 'Lab' },
  }, kp.privateKey);
  const r = await call('POST', '/attestations', undefined, signed);
  assert.equal(r.status, 200, JSON.stringify(r.json));
  return attestationId;
};
const attach = (d, id) => call('POST', `/transfers/${d.transferId}/receipt`, d.lab, { attestationId: id });

test('the breeder’s sample details are stored with the lab code, given to the lab on claim and listed for the sender', async () => {
  const d = await claimed();
  assert.deepEqual(d.claim.sample, SAMPLE);
  const sent = (await call('GET', '/transfers/sent', d.sender)).json.transfers.find((t) => t.id === d.transferId);
  assert.deepEqual(sent.sample_custody, SAMPLE);
  assert.equal('arrival_custody' in sent, false, 'nothing written on arrival yet');
  // Not on the public pending list.
  const pending = await call('GET', '/transfers/pending/lab@x');
  assert.equal(JSON.stringify(pending.json).includes('4471'), false);
  // None given: {} to the lab, absent from the sent list.
  const none = await claimed(null);
  assert.deepEqual(none.claim.sample, {});
  const row = (await call('GET', '/transfers/sent', none.sender)).json.transfers.find((t) => t.id === none.transferId);
  assert.equal('sample_custody' in row, false);
});

test('fields are trimmed, empty ones dropped, and checked for shape and length', async () => {
  const sender = key();
  const source = await plant(sender);
  const offer = (sample) => call('POST', '/transfers', sender, { sourceRecord: source.id, toHandle: 'lab@y', sample });
  const ok = await offer({ sampleId: '  A-1 ', sealNumber: '', witness: '   ' });
  assert.equal(ok.status, 200);
  const custody = await call('GET', `/transfers/${ok.json.transferId}/custody`, sender);
  assert.deepEqual(custody.json.sample, { sampleId: 'A-1' });
  for (const [bad, why] of [
    [{ sampleId: 'x'.repeat(CUSTODY_FIELDS.sample.sampleId + 1) }, /at most 120/],
    [{ takenFrom: 'x'.repeat(301) }, /at most 300/],
    [{ witness: 'x'.repeat(201) }, /at most 200/],
    [{ takenOn: '14/10/2026' }, /YYYY-MM-DD/],
    [{ takenOn: '2026-13-45' }, /YYYY-MM-DD/],
    [{ sealNumber: 4471 }, /must be a string/],
    [{ colour: 'red' }, /not a field here/],
    [['4471'], /must be an object/],
  ]) {
    const r = await offer(bad);
    assert.equal(r.status, 400, JSON.stringify(bad));
    assert.match(r.json.error, why);
  }
  // The lab's side.
  const d = await claimed();
  for (const [bad, why] of [
    [{ sealIntact: 'maybe' }, /one of yes, no, no-seal/],
    [{ condition: 'x'.repeat(1001) }, /at most 1000/],
    [{ labRef: 'x'.repeat(201) }, /at most 200/],
    [{ arrivedOn: 'yesterday' }, /YYYY-MM-DD/],
    [{ takenFrom: 'a lab can’t write this' }, /not a field here/],
  ]) {
    const r = await call('POST', `/transfers/${d.transferId}/custody`, d.lab, { arrival: bad });
    assert.equal(r.status, 400, JSON.stringify(bad));
    assert.match(r.json.error, why);
  }
});

test('only the sender writes the sample side, and only until the lab receives it', async () => {
  const sender = key(), lab = key(), stranger = key();
  const source = await plant(sender);
  const o = (await call('POST', '/transfers', sender, { sourceRecord: source.id, toHandle: 'lab@z' })).json;
  const path = `/transfers/${o.transferId}/custody`;
  assert.equal((await call('POST', path, stranger, { sample: { sealNumber: '1' } })).status, 403);
  assert.equal((await call('POST', path, undefined, { sample: { sealNumber: '1' } })).status, 401);
  const set = await call('POST', path, sender, { sample: { sealNumber: '4471' } });
  assert.equal(set.status, 200);
  assert.deepEqual(set.json.sample, { sealNumber: '4471' });
  assert.equal((await call('POST', `/transfers/${o.transferId}/claim`, lab, { claimCode: o.claimCode })).status, 200);
  // The lab can't write the breeder's side, and now nobody can.
  assert.equal((await call('POST', path, lab, { sample: { sealNumber: '4417' } })).status, 403);
  const late = await call('POST', path, sender, { sample: { sealNumber: '9999' } });
  assert.equal(late.status, 409);
  assert.deepEqual((await call('GET', path, sender)).json.sample, { sealNumber: '4471' });
  assert.equal((await call('POST', '/transfers/TR-NOPE0000/custody', sender, { sample: {} })).status, 404);
  assert.equal((await call('POST', path, sender, {})).status, 400, 'one side must be sent');
  assert.equal((await call('POST', path, sender, { sample: {}, arrival: {} })).status, 400, 'not both');
});

test('only whoever received the delivery writes the arrival side; the sender and the lab read both, nobody else', async () => {
  const sender = key(), lab = key(), stranger = key();
  const source = await plant(sender);
  const o = (await call('POST', '/transfers', sender, { sourceRecord: source.id, toHandle: 'lab@w', sample: SAMPLE })).json;
  const path = `/transfers/${o.transferId}/custody`;
  const arrival = { sampleId: 'BLU-07', sealNumber: '4417', sealIntact: 'yes', arrivedOn: '2026-10-15', condition: 'Cold, bag dry', labRef: 'ACC-9' };
  assert.equal((await call('POST', path, lab, { arrival })).status, 409, 'not before it is received');
  assert.equal((await call('POST', `/transfers/${o.transferId}/claim`, lab, { claimCode: o.claimCode })).status, 200);
  assert.equal((await call('POST', path, sender, { arrival })).status, 403, 'the sender can’t write how it arrived');
  assert.equal((await call('POST', path, stranger, { arrival })).status, 403);
  const set = await call('POST', path, lab, { arrival });
  assert.equal(set.status, 200);
  assert.deepEqual(set.json, { transferId: o.transferId, sample: SAMPLE, arrival });
  for (const who of [sender, lab]) {
    const r = await call('GET', path, who);
    assert.equal(r.status, 200);
    assert.deepEqual(r.json, { transferId: o.transferId, sample: SAMPLE, arrival, receiptAttestationId: null });
  }
  assert.equal((await call('GET', path, stranger)).status, 403);
  assert.equal((await call('GET', path)).status, 401);
  const sent = (await call('GET', '/transfers/sent', sender)).json.transfers.find((t) => t.id === o.transferId);
  assert.deepEqual(sent.arrival_custody, arrival);
  // A later write replaces the whole side.
  assert.deepEqual((await call('POST', path, lab, { arrival: { sealIntact: 'no' } })).json.arrival, { sealIntact: 'no' });
});

test('a receipt whose id carries the custody digest is linked only when it covers exactly what is stored', async () => {
  const d = await claimed();
  const arrival = { sampleId: 'BLU-07', sealNumber: '4417', sealIntact: 'yes', arrivedOn: '2026-10-15' };
  assert.equal((await call('POST', `/transfers/${d.transferId}/custody`, d.lab, { arrival })).status, 200);
  const digest = custodyDigest(d.transferId, SAMPLE, arrival);
  // The site computes the same digest the same way (transfers.ts custodyDigest).
  assert.equal(digest, await sha256Hex(canonicalise({ format: 'veilcore/sample-custody/v1', transferId: d.transferId, sample: SAMPLE, arrival })));

  // Signed over other values (here: the seal number as sent, not as it arrived): refused.
  const wrong = await receipt(d, custodyDigest(d.transferId, SAMPLE, { ...arrival, sealNumber: '4471' }));
  const refused = await attach(d, wrong);
  assert.equal(refused.status, 400);
  assert.match(refused.json.error, /different sample details/);

  const good = await receipt(d, digest);
  assert.equal(receiptCustodyDigest(good), digest);
  const r = await attach(d, good);
  assert.equal(r.status, 200, JSON.stringify(r.json));
  const sent = (await call('GET', '/transfers/sent', d.sender)).json.transfers.find((t) => t.id === d.transferId);
  assert.equal(sent.receipt_attestation_id, good);
  assert.deepEqual(sent.arrival_custody, arrival);
  assert.equal(receiptCustodyDigest(sent.receipt_attestation_id), custodyDigest(d.transferId, sent.sample_custody, sent.arrival_custody));

  // The subject/document binding is unchanged: the right digest on another delivery's receipt fails as before.
  const other = await claimed();
  const kp = await generateKeypair();
  const foreign = `att_${randomBytes(8).toString('hex')}_sc1_${custodyDigest(other.transferId, SAMPLE, {})}`;
  const s = await signAttestation({
    attestationId: foreign, type: 'chain-of-custody', subjectCommitment: d.source.recordFingerprint,
    documentHash: d.received.recordFingerprint, hashAlgorithm: 'sha256',
    issuedAt: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'), attester: { publicKey: kp.publicKey },
  }, kp.privateKey);
  assert.equal((await call('POST', '/attestations', undefined, s)).status, 200);
  assert.equal((await attach(other, foreign)).status, 400, 'about another delivery’s plant');
});

test('older receipts without the digest still link, with or without sample details stored', async () => {
  for (const sample of [null, SAMPLE]) {
    const d = await claimed(sample);
    const id = await receipt(d);
    assert.equal(receiptCustodyDigest(id), null);
    const r = await attach(d, id);
    assert.equal(r.status, 200, JSON.stringify(r.json));
  }
});

test('the digest is over canonical JSON: key order and missing sides don’t change it, any value does', () => {
  // The site's sample-custody.test.ts checks its custodyDigest gives this same value.
  assert.equal(custodyDigest('TR-0A1B2C3D',
    { sampleId: 'BLU-07', sealNumber: '4471', takenFrom: 'Mother M3', takenOn: '2026-10-14', witness: 'J. Doe' },
    { sampleId: 'BLU-07', sealNumber: '4417', sealIntact: 'yes', arrivedOn: '2026-10-15', condition: 'Cold, dry', labRef: 'ACC-9' }),
  '20414775107061b3a541797f4ed8fe2e2a9c65e43f649c481ab637ecfc5929c2');
  const a = custodyDigest('TR-00000001', { sealNumber: '4471', sampleId: 'A' }, {});
  assert.equal(a, custodyDigest('TR-00000001', { sampleId: 'A', sealNumber: '4471' }));
  assert.notEqual(a, custodyDigest('TR-00000001', { sampleId: 'A', sealNumber: '4417' }));
  assert.notEqual(a, custodyDigest('TR-00000002', { sampleId: 'A', sealNumber: '4471' }));
  assert.equal(receiptCustodyDigest(`att_0123456789abcdef_sc1_${a}`), a);
  assert.equal(receiptCustodyDigest('att_0123456789abcdef'), null);
  assert.equal(receiptCustodyDigest(`att_x_sc1_${a.toUpperCase()}`), null);
});

// ---- round 2 of the 15 Oct review ----------------------------------------------------------

/**
 * Shared with the site's sample-custody.test.ts (CROSS_CHECK there): the same input must be
 * normalised to the same values and give the same digest on both sides, or a receipt the
 * lab's browser signs would never link.
 */
const CROSS_SAMPLE_IN = { sampleId: '  BLU-07 ', sealNumber: '4471', takenFrom: 'Mother M3, bench 2', takenOn: '2024-02-29', witness: 'Jose\u0301 Doe' };
const CROSS_ARRIVAL_IN = { sampleId: 'BLU-07', sealNumber: ' 4417', sealIntact: 'no', arrivedOn: '2026-10-15',
  condition: '  Cold, bag dry   \r\n\r\n\r\n\r\nTube cracked at the cap \r\n', labRef: 'ACC-9' };
const CROSS_SAMPLE = { sampleId: 'BLU-07', sealNumber: '4471', takenFrom: 'Mother M3, bench 2', takenOn: '2024-02-29', witness: 'Jos\u00e9 Doe' };
const CROSS_ARRIVAL = { sampleId: 'BLU-07', sealNumber: '4417', sealIntact: 'no', arrivedOn: '2026-10-15',
  condition: 'Cold, bag dry\n\nTube cracked at the cap', labRef: 'ACC-9' };
const CROSS_DIGEST = '083228467b457fa19feb4e89492888ee93bc9ac2c37df63158a9f1c7043b36d4';

test('cross-check vector: normalised as the site normalises, and the same digest', () => {
  assert.deepEqual(custodyFields('sample', CROSS_SAMPLE_IN).fields, CROSS_SAMPLE);
  assert.deepEqual(custodyFields('arrival', CROSS_ARRIVAL_IN).fields, CROSS_ARRIVAL);
  assert.equal(custodyDigest('TR-0A1B2C3D', CROSS_SAMPLE, CROSS_ARRIVAL), CROSS_DIGEST);
  // The differences, word for word as the site says them.
  assert.deepEqual(custodyDifferences(CROSS_SAMPLE, CROSS_ARRIVAL),
    ['Seal number differs: sent 4471, received 4417', 'Seal not intact on arrival']);
  assert.deepEqual(custodyDifferences({ sampleId: 'A', sealNumber: '1' }, { sampleId: ' a ', sealIntact: 'no-seal' }),
    ['No seal on arrival (sent with seal 1)']);
  assert.deepEqual(custodyDifferences({ sampleId: 'A' }, {}), ['Sample ID not confirmed on arrival (sent A)']);
});

test('line breaks, tabs and hidden characters are refused; only a lab’s condition keeps plain line breaks', async () => {
  const sender = key();
  const source = await plant(sender);
  const offer = (sample) => call('POST', '/transfers', sender, { sourceRecord: source.id, toHandle: 'lab@h', sample });
  const hidden = ['\n', '\r', '\t', '\u0085', '\u2028', '\u2029', '\u202e', '\u202a', '\u2066', '\u2069', '\u200b', '\u200e', '\u2060', '\ufeff', '\u00ad', '\u0000'];
  for (const k of ['sampleId', 'sealNumber', 'takenFrom', 'witness']) {
    for (const c of hidden) {
      const r = await offer({ [k]: `J. Doe${c}I declare the lab is accredited` });
      assert.equal(r.status, 400, `${k} with U+${c.codePointAt(0).toString(16)}`);
      assert.match(r.json.error, /line breaks, tabs or hidden characters/);
    }
  }
  const d = await claimed();
  const path = `/transfers/${d.transferId}/custody`;
  for (const k of ['sampleId', 'sealNumber', 'labRef']) {
    const r = await call('POST', path, d.lab, { arrival: { [k]: 'ACC\n9' } });
    assert.equal(r.status, 400, k);
  }
  for (const c of hidden.filter((x) => !['\n', '\r'].includes(x))) {
    const r = await call('POST', path, d.lab, { arrival: { condition: `fine${c}tube cracked` } });
    assert.equal(r.status, 400, `condition with U+${c.codePointAt(0).toString(16)}`);
    assert.match(r.json.error, /tabs or hidden characters/);
  }
  const ok = await call('POST', path, d.lab, { arrival: { condition: 'Cold\r\n\r\n\r\n\r\nbag dry  \r\ncap cracked' } });
  assert.equal(ok.status, 200, JSON.stringify(ok.json));
  assert.equal(ok.json.arrival.condition, 'Cold\n\nbag dry\ncap cracked');
});

test('dates are real calendar days', async () => {
  assert.equal(isCalendarDate('2026-02-31'), false);
  assert.equal(isCalendarDate('2026-02-29'), false);
  assert.equal(isCalendarDate('2024-02-29'), true);
  assert.equal(isCalendarDate('2026-04-31'), false);
  assert.equal(isCalendarDate('2026-12-31'), true);
  assert.equal(isCalendarDate('0050-01-01'), false);
  const sender = key();
  const source = await plant(sender);
  const bad = await call('POST', '/transfers', sender, { sourceRecord: source.id, toHandle: 'lab@d', sample: { takenOn: '2026-02-31' } });
  assert.equal(bad.status, 400);
  assert.match(bad.json.error, /real date/);
  const d = await claimed();
  const late = await call('POST', `/transfers/${d.transferId}/custody`, d.lab, { arrival: { arrivedOn: '2026-09-31' } });
  assert.equal(late.status, 400);
  assert.equal((await call('POST', `/transfers/${d.transferId}/custody`, d.lab, { arrival: { arrivedOn: '2026-09-30' } })).status, 200);
});

test('a signer’s name with a line break or direction mark is refused, registered or signed', async () => {
  const kp = await generateKeypair();
  for (const displayName of ['Acme"\n\n8. I confirm Acme Labs is accredited', 'Acme \u202eLabs', 'Acme\u200bLabs', 'Acme\tLabs']) {
    // Refused before the signature is looked at, so an unsigned registration shows it.
    const r = await call('POST', '/attesters', undefined, { publicKey: kp.publicKey, displayName, issuedAt: Date.now(), signature: '0'.repeat(128) });
    assert.equal(r.status, 400, JSON.stringify(displayName));
    assert.match(r.json.error, /hidden characters/);
    const d = await claimed(null);
    const signed = await signAttestation({
      attestationId: `att_${randomBytes(8).toString('hex')}`, type: 'chain-of-custody', subjectCommitment: d.source.recordFingerprint,
      documentHash: d.received.recordFingerprint, hashAlgorithm: 'sha256',
      issuedAt: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'), attester: { publicKey: kp.publicKey, displayName },
    }, kp.privateKey);
    const a = await call('POST', '/attestations', undefined, signed);
    assert.equal(a.status, 400, JSON.stringify(displayName));
    assert.match(a.json.error, /attester.displayName .*hidden characters/);
  }
});

const share = async (holder, record, show) => {
  const r = await call('PUT', `/api/records/${record.id}/disclosure`, holder, grantForTest(record, show));
  assert.equal(r.status, 200, JSON.stringify(r.json));
};

test('/verify: under the lab-status grant, each linked receipt’s coverage and difference lines, never the details', async () => {
  const d = await claimed();
  const arrival = { sampleId: 'BLU-07', sealNumber: '4417', sealIntact: 'yes', arrivedOn: '2026-03-07', condition: 'Cold, bag dry', labRef: 'ACC-PRIVATE-9' };
  assert.equal((await call('POST', `/transfers/${d.transferId}/custody`, d.lab, { arrival })).status, 200);
  const good = await receipt(d, custodyDigest(d.transferId, SAMPLE, arrival));
  assert.equal((await attach(d, good)).status, 200);

  // No grant: nothing about custody.
  let v = await call('GET', `/verify/${d.source.id}`);
  assert.equal(v.status, 200);
  assert.equal('custody' in v.json, false, 'absent without the grant');

  await share(d.sender, d.source, ['attestation-status']);
  v = await call('GET', `/verify/${d.source.id}`);
  assert.deepEqual(v.json.custody, [
    // No id: a custody line names its receipt only when the holder shares it (8 Nov 2026).
    { covered: 'covered', differences: ['Seal number differs: sent 4471, received 4417'] },
  ]);
  // The details themselves stay private: only the difference line carries any of them.
  const body = JSON.stringify(v.json);
  for (const secret of ['Mother M3', 'J. Doe', 'Cold, bag dry', 'ACC-PRIVATE-9', '2026-10-14', '2026-03-07', d.transferId]) {
    assert.equal(body.includes(secret), false, secret);
  }
  // A link narrowed to other facts doesn't get it.
  v = await call('GET', `/verify/${d.source.id}?show=existence`);
  assert.equal('custody' in v.json, false, 'absent when ?show= leaves out the lab status');
  // The received record's own /verify says nothing about the sender's deliveries.
  await share(d.lab, d.received, ['attestation-status']);
  assert.equal('custody' in (await call('GET', `/verify/${d.received.id}`)).json, false);

  // The lab rewrites its arrival details after signing: the registry still holds the receipt,
  // and now says it doesn't cover them, with no difference lines.
  assert.equal((await call('POST', `/transfers/${d.transferId}/custody`, d.lab, { arrival: { ...arrival, sealNumber: '4471' } })).status, 200);
  v = await call('GET', `/verify/${d.source.id}`);
  assert.deepEqual(v.json.custody, [{ covered: 'changed', differences: [] }]);
});

test('/verify: an older receipt without the digest is "not-covered"; a withdrawn one and other holders’ deliveries are left out', async () => {
  const d = await claimed();
  const old = await receipt(d);
  assert.equal((await attach(d, old)).status, 200);
  await share(d.sender, d.source, ['attestation-status']);
  let v = await call('GET', `/verify/${d.source.id}`);
  assert.deepEqual(v.json.custody, [{ covered: 'not-covered', differences: [] }]);

  // Withdrawn by its signer: left out, as the check page leaves out a withdrawn signature.
  // (Written straight to the table: a real withdrawal needs the signer's key, which receipt() doesn't keep.)
  require('../server.js').db.prepare('INSERT INTO retractions (attestation_id, body, retracted_at) VALUES (?,?,?)').run(old, '{}', Date.now());
  v = await call('GET', `/verify/${d.source.id}`);
  assert.equal('custody' in v.json, false);

  // A stranger's record: nothing of this sender's deliveries.
  const other = await plant(key());
  const s = await call('GET', `/verify/${other.id}`);
  assert.equal('custody' in s.json, false);
});

test('/verify, /embed, /records/:id: a stale grant still answers the registry\'s own lab-status facts; only the DNA pairing goes stale', async () => {
  const d = await claimed();
  const arrival = { sampleId: 'BLU-07', sealNumber: '4417', sealIntact: 'yes', arrivedOn: '2026-03-07' };
  assert.equal((await call('POST', `/transfers/${d.transferId}/custody`, d.lab, { arrival })).status, 200);
  const good = await receipt(d, custodyDigest(d.transferId, SAMPLE, arrival));
  assert.equal((await attach(d, good)).status, 200);
  // No id: the grant shares no receipt (8 Nov 2026, hide-lab-reports.test.mjs).
  const custody = [{ covered: 'covered', differences: ['Seal number differs: sent 4471, received 4417'] }];

  // A grant without forFingerprint or values (as an older site sends it): nothing the holder
  // wrote is current, yet the receipt and its custody are the registry's own and are answered.
  const g = await call('PUT', `/api/records/${d.source.id}/disclosure`, d.sender, { show: ['existence', 'attestation-status', 'sealed-at'] });
  assert.equal(g.status, 200);
  let v = (await call('GET', `/verify/${d.source.id}`)).json;
  assert.deepEqual(v.custody, custody);
  assert.deepEqual(v.disclosed, ['own', 'dna']);
  assert.deepEqual(v.staleGrant, ['dna', 'sealed']);
  for (const f of ['dnaPairedByHolder', 'dnaPairBinding', 'dnaPairingFingerprint', 'dnaFileSha256', 'sealedAt']) assert.equal(f in v, false, f);
  assert.equal(typeof v.signedAttestation, 'boolean');
  assert.equal(typeof v.attestedByVettedLab, 'boolean');
  const embedHtml = (await fetch(`${base}/embed/${d.source.id}`).then((r) => r.text()));
  assert.doesNotMatch(embedHtml, /Date stated by the holder/);
  const pub = (await call('GET', `/records/${d.source.id}`)).json;
  assert.deepEqual(pub.staleGrant, ['attestation-status', 'sealed-at']);
  assert.equal(pub.loggedAtClaimedByHolder, undefined);

  // With the values the app sends, for the record as it is: the pairing is answered too.
  // The pairing in its bound form (round 5, CONTRACT.md #29).
  const pairing = 'ab'.repeat(32);
  const fresh = await call('PUT', `/api/records/${d.source.id}/disclosure`, d.sender, {
    show: ['existence', 'attestation-status'], forFingerprint: d.source.recordFingerprint, values: { dnaPairBinding: pairing },
  });
  assert.equal(fresh.status, 200, JSON.stringify(fresh.json));
  v = (await call('GET', `/verify/${d.source.id}`)).json;
  assert.deepEqual(v.custody, custody);
  assert.equal(v.dnaPairedByHolder, true);
  assert.equal(v.dnaPairBinding, pairing);
  assert.equal(v.staleGrant, undefined);
  // The holder's listing carries the values, so a browser can tell a changed pairing apart.
  const listed = (await call('GET', '/api/disclosures', d.sender)).json;
  assert.deepEqual(listed.map((x) => [x.recordId, x.values]), [[d.source.id, { dnaPairBinding: pairing }]]);
});
