// Round 11: adversarial pass against the public registry before launch.
//
// Each test started as a demonstration of an attack that worked. Each now asserts the
// attack is refused, alongside the legitimate flow it must not break.
// In-process server, in-memory database.
//
// SPDX-License-Identifier: Apache-2.0

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import http from 'node:http';
import { createHash } from 'node:crypto';
import { generateKeypair, signAttestation, canonicalise, sha256Hex, newNonce } from 'veilcore-records';
import { registrationPayload } from '../lineage/attesters.mjs';
import { inOneMinute, untilReady, testBody, plain, grantForTest, openForTest, vaultKeyFor, sealForTest, openOfferForTest, offerKeyFor, handleTagFor } from './helpers.mjs';

process.env.DB_PATH = ':memory:';
process.env.VEILCORE_OPERATOR_TOKEN = 'test-operator-token-at-least-32-chars';
const require = createRequire(import.meta.url);
const { app, db } = require('../server.js');

let base;
let server;
before(async () => {
  server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  base = `http://127.0.0.1:${server.address().port}`;
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
  return { status: res.status, json, text, headers: res.headers };
};

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const key = () => [...crypto.getRandomValues(new Uint8Array(32))].map((b) => b.toString(16).padStart(2, '0')).join('');

const makeRecord = async (id, over = {}) => {
  const r = {
    id,
    strainName: 'Test Cultivar',
    bredBy: 'Breeder',
    dateCreated: '2026-01-01',
    loggedAt: '2026-01-01T00:00:00Z',
    nonce: newNonce(),
    notes: 'private notes',
    parents: [{ name: 'Secret Mother' }],
    photoFingerprints: [],
    breedingMethod: 'secret method',
    refId: '',
    ...over,
  };
  const committed = {
    breedingMethod: r.breedingMethod, bredBy: r.bredBy, dateCreated: r.dateCreated, loggedAt: r.loggedAt,
    nonce: r.nonce, notes: r.notes, parents: r.parents, photoFingerprints: r.photoFingerprints,
    refId: r.refId, strainName: r.strainName,
  };
  r.recordFingerprint = await sha256Hex(canonicalise(committed));
  return r;
};

const registration = async (kp, fields) => {
  const reg = { publicKey: kp.publicKey, issuedAt: Date.now(), ...fields };
  const priv = await crypto.subtle.importKey('pkcs8', Buffer.from(kp.privateKey, 'hex'), { name: 'Ed25519' }, false, ['sign']);
  const sig = await crypto.subtle.sign('Ed25519', priv, new TextEncoder().encode(registrationPayload(reg)));
  return { ...reg, signature: Buffer.from(sig).toString('hex') };
};

// ---------------------------------------------------------------------------------------
// HIGH: registryFirstSeen used to survive a full content swap, so a holder could backdate
// the registry's own date. Placeholder now, real content later, "unaltered since <then>".
// ---------------------------------------------------------------------------------------
test('backdate is refused: new content under an old id gets a new registryFirstSeen; same content keeps it', async () => {
  const holder = key();
  const placeholder = await makeRecord('VEIL-BACKDT', { strainName: 'Placeholder' });
  assert.equal((await call('PUT', '/api/records', { holder, body: [placeholder] })).json.count, 1);
  const firstSeen = (await call('GET', '/records/VEIL-BACKDT')).json.registryFirstSeen;

  // Legitimate re-save of the same content with uncommitted changes (the app re-sends the
  // whole set on every change): the date stands.
  await sleep(20);
  const paired = { ...placeholder, dnaFingerprint: 'ef'.repeat(32), dnaPairedAt: Date.now() };
  assert.equal((await call('PUT', '/api/records', { holder, body: [paired] })).json.count, 1);
  assert.equal((await call('GET', '/records/VEIL-BACKDT')).json.registryFirstSeen, firstSeen);

  await sleep(50);
  const swapAt = Date.now();
  // Entirely different record, different commitment, same id.
  const real = await makeRecord('VEIL-BACKDT', { strainName: 'Prize Cultivar', loggedAt: '2024-01-01T00:00:00Z' });
  assert.notEqual(real.recordFingerprint, placeholder.recordFingerprint);
  assert.equal((await call('PUT', '/api/records', { holder, body: [real] })).json.count, 1);

  await call('PUT', '/api/records/VEIL-BACKDT/disclosure', { holder, body: grantForTest(real, ['existence', 'sealed-at', 'name']) });
  const v = (await call('GET', '/verify/VEIL-BACKDT?show=own,sealed,name')).json;
  assert.equal(v.cultivar, 'Prize Cultivar');
  assert.equal(v.recordFingerprint, real.recordFingerprint);
  assert.notEqual(v.registryFirstSeen, firstSeen, 'first-seen date no longer belongs to the placeholder');
  assert.ok(Date.parse(v.registryFirstSeen) >= swapAt, 'the date covers only the content now stored');
  assert.equal(v.loggedAtClaimedByHolder, '2024-01-01T00:00:00Z', 'the holder\'s own date is still reported as theirs');
});

// ---------------------------------------------------------------------------------------
// HIGH: any fresh keypair was "a signed lab attestation". The holder self-attests, names
// the key after a real lab, adds an inline accreditation, and every verifier said so.
// ---------------------------------------------------------------------------------------
test('self-attestation is not shown as a lab: unvetted keys are "self-registered", only the operator vets', async () => {
  const holder = key();
  const rec = await makeRecord('VEIL-SELFAT', { strainName: 'Self Vouched' });
  await call('PUT', '/api/records', { holder, body: [rec] });

  const me = await generateKeypair(); // the holder, not a lab
  assert.equal((await call('POST', '/attesters', { body: await registration(me, { displayName: 'Eurofins Scientific', role: 'laboratory' }) })).status, 200);
  const att = await signAttestation({
    attestationId: `att_self_${Date.now()}`,
    attester: { publicKey: me.publicKey, displayName: 'Eurofins Scientific', accreditation: { scheme: 'ISO/IEC 17025', identifier: 'made-up', accreditor: 'A2LA' } },
    documentHash: 'ab'.repeat(32), hashAlgorithm: 'sha256', issuedAt: '2026-10-01T00:00:00Z',
    // Type `other`, which stays public: a lab report or receipt, and a lab key's genetic-fingerprint
    // or inspection, are shown only to the record's holder and the lab, and never counted on
    // /verify (8 Nov 2026, hide-lab-reports.test.mjs).
    subjectCommitment: rec.recordFingerprint, type: 'other',
  }, me.privateKey);
  const sub = await call('POST', '/attestations', { body: att });
  assert.equal(sub.status, 200, 'a valid signature is still accepted and recorded');
  assert.equal(sub.json.strength, 'signed', 'strength no longer comes from a field the signer typed');

  const v = (await call('GET', '/verify/VEIL-SELFAT')).json;
  assert.equal(v.signedAttestation, true, 'there is a valid signature');
  assert.equal(v.attestedByVettedLab, false, 'but not from a key anyone checked');
  assert.equal(v.attested, false, 'old clients read `attested` as "lab attestation"');

  const embed = await call('GET', '/embed/VEIL-SELFAT');
  assert.doesNotMatch(embed.text, /Confirmed by Eurofins/);
  assert.doesNotMatch(embed.text, /accreditation/i, 'no accreditation claim from what the signer typed');
  assert.match(embed.text, /a key named “Eurofins Scientific” \(name not checked\)/);

  // Vetting needs the operator token: the attester cannot vet itself.
  assert.equal((await call('POST', `/attesters/${me.publicKey}/vetting`, { body: { vetted: true } })).status, 401);
  assert.equal((await call('POST', `/attesters/${me.publicKey}/vetting`, { body: { vetted: true }, headers: { 'x-operator-token': 'wrong' } })).status, 401);

  // A real lab, vetted by the operator, is described as such.
  const lab = await generateKeypair();
  await call('POST', '/attesters', { body: await registration(lab, { displayName: 'Real Lab Inc', role: 'laboratory' }) });
  const vet = await call('POST', `/attesters/${lab.publicKey}/vetting`, { body: { vetted: true, check: { source: 'licence-listing', sourceUrl: 'https://agriculture.example.gov/testing-labs', licenceNo: 'TL-0001', emailDomain: 'reallab.example', checkedAt: new Date().toISOString().slice(0, 10), checkedBy: 'AB' }, note: 'code signed from qa@reallab.example' }, headers: { 'x-operator-token': 'test-operator-token-at-least-32-chars' } });
  assert.equal(vet.status, 200);
  const rec2 = await makeRecord('VEIL-VETTED', { strainName: 'Lab Checked' });
  await call('PUT', '/api/records', { holder, body: [rec2] });
  const labAtt = await signAttestation({
    attestationId: `att_lab_${Date.now()}`, attester: { publicKey: lab.publicKey },
    documentHash: 'cd'.repeat(32), hashAlgorithm: 'sha256', issuedAt: '2026-10-01T00:00:00Z',
    subjectCommitment: rec2.recordFingerprint, type: 'other',
  }, lab.privateKey);
  assert.equal((await call('POST', '/attestations', { body: labAtt })).json.strength, 'signed-and-accredited');
  const v2 = (await call('GET', '/verify/VEIL-VETTED')).json;
  assert.equal(v2.attestedByVettedLab, true);
  assert.equal(v2.attested, true);
  assert.match((await call('GET', '/embed/VEIL-VETTED')).text, /Signed by Real Lab Inc\. VeilCore’s operator matched this name to agriculture\.example\.gov \(license TL-0001\) on \d{4}-\d{2}-\d{2}\. VeilCore doesn’t vouch for the lab’s work\./);

  // Renaming a vetted key drops the vetting.
  await sleep(5);
  await call('POST', '/attesters', { body: await registration(lab, { displayName: 'Eurofins Scientific', role: 'laboratory' }) });
  assert.equal((await call('GET', `/attesters/${lab.publicKey}`)).json.vetted, false);
  assert.equal((await call('GET', '/verify/VEIL-VETTED')).json.attestedByVettedLab, false);
});

// ---------------------------------------------------------------------------------------
// MEDIUM: the received-record id was derived from public data, so anyone could pre-create
// it and the recipient's claim failed forever with a 500. /transfers/pending/:handle also
// handed a stranger the source record id, quantity and note.
// ---------------------------------------------------------------------------------------
test('transfer block is refused: pending list leaks nothing, received id is random, claim succeeds', async () => {
  const sender = key();
  const recipient = key();
  const attacker = key();
  const rec = await makeRecord('VEIL-XFER01');
  await call('PUT', '/api/records', { holder: sender, body: [rec] });
  const offer = await call('POST', '/transfers', { holder: sender, body: { sourceRecord: rec.id, toHandle: 'lab@example.com', quantity: '10 clones', note: 'invoice 4411, deal terms attached' } });
  assert.equal(offer.status, 200);

  // A stranger, no key, guesses the handle. The pending list used to say that something was
  // waiting; since sealed records round 2 it is gone (410), and the registry holds only the
  // tag the sender's browser made from the handle (helpers.mjs testBody), never the handle.
  const pend = await call('GET', '/transfers/pending/lab@example.com');
  assert.equal(pend.status, 410);
  assert.deepEqual(pend.json, { error: 'removed' });
  assert.doesNotMatch(JSON.stringify(pend.json), /invoice|10 clones|VEIL-XFER01/);
  assert.equal(db.prepare('SELECT to_handle FROM transfers WHERE id = ?').get(offer.json.transferId).to_handle, handleTagFor(sender, 'lab@example.com'));
  // The old derivation, squatted anyway: it no longer matters.
  const oldDerivedId = `${rec.id}-R${offer.json.transferId.slice(3, 7)}`;
  await call('PUT', '/api/records', { holder: attacker, body: [{ id: oldDerivedId, strainName: 'squat' }] });

  const wrongCode = await call('POST', `/transfers/${offer.json.transferId}/claim`, { holder: attacker, body: { claimCode: 'nope' } });
  assert.equal(wrongCode.status, 400);

  const claim = await call('POST', `/transfers/${offer.json.transferId}/claim`, { holder: recipient, body: { claimCode: offer.json.claimCode } });
  assert.equal(claim.status, 200);
  assert.match(claim.json.recordId, /^VEIL-[0-9A-F]{32}$/, '128 random bits, chosen by the server');
  assert.notEqual(claim.json.recordId, oldDerivedId);
  // The quantity and note were sealed by the sender's browser (test wrapper: helpers.mjs
  // testBody); the recipient, holding the code, opens them. The registry has neither.
  const offered = openOfferForTest(claim.json.offerSealed, offerKeyFor(rec.id), rec.id, '');
  assert.equal(offered.note, 'invoice 4411, deal terms attached', 'the recipient, holding the code, gets the note');
  assert.equal(offered.quantity, '10 clones');
  assert.equal(claim.json.note, null);
  assert.equal(claim.json.quantity, null);
  const mine = (await call('GET', '/api/records', { holder: recipient })).json;
  assert.ok(mine.some((r) => r.id === claim.json.recordId && r.receivedFrom === rec.id));
  assert.ok((await call('GET', `/records/${claim.json.recordId}`)).json.registryFirstSeen, 'received records get a first-seen date');

  const again = await call('POST', `/transfers/${offer.json.transferId}/claim`, { holder: recipient, body: { claimCode: offer.json.claimCode } });
  assert.equal(again.status, 400, 'a second claim is a clear refusal, not a 500');
  assert.match(again.json.error, /already been claimed/);
});

// ---------------------------------------------------------------------------------------
// MEDIUM: /lineage/verify said ok:true for a commitment nothing in the registry has.
// ---------------------------------------------------------------------------------------
test('clean-descent for nothing is refused: /lineage/verify says ok:false for an unknown commitment', async () => {
  const nonexistent = 'ab'.repeat(32);
  const out = await call('POST', '/lineage/verify', { body: { record: nonexistent, chain: [] } });
  assert.equal(out.status, 200);
  assert.equal(out.json.ok, false);
  assert.match(out.json.reason, /no record with that commitment/);

  // A stored, unencumbered record still verifies.
  const rec = await makeRecord('VEIL-LINOK1');
  await call('PUT', '/api/records', { holder: key(), body: [rec] });
  assert.equal((await call('POST', '/lineage/verify', { body: { record: rec.recordFingerprint, chain: [] } })).json.ok, true);
});

// ---------------------------------------------------------------------------------------
// MEDIUM: the embed printed the holder's own loggedAt as "Sealed <date>" and said the date
// rested on the registry, never that the holder typed it.
// ---------------------------------------------------------------------------------------
test('embed date: the holder\'s date is labelled as theirs and the registry\'s first-seen date is shown apart', async () => {
  const holder = key();
  const rec = await makeRecord('VEIL-EMBDAT', { loggedAt: '2021-03-01T00:00:00Z' });
  await call('PUT', '/api/records', { holder, body: [rec] });
  // The holder's date is shown only if they grant it (round D).
  assert.doesNotMatch((await call('GET', '/embed/VEIL-EMBDAT')).text, /Date stated by the holder/);
  await call('PUT', '/api/records/VEIL-EMBDAT/disclosure', { holder, body: grantForTest(rec, ['sealed-at']) });
  const html = (await call('GET', '/embed/VEIL-EMBDAT')).text;
  assert.doesNotMatch(html, /Sealed 20/, 'no bare "Sealed <date>"');
  assert.match(html, /Date stated by the holder: 2021-03-01 \(UTC\)\. The holder chose this date; nobody checked it\./);
  const today = new Date().toISOString().slice(0, 10);
  assert.match(html, new RegExp(`First seen by this registry, in this exact form, on ${today}`));
  assert.doesNotMatch(html, /its date rests on the registry rather than on a ledger/);
});

// ---------------------------------------------------------------------------------------
// MEDIUM: correction ids were predictable (<id>-C + 4 base36 chars of Date.now()). An
// attacker who squatted one made the victim's original publicly point at attacker content.
// The app now uses 128-bit random ids; the server refuses the pointer regardless.
// ---------------------------------------------------------------------------------------
test('correction hijack is refused: supersededBy may not name another holder\'s record', async () => {
  const victim = key();
  const attacker = key();
  const orig = await makeRecord('VEIL-CORR01', { strainName: 'Genuine' });
  await call('PUT', '/api/records', { holder: victim, body: [orig] });

  const predicted = 'VEIL-CORR01-CABCD';
  await call('PUT', '/api/records', { holder: attacker, body: [{ id: predicted, strainName: 'Attacker Says Revoked' }] });

  const correction = await makeRecord(predicted, { strainName: 'Genuine (corrected)' });
  const save = await call('PUT', '/api/records', { holder: victim, body: [{ ...orig, supersededBy: predicted }, correction] });
  assert.equal(save.json.ok, false, 'the app now reads this and rolls the correction back');
  assert.deepEqual(save.json.notWritten, [predicted]);
  assert.ok(save.json.rejected.some((r) => r.id === orig.id && /another holder/.test(r.reason)));

  assert.equal((await call('GET', '/verify/VEIL-CORR01')).json.supersededBy, undefined, 'the original is not marked superseded');

  // The legitimate flow: a fresh 128-bit id, saved together with the original.
  const freshId = `VEIL-${key().slice(0, 32).toUpperCase()}`;
  const good = await makeRecord(freshId, { strainName: 'Genuine (corrected)' });
  const ok = await call('PUT', '/api/records', { holder: victim, body: [{ ...orig, supersededBy: freshId }, { ...good, supersedes: { recordId: orig.id, changedFields: ['strainName'], effectiveAt: '2026-10-01T00:00:00Z' } }] });
  assert.equal(ok.json.ok, true);
  assert.equal((await call('GET', '/verify/VEIL-CORR01')).json.supersededBy, freshId);
  // The short legacy ids still store.
  assert.equal((await call('PUT', '/api/records', { holder: victim, body: [await makeRecord('VEIL-A1B2C3')] })).json.count, 1);
});

// ---------------------------------------------------------------------------------------
// LOW: the public view echoed holder-supplied `supersedes` verbatim (correction reason
// text, or any JSON up to the body cap).
// ---------------------------------------------------------------------------------------
test('public view echo is refused: supersedes is whitelisted to recordId, changedFields, effectiveAt', async () => {
  const holder = key();
  const rec = {
    ...(await makeRecord('VEIL-ECHO01')),
    supersedes: { recordId: 'VEIL-ECHO00', changedFields: ['notes'], effectiveAt: '2026-10-01T00:00:00Z', reason: 'lab found botrytis in batch 7', anything: { nested: ['x'.repeat(1000)] } },
  };
  await call('PUT', '/api/records', { holder, body: [rec] });
  const pub = (await call('GET', '/records/VEIL-ECHO01')).json;
  assert.deepEqual(pub.supersedes, { recordId: 'VEIL-ECHO00', changedFields: ['notes'], effectiveAt: '2026-10-01T00:00:00Z' });
  const embed = (await call('GET', '/embed/VEIL-ECHO01')).text;
  assert.doesNotMatch(embed, /botrytis/);
  // The holder still reads their own record in full: the reason is sealed with the rest.
  const mine = (await call('GET', '/api/records', { holder })).json.find((r) => r.id === 'VEIL-ECHO01');
  assert.equal(mine.supersedes.reason, undefined, 'not stored in the clear');
  assert.equal(openForTest(mine, vaultKeyFor(holder)).supersedes.reason, 'lab found botrytis in batch 7');
  // And a reason sent in the clear is refused, not stored and filtered.
  const leaky = { ...sealForTest(await makeRecord('VEIL-ECHO02'), vaultKeyFor(holder)), supersedes: { recordId: 'VEIL-ECHO00', reason: 'botrytis' } };
  const r = await call('PUT', '/api/records', { holder, body: plain([leaky]) });
  assert.match(r.json.rejected[0].reason, /^supersedes\.reason is not stored in the clear/);
});

// ---------------------------------------------------------------------------------------
// LOW: claiming a transfer wrote the first 16 chars of the RECIPIENT's secret holder key
// into the SENDER's record body. Any holder key, even one character, was accepted.
// ---------------------------------------------------------------------------------------
test('key prefix leak is refused: the sender sees a one-way party id; short keys are rejected', async () => {
  const sender = key();
  const recipient = key();
  const rec = await makeRecord('VEIL-KLEAK1');
  await call('PUT', '/api/records', { holder: sender, body: [rec] });
  const offer = (await call('POST', '/transfers', { holder: sender, body: { sourceRecord: rec.id, toHandle: 'h-kleak' } })).json;
  assert.equal((await call('POST', `/transfers/${offer.transferId}/claim`, { holder: recipient, body: { claimCode: offer.claimCode } })).status, 200);
  const mine = (await call('GET', '/api/records', { holder: sender })).json.find((r) => r.id === rec.id);
  assert.equal(mine.attestation.type, 'receipt-confirmed', 'the receipt confirmation still lands');
  assert.equal(mine.attestation.attesterKey, createHash('sha256').update(`veilcore:party:${recipient}`).digest('hex'));
  assert.ok(!JSON.stringify(mine).includes(recipient.slice(0, 8)), 'no part of the recipient\'s key');

  for (const bad of ['a', 'flood', 'z'.repeat(64), 'ab'.repeat(31)]) {
    assert.equal((await call('GET', '/api/records', { holder: bad })).status, 400, `holder key ${bad.slice(0, 8)}… refused`);
  }
  assert.equal((await call('GET', '/api/records', { holder: recipient.toUpperCase() })).status, 200, 'upper-case hex, as a restored key may be, is accepted');
});

// ---------------------------------------------------------------------------------------
// LOW: field limits. Licences had no validation; records only the 512 KB request cap.
// ---------------------------------------------------------------------------------------
test('oversized and malformed records and licences are refused; normal ones store', async () => {
  const holder = key();
  // Since sealed records the limits are on the box (sealed.js): the registry can't see a
  // field's length, only the whole record's.
  // Round 2 (L5): 360,000 characters of box, 384 KiB of row.
  const big = await makeRecord('VEIL-HUGE01', { notes: 'x'.repeat(280_000) });
  const r0 = await call('PUT', '/api/records', { holder, body: [big] });
  assert.equal(r0.json.count, 0);
  assert.match(r0.json.rejected[0].reason, /sealed\.ct may be at most 360000 characters/);
  const huge = await makeRecord('VEIL-HUGE01', { notes: 'x'.repeat(300_000) });
  const r1 = await call('PUT', '/api/records', { holder, body: [huge] });
  assert.equal(r1.json.count, 0);
  assert.match(r1.json.rejected[0].reason, /a record may be at most 393216 bytes/);
  assert.equal((await call('PUT', '/api/records', { holder, body: [await makeRecord('VEIL-HUGE01', { notes: 'x'.repeat(100_000) })] })).json.count, 1,
    'a long note is the holder\'s business');
  const badId = await call('PUT', '/api/records', { holder, body: [{ ...(await makeRecord('ok')), id: 'has spaces and <tags>' }] });
  assert.equal(badId.json.count, 0);

  const lic = await call('PUT', '/api/licenses', { holder, body: [
    { id: 'LIC-1', recordId: 'VEIL-HUGE01', terms: { licensee: 'Grower' } },
    { id: 'LIC-2', blob: 'y'.repeat(280_000) },
    { id: 'bad id!' },
    'not an object',
  ] });
  assert.equal(lic.json.count, 1);
  assert.equal(lic.json.rejected.length, 3);
  assert.equal((await call('GET', '/api/licenses', { holder })).json.length, 1);
  // A licence is { id, sealed }: which record it is about is sealed too.
  const clear = await call('PUT', '/api/licenses', { holder, body: plain([{ ...sealForTest({ id: 'LIC-3' }, vaultKeyFor(holder), 'licenses'), recordId: 'VEIL-HUGE01' }]) });
  assert.match(clear.json.rejected[0].reason, /^recordId is not stored in the clear/);
});

// ---------------------------------------------------------------------------------------
// LOW: rate limit. Behind Railway's single proxy, the client cannot choose its bucket by
// writing X-Forwarded-For: the proxy appends the address it saw and only that is trusted.
// ---------------------------------------------------------------------------------------
test('rate limit: rotating X-Forwarded-For through a one-hop proxy does not escape the limit', async () => {
  // A stand-in for Railway's edge: forwards to the app and appends the peer address.
  const proxy = http.createServer((req, res) => {
    const upstream = new URL(base);
    const xff = [req.headers['x-forwarded-for'], req.socket.remoteAddress].filter(Boolean).join(', ');
    const p = http.request({ host: upstream.hostname, port: upstream.port, path: req.url, method: req.method, headers: { ...req.headers, 'x-forwarded-for': xff } }, (up) => {
      res.writeHead(up.statusCode, up.headers);
      up.pipe(res);
    });
    req.pipe(p);
  });
  proxy.listen(0);
  await new Promise((r) => proxy.once('listening', r));
  const via = `http://127.0.0.1:${proxy.address().port}`;
  let limited = 0;
  try {
    // In one minute, as a client hammering it would be (helpers.mjs).
    await inOneMinute(async () => {
      for (let i = 0; i < 140; i++) {
        const r = await fetch(`${via}/api/records`, {
          method: 'DELETE',
          headers: { 'content-type': 'application/json', 'x-holder-key': key(), 'x-forwarded-for': `10.9.${i >> 8}.${i & 255}` },
          body: JSON.stringify({ ids: ['x'] }),
        });
        await r.text();
        if (r.status === 429) limited++;
      }
    });
  } finally {
    proxy.close();
  }
  assert.ok(limited > 0, 'a spoofed X-Forwarded-For no longer picks a fresh bucket');
});
