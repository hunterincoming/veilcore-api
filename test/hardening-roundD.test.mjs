// Attack round D (4 Oct 2026), turned into regression tests. The PoCs in
// review-out/roundD-registry.md each demonstrated a weakness; every test here asserts the
// fixed behaviour instead. Plus the four registry questions from the site review, and
// holder-controlled disclosure (the site's "choose what they see" now limits what a
// stranger gets). No network, no live service.
//
// SPDX-License-Identifier: Apache-2.0

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { createHash, randomBytes } from 'node:crypto';
import { generateKeypair, signAttestation, canonicalise, sha256Hex, newNonce } from 'veilcore-records';
import { registrationPayload, ATTESTATION_LIMITS } from '../lineage/attesters.mjs';
import { untilReady, testBody, plain, sealForTest, vaultKeyFor, grantForTest, offerFromRecord, sealOfferForTest, openOfferForTest } from './helpers.mjs';

process.env.DB_PATH = ':memory:';
process.env.VEILCORE_OTS = 'off';
process.env.VEILCORE_OPERATOR_TOKEN = 'op-secret-token-at-least-32-characters';
const require = createRequire(import.meta.url);
const { app, db } = require('../server.js');

const H = (name) => createHash('sha256').update(name).digest('hex');
const OP = { 'x-operator-token': 'op-secret-token-at-least-32-characters' };

let base, server;
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
    headers: { 'content-type': 'application/json', ...(holder ? { 'x-holder-key': holder } : {}), ...headers },
    body: body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(testBody(method, path, holder, body)),
  });
  const text = await res.text();
  let json; try { json = JSON.parse(text); } catch { json = text; }
  return { status: res.status, json, text };
};

const committedOf = (r) => ({ breedingMethod: r.breedingMethod ?? '', bredBy: r.bredBy, dateCreated: r.dateCreated,
  loggedAt: r.loggedAt, nonce: r.nonce, notes: r.notes, parents: r.parents ?? [],
  photoFingerprints: r.photoFingerprints ?? [], refId: r.refId ?? '', strainName: r.strainName });

const makeRecord = async (id, over = {}) => {
  const r = { id, strainName: 'C' + id, bredBy: 'B', dateCreated: '2026-01-01',
    loggedAt: '2024-01-01T00:00:00Z', nonce: newNonce(), notes: 'n', parents: [], photoFingerprints: [],
    breedingMethod: 'm', refId: '', ...over };
  r.recordFingerprint = await sha256Hex(canonicalise(committedOf(r)));
  return r;
};

const signedAttestationFor = async (subjectCommitment, attestationId, kp) => {
  kp ??= await generateKeypair();
  const body = {
    type: 'veilcore/attestation/v1', attestationId, subjectCommitment,
    documentHash: 'a'.repeat(64), hashAlgorithm: 'sha256', issuedAt: new Date().toISOString(),
    attester: { publicKey: kp.publicKey, displayName: 'A Real Lab' },
  };
  return signAttestation(body, kp.privateKey);
};

const registration = async (kp, fields) => {
  const reg = { publicKey: kp.publicKey, issuedAt: Date.now(), ...fields };
  const priv = await crypto.subtle.importKey('pkcs8', Buffer.from(kp.privateKey, 'hex'), { name: 'Ed25519' }, false, ['sign']);
  const sig = await crypto.subtle.sign('Ed25519', priv, new TextEncoder().encode(registrationPayload(reg)));
  return { ...reg, signature: Buffer.from(sig).toString('hex') };
};

/** Rows straight into the table: the write rate limit (120/min) is not what is under test. */
const plantUnvetted = (subject, n, prefix) => {
  const ins = db.prepare('INSERT INTO attestations (attestation_id, subject_commitment, attester_key, body, created_at) VALUES (?,?,?,?,?)');
  db.transaction(() => {
    for (let i = 0; i < n; i++) {
      const pk = randomBytes(32).toString('hex');
      const id = `${prefix}-${i}`;
      ins.run(id, subject, pk, JSON.stringify({ attestationId: id, subjectCommitment: subject, signature: 'ff', attester: { publicKey: pk } }), Date.now() - 1000 + i);
    }
  })();
};

// ---------------------------------------------------------------------------------------
// D1 (Medium) attestation griefing
// ---------------------------------------------------------------------------------------
test('D1 unvetted attestations per record are capped; a vetted lab still gets in; reads are bounded and vetted-first', async () => {
  const victim = await makeRecord('d1-victim');
  assert.equal((await call('PUT', '/api/records', { holder: H('d1-holder'), body: [victim] })).json.count, 1);
  const c = victim.recordFingerprint;

  plantUnvetted(c, ATTESTATION_LIMITS.unvettedPerSubject, 'd1-junk');
  const over = await call('POST', '/attestations', { body: await signedAttestationFor(c, 'd1-one-too-many') });
  assert.equal(over.status, 400);
  assert.match(over.json.error, /keys nobody has vetted/);

  // A lab the operator has vetted is not kept out by the junk.
  const lab = await generateKeypair();
  assert.equal((await call('POST', '/attesters', { body: await registration(lab, { displayName: 'Vetted Lab' }) })).status, 200);
  assert.equal((await call('POST', `/attesters/${lab.publicKey}/vetting`, { headers: OP, body: { vetted: true, check: { source: 'licence-listing', sourceUrl: 'https://agriculture.example.gov/testing-labs', licenceNo: 'TL-0001', emailDomain: 'reallab.example', checkedAt: new Date().toISOString().slice(0, 10), checkedBy: 'AB' } } })).status, 200);
  const real = await call('POST', '/attestations', { body: await signedAttestationFor(c, 'd1-real-lab', lab) });
  assert.equal(real.status, 200, JSON.stringify(real.json));

  // Listing: one bounded page, the vetted one first, and the total so a client sees the cut.
  plantUnvetted(c, 30, 'd1-more'); // the cap is enforced on submit; old rows may exceed it
  const page = await call('GET', `/attestations/subject/${c}`);
  assert.equal(page.json.attestations.length, ATTESTATION_LIMITS.page);
  assert.equal(page.json.total, ATTESTATION_LIMITS.unvettedPerSubject + 30 + 1);
  assert.equal(page.json.attestations[0].attestationId, 'd1-real-lab');
  assert.equal(page.json.attestations[0].vettedAttester, true);
  const asked = await call('GET', `/attestations/subject/${c}?limit=100000&offset=120`);
  assert.equal(asked.json.limit, ATTESTATION_LIMITS.page, 'a caller cannot ask for more than a page');
  assert.equal(asked.json.attestations.length, page.json.total - 120);

  // /verify does not load the rows at all now, and still answers correctly.
  const v = await call('GET', `/verify/${victim.id}`);
  assert.equal(v.json.signedAttestation, true);
  assert.equal(v.json.attestedByVettedLab, true);
  // The embed renders one page.
  assert.equal((await call('GET', `/embed/${victim.id}`)).status, 200);
});

test('D1 re-sending an attestation already stored stays idempotent at the cap', async () => {
  const rec = await makeRecord('d1-idem');
  await call('PUT', '/api/records', { holder: H('d1-idem'), body: [rec] });
  const att = await signedAttestationFor(rec.recordFingerprint, 'd1-idem-att');
  assert.equal((await call('POST', '/attestations', { body: att })).status, 200);
  plantUnvetted(rec.recordFingerprint, ATTESTATION_LIMITS.unvettedPerSubject, 'd1-idem-junk');
  assert.equal((await call('POST', '/attestations', { body: att })).status, 200);
});

test('D1 a retracted attestation no longer counts as signed on /verify', async () => {
  const rec = await makeRecord('d1-retract');
  await call('PUT', '/api/records', { holder: H('d1-retract'), body: [rec] });
  const kp = await generateKeypair();
  const att = await signedAttestationFor(rec.recordFingerprint, 'd1-retract-att', kp);
  await call('POST', '/attestations', { body: att });
  assert.equal((await call('GET', `/verify/${rec.id}`)).json.signedAttestation, true);
  db.prepare('INSERT INTO retractions (attestation_id, body, retracted_at) VALUES (?,?,?)').run('d1-retract-att', '{}', Date.now());
  assert.equal((await call('GET', `/verify/${rec.id}`)).json.signedAttestation, false);
});

// ---------------------------------------------------------------------------------------
// D2 (Low) obligation proposals on records that do not exist; unbounded listing
// ---------------------------------------------------------------------------------------
test('D2 a proposal against a commitment no record carries is refused; listings are paged', async () => {
  const atk = H('d2-spammer');
  const missing = createHash('sha256').update('d2-missing').digest('hex');
  const obl = createHash('sha256').update('d2-obl').digest('hex');
  const r = await call('POST', '/lineage/obligations', { holder: atk, body: { record: missing, obligation: obl } });
  assert.equal(r.status, 400);
  assert.match(r.json.error, /no record with that fingerprint/);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM obligations_v2 WHERE record = ?').get(missing).n, 0);

  // A proposal against a real record still works (the holder decides on it).
  const rec = await makeRecord('d2-real');
  await call('PUT', '/api/records', { holder: H('d2-holder'), body: [rec] });
  for (let i = 0; i < 3; i++) {
    const o = createHash('sha256').update(`d2-real-obl-${i}`).digest('hex');
    const p = await call('POST', '/lineage/obligations', { holder: atk, body: { record: rec.recordFingerprint, obligation: o } });
    assert.equal(p.json.status, 'proposed');
  }
  // The open listing is gone since round 3 (P5): nothing to page.
  assert.equal((await call('GET', '/lineage/obligations?limit=2')).status, 410);
  const mine = await call('GET', '/lineage/obligations/proposals?limit=1', { holder: H('d2-holder') });
  assert.equal(mine.json.proposals.length, 1);
});

test('D2 a malformed commitment on /lineage/ancestors is a 400, not a 500', async () => {
  const r = await call('GET', '/lineage/ancestors/not-hex');
  assert.equal(r.status, 400);
  const ok = await call('GET', `/lineage/ancestors/${'ab'.repeat(32)}`);
  assert.equal(ok.status, 200);
  assert.deepEqual(ok.json.ancestors, []);
  assert.equal(ok.json.total, 0);
});

// ---------------------------------------------------------------------------------------
// D3 (Low) validation input reached the 500 handler
// ---------------------------------------------------------------------------------------
test('D3 a malformed record is a per-record rejection, and the rest of the batch is stored', async () => {
  // Since sealed records the registry can't recompute a commitment (a committed field set
  // to null is inside the box), so it no longer says it checked one: integrityCheckedBy
  // "holder". A record it can see is wrong is still refused on its own, never the batch.
  const holder = H('d3-holder');
  const nullInside = await makeRecord('d3-null');
  nullInside.bredBy = null;
  const good = await makeRecord('d3-good');
  const clear = { ...sealForTest(await makeRecord('d3-clear'), vaultKeyFor(holder)), bredBy: null };
  const r = await call('PUT', '/api/records', { holder, body: plain([clear, sealForTest(nullInside, vaultKeyFor(holder)), sealForTest(good, vaultKeyFor(holder))]) });
  assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.equal(r.json.count, 2, 'what the registry cannot see is the holder\'s to check');
  assert.equal(r.json.integrityCheckedBy, 'holder');
  assert.equal(r.json.verified, undefined, 'no claim that anything was verified');
  assert.equal(r.json.rejected.length, 1);
  assert.equal(r.json.rejected[0].id, 'd3-clear');
  assert.match(r.json.rejected[0].reason, /^bredBy is not stored in the clear/);
});

test('D3b a number that parses to Infinity (1e400) is rejected cleanly', async () => {
  const sealed = sealForTest(await makeRecord('d3b-inf'), vaultKeyFor(H('d3b-holder')));
  const raw = JSON.stringify([sealed]).replace(/}]$/, ',"loggedAt":1e400}]');
  const r = await call('PUT', '/api/records', { holder: H('d3b-holder'), body: raw });
  assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.equal(r.json.count, 0);
  assert.match(r.json.rejected[0].reason, /^loggedAt is not stored in the clear/);
  const fp = JSON.stringify([{ ...sealed, recordFingerprint: 'x' }]).replace('"recordFingerprint":"x"', '"recordFingerprint":1e400');
  const r2 = await call('PUT', '/api/records', { holder: H('d3b-holder'), body: fp });
  assert.equal(r2.status, 200, JSON.stringify(r2.json));
  assert.match(r2.json.rejected[0].reason, /recordFingerprint must be 64 lowercase hexadecimal/);
});

// ---------------------------------------------------------------------------------------
// D4 (Low) concurrent seals
// ---------------------------------------------------------------------------------------
test('D4 concurrent seals produce one batch, and every batch has its proofs', async () => {
  const recs = [];
  for (let i = 0; i < 4; i++) recs.push(await makeRecord(`d4-${i}`));
  await call('PUT', '/api/records', { holder: H('d4-holder'), body: recs });
  const before = db.prepare('SELECT COUNT(*) AS n FROM batches').get().n;

  const results = await Promise.all([
    call('POST', '/batches/seal', { headers: OP }),
    call('POST', '/batches/seal', { headers: OP }),
    call('POST', '/batches/seal', { headers: OP }),
  ]);
  const ok = results.filter((r) => r.status === 200);
  assert.equal(ok.length, 1, JSON.stringify(results.map((r) => [r.status, r.json])));
  for (const r of results.filter((x) => x.status !== 200)) {
    assert.ok(r.status === 409 || (r.status === 400 && /nothing pending/.test(r.json.error)), JSON.stringify(r.json));
    assert.equal(r.json.code, undefined, 'the internal status code is not echoed');
  }
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM batches').get().n, before + 1);
  const orphaned = db.prepare(`SELECT b.batch_id FROM batches b WHERE b.record_count > 0
    AND NOT EXISTS (SELECT 1 FROM batch_proofs p WHERE p.batch_id = b.batch_id)`).all();
  assert.deepEqual(orphaned, []);
  for (const r of recs) {
    assert.equal(db.prepare('SELECT batch_id FROM batch_proofs WHERE commitment = ?').get(r.recordFingerprint).batch_id, ok[0].json.batchId);
  }
});

// ---------------------------------------------------------------------------------------
// D5 (Low) transfer claim copied the sender's private body
// ---------------------------------------------------------------------------------------
test('D5 a claimed transfer carries only the allow-listed fields, and the recipient can seal it', async () => {
  const sender = H('d5-sender');
  const recipient = H('d5-recipient');
  const src = await makeRecord('d5-src', {
    notes: 'TOP SECRET breeding notes', breedingMethod: 'proprietary tek', parents: [{ name: 'Secret Mother' }],
    photoFingerprints: ['e'.repeat(64)], refId: 'internal-42',
  });
  src.dnaFingerprint = 'd'.repeat(64);
  src.licenseIds = ['LIC-PRIVATE'];
  assert.equal((await call('PUT', '/api/records', { holder: sender, body: [src] })).json.count, 1);

  // What crosses is now chosen by the sender's browser, in the sealed offer (CONTRACT.md #8).
  const offerKey = randomBytes(32);
  const sealedOffer = sealOfferForTest(offerFromRecord(src, { quantity: '10 clones' }), offerKey, src.id, src.recordFingerprint);
  const offer = await call('POST', '/transfers', { holder: sender, body: { sourceRecord: 'd5-src', toHandle: 'buyer@example', sealedOffer } });
  const claim = await call('POST', `/transfers/${offer.json.transferId}/claim`, { holder: recipient, body: { claimCode: offer.json.claimCode } });
  assert.ok(claim.json.recordId);
  assert.deepEqual(claim.json.offerSealed, sealedOffer, 'the offer, exactly as sent');

  // The registry writes a stub of public fields only: no nonce, nothing of the sender's.
  const stub = (await call('GET', '/api/records', { holder: recipient })).json.find((r) => r.id === claim.json.recordId);
  // No name either (round 5, CONTRACT.md #28): it is in the sealed offer.
  assert.deepEqual(Object.keys(stub).sort(), ['id', 'receivedAt', 'receivedFrom', 'receivedFromCommitment', 'transferId']);
  assert.equal(stub.strainName, undefined);
  assert.equal(stub.receivedFrom, 'd5-src');
  assert.equal(stub.receivedFromCommitment, src.recordFingerprint);
  const offered = openOfferForTest(claim.json.offerSealed, offerKey, src.id, src.recordFingerprint);
  assert.equal(offered.bredBy, src.bredBy);
  assert.equal(offered.quantity, '10 clones');
  for (const text of [JSON.stringify(stub), JSON.stringify(offered)]) {
    assert.ok(!text.includes('TOP SECRET'));
    assert.ok(!text.includes('Secret Mother'));
    assert.ok(!text.includes('LIC-PRIVATE'));
  }

  // Unsealed: a grant on it has nothing current to answer from.
  await call('PUT', `/api/records/${stub.id}/disclosure`, { holder: recipient, body: { show: ['attestation-status'] } });
  const v = (await call('GET', `/verify/${stub.id}`)).json;
  assert.equal(v.dnaPairedByHolder, undefined);
  assert.deepEqual(v.staleGrant, ['dna']);

  // The recipient's browser builds the record from the offer and seals it, as the app does.
  const received = {
    ...stub, strainName: offered.strainName, bredBy: offered.bredBy, dateCreated: offered.dateCreated, quantity: offered.quantity,
    notes: '', breedingMethod: '', parents: [], photoFingerprints: [], refId: '', licenseIds: [],
    nonce: newNonce(), loggedAt: stub.receivedAt,
  };
  const sealed = { ...received, recordFingerprint: await sha256Hex(canonicalise(committedOf(received))) };
  const put = await call('PUT', '/api/records', { holder: recipient, body: [sealed] });
  assert.equal(put.json.count, 1, JSON.stringify(put.json));
  assert.equal(put.json.integrityCheckedBy, 'holder');
});

// ---------------------------------------------------------------------------------------
// The site review's four "needs the registry" questions
// ---------------------------------------------------------------------------------------
test('(b) PUT /api/records does not store client-supplied attestation; the registry-written one survives re-saves', async () => {
  const holder = H('qb-holder');
  const typed = { ...(await makeRecord('qb-typed')), attestation: { lab: 'Fake Lab', attestedAt: 1 } };
  assert.equal((await call('PUT', '/api/records', { holder, body: [typed] })).json.count, 1);
  const stored = (await call('GET', '/api/records', { holder })).json.find((r) => r.id === 'qb-typed');
  assert.equal(stored.attestation, undefined, 'a holder cannot type an attestation into their own record');

  // A real one, written by the registry when the recipient claims.
  const src = await makeRecord('qb-src');
  await call('PUT', '/api/records', { holder, body: [src] });
  const offer = await call('POST', '/transfers', { holder, body: { sourceRecord: 'qb-src', toHandle: 'lab@example' } });
  await call('POST', `/transfers/${offer.json.transferId}/claim`, { holder: H('qb-lab'), body: { claimCode: offer.json.claimCode } });
  const withReceipt = (await call('GET', '/api/records', { holder })).json.find((r) => r.id === 'qb-src');
  assert.equal(withReceipt.attestation.type, 'receipt-confirmed');

  // The app re-saves from a stale copy (no attestation), then a forged one: both ignored.
  assert.equal((await call('PUT', '/api/records', { holder, body: [src] })).json.count, 1);
  assert.deepEqual((await call('GET', '/api/records', { holder })).json.find((r) => r.id === 'qb-src').attestation, withReceipt.attestation);
  await call('PUT', '/api/records', { holder, body: [{ ...src, attestation: { type: 'receipt-confirmed', addressedTo: 'someone-else' } }] });
  assert.deepEqual((await call('GET', '/api/records', { holder })).json.find((r) => r.id === 'qb-src').attestation, withReceipt.attestation);
});

test('(c) an empty upload deletes nothing; DELETE needs explicit ids', async () => {
  const holder = H('qc-holder');
  const recs = [await makeRecord('qc-1'), await makeRecord('qc-2')];
  await call('PUT', '/api/records', { holder, body: recs });
  const empty = await call('PUT', '/api/records', { holder, body: [] });
  assert.equal(empty.status, 200);
  assert.equal(empty.json.count, 0);
  assert.equal((await call('GET', '/api/records', { holder })).json.length, 2);
  assert.equal((await call('DELETE', '/api/records', { holder, body: { ids: [] } })).status, 400);
  assert.equal((await call('DELETE', '/api/records', { holder, body: {} })).status, 400);
  assert.equal((await call('GET', '/api/records', { holder })).json.length, 2);
});

test('(d) a record reusing another holder\'s fingerprint is refused, including when both race', async () => {
  const rec = await makeRecord('qd-original');
  await call('PUT', '/api/records', { holder: H('qd-owner'), body: [rec] });
  const copy = await call('PUT', '/api/records', { holder: H('qd-copier'), body: [{ ...rec, id: 'qd-copy' }] });
  assert.equal(copy.json.count, 0);
  assert.match(copy.json.rejected[0].reason, /already registered by another holder/);

  // Two holders storing the same new fingerprint at the same moment: exactly one wins.
  const shared = await makeRecord('qd-race-a');
  const [a, b] = await Promise.all([
    call('PUT', '/api/records', { holder: H('qd-racer-1'), body: [shared] }),
    call('PUT', '/api/records', { holder: H('qd-racer-2'), body: [{ ...shared, id: 'qd-race-b' }] }),
  ]);
  assert.equal(a.json.count + b.json.count, 1, JSON.stringify([a.json, b.json]));
  const holders = db.prepare("SELECT DISTINCT holder_key FROM records WHERE json_extract(body, '$.recordFingerprint') = ?").all(shared.recordFingerprint);
  assert.equal(holders.length, 1);
});

// ---------------------------------------------------------------------------------------
// Holder-controlled disclosure
// ---------------------------------------------------------------------------------------
const GATED = ['priorPossession', 'unalteredSinceRegistryFirstSeen', 'dnaPairedByHolder', 'sealedAt',
  'loggedAtClaimedByHolder', 'lineageIntact', 'lineageNote', 'parents', 'breedingMethod'];

const secretRecord = async (id) => ({
  ...(await makeRecord(id, { parents: [{ name: 'Secret Mother' }, { name: 'Secret Father' }], breedingMethod: 'backcross x3', loggedAt: '2021-03-01T00:00:00Z' })),
  dnaFingerprint: 'ab'.repeat(32),
});

test('disclosure: no grant stored means the base view only, whatever ?show= asks for', async () => {
  const holder = H('g-none');
  const rec = await secretRecord('g-none');
  await call('PUT', '/api/records', { holder, body: [rec] });

  for (const q of ['', '?show=own,dna,lineage,sealed,parents,method', '?show=existence,attestation-status,descent-clean,sealed-at,parent-names,breeding-method']) {
    const v = (await call('GET', `/verify/${rec.id}${q}`)).json;
    assert.equal(v.found, true);
    assert.equal(v.recordFingerprint, rec.recordFingerprint);
    // The name is sealed (round 5): not in the base view.
    assert.equal(v.cultivar, undefined);
    assert.ok(v.registryFirstSeen);
    assert.equal(typeof v.signedAttestation, 'boolean');
    assert.equal(typeof v.anchored, 'boolean');
    assert.deepEqual(v.disclosed, [], q);
    for (const f of GATED) assert.equal(v[f], undefined, `${f} must not be in the base view (${q})`);
    if (q) assert.deepEqual(v.notGranted, ['own', 'dna', 'lineage', 'sealed', 'parents', 'method']);
  }
  assert.equal((await call('GET', `/records/${rec.id}`)).json.loggedAtClaimedByHolder, undefined);
  const html = (await call('GET', `/embed/${rec.id}?show=sealed-at`)).text;
  assert.doesNotMatch(html, /Date stated by the holder/);
  assert.doesNotMatch(html, /Secret Mother|backcross/);
  assert.deepEqual((await call('GET', `/api/records/${rec.id}/disclosure`, { holder })).json, { recordId: rec.id, show: [], forFingerprint: null, values: null, updatedAt: null });
});

test('disclosure: a stranger can neither set nor read a holder\'s grant', async () => {
  const holder = H('g-owner');
  const rec = await secretRecord('g-owner');
  await call('PUT', '/api/records', { holder, body: [rec] });
  assert.equal((await call('PUT', `/api/records/${rec.id}/disclosure`, { holder, body: { show: ['existence'] } })).status, 200);

  const stranger = H('g-stranger');
  const set = await call('PUT', `/api/records/${rec.id}/disclosure`, { holder: stranger, body: { show: ['parent-names', 'breeding-method'] } });
  assert.equal(set.status, 404);
  assert.equal((await call('PUT', `/api/records/${rec.id}/disclosure`, { body: { show: ['parent-names'] } })).status, 401);
  assert.equal((await call('PUT', `/api/records/${rec.id}/disclosure`, { holder: 'zz', body: { show: ['parent-names'] } })).status, 400);
  assert.equal((await call('GET', `/api/records/${rec.id}/disclosure`, { holder: stranger })).status, 404);
  assert.equal((await call('GET', `/api/records/${rec.id}/disclosure`)).status, 401);
  // Same answer for a record that does not exist at all.
  assert.equal((await call('PUT', '/api/records/no-such-record/disclosure', { holder: stranger, body: { show: [] } })).status, 404);

  assert.deepEqual((await call('GET', `/api/records/${rec.id}/disclosure`, { holder })).json.show, ['existence']);
  const v = (await call('GET', `/verify/${rec.id}?show=parents,method`)).json;
  assert.equal(v.parents, undefined);
  assert.equal(v.breedingMethod, undefined);
});

test('disclosure: ?show= narrows the grant and never widens it; no ?show= gives the whole grant', async () => {
  const holder = H('g-narrow');
  const rec = await secretRecord('g-narrow');
  await call('PUT', '/api/records', { holder, body: [rec] });
  const g = await call('PUT', `/api/records/${rec.id}/disclosure`, { holder, body: grantForTest(rec, ['sealed-at', 'existence', 'attestation-status']) });
  assert.equal(g.status, 200);
  assert.deepEqual(g.json.show, ['existence', 'attestation-status', 'sealed-at'], 'stored in canonical order');

  const widened = (await call('GET', `/verify/${rec.id}?show=existence,parent-names,breeding-method,holder-portfolio,terms-full`)).json;
  assert.deepEqual(widened.disclosed, ['own']);
  assert.equal(widened.priorPossession, false);
  assert.equal(widened.parents, undefined);
  assert.equal(widened.breedingMethod, undefined);
  assert.equal(widened.sealedAt, undefined, 'granted but not asked for: ?show= narrowed it away');
  assert.equal(widened.dnaPairedByHolder, undefined);
  assert.deepEqual(widened.notGranted, ['parents', 'method']);
  assert.deepEqual(widened.unavailable, ['others', 'agreementTerms']);

  const whole = (await call('GET', `/verify/${rec.id}`)).json;
  assert.deepEqual(whole.disclosed, ['own', 'dna', 'sealed']);
  assert.equal(whole.dnaPairedByHolder, true);
  assert.equal(whole.sealedAt, '2021-03-01T00:00:00Z');
  assert.equal(whole.loggedAtClaimedByHolder, '2021-03-01T00:00:00Z');
  assert.equal(whole.parents, undefined);
  assert.equal(whole.notGranted, undefined);
  assert.equal((await call('GET', `/records/${rec.id}`)).json.loggedAtClaimedByHolder, '2021-03-01T00:00:00Z');
  assert.match((await call('GET', `/embed/${rec.id}`)).text, /Date stated by the holder: 2021-03-01/);
  assert.doesNotMatch((await call('GET', `/embed/${rec.id}?show=existence`)).text, /Date stated by the holder/);

  // Withdrawing: an empty grant is base only again.
  await call('PUT', `/api/records/${rec.id}/disclosure`, { holder, body: { show: [] } });
  const after = (await call('GET', `/verify/${rec.id}`)).json;
  assert.deepEqual(after.disclosed, []);
  for (const f of GATED) assert.equal(after[f], undefined, f);
});

test('disclosure: legacy names are accepted in the grant and in ?show=, and both spellings answer', async () => {
  const holder = H('g-legacy');
  const rec = await secretRecord('g-legacy');
  await call('PUT', '/api/records', { holder, body: [rec] });
  const g = await call('PUT', `/api/records/${rec.id}/disclosure`, { holder, body: grantForTest(rec, ['own', 'parents', 'method', 'lineage', 'parent-names']) });
  assert.equal(g.status, 200, JSON.stringify(g.json));
  assert.deepEqual(g.json.show, ['existence', 'descent-clean', 'parent-names', 'breeding-method']);
  assert.deepEqual((await call('GET', `/api/records/${rec.id}/disclosure`, { holder })).json.show, g.json.show);

  const legacy = (await call('GET', `/verify/${rec.id}?show=parents`)).json;
  assert.deepEqual(legacy.parents, ['Secret Mother', 'Secret Father']);
  assert.deepEqual(legacy.disclosed, ['parents']);
  const current = (await call('GET', `/verify/${rec.id}?show=parent-names,breeding-method,descent-clean`)).json;
  assert.deepEqual(current.parents, ['Secret Mother', 'Secret Father']);
  assert.equal(current.breedingMethod, 'backcross x3');
  assert.equal(current.lineageIntact, null);
  assert.deepEqual(current.disclosed, ['lineage', 'parents', 'method']);
});

test('disclosure: unknown keys and holder-scoped keys are refused, and nothing is stored', async () => {
  const holder = H('g-refuse');
  const rec = await secretRecord('g-refuse');
  await call('PUT', '/api/records', { holder, body: [rec] });
  for (const show of [['holder-portfolio'], ['others'], ['terms-full'], ['agreementTerms'], ['existence', 'genetics'], 'existence', [1], null]) {
    const r = await call('PUT', `/api/records/${rec.id}/disclosure`, { holder, body: { show } });
    assert.equal(r.status, 400, JSON.stringify(show));
  }
  assert.deepEqual((await call('GET', `/api/records/${rec.id}/disclosure`, { holder })).json.show, []);
});

test('disclosure: a grant goes with its record, and does not pass to whoever stores the id next', async () => {
  const holder = H('g-del');
  const rec = await secretRecord('g-del');
  await call('PUT', '/api/records', { holder, body: [rec] });
  await call('PUT', `/api/records/${rec.id}/disclosure`, { holder, body: grantForTest(rec, ['parent-names']) });
  assert.deepEqual((await call('GET', `/verify/${rec.id}`)).json.parents, ['Secret Mother', 'Secret Father']);
  const ex = await call('GET', '/api/export', { holder });
  assert.deepEqual(ex.json.disclosures, { 'g-del': ['parent-names'] });
  assert.deepEqual(ex.json.disclosureValues['g-del'].forFingerprint, rec.recordFingerprint);

  assert.deepEqual((await call('DELETE', '/api/records', { holder, body: { ids: [rec.id] } })).json.removed, [rec.id]);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM disclosure_grants WHERE record_id = ?').get(rec.id).n, 0);

  // A grant row left by an older holder (e.g. stored before deletes removed grants).
  const other = await secretRecord('g-del');
  db.prepare('INSERT INTO disclosure_grants (record_id, holder_key, show, updated_at, grant_values, for_fingerprint) VALUES (?,?,?,?,?,?)')
    .run(rec.id, holder, JSON.stringify(['parent-names']), Date.now(), JSON.stringify({ parents: [{ name: 'Secret Mother' }] }), other.recordFingerprint);
  assert.equal((await call('PUT', '/api/records', { holder: H('g-next'), body: [other] })).json.count, 1);
  const v = (await call('GET', `/verify/${rec.id}`)).json;
  assert.deepEqual(v.disclosed, []);
  assert.equal(v.parents, undefined);
});

// ---------------------------------------------------------------------------------------
// Verification follow-up (4 Oct 2026): one malformed legacy fingerprint must not block
// sealing. veilcore-records 0.15's buildBatch throws on any commitment that is not 64
// lowercase hex, so such rows are left out of the batch and reported.
// ---------------------------------------------------------------------------------------
test('seal: malformed legacy fingerprints are skipped and reported; the rest is sealed', async () => {
  const insert = db.prepare('INSERT INTO records (id, holder_key, body, updated_at) VALUES (?,?,?,?)');
  const bad = {
    'legacy-upper': 'AB'.repeat(32),
    'legacy-short': 'ab'.repeat(31),
    'legacy-long': 'ab'.repeat(33),
    'legacy-nonhex': 'zz'.repeat(32),
    'legacy-0x': `0x${'ab'.repeat(31)}`,
    'legacy-number': 12345,
  };
  for (const [id, fp] of Object.entries(bad)) insert.run(id, H('legacy-holder'), JSON.stringify({ id, recordFingerprint: fp }), 0);
  const good = [await makeRecord('fp-good-1'), await makeRecord('fp-good-2')];
  assert.equal((await call('PUT', '/api/records', { holder: H('fp-holder'), body: good })).json.count, 2);

  const pending = await call('GET', '/batches/pending', { headers: OP });
  assert.equal(pending.status, 200);
  for (const id of Object.keys(bad)) assert.ok(!pending.json.records.includes(id), id);
  for (const r of good) assert.ok(pending.json.records.includes(r.id), r.id);
  assert.equal(pending.json.count, pending.json.records.length);
  assert.deepEqual(pending.json.skipped.map((s) => s.recordId).sort(), Object.keys(bad).sort());

  const sealed = await call('POST', '/batches/seal', { headers: OP });
  assert.equal(sealed.status, 200, JSON.stringify(sealed.json));
  assert.deepEqual(sealed.json.skipped.map((s) => s.recordId).sort(), Object.keys(bad).sort());
  for (const s of sealed.json.skipped) assert.match(s.reason, /64 lowercase hex/);
  // The malformed value itself is not echoed back.
  assert.ok(!JSON.stringify(sealed.json.skipped).includes('AB'.repeat(32)));
  for (const r of good) {
    assert.equal(db.prepare('SELECT batch_id FROM batch_proofs WHERE commitment = ?').get(r.recordFingerprint).batch_id, sealed.json.batchId);
  }
  // Everything in the batch is what a strict buildBatch accepts.
  for (const { commitment } of db.prepare('SELECT commitment FROM batch_proofs WHERE batch_id = ?').all(sealed.json.batchId)) {
    assert.match(commitment, /^[0-9a-f]{64}$/);
  }

  // With only malformed rows left, sealing says "nothing pending" (which the anchoring job
  // reads as "nothing to do") and still reports them.
  const again = await call('POST', '/batches/seal', { headers: OP });
  assert.equal(again.status, 400);
  assert.equal(again.json.error, 'nothing pending');
  assert.deepEqual(again.json.skipped.map((s) => s.recordId).sort(), Object.keys(bad).sort());
  assert.equal((await call('GET', '/batches/pending', { headers: OP })).json.count, 0);
});
