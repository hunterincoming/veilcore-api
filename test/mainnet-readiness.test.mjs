// Mainnet readiness (6 Oct 2026): veilcore-records 0.15.0, the two round D verification
// Lows on attester registration, and anchors across the move from Preview to mainnet.
//
// This file runs the registry as it is configured on mainnet day: VEILCORE_ANCHOR_NETWORK
// = mainnet and a mainnet contract. Batches anchored on Preview before the switch are
// written straight into the database, as the running registry holds them today.
//
// SPDX-License-Identifier: Apache-2.0

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  canonicalise, sha256Hex, verifyInclusion, verifyAttestation, signAttestation, generateKeypair,
} from 'veilcore-records';
import { checkRecord } from '../lineage/conformance.mjs';
import { registrationPayload, unusableKeyReason } from '../lineage/attesters.mjs';
import { untilReady, testBody, openForTest, vaultKeyFor } from './helpers.mjs';

const MAINNET_CONTRACT = '5c'.repeat(32);
const PREVIEW_CONTRACT = 'f75d42dc'.repeat(8); // the shape of the 27 Sep Preview contract
process.env.DB_PATH = ':memory:';
process.env.VEILCORE_OTS = 'off';
process.env.VEILCORE_OPERATOR_TOKEN = 'mainnet-op-token-at-least-32-characters';
process.env.VEILCORE_ANCHOR_NETWORK = 'mainnet';
// As pasted from a block explorer: upper case with 0x. Published and compared in lower case.
process.env.VEILCORE_ANCHOR_CONTRACT = `0x${MAINNET_CONTRACT.toUpperCase()}`;
const require = createRequire(import.meta.url);
const { app, db } = require('../server.js');

const OP = { 'x-operator-token': 'mainnet-op-token-at-least-32-characters' };
const H = (name) => createHash('sha256').update(name).digest('hex');
const here = (p) => fileURLToPath(new URL(p, import.meta.url));

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
    body: body === undefined ? undefined : JSON.stringify(testBody(method, path, holder, body)),
  });
  const text = await res.text();
  let json; try { json = JSON.parse(text); } catch { json = text; }
  return { status: res.status, json, text };
};

// What bboard-ui/src/veilcore/commitment.ts commits, verbatim (committedRecordFields).
const appCommitted = (r) => ({
  breedingMethod: r.breedingMethod ?? '', bredBy: r.bredBy, dateCreated: r.dateCreated, loggedAt: r.loggedAt,
  nonce: r.nonce, notes: r.notes, parents: r.parents ?? [], photoFingerprints: r.photoFingerprints ?? [],
  refId: r.refId ?? '', strainName: r.strainName,
  ...(r.profile ? { profile: r.profile } : {}), ...(r.taxon ? { taxon: r.taxon } : {}),
});

const recordFor = async (id, over = {}) => {
  const r = { id, strainName: `S ${id}`, bredBy: 'B', dateCreated: '2026-10-01', notes: '', loggedAt: 1759600000000,
    nonce: H(`nonce:${id}`), parents: [], photoFingerprints: [], breedingMethod: '', refId: '', ...over };
  r.recordFingerprint = await sha256Hex(canonicalise(appCommitted(r)));
  return r;
};

/** Store one record and seal it on its own. */
const sealedBatch = async (id) => {
  const r = await recordFor(id);
  assert.equal((await call('PUT', '/api/records', { holder: H(`holder:${id}`), body: [r] })).json.count, 1);
  const s = await call('POST', '/batches/seal', { headers: OP });
  assert.equal(s.status, 200, JSON.stringify(s.json));
  return { record: r, batchId: s.json.batchId };
};

// =====================================================================================
// 1. veilcore-records 0.15.0, pinned exactly
// =====================================================================================

test('veilcore-records is pinned at exactly 0.15.0 and that is what is installed', () => {
  const pkg = JSON.parse(readFileSync(here('../package.json'), 'utf8'));
  assert.equal(pkg.dependencies['veilcore-records'], '0.15.0');
  const lock = JSON.parse(readFileSync(here('../package-lock.json'), 'utf8'));
  assert.equal(lock.packages['node_modules/veilcore-records'].version, '0.15.0');
  assert.equal(JSON.parse(readFileSync(require.resolve('veilcore-records/package.json'), 'utf8')).version, '0.15.0');
});

const fixture = JSON.parse(readFileSync(here('./fixtures/site-records-0.13.json'), 'utf8'));
const sealedOnes = fixture.records.filter((r) => r.recordFingerprint);

test('records the site wrote under 0.13 (profile, taxon, parents, NFD text, corrections, transfers) still verify under 0.15', async () => {
  assert.equal(fixture.sdk, '0.13.0');
  assert.ok(sealedOnes.some((r) => r.profile && r.taxon) && sealedOnes.some((r) => !r.profile), 'both kinds present');
  for (const r of fixture.records) {
    const check = await checkRecord(r);
    if (r.recordFingerprint) {
      assert.deepEqual(check, { ok: true, verified: true }, r.id);
      // And an outside verifier on 0.15, with the app's own field list, gets the same number.
      assert.equal(await sha256Hex(canonicalise(appCommitted(r))), r.recordFingerprint, r.id);
    } else {
      assert.equal(check.ok, true, 'a pre-canonical record is still accepted');
      assert.equal(check.verified, false);
    }
  }
});

test('those records are accepted on save, served publicly, sealed, and their proofs verify under 0.15', async () => {
  const holder = H('site-holder');
  const put = await call('PUT', '/api/records', { holder, body: fixture.records });
  assert.equal(put.status, 200);
  assert.deepEqual(put.json, { ok: true, count: fixture.records.length, integrityCheckedBy: 'holder' });

  // The holder opens exactly what was stored. The received-record fields are the
  // registry's to write (on a claim), so a client's copy on a fresh row is not kept.
  const SERVER_KEPT = ['receivedFrom', 'receivedFromCommitment', 'receivedAt', 'transferId'];
  const mine = (await call('GET', '/api/records', { holder })).json;
  for (const r of fixture.records) {
    const stored = mine.find((m) => m.id === r.id);
    assert.ok(stored.sealed, `${r.id} is stored sealed`);
    const expected = Object.fromEntries(Object.entries(r).filter(([k]) => !SERVER_KEPT.includes(k)));
    assert.deepEqual(openForTest(stored, vaultKeyFor(holder)), expected, r.id);
  }

  for (const r of fixture.records) {
    const v = await call('GET', `/verify/${encodeURIComponent(r.id)}`);
    assert.equal(v.status, 200, r.id);
    assert.equal(v.json.found, true);
    // The name is sealed (round 5, CONTRACT.md #28): not served unless the holder shows it.
    assert.equal(v.json.cultivar, undefined);
    assert.equal(v.json.recordFingerprint, r.recordFingerprint);
    assert.equal((await call('GET', `/records/${encodeURIComponent(r.id)}`)).json.recordFingerprint, r.recordFingerprint);
    assert.equal((await call('GET', `/embed/${encodeURIComponent(r.id)}`)).status, 200);
  }
  const corrected = fixture.records.find((r) => r.supersededBy);
  assert.equal((await call('GET', `/verify/${encodeURIComponent(corrected.id)}`)).json.supersededBy, corrected.supersededBy);

  const sealed = await call('POST', '/batches/seal', { headers: OP });
  assert.equal(sealed.status, 200, JSON.stringify(sealed.json));
  assert.equal(sealed.json.skipped, undefined, 'every fingerprint the site wrote is sealable');
  for (const r of sealedOnes) {
    const proof = (await call('GET', `/proof/${r.recordFingerprint}`)).json;
    assert.equal(proof.batchId, sealed.json.batchId);
    assert.equal(await verifyInclusion(proof), true, r.id);
  }
});

test('rows stored by the 0.13 registry (written before this upgrade, never re-saved) are still served and sealed', async () => {
  const insert = db.prepare('INSERT INTO records (id, holder_key, body, updated_at, first_seen) VALUES (?,?,?,?,?)');
  const old = await recordFor('stored-under-013', { profile: 'veilcore/profile/plant-variety/v1', taxon: 'Humulus lupulus' });
  insert.run(old.id, H('old-holder'), JSON.stringify(old), 1759000000000, 1759000000000);
  const v = (await call('GET', `/verify/${old.id}`)).json;
  assert.equal(v.recordFingerprint, old.recordFingerprint);
  assert.equal(v.registryFirstSeen, new Date(1759000000000).toISOString());
  const s = await call('POST', '/batches/seal', { headers: OP });
  assert.equal(s.status, 200);
  assert.equal(await verifyInclusion((await call('GET', `/proof/${old.recordFingerprint}`)).json), true);
});

test('0.15 stricter input: a record 0.15 cannot commit is the holder\'s browser\'s to refuse; sealed, the registry stores it', async () => {
  // Since sealed records the registry can't see these fields, so it can't refuse them; it
  // says the holder checks (integrityCheckedBy), and never fails the whole save.
  const holder = H('strict-holder');
  const fine = await recordFor('strict-fine');
  const surrogate = { ...(await recordFor('strict-surrogate')), notes: 'lone \ud800 surrogate' };
  const big = { ...(await recordFor('strict-big')), loggedAt: 2 ** 60 };
  const put = await call('PUT', '/api/records', { holder, body: [fine, surrogate, big] });
  assert.equal(put.status, 200);
  assert.equal(put.json.count, 3);
  assert.equal(put.json.integrityCheckedBy, 'holder');
  // What the browser's own check (the same canonicalisation) does with them: refuses.
  for (const r of [surrogate, big]) {
    await assert.rejects(async () => { if (!(await checkRecord(r)).ok) throw new Error('refused'); }, undefined, r.id);
  }
});

// =====================================================================================
// 2. The two Lows from the round D verification: attester registration
// =====================================================================================

/** Sign a registration with a real key, as the site does. */
const registration = async (kp, fields = {}) => {
  const reg = { publicKey: kp.publicKey, issuedAt: Date.now(), displayName: 'Lab', ...fields };
  const priv = await crypto.subtle.importKey('pkcs8', Buffer.from(kp.privateKey, 'hex'), { name: 'Ed25519' }, false, ['sign']);
  const sig = await crypto.subtle.sign('Ed25519', priv, new TextEncoder().encode(registrationPayload(reg)));
  return { ...reg, signature: Buffer.from(sig).toString('hex') };
};

const SMALL_ORDER_KEYS = [
  '0000000000000000000000000000000000000000000000000000000000000000',
  '0100000000000000000000000000000000000000000000000000000000000000',
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  'eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
];
// The same points with the x-sign bit set name the same small-order points.
const ALL_BAD_KEYS = [
  ...SMALL_ORDER_KEYS,
  ...SMALL_ORDER_KEYS.map((k) => k.slice(0, 62) + (parseInt(k.slice(62), 16) | 0x80).toString(16).padStart(2, '0')),
  'efffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f', // y = p + 2, not canonical
];

test('FIXED [LOW] attester registration refuses small-order and non-canonical Ed25519 keys', async () => {
  // The hole: with the identity point as the key, R = identity and S = 0 "verifies" for any
  // message under WebCrypto (checked on Node 22, 6 Oct 2026), so this forged registration
  // passed the signature check and put "Definitely A Lab" on a key nobody holds.
  const identity = SMALL_ORDER_KEYS[1];
  const forged = identity + '00'.repeat(32);

  for (const publicKey of ALL_BAD_KEYS) {
    assert.ok(unusableKeyReason(publicKey), publicKey);
    const r = await call('POST', '/attesters', {
      body: { publicKey, issuedAt: Date.now(), displayName: 'Definitely A Lab', signature: forged },
    });
    assert.equal(r.status, 400, publicKey);
    assert.match(r.json.error, /small-order|not a canonical/, publicKey);
    assert.equal(db.prepare('SELECT 1 FROM attesters WHERE public_key = ?').get(publicKey), undefined);
  }
  // The registry and veilcore-records 0.15 refuse the same keys: an attestation "signed" by
  // one does not verify either.
  const body = { type: 'veilcore/attestation/v1', attestationId: 'so-1', subjectCommitment: 'ab'.repeat(32),
    documentHash: 'cd'.repeat(32), hashAlgorithm: 'sha256', issuedAt: new Date().toISOString(),
    attester: { publicKey: identity }, signature: forged };
  assert.equal(await verifyAttestation(body), false);

  // A real key still registers.
  const kp = await generateKeypair();
  assert.equal(unusableKeyReason(kp.publicKey), null);
  const ok = await call('POST', '/attesters', { body: await registration(kp) });
  assert.equal(ok.status, 200, JSON.stringify(ok.json));
});

test('attester registration refuses an upper-case key (0.15 would never verify its attestations)', async () => {
  const kp = await generateKeypair();
  const upper = { ...kp, publicKey: kp.publicKey.toUpperCase() };
  const r = await call('POST', '/attesters', { body: await registration(upper) });
  assert.equal(r.status, 400);
  assert.match(r.json.error, /lowercase/);
});

test('FIXED [LOW] an attestation with an upper-case subjectCommitment is refused, and says why', async () => {
  const kp = await generateKeypair();
  const { record } = await sealedBatch('att-subject');
  const sign = (subjectCommitment, attestationId) => signAttestation({
    type: 'veilcore/attestation/v1', attestationId, subjectCommitment, documentHash: 'cd'.repeat(32),
    hashAlgorithm: 'sha256', issuedAt: new Date().toISOString(), attester: { publicKey: kp.publicKey, displayName: 'Lab' },
  }, kp.privateKey);
  const upper = await call('POST', '/attestations', { body: await sign(record.recordFingerprint.toUpperCase(), 'att-upper') });
  assert.equal(upper.status, 400);
  assert.match(upper.json.error, /subjectCommitment .*lowercase/);
  assert.equal(db.prepare('SELECT 1 FROM attestations WHERE attestation_id = ?').get('att-upper'), undefined);

  const lower = await call('POST', '/attestations', { body: await sign(record.recordFingerprint, 'att-lower') });
  assert.equal(lower.status, 200, JSON.stringify(lower.json));
  assert.equal((await call('GET', `/verify/${record.id}`)).json.signedAttestation, true);

  // 0.15's verifiers answer false instead of throwing: malformed bodies are a 400, not a 500.
  for (const bad of [[], { attestationId: 'x', subjectCommitment: 'ab'.repeat(32) }, { attestationId: 'y', subjectCommitment: 'ab'.repeat(32), attester: null, signature: 'zz' }]) {
    assert.equal((await call('POST', '/attestations', { body: bad })).status, 400, JSON.stringify(bad));
  }
});

// =====================================================================================
// 3. Mainnet day: anchors
// =====================================================================================

test('/.well-known names mainnet and the contract, in lower case without 0x', async () => {
  const wk = (await call('GET', '/.well-known/veilcore-registry')).json;
  assert.deepEqual(wk.anchors, [{ chain: 'midnight', network: 'mainnet', contractAddress: MAINNET_CONTRACT }]);
});

test('after the switch, an anchor made on Preview or preprod, or on another contract, cannot be recorded', async () => {
  const { batchId } = await sealedBatch('stray');
  const post = (body) => call('POST', `/batches/${batchId}/anchor`, { headers: OP, body: { txHash: 'ee'.repeat(32), blockHeight: 10, ...body } });
  for (const [why, body] of [
    ['the Preview contract on Preview', { network: 'preview', contractAddress: PREVIEW_CONTRACT }],
    ['the mainnet contract address, but labelled Preview', { network: 'preview', contractAddress: MAINNET_CONTRACT }],
    ['preprod', { network: 'preprod', contractAddress: MAINNET_CONTRACT }],
    ['the Preview contract labelled mainnet', { network: 'mainnet', contractAddress: PREVIEW_CONTRACT }],
    ['another chain', { chain: 'cardano', network: 'mainnet', contractAddress: MAINNET_CONTRACT }],
    ['Mainnet in capitals', { network: 'Mainnet', contractAddress: MAINNET_CONTRACT }],
    ['no network', { contractAddress: MAINNET_CONTRACT }],
    ['no contract', { network: 'mainnet' }],
  ]) {
    const r = await post(body);
    assert.equal(r.status, 400, why);
  }
  assert.equal(db.prepare('SELECT anchor FROM batches WHERE batch_id = ?').get(batchId).anchor, null, 'nothing recorded');
  // Without the operator token nothing is even checked.
  assert.equal((await call('POST', `/batches/${batchId}/anchor`, { body: { network: 'mainnet', contractAddress: MAINNET_CONTRACT, txHash: 'ee'.repeat(32) } })).status, 401);
});

test('a mainnet anchor is recorded in lower-case hex, and its shape is checked', async () => {
  const { batchId, record } = await sealedBatch('main-1');
  const post = (body) => call('POST', `/batches/${batchId}/anchor`, { headers: OP, body: { network: 'mainnet', contractAddress: `0x${MAINNET_CONTRACT.toUpperCase()}`, ...body } });
  assert.equal((await post({ txHash: 'ab'.repeat(31) })).status, 400, 'short txHash');
  assert.equal((await post({ txHash: 'ab'.repeat(32), blockHeight: '123' })).status, 400, 'blockHeight as a string');
  assert.equal((await post({ txHash: 'ab'.repeat(32), blockHeight: -1 })).status, 400, 'negative blockHeight');
  assert.equal((await post({ txHash: 'ab'.repeat(32), anchoredAt: 'yesterday' })).status, 400, 'anchoredAt not a date');
  assert.equal((await call('POST', '/batches/B-NOPE/anchor', { headers: OP, body: { network: 'mainnet', contractAddress: MAINNET_CONTRACT, txHash: 'ab'.repeat(32) } })).status, 404);

  // After the batch was sealed: an earlier date is refused (deep dive, 8 Oct 2026).
  const anchoredAt = new Date().toISOString();
  const ok = await post({ txHash: `0x${'AB'.repeat(32)}`, blockHeight: 4242, anchoredAt });
  assert.equal(ok.status, 200, JSON.stringify(ok.json));
  const stored = JSON.parse(db.prepare('SELECT anchor FROM batches WHERE batch_id = ?').get(batchId).anchor);
  assert.deepEqual(stored, { chain: 'midnight', network: 'mainnet', contractAddress: MAINNET_CONTRACT, txHash: 'ab'.repeat(32), blockHeight: 4242, anchoredAt });

  const proof = (await call('GET', `/proof/${record.recordFingerprint}`)).json;
  assert.deepEqual(proof.anchor, { ...stored, testNetwork: false });
  assert.equal(await verifyInclusion(proof), true);
  const v = (await call('GET', `/verify/${record.id}`)).json;
  assert.equal(v.anchored, true);
  assert.equal(v.anchor.network, 'mainnet');
  assert.equal(v.anchor.testNetwork, false);
  const html = (await call('GET', `/embed/${record.id}`)).text;
  // Named, with who recorded it and what to look up (deep dive, 8 Oct 2026).
  assert.match(html, /Anchored on Midnight mainnet, as recorded by this registry\u2019s operator/);
  assert.doesNotMatch(html, /test network/);
});

test('a batch anchored on Preview before the switch is reported as Preview, a test network, everywhere', async () => {
  const holder = H('holder:preview-era');
  const r = await recordFor('preview-era');
  assert.equal((await call('PUT', '/api/records', { holder, body: [r] })).json.count, 1);
  const { batchId } = (await call('POST', '/batches/seal', { headers: OP })).json;
  // Exactly what the registry stored for an anchor recorded while it was on Preview.
  const previewAnchor = { chain: 'midnight', network: 'preview', contractAddress: PREVIEW_CONTRACT,
    txHash: 'cd'.repeat(32), blockHeight: 99, anchoredAt: '2026-10-01T00:00:00.000Z' };
  db.prepare('UPDATE batches SET anchor = ? WHERE batch_id = ?').run(JSON.stringify(previewAnchor), batchId);
  assert.equal((await call('PUT', `/api/records/${r.id}/disclosure`, { holder, body: { show: ['existence'] } })).status, 200);

  const proof = (await call('GET', `/proof/${r.recordFingerprint}`)).json;
  assert.deepEqual(proof.anchor, { ...previewAnchor, testNetwork: true });
  assert.equal(await verifyInclusion(proof), true, 'the proof itself still verifies');

  const v = (await call('GET', `/verify/${r.id}`)).json;
  assert.equal(v.anchor.network, 'preview');
  assert.equal(v.anchor.testNetwork, true);
  // Anchored somewhere, so the site can show it as Preview with its warning; but a
  // test-network date is not prior possession, for any client that reads only that field.
  assert.equal(v.anchored, true);
  assert.equal(v.priorPossession, false, 'a Preview anchor is never reported as prior possession');
  assert.equal(v.unalteredSinceRegistryFirstSeen, true);
  assert.equal(v.anchor.contractAddress, PREVIEW_CONTRACT, 'not relabelled with the mainnet contract');

  const html = (await call('GET', `/embed/${r.id}`)).text;
  assert.match(html, /Anchored only on Midnight Preview, a test network/);
  assert.match(html, /carries no evidential weight/);
  assert.doesNotMatch(html, /mainnet, a public ledger/);

  const listed = (await call('GET', '/batches')).json.batches.find((b) => b.batch_id === batchId);
  assert.equal(listed.anchor.testNetwork, true);

  const ex = (await call('GET', '/api/export', { holder })).json;
  assert.equal(ex.proofs[r.recordFingerprint].anchor.network, 'preview');
  assert.equal(ex.proofs[r.recordFingerprint].anchor.testNetwork, true);
  assert.equal(ex.batches.find((b) => b.batchId === batchId).anchor.testNetwork, true);

  // The stored row is never rewritten.
  assert.deepEqual(JSON.parse(db.prepare('SELECT anchor FROM batches WHERE batch_id = ?').get(batchId).anchor), previewAnchor);
});

test('a Preview-era batch can be anchored again on mainnet, and is then reported as mainnet', async () => {
  const r = await recordFor('reanchor');
  const holder = H('holder:reanchor');
  assert.equal((await call('PUT', '/api/records', { holder, body: [r] })).json.count, 1);
  assert.equal((await call('PUT', `/api/records/${r.id}/disclosure`, { holder, body: { show: ['existence'] } })).status, 200);
  const { batchId } = (await call('POST', '/batches/seal', { headers: OP })).json;
  db.prepare('UPDATE batches SET anchor = ? WHERE batch_id = ?')
    .run(JSON.stringify({ chain: 'midnight', network: 'preview', contractAddress: PREVIEW_CONTRACT, txHash: 'cd'.repeat(32) }), batchId);
  assert.equal((await call('GET', `/verify/${r.id}`)).json.priorPossession, false, 'on Preview: no prior possession');
  const ok = await call('POST', `/batches/${batchId}/anchor`, { headers: OP, body: { network: 'mainnet', contractAddress: MAINNET_CONTRACT, txHash: 'ef'.repeat(32), blockHeight: 7 } });
  assert.equal(ok.status, 200);
  assert.equal((await call('GET', `/proof/${r.recordFingerprint}`)).json.anchor.testNetwork, false);
  const v = (await call('GET', `/verify/${r.id}`)).json;
  assert.equal(v.anchored, true);
  assert.equal(v.anchor.network, 'mainnet');
  assert.equal(v.priorPossession, true, 'a mainnet anchor is prior possession');

  // The Preview anchor it took the place of is kept, not lost (11 Oct 2026).
  assert.deepEqual(ok.json.supersedes, { chain: 'midnight', network: 'preview', contractAddress: PREVIEW_CONTRACT, txHash: 'cd'.repeat(32), testNetwork: true });
  const listed = (await call('GET', '/batches')).json.batches.find((b) => b.batch_id === batchId);
  assert.equal(listed.anchor.network, 'mainnet');
  assert.equal(listed.earlierAnchors.length, 1);
  assert.equal(listed.earlierAnchors[0].network, 'preview');
  assert.equal(listed.earlierAnchors[0].txHash, 'cd'.repeat(32));
  assert.equal(listed.earlierAnchors[0].testNetwork, true);
  assert.match(listed.earlierAnchors[0].replacedAt, /^\d{4}-\d{2}-\d{2}T/);
});

test('a mainnet anchor is never replaced: a different transaction is 409, the same one changes nothing', async () => {
  const { batchId, record } = await sealedBatch('no-overwrite');
  const post = (txHash, extra = {}) => call('POST', `/batches/${batchId}/anchor`, { headers: OP, body: { network: 'mainnet', contractAddress: MAINNET_CONTRACT, txHash, ...extra } });
  const first = await post('a1'.repeat(32), { blockHeight: 100 });
  assert.equal(first.status, 200, JSON.stringify(first.json));
  const stored = db.prepare('SELECT anchor FROM batches WHERE batch_id = ?').get(batchId).anchor;

  // Another transaction, a later block: refused, and the first anchor's date stands.
  const second = await post('b2'.repeat(32), { blockHeight: 200 });
  assert.equal(second.status, 409);
  assert.match(second.json.error, /already anchored on mainnet/);
  // The same transaction again (a retried curl): 200, unchanged, nothing rewritten, even
  // with a different block height or date.
  const again = await post(`0x${'A1'.repeat(32)}`, { blockHeight: 999 });
  assert.equal(again.status, 200);
  assert.equal(again.json.unchanged, true);
  assert.equal(again.json.anchor.blockHeight, 100);
  assert.equal(db.prepare('SELECT anchor FROM batches WHERE batch_id = ?').get(batchId).anchor, stored, 'stored row untouched');
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM batch_anchor_history WHERE batch_id = ?').get(batchId).n, 0, 'nothing superseded');
  assert.equal((await call('GET', `/proof/${record.recordFingerprint}`)).json.anchor.txHash, 'a1'.repeat(32));
  const listed = (await call('GET', '/batches')).json.batches.find((b) => b.batch_id === batchId);
  assert.equal('earlierAnchors' in listed, false, 'no earlierAnchors on a batch never superseded');
});

test('anchoring is refused (503) until both variables are set, and /.well-known lists nothing until then', () => {
  const child = here('./fixtures/anchor-config-child.mjs');
  const run = (env, body) => {
    const e = { ...process.env, ...env, CHILD_ANCHOR_BODY: JSON.stringify(body) };
    for (const k of ['VEILCORE_ANCHOR_NETWORK', 'VEILCORE_ANCHOR_CONTRACT']) if (env[k] === undefined) delete e[k];
    const out = execFileSync(process.execPath, [child], { env: e, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
    return JSON.parse(out.trim().split('\n').pop());
  };
  const any = { network: 'mainnet', contractAddress: MAINNET_CONTRACT, txHash: 'ab'.repeat(32) };
  for (const [why, env] of [
    ['neither set', {}],
    ['network only (the contract forgotten on the day)', { VEILCORE_ANCHOR_NETWORK: 'mainnet' }],
    ['contract only', { VEILCORE_ANCHOR_CONTRACT: MAINNET_CONTRACT }],
    ['a malformed contract', { VEILCORE_ANCHOR_NETWORK: 'mainnet', VEILCORE_ANCHOR_CONTRACT: `${MAINNET_CONTRACT}0` }],
  ]) {
    const out = run(env, any);
    assert.equal(out.anchorStatus, 503, why);
    assert.deepEqual(out.anchors, [], why);
  }
  const good = run({ VEILCORE_ANCHOR_NETWORK: 'mainnet', VEILCORE_ANCHOR_CONTRACT: MAINNET_CONTRACT }, any);
  assert.equal(good.anchorStatus, 200);
  assert.deepEqual(good.anchors, [{ chain: 'midnight', network: 'mainnet', contractAddress: MAINNET_CONTRACT }]);
});
