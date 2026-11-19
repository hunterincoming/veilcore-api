// A lab's signed result, held by the lab and by the breeder it was signed for (18 Nov 2026).
//
// The lab keeps every result it signs as a record it holds (the site's lab-result-sign.ts), so
// the result's proof code is the lab's here: stored first by the lab, dated in its batch, and
// kept with the lab in fingerprint_holders ("A fingerprint stays with its first holder"). The
// breeder adds the same result from the lab's file. Sent with that proof code in the clear,
// the breeder's copy was refused at every save ("already registered by another holder"), and
// so was anything the breeder kept on it.
//
// The site now sends such a copy with the proof code inside its locked box only (records.ts
// `copy`). That needs nothing new here, and opens nothing: to this registry the copy is a
// sealed row with no proof code, so the first-holder rule never sees it, and no route that
// reads a proof code (dating, deliveries, private lab signatures, /verify, deletion) ties the
// lab's proof code to the breeder. These tests hold the registry to that, so a later change
// can't refuse such a row, or start reading a proof code from somewhere else.
//
// SPDX-License-Identifier: Apache-2.0

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { randomBytes } from 'node:crypto';
import { canonicalise, sha256Hex, newNonce } from 'veilcore-records';
import { untilReady, sealForTest, openForTest, vaultKeyFor, handleTagFor, offerFromRecord, sealOfferForTest } from './helpers.mjs';

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

const call = async (method, path, holder, body) => {
  const res = await fetch(`${base}${path}`, {
    method,
    headers: { 'content-type': 'application/json', 'x-forwarded-for': `10.${randomBytes(3).join('.')}`, ...(holder ? { 'x-holder-key': holder } : {}) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const text = await res.text();
  let json; try { json = JSON.parse(text); } catch { json = text; }
  return { status: res.status, json };
};
const put = (holder, rows) => call('PUT', '/api/records', holder, rows);
const rowsOf = async (holder) => (await call('GET', '/api/records', holder)).json;

const committedOf = (r) => ({ breedingMethod: r.breedingMethod ?? '', bredBy: r.bredBy, dateCreated: r.dateCreated,
  loggedAt: r.loggedAt, nonce: r.nonce, notes: r.notes, parents: r.parents ?? [],
  photoFingerprints: r.photoFingerprints ?? [], refId: r.refId ?? '', strainName: r.strainName });
/** A lab's result record as the lab's browser keeps it (the details here are only practice data). */
const labResult = async (id) => {
  const r = { id, profile: 'veilcore/profile/document/v1', strainName: 'LAB-COPY-1', bredBy: 'Practice Lab',
    dateCreated: '2026-11-18', loggedAt: 1763452800000, nonce: newNonce(), notes: '', parents: [], photoFingerprints: [],
    refId: 'LAB-COPY-1', labResult: { statement: { kind: 'pathogen', call: 'not-detected' } } };
  r.recordFingerprint = await sha256Hex(canonicalise(committedOf(r)));
  return r;
};
/** The breeder's copy as the site sends it now: the proof code and the `copy` mark sealed, nothing of it in the clear. */
const copyRow = (holder, result, id, over = {}) => {
  const row = sealForTest({ ...result, id, copy: true, ...over }, vaultKeyFor(holder), 'records', { inside: ['recordFingerprint'] });
  assert.equal(row.recordFingerprint, undefined);
  return row;
};

test('the breeder keeps a copy of the lab’s result; the proof code stays the lab’s', async () => {
  const lab = key(), breeder = key();
  const result = await labResult('lab-result-1');
  const F = result.recordFingerprint;
  assert.equal((await put(lab, [sealForTest(result, vaultKeyFor(lab))])).json.count, 1);

  // With the proof code in the clear, the copy is refused, as before: the first-holder rule stands.
  const clear = await put(breeder, [sealForTest({ ...result, id: 'copy-clear' }, vaultKeyFor(breeder))]);
  assert.equal(clear.json.count, 0);
  assert.match(clear.json.rejected[0].reason, /already registered by another holder/);
  // So is its proof code sent alone, to be dated (dating first).
  const dating = await call('PUT', '/api/records/dating', breeder, [{ id: 'copy-clear', recordFingerprint: F }]);
  assert.match(JSON.stringify(dating.json.rejected), /already registered by another holder/);

  // The copy as the site sends it: stored, and read back whole, the proof code inside.
  const saved = await put(breeder, [copyRow(breeder, result, 'copy-1', { rev: 1 })]);
  assert.equal(saved.json.count, 1, JSON.stringify(saved.json));
  const back = (await rowsOf(breeder)).find((r) => r.id === 'copy-1');
  assert.equal(back.recordFingerprint, undefined);
  const opened = openForTest(back, vaultKeyFor(breeder));
  assert.equal(opened.recordFingerprint, F);
  assert.equal(opened.copy, true);

  // What the breeder keeps on it is kept: a claim, saved with the next copy, is there when read again.
  const claim = { kind: 'range', slot: 1, op: 'at-most', bound: '0', record: F, txId: '01'.repeat(32), blockHeight: 3600001 };
  assert.equal((await put(breeder, [copyRow(breeder, result, 'copy-1', { rev: 2, claims: [claim] })])).json.count, 1);
  const again = openForTest((await rowsOf(breeder)).find((r) => r.id === 'copy-1'), vaultKeyFor(breeder));
  assert.deepEqual(again.claims, [claim]);

  // The lab is still the proof code's one holder, and saves its own record as before.
  const holders = db.prepare('SELECT holder_key FROM fingerprint_holders WHERE fingerprint = ?').all(F);
  assert.deepEqual(holders.map((h) => h.holder_key), [storedHolderKey(lab)]);
  const withFp = db.prepare("SELECT holder_key FROM records WHERE json_extract(body, '$.recordFingerprint') = ?").all(F);
  assert.deepEqual(withFp.map((h) => h.holder_key), [storedHolderKey(lab)]);
  assert.equal((await put(lab, [sealForTest({ ...result, rev: 1 }, vaultKeyFor(lab))])).json.count, 1);
  // A stranger with the proof code is refused, as before; the copy made no room for one.
  const stranger = await put(key(), [sealForTest({ ...result, id: 'stranger' }, vaultKeyFor(key()))]);
  assert.match(stranger.json.rejected[0].reason, /already registered by another holder/);
});

test('a copy ties nothing of the lab’s proof code to the breeder', async () => {
  const lab = key(), breeder = key();
  const result = await labResult('lab-result-2');
  const F = result.recordFingerprint;
  assert.equal((await put(lab, [sealForTest(result, vaultKeyFor(lab))])).json.count, 1);
  assert.equal((await put(breeder, [copyRow(breeder, result, 'copy-2')])).json.count, 1);

  // Its public check page names no proof code, so no date and no lab signature hang on it.
  const v = await call('GET', '/verify/copy-2');
  assert.equal(v.status, 200);
  assert.equal(v.json.recordFingerprint, undefined);
  assert.equal(v.json.anchored, false);
  assert.equal(v.json.signedAttestation, false);
  // The lab's own page is the one that carries it.
  assert.equal((await call('GET', `/verify/${result.id}`)).json.recordFingerprint, F);

  // A delivery of the copy names no proof code either: sending it reads no lab signature about F.
  const offerKey = randomBytes(32);
  const sent = await call('POST', '/transfers', breeder, {
    sourceRecord: 'copy-2', toHandle: handleTagFor(breeder, 'someone@x'),
    sealedOffer: sealOfferForTest(offerFromRecord({ ...result, id: 'copy-2' }), offerKey, 'copy-2', ''),
  });
  assert.equal(sent.status, 200, JSON.stringify(sent.json));
  assert.equal(db.prepare('SELECT source_fingerprint FROM transfers WHERE id = ?').get(sent.json.transferId).source_fingerprint, null);

  // Deleting the copy takes the copy only: the lab's record and its proof code stay the lab's.
  const del = await call('DELETE', '/api/records', breeder, { ids: ['copy-2'] });
  assert.equal(del.status, 200, JSON.stringify(del.json));
  assert.ok((await rowsOf(lab)).some((r) => r.id === result.id && r.recordFingerprint === F));
  assert.deepEqual(
    db.prepare('SELECT holder_key FROM fingerprint_holders WHERE fingerprint = ?').all(F).map((h) => h.holder_key),
    [storedHolderKey(lab)],
  );
  // And the lab saves its record as before.
  assert.equal((await put(lab, [sealForTest({ ...result, rev: 1 }, vaultKeyFor(lab))])).json.count, 1);
});
