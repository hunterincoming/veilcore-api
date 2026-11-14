// Deep dive, 8 Oct 2026: the registry findings, each as a test that failed before its fix.
// No network, no live service.
//
// SPDX-License-Identifier: Apache-2.0

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { createHash, randomBytes } from 'node:crypto';
import { canonicalise, sha256Hex, newNonce, generateKeypair, signAttestation, signRetraction, verifyAttestation, verifyRetraction } from 'veilcore-records';
import { inOneMinute, untilReady, testBody, handleTagFor } from './helpers.mjs';

const OP_TOKEN = 'deepdive-operator-token-at-least-32-chars';
process.env.DB_PATH = ':memory:';
process.env.VEILCORE_OTS = 'off';
process.env.VEILCORE_OPERATOR_TOKEN = OP_TOKEN;
// Small, so the per-holder ceiling can be reached in a test. Production default: 16 MB.
process.env.HOLDER_MAX_BYTES = String(3 * 1024 * 1024);
const CONTRACT = '5e'.repeat(32);
process.env.VEILCORE_ANCHOR_NETWORK = 'mainnet';
process.env.VEILCORE_ANCHOR_CONTRACT = CONTRACT;
const require = createRequire(import.meta.url);
const { app, db } = require('../server.js');

const H = (name) => createHash('sha256').update(name).digest('hex');
const key = () => randomBytes(32).toString('hex');
const OP = { 'x-operator-token': OP_TOKEN };

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
  return { status: res.status, json, text, headers: res.headers };
};

const committedOf = (r) => ({ breedingMethod: r.breedingMethod ?? '', bredBy: r.bredBy, dateCreated: r.dateCreated,
  loggedAt: r.loggedAt, nonce: r.nonce, notes: r.notes, parents: r.parents ?? [],
  photoFingerprints: r.photoFingerprints ?? [], refId: r.refId ?? '', strainName: r.strainName });
const makeRecord = async (id, over = {}) => {
  const r = { id, strainName: 'C' + id, bredBy: 'B', dateCreated: '2026-01-01', loggedAt: '2026-01-01T00:00:00Z',
    nonce: newNonce(), notes: 'n', parents: [], photoFingerprints: [], breedingMethod: 'm', refId: '', ...over };
  r.recordFingerprint = await sha256Hex(canonicalise(committedOf(r)));
  return r;
};
const many = async (prefix, n, over) => {
  const out = [];
  for (let i = 0; i < n; i++) out.push(await makeRecord(`${prefix}-${String(i).padStart(5, '0')}`, over));
  return out;
};
const NOTES_20K = 'x'.repeat(20_000);

// ---------------------------------------------------------------------------------------
// 1 (HIGH) GET /api/records returned every record a holder had, unpaged: 10,000 × 64 KB,
// ~640 MB per read, from a key anyone can make.
// ---------------------------------------------------------------------------------------

test('HIGH: GET /api/records pages with ?limit= and ?cursor=, at most 100 a page, every record exactly once', async () => {
  const holder = key();
  const recs = await many('pg', 250);
  assert.equal((await call('PUT', '/api/records', { holder, body: recs })).json.count, 250);
  const seen = [];
  let cursor = '';
  for (let pages = 0; pages < 10; pages++) {
    const r = await call('GET', `/api/records?limit=1000${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`, { holder });
    assert.equal(r.status, 200);
    assert.ok(Array.isArray(r.json.records), 'a paged answer is { records, nextCursor }');
    assert.ok(r.json.records.length <= 100, 'limit=1000 is cut to 100');
    seen.push(...r.json.records.map((x) => x.id));
    if (!r.json.nextCursor) break;
    cursor = r.json.nextCursor;
  }
  assert.equal(seen.length, 250);
  assert.equal(new Set(seen).size, 250);
  assert.deepEqual(seen, [...seen].sort(), 'in id order, so a save in between cannot reorder pages');
  const first = await call('GET', '/api/records?limit=10', { holder });
  assert.equal(first.json.records.length, 10);
  assert.equal(first.json.nextCursor, first.json.records[9].id);
  // Another holder's cursor or rows never leak in.
  assert.deepEqual((await call('GET', `/api/records?limit=5&cursor=${encodeURIComponent('')}`, { holder: key() })).json, { records: [], nextCursor: null, limit: 5 });
});

test('HIGH: a page also stops at about 1 MB, and the next one carries on', async () => {
  const holder = key();
  const recs = await many('big', 80, { notes: NOTES_20K });
  assert.equal((await call('PUT', '/api/records', { holder, body: recs })).json.count, 80);
  const p1 = await call('GET', '/api/records?limit=100', { holder });
  assert.ok(p1.json.records.length < 80, `one page of 20 KB records stops early (${p1.json.records.length})`);
  assert.ok(p1.text.length <= 1.1 * 1024 * 1024, `page is ${p1.text.length} bytes`);
  assert.ok(p1.json.nextCursor);
  let n = p1.json.records.length;
  for (let cursor = p1.json.nextCursor; cursor;) {
    const p = await call('GET', `/api/records?limit=100&cursor=${encodeURIComponent(cursor)}`, { holder });
    assert.ok(p.text.length <= 1.1 * 1024 * 1024);
    n += p.json.records.length;
    cursor = p.json.nextCursor;
  }
  assert.equal(n, 80, 'the following pages carry the rest');
});

test('HIGH: without ?limit= the answer is still a plain array (the site reads that), bounded and flagged when cut', async () => {
  const holder = key();
  const small = await many('legacy', 3);
  await call('PUT', '/api/records', { holder, body: small });
  const r = await call('GET', '/api/records', { holder });
  assert.ok(Array.isArray(r.json), 'unchanged shape for current clients');
  assert.equal(r.json.length, 3);
  assert.equal(r.headers.get('x-veilcore-truncated'), null);

  const lots = await many('lots', 1001);
  assert.equal((await call('PUT', '/api/records', { holder, body: lots })).json.count, 1001);
  const cut = await call('GET', '/api/records', { holder });
  assert.ok(Array.isArray(cut.json));
  assert.equal(cut.json.length, 1000, 'at most 1000 records without paging');
  assert.equal(cut.headers.get('x-veilcore-truncated'), 'true');
  assert.match(cut.headers.get('access-control-expose-headers') ?? '', /X-VeilCore-Truncated/i);
});

test('HIGH: a holder may store at most HOLDER_MAX_BYTES; re-saving or shrinking what is held still works', async () => {
  const holder = key();
  // Sealed, each is about 27 KB: ~2.7 MB of the 3 MB set for this test.
  const recs = await many('cap', 100, { notes: NOTES_20K });
  const first = await call('PUT', '/api/records', { holder, body: recs });
  assert.equal(first.json.count, 100, JSON.stringify(first.json).slice(0, 200));
  const more = await many('cap-more', 20, { notes: NOTES_20K });
  const over = await call('PUT', '/api/records', { holder, body: [...recs, ...more] });
  assert.equal(over.status, 413);
  assert.match(over.json.error, /bytes|MB/);
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM records WHERE id LIKE 'cap-more-%'").get().n, 0, 'nothing of the refused save was written');
  // The app re-sends the whole set on every save: an unchanged set is fine, and so is one
  // that shrinks, even for a holder already over the ceiling (set by hand here).
  assert.equal((await call('PUT', '/api/records', { holder, body: recs })).status, 200);
  const extra = await makeRecord('cap-over', { notes: NOTES_20K });
  db.prepare('INSERT INTO records (id, holder_key, body, updated_at, first_seen) SELECT ?, holder_key, ?, 0, 0 FROM records WHERE id = ?')
    .run(extra.id, JSON.stringify({ ...extra, notes: 'z'.repeat(600_000) }), recs[0].id);
  assert.equal((await call('PUT', '/api/records', { holder, body: recs })).status, 200, 'over the ceiling, an unchanged re-save still works');
  assert.equal((await call('PUT', '/api/records', { holder, body: [await makeRecord('cap-new')] })).status, 413, 'nothing new is added');
  assert.equal((await call('PUT', '/api/records', { holder, body: [extra] })).status, 200, 'but a save that shrinks the set works');
  // Licences have the same ceiling.
  const lic = Array.from({ length: 60 }, (_, i) => ({ id: `L-${i}`, terms: 'y'.repeat(60_000) }));
  let stored = 0, refused = 0;
  for (let i = 0; i < lic.length; i += 5) {
    const r = await call('PUT', '/api/licenses', { holder, body: lic.slice(i, i + 5) });
    if (r.status === 200) stored += r.json.count; else { assert.equal(r.status, 413); refused++; }
  }
  assert.ok(refused > 0 && stored < 60, `licences are capped too (${stored} stored)`);
});

test('HIGH: GET /api/licenses pages the same way', async () => {
  const holder = key();
  const lic = Array.from({ length: 120 }, (_, i) => ({ id: `PL-${String(i).padStart(3, '0')}` }));
  assert.equal((await call('PUT', '/api/licenses', { holder, body: lic })).json.count, 120);
  const p = await call('GET', '/api/licenses?limit=50', { holder });
  assert.equal(p.json.licenses.length, 50);
  assert.equal(p.json.nextCursor, 'PL-049');
  assert.equal((await call('GET', '/api/licenses', { holder })).json.length, 120, 'unpaged: a plain array, as the site reads it');
});

test('HIGH: whole-set reads without paging are limited per holder key', async () => {
  const holder = key();
  await call('PUT', '/api/records', { holder, body: await many('rl', 1) });
  let first429 = -1;
  // In one minute, as a client hammering it would be (helpers.mjs).
  await inOneMinute(async () => {
    for (let i = 0; i < 61 && first429 < 0; i++) {
      if ((await call('GET', '/api/records', { holder })).status === 429) first429 = i;
    }
  });
  assert.ok(first429 >= 30 && first429 <= 60, `the 31st read in a minute is refused (refused at ${first429})`);
  assert.equal((await call('GET', '/api/records?limit=10', { holder })).status, 200, 'paged reads are not');
});

// ---------------------------------------------------------------------------------------
// 2 (MEDIUM) GET /transfers/pending/:handle was public, unpaged, and any number of offers
// could be made to one handle. 7 (LOW) it listed transfer ids, and a transfer made before
// claim codes could be claimed by anyone holding its id.
// ---------------------------------------------------------------------------------------

const DAY = 86_400_000;
const plantOffers = (n, { handle, fromHolder, createdAt = Date.now(), code = 'c'.repeat(32), prefix }) => {
  const ins = db.prepare(`INSERT INTO transfers (id, source_record, from_holder, to_handle, claim_code, created_at)
                          VALUES (?,?,?,?,?,?)`);
  db.transaction(() => {
    for (let i = 0; i < n; i++) ins.run(`${prefix}-${i}`, 'nowhere', fromHolder, handle, code, createdAt);
  })();
};
const storedKey = (k) => require('../holder-key.js').storedHolderKey(k);

test('MEDIUM: the pending list is gone (sealed records round 2): 410 for any handle, and nothing about offers', async () => {
  // It was public and paged (deep dive, 8 Oct 2026); since round 2 the registry holds only a
  // tag the sender's browser makes from a handle, so there is nothing a stranger could ask
  // it for. A name, a tag, paged or not: the same answer, whether or not anything waits.
  const sender = key();
  const rec = await makeRecord('pend-src');
  await call('PUT', '/api/records', { holder: sender, body: [rec] });
  assert.equal((await call('POST', '/transfers', { holder: sender, body: { sourceRecord: rec.id, toHandle: 'paged@lab' } })).status, 200);
  for (const path of ['/transfers/pending/paged@lab', `/transfers/pending/${handleTagFor(sender, 'paged@lab')}`, '/transfers/pending/nobody?limit=500']) {
    const r = await call('GET', path);
    assert.equal(r.status, 410, path);
    assert.deepEqual(r.json, { error: 'removed' }, path);
  }
});

test('MEDIUM: open offers are capped per sender and handle, and per sender (offers older than 30 days do not count)', async () => {
  // Per handle alone was round 1; round 2 counts per sender and handle together, so other
  // senders' offers never block one (test/deepdive-8oct-round2.test.mjs has the rest).
  const sender = key();
  const rec = await makeRecord('cap-src');
  await call('PUT', '/api/records', { holder: sender, body: [rec] });
  const offer = (holder, toHandle) => call('POST', '/transfers', { holder, body: { sourceRecord: rec.id, toHandle } });
  plantOffers(100, { handle: handleTagFor(sender, 'full@lab'), fromHolder: storedKey(key()), prefix: 'FH' });
  assert.equal((await offer(sender, 'full@lab')).status, 200, 'someone else\'s offers do not count');
  plantOffers(20, { handle: handleTagFor(sender, 'mine@lab'), fromHolder: storedKey(sender), prefix: 'MH' });
  const refused = await offer(sender, 'mine@lab');
  assert.equal(refused.status, 429);
  assert.match(refused.json.error, /to this handle/);
  // Old offers no longer count.
  plantOffers(100, { handle: handleTagFor(sender, 'old@lab'), fromHolder: storedKey(sender), prefix: 'OH', createdAt: Date.now() - 31 * DAY });
  assert.equal((await offer(sender, 'old@lab')).status, 200);
  // A claimed one does not count either.
  db.prepare("UPDATE transfers SET claimed_by = 'h1:x', claimed_at = 1 WHERE id = 'MH-0'").run();
  assert.equal((await offer(sender, 'mine@lab')).status, 200);
  // Per sender: 200 open in the last 30 days, across handles.
  const busy = key();
  await call('PUT', '/api/records', { holder: busy, body: [await makeRecord('cap-src-2')] });
  plantOffers(199, { handle: handleTagFor(busy, 'spread@lab'), fromHolder: storedKey(busy), prefix: 'FS' });
  db.prepare("UPDATE transfers SET to_handle = substr(to_handle, 1, 52) || printf('%012x', rowid) WHERE id LIKE 'FS-%'").run();
  assert.equal((await call('POST', '/transfers', { holder: busy, body: { sourceRecord: 'cap-src-2', toHandle: 'a@lab' } })).status, 200);
  const tooMany = await call('POST', '/transfers', { holder: busy, body: { sourceRecord: 'cap-src-2', toHandle: 'b@lab' } });
  assert.equal(tooMany.status, 429);
  assert.match(tooMany.json.error, /you have/);
});

test('LOW: a transfer made before claim codes cannot be claimed by whoever has its id', async () => {
  const sender = key();
  const rec = await makeRecord('legacy-src');
  await call('PUT', '/api/records', { holder: sender, body: [rec] });
  db.prepare(`INSERT INTO transfers (id, source_record, from_holder, to_handle, claim_code, created_at)
              VALUES ('TR-NOCODE1', ?, ?, 'legacy@lab', NULL, ?)`).run(rec.id, storedKey(sender), Date.now() - 10 * DAY);
  const stranger = key();
  const r = await call('POST', '/transfers/TR-NOCODE1/claim', { holder: stranger, body: {} });
  assert.equal(r.status, 400);
  assert.match(r.json.error, /before claim codes/);
  assert.equal(db.prepare("SELECT claimed_by FROM transfers WHERE id = 'TR-NOCODE1'").get().claimed_by, null);
  assert.deepEqual((await call('GET', '/api/records', { holder: stranger })).json, [], 'no record was made');
});

test('LOW: /transfers/sent is paged', async () => {
  const sender = key();
  plantOffers(30, { handle: 'sent@lab', fromHolder: storedKey(sender), prefix: 'SENT' });
  const r = (await call('GET', '/transfers/sent?limit=10', { holder: sender })).json;
  assert.equal(r.transfers.length, 10);
  assert.equal(r.total, 30);
  assert.equal((await call('GET', '/transfers/sent', { holder: sender })).json.transfers.length, 30);
});

// ---------------------------------------------------------------------------------------
// 9 (LOW) A claimed transfer counted as the parent's consent to a descent edge by the
// source record's CURRENT fingerprint: whatever was stored under that id later (by its
// sender, or by anyone after the sender deleted it) inherited the consent.
// ---------------------------------------------------------------------------------------

test('LOW: a claimed transfer is consent only for the material it carried, from the holder who sent it', async () => {
  const sender = key(), recipient = key(), victim = key();
  const src = await makeRecord('x9-src');
  await call('PUT', '/api/records', { holder: sender, body: [src] });
  const offer = (await call('POST', '/transfers', { holder: sender, body: { sourceRecord: src.id, toHandle: 'x9@lab' } })).json;
  const claim = await call('POST', `/transfers/${offer.transferId}/claim`, { holder: recipient, body: { claimCode: offer.claimCode } });
  assert.equal(claim.status, 200);
  // The recipient seals what they received.
  const received = (await call('GET', '/api/records', { holder: recipient })).json.find((r) => r.id === claim.json.recordId);
  const sealed = { ...received, ...(await makeRecord(received.id, { strainName: received.strainName, nonce: received.nonce })) };
  assert.equal((await call('PUT', '/api/records', { holder: recipient, body: [sealed] })).json.count, 1);

  // The sender deletes the source; someone else stores their own record under that id.
  assert.deepEqual((await call('DELETE', '/api/records', { holder: sender, body: { ids: [src.id] } })).json.removed, [src.id]);
  const squat = await makeRecord(src.id, { strainName: 'Victim Mother' });
  assert.equal((await call('PUT', '/api/records', { holder: victim, body: [squat] })).json.count, 1);

  // The recipient names the victim's record as the parent: a proposal, not an edge.
  const p = await call('POST', '/lineage/descent', { holder: recipient, body: { child: sealed.recordFingerprint, parent: squat.recordFingerprint } });
  assert.equal(p.status, 200, JSON.stringify(p.json));
  assert.equal(p.json.confirmed, false, 'the victim never consented');
  assert.deepEqual((await call('GET', `/lineage/ancestors/${sealed.recordFingerprint}`)).json.ancestors, []);
});

test('LOW: a claimed transfer still confirms descent from exactly what was sent', async () => {
  const sender = key(), recipient = key();
  const src = await makeRecord('x9-good');
  await call('PUT', '/api/records', { holder: sender, body: [src] });
  const offer = (await call('POST', '/transfers', { holder: sender, body: { sourceRecord: src.id, toHandle: 'x9g@lab' } })).json;
  const claim = await call('POST', `/transfers/${offer.transferId}/claim`, { holder: recipient, body: { claimCode: offer.claimCode } });
  const received = (await call('GET', '/api/records', { holder: recipient })).json.find((r) => r.id === claim.json.recordId);
  // The name comes from the sender's sealed offer (round 5: the stub has none).
  const sealed = { ...received, ...(await makeRecord(received.id, { strainName: src.strainName, nonce: received.nonce })) };
  await call('PUT', '/api/records', { holder: recipient, body: [sealed] });
  const p = await call('POST', '/lineage/descent', { holder: recipient, body: { child: sealed.recordFingerprint, parent: src.recordFingerprint } });
  assert.equal(p.json.confirmed, true);
});

test('LOW: a source record changed after the offer cannot be claimed under it', async () => {
  const sender = key(), recipient = key();
  const src = await makeRecord('x9-swap');
  await call('PUT', '/api/records', { holder: sender, body: [src] });
  const offer = (await call('POST', '/transfers', { holder: sender, body: { sourceRecord: src.id, toHandle: 'x9s@lab' } })).json;
  const swapped = await makeRecord(src.id, { strainName: 'Something Else' });
  assert.equal((await call('PUT', '/api/records', { holder: sender, body: [swapped] })).json.count, 1);
  const claim = await call('POST', `/transfers/${offer.transferId}/claim`, { holder: recipient, body: { claimCode: offer.claimCode } });
  assert.equal(claim.status, 400);
  assert.match(claim.json.error, /changed since/);
});

// ---------------------------------------------------------------------------------------
// 3 (MEDIUM) An attestation was stored and served whole, up to 16 KB of whatever the
// submitter added around the signed fields, 100 to a page, to anyone, on any fingerprint;
// the embed parsed the same rows on every view. Retractions had no size limit at all.
// ---------------------------------------------------------------------------------------

const attestation = async (subjectCommitment, attestationId, over = {}, kp) => {
  kp ??= await generateKeypair();
  const body = {
    // Any public type: a lab report signature is listed only for its delivery's sender and lab
    // (8 Nov 2026, hide-lab-reports.test.mjs).
    type: 'inspection', attestationId, subjectCommitment,
    documentHash: 'a'.repeat(64), hashAlgorithm: 'sha256', issuedAt: new Date().toISOString(),
    attester: { publicKey: kp.publicKey, displayName: 'Some Lab' }, ...over,
  };
  return { signed: await signAttestation(body, kp.privateKey), kp };
};

test('MEDIUM: only the signed fields of an attestation are stored and served, and they still verify', async () => {
  const subject = H('att-strip');
  // An inspection signature, served whole to anyone. Lab report signatures are listed only for
  // their delivery's sender and lab (hide-lab-reports.test.mjs).
  const { signed, kp } = await attestation(subject, 'att-strip-1_ld1');
  const padded = { ...signed, padding: 'p'.repeat(12_000), note: 'unsigned', attester: { ...signed.attester, extra: 'unsigned too' } };
  const r = await call('POST', '/attestations', { body: padded });
  assert.equal(r.status, 200, JSON.stringify(r.json));
  const stored = db.prepare('SELECT body FROM attestations WHERE attestation_id = ?').get('att-strip-1_ld1').body;
  assert.ok(stored.length < 1024, `stored ${stored.length} bytes`);
  assert.doesNotMatch(stored, /padding|unsigned/);
  const listed = (await call('GET', `/attestations/subject/${subject}`)).json.attestations[0];
  assert.equal(listed.padding, undefined);
  assert.equal(listed.note, undefined);
  assert.equal(listed.attester.extra, undefined);
  const { strength, vettedAttester, registeredAs, retraction, ...asSigned } = listed;
  assert.equal(await verifyAttestation(asSigned), true, 'what is served verifies, as the site checks it');
  // Sending the same attestation again, padded or not, is still idempotent.
  assert.equal((await call('POST', '/attestations', { body: signed })).status, 200);
  assert.equal((await call('POST', '/attestations', { body: padded })).status, 200);

  // Retractions: signed fields only, and small.
  const ret = await signRetraction({ attestationId: 'att-strip-1_ld1', attesterPublicKey: kp.publicKey, reason: 'wrong sample', retractedAt: new Date().toISOString() }, kp.privateKey);
  assert.equal((await call('POST', '/attestations/att-strip-1_ld1/retract', { body: { ...ret, junk: 'j'.repeat(10_000) } })).status, 200);
  const storedRet = db.prepare('SELECT body FROM retractions WHERE attestation_id = ?').get('att-strip-1_ld1').body;
  assert.doesNotMatch(storedRet, /junk/);
  const listedRet = (await call('GET', `/attestations/subject/${subject}`)).json.attestations[0].retraction;
  assert.equal(await verifyRetraction(listedRet, asSigned), true);
});

test('MEDIUM: an attestation whose signed fields exceed 4 KB is refused, and so is a long retraction', async () => {
  const subject = H('att-big');
  const kp = await generateKeypair();
  const { signed: big } = await attestation(subject, 'att-big-1', { attester: { publicKey: kp.publicKey, displayName: 'L'.repeat(5000) } }, kp);
  assert.equal(await verifyAttestation(big), true, 'a genuine signature over a 5 KB name');
  const r = await call('POST', '/attestations', { body: big });
  assert.equal(r.status, 400);
  assert.match(r.json.error, /4096 bytes/);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM attestations WHERE subject_commitment = ?').get(subject).n, 0);

  const { signed: ok, kp: kp2 } = await attestation(subject, 'att-big-2');
  assert.equal((await call('POST', '/attestations', { body: ok })).status, 200);
  const longReason = await signRetraction({ attestationId: 'att-big-2', attesterPublicKey: kp2.publicKey, reason: 'r'.repeat(3000), retractedAt: new Date().toISOString() }, kp2.privateKey);
  const rr = await call('POST', '/attestations/att-big-2/retract', { body: longReason });
  assert.equal(rr.status, 400);
  assert.match(rr.json.error, /2048 bytes/);
});

test('MEDIUM: a full page of attestations stays small', async () => {
  const subject = H('att-page');
  const ins = db.prepare('INSERT INTO attestations (attestation_id, subject_commitment, attester_key, body, created_at) VALUES (?,?,?,?,?)');
  const { signed } = await attestation(subject, 'att-page-x');
  // As an older registry stored them: the whole submitted body, padding and all.
  for (let i = 0; i < 100; i++) ins.run(`att-page-${i}`, subject, signed.attester.publicKey, JSON.stringify({ ...signed, attestationId: `att-page-${i}`, padding: 'p'.repeat(15_000) }), i);
  const r = await call('GET', `/attestations/subject/${subject}`);
  assert.equal(r.json.attestations.length, 100);
  assert.ok(r.text.length < 100 * 1024, `a page of 100 is ${r.text.length} bytes, not ~1.6 MB`);
});

// ---------------------------------------------------------------------------------------
// 8 (LOW) The embed printed an attester's self-chosen display name as given: bidi
// overrides, zero-width and control characters, any length. A name can be made to render
// as something else on a third party's page.
// ---------------------------------------------------------------------------------------

test('LOW: names on the embed lose bidi, control and zero-width characters, are NFC, and are cut short', async () => {
  const { renderEmbed } = await import('../lineage/embed.mjs');
  const signer = (displayName, vetted = false) => ({ strength: 'signed', vettedAttester: vetted, retraction: null, registeredAs: { displayName, ...(vetted ? { nameCheck: { source: 'licence-listing', sourceUrl: 'https://agriculture.example.gov/labs', licenceNo: 'TL-1', emailDomain: 'lab.example', checkedAt: '2026-10-14', checkedBy: 'AB', expiresAt: '2027-10-14' } } : {}) } });
  const nasty = 'Acme‮bal‬ ​Lab⁦\u0007­﻿' + 'Café' + ' padding'.repeat(40);
  const html = renderEmbed({ found: true, id: 'X', cultivar: 'Cult‮ivar‍', recordFingerprint: 'a'.repeat(64),
    attestations: [signer(nasty, true), signer('Other‮ Lab')] }, 'https://registry.example');
  for (const c of ['‮', '‬', '​', '⁦', '\u0007', '­', '﻿', '‍']) {
    assert.equal(html.includes(c), false, `U+${c.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')} removed`);
  }
  assert.match(html, /Signed by Acmebal Lab/);
  assert.ok(html.includes('Café'), 'NFC: e + combining acute is one character');
  const shown = /Signed by (.*?)\. VeilCore’s operator matched/.exec(html)[1];
  assert.ok([...shown].length <= 64, `cut to 64 characters (${[...shown].length})`);
  assert.ok(shown.endsWith('…'));
  assert.match(html, /a key named “Other Lab” \(name not checked\)/);
  assert.match(html, /vc-title">Cultivar</);
  // A name that is nothing but invisible characters is no name.
  const blank = renderEmbed({ found: true, id: 'Y', cultivar: 'c', recordFingerprint: 'b'.repeat(64), attestations: [signer('​‮', true)] }, 'https://r.example');
  assert.match(blank, /Signed by a key whose registered name can’t be shown here\. VeilCore’s operator matched that name/);
});

// ---------------------------------------------------------------------------------------
// 4 (MEDIUM) An anchor is whatever the operator posts: the transaction is never looked up,
// and anchoredAt could be any date, even before the batch was sealed. Yet /verify's
// priorPossession rests on it and the embed said the date "does not rest on ... this
// registry's" word.
// ---------------------------------------------------------------------------------------

test('MEDIUM: an anchor dated before its batch was sealed, or in the future, is refused', async () => {
  const holder = key();
  const rec = await makeRecord('anchor-when');
  await call('PUT', '/api/records', { holder, body: [rec] });
  const sealed = await call('POST', '/batches/seal', { headers: OP });
  assert.equal(sealed.status, 200, JSON.stringify(sealed.json).slice(0, 200));
  const post = (anchoredAt) => call('POST', `/batches/${sealed.json.batchId}/anchor`, { headers: OP,
    body: { network: 'mainnet', contractAddress: CONTRACT, txHash: 'cd'.repeat(32), blockHeight: 7, ...(anchoredAt === undefined ? {} : { anchoredAt }) } });
  const early = await post('2024-01-01T00:00:00.000Z');
  assert.equal(early.status, 400);
  assert.match(early.json.error, /before .*sealed/);
  const hourBefore = await post(new Date(Date.now() - 3_600_000).toISOString());
  assert.equal(hourBefore.status, 400, 'an hour before sealing');
  const future = await post(new Date(Date.now() + 86_400_000).toISOString());
  assert.equal(future.status, 400);
  assert.match(future.json.error, /future/);
  assert.equal(db.prepare('SELECT anchor FROM batches WHERE batch_id = ?').get(sealed.json.batchId).anchor, null, 'nothing recorded');
  assert.equal((await post(new Date(Date.now() + 60_000).toISOString())).status, 200, 'a minute of clock skew is fine');
  assert.equal((await post()).status, 200, 'no date: now');
});

test('MEDIUM: /verify and the embed say the anchor is recorded by the operator, unchecked, and how to check it', async () => {
  const holder = key();
  const rec = await makeRecord('anchor-words');
  await call('PUT', '/api/records', { holder, body: [rec] });
  await call('PUT', `/api/records/${rec.id}/disclosure`, { holder, body: { show: ['existence'] } });
  const { batchId } = (await call('POST', '/batches/seal', { headers: OP })).json;
  const tx = 'ef'.repeat(32);
  assert.equal((await call('POST', `/batches/${batchId}/anchor`, { headers: OP, body: { network: 'mainnet', contractAddress: CONTRACT, txHash: tx, blockHeight: 9 } })).status, 200);

  const v = (await call('GET', `/verify/${rec.id}`)).json;
  assert.equal(v.anchored, true);
  assert.equal(v.priorPossession, true, 'unchanged: a mainnet anchor');
  assert.equal(v.anchorRecordedBy, 'registry-operator');
  assert.equal(v.anchorCheckedOnChain, false);
  assert.ok(v.anchorNote.includes(tx) && v.anchorNote.includes(CONTRACT), 'names the transaction and contract to look up');
  assert.match(v.anchorNote, /not looked/);

  const html = (await call('GET', `/embed/${rec.id}`)).text;
  assert.doesNotMatch(html, /does not rest on the holder\u2019s word or this registry\u2019s/, 'no longer claims more than the registry checked');
  assert.ok(html.includes(tx), 'the full transaction hash is shown');
  assert.ok(html.includes(CONTRACT), 'and the contract');
  assert.match(html, /recorded by this registry\u2019s operator/);
  assert.match(html, /has not checked/);
});
