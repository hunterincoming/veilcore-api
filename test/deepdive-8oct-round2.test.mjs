// Deep dive, 8 Oct 2026, round 2: holes a verification review found in the first round of
// fixes (PoCs in the review's verify2 folder), each as a test that failed before its fix.
// No network, no live service.
//
// SPDX-License-Identifier: Apache-2.0

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { randomBytes } from 'node:crypto';
import { canonicalise, sha256Hex, newNonce } from 'veilcore-records';
import { inOneMinute, untilReady, testBody, openForTest, vaultKeyFor, handleTagFor } from './helpers.mjs';

const OP_TOKEN = 'round2-operator-token-at-least-32-characters';
const CAP = 1024 * 1024;
process.env.DB_PATH = ':memory:';
process.env.VEILCORE_OTS = 'off';
process.env.VEILCORE_OPERATOR_TOKEN = OP_TOKEN;
process.env.HOLDER_MAX_BYTES = String(CAP);
// Small, so the per-address budget for whole-set reads can be spent in a test. Default 64 MB.
process.env.WHOLE_SET_READ_BYTES_PER_MINUTE = String(3 * CAP);
const CONTRACT = '5e'.repeat(32);
process.env.VEILCORE_ANCHOR_NETWORK = 'mainnet';
process.env.VEILCORE_ANCHOR_CONTRACT = CONTRACT;
const require = createRequire(import.meta.url);
const { app, db } = require('../server.js');
const { storedHolderKey } = require('../holder-key.js');
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
  photoFingerprints: r.photoFingerprints ?? [], refId: r.refId ?? '', strainName: r.strainName,
  ...(r.profile ? { profile: r.profile } : {}) });
const makeRecord = async (id, over = {}) => {
  const r = { id, strainName: 'C' + id, bredBy: 'B', dateCreated: '2026-01-01', loggedAt: '2026-01-01T00:00:00Z',
    nonce: newNonce(), notes: 'n', parents: [], photoFingerprints: [], breedingMethod: 'm', refId: '', ...over };
  r.recordFingerprint = await sha256Hex(canonicalise(committedOf(r)));
  return r;
};
const held = (holder, table = 'records') =>
  db.prepare(`SELECT COALESCE(SUM(octet_length(body)), 0) AS bytes, COUNT(*) AS n FROM ${table} WHERE holder_key = ?`).get(storedHolderKey(holder));
const PADX = { pad: 'p'.repeat(60_000) };

// ---------------------------------------------------------------------------------------
// 1a (HIGH) The byte ceiling counted each copy of an id in one save against the same stored
// row: small copies first, then the big one, and the save looked like it shrank the set.
// ---------------------------------------------------------------------------------------

test('HIGH 1a: an id sent several times in one save is counted once, as its last copy', async () => {
  const h = key();
  const big = await makeRecord('dup-A', PADX);
  assert.equal((await call('PUT', '/api/records', { holder: h, body: [big] })).json.count, 1);
  for (let i = 0; ; i++) {
    const r = await call('PUT', '/api/records', { holder: h, body: [await makeRecord(`fill-${i}`, PADX)] });
    if (r.status !== 200) break;
  }
  assert.ok(held(h).bytes <= CAP);
  const small = { ...big, pad: 'x' };
  const news = [];
  for (let k = 0; k < 10; k++) news.push(await makeRecord(`over-${k}`, PADX));
  const r = await call('PUT', '/api/records', { holder: h, body: [...Array(45).fill(small), big, ...news] });
  assert.equal(r.status, 413, JSON.stringify(r.json).slice(0, 200));
  assert.ok(held(h).bytes <= CAP, `holds ${held(h).bytes}`);
  // The last copy is the one stored.
  assert.equal((await call('PUT', '/api/records', { holder: h, body: [big, small] })).status, 200);
  assert.equal(openForTest(JSON.parse(db.prepare("SELECT body FROM records WHERE id = 'dup-A'").get().body), vaultKeyFor(h)).pad, 'x');
});

test('HIGH 1a: the same for licences', async () => {
  const h = key();
  const big = { id: 'L-A', pad: 'q'.repeat(60_000) };
  await call('PUT', '/api/licenses', { holder: h, body: [big] });
  for (let i = 0; ; i++) {
    const r = await call('PUT', '/api/licenses', { holder: h, body: [{ id: `LF-${i}`, pad: 'q'.repeat(60_000) }] });
    if (r.status !== 200) break;
  }
  const small = { id: 'L-A', pad: '' };
  const news = Array.from({ length: 6 }, (_, k) => ({ id: `LO-${k}`, pad: 'q'.repeat(60_000) }));
  const r = await call('PUT', '/api/licenses', { holder: h, body: [...Array(7).fill(small), big, ...news] });
  assert.equal(r.status, 413);
  assert.ok(held(h, 'licenses').bytes <= CAP);
});

// ---------------------------------------------------------------------------------------
// 1b (HIGH) Claiming a transfer inserted a record for the claimant with no count or byte
// check, copying the source's profile (up to 64 KB): offer, claim, repeat, and the
// claimant held any amount for a few bytes of requests. Since sealed records the copy is a
// stub of public fields, but it is still a row in the claimant's set and still counted.
// ---------------------------------------------------------------------------------------

const offerAndClaim = async (sender, sourceRecord, claimant, toHandle = 'me@x') => {
  const o = await call('POST', '/transfers', { holder: sender, body: { sourceRecord, toHandle } });
  assert.equal(o.status, 200, JSON.stringify(o.json));
  return call('POST', `/transfers/${o.json.transferId}/claim`, { holder: claimant, body: { claimCode: o.json.claimCode } });
};

test('HIGH 1b: claims count against the claimant\'s byte ceiling', async () => {
  const s = key(), rcpt = key();
  // A long source id: the stub copies it (since round 5 the stub has no name).
  const src = await makeRecord(`claim-src-${'x'.repeat(118)}`, { strainName: 'S'.repeat(500) });
  assert.equal((await call('PUT', '/api/records', { holder: s, body: [src] })).json.count, 1);
  // The claimant is a few stubs short of full (one row, straight into the table).
  db.prepare('INSERT INTO records (id, holder_key, body, updated_at, first_seen) VALUES (?,?,?,0,0)')
    .run('claim-filler', storedHolderKey(rcpt), JSON.stringify({ id: 'claim-filler', pad: 'f'.repeat(CAP - 3000) }));
  let refused = null;
  let claimed = 0;
  for (let k = 0; k < 25 && !refused; k++) {
    const c = await offerAndClaim(s, src.id, rcpt, `me${k}@x`);
    if (c.status !== 200) refused = c;
    else claimed++;
  }
  assert.ok(refused, 'a claim is refused once the claimant is full');
  assert.ok(claimed >= 3 && claimed <= 12, `several ~330-byte stubs fit in the last 3 KB (${claimed})`);
  assert.equal(refused.status, 413);
  assert.match(refused.json.error, /MB/);
  assert.ok(held(rcpt).bytes <= CAP, `claimant holds ${held(rcpt).bytes}`);
});

test('HIGH 1b: claims count against the claimant\'s record count', async () => {
  const s = key(), rcpt = key();
  const src = await makeRecord('claim-count-src');
  await call('PUT', '/api/records', { holder: s, body: [src] });
  const ins = db.prepare('INSERT INTO records (id, holder_key, body, updated_at, first_seen) VALUES (?,?,?,0,0)');
  db.transaction(() => { for (let i = 0; i < 10_000; i++) ins.run(`cc-${i}`, storedHolderKey(rcpt), '{}'); })();
  const c = await offerAndClaim(s, src.id, rcpt, 'count@x');
  assert.equal(c.status, 413);
  assert.match(c.json.error, /10000 records/);
  assert.equal(held(rcpt).n, 10_000);
});

// ---------------------------------------------------------------------------------------
// 1c (HIGH) /api/export built the whole export in memory in one piece, however large the
// holder's set (and sets past the ceiling exist: stored before it, or through 1a and 1b).
// ---------------------------------------------------------------------------------------

test('HIGH 1c: the export is streamed in pieces and still holds everything, valid JSON', async () => {
  const h = key();
  // Past the ceiling, as a set stored before it could be: written straight to the table.
  const ins = db.prepare('INSERT INTO records (id, holder_key, body, updated_at, first_seen) VALUES (?,?,?,?,?)');
  const recs = [];
  for (let i = 0; i < 40; i++) recs.push(await makeRecord(`exp-${String(i).padStart(3, '0')}`, PADX));
  db.transaction(() => { for (const r of recs) ins.run(r.id, storedHolderKey(h), JSON.stringify(r), 1, 1759000000000); })();
  await call('PUT', '/api/licenses', { holder: h, body: [{ id: 'exp-lic' }] });
  await call('PUT', `/api/records/${recs[0].id}/disclosure`, { holder: h, body: { show: ['existence'] } });
  const sealed = await call('POST', '/batches/seal', { headers: OP });
  assert.equal(sealed.status, 200);

  const res = await fetch(`${base}/api/export`, { headers: { 'x-holder-key': h } });
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('transfer-encoding'), 'chunked', 'written in pieces, not built whole');
  assert.equal(res.headers.get('content-length'), null);
  assert.match(res.headers.get('content-type'), /application\/json/);
  assert.equal(res.headers.get('cache-control'), 'no-store');
  const text = await res.text();
  assert.ok(text.length > 2 * CAP, `the whole set is there (${text.length} bytes)`);
  const out = JSON.parse(text);
  assert.equal(out.format, 'veilcore-registry-export/v1');
  assert.deepEqual(out.records.map((r) => r.id), recs.map((r) => r.id));
  assert.equal(out.records[0].registryFirstSeen, new Date(1759000000000).toISOString());
  assert.deepEqual(out.licenses.map((l) => l.id), ['exp-lic']);
  assert.deepEqual(out.disclosures, { [recs[0].id]: ['existence'] });
  assert.equal(Object.keys(out.proofs).length, 40);
  assert.equal(out.proofs[recs[5].recordFingerprint].batchId, sealed.json.batchId);
  assert.equal(out.batches.length, 1);
  assert.equal(out.batches[0].batchId, sealed.json.batchId);
  assert.match(out.note, /never sent here/);
});

// ---------------------------------------------------------------------------------------
// 2 (MEDIUM) The per-handle cap on open offers let anyone block a recipient: 100 junk
// offers to lab@realcorp.com and no real sender could offer them anything for 30 days.
// ---------------------------------------------------------------------------------------

const plantOffers = (n, { handle, fromHolder, prefix, createdAt = Date.now() }) => {
  const ins = db.prepare(`INSERT INTO transfers (id, source_record, from_holder, to_handle, claim_code, created_at)
                          VALUES (?,?,?,?,?,?)`);
  db.transaction(() => { for (let i = 0; i < n; i++) ins.run(`${prefix}-${i}`, 'nowhere', storedHolderKey(fromHolder), handle, 'c'.repeat(32), createdAt); })();
};

test('MEDIUM 2: junk offers to a handle from one sender do not stop another sender', async () => {
  const griefer = key(), legit = key();
  // Planted under the very tag the legit sender's browser makes for the handle (since round 2
  // the registry holds tags, not names), the worst case: they still do not count.
  plantOffers(150, { handle: handleTagFor(legit, 'lab@realcorp.com'), fromHolder: griefer, prefix: 'GRIEF' });
  const l = await makeRecord('legit-src');
  await call('PUT', '/api/records', { holder: legit, body: [l] });
  const r = await call('POST', '/transfers', { holder: legit, body: { sourceRecord: l.id, toHandle: 'lab@realcorp.com' } });
  assert.equal(r.status, 200, JSON.stringify(r.json));
});

test('MEDIUM 2: one sender may have at most 20 open offers to one handle, and 200 in all', async () => {
  const s = key();
  const src = await makeRecord('pair-src');
  await call('PUT', '/api/records', { holder: s, body: [src] });
  plantOffers(19, { handle: handleTagFor(s, 'pair@lab'), fromHolder: s, prefix: 'PAIR' });
  assert.equal((await call('POST', '/transfers', { holder: s, body: { sourceRecord: src.id, toHandle: 'pair@lab' } })).status, 200, 'the 20th');
  const over = await call('POST', '/transfers', { holder: s, body: { sourceRecord: src.id, toHandle: 'pair@lab' } });
  assert.equal(over.status, 429);
  assert.match(over.json.error, /to this handle/);
  // Older than 30 days: no longer counted.
  db.prepare("UPDATE transfers SET created_at = ? WHERE id LIKE 'PAIR-%'").run(Date.now() - 31 * 86_400_000);
  assert.equal((await call('POST', '/transfers', { holder: s, body: { sourceRecord: src.id, toHandle: 'pair@lab' } })).status, 200);
  // The total per sender still holds, across handles.
  plantOffers(198, { handle: handleTagFor(s, 'elsewhere@lab'), fromHolder: s, prefix: 'TOTAL' });
  db.prepare("UPDATE transfers SET to_handle = substr(to_handle, 1, 52) || printf('%012x', rowid) WHERE id LIKE 'TOTAL-%'").run();
  const total = await call('POST', '/transfers', { holder: s, body: { sourceRecord: src.id, toHandle: 'new@lab' } });
  assert.equal(total.status, 429, JSON.stringify(total.json));
  assert.match(total.json.error, /unclaimed offers/);
});

// ---------------------------------------------------------------------------------------
// 3 (MEDIUM) One claimed transfer counted as the sender's consent for ANY record of the
// recipient to descend from the source, not just the record the claim created.
// ---------------------------------------------------------------------------------------

test('MEDIUM 3: a claimed transfer confirms descent only for the record the claim created', async () => {
  const s = key(), rcpt = key();
  const src = await makeRecord('consent-src');
  await call('PUT', '/api/records', { holder: s, body: [src] });
  const claim = await offerAndClaim(s, src.id, rcpt, 'c@x');
  assert.equal(claim.status, 200);
  const kids = [await makeRecord('unrel-1'), await makeRecord('unrel-2')];
  await call('PUT', '/api/records', { holder: rcpt, body: kids });
  for (const k of kids) {
    const p = await call('POST', '/lineage/descent', { holder: rcpt, body: { child: k.recordFingerprint, parent: src.recordFingerprint } });
    assert.equal(p.status, 200, JSON.stringify(p.json));
    assert.equal(p.json.confirmed, false, `${k.id} is only proposed: the sender never sent it`);
    await call('DELETE', `/lineage/descent/${k.recordFingerprint}`, { holder: rcpt });
  }
  // The record the claim created, once sealed, is confirmed at once.
  const received = (await call('GET', '/api/records', { holder: rcpt })).json.find((r) => r.id === claim.json.recordId);
  const sealed = { ...received, ...(await makeRecord(received.id, { strainName: received.strainName, nonce: received.nonce })) };
  assert.equal((await call('PUT', '/api/records', { holder: rcpt, body: [sealed] })).json.count, 1);
  const ok = await call('POST', '/lineage/descent', { holder: rcpt, body: { child: sealed.recordFingerprint, parent: src.recordFingerprint } });
  assert.equal(ok.json.confirmed, true);
  assert.equal(db.prepare('SELECT received_record FROM transfers WHERE claimed_by = ?').get(storedHolderKey(rcpt)).received_record, claim.json.recordId);
});

// ---------------------------------------------------------------------------------------
// 5 (LOW) anchoredAt with no time zone was accepted and stored as sent: read in UTC by
// some clients and in local time by others, and checked here in the server's zone.
// ---------------------------------------------------------------------------------------

test('LOW 5: anchoredAt needs Z or an offset, and is stored in UTC as an ISO string', async () => {
  const holder = key();
  await call('PUT', '/api/records', { holder, body: [await makeRecord('anchor-tz')] });
  const sealed = await call('POST', '/batches/seal', { headers: OP });
  assert.equal(sealed.status, 200);
  const post = (anchoredAt) => call('POST', `/batches/${sealed.json.batchId}/anchor`, { headers: OP,
    body: { network: 'mainnet', contractAddress: CONTRACT, txHash: 'cd'.repeat(32), anchoredAt } });
  const d = new Date(Date.now() + 30_000);
  const noZone = d.toISOString().slice(0, 19);
  for (const bad of [noZone, d.toISOString().slice(0, 10), d.toDateString(), d.toUTCString(), `${noZone}+0200`]) {
    const r = await post(bad);
    assert.equal(r.status, 400, bad);
    assert.match(r.json.error, /time zone|ISO 8601/, bad);
  }
  // An offset is fine, and stored as the same instant in UTC.
  const hh = String((d.getUTCHours() + 2) % 24).padStart(2, '0');
  const later = d.getUTCHours() >= 22; // the +02:00 form would be tomorrow's date; skip that edge
  if (!later) {
    const withOffset = `${d.toISOString().slice(0, 11)}${hh}${d.toISOString().slice(13, 23)}+02:00`;
    const ok = await post(withOffset);
    assert.equal(ok.status, 200, JSON.stringify(ok.json));
    assert.equal(ok.json.anchor.anchoredAt, new Date(withOffset).toISOString());
    assert.equal(JSON.parse(db.prepare('SELECT anchor FROM batches WHERE batch_id = ?').get(sealed.json.batchId).anchor).anchoredAt, d.toISOString());
  }
  assert.equal((await post(d.toISOString())).status, 200);
});

// ---------------------------------------------------------------------------------------
// 6 (LOW) Name cleaning kept characters that print as nothing without being format
// characters (U+2800 braille blank, U+034F, U+17B4/U+17B5, Hangul fillers), so a "name"
// of blanks was printed as a name; and NFC let styled lookalikes through (U+1D40B...).
// ---------------------------------------------------------------------------------------

test('LOW 6: invisible names are no names; display names are NFKC; a name needs a letter or digit', async () => {
  const { renderEmbed, displayName } = await import('../lineage/embed.mjs');
  for (const blank of ['⠀', '͏͏', '឴឵', 'ㅤ', 'ᅟᅠ', 'ﾠ', '⠀  ⠀', '-- ..', '\u{E0041}\u{E0042}']) {
    assert.equal(displayName(blank), '', JSON.stringify(blank));
  }
  assert.equal(displayName('\u{1D40B}\u{1D41A}\u{1D41B}'), 'Lab', 'mathematical bold letters read as the letters they look like');
  assert.equal(displayName('Ａｃｍｅ'), 'Acme', 'fullwidth');
  assert.equal(displayName('A⠀c͏me 2'), 'Acme 2');
  assert.equal(displayName('אב Lab'), 'אב Lab', 'a right-to-left name keeps its letters');
  const signer = (name, vetted) => ({ strength: 'signed', vettedAttester: vetted, retraction: null, registeredAs: { displayName: name, ...(vetted ? { nameCheck: { source: 'licence-listing', sourceUrl: 'https://agriculture.example.gov/labs', licenceNo: 'TL-1', emailDomain: 'lab.example', checkedAt: '2026-10-14', checkedBy: 'AB', expiresAt: '2027-10-14' } } : {}) } });
  const html = renderEmbed({ found: true, id: 'Y', cultivar: '⠀', recordFingerprint: 'b'.repeat(64),
    attestations: [signer('⠀', true), signer('឴', false), signer('\u{1D40B}\u{1D41A}\u{1D41B}', false)] }, 'https://r.example');
  assert.match(html, /Signed by a key whose registered name can’t be shown here/);
  assert.doesNotMatch(html, /⠀|឴/);
  assert.match(html, /a key named “Lab” \(name not checked\)/);
  assert.match(html, /Signed by a key nobody has registered/, 'a blank name counts as no name');
  assert.match(html, /vc-title">Name not shared</);
});

// ---------------------------------------------------------------------------------------
// 8 The site reads the whole set without paging, every 30 s, and treats any non-200 as "no
// records". Round 1 allowed 60 such reads a minute per address: behind a shared NAT a few
// dozen users would have had their records blanked. The per-address limit is now on bytes
// served, which real sets barely touch; the per-key count stays.
// ---------------------------------------------------------------------------------------

test('8: many holders behind one address can all read their whole sets', async () => {
  const keys = Array.from({ length: 80 }, () => key());
  // Straight into the table: the write rate limit (120/min) is not what is under test.
  const ins = db.prepare('INSERT INTO records (id, holder_key, body, updated_at, first_seen) VALUES (?,?,?,?,?)');
  for (const k of keys) {
    const r = await makeRecord(`nat-${k.slice(0, 8)}`);
    ins.run(r.id, storedHolderKey(k), JSON.stringify(r), 1, 1);
  }
  for (const k of keys) {
    const r = await call('GET', '/api/records', { holder: k });
    assert.equal(r.status, 200, 'not refused for sharing an address');
    assert.equal(r.json.length, 1);
    assert.equal((await call('GET', '/api/licenses', { holder: k })).status, 200);
  }
});

test('8: one address reading large sets over and over is still stopped, by bytes', async () => {
  const k = key();
  const recs = [];
  for (let i = 0; i < 10; i++) recs.push(await makeRecord(`natbig-${i}`, PADX)); // ~0.8 MB sealed
  assert.equal((await call('PUT', '/api/records', { holder: k, body: recs })).status, 200);
  let first429 = -1;
  // In one minute, as a client hammering it would be (helpers.mjs).
  await inOneMinute(async () => {
    for (let i = 0; i < 12 && first429 < 0; i++) {
      const r = await call('GET', '/api/records', { holder: k });
      if (r.status === 429) { first429 = i; assert.match(r.json.error, /page with \?limit=/); }
    }
  });
  assert.ok(first429 >= 3 && first429 <= 9, `refused once ~3 MB were served this minute (at read ${first429})`);
  assert.equal((await call('GET', '/api/records?limit=5', { holder: k })).status, 200, 'paged reads are not');
});
