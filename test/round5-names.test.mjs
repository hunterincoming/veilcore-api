// Round 5 of sealing (17 Oct 2026, the site's CONTRACT.md #28 and #29): nothing readable the
// registry doesn't need.
//   #28  a record's name is sealed: a save with a clear `strainName` is refused (400 "strainName
//        belongs inside sealed"); public answers give a name only from the holder's `name`
//        grant, or from a row saved before this until its holder's browser saves it again;
//        a claim's stub has none; the purge removes what is left.
//   #29  a DNA report is published only bound (dnaPairBinding): the plain values are refused
//        and never answered (verify-current-pairing.test.mjs has the rest).
// No network.
//
// SPDX-License-Identifier: Apache-2.0

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { randomBytes } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import Database from 'better-sqlite3';
import { canonicalise, sha256Hex, newNonce } from 'veilcore-records';
import { untilReady, sealForTest, vaultKeyFor, sealOfferForTest, openOfferForTest, offerFromRecord, handleTagFor, grantForTest } from './helpers.mjs';

process.env.DB_PATH = ':memory:';
process.env.VEILCORE_OTS = 'off';
const require = createRequire(import.meta.url);
const { app, db } = require('../server.js');
const { storedHolderKey } = require('../holder-key.js');
const sealedJs = require('../sealed.js');

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
const committedOf = (r) => ({ breedingMethod: r.breedingMethod ?? '', bredBy: r.bredBy, dateCreated: r.dateCreated,
  loggedAt: r.loggedAt, nonce: r.nonce, notes: r.notes, parents: r.parents ?? [],
  photoFingerprints: r.photoFingerprints ?? [], refId: r.refId ?? '', strainName: r.strainName });
const makeRecord = async (id, over = {}) => {
  const r = { id, strainName: `Secret Name ${randomBytes(4).toString('hex')}`, bredBy: 'Breeder', dateCreated: '2026-01-01',
    loggedAt: 1760000000000, nonce: newNonce(), notes: '', parents: [], photoFingerprints: [], breedingMethod: '', refId: '', ...over };
  r.recordFingerprint = await sha256Hex(canonicalise(committedOf(r)));
  return r;
};
const sealedFor = (holder, r) => sealForTest(r, vaultKeyFor(holder));
const bodyOf = (id) => JSON.parse(db.prepare('SELECT body FROM records WHERE id = ?').get(id).body);
const verify = async (id, q = '') => (await call('GET', `/verify/${id}${q}`)).json;
const embedTitle = async (id) => /vc-title">([^<]*)</.exec(await (await fetch(`${base}/embed/${id}`)).text())?.[1];

test('#28: the contract strings and the feature are exactly as the site expects', async () => {
  assert.equal(sealedJs.NAME_IN_CLEAR, 'strainName belongs inside sealed');
  assert.ok(!sealedJs.PUBLIC_RECORD_FIELDS.includes('strainName'));
  const h = (await call('GET', '/health')).json;
  assert.ok(h.features.includes('sealed-name-v1'));
  assert.ok(h.features.includes('dna-pair-binding-v1'));
});

test('#28: a sealed save stores no name; the base view shows none; nothing of it is readable', async () => {
  const holder = key();
  const rec = await makeRecord(`N-${randomBytes(4).toString('hex')}`);
  const r = await call('PUT', '/api/records', holder, [sealedFor(holder, rec)]);
  assert.equal(r.json.count, 1, JSON.stringify(r.json));
  assert.equal(bodyOf(rec.id).strainName, undefined);
  assert.ok(!db.prepare('SELECT body FROM records WHERE id = ?').get(rec.id).body.includes(rec.strainName));
  const v = await verify(rec.id);
  assert.equal(v.cultivar, undefined);
  assert.equal((await call('GET', `/records/${rec.id}`)).json.cultivar, undefined);
  assert.equal(await embedTitle(rec.id), 'Name not shared');
  // The holder gets the row back, and only its box holds the name.
  const mine = (await call('GET', '/api/records', holder)).json.find((x) => x.id === rec.id);
  assert.equal(mine.strainName, undefined);
});

test('#28: the name grant publishes the name on purpose, goes stale with the record, and ?show= narrows it', async () => {
  const holder = key();
  const rec = await makeRecord(`G-${randomBytes(4).toString('hex')}`, { strainName: 'Harbour Mist' });
  await call('PUT', '/api/records', holder, [sealedFor(holder, rec)]);
  const g = await call('PUT', `/api/records/${rec.id}/disclosure`, holder, grantForTest(rec, ['existence', 'name']));
  assert.equal(g.status, 200, JSON.stringify(g.json));
  assert.deepEqual(g.json.show, ['existence', 'name']);
  assert.deepEqual(g.json.values, { name: 'Harbour Mist' });
  let v = await verify(rec.id);
  assert.equal(v.cultivar, 'Harbour Mist');
  assert.deepEqual(v.disclosed, ['own', 'name']);
  assert.equal((await call('GET', `/records/${rec.id}`)).json.cultivar, 'Harbour Mist');
  assert.equal(await embedTitle(rec.id), 'Harbour Mist');
  // A link that narrows it away gets no name.
  assert.equal((await verify(rec.id, '?show=own')).cultivar, undefined);
  // A name value without the grant is refused; one over 500 characters too.
  const noKey = await call('PUT', `/api/records/${rec.id}/disclosure`, holder, { show: ['existence'], forFingerprint: rec.recordFingerprint, values: { name: 'x' } });
  assert.equal(noKey.status, 400);
  assert.match(noKey.json.error, /values\.name is accepted only with the name grant/);
  const long = await call('PUT', `/api/records/${rec.id}/disclosure`, holder, { show: ['name'], forFingerprint: rec.recordFingerprint, values: { name: 'n'.repeat(501) } });
  assert.equal(long.status, 400);
  // The holder changes the record: the published name described the old one, and goes stale.
  const edited = await makeRecord(rec.id, { strainName: 'Harbour Mist II' });
  await call('PUT', '/api/records', holder, [sealedFor(holder, edited)]);
  v = await verify(rec.id);
  assert.equal(v.cultivar, undefined);
  assert.deepEqual(v.staleGrant, ['name']);
  // Sent again by the holder's app: shown again.
  await call('PUT', `/api/records/${rec.id}/disclosure`, holder, grantForTest(edited, ['existence', 'name']));
  assert.equal((await verify(rec.id)).cultivar, 'Harbour Mist II');
});

test('#28: a row saved before names were sealed keeps showing its name until its holder saves it again', async () => {
  const holder = key();
  const rec = await makeRecord(`L-${randomBytes(4).toString('hex')}`, { strainName: 'Old Public Name' });
  // As a site before round 5 stored it: the name beside the box.
  db.prepare('INSERT INTO records (id, holder_key, body, updated_at, first_seen) VALUES (?,?,?,?,?)')
    .run(rec.id, storedHolderKey(holder), JSON.stringify({ ...sealedFor(holder, rec), strainName: rec.strainName }), 1, 1);
  assert.equal((await verify(rec.id)).cultivar, 'Old Public Name', 'old links keep working');
  // The holder's app saves it again, sealed with the name inside: the clear name is gone.
  const r = await call('PUT', '/api/records', holder, [sealedFor(holder, rec)]);
  assert.equal(r.json.count, 1, JSON.stringify(r.json));
  assert.equal(bodyOf(rec.id).strainName, undefined);
  assert.equal((await verify(rec.id)).cultivar, undefined);
  // An older site that still sends it is refused whole, and changes nothing.
  const before = db.prepare('SELECT body FROM records WHERE id = ?').get(rec.id).body;
  const old = await call('PUT', '/api/records', holder, [{ ...sealedFor(holder, rec), strainName: rec.strainName }]);
  assert.equal(old.status, 400);
  assert.deepEqual(old.json, { error: 'strainName belongs inside sealed' });
  assert.equal(db.prepare('SELECT body FROM records WHERE id = ?').get(rec.id).body, before);
});

test('#28: a claim\'s stub carries no name; the recipient reads it from the sealed offer', async () => {
  const sender = key(), lab = key();
  const src = await makeRecord(`S-${randomBytes(4).toString('hex')}`, { strainName: 'Offered Name' });
  await call('PUT', '/api/records', sender, [sealedFor(sender, src)]);
  const offerKey = randomBytes(32);
  const o = await call('POST', '/transfers', sender, {
    sourceRecord: src.id, toHandle: handleTagFor(sender, 'lab'), sealedOffer: sealOfferForTest(offerFromRecord(src), offerKey, src.id, src.recordFingerprint),
  });
  assert.equal(o.status, 200, JSON.stringify(o.json));
  const c = await call('POST', `/transfers/${o.json.transferId}/claim`, lab, { claimCode: o.json.claimCode });
  assert.equal(c.status, 200, JSON.stringify(c.json));
  const stub = bodyOf(c.json.recordId);
  assert.equal(stub.strainName, undefined);
  assert.ok(!JSON.stringify(stub).includes('Offered Name'));
  assert.equal(openOfferForTest(c.json.offerSealed, offerKey, src.id, src.recordFingerprint).strainName, 'Offered Name');
  assert.equal((await verify(c.json.recordId)).cultivar, undefined);
});

test('#28: the export holds no clear name for a sealed row', async () => {
  const holder = key();
  const rec = await makeRecord(`E-${randomBytes(4).toString('hex')}`);
  await call('PUT', '/api/records', holder, [sealedFor(holder, rec)]);
  const ex = await call('GET', '/api/export', holder);
  assert.equal(ex.status, 200);
  assert.ok(!JSON.stringify(ex.json.records).includes(rec.strainName));
  assert.doesNotMatch(ex.json.note, /each record's public name/);
});

test('#28, round 6 (#37): the guarded purge reports clear names and removes none; only both flags remove them', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'veilcore-names-'));
  try {
    const file = join(dir, 'n.db');
    const f = new Database(file);
    for (const { sql } of db.prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name IN ('records', 'licenses', 'transfers', 'disclosure_grants')").all()) f.exec(sql);
    const box = { v: 1, alg: 'A256GCM', kid: '0'.repeat(16), iv: 'A'.repeat(16), ct: 'A'.repeat(24) };
    const moved = 'h1:moved', waiting = 'h1:waiting';
    const ins = f.prepare('INSERT INTO records (id, holder_key, body, updated_at, first_seen) VALUES (?,?,?,?,?)');
    // `moved`: their app seals names (one sealed row has none); one row it could not save again.
    ins.run('M-NEW', moved, JSON.stringify({ id: 'M-NEW', sealed: box }), 1, 1);
    ins.run('M-OLD', moved, JSON.stringify({ id: 'M-OLD', strainName: 'NAME-MOVED-OLD', sealed: box }), 1, 1);
    // A claim's stub from before round 5: kept unless both flags (the recipient may need it).
    ins.run('M-STUB', moved, JSON.stringify({ id: 'M-STUB', strainName: 'NAME-STUB', receivedFrom: 'X', transferId: 'TR-1', receivedAt: 1 }), 1, 1);
    // `waiting`: sealed, but every row still has its name in the clear: their app hasn't moved it.
    ins.run('W-1', waiting, JSON.stringify({ id: 'W-1', strainName: 'NAME-WAITING', sealed: box }), 1, 1);
    f.close();
    const purge = fileURLToPath(new URL('../scripts/purge-plaintext.mjs', import.meta.url));
    const run = (...flags) => execFileSync(process.execPath, [purge, '--db', file, ...flags], { encoding: 'utf8' });
    const dry = run();
    // A sealed row with a clear name was sealed before names went inside the lock: the clear
    // name is its only copy, so the guarded run reports it and removes none (round 6, #37).
    assert.match(dry, /record names in the clear: 2 on sealed rows locked before names went inside the lock \(reported, not removed[^)]*\), 1 on claims' stubs \(kept\)/);
    assert.doesNotMatch(dry, /or backup/);
    for (const n of ['NAME-MOVED-OLD', 'NAME-STUB', 'NAME-WAITING']) assert.ok(!dry.includes(n), 'never prints a name');
    run('--apply');
    let raw = new Database(file, { readonly: true });
    const body = (id) => JSON.parse(raw.prepare('SELECT body FROM records WHERE id = ?').get(id).body);
    assert.equal(body('M-OLD').strainName, 'NAME-MOVED-OLD', 'kept: its box has no name, so this is the only copy');
    assert.equal(body('M-STUB').strainName, 'NAME-STUB');
    assert.equal(body('W-1').strainName, 'NAME-WAITING', 'kept: removing it now would lose it');
    raw.close();
    const all = run('--apply', '--include-unconverted', '--i-understand-this-deletes-text');
    assert.match(all, /record names in the clear: 3 removed \(--include-unconverted\)/);
    assert.doesNotMatch(all, /or backup/);
    raw = new Database(file, { readonly: true });
    for (const id of ['M-OLD', 'M-STUB', 'W-1']) assert.equal(body(id).strainName, undefined, id);
    // The stub is still a stub: the recipient's app can still finish receiving it.
    assert.deepEqual(body('M-STUB'), { id: 'M-STUB', receivedFrom: 'X', transferId: 'TR-1', receivedAt: 1 });
    raw.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('persona review: "Bred by" is a fact the holder may share, off unless granted, and goes stale with the record', async () => {
  const holder = key();
  const rec = await makeRecord(`B-${randomBytes(4).toString('hex')}`, { bredBy: 'Hilltop Seeds' });
  await call('PUT', '/api/records', holder, [sealedFor(holder, rec)]);
  assert.ok((await call('GET', '/health')).json.features.includes('bred-by-grant-v1'));
  // Not granted: nothing about who bred it.
  await call('PUT', `/api/records/${rec.id}/disclosure`, holder, grantForTest(rec, ['existence']));
  assert.equal((await verify(rec.id)).bredBy, undefined);
  // A value without the grant is refused.
  const noKey = await call('PUT', `/api/records/${rec.id}/disclosure`, holder, { show: ['existence'], forFingerprint: rec.recordFingerprint, values: { bredBy: 'x' } });
  assert.equal(noKey.status, 400);
  assert.match(noKey.json.error, /values\.bredBy is accepted only with the bred-by grant/);
  const long = await call('PUT', `/api/records/${rec.id}/disclosure`, holder, { show: ['bred-by'], forFingerprint: rec.recordFingerprint, values: { bredBy: 'b'.repeat(501) } });
  assert.equal(long.status, 400);
  // Granted, last in order after the name.
  const g = await call('PUT', `/api/records/${rec.id}/disclosure`, holder, grantForTest(rec, ['existence', 'name', 'bred-by']));
  assert.equal(g.status, 200, JSON.stringify(g.json));
  assert.deepEqual(g.json.show, ['existence', 'name', 'bred-by']);
  let v = await verify(rec.id);
  assert.equal(v.bredBy, 'Hilltop Seeds');
  assert.deepEqual(v.disclosed, ['own', 'name', 'bredBy']);
  // A link that narrows it away gets nothing; the older spelling narrows to it.
  assert.equal((await verify(rec.id, '?show=own')).bredBy, undefined);
  assert.equal((await verify(rec.id, '?show=bredBy')).bredBy, 'Hilltop Seeds');
  // The record changes: the value described the old one and goes stale.
  const edited = await makeRecord(rec.id, { bredBy: 'Someone Else' });
  await call('PUT', '/api/records', holder, [sealedFor(holder, edited)]);
  v = await verify(rec.id);
  assert.equal(v.bredBy, undefined);
  assert.ok(v.staleGrant.includes('bredBy'));
});
