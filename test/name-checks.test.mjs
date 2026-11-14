// Round 4: a mark on a lab's key is a written name check, and says only that.
//
// The operator's mark used to be a bare flag and a free-text note, and the site and embed
// turned it into "VeilCore has checked". Now a mark needs the record of one procedure
// (site repo docs/lab-name-checks.md): the public listing it was found in, the lab's own
// email domain, the day and who. It expires after 12 months; taking it off records why;
// a mark made before this reads as "name not checked".
//
// SPDX-License-Identifier: Apache-2.0

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import Database from 'better-sqlite3';
import { generateKeypair, signAttestation } from 'veilcore-records';
import { createAttesters, registrationPayload, validateNameCheck, WITHDRAW_REASONS } from '../lineage/attesters.mjs';
import { renderEmbed } from '../lineage/embed.mjs';
import { untilReady } from './helpers.mjs';

process.env.DB_PATH = ':memory:';
process.env.VEILCORE_OPERATOR_TOKEN = 'test-operator-token-at-least-32-chars';
const require = createRequire(import.meta.url);
const { app } = require('../server.js');
const OP = { 'x-operator-token': process.env.VEILCORE_OPERATOR_TOKEN };

let base;
let server;
before(async () => {
  server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  base = `http://127.0.0.1:${server.address().port}`;
  await untilReady(base);
});
after(() => server.close());

const call = async (method, path, { body, headers = {} } = {}) => {
  const res = await fetch(`${base}${path}`, {
    method,
    headers: { 'content-type': 'application/json', ...headers },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  let json;
  try { json = JSON.parse(text); } catch { json = text; }
  return { status: res.status, json, text };
};

const registration = async (kp, fields) => {
  const reg = { publicKey: kp.publicKey, issuedAt: Date.now(), ...fields };
  const priv = await crypto.subtle.importKey('pkcs8', Buffer.from(kp.privateKey, 'hex'), { name: 'Ed25519' }, false, ['sign']);
  const sig = await crypto.subtle.sign('Ed25519', priv, new TextEncoder().encode(registrationPayload(reg)));
  return { ...reg, signature: Buffer.from(sig).toString('hex') };
};
const attestation = (kp, subjectCommitment, attestationId) =>
  signAttestation({
    type: 'veilcore/attestation/v1', attestationId, subjectCommitment,
    documentHash: 'a'.repeat(64), hashAlgorithm: 'sha256', issuedAt: new Date().toISOString(),
    attester: { publicKey: kp.publicKey },
  }, kp.privateKey);

const day = (ms) => new Date(ms).toISOString().slice(0, 10);
const goodCheck = (over = {}) => ({
  source: 'licence-listing',
  sourceUrl: 'https://agriculture.example.gov/licensed-testing-labs',
  licenceNo: 'TL-000123',
  emailDomain: 'acmelabs.example',
  checkedAt: day(Date.now()),
  checkedBy: 'AB',
  ...over,
});

// ---------------------------------------------------------------------------------------

test('a check record is refused without its source, the lab’s email domain or the day', () => {
  const now = Date.now();
  assert.ok(validateNameCheck(goodCheck(), now).check);
  for (const missing of ['sourceUrl', 'emailDomain', 'checkedAt', 'checkedBy', 'source']) {
    const c = goodCheck();
    delete c[missing];
    assert.match(validateNameCheck(c, now).error ?? '', new RegExp(missing), `${missing} is required`);
  }
  // Nothing personal: an address is not a domain, free mail is not the lab's own domain,
  // and no field outside the record rides along into the public answer.
  assert.match(validateNameCheck(goodCheck({ emailDomain: 'qa@acmelabs.example' }), now).error, /domain only/);
  assert.match(validateNameCheck(goodCheck({ emailDomain: 'gmail.com' }), now).error, /free mail/);
  assert.match(validateNameCheck({ ...goodCheck(), contactEmail: 'jane@acmelabs.example' }, now).error, /takes only/);
  assert.match(validateNameCheck(goodCheck({ sourceUrl: 'http://agriculture.example.gov/labs' }), now).error, /https/);
  assert.match(validateNameCheck(goodCheck({ sourceUrl: 'javascript:alert(1)' }), now).error, /https/);
  assert.match(validateNameCheck(goodCheck({ sourceUrl: 'https://u:p@agriculture.example.gov/' }), now).error, /user name/);
  assert.match(validateNameCheck(goodCheck({ checkedBy: 'hunter' }), now).error, /initials/);
  assert.match(validateNameCheck(goodCheck({ source: 'phone-call' }), now).error, /source/);
  assert.match(validateNameCheck(goodCheck({ licenceNo: 'x@y' }), now).error, /licenceNo/);
  // The day: not in the future, not already 12 months old.
  assert.match(validateNameCheck(goodCheck({ checkedAt: day(now + 3 * 86_400_000) }), now).error, /future/);
  assert.match(validateNameCheck(goodCheck({ checkedAt: '2025-01-01' }), Date.parse('2026-10-14')).error, /expired/);
  assert.match(validateNameCheck(goodCheck({ checkedAt: '2026-02-30' }), now).error, /YYYY-MM-DD/);
});

test('a check expires 12 months after the day it was done, or sooner if the operator says so', () => {
  const now = Date.parse('2026-10-14T12:00:00Z');
  const { check } = validateNameCheck(goodCheck({ checkedAt: '2026-10-14', emailDomain: 'AcmeLabs.Example' }), now);
  assert.equal(check.expiresAt, '2027-10-14');
  assert.equal(check.emailDomain, 'acmelabs.example');
  // A licence that runs out sooner: the mark ends with it.
  assert.equal(validateNameCheck(goodCheck({ checkedAt: '2026-10-14', expiresAt: '2027-03-31' }), now).check.expiresAt, '2027-03-31');
  assert.match(validateNameCheck(goodCheck({ checkedAt: '2026-10-14', expiresAt: '2027-10-15' }), now).error, /at most 12 months/);
  // 31 Jan + 12 months is 31 Jan; 29 Feb + 12 months is 28 Feb.
  assert.equal(validateNameCheck(goodCheck({ checkedAt: '2028-02-29' }), Date.parse('2028-03-01')).check.expiresAt, '2029-02-28');
});

test('routes: only the operator marks; a mark without a check record is refused; the public sees the record, not the note', async () => {
  const lab = await generateKeypair();
  assert.equal((await call('POST', '/attesters', { body: await registration(lab, { displayName: 'Acme Labs', role: 'laboratory' }) })).status, 200);
  const path = `/attesters/${lab.publicKey}/vetting`;

  assert.equal((await call('POST', path, { body: { vetted: true, check: goodCheck() } })).status, 401);
  // The old body, a bare flag and a note, is refused now.
  const bare = await call('POST', path, { headers: OP, body: { vetted: true, note: 'checked by phone' } });
  assert.equal(bare.status, 400);
  assert.match(bare.json.error, /check must be an object/);
  const noDomain = await call('POST', path, { headers: OP, body: { vetted: true, check: goodCheck({ emailDomain: undefined }) } });
  assert.equal(noDomain.status, 400);

  const note = 'code 7Q4K signed from qa@acmelabs.example; listing shows active';
  const ok = await call('POST', path, { headers: OP, body: { vetted: true, check: goodCheck(), note } });
  assert.equal(ok.status, 200, JSON.stringify(ok.json));
  assert.equal(ok.json.nameCheck.checkedName, 'Acme Labs');

  const pub = await call('GET', `/attesters/${lab.publicKey}`);
  assert.equal(pub.json.vetted, true);
  assert.equal(pub.json.nameCheckStatus, 'checked');
  assert.deepEqual(Object.keys(pub.json.nameCheck).sort(),
    ['checkedAt', 'checkedBy', 'checkedName', 'emailDomain', 'expiresAt', 'licenceNo', 'source', 'sourceUrl']);
  assert.doesNotMatch(pub.text, /qa@|7Q4K|vettedNote/, 'the private note is never public');

  // The attestation listing carries the record with the signer.
  const subject = 'c'.repeat(64);
  assert.equal((await call('POST', '/attestations', { body: await attestation(lab, subject, `nc-${Date.now()}`) })).status, 200);
  const listed = (await call('GET', `/attestations/subject/${subject}`)).json.attestations[0];
  assert.equal(listed.vettedAttester, true);
  assert.equal(listed.strength, 'signed-and-accredited');
  assert.equal(listed.registeredAs.nameCheck.sourceUrl, 'https://agriculture.example.gov/licensed-testing-labs');
  assert.equal(listed.registeredAs.nameCheckStatus, 'checked');

  // The operator can read the log back, notes and all.
  assert.equal((await call('GET', path)).status, 401);
  const logged = await call('GET', path, { headers: OP });
  assert.equal(logged.json.log[0].action, 'mark');
  assert.equal(logged.json.log[0].note, note);

  // Unmarking needs a reason, and the reason is public; the note is not.
  const noReason = await call('POST', path, { headers: OP, body: { vetted: false } });
  assert.equal(noReason.status, 400);
  assert.match(noReason.json.error, /reason/);
  const off = await call('POST', path, { headers: OP, body: { vetted: false, reason: 'licence-lapsed', note: 'listing shows expired 2026-10-01' } });
  assert.equal(off.status, 200);
  const after = (await call('GET', `/attesters/${lab.publicKey}`)).json;
  assert.equal(after.vetted, false);
  assert.equal(after.nameCheckStatus, 'withdrawn');
  assert.equal(after.withdrawn.reason, 'licence-lapsed');
  assert.equal(after.nameCheck, null);
  assert.equal((await call('GET', `/attestations/subject/${subject}`)).json.attestations[0].vettedAttester, false);
  assert.equal((await call('GET', path, { headers: OP })).json.log[0].reason, 'licence-lapsed');
});

test('a key taken off as compromised cannot be marked again; renaming drops the check', async () => {
  const lab = await generateKeypair();
  await call('POST', '/attesters', { body: await registration(lab, { displayName: 'Beta Labs' }) });
  const path = `/attesters/${lab.publicKey}/vetting`;
  assert.equal((await call('POST', path, { headers: OP, body: { vetted: true, check: goodCheck() } })).status, 200);

  // Renamed: the check was for the old name, so it goes.
  await new Promise((r) => setTimeout(r, 5));
  await call('POST', '/attesters', { body: await registration(lab, { displayName: 'Gamma Labs' }) });
  const renamed = (await call('GET', `/attesters/${lab.publicKey}`)).json;
  assert.equal(renamed.vetted, false);
  assert.equal(renamed.nameCheck, null);

  assert.equal((await call('POST', path, { headers: OP, body: { vetted: false, reason: 'key-compromised' } })).status, 200);
  const again = await call('POST', path, { headers: OP, body: { vetted: true, check: goodCheck() } });
  assert.equal(again.status, 400);
  assert.match(again.json.error, /compromised/);
  // Re-registering does not wash the withdrawal off.
  await new Promise((r) => setTimeout(r, 5));
  await call('POST', '/attesters', { body: await registration(lab, { displayName: 'Gamma Labs' }) });
  assert.equal((await call('GET', `/attesters/${lab.publicKey}`)).json.withdrawn.reason, 'key-compromised');
  assert.equal((await call('POST', path, { headers: OP, body: { vetted: true, check: goodCheck() } })).status, 400);
  assert.ok(WITHDRAW_REASONS.includes('expired'));
});

test('an expired mark, and a mark from before round 4 with no record, both read as not checked', async () => {
  const db = new Database(':memory:');
  let clock = Date.now();
  const reg = createAttesters(db, { now: () => clock });
  const lab = await generateKeypair();
  assert.ok((await reg.register(await registration(lab, { displayName: 'Delta Labs' }))).attesterId);
  assert.equal(reg.setVetted(lab.publicKey, { vetted: true, check: goodCheck() }).vetted, true);
  const subject = 'd'.repeat(64);
  assert.ok((await reg.submit(await attestation(lab, subject, 'exp-1'))).attestationId);
  assert.equal(reg.summaryFor(subject).vetted, true);
  assert.equal(reg.forSubject(subject)[0].vettedAttester, true);

  // A day past the expiry.
  clock = Date.parse(reg.lookup(lab.publicKey).nameCheck.expiresAt) + 86_400_000;
  const expired = reg.lookup(lab.publicKey);
  assert.equal(expired.vetted, false);
  assert.equal(expired.nameCheckStatus, 'expired');
  assert.equal(expired.nameCheck, null);
  assert.ok(expired.nameCheckExpiredOn);
  assert.equal(reg.summaryFor(subject).vetted, false);
  const row = reg.forSubject(subject)[0];
  assert.equal(row.vettedAttester, false);
  assert.equal(row.strength, 'signed');
  assert.equal(row.registeredAs.nameCheck, null);
  assert.equal(row.registeredAs.nameCheckStatus, 'expired');

  // A mark as it was stored before round 4: the flag and a note, no check record.
  clock = Date.now();
  const old = await generateKeypair();
  await reg.register(await registration(old, { displayName: 'Old Mark Labs' }));
  db.prepare('UPDATE attesters SET vetted = 1, vetted_at = ?, vetted_note = ? WHERE public_key = ?').run(clock, 'checked by phone', old.publicKey);
  assert.ok((await reg.submit(await attestation(old, 'e'.repeat(64), 'old-1'))).attestationId);
  const legacy = reg.lookup(old.publicKey);
  assert.equal(legacy.vetted, false);
  assert.equal(legacy.nameCheckStatus, 'not-checked');
  assert.equal(legacy.vettedNote, undefined);
  assert.equal(reg.summaryFor('e'.repeat(64)).vetted, false);
  assert.equal(reg.forSubject('e'.repeat(64))[0].vettedAttester, false);

  // The embed says "name not checked" for both, and never "VeilCore has checked".
  const html = renderEmbed({ found: true, id: 'X', cultivar: 'c', recordFingerprint: 'e'.repeat(64),
    attestations: reg.forSubject('e'.repeat(64)) }, 'https://r.example');
  assert.match(html, /a key named “Old Mark Labs” \(name not checked\)/);
  assert.doesNotMatch(html, /has checked|verified by VeilCore/);
});

test('an older database gains the columns on start, and its old marks read as not checked', async () => {
  const db = new Database(':memory:');
  db.exec(`CREATE TABLE attesters (public_key TEXT PRIMARY KEY, attester_id TEXT NOT NULL, display_name TEXT, role TEXT,
    accreditation TEXT, registered_at INTEGER NOT NULL, vetted INTEGER NOT NULL DEFAULT 0, vetted_at INTEGER, vetted_note TEXT)`);
  db.prepare('INSERT INTO attesters VALUES (?,?,?,?,?,?,?,?,?)').run('f'.repeat(64), 'att-old', 'Old Lab', 'laboratory', null, 1, 1, 1, 'phone');
  const reg = createAttesters(db);
  const cols = db.prepare('PRAGMA table_info(attesters)').all().map((c) => c.name);
  for (const c of ['name_check', 'name_check_expires_at', 'unvetted_at', 'unvetted_reason']) assert.ok(cols.includes(c), c);
  assert.equal(reg.lookup('f'.repeat(64)).nameCheckStatus, 'not-checked');
  // And it can be checked properly now.
  assert.equal(reg.setVetted('f'.repeat(64), { vetted: true, check: goodCheck() }).vetted, true);
  assert.equal(reg.lookup('f'.repeat(64)).nameCheckStatus, 'checked');
  createAttesters(db); // safe to run again
});

test('the embed states what was checked, where and when, and that VeilCore doesn’t vouch', () => {
  const check = { ...validateNameCheck(goodCheck({ checkedAt: '2026-10-14' }), Date.parse('2026-10-14T12:00:00Z')).check, checkedName: 'Acme Labs' };
  const signer = (nameCheck) => ({ strength: 'signed-and-accredited', vettedAttester: true, retraction: null, registeredAs: { displayName: 'Acme Labs', nameCheck } });
  const html = renderEmbed({ found: true, id: 'X', cultivar: 'c', recordFingerprint: 'a'.repeat(64), attestations: [signer(check)] }, 'https://r.example');
  assert.match(html, /Signed by Acme Labs\. VeilCore’s operator matched this name to agriculture\.example\.gov \(license TL-000123\) on 2026-10-14\. VeilCore doesn’t vouch for the lab’s work\./);
  // A "vetted" flag with no record behind it is not described as matched.
  const bare = renderEmbed({ found: true, id: 'X', cultivar: 'c', recordFingerprint: 'a'.repeat(64), attestations: [signer(null)] }, 'https://r.example');
  assert.match(bare, /a key named “Acme Labs” \(name not checked\)/);
  assert.doesNotMatch(bare, /matched this name/);
});
