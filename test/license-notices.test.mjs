// License notices (README "License notices"): a record's holder says publicly that a royalty
// statement on a license from it is overdue, that they sent a notice of breach, or that the
// license was revoked for non-payment; the licensee answers in their own name. The registry is the
// clock and the gate: it dates the notice of breach itself, files one only for a statement the
// licensee registered and only after the due date they registered, refuses "revoked for
// non-payment" until the cure period has run out by its own clock with nothing paid on file, and
// keeps the licensee's signed answer where the licensor can't remove or change it. Every line is
// signed with the deal's licensor key, so only that licensor can say anything about its
// statements, on one record. No network.
//
// Includes the round-2 verifier's probes (vrp2-int notices.int / premature.int) and the round-3
// verifier's (vrp3-probe P1, P1b, P2, P7; M2, M3, L1, L2, L4, L5, L6) that apply to the registry,
// the round-4 findings N1 and N3 (vrp4-probe R4-7), and round 5's R5-5.
//
// SPDX-License-Identifier: Apache-2.0

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { createServer } from 'node:net';
import { networkInterfaces } from 'node:os';
import { fileURLToPath } from 'node:url';
import { canonicalise, sha256Hex, newNonce } from 'veilcore-records';
import { untilReady, testBody, plain, waitFor } from './helpers.mjs';
import { dealTokenHash } from '../lineage/deals.mjs';
import { commitHashOf, inviteTokenHash } from '../lineage/license-invites.mjs';

process.env.DB_PATH = ':memory:';
process.env.VEILCORE_OTS = 'off';
const require = createRequire(import.meta.url);
const { app, db } = require('../server.js');

const DAY = 86_400_000;
const key = () => randomBytes(32).toString('hex');
const hex32 = () => randomBytes(32).toString('hex');
let base, server;
before(async () => {
  server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  base = `http://127.0.0.1:${server.address().port}`;
  await untilReady(base);
});
after(() => server.close());

/** Run `fn` with the registry's clock (Date.now, in this process) at `ms`. */
const at = async (ms, fn) => {
  const real = Date.now;
  Date.now = () => ms;
  try {
    return await fn();
  } finally {
    Date.now = real;
  }
};
const noon = (day) => Date.parse(`${day}T12:00:00Z`);
const today = () => new Date().toISOString().slice(0, 10);
const plusDays = (day, n) => new Date(Date.parse(`${day}T00:00:00Z`) + n * DAY).toISOString().slice(0, 10);

const call = async (method, path, holder, body) => {
  const res = await fetch(`${base}${path}`, {
    method,
    headers: { 'content-type': 'application/json', 'x-forwarded-for': `10.${randomBytes(3).join('.')}`, ...(holder ? { 'x-holder-key': holder } : {}) },
    ...(body === undefined ? {} : { body: JSON.stringify(testBody(method, path, holder, body)) }),
  });
  const text = await res.text();
  let json; try { json = JSON.parse(text); } catch { json = text; }
  return { status: res.status, json };
};

/** A sealed record saved under `holder`; its id. */
const saveRecord = async (holder, id = `LN-${randomBytes(4).toString('hex')}`) => {
  const committed = { breedingMethod: '', bredBy: 'B', dateCreated: '2026-01-01', loggedAt: 1760000000000,
    nonce: newNonce(), notes: '', parents: [], photoFingerprints: [], refId: '', strainName: 'Notice Plant' };
  const recordFingerprint = await sha256Hex(canonicalise(committed));
  const r = await call('PUT', '/api/records', holder, [{ id, ...committed, recordFingerprint }]);
  assert.equal(r.status, 200, JSON.stringify(r.json));
  return id;
};
const verify = async (id) => (await call('GET', `/verify/${id}`)).json;

/** An Ed25519 key: its raw public half as hex, and a signer. */
const edKey = () => {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const pub = Buffer.from(publicKey.export({ format: 'jwk' }).x, 'base64url').toString('hex');
  return { pub, sign: (bytes) => sign(null, bytes, privateKey).toString('hex') };
};

/**
 * A license's deal, opened the way the site opens it (an invite taken to the reveal, with the two
 * sides' deal keys as its nonces), and `n` messages in it: their fingerprints stand for the
 * licensee's statements.
 */
const deal = async (n = 1) => {
  const licensee = edKey();
  const issuer = edKey();
  const accept = randomBytes(16).toString('base64url');
  const issuerToken = randomBytes(16).toString('base64url');
  const inv = await call('POST', '/license-invites', undefined, {
    identity: hex32(), label: 'x', acceptTokenHash: inviteTokenHash(accept), issuerTokenHash: inviteTokenHash(issuerToken),
  });
  const id = inv.json.id;
  const c = { commitment: hex32(), issuerRecord: hex32(), licenseeNonce: licensee.pub };
  await call('POST', `/license-invites/${id}/accept`, undefined, { commitHash: commitHashOf(c.commitment, c.issuerRecord, c.licenseeNonce), token: accept });
  await call('POST', `/license-invites/${id}/nonce`, undefined, { issuerNonce: issuer.pub, token: issuerToken });
  await call('POST', `/license-invites/${id}/reveal`, undefined, { ...c, token: accept });
  const token = randomBytes(16).toString('base64url');
  const dealId = randomBytes(16).toString('hex');
  const o = await call('POST', '/deals', undefined, { dealId, writeTokenHash: dealTokenHash(token), inviteId: id, token: issuerToken });
  assert.equal(o.status, 200, JSON.stringify(o.json));
  const statements = [];
  for (let i = 0; i < n; i++) {
    const m = await call('POST', `/deals/${dealId}/messages`, undefined, { token, iv: randomBytes(12).toString('base64url'), ct: randomBytes(120).toString('base64url') });
    statements.push(m.json.fingerprint);
  }
  return { licensee, issuer, statements, statement: statements[0], dealId };
};
const refOf = (statement) => createHash('sha256').update(`veilcore/license-notice/v2\n${statement}`, 'utf8').digest('hex').slice(0, 32);

/** The licensor's signature on a line, as the site's license-notices.ts lineSignature makes it. */
const lineSig = (signer, recordId, line) =>
  signer.sign(Buffer.from(`veilcore/license-line/v1\n${canonicalise({ ...line, recordId })}`, 'utf8'));
/** A line put up by the record's holder, signed with the deal's licensor key (or `signer`). */
const put = (id, holder, line, d, signer = d.issuer) =>
  call('PUT', `/api/records/${id}/license-notices/${refOf(line.statement)}`, holder, { ...line, signature: lineSig(signer, id, line) });

/** The licensee's signed word, as the site's license-notices.ts fileAnswer and registerStatement make it. */
const signed = (signer, answer) => ({ answer, signature: signer.sign(Buffer.from(`veilcore/license-answer/v1\n${canonicalise(answer)}`, 'utf8')) });
const answerBody = (signer, statement, type, reference = 'HR-7Q4K') => signed(signer, {
  v: 'veilcore/license-answer/v1',
  statement,
  type,
  ...(type === 'paid' ? { referenceHash: createHash('sha256').update(reference, 'utf8').digest('hex') } : {}),
});
const answer = (signer, statement, type, reference) => call('POST', '/license-answers', undefined, answerBody(signer, statement, type, reference));
/** The licensee registers a statement as theirs, with its payment's due date. */
const register = (d, statement, dueOn, signer = d.licensee) =>
  call('POST', '/license-answers', undefined, signed(signer, { v: 'veilcore/license-answer/v1', statement, type: 'statement', dueOn }));

test('/health lists license-notices-v1, -v2 and -v3, for the site’s deploy preflights', async () => {
  const h = (await call('GET', '/health')).json;
  for (const f of ['license-notices-v1', 'license-notices-v2', 'license-notices-v3']) assert.ok(h.features.includes(f), JSON.stringify(h));
});

test('an overdue line, signed by the deal’s licensor; anyone reads it, as the holder’s word, dated to the day', async () => {
  const holder = key();
  const id = await saveRecord(holder);
  const d = await deal(2);
  assert.equal((await verify(id)).licenseNotices, undefined, 'none: the field is absent');
  const since = plusDays(today(), -5);
  const r = await put(id, holder, { kind: 'overdue', since, statement: d.statement }, d);
  assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.ok(Math.abs(r.json.now - Date.now()) < 60_000, 'the answer carries the registry’s time');
  const v = await verify(id);
  assert.equal(v.licenseNoticesBy, 'record-holder');
  assert.equal(v.licenseAnswersBy, 'licensee');
  assert.deepEqual(v.licenseNotices, [{ ref: refOf(d.statement), kind: 'overdue', since, updatedAt: today() }], 'L2: the last change as a UTC day, no finer');
  assert.ok(!JSON.stringify(v).includes(d.statement), 'the statement’s fingerprint is never public');
  // Put again: replaced, not doubled. Taken off.
  await put(id, holder, { kind: 'overdue', since: plusDays(since, 1), statement: d.statement }, d);
  assert.deepEqual((await verify(id)).licenseNotices.map((n) => n.since), [plusDays(since, 1)]);
  assert.equal((await call('DELETE', `/api/records/${id}/license-notices/${refOf(d.statement)}`, holder)).status, 200);
  assert.equal((await verify(id)).licenseNotices, undefined);
  assert.equal((await call('DELETE', `/api/records/${id}/license-notices/${refOf(d.statement)}`, holder)).status, 404);
  // The holder's own view, with the registry's time.
  const own = await call('GET', `/api/records/${id}/license-notices`, holder);
  assert.equal(own.status, 200);
  assert.deepEqual(own.json.licenseNotices, []);
  assert.equal(own.json.cureDays, 30);
  assert.equal(typeof own.json.now, 'number');
});

test('nothing but a kind, a date, the statement and the licensor’s signature: amounts, names, text, other reasons and the unsigned v2 shape are refused', async () => {
  const holder = key();
  const id = await saveRecord(holder);
  const d = await deal();
  const s = d.statement;
  const since = plusDays(today(), -5);
  const sig = lineSig(d.issuer, id, { kind: 'overdue', since, statement: s });
  for (const body of [
    { kind: 'overdue', since },
    { kind: 'revoked', reason: 'non-payment', on: since },
    { kind: 'overdue', since, statement: s }, // the unsigned v2 shape
    { kind: 'overdue', since, statement: s, signature: 'zz' },
    { kind: 'overdue', since, statement: s, signature: sig, amount: '1000.00' },
    { kind: 'overdue', since, statement: s, signature: sig, licensee: 'Bo Grower' },
    { kind: 'overdue', since, statement: s, signature: sig, disputed: since },
    { kind: 'overdue', since: '15 May 2026', statement: s, signature: sig },
    { kind: 'overdue', since: '2026-02-30', statement: s, signature: sig },
    { kind: 'overdue', since: plusDays(today(), 1), statement: s, signature: sig },
    { kind: 'breach', since: plusDays(today(), 1), statement: s, signature: sig },
    { kind: 'revoked', reason: 'they were rude', on: since, statement: s, signature: sig },
    { kind: 'revoked', on: since, statement: s, signature: sig },
    { kind: 'overdue', since, statement: 'NOT-HEX', signature: sig },
    ['overdue'],
    'overdue',
  ]) {
    const r = await call('PUT', `/api/records/${id}/license-notices/${refOf(s)}`, holder, plain(body));
    assert.equal(r.status, 400, JSON.stringify(body));
  }
  // A ref that isn't the statement's; a statement no deal here holds.
  assert.equal((await call('PUT', `/api/records/${id}/license-notices/${refOf(hex32())}`, holder, { kind: 'overdue', since, statement: s, signature: sig })).status, 400);
  const r = await put(id, holder, { kind: 'overdue', since, statement: hex32() }, d);
  assert.equal(r.status, 409);
  assert.equal(r.json.code, 'no-deal');
  assert.equal((await verify(id)).licenseNotices, undefined);
});

test('L1 / P2: only the deal’s licensor can put a line up, on one record; a stranger who learned the fingerprint can’t', async () => {
  const licensor = key();
  const rec = await saveRecord(licensor);
  const other = await saveRecord(licensor);
  const d = await deal();
  const s = d.statement;
  const since = plusDays(today(), -5);
  // A stranger with the fingerprint, on their own record: their own key, the licensee's, or a
  // signature the licensor made for another record (a replay) are all refused.
  const strangerKey = key();
  const recS = await saveRecord(strangerKey);
  for (const signer of [edKey(), d.licensee]) {
    const r = await put(recS, strangerKey, { kind: 'overdue', since, statement: s }, d, signer);
    assert.equal(r.status, 403, JSON.stringify(r.json));
    assert.equal(r.json.code, 'not-licensor');
  }
  const replay = await call('PUT', `/api/records/${recS}/license-notices/${refOf(s)}`, strangerKey,
    { kind: 'overdue', since, statement: s, signature: lineSig(d.issuer, rec, { kind: 'overdue', since, statement: s }) });
  assert.equal(replay.status, 403, 'a licensor’s signature is for one record');
  // The licensor's line goes up on their record; the same statement on another record is refused.
  assert.equal((await put(rec, licensor, { kind: 'overdue', since, statement: s }, d)).status, 200);
  const elsewhere = await put(other, licensor, { kind: 'overdue', since, statement: s }, d);
  assert.equal(elsewhere.status, 409);
  assert.equal(elsewhere.json.code, 'other-record');
  // What the licensee's page reads: the one line, on the deal's record.
  const g = await call('GET', `/license-answers/${s}`);
  assert.deepEqual(g.json.lines.map((l) => [l.kind, l.since]), [['overdue', since]]);
  assert.equal((await verify(recS)).licenseNotices, undefined);
  assert.equal((await verify(other)).licenseNotices, undefined);
  // Taken off the first record, it can go on the other (one at a time).
  await call('DELETE', `/api/records/${rec}/license-notices/${refOf(s)}`, licensor);
  assert.equal((await put(other, licensor, { kind: 'overdue', since, statement: s }, d)).status, 200);
});

test('B2: a notice of breach only for a statement the licensee registered, and only after the due date they registered', async () => {
  const holder = key();
  const id = await saveRecord(holder);
  const d = await deal(2);
  const [s, payout] = d.statements;
  const t0 = noon('2026-05-20');
  // Not registered: refused, and the line stays a plain overdue claim.
  let r = await at(t0, () => put(id, holder, { kind: 'breach', since: '2026-05-15', statement: s }, d));
  assert.deepEqual([r.status, r.json.code], [409, 'not-registered']);
  // The licensor can't register for the licensee; a stranger can't either.
  assert.equal((await register(d, s, '2026-05-14', d.issuer)).status, 403);
  assert.equal((await register(d, s, '2026-05-14', edKey())).status, 403);
  for (const dueOn of ['2026-02-30', '14 May 2026', '']) {
    assert.equal((await register(d, s, dueOn)).status, 400, dueOn);
  }
  // Registered as due on 14 May. Again, with another date: the first stands.
  const reg = await at(t0 - 10 * DAY, () => register(d, s, '2026-05-14'));
  assert.deepEqual([reg.status, reg.json.filed, reg.json.dueOn, reg.json.on], [200, true, '2026-05-14', '2026-05-10']);
  const again = await register(d, s, '2026-12-31');
  assert.deepEqual([again.json.filed, again.json.dueOn], [false, '2026-05-14']);
  // On the due date itself, by the registry's clock, or with an overdue date not after it: refused.
  r = await at(noon('2026-05-14'), () => put(id, holder, { kind: 'breach', since: '2026-05-14', statement: s }, d));
  assert.deepEqual([r.status, r.json.code, r.json.dueOn], [409, 'not-due', '2026-05-14']);
  r = await at(t0, () => put(id, holder, { kind: 'breach', since: '2026-05-14', statement: s }, d));
  assert.deepEqual([r.status, r.json.code], [409, 'not-due']);
  // The day after: filed, dated by the registry.
  r = await at(t0, () => put(id, holder, { kind: 'breach', since: '2026-05-15', statement: s }, d));
  assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.equal(r.json.breachNoticeOn, '2026-05-20');
  // A registration is never public; both sides read it by the statement.
  assert.ok(!JSON.stringify(await verify(id)).includes('2026-05-14'));
  assert.deepEqual((await call('GET', `/license-answers/${s}`)).json.registered, { dueOn: '2026-05-14', on: '2026-05-10' });
  // The licensor's own message (a payout, say) was never registered: no notice of breach for it.
  r = await at(t0, () => put(id, holder, { kind: 'breach', since: '2026-05-15', statement: payout }, d));
  assert.deepEqual([r.status, r.json.code], [409, 'not-registered']);
});

test('B2 / vrp3 P1: a licensor’s own deal message never reaches "revoked for non-payment"', async () => {
  const holder = key(); const id = await saveRecord(holder);
  const d = await deal(3);
  const fp = d.statements[2]; // the licensor's own payout message, not a statement
  const T0 = noon(today());
  const b = await at(T0, () => put(id, holder, { kind: 'breach', since: today(), statement: fp }, d));
  assert.deepEqual([b.status, b.json.code], [409, 'not-registered']);
  const r = await at(T0 + 31 * DAY, () => put(id, holder, { kind: 'revoked', reason: 'non-payment', on: plusDays(today(), 31), statement: fp }, d));
  assert.deepEqual([r.status, r.json.code], [409, 'no-breach']);
  assert.equal((await at(T0 + 31 * DAY, () => verify(id))).licenseNotices, undefined);
});

test('B2 / vrp3 P1b: a notice of breach sent the day the statement arrives, before anything is due, starts nothing', async () => {
  const holder = key(); const id = await saveRecord(holder);
  const d = await deal(1);
  const T0 = noon(today());
  // The licensee's page registers the statement as it is sent: payment due in 30 days.
  assert.equal((await at(T0, () => register(d, d.statement, plusDays(today(), 30)))).status, 200);
  const b = await at(T0, () => put(id, holder, { kind: 'breach', since: today(), statement: d.statement }, d));
  assert.deepEqual([b.status, b.json.code], [409, 'not-due']);
  const r = await at(T0 + 31 * DAY, () => put(id, holder, { kind: 'revoked', reason: 'non-payment', on: plusDays(today(), 31), statement: d.statement }, d));
  assert.deepEqual([r.status, r.json.code], [409, 'no-breach']);
  // Filed on day 31 (the day after the due date), it is revocable only 30 full days later.
  const late = await at(T0 + 31 * DAY, () => put(id, holder, { kind: 'breach', since: plusDays(today(), 31), statement: d.statement }, d));
  assert.equal(late.status, 200);
  const early = await at(T0 + 61 * DAY, () => put(id, holder, { kind: 'revoked', reason: 'non-payment', on: plusDays(today(), 61), statement: d.statement }, d));
  assert.deepEqual([early.status, early.json.code], [409, 'cure-not-over']);
  const ok = await at(T0 + 62 * DAY, () => put(id, holder, { kind: 'revoked', reason: 'non-payment', on: plusDays(today(), 62), statement: d.statement }, d));
  assert.equal(ok.status, 200, JSON.stringify(ok.json));
});

test('the notice of breach is dated by the registry when it first arrives; a resend or a later device does not move it', async () => {
  const holder = key();
  const id = await saveRecord(holder);
  const d = await deal();
  await register(d, d.statement, '2026-05-14');
  const t0 = noon('2026-05-20');
  await at(t0, () => put(id, holder, { kind: 'overdue', since: '2026-05-15', statement: d.statement }, d));
  const b = await at(t0, () => put(id, holder, { kind: 'breach', since: '2026-05-15', statement: d.statement }, d));
  assert.equal(b.status, 200, JSON.stringify(b.json));
  assert.equal(b.json.breachNoticeOn, '2026-05-20');
  assert.equal(b.json.kind, 'overdue', 'shown as the overdue line, with the notice of breach beside it');
  // Sent again ten days later (another device, a resend): still the first day.
  await at(t0 + 10 * DAY, () => put(id, holder, { kind: 'breach', since: '2026-05-15', statement: d.statement }, d));
  // Put back as plain overdue: the notice of breach on file stays.
  await at(t0 + 11 * DAY, () => put(id, holder, { kind: 'overdue', since: '2026-05-15', statement: d.statement }, d));
  const v = await at(t0 + 11 * DAY, () => verify(id));
  assert.deepEqual(v.licenseNotices.map(({ updatedAt, ...n }) => n), [
    { ref: refOf(d.statement), kind: 'overdue', since: '2026-05-15', breachNoticeOn: '2026-05-20' },
  ]);
  // The resends changed nothing, so the line's last change is still the day the notice arrived.
  assert.equal(v.licenseNotices[0].updatedAt, '2026-05-20');
});

test('revoked for non-payment: refused with no notice of breach, during the cure period, and on its last day; accepted after', async () => {
  const holder = key();
  const id = await saveRecord(holder);
  const d = await deal();
  const s = d.statement;
  await register(d, s, '2026-05-14');
  const t0 = noon('2026-05-20');
  // Probe: a revoked line with no notice of breach at all.
  let r = await at(t0, () => put(id, holder, { kind: 'revoked', reason: 'non-payment', on: '2026-05-20', statement: s }, d));
  assert.equal(r.status, 409);
  assert.equal(r.json.code, 'no-breach');
  await at(t0, () => put(id, holder, { kind: 'breach', since: '2026-05-15', statement: s }, d));
  // Probe: five days into the cure period, and a device clock 31 days ahead changes nothing here.
  r = await at(t0 + 5 * DAY, () => put(id, holder, { kind: 'revoked', reason: 'non-payment', on: '2026-06-21', statement: s }, d));
  assert.equal(r.status, 400, 'a date after the registry’s today is refused');
  r = await at(t0 + 5 * DAY, () => put(id, holder, { kind: 'revoked', reason: 'non-payment', on: '2026-05-25', statement: s }, d));
  assert.equal(r.status, 409);
  assert.equal(r.json.code, 'cure-not-over');
  assert.equal(r.json.revocableFrom, '2026-06-20');
  // The last day to pay (20 May + 30 = 19 June), at one second before midnight UTC: still refused.
  r = await at(Date.parse('2026-06-19T23:59:59Z'), () => put(id, holder, { kind: 'revoked', reason: 'non-payment', on: '2026-06-19', statement: s }, d));
  assert.equal(r.status, 409);
  // The day after: a date before then is still refused; that day is accepted.
  const t1 = Date.parse('2026-06-20T00:00:01Z');
  r = await at(t1, () => put(id, holder, { kind: 'revoked', reason: 'non-payment', on: '2026-06-19', statement: s }, d));
  assert.equal(r.status, 409, 'a revocation dated inside the cure period');
  r = await at(t1, () => put(id, holder, { kind: 'revoked', reason: 'non-payment', on: '2026-06-20', statement: s }, d));
  assert.equal(r.status, 200, JSON.stringify(r.json));
  // Probe: resent a week later with another date: the first one stands. An overdue PUT can't undo it.
  await at(t1 + 7 * DAY, () => put(id, holder, { kind: 'revoked', reason: 'non-payment', on: '2026-06-27', statement: s }, d));
  await at(t1 + 8 * DAY, () => put(id, holder, { kind: 'overdue', since: '2026-05-15', statement: s }, d));
  const v = await at(t1 + 8 * DAY, () => verify(id));
  assert.deepEqual(v.licenseNotices.map(({ updatedAt, ...n }) => n), [
    { ref: refOf(s), kind: 'revoked', reason: 'non-payment', on: '2026-06-20', breachNoticeOn: '2026-05-20' },
  ]);
});

test('"paid" on file stops "revoked for non-payment": the licensee’s own answer, filed before or during the cure period', async () => {
  const holder = key();
  const id = await saveRecord(holder);
  const d = await deal(2);
  const t0 = noon('2026-05-20');
  for (const s of d.statements) {
    await register(d, s, '2026-05-14');
    await at(t0, () => put(id, holder, { kind: 'breach', since: '2026-05-15', statement: s }, d));
  }
  // Probe: the licensee paid ("I paid") during the cure period.
  assert.equal((await at(t0 + 3 * DAY, () => answer(d.licensee, d.statements[0], 'paid'))).status, 200);
  const r = await at(t0 + 40 * DAY, () => put(id, holder, { kind: 'revoked', reason: 'non-payment', on: '2026-06-29', statement: d.statements[0] }, d));
  assert.equal(r.status, 409);
  assert.equal(r.json.code, 'paid');
  // A dispute doesn't stop it: a court, not the registry, decides who is right.
  await at(t0 + 4 * DAY, () => answer(d.licensee, d.statements[1], 'disputed'));
  const ok = await at(t0 + 40 * DAY, () => put(id, holder, { kind: 'revoked', reason: 'non-payment', on: '2026-06-29', statement: d.statements[1] }, d));
  assert.equal(ok.status, 200);
  const v = await at(t0 + 40 * DAY, () => verify(id));
  const by = Object.fromEntries(v.licenseNotices.map((n) => [n.ref, n]));
  assert.deepEqual(by[refOf(d.statements[0])].answers, [{ type: 'paid', on: '2026-05-23' }], 'the registration is never among the public answers');
  assert.equal(by[refOf(d.statements[0])].kind, 'overdue');
  assert.deepEqual(by[refOf(d.statements[1])].answers, [{ type: 'disputed', on: '2026-05-24' }]);
  assert.equal(by[refOf(d.statements[1])].kind, 'revoked');
});

test('L5: "paid" with an empty payment reference is refused; any other reference stops the revoked line for good', async () => {
  const holder = key(); const id = await saveRecord(holder);
  const d = await deal(1);
  const empty = await answer(d.licensee, d.statement, 'paid', '');
  assert.equal(empty.status, 400, JSON.stringify(empty.json));
  assert.match(empty.json.error, /empty/);
  assert.equal((await answer(d.licensee, d.statement, 'paid', ' ')).status, 200, 'the registry sees only a hash: any other reference counts');
  await register(d, d.statement, '2026-05-14');
  await at(noon('2026-05-20'), () => put(id, holder, { kind: 'breach', since: '2026-05-15', statement: d.statement }, d));
  const r = await at(noon('2026-09-01'), () => put(id, holder, { kind: 'revoked', reason: 'non-payment', on: '2026-09-01', statement: d.statement }, d));
  assert.deepEqual([r.status, r.json.code], [409, 'paid']);
});

test('the licensee’s answer: only their deal key signs it, exactly { answer, signature }, the first of each type stands, and the licensor can’t remove it', async () => {
  const holder = key();
  const id = await saveRecord(holder);
  const d = await deal(2);
  const s = d.statement;
  const t0 = noon('2026-05-20');
  await at(t0, () => put(id, holder, { kind: 'overdue', since: '2026-05-15', statement: s }, d));
  // The licensor's deal key, a stranger's, a changed answer, a replay onto another statement: refused.
  assert.equal((await answer(d.issuer, s, 'disputed')).status, 403);
  assert.equal((await answer(edKey(), s, 'disputed')).status, 403);
  const forged = answerBody(d.licensee, s, 'disputed');
  assert.equal((await call('POST', '/license-answers', undefined, { ...forged, answer: { ...forged.answer, type: 'paid', referenceHash: hex32() } })).status, 403);
  assert.equal((await call('POST', '/license-answers', undefined, { ...forged, answer: { ...forged.answer, statement: d.statements[1] } })).status, 403);
  // L6: anything else beside the answer and its signature is refused, not ignored.
  for (const extra of [{ note: 'top-level text' }, { licensee: 'Bo Grower' }]) {
    const r = await call('POST', '/license-answers', undefined, { ...forged, ...extra });
    assert.equal(r.status, 400, JSON.stringify(extra));
  }
  assert.equal((await call('POST', '/license-answers', undefined, { answer: forged.answer })).status, 400);
  // Never free text, never the reference itself; a statement no deal here holds.
  for (const a of [
    { ...answerBody(d.licensee, s, 'disputed').answer, note: 'he never paid me' },
    { v: 'veilcore/license-answer/v1', statement: s, type: 'paid', reference: 'HR-7Q4K' },
    { v: 'veilcore/license-answer/v1', statement: s, type: 'withdrawn' },
    { v: 'veilcore/license-answer/v1', statement: s, type: 'statement' },
    { v: 'veilcore/license-answer/v1', statement: s, type: 'disputed', dueOn: '2026-05-14' },
  ]) {
    assert.equal((await call('POST', '/license-answers', undefined, signed(d.licensee, a))).status, 400, JSON.stringify(a));
  }
  const nowhere = await answer(d.licensee, hex32(), 'disputed');
  assert.deepEqual([nowhere.status, nowhere.json.code], [404, 'no-deal']);
  // Filed; again later (another device): the first date stands. Probe: the public dispute date.
  const a1 = await at(t0 + 1 * DAY, () => answer(d.licensee, s, 'disputed'));
  assert.deepEqual([a1.status, a1.json.filed, a1.json.on], [200, true, '2026-05-21']);
  const a2 = await at(t0 + 20 * DAY, () => answer(d.licensee, s, 'disputed'));
  assert.deepEqual([a2.json.filed, a2.json.on], [false, '2026-05-21']);
  // Beside the line, as the licensee's: type and date only.
  let v = await verify(id);
  assert.deepEqual(v.licenseNotices[0].answers, [{ type: 'disputed', on: '2026-05-21' }]);
  assert.ok(!JSON.stringify(v).includes('HR-7Q4K'));
  // Probe: the licensor "drops the dispute" by putting the line again, or taking it off and
  // putting it back: the answer is still beside it.
  await put(id, holder, { kind: 'overdue', since: '2026-05-15', statement: s }, d);
  await call('DELETE', `/api/records/${id}/license-notices/${refOf(s)}`, holder);
  await put(id, holder, { kind: 'overdue', since: '2026-05-15', statement: s }, d);
  v = await verify(id);
  assert.deepEqual(v.licenseNotices[0].answers, [{ type: 'disputed', on: '2026-05-21' }]);
  // Both sides' pages read what is on file by the statement, with the registry's time.
  const g = await call('GET', `/license-answers/${s}`);
  assert.equal(g.status, 200);
  assert.deepEqual(g.json.answers, [{ type: 'disputed', on: '2026-05-21' }]);
  assert.deepEqual(g.json.lines.map((l) => [l.kind, l.since]), [['overdue', '2026-05-15']]);
  assert.ok(!JSON.stringify(g.json).includes(id), 'the record isn’t named');
  assert.equal(typeof g.json.now, 'number');
  assert.deepEqual((await call('GET', `/license-answers/${hex32()}`)).json.answers, []);
});

test('POST /license-answers/lookup: a deal’s statements at once, in the order asked; bad lists refused', async () => {
  const holder = key(); const id = await saveRecord(holder);
  const d = await deal(3);
  await register(d, d.statements[0], '2026-05-14');
  await at(noon('2026-05-20'), () => put(id, holder, { kind: 'breach', since: '2026-05-15', statement: d.statements[0] }, d));
  await answer(d.licensee, d.statements[1], 'disputed');
  const unknown = hex32();
  const r = await call('POST', '/license-answers/lookup', undefined, { statements: [...d.statements, unknown] });
  assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.deepEqual(r.json.results.map((x) => x.statement), [...d.statements, unknown]);
  assert.deepEqual(r.json.results[0].registered, { dueOn: '2026-05-14', on: today() });
  assert.deepEqual(r.json.results[0].lines.map((l) => [l.kind, l.breachNoticeOn]), [['overdue', '2026-05-20']]);
  assert.deepEqual(r.json.results[1].answers.map((a) => a.type), ['disputed']);
  assert.deepEqual(r.json.results[3], { statement: unknown, answers: [], lines: [] });
  assert.equal(r.json.cureDays, 30);
  assert.ok(!JSON.stringify(r.json).includes(id), 'the record isn’t named');
  for (const body of [
    {}, { statements: [] }, { statements: ['NOT'] }, { statements: [unknown, unknown] },
    { statements: Array.from({ length: 101 }, hex32) }, { statements: [unknown], extra: 1 }, [unknown],
  ]) {
    assert.equal((await call('POST', '/license-answers/lookup', undefined, plain(body))).status, 400, JSON.stringify(body).slice(0, 80));
  }
});

test('only the record’s holder writes or takes off a line; a stranger and no key are refused, with what is wrong', async () => {
  const holder = key();
  const id = await saveRecord(holder);
  const d = await deal(2);
  const since = plusDays(today(), -5);
  await put(id, holder, { kind: 'overdue', since, statement: d.statements[0] }, d);
  const stranger = await put(id, key(), { kind: 'overdue', since, statement: d.statements[1] }, d);
  assert.equal(stranger.status, 404);
  assert.equal(stranger.json.code, 'no-record');
  assert.equal((await call('DELETE', `/api/records/${id}/license-notices/${refOf(d.statements[0])}`, key())).status, 404);
  assert.equal((await put(id, undefined, { kind: 'overdue', since, statement: d.statements[1] }, d)).status, 401);
  assert.equal((await call('GET', `/api/records/${id}/license-notices`, key())).status, 404);
  assert.equal((await verify(id)).licenseNotices.length, 1);
});

test('at most 20 per record; deleting the record deletes its lines (the licensee’s answers stay theirs)', async () => {
  const holder = key();
  const id = await saveRecord(holder);
  const d = await deal(21);
  const since = plusDays(today(), -5);
  for (let i = 0; i < 20; i++) assert.equal((await put(id, holder, { kind: 'overdue', since, statement: d.statements[i] }, d)).status, 200);
  assert.equal((await put(id, holder, { kind: 'overdue', since, statement: d.statements[20] }, d)).status, 409);
  await answer(d.licensee, d.statements[0], 'disputed');
  assert.equal((await call('DELETE', '/api/records', holder, { ids: [id] })).status, 200);
  assert.equal(await saveRecord(holder, id), id);
  assert.equal((await verify(id)).licenseNotices, undefined);
  assert.equal((await call('GET', `/license-answers/${d.statements[0]}`)).json.answers.length, 1);
});

test('M1: a deal opened before the deal keys were kept here says so (code predates) to both sides', async () => {
  const holder = key(); const id = await saveRecord(holder);
  const d = await deal(1);
  db.prepare('UPDATE deals SET issuer_key = NULL, licensee_key = NULL WHERE deal_id = ?').run(d.dealId);
  const line = await put(id, holder, { kind: 'overdue', since: plusDays(today(), -5), statement: d.statement }, d);
  assert.deepEqual([line.status, line.json.code], [409, 'predates']);
  const a = await answer(d.licensee, d.statement, 'disputed');
  assert.deepEqual([a.status, a.json.code], [409, 'predates']);
  const reg = await register(d, d.statement, '2026-05-14');
  assert.deepEqual([reg.status, reg.json.code], [409, 'predates']);
  // Both sides' pages learn it from what they read, and say so plainly.
  assert.equal((await call('GET', `/license-answers/${d.statement}`)).json.predates, true);
  const l = await call('POST', '/license-answers/lookup', undefined, { statements: [d.statement] });
  assert.equal(l.json.results[0].predates, true);
});

test('M3: lines from before the signature (v1, no statement; v2, unsigned) stay in the database and are never shown', async () => {
  const holder = key(); const id = await saveRecord(holder);
  const d = await deal(1);
  const stored = db.prepare('SELECT holder_key FROM records WHERE id = ?').get(id).holder_key;
  const ins = db.prepare('INSERT INTO license_notices (record_id, ref, holder_key, kind, day, statement, breach_at, revoked_at, line_sig, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)');
  ins.run(id, 'ab'.repeat(16), stored, 'revoked', '2026-05-01', null, null, null, null, Date.now());
  ins.run(id, refOf(d.statement), stored, 'revoked', '2026-05-02', d.statement, Date.now() - 40 * DAY, Date.now(), null, Date.now());
  assert.equal((await verify(id)).licenseNotices, undefined);
  assert.deepEqual((await call('GET', `/api/records/${id}/license-notices`, holder)).json.licenseNotices, []);
  assert.deepEqual((await call('GET', `/license-answers/${d.statement}`)).json.lines, []);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM license_notices WHERE record_id = ?').get(id).n, 2, 'kept, not deleted');
  // The unsigned v2 row is no "prior": its notice-of-breach date doesn't open a revoke.
  const r = await put(id, holder, { kind: 'revoked', reason: 'non-payment', on: today(), statement: d.statement }, d);
  assert.deepEqual([r.status, r.json.code], [409, 'no-breach']);
});

// ---- starting up, and the test clock (separate processes) ----

const serverJs = fileURLToPath(new URL('../server.js', import.meta.url));
const runRequire = (env) => spawnSync(process.execPath, ['-e', `require(${JSON.stringify(serverJs)})`], {
  env: { ...process.env, DB_PATH: ':memory:', VEILCORE_OTS: 'off', ...env }, encoding: 'utf8', timeout: 20_000,
});
const freePort = () => new Promise((resolve, reject) => {
  const s = createServer();
  s.once('error', reject);
  s.listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => resolve(port)); });
});
/** `node server.js` as Railway runs it (npm start), with `env`; its address, output and a stop. */
const boot = async (env = {}) => {
  const port = await freePort();
  const child = spawn(process.execPath, [serverJs], {
    env: { ...process.env, DB_PATH: ':memory:', VEILCORE_OTS: 'off', PORT: String(port), ...env },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let out = '';
  child.stdout.on('data', (b) => { out += b; });
  child.stderr.on('data', (b) => { out += b; });
  let exited = null;
  child.once('exit', (code) => { exited = code; });
  const base = `http://127.0.0.1:${port}`;
  await waitFor(`node server.js on ${process.version} to answer /health 200 (output: ${out.slice(-400)})`, async () => {
    if (exited !== null) throw new Error(`node server.js exited ${exited} on ${process.version}:\n${out}`);
    return (await fetch(`${base}/health`).catch(() => null))?.status === 200;
  }, { within: 45_000 });
  return { port, base, output: () => out, stop: () => new Promise((r) => { child.once('exit', r); child.kill(); }) };
};

test(`B1: node server.js starts and serves license answers on this Node (${process.version}), with no require() of an ES module racing its import()`, async () => {
  const s = await boot();
  try {
    assert.doesNotMatch(s.output(), /ERR_REQUIRE_ESM/);
    // Ready means ready: a well-formed answer reaches the deal lookup (404, no such deal), not 503.
    const r = await fetch(`${s.base}/license-answers`, { method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ answer: { v: 'veilcore/license-answer/v1', statement: hex32(), type: 'disputed' }, signature: 'a'.repeat(128) }) });
    assert.equal(r.status, 404);
  } finally {
    await s.stop();
  }
});

test('B1: no file the registry runs require()s a package that is an ES module (Node 24 races it against import())', async () => {
  const { readFileSync, readdirSync, existsSync } = await import('node:fs');
  const { join, dirname } = await import('node:path');
  const root = dirname(serverJs);
  const files = readdirSync(root).filter((f) => f.endsWith('.js') || f.endsWith('.cjs'));
  const found = [];
  for (const f of files) {
    for (const m of readFileSync(join(root, f), 'utf8').matchAll(/require\(\s*['"]([^'"./][^'"]*)['"]\s*\)/g)) {
      const name = m[1].startsWith('@') ? m[1].split('/').slice(0, 2).join('/') : m[1].split('/')[0];
      const pkg = join(root, 'node_modules', name, 'package.json');
      if (existsSync(pkg) && JSON.parse(readFileSync(pkg, 'utf8')).type === 'module') found.push(`${f}: ${m[1]}`);
    }
  }
  assert.deepEqual(found, []);
});

test('B1: /license-answers answers 503 while veilcore-records is still loading, and works once it has', () => {
  // A child that holds veilcore-records back in its evaluation (fixtures/fail-module-hooks.mjs,
  // DELAY_MODULE), asks, lets it go, and asks again.
  const hooks = new URL('./fixtures/fail-module-hooks.mjs', import.meta.url).href;
  const script = `
    import { register, createRequire } from 'node:module';
    let release; globalThis.__veilcoreHeldModule = new Promise((r) => { release = r; });
    register(${JSON.stringify(hooks)});
    const { app } = createRequire(import.meta.url)(${JSON.stringify(serverJs)});
    const s = app.listen(0); await new Promise((r) => s.once('listening', r));
    const base = 'http://127.0.0.1:' + s.address().port;
    const ask = () => fetch(base + '/license-answers', { method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ answer: { v: 'veilcore/license-answer/v1', statement: 'ab'.repeat(32), type: 'disputed' }, signature: 'a'.repeat(128) }) }).then((r) => r.status);
    const held = await ask();
    release();
    let after = 503;
    for (let i = 0; i < 600 && after === 503; i++) { await new Promise((r) => setTimeout(r, 50)); after = await ask(); }
    console.log('RESULT ' + JSON.stringify({ held, after }));
    process.exit(0);`;
  const r = spawnSync(process.execPath, ['--input-type=module', '-e', script], {
    env: { ...process.env, DB_PATH: ':memory:', VEILCORE_OTS: 'off', DELAY_MODULE: 'veilcore-records/dist/index.js', FAIL_MODULE: '' },
    encoding: 'utf8', timeout: 60_000,
  });
  const line = r.stdout.split('\n').find((l) => l.startsWith('RESULT '));
  assert.ok(line, r.stderr + r.stdout);
  assert.deepEqual(JSON.parse(line.slice(7)), { held: 503, after: 404 });
});

test('M2: the test clock is refused on Railway, on a mainnet registry, and with any value but "on"', () => {
  for (const env of [
    { VEILCORE_TEST_CLOCK: 'on', RAILWAY_ENVIRONMENT: 'production' },
    { VEILCORE_TEST_CLOCK: 'on', VEILCORE_ANCHOR_NETWORK: 'mainnet' },
    { VEILCORE_TEST_CLOCK: 'on', VEILCORE_ANCHOR_NETWORK: ' Mainnet ' },
    { VEILCORE_TEST_CLOCK: 'yes' },
  ]) {
    const r = runRequire(env);
    assert.equal(r.status, 1, `${JSON.stringify(env)}: ${r.stderr}`);
    assert.match(r.stderr, /VEILCORE_TEST_CLOCK/);
  }
});

test('M2: the test clock answers only a request from this machine, whatever a forwarded header says', async (t) => {
  const outside = Object.values(networkInterfaces()).flat().find((a) => a && a.family === 'IPv4' && !a.internal)?.address;
  const s = await boot({ VEILCORE_TEST_CLOCK: 'on' });
  try {
    const move = (host, headers = {}) => fetch(`http://${host}:${s.port}/__test/clock`, {
      method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify({ offsetMs: DAY }),
    });
    const here = await move('127.0.0.1');
    assert.equal(here.status, 200);
    assert.ok((await here.json()).now - Date.now() > DAY - 60_000);
    if (!outside) return t.skip('no non-loopback address on this machine to ask from');
    assert.equal((await move(outside)).status, 404);
    assert.equal((await move(outside, { 'x-forwarded-for': '127.0.0.1' })).status, 404);
  } finally {
    await s.stop();
  }
});

test('the test clock route does not exist on an ordinary registry', async () => {
  assert.equal((await call('POST', '/__test/clock', undefined, { offsetMs: 40 * DAY })).status, 404);
});

/** The licensor's signature stored for a line (never public). */
const storedSig = (id, statement) => db.prepare('SELECT line_sig FROM license_notices WHERE record_id = ? AND ref = ?').get(id, refOf(statement))?.line_sig;

test('N3 / vrp4 R4-7: once a notice of breach is on file, a resend can\u2019t move "overdue since" or replace the signature', async () => {
  const holder = key(); const id = await saveRecord(holder); const d = await deal();
  const s = d.statement;
  await register(d, s, '2026-05-14');
  const t0 = noon('2026-05-20');
  const breach = { kind: 'breach', since: '2026-05-15', statement: s };
  assert.equal((await at(t0, () => put(id, holder, breach, d))).status, 200);
  const sig = storedSig(id, s);
  assert.equal(sig, lineSig(d.issuer, id, breach));
  // Backdated to before the due date, moved later, or sent again as a breach with another date:
  // answered as the line stands, and nothing on file changes.
  for (const line of [
    { kind: 'overdue', since: '2020-01-01', statement: s },
    { kind: 'overdue', since: '2026-05-18', statement: s },
    { kind: 'breach', since: '2026-05-16', statement: s },
  ]) {
    const r = await at(t0 + DAY, () => put(id, holder, line, d));
    assert.equal(r.status, 200, JSON.stringify(r.json));
    assert.deepEqual([r.json.since, r.json.breachNoticeOn, r.json.updatedAt], ['2026-05-15', '2026-05-20', '2026-05-20'], JSON.stringify(line));
    assert.equal(storedSig(id, s), sig);
  }
  const v = await at(t0 + DAY, () => verify(id));
  assert.deepEqual(v.licenseNotices.map((n) => [n.kind, n.since, n.breachNoticeOn]), [['overdue', '2026-05-15', '2026-05-20']]);
});

test('N3 / vrp4 R4-7: once revoked, a resend of any kind leaves the line, its date and the licensor\u2019s signature over it', async () => {
  const holder = key(); const id = await saveRecord(holder); const d = await deal();
  const s = d.statement;
  await register(d, s, '2026-05-14');
  await at(noon('2026-05-20'), () => put(id, holder, { kind: 'breach', since: '2026-05-15', statement: s }, d));
  const revoked = { kind: 'revoked', reason: 'non-payment', on: '2026-06-20', statement: s };
  const t1 = noon('2026-06-20');
  assert.equal((await at(t1, () => put(id, holder, revoked, d))).status, 200);
  const sig = storedSig(id, s);
  assert.equal(sig, lineSig(d.issuer, id, revoked));
  for (const line of [
    { kind: 'overdue', since: '2020-01-01', statement: s },
    { kind: 'breach', since: '2026-05-15', statement: s },
    { kind: 'revoked', reason: 'non-payment', on: '2026-06-27', statement: s },
  ]) {
    const r = await at(t1 + 8 * DAY, () => put(id, holder, line, d));
    assert.equal(r.status, 200, JSON.stringify(r.json));
    assert.deepEqual([r.json.kind, r.json.on, r.json.updatedAt], ['revoked', '2026-06-20', '2026-06-20'], JSON.stringify(line));
    assert.equal(storedSig(id, s), sig, 'the stored signature is still the one over the revoked line');
  }
  const row = db.prepare('SELECT kind, day FROM license_notices WHERE record_id = ?').get(id);
  assert.deepEqual({ ...row }, { kind: 'revoked', day: '2026-06-20' });
});

test('N3: once the registered due date has passed, "overdue since" can\u2019t be on or before it; a date still to come doesn\u2019t silence the line', async () => {
  const holder = key(); const id = await saveRecord(holder); const d = await deal(2);
  const [s, far] = d.statements;
  await register(d, s, '2026-05-14');
  const t0 = noon('2026-05-20');
  for (const since of ['2020-01-01', '2026-05-14']) {
    const r = await at(t0, () => put(id, holder, { kind: 'overdue', since, statement: s }, d));
    assert.deepEqual([r.status, r.json.code, r.json.dueOn], [409, 'not-due', '2026-05-14'], since);
  }
  const ok = await at(t0, () => put(id, holder, { kind: 'overdue', since: '2026-05-15', statement: s }, d));
  assert.deepEqual([ok.status, ok.json.since], [200, '2026-05-15']);
  // Before a notice of breach, the plain overdue line can still move (the licensor's word), but
  // not back to the due date or before.
  const later = await at(t0, () => put(id, holder, { kind: 'overdue', since: '2026-05-17', statement: s }, d));
  assert.deepEqual([later.status, later.json.since], [200, '2026-05-17']);
  assert.equal((await at(t0, () => put(id, holder, { kind: 'overdue', since: '2026-05-01', statement: s }, d))).status, 409);
  // A licensee who registers a due date far off can keep the notice of breach off, not the
  // licensor's plain overdue line (vrp4 R4-4): that stays up, labelled as their word.
  await register(d, far, '9999-12-31');
  const o = await at(t0, () => put(id, holder, { kind: 'overdue', since: '2026-05-15', statement: far }, d));
  assert.equal(o.status, 200, JSON.stringify(o.json));
  const b = await at(t0, () => put(id, holder, { kind: 'breach', since: '2026-05-15', statement: far }, d));
  assert.deepEqual([b.status, b.json.code], [409, 'not-due']);
});

test('N1: the licensee can dispute a line about any message in their deal, one their page can\u2019t open or one never registered', async () => {
  const holder = key(); const id = await saveRecord(holder); const d = await deal(2);
  // Junk bytes the licensor posted to the deal, and a second sealing of the licensee's report
  // (a new fingerprint): neither is registered, and the licensor puts an overdue line on each.
  const [junk, reseal] = d.statements;
  const t0 = noon('2026-05-20');
  for (const s of [junk, reseal]) {
    assert.equal((await at(t0, () => put(id, holder, { kind: 'overdue', since: '2026-05-15', statement: s }, d))).status, 200);
    // Only the licensee's deal key files the dispute; the licensor's can't.
    assert.equal((await answer(d.issuer, s, 'disputed')).status, 403);
    const r = await at(t0, () => answer(d.licensee, s, 'disputed'));
    assert.deepEqual([r.status, r.json.filed, r.json.on], [200, true, '2026-05-20'], JSON.stringify(r.json));
  }
  const v = await at(t0, () => verify(id));
  assert.equal(v.licenseNotices.length, 2);
  for (const n of v.licenseNotices) assert.deepEqual(n.answers, [{ type: 'disputed', on: '2026-05-20' }]);
  // The licensee's page finds them by the messages' fingerprints, as it reads every one.
  const lk = await call('POST', '/license-answers/lookup', undefined, { statements: [junk, reseal] });
  assert.deepEqual(lk.json.results.map((x) => [x.lines.length, x.answers[0]?.type, x.registered]), [[1, 'disputed', undefined], [1, 'disputed', undefined]]);
  // A message that isn't in any deal held here: nothing to dispute.
  assert.equal((await answer(d.licensee, hex32(), 'disputed')).status, 404);
});

test('R5-5 (review round 5, B1): a later registered due date, passed: the refusal names it, and lines dated from the day after it are taken', async () => {
  // What the site's licensor page relies on: the terms say due 2026-05-01 (so it sends "since
  // 2026-05-02"), the licensee's page registered 2026-05-15, and the registry's clock is 2026-05-20.
  const holder = key(); const id = await saveRecord(holder); const d = await deal(1);
  await register(d, d.statement, '2026-05-15');
  const t0 = noon('2026-05-20');
  for (const kind of ['breach', 'overdue']) {
    const r = await at(t0, () => put(id, holder, { kind, since: '2026-05-02', statement: d.statement }, d));
    assert.deepEqual([r.status, r.json.code, r.json.dueOn, r.json.now], [409, 'not-due', '2026-05-15', t0], kind);
  }
  assert.deepEqual((await at(t0, () => verify(id))).licenseNotices ?? [], []);
  // The registered date is public by statement, for the licensor's page to read before it sends.
  const lk = await at(t0, () => call('POST', '/license-answers/lookup', undefined, { statements: [d.statement] }));
  assert.equal(lk.json.results[0].registered.dueOn, '2026-05-15');
  // Dated from the day after it, the notice of breach is filed, by this registry's clock.
  const b = await at(t0, () => put(id, holder, { kind: 'breach', since: '2026-05-16', statement: d.statement }, d));
  assert.deepEqual([b.status, b.json.since, b.json.breachNoticeOn], [200, '2026-05-16', '2026-05-20'], JSON.stringify(b.json));
  assert.deepEqual((await at(t0, () => verify(id))).licenseNotices.map((n) => [n.kind, n.since, n.breachNoticeOn]), [['overdue', '2026-05-16', '2026-05-20']]);
});
