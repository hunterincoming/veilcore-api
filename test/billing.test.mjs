// Paid plans through Paddle (billing.js), switched on, with a free number of 3.
//
// What these tests hold the registry to:
//   - a webhook counts only with a valid Paddle-Signature over its exact bytes, a fresh
//     timestamp, and an event id not seen before;
//   - Paddle is handed a billing id, never the holder key, and an unknown one changes nothing;
//   - a paid plan lifts the ceiling; a canceled one keeps it until the period ends plus the
//     grace, then the free number applies again, and nothing already held is touched;
//   - an event older than the one applied, or for a price we don't sell, changes nothing;
//   - the free number holds on every route that adds a record (save and dating), and the
//     refusal says it is the plan's;
//   - holders over the free number on the day billing is switched on keep what they hold and
//     may add the free number again;
//   - a save that adds nothing is never refused, and deleting doesn't make room on the free
//     plan; received deliveries don't count against it;
//   - a checkout needs a record held; a past_due plan is paid for the grace only; an event
//     that can't be applied yet is answered 5xx and not kept, so Paddle sends it again.
// billing-off.test.mjs holds that, switched off, nothing changes. No network.
//
// SPDX-License-Identifier: Apache-2.0

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { createHmac, randomBytes } from 'node:crypto';
import Database from 'better-sqlite3';
import { untilReady, testBody } from './helpers.mjs';

const SECRET = 'pdl_ntfset_test_secret_0123456789';
const BREEDER = 'pri_01testbreeder0001';
const LAB = 'pri_01testlab0000001';
process.env.DB_PATH = ':memory:';
process.env.VEILCORE_OTS = 'off';
process.env.VEILCORE_OPERATOR_TOKEN = 'billing-test-operator-token-0123456789abcdef';
process.env.BILLING = 'on';
process.env.BILLING_PADDLE_WEBHOOK_SECRET = SECRET;
process.env.BILLING_FREE_RECORDS = '3';
process.env.BILLING_PADDLE_PRICES = `${BREEDER}=breeder, ${LAB}=lab`;
process.env.BILLING_PADDLE_API = 'https://sandbox-api.paddle.com';
process.env.BILLING_PADDLE_API_KEY = 'pdl_sdbx_apikey_test_0123456789abcdef';
process.env.BILLING_PADDLE_CHECKOUT = 'https://sandbox-pay.paddle.io/checkout/hsc_01testcheckout000001';
const env = {
  BILLING: 'on',
  BILLING_PADDLE_WEBHOOK_SECRET: SECRET,
  BILLING_FREE_RECORDS: '3',
  BILLING_PADDLE_PRICES: `${BREEDER}=breeder`,
  BILLING_PADDLE_API: process.env.BILLING_PADDLE_API,
  BILLING_PADDLE_API_KEY: process.env.BILLING_PADDLE_API_KEY,
  BILLING_PADDLE_CHECKOUT: process.env.BILLING_PADDLE_CHECKOUT,
};

// Paddle's API, stood in for: every transaction the registry opens is kept, with its body and
// headers, so a test can read the billing id it carried (as Paddle would) and check what was sent.
const opened = [];
let paddleAnswer = null;
const realFetch = globalThis.fetch;
globalThis.fetch = async (url, init) => {
  if (String(url).startsWith('https://sandbox-api.paddle.com/')) {
    opened.push({ url: String(url), headers: init.headers, body: JSON.parse(init.body) });
    if (paddleAnswer) return paddleAnswer();
    return new Response(JSON.stringify({ data: { id: `txn_01${randomBytes(10).toString('hex')}` } }), { status: 201 });
  }
  return realFetch(url, init);
};
const require = createRequire(import.meta.url);
const { app } = require('../server.js');
const { createBilling, GRACE_MS } = require('../billing.js');

const hex = (n = 32) => randomBytes(n).toString('hex');
const recordId = () => `VEIL-${hex(16).toUpperCase()}`;
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
    headers: {
      'content-type': 'application/json',
      'x-forwarded-for': `10.${randomBytes(3).join('.')}`,
      ...(holder ? { 'x-holder-key': holder } : {}),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(path === '/api/records' ? testBody(method, path, holder, body) : body) }),
  });
  return { status: res.status, json: await res.json() };
};
const date = (holder, n) => call('PUT', '/api/records/dating', holder, Array.from({ length: n }, () => ({ id: recordId(), recordFingerprint: hex() })));
// testBody seals each record as the browser does, with the holder's vault key.
const newRecord = () => ({ id: recordId(), recordFingerprint: hex(), nonce: hex(), strainName: 'S' });
const saveAll = (holder, records) => call('PUT', '/api/records', holder, records);
const save = (holder) => saveAll(holder, [newRecord()]);
const plan = (holder) => call('GET', '/api/billing/plan', holder);
// A checkout needs a record held: each test holder gets one dated first, once.
const holding = new Set();
const checkout = async (holder, planName = 'breeder') => {
  if (holder && !holding.has(holder)) {
    holding.add(holder);
    await date(holder, 1);
  }
  return call('POST', '/api/billing/checkout', holder, { plan: planName });
};
/** Open a checkout as the holder would, and read the billing id it carried, as Paddle would. */
const billingId = async (holder) => {
  const r = await checkout(holder);
  assert.equal(r.status, 200, JSON.stringify(r.json));
  return opened.at(-1).body.custom_data.veilcoreBillingId;
};

let n = 0;
const event = (type, { billingId: bid, sub, status = 'active', price = BREEDER, endsAt, occurredAt } = {}) => ({
  event_id: `evt_01test${String(++n).padStart(12, '0')}`,
  event_type: type,
  occurred_at: occurredAt ?? new Date().toISOString(),
  data: {
    id: sub,
    status,
    items: [{ price: { id: price } }],
    current_billing_period: endsAt === null ? null : { ends_at: endsAt ?? new Date(Date.now() + 30 * 86_400_000).toISOString() },
    ...(bid ? { custom_data: { veilcoreBillingId: bid } } : {}),
  },
});
const sign = (raw, ts = Math.floor(Date.now() / 1000), secret = SECRET) =>
  `ts=${ts};h1=${createHmac('sha256', secret).update(`${ts}:${raw}`).digest('hex')}`;
const send = async (ev, { signature, raw } = {}) => {
  const body = raw ?? JSON.stringify(ev);
  const res = await fetch(`${base}/api/billing/paddle`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'paddle-signature': signature ?? sign(body) },
    body,
  });
  return { status: res.status, json: await res.json() };
};
const subId = () => `sub_01${hex(10)}`;

test('/health lists billing-v1 while billing is on', async () => {
  const h = await (await fetch(`${base}/health`)).json();
  assert.ok(h.features.includes('billing-v1'));
});

test('free: three records, then the save and the dating route both refuse, saying it is the plan', async () => {
  const holder = hex();
  assert.equal((await date(holder, 2)).status, 200);
  assert.equal((await save(holder)).json.ok, true);
  const over = await save(holder);
  assert.equal(over.status, 200);
  assert.equal(over.json.ok, false);
  assert.equal(over.json.rejected?.[0]?.code, 'plan-limit', JSON.stringify(over.json));
  assert.equal(over.json.rejected?.[0]?.cap, 3);
  const dated = await date(holder, 1);
  assert.equal(dated.json.rejected?.[0]?.code, 'plan-limit', JSON.stringify(dated.json));
  const p = await plan(holder);
  assert.deepEqual(p.json, {
    plan: 'free',
    status: null,
    periodEnd: null,
    recordsHeld: 3,
    recordsCounted: 3,
    recordCap: 3,
    plans: ['breeder', 'lab'],
  });
});

test('a checkout goes to Paddle with a billing id, never the holder key; earlier ids still work', async () => {
  const holder = hex();
  const r = await checkout(holder, 'lab');
  assert.equal(r.status, 200);
  const sent = opened.at(-1);
  assert.equal(sent.url, 'https://sandbox-api.paddle.com/transactions');
  assert.equal(sent.headers.authorization, `Bearer ${process.env.BILLING_PADDLE_API_KEY}`);
  assert.deepEqual(sent.body.items, [{ price_id: LAB, quantity: 1 }]);
  const a = sent.body.custom_data.veilcoreBillingId;
  assert.match(a, /^[0-9a-f]{64}$/);
  assert.ok(!JSON.stringify(sent).includes(holder), 'the holder key is not sent to Paddle');
  // The holder is sent to Paddle's own hosted page, for that transaction. No billing id in it.
  assert.match(r.json.url, /^https:\/\/sandbox-pay\.paddle\.io\/checkout\/hsc_01testcheckout000001\?transaction_id=txn_01[0-9a-f]{20}$/);
  assert.ok(!r.json.url.includes(a));
  // A second checkout (another tab) gets a new id; a payment through the first still lands.
  const b = await billingId(holder);
  assert.notEqual(a, b);
  const paid = await send(event('subscription.created', { billingId: a, sub: subId(), price: LAB }));
  assert.deepEqual(paid.json, { ok: true });
  assert.equal((await plan(holder)).json.plan, 'lab');
  // No holder key, an unknown plan: refused before Paddle is asked.
  const before = opened.length;
  assert.equal((await call('POST', '/api/billing/checkout', undefined, { plan: 'breeder' })).status, 401);
  assert.equal((await checkout(holder, 'gold')).status, 400);
  assert.equal(opened.length, before);
});

test('Paddle refusing or unreachable: a plain 502, nothing stored as paid', async () => {
  const holder = hex();
  paddleAnswer = () => new Response(JSON.stringify({ error: { code: 'forbidden' } }), { status: 403 });
  assert.equal((await checkout(holder)).status, 502);
  paddleAnswer = () => { throw new TypeError('fetch failed'); };
  assert.equal((await checkout(holder)).status, 502);
  paddleAnswer = () => new Response(JSON.stringify({ data: { id: '<script>' } }), { status: 201 });
  assert.equal((await checkout(holder)).status, 502);
  paddleAnswer = null;
  assert.equal((await plan(holder)).json.plan, 'free');
});

test('a holder may open ten checkouts an hour', async () => {
  const holder = hex();
  for (let i = 0; i < 10; i++) assert.equal((await checkout(holder)).status, 200);
  assert.equal((await checkout(holder)).status, 429);
});

test('a webhook counts only when signed over its exact bytes, fresh, and once', async () => {
  const holder = hex();
  const bid = await billingId(holder);
  const ev = event('subscription.created', { billingId: bid, sub: subId() });
  const raw = JSON.stringify(ev);
  assert.equal((await send(ev, { signature: sign(raw, undefined, 'pdl_ntfset_wrong_secret_000000') })).status, 401);
  assert.equal((await send(ev, { signature: 'ts=1;h1=00' })).status, 401);
  assert.equal((await send(ev, { signature: '' })).status, 401);
  const stale = Math.floor(Date.now() / 1000) - 10 * 60;
  assert.equal((await send(ev, { raw, signature: sign(raw, stale) })).status, 401);
  // The same JSON with a space added is different bytes: refused.
  assert.equal((await send(ev, { raw: `${raw} `, signature: sign(raw) })).status, 401);
  assert.equal((await plan(holder)).json.plan, 'free');
  // Signed with the old and the new secret during a rotation: either h1 counts.
  const ts = Math.floor(Date.now() / 1000);
  const both = `${sign(raw, ts, 'pdl_ntfset_old_secret_00000000')};h1=${createHmac('sha256', SECRET).update(`${ts}:${raw}`).digest('hex')}`;
  assert.deepEqual((await send(ev, { raw, signature: both })).json, { ok: true });
  assert.equal((await plan(holder)).json.plan, 'breeder');
  // Sent again (a replay, or Paddle retrying): acknowledged, changes nothing.
  assert.deepEqual((await send(ev)).json, { ok: true, repeat: true });
});

test('a paid plan lifts the ceiling; cancelled, it holds until the period ends plus the grace', async () => {
  const holder = hex();
  const bid = await billingId(holder);
  const sub = subId();
  await date(holder, 3);
  assert.equal((await date(holder, 1)).json.rejected?.[0]?.code, 'plan-limit');
  await send(event('subscription.created', { billingId: bid, sub, price: LAB }));
  const paid = await date(holder, 2);
  assert.equal(paid.json.dated?.length, 2, JSON.stringify(paid.json));
  const p = await plan(holder);
  assert.equal(p.json.plan, 'lab');
  assert.equal(p.json.recordCap, 10_000);
  // Cancelled with the period still running: still paid. Later events need no billing id.
  await send(event('subscription.canceled', { sub, status: 'canceled', price: LAB }));
  assert.equal((await plan(holder)).json.plan, 'lab');
  // The period ended longer ago than the grace: back to the free number. Nothing is removed.
  const ended = new Date(Date.now() - GRACE_MS - 86_400_000).toISOString();
  await send(event('subscription.canceled', { sub, status: 'canceled', price: LAB, endsAt: ended }));
  const after = await plan(holder);
  assert.deepEqual([after.json.plan, after.json.recordsHeld, after.json.recordCap], ['free', 5, 3]);
  assert.equal((await date(holder, 1)).json.rejected?.[0]?.code, 'plan-limit');
});

test('an older event, a price we do not sell, or an unknown billing id changes nothing', async () => {
  const holder = hex();
  const bid = await billingId(holder);
  const sub = subId();
  await send(event('subscription.created', { billingId: bid, sub }));
  const older = new Date(Date.now() - 3_600_000).toISOString();
  const ended = new Date(Date.now() - GRACE_MS - 86_400_000).toISOString();
  const r = await send(event('subscription.canceled', { sub, status: 'canceled', endsAt: ended, occurredAt: older }));
  assert.deepEqual(r.json, { ok: true, ignored: 'older event' });
  assert.equal((await plan(holder)).json.plan, 'breeder');

  const other = hex();
  const otherId = await billingId(other);
  // A price we don't sell, or a billing id we don't know: not applied, answered 5xx so Paddle
  // sends it again (the operator fixes the setting meanwhile), and not kept as seen.
  const priced = event('subscription.created', { billingId: otherId, sub: subId(), price: 'pri_01notours00000001' });
  assert.equal((await send(priced)).status, 503);
  assert.equal((await send(priced)).status, 503, 'not refused as a repeat');
  assert.equal((await send(event('subscription.created', { billingId: hex(), sub: subId() }))).status, 503);
  // Someone puts a holder key where the billing id goes: it is not one.
  assert.equal((await send(event('subscription.created', { billingId: other, sub: subId() }))).status, 503);
  assert.equal((await plan(other)).json.plan, 'free');
  // Not a subscription event: acknowledged so Paddle stops retrying, nothing stored.
  assert.deepEqual((await send(event('transaction.completed', { sub: subId() }))).json, { ok: true, ignored: 'event type' });
});

test('switched on over existing holders: those above the free number keep theirs and may add it again', () => {
  const db = new Database(':memory:');
  db.exec('CREATE TABLE records (id TEXT PRIMARY KEY, holder_key TEXT NOT NULL, body TEXT)');
  const add = db.prepare('INSERT INTO records (id, holder_key, body) VALUES (?, ?, ?)');
  for (let i = 0; i < 5; i++) add.run(`big-${i}`, 'h1:big', '{}');
  add.run('small-0', 'h1:small', '{}');
  const b = createBilling(db, { env, hardCap: 10_000 });
  assert.equal(b.recordCapFor('h1:big'), 8);
  assert.equal(b.recordCapFor('h1:small'), 3);
  assert.equal(b.recordCapFor('h1:new'), 3);
  // Done when billing goes on: a holder who grows while it stays on is not grandfathered again.
  for (let i = 0; i < 5; i++) add.run(`small-later-${i}`, 'h1:small', '{}');
  assert.equal(createBilling(db, { env, hardCap: 10_000 }).recordCapFor('h1:small'), 3);
  // Off, then on again: done again, and a cap is only raised.
  createBilling(db, { env: {}, hardCap: 10_000 });
  db.prepare("DELETE FROM records WHERE id = 'big-0'").run();
  const again = createBilling(db, { env, hardCap: 10_000 });
  assert.equal(again.recordCapFor('h1:small'), 9);
  assert.equal(again.recordCapFor('h1:big'), 8, 'not lowered');
  // Every record they hold counts, so the room is the free number again.
  assert.equal(again.planRoom('h1:small').room, 3);
  // Off, or half configured: everyone keeps the registry's ceiling, as before.
  assert.equal(createBilling(db, { env: {}, hardCap: 10_000 }).recordCapFor('h1:new'), 10_000);
  assert.equal(createBilling(db, { env: { ...env, BILLING_PADDLE_PRICES: '' }, hardCap: 10_000 }).recordCapFor('h1:new'), 10_000);
  for (const wrong of [
    { BILLING_PADDLE_WEBHOOK_SECRET: 'short' },
    { BILLING_PADDLE_API: 'https://evil.example' },
    { BILLING_PADDLE_API: 'https://api.paddle.com' }, // a sandbox key against the live API
    { BILLING_PADDLE_API_KEY: '' },
    { BILLING_PADDLE_CHECKOUT: 'https://evil.example/checkout/hsc_01testcheckout000001' },
    { BILLING_PADDLE_PRICES: `${BREEDER}=breeder,${LAB}=breeder` },
    { BILLING_FREE_RECORDS: '3abc' },
    { BILLING_FREE_RECORDS: '' },
    { BILLING: 'On' },
  ]) {
    assert.equal(createBilling(db, { env: { ...env, ...wrong }, hardCap: 10_000 }).recordCapFor('h1:new'), 10_000, JSON.stringify(wrong));
  }
});

test('a holder above the ceiling can still save edits; only new records are refused', async () => {
  const holder = hex();
  const kept = [newRecord(), newRecord(), newRecord()];
  assert.equal((await saveAll(holder, kept)).json.ok, true);
  // Paid, then lapsed past the grace: over nothing, at the ceiling.
  const bid = await billingId(holder);
  const sub = subId();
  await send(event('subscription.created', { billingId: bid, sub }));
  assert.equal((await date(holder, 2)).json.dated?.length, 2);
  const ended = new Date(Date.now() - GRACE_MS - 86_400_000).toISOString();
  await send(event('subscription.canceled', { sub, status: 'canceled', endsAt: ended }));
  assert.equal((await plan(holder)).json.plan, 'free');
  // The whole set re-sent, as the app does on every change: saved.
  const again = await saveAll(holder, kept);
  assert.equal(again.status, 200, JSON.stringify(again.json));
  // A new record waiting in the browser goes with every save: only it is refused, and the edit
  // beside it is stored.
  const stuck = newRecord();
  const edited = { ...kept[0], strainName: 'S edited' };
  const more = await saveAll(holder, [edited, kept[1], kept[2], stuck]);
  assert.equal(more.status, 200, JSON.stringify(more.json));
  assert.deepEqual(more.json.rejected?.map((r) => [r.id, r.code]), [[stuck.id, 'plan-limit']]);
  assert.equal(more.json.count, 3);
});

test('an id that belongs to another holder is not counted as new', async () => {
  const other = hex();
  const theirs = newRecord();
  assert.equal((await saveAll(other, [theirs])).json.ok, true);
  const holder = hex();
  const mine = [newRecord(), newRecord(), newRecord()];
  assert.equal((await saveAll(holder, mine)).json.ok, true);
  // The same id with another proof code (the fingerprint rule would refuse a copy first).
  const r = await saveAll(holder, [...mine, { ...theirs, recordFingerprint: hex() }]);
  assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.deepEqual(r.json.notWritten, [theirs.id], JSON.stringify(r.json));
  assert.equal(r.json.rejected, undefined, 'not refused for the plan');
});

const correctionOf = (r) => ({
  id: recordId(),
  recordFingerprint: hex(),
  nonce: hex(),
  strainName: 'S fixed',
  supersedes: { recordId: r.id, changedFields: ['notes'], effectiveAt: '2026-11-08T09:30:00Z', reason: 'typo' },
});

test("a record's one correction doesn't count on the free plan; a correction of a correction does", async () => {
  const holder = hex();
  const kept = [newRecord(), newRecord(), newRecord()];
  assert.equal((await saveAll(holder, kept)).json.ok, true);
  // At the free number: the correction of a record is stored all the same.
  const fix = correctionOf(kept[0]);
  const r = await saveAll(holder, [{ ...kept[0], supersededBy: fix.id }, fix]);
  assert.equal(r.json.ok, true, JSON.stringify(r.json));
  assert.equal((await plan(holder)).json.recordsCounted, 3);
  // Correcting the correction would date a new proof code for free: it counts, so it is refused.
  const fix2 = correctionOf(fix);
  const r2 = await saveAll(holder, [fix2]);
  assert.deepEqual(r2.json.rejected?.map((x) => x.code), ['plan-limit'], JSON.stringify(r2.json));
});

test("a record's free correction is used once: deleted and made again, it counts", () => {
  const { db, b } = standalone();
  db.prepare('INSERT INTO records VALUES (?, ?, ?)').run('r1', 'h1:a', '{}');
  assert.equal(b.correctionIsFree('h1:a', 'r1'), true);
  b.noteFreeCorrection('h1:a', 'r1');
  assert.equal(b.correctionIsFree('h1:a', 'r1'), false);
});

test('on the free plan, deleting a record does not make room for another', async () => {
  const holder = hex();
  const records = [newRecord(), newRecord(), newRecord()];
  assert.equal((await saveAll(holder, records)).json.ok, true);
  const del = await call('DELETE', '/api/records', holder, { ids: [records[0].id] });
  assert.equal(del.status, 200, JSON.stringify(del.json));
  const p = await plan(holder);
  assert.deepEqual([p.json.recordsHeld, p.json.recordsCounted, p.json.recordCap], [2, 3, 3]);
  assert.equal((await save(holder)).json.rejected?.[0]?.code, 'plan-limit');
  assert.equal((await date(holder, 1)).json.rejected?.[0]?.code, 'plan-limit');
  // Saving the deleted record again (a backup) doesn't count it twice.
  const back = await saveAll(holder, [records[0]]);
  assert.equal(back.json.ok, true, JSON.stringify(back.json));
  assert.equal((await plan(holder)).json.recordsCounted, 3);
});

test('a checkout needs a record held', async () => {
  const before = opened.length;
  const r = await call('POST', '/api/billing/checkout', hex(), { plan: 'breeder' });
  assert.equal(r.status, 409);
  assert.equal(opened.length, before, 'Paddle not asked');
});

// A billing instance on its own database and clock, for what depends on time.
const standalone = () => {
  const db = new Database(':memory:');
  db.exec('CREATE TABLE records (id TEXT PRIMARY KEY, holder_key TEXT NOT NULL, body TEXT)');
  const clock = { t: Date.parse('2027-01-01T00:00:00Z') };
  const sent = [];
  const fetchImpl = async (_url, init) => {
    sent.push(JSON.parse(init.body));
    return new Response(JSON.stringify({ data: { id: `txn_01${hex(10)}` } }), { status: 201 });
  };
  const b = createBilling(db, { env, hardCap: 10_000, now: () => clock.t, fetchImpl });
  const answer = () => {
    const r = { code: 200, body: null };
    return { r, status(c) { r.code = c; return this; }, json(j) { r.body = j; return this; } };
  };
  const checkoutId = async (holder, ip = '10.0.0.1') => {
    const out = answer();
    await b.checkout(holder, { plan: 'breeder' }, out, ip);
    assert.equal(out.r.code, 200, JSON.stringify(out.r.body));
    return sent.at(-1).custom_data.veilcoreBillingId;
  };
  const hook = (ev) => {
    const raw = Buffer.from(JSON.stringify(ev));
    const ts = Math.floor(clock.t / 1000);
    const sig = `ts=${ts};h1=${createHmac('sha256', SECRET).update(`${ts}:`).update(raw).digest('hex')}`;
    const out = answer();
    b.webhook({ get: () => sig, body: raw }, out);
    return out.r;
  };
  return { db, clock, b, checkoutId, hook };
};

test('past_due is paid for the grace from the first failed renewal, not to the new period end', async () => {
  const { db, clock, b, checkoutId, hook } = standalone();
  db.prepare('INSERT INTO records VALUES (?, ?, ?)').run('r1', 'h1:a', '{}');
  const bid = await checkoutId('h1:a');
  const sub = subId();
  const at = () => new Date(clock.t).toISOString();
  const later = new Date(clock.t + 60 * 86_400_000).toISOString();
  assert.equal(hook(event('subscription.created', { billingId: bid, sub, occurredAt: at() })).code, 200);
  assert.equal(b.recordCapFor('h1:a'), 10_000);
  clock.t += 30 * 86_400_000;
  // The renewal fails; Paddle has moved the period on a month.
  hook(event('subscription.past_due', { sub, status: 'past_due', endsAt: later, occurredAt: at() }));
  assert.equal(b.recordCapFor('h1:a'), 10_000, 'paid during the grace');
  clock.t += GRACE_MS - 86_400_000;
  // Another past_due update doesn't restart the grace.
  hook(event('subscription.updated', { sub, status: 'past_due', endsAt: later, occurredAt: at() }));
  clock.t += 2 * 86_400_000;
  assert.equal(b.recordCapFor('h1:a'), 3, 'grace over, though the period runs on');
  // Paid at last: active again.
  hook(event('subscription.updated', { sub, status: 'active', endsAt: later, occurredAt: at() }));
  assert.equal(b.recordCapFor('h1:a'), 10_000);
});

test('cancelled after a failed renewal: paid only to the end of the period paid for, plus the grace', async () => {
  const { db, clock, b, checkoutId, hook } = standalone();
  db.prepare('INSERT INTO records VALUES (?, ?, ?)').run('r1', 'h1:a', '{}');
  const bid = await checkoutId('h1:a');
  const sub = subId();
  const at = () => new Date(clock.t).toISOString();
  const paidTo = new Date(clock.t + 30 * 86_400_000).toISOString();
  hook(event('subscription.created', { billingId: bid, sub, endsAt: paidTo, occurredAt: at() }));
  clock.t += 30 * 86_400_000;
  const moved = new Date(clock.t + 30 * 86_400_000).toISOString();
  hook(event('subscription.past_due', { sub, status: 'past_due', endsAt: moved, occurredAt: at() }));
  clock.t += 86_400_000;
  // Cancelled with no period of its own: the moved end isn't reached.
  hook(event('subscription.canceled', { sub, status: 'canceled', endsAt: null, occurredAt: at() }));
  assert.equal(b.recordCapFor('h1:a'), 10_000, 'within the grace');
  clock.t += GRACE_MS;
  assert.equal(b.recordCapFor('h1:a'), 3, 'not to the moved period end');
});

test('billing ids are kept at least seven days, whatever the number', async () => {
  const { db, clock, checkoutId } = standalone();
  db.prepare('INSERT INTO records VALUES (?, ?, ?)').run('r1', 'h1:a', '{}');
  const count = () => db.prepare("SELECT COUNT(*) AS n FROM billing_ids WHERE holder_key = 'h1:a'").get().n;
  for (let i = 0; i < 25; i++) {
    if (i % 10 === 0) clock.t += 3_600_000; // ten checkouts an hour
    await checkoutId('h1:a');
  }
  assert.equal(count(), 25);
  clock.t += 8 * 86_400_000;
  await checkoutId('h1:a');
  assert.equal(count(), 20);
});

test('received deliveries do not count against the free plan, at switch-on or after', () => {
  const db = new Database(':memory:');
  db.exec('CREATE TABLE records (id TEXT PRIMARY KEY, holder_key TEXT NOT NULL, body TEXT)');
  const add = db.prepare('INSERT INTO records VALUES (?, ?, ?)');
  for (let i = 0; i < 2; i++) add.run(`own-${i}`, 'h1:a', '{}');
  for (let i = 0; i < 5; i++) add.run(`got-${i}`, 'h1:a', JSON.stringify({ receivedFrom: `VEIL-${i}` }));
  // Seven held, two of their own: not grandfathered, and one more of their own fits under three.
  const b = createBilling(db, { env, hardCap: 10_000 });
  assert.equal(b.recordCapFor('h1:a'), 3);
  assert.equal(b.planRoom('h1:a').room, 1);
  add.run('own-2', 'h1:a', '{}');
  b.noteAdded('h1:a', ['own-2']);
  assert.equal(b.planRoom('h1:a').room, 0);
  // Deleting one of their own doesn't give it back; saving it again doesn't count it twice.
  db.prepare("DELETE FROM records WHERE id = 'own-0'").run();
  assert.equal(b.planRoom('h1:a').room, 0);
  b.noteAdded('h1:a', ['own-0']);
  assert.equal(b.planRoom('h1:a').room, 0);
  assert.equal(b.wasCounted('h1:a', 'own-0'), true);
});

test('checkout limits: ten per holder an hour, and fresh keys cannot reset anyone', async () => {
  const { db, clock, b, checkoutId } = standalone();
  const add = db.prepare('INSERT INTO records VALUES (?, ?, ?)');
  add.run('r-a', 'h1:a', '{}');
  for (let i = 0; i < 10; i++) await checkoutId('h1:a');
  const out = { code: 200, status(c) { this.code = c; return this; }, json() { return this; } };
  await b.checkout('h1:a', { plan: 'breeder' }, out);
  assert.equal(out.code, 429);
  for (let i = 0; i < 50; i++) {
    add.run(`r-${i}`, `h1:flood-${i}`, '{}');
    await checkoutId(`h1:flood-${i}`, `10.1.${i}.1`);
  }
  const still = { code: 200, status(c) { this.code = c; return this; }, json() { return this; } };
  await b.checkout('h1:a', { plan: 'breeder' }, still);
  assert.equal(still.code, 429, 'still limited this hour');
  clock.t += 3_600_000;
  await checkoutId('h1:a');
});

test('checkout limits: twenty per address an hour; Paddle failing uses up only attempts', async () => {
  const { db, clock, b, checkoutId } = standalone();
  const add = db.prepare('INSERT INTO records VALUES (?, ?, ?)');
  for (let i = 0; i < 21; i++) add.run(`r-${i}`, `h1:ip-${i}`, '{}');
  for (let i = 0; i < 20; i++) await checkoutId(`h1:ip-${i}`, '10.2.2.2');
  const out = { code: 200, status(c) { this.code = c; return this; }, json() { return this; } };
  await b.checkout('h1:ip-20', { plan: 'breeder' }, out, '10.2.2.2');
  assert.equal(out.code, 429);
  // Another hour: Paddle down. Failures don't use up the ten checkouts a holder may open.
  clock.t += 3_600_000;
  const down = createBilling(db, { env, hardCap: 10_000, now: () => clock.t, fetchImpl: async () => { throw new TypeError('down'); } });
  for (let i = 0; i < 12; i++) {
    const o = { code: 200, status(c) { this.code = c; return this; }, json() { return this; } };
    await down.checkout('h1:ip-0', { plan: 'breeder' }, o, `10.3.3.${i}`);
    assert.equal(o.code, 502);
  }
});

test('the webhook has its own rate window: a burst from one address is not refused', async () => {
  const statuses = new Set();
  for (let i = 0; i < 130; i++) {
    const res = await fetch(`${base}/api/billing/paddle`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'paddle-signature': 'ts=1;h1=00', 'x-forwarded-for': '10.9.9.9' },
      body: '{}',
    });
    statuses.add(res.status);
  }
  assert.deepEqual([...statuses], [401]);
});

test('a plan and its counts follow the holder key when its stored form moves', () => {
  const { adoptPlaintextKey, storedHolderKey, legacyStoredHolderKey, HOLDER_KEY_COLUMNS } = require('../holder-key.js');
  const tables = ['billing_ids', 'billing_plans', 'billing_grandfathered', 'billing_counted', 'billing_free_corrections'];
  for (const t of tables) {
    assert.ok(HOLDER_KEY_COLUMNS.some(([table, col]) => table === t && col === 'holder_key'), t);
  }
  const { db } = standalone();
  for (const c of ['correction_conflict TEXT', 'first_seen INTEGER', 'updated_at INTEGER']) db.exec(`ALTER TABLE records ADD COLUMN ${c}`);
  const upper = hex().toUpperCase();
  const old = legacyStoredHolderKey(upper);
  db.prepare(
    "INSERT INTO billing_plans (subscription_id, holder_key, plan, status, occurred_at, updated_at) VALUES ('sub_01moved0000000001', ?, 'breeder', 'active', 1, 1)",
  ).run(old);
  db.prepare('INSERT INTO billing_grandfathered VALUES (?, 9)').run(old);
  db.prepare("INSERT INTO billing_counted VALUES (?, 'c1')").run(old);
  db.prepare("INSERT INTO billing_free_corrections VALUES (?, 't1')").run(old);
  db.prepare("INSERT INTO billing_ids VALUES ('d1', ?, 1)").run(old);
  adoptPlaintextKey(db, upper);
  const now = storedHolderKey(upper);
  for (const t of tables) {
    assert.equal(db.prepare(`SELECT COUNT(*) AS n FROM ${t} WHERE holder_key = ?`).get(now).n, 1, t);
  }
});
