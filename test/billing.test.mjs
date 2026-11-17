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
//     may add the free number again.
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
const save = (holder) => call('PUT', '/api/records', holder, [{ id: recordId(), recordFingerprint: hex(), nonce: hex(), strainName: 'S' }]);
const plan = (holder) => call('GET', '/api/billing/plan', holder);
const checkout = (holder, planName = 'breeder') => call('POST', '/api/billing/checkout', holder, { plan: planName });
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

test('free: three records, then the save and the dating route both refuse, saying it is the plan', async () => {
  const holder = hex();
  assert.equal((await date(holder, 2)).status, 200);
  assert.equal((await save(holder)).json.ok, true);
  const over = await save(holder);
  assert.equal(over.status, 413);
  assert.equal(over.json.code, 'plan-limit');
  assert.equal(over.json.cap, 3);
  const dated = await date(holder, 1);
  assert.equal(dated.json.rejected?.[0]?.code, 'plan-limit', JSON.stringify(dated.json));
  const p = await plan(holder);
  assert.deepEqual(p.json, { plan: 'free', status: null, periodEnd: null, recordsHeld: 3, recordCap: 3 });
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
  const unknownPrice = await send(event('subscription.created', { billingId: otherId, sub: subId(), price: 'pri_01notours00000001' }));
  assert.deepEqual(unknownPrice.json, { ok: true, ignored: 'no known price' });
  const unknownId = await send(event('subscription.created', { billingId: hex(), sub: subId() }));
  assert.deepEqual(unknownId.json, { ok: true, ignored: 'unknown billing id' });
  // Someone puts a holder key where the billing id goes: it is not one.
  const keyAsId = await send(event('subscription.created', { billingId: other, sub: subId() }));
  assert.deepEqual(keyAsId.json, { ok: true, ignored: 'unknown billing id' });
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
  // Done once: a holder who grows later is not grandfathered at the next start.
  for (let i = 0; i < 5; i++) add.run(`small-later-${i}`, 'h1:small', '{}');
  assert.equal(createBilling(db, { env, hardCap: 10_000 }).recordCapFor('h1:small'), 3);
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
  ]) {
    assert.equal(createBilling(db, { env: { ...env, ...wrong }, hardCap: 10_000 }).recordCapFor('h1:new'), 10_000, JSON.stringify(wrong));
  }
});
