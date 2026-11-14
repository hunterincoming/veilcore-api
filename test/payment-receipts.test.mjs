// Payment receipts (lineage/payment-receipts.mjs): a registered payment partner's signed
// word that a statement held in a deal was paid.
//
// SPDX-License-Identifier: Apache-2.0

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { registrationPayload } from '../lineage/attesters.mjs';
import { dealTokenHash } from '../lineage/deals.mjs';
import { commitHashOf, inviteTokenHash } from '../lineage/license-invites.mjs';
import { RECEIPT_VERSION, receiptBytes } from '../lineage/payment-receipts.mjs';
import { untilReady } from './helpers.mjs';

process.env.DB_PATH = ':memory:';
process.env.VEILCORE_OTS = 'off';
process.env.VEILCORE_OPERATOR_TOKEN = 'test-operator-token-at-least-32-chars';
const require = createRequire(import.meta.url);
const { app } = require('../server.js');

let base, server;
before(async () => {
  server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  base = `http://127.0.0.1:${server.address().port}`;
  await untilReady(base);
});
after(() => server.close());

const call = async (method, path, body, headers = {}) => {
  const res = await fetch(`${base}${path}`, {
    method,
    headers: { 'content-type': 'application/json', ...headers },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  return { status: res.status, json: await res.json() };
};

const partnerKey = () => {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const pub = publicKey.export({ format: 'jwk' }).x;
  return { privateKey, hex: Buffer.from(pub, 'base64url').toString('hex') };
};
const register = async (k, role, { vet = true } = {}) => {
  const reg = { publicKey: k.hex, issuedAt: Date.now(), displayName: 'Example Pay', role };
  const signature = sign(null, Buffer.from(registrationPayload(reg), 'utf8'), k.privateKey).toString('hex');
  const r = await call('POST', '/attesters', { ...reg, signature });
  if (vet) {
    const check = {
      source: 'licence-listing', sourceUrl: 'https://nmls.example.gov/pay', licenceNo: 'MT-1', emailDomain: 'pay.example',
      checkedAt: new Date().toISOString().slice(0, 10), checkedBy: 'AB',
    };
    const v = await call('POST', `/attesters/${k.hex}/vetting`, { vetted: true, check }, { 'x-operator-token': process.env.VEILCORE_OPERATOR_TOKEN });
    assert.equal(v.status, 200, JSON.stringify(v.json));
  }
  return r;
};
/** A statement message held in a deal: what a receipt points at. */
const heldStatement = async () => {
  const token = randomBytes(16).toString('base64url');
  const dealId = randomBytes(16).toString('hex');
  const hex = () => randomBytes(32).toString('hex');
  const accept = randomBytes(16).toString('base64url');
  const issuer = randomBytes(16).toString('base64url');
  const inv = (await call('POST', '/license-invites', {
    identity: hex(), label: 'x', acceptTokenHash: inviteTokenHash(accept), issuerTokenHash: inviteTokenHash(issuer),
  })).json.id;
  const c = { commitment: hex(), issuerRecord: hex(), licenseeNonce: hex() };
  await call('POST', `/license-invites/${inv}/accept`, { commitHash: commitHashOf(c.commitment, c.issuerRecord, c.licenseeNonce), token: accept });
  await call('POST', `/license-invites/${inv}/nonce`, { issuerNonce: hex(), token: issuer });
  await call('POST', `/license-invites/${inv}/reveal`, { ...c, token: accept });
  await call('POST', '/deals', { dealId, writeTokenHash: dealTokenHash(token), inviteId: inv, token: issuer });
  const m = await call('POST', `/deals/${dealId}/messages`, {
    iv: randomBytes(12).toString('base64url'),
    ct: randomBytes(300).toString('base64url'),
    token,
  });
  return m.json.fingerprint;
};
const receiptFor = (fp, k, over = {}) => ({
  v: RECEIPT_VERSION,
  statementFingerprint: fp,
  statementId: 's1',
  amount: '500.00',
  currency: 'USD',
  payTo: 'acct-123',
  reference: 'PAY-0001',
  paidAt: '2026-10-21T12:00:00.000Z',
  partner: k.hex,
  ...over,
});
const signed = (receipt, k) => ({ receipt, signature: sign(null, receiptBytes(receipt), k.privateKey).toString('hex') });

test('a registered payment partner files a signed receipt, and both sides can read it', async () => {
  const k = partnerKey();
  assert.equal((await register(k, 'payment-partner')).status, 200);
  const fp = await heldStatement();
  const r = receiptFor(fp, k);
  assert.equal((await call('POST', '/payment-receipts', signed(r, k))).json.filed, true);
  assert.equal((await call('POST', '/payment-receipts', signed(r, k))).json.filed, false, 'the same receipt twice is one');
  const got = (await call('GET', `/payment-receipts/${fp}`)).json.receipts;
  assert.equal(got.length, 1);
  assert.deepEqual(got[0].receipt, r);
  assert.deepEqual(got[0].partner, { displayName: 'Example Pay', nameChecked: true });
});

test('refused: a bad signature, a key that is not a payment partner, a statement not held here', async () => {
  const k = partnerKey();
  await register(k, 'payment-partner');
  const fp = await heldStatement();
  const other = partnerKey();
  const bad = { receipt: receiptFor(fp, k), signature: signed(receiptFor(fp, k), other).signature };
  assert.equal((await call('POST', '/payment-receipts', bad)).status, 403);
  // Anyone can register a key as a partner under any name: unchecked, its receipts are refused.
  const unchecked = partnerKey();
  await register(unchecked, 'payment-partner', { vet: false });
  assert.equal((await call('POST', '/payment-receipts', signed(receiptFor(fp, unchecked), unchecked))).status, 403);
  const lab = partnerKey();
  await register(lab, 'laboratory');
  assert.equal((await call('POST', '/payment-receipts', signed(receiptFor(fp, lab), lab))).status, 403);
  const stranger = partnerKey();
  assert.equal((await call('POST', '/payment-receipts', signed(receiptFor(fp, stranger), stranger))).status, 403);
  assert.equal((await call('POST', '/payment-receipts', signed(receiptFor('ab'.repeat(32), k), k))).status, 404);
  // A changed amount no longer matches its signature.
  const s = signed(receiptFor(fp, k), k);
  assert.equal((await call('POST', '/payment-receipts', { ...s, receipt: { ...s.receipt, amount: '5.00' } })).status, 403);
  // A different receipt under the same reference is refused.
  assert.equal((await call('POST', '/payment-receipts', s)).json.filed, true);
  assert.equal((await call('POST', '/payment-receipts', signed(receiptFor(fp, k, { amount: '1.00' }), k))).status, 409);
  assert.equal((await call('POST', '/payment-receipts', signed(receiptFor(fp, k, { extra: 1 }), k))).status, 400);
});
