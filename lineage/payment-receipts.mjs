// Payment receipts: a payment partner's signed word that a royalty statement was paid.
//
// VeilCore never moves money. A licensee who pays through a partner (a wallet or payment
// company with its own licences) hands the partner a payment request from the site: the
// statement and the licensor's payout details, each signed by the party who wrote it, so the
// partner pays only the account the licensor named. After paying, the partner signs a
// receipt with its registered key (an attester registered with role "payment-partner";
// lineage/attesters.mjs) and posts it here. Both sides' pages show it under the statement.
//
// What the registry checks before it keeps a receipt:
//   - the signature, over "veilcore/payment-receipt/v1\n" + the canonical receipt, by the
//     key the receipt names (Ed25519; small-order and non-canonical keys refused);
//   - that key is a registered attester whose role is payment-partner, and whose name VeilCore
//     has checked (anyone can register a key under any name);
//   - the statement it names is a message held in a deal here (by fingerprint), so a receipt
//     can't be filed against nothing.
// The registry can't read the statement (it is encrypted for the two parties), so whether
// the amount matches what was owed is for their pages to check, and they do.
//
// SPDX-License-Identifier: Apache-2.0

import { createPublicKey, verify } from 'node:crypto';
import { canonicalise } from 'veilcore-records';
import { unusableKeyReason } from './attesters.mjs';

export const RECEIPT_VERSION = 'veilcore/payment-receipt/v1';
export const PARTNER_ROLE = 'payment-partner';
const HEX64 = /^[0-9a-f]{64}$/;
const SIG = /^[0-9a-f]{128}$/;
const AMOUNT = /^(0|[1-9][0-9]{0,14})(\.[0-9]{1,8})?$/;
const CURRENCY = /^[A-Z0-9]{2,10}$/;
const FIELDS = ['v', 'statementFingerprint', 'statementId', 'amount', 'currency', 'payTo', 'reference', 'paidAt', 'partner'];

/** The bytes a receipt's signature covers. */
export const receiptBytes = (receipt) => Buffer.from(`${RECEIPT_VERSION}\n${canonicalise(receipt)}`, 'utf8');

const keyOf = (hex) =>
  createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(hex, 'hex').toString('base64url') }, format: 'jwk' });

/** What is wrong with a receipt's shape, or null. */
export const receiptProblem = (r) => {
  if (typeof r !== 'object' || r === null || Array.isArray(r)) return 'receipt must be a JSON object';
  const extra = Object.keys(r).filter((k) => !FIELDS.includes(k));
  if (extra.length) return `receipt has fields it should not: ${extra.join(', ')}`;
  if (r.v !== RECEIPT_VERSION) return `receipt.v must be ${RECEIPT_VERSION}`;
  if (typeof r.statementFingerprint !== 'string' || !HEX64.test(r.statementFingerprint)) return 'statementFingerprint must be 64 hex characters';
  if (typeof r.statementId !== 'string' || !r.statementId || r.statementId.length > 64) return 'statementId must be 1 to 64 characters';
  if (typeof r.amount !== 'string' || !AMOUNT.test(r.amount)) return 'amount must be a decimal string, e.g. "500.00"';
  if (typeof r.currency !== 'string' || !CURRENCY.test(r.currency)) return 'currency must be 2 to 10 capital letters or digits';
  if (typeof r.payTo !== 'string' || !r.payTo || r.payTo.length > 200) return 'payTo must be the account paid, 1 to 200 characters';
  if (typeof r.reference !== 'string' || !r.reference || r.reference.length > 120) return 'reference must be the partner’s payment id, 1 to 120 characters';
  if (typeof r.paidAt !== 'string' || Number.isNaN(Date.parse(r.paidAt)) || r.paidAt.length > 40) return 'paidAt must be an ISO 8601 time';
  if (typeof r.partner !== 'string' || !HEX64.test(r.partner)) return 'partner must be the signing key, 64 lowercase hex characters';
  return null;
};

export const createPaymentReceipts = (db, attesters, { now = () => Date.now() } = {}) => {
  db.exec(`
    CREATE TABLE IF NOT EXISTS payment_receipts (
      statement_fingerprint TEXT NOT NULL,
      partner               TEXT NOT NULL,
      reference             TEXT NOT NULL,
      receipt               TEXT NOT NULL,
      signature             TEXT NOT NULL,
      received_at           INTEGER NOT NULL,
      PRIMARY KEY (statement_fingerprint, partner, reference)
    );
  `);
  const st = (sql) => db.prepare(sql);

  return {
    file(body) {
      const { receipt, signature } = body ?? {};
      const problem = receiptProblem(receipt);
      if (problem) return { error: problem };
      if (typeof signature !== 'string' || !SIG.test(signature)) return { error: 'signature must be 128 hex characters' };
      const unusable = unusableKeyReason(receipt.partner);
      if (unusable) return { error: unusable };
      let ok = false;
      try {
        ok = verify(null, receiptBytes(receipt), keyOf(receipt.partner), Buffer.from(signature, 'hex'));
      } catch {
        ok = false;
      }
      if (!ok) return { error: 'the signature does not verify for that partner key', code: 403 };
      const partner = attesters.lookup(receipt.partner);
      if (!partner || partner.role !== PARTNER_ROLE) {
        return { error: `that key is not registered as a ${PARTNER_ROLE}`, code: 403 };
      }
      // Only a partner whose name VeilCore checked (review round 3, H1): anyone can register a
      // key under any name, so an unchecked "partner" could be the payer itself.
      if (partner.vetted !== true) {
        return { error: 'that payment partner’s name has not been checked by VeilCore yet', code: 403 };
      }
      const held = st("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'deal_messages'").get()
        && st('SELECT 1 FROM deal_messages WHERE fingerprint = ?').get(receipt.statementFingerprint);
      if (!held) return { error: 'no statement with that fingerprint is held here', code: 404 };
      const had = st('SELECT receipt, signature FROM payment_receipts WHERE statement_fingerprint = ? AND partner = ? AND reference = ?')
        .get(receipt.statementFingerprint, receipt.partner, receipt.reference);
      if (had) {
        return had.signature === signature ? { filed: false } : { error: 'a different receipt with that reference is already filed', code: 409 };
      }
      st('INSERT INTO payment_receipts (statement_fingerprint, partner, reference, receipt, signature, received_at) VALUES (?,?,?,?,?,?)')
        .run(receipt.statementFingerprint, receipt.partner, receipt.reference, canonicalise(receipt), signature, now());
      return { filed: true };
    },

    /** The receipts for a statement, each with what the registry knows of its partner. */
    forStatement(fingerprint) {
      if (typeof fingerprint !== 'string' || !HEX64.test(fingerprint)) return { error: 'not a fingerprint' };
      const rows = st('SELECT receipt, signature, received_at FROM payment_receipts WHERE statement_fingerprint = ? ORDER BY received_at')
        .all(fingerprint);
      return {
        receipts: rows.map((r) => {
          const receipt = JSON.parse(r.receipt);
          const p = attesters.lookup(receipt.partner);
          return {
            receipt,
            signature: r.signature,
            receivedAt: r.received_at,
            partner: p ? { displayName: p.displayName, nameChecked: p.vetted === true } : null,
          };
        }),
      };
    },
  };
};
