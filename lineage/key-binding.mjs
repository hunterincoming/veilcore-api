// A record that names its own key (the site's docs/identity-in-record.md, SPEC 3.6.1).
//
// A record sealed since 14 October 2026 carries keyBinding = H(keybind, key, keySalt),
// and its fingerprint is H(keyrecord, keyBinding, SHA-256 of the canonical sealed fields).
// The registry checks only that shape: it never sees the key or the salt, so it can't tell
// (or reveal) which on-chain key a record names. A checker with the link's key and salt
// does that, on its own (the site's veilcore/key-binding.ts).
//
// H is SHA-256 over 32-byte pieces, the first the tag in UTF-8 padded with zeros to 32.
// SPDX-License-Identifier: Apache-2.0

import { createHash } from 'node:crypto';

export const KEY_BOUND_ALGORITHM = 'sha256/key-bound/v1';

const HEX64 = /^[0-9a-f]{64}$/;
export const isHex64 = (v) => typeof v === 'string' && HEX64.test(v);

const tagged = (tag, ...hexParts) => {
  const t = Buffer.alloc(32);
  t.write(tag, 'utf8');
  return createHash('sha256')
    .update(Buffer.concat([t, ...hexParts.map((h) => Buffer.from(h, 'hex'))]))
    .digest('hex');
};

const need = (v, what) => {
  if (!isHex64(v)) throw new Error(`${what} must be 64 lowercase hex characters`);
  return v;
};

/**
 * A field-set record's content hash (SPEC 4.5): H("veilcore:v1:frecord", fieldSetRoot, the
 * SHA-256 of its canonical sealed fields). Only a document record may carry a field set.
 */
export const fieldRecordCommitment = (fieldSetRoot, jsonDigest) =>
  tagged('veilcore:v1:frecord', need(fieldSetRoot, 'fieldSetRoot'), need(jsonDigest, 'the JSON digest'));

/** A bound record's fingerprint, from its keyBinding and the hash of its sealed fields. */
export const keyBoundFingerprint = (keyBinding, contentHash) =>
  tagged('veilcore:v1:keyrecord', need(keyBinding, 'keyBinding'), need(contentHash, 'the content hash'));

/** The key's on-chain identity from its secret: the contract's commit(). For tests and vectors. */
export const identityFromSecret = (secret) => tagged('veilcore:v1:commit', need(secret, 'the record secret'));
export const keySaltOf = (secret) => tagged('veilcore:v1:keysalt', need(secret, 'the record secret'));
export const keyBindingOf = (identity, keySalt) =>
  tagged('veilcore:v1:keybind', need(identity, 'the key'), need(keySalt, "the key's salt"));

/** What a checker does: is this key the one the record with this fingerprint named? */
export const keyMatchesRecord = (identity, { fingerprint, keySalt, contentHash }) =>
  [identity, fingerprint, keySalt, contentHash].every(isHex64) &&
  keyBoundFingerprint(keyBindingOf(identity, keySalt), contentHash) === fingerprint;
