// What the registry tests share: waiting for something to be true (the server finished
// starting, a background job done) by asking until it is, rather than sleeping for a guess
// at how long it takes; and holding the clock still across a burst of requests that a
// per-minute limit counts. Not a test file itself (npm test runs test/*.test.mjs).
//
// Before these, a server start was "ask /health every 50 ms, at most 80 times" and a burst
// counted against a fixed-window limit could straddle the turn of a minute. Both passed on
// an idle machine and failed now and then on a busy one (flaky-test hunt, 15 Oct 2026).
//
// SPDX-License-Identifier: Apache-2.0

import { performance } from 'node:perf_hooks';
import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes } from 'node:crypto';

/**
 * Ask `check` until it returns something truthy, and return that. `within` only turns a
 * hang into a failure that says what never happened: nothing here passes by waiting long
 * enough. Measured on performance.now, so a held clock (inOneMinute) can't stop it.
 */
export const waitFor = async (what, check, { within = 60_000, every = 20 } = {}) => {
  const end = performance.now() + within;
  for (;;) {
    const v = await check();
    if (v) return v;
    if (performance.now() > end) throw new Error(`still not true after ${within / 1000} s: ${what}`);
    await new Promise((r) => setTimeout(r, every));
  }
};

/**
 * The registry at `base` has finished starting: /health is 200, which (server.js) is once
 * every module has loaded. A part that failed to load fails here at once, by name, rather
 * than as a 503 from whichever route a test happens to call first.
 */
export const untilReady = (base, fetchImpl = fetch) =>
  waitFor(`${base}/health to say ready`, async () => {
    const res = await fetchImpl(`${base}/health`);
    if (res.status === 200) return true;
    const body = await res.json().catch(() => ({}));
    if (body.status === 'failed') throw new Error(`the registry did not start: ${JSON.stringify(body)}`);
    return false;
  });

/**
 * Run `fn` with Date.now held at the moment it starts. The registry's limits count per
 * minute (and per day) by Date.now, in fixed windows: a burst that crossed the turn of a
 * minute started counting from zero halfway, and the request a test expected to be
 * refused was let through. Held, the whole burst falls in one window, as it does for the
 * client the limit is meant to stop.
 */
export const inOneMinute = async (fn) => {
  const realNow = Date.now;
  const at = realNow();
  Date.now = () => at;
  try {
    return await fn();
  } finally {
    Date.now = realNow;
  }
};

// ---- sealed records (the site's CONTRACT.md for sealed records) ------------------------
//
// The registry stores a record as its public fields beside `sealed`, an AES-256-GCM box
// the holder's browser makes with a vault key the registry never sees. These do what the
// browser does, with node:crypto, so tests send what the site sends.

/** Fields a record carries outside its box (sealed.js PUBLIC_RECORD_FIELDS). */
const PUBLIC_FIELDS = [
  'id', 'profile', 'recordFingerprint', 'keyBinding', 'supersedes', 'supersededBy',
  'receivedFrom', 'receivedFromCommitment', 'receivedAt', 'transferId', 'attestation',
];

/** A vault key for a test holder: fixed per holder key, so one holder always has one vault. */
export const vaultKeyFor = (holder) =>
  createHash('sha256').update(`veilcore-test-vault:${String(holder).trim().toLowerCase()}`).digest();

/** The vault id: first 16 hex of SHA-256("veilcore:vault-id:v1:" || key). */
export const kidOf = (key) =>
  createHash('sha256').update(Buffer.concat([Buffer.from('veilcore:vault-id:v1:', 'utf8'), key])).digest('hex').slice(0, 16);

/** The AAD a record or licence box is sealed with. */
export const sealedAad = (table, id, kid) => Buffer.from(`veilcore:sealed:v1\0${table}\0${id}\0${kid}`, 'utf8');
/** The AAD an offer box is sealed with. */
export const offerAad = (sourceRecordId, sourceFingerprint) =>
  Buffer.from(`veilcore:offer:v1\0${sourceRecordId}\0${sourceFingerprint ?? ''}`, 'utf8');

/**
 * The size the browser pads a sealed plaintext to (CONTRACT.md #20): the next multiple of
 * 1 KiB up to 16 KiB, then of 8 KiB, never past the 256 KiB the browser allows.
 */
export const paddedSize = (bytes) => {
  const K = 1024;
  const to = bytes <= 16 * K ? Math.ceil(bytes / K) * K : Math.ceil(bytes / (8 * K)) * 8 * K;
  return Math.max(Math.min(to, 256 * K), bytes);
};
const seal = (value, key, aad, { pad = false } = {}) => {
  const iv = randomBytes(12);
  const c = createCipheriv('aes-256-gcm', key, iv);
  c.setAAD(aad);
  let text = Buffer.from(JSON.stringify(value), 'utf8');
  // Padded with spaces after the JSON, which JSON.parse ignores: the registry can't tell.
  if (pad) text = Buffer.concat([text, Buffer.alloc(paddedSize(text.length) - text.length, 0x20)]);
  const ct = Buffer.concat([c.update(text), c.final(), c.getAuthTag()]);
  return { iv: iv.toString('base64url'), ct: ct.toString('base64url') };
};
const open = (box, key, aad) => {
  const ct = Buffer.from(box.ct, 'base64url');
  const d = createDecipheriv('aes-256-gcm', key, Buffer.from(box.iv, 'base64url'));
  d.setAAD(aad);
  d.setAuthTag(ct.subarray(ct.length - 16));
  return JSON.parse(Buffer.concat([d.update(ct.subarray(0, ct.length - 16)), d.final()]).toString('utf8'));
};

/**
 * A record (or, with table "licenses", a licence) as the browser sends it. A record keeps
 * its public fields in the clear (since round 5 not its name: that is sealed too) (`supersedes` only as recordId, changedFields,
 * effectiveAt) and seals everything else, the full `supersedes` included. A licence is
 * { id, sealed } with everything but its id inside. `inside` names public fields sealed instead
 * (a copy of a record another holder dated keeps its proof code inside: lab-result-copy.test.mjs).
 */
export const sealForTest = (record, key, table = 'records', { pad = false, inside: sealedToo = [] } = {}) => {
  const kid = kidOf(key);
  if (table === 'licenses') {
    const { id, ...inside } = record;
    return { id, sealed: { v: 1, alg: 'A256GCM', kid, ...seal(inside, key, sealedAad('licenses', id, kid), { pad }) } };
  }
  const out = {};
  const inside = {};
  for (const [k, v] of Object.entries(record)) {
    if (k === 'sealed') continue;
    if (PUBLIC_FIELDS.includes(k) && k !== 'supersedes' && !sealedToo.includes(k)) out[k] = v;
    else inside[k] = v;
  }
  if (record.supersedes && typeof record.supersedes === 'object') {
    const { recordId, changedFields, effectiveAt } = record.supersedes;
    out.supersedes = {
      recordId,
      ...(changedFields !== undefined ? { changedFields } : {}),
      ...(effectiveAt !== undefined ? { effectiveAt } : {}),
    };
  }
  out.sealed = { v: 1, alg: 'A256GCM', kid, ...seal(inside, key, sealedAad('records', record.id, kid), { pad }) };
  return out;
};

/** A stored row opened again: its public fields and what was sealed, as one record. */
export const openForTest = (row, key, table = 'records') => {
  if (!row?.sealed) return row;
  const inside = open(row.sealed, key, sealedAad(table, row.id, row.sealed.kid));
  const { sealed, ...pub } = row;
  return { ...pub, ...inside };
};

/** A sealed offer for POST /transfers: { v, alg, iv, ct } under the delivery code's offer key. */
export const sealOfferForTest = (offer, offerKey, sourceRecordId, sourceFingerprint) =>
  ({ v: 1, alg: 'A256GCM', ...seal(offer, offerKey, offerAad(sourceRecordId, sourceFingerprint)) });
export const openOfferForTest = (box, offerKey, sourceRecordId, sourceFingerprint) =>
  open(box, offerKey, offerAad(sourceRecordId, sourceFingerprint));
/**
 * A delivery's sample details as the site seals them (CONTRACT.md #27): each side under the
 * delivery's offer key, AAD "veilcore:sealed:v1\0custody\0<transferId>\0<side>", kid the
 * first 16 hex of SHA-256("veilcore:offer-id:v1:" || offer key). The sender's side carries a
 * salt (32 random bytes, base64url) beside its fields.
 */
export const offerKidOf = (offerKey) =>
  createHash('sha256').update(Buffer.concat([Buffer.from('veilcore:offer-id:v1:', 'utf8'), offerKey])).digest('hex').slice(0, 16);
export const custodyAad = (transferId, side) => Buffer.from(`veilcore:sealed:v1\0custody\0${transferId}\0${side}`, 'utf8');
export const sealCustodyForTest = (value, offerKey, transferId, side) =>
  ({ v: 1, alg: 'A256GCM', kid: offerKidOf(offerKey), ...seal(value, offerKey, custodyAad(transferId, side)) });
export const openCustodyForTest = (box, offerKey, transferId, side) => open(box, offerKey, custodyAad(transferId, side));

/** The offer key the request wrapper below uses for a source record. */
export const offerKeyFor = (sourceRecordId) => createHash('sha256').update(`veilcore-test-offer:${sourceRecordId}`).digest();

/**
 * A recipient handle as the browser sends it (CONTRACT.md #15): lowercase hex
 * HMAC-SHA256(key = the vault key, msg = "veilcore:handle:v1\0" + handle, NFC, trimmed,
 * lower case). The registry stores this tag and never the name.
 */
export const handleTagFor = (holder, handle) => createHmac('sha256', vaultKeyFor(holder))
  .update(`veilcore:handle:v1\0${String(handle).normalize('NFC').trim().toLowerCase()}`, 'utf8')
  .digest('hex');
const HANDLE_TAG = /^[0-9a-f]{64}$/;

class Plain { constructor(body) { this.body = body; } }
/** A body sent exactly as given: testBody leaves it alone (for tests of what is refused). */
export const plain = (body) => new Plain(body);

/**
 * What a test's request helper sends: a body as the sealing site would send it. Records
 * and licences without `sealed` are sealed under the holder's test vault (vaultKeyFor);
 * an offer without `sealedOffer` has its quantity and note moved into one, under
 * offerKeyFor(sourceRecord). The registry can't check what an AAD names, so the offer's
 * is bound to the source id only; transfer-sealed.test.mjs binds both, as the site does.
 * An offer's `toHandle` written as a name is sent as its tag (handleTagFor), as the site
 * does since round 2.
 */
export const testBody = (method, path, holder, body) => {
  if (body instanceof Plain) return body.body;
  if (method === 'POST' && path === '/transfers' && body && typeof body === 'object' && holder
    && typeof body.toHandle === 'string' && !HANDLE_TAG.test(body.toHandle)) {
    body = { ...body, toHandle: handleTagFor(holder, body.toHandle) };
  }
  if (method === 'PUT' && (path === '/api/records' || path === '/api/licenses') && Array.isArray(body) && holder) {
    const table = path === '/api/records' ? 'records' : 'licenses';
    const key = vaultKeyFor(holder);
    return body.map((item) => (item && typeof item === 'object' && !Array.isArray(item) && typeof item.id === 'string' && !item.sealed
      ? sealForTest(item, key, table)
      : item));
  }
  if (method === 'POST' && path === '/transfers' && body && typeof body === 'object' && body.sealedOffer === undefined
    && typeof body.sourceRecord === 'string') {
    const { quantity, note, ...rest } = body;
    return {
      ...rest,
      sealedOffer: sealOfferForTest({ quantity: quantity ?? null, note: note ?? null }, offerKeyFor(body.sourceRecord), body.sourceRecord, ''),
    };
  }
  return body;
};

const LEGACY_KEYS = {
  own: 'existence', dna: 'attestation-status', lineage: 'descent-clean', sealed: 'sealed-at',
  parents: 'parent-names', method: 'breeding-method', individualId: 'individual-id',
};
/**
 * A grant body as the site sends it (disclosure.ts saveGrant): the keys, the fingerprint of
 * the record the values are read from, and for each granted key the values it publishes.
 */
export const grantForTest = (record, show) => {
  const keys = new Set(show.map((k) => LEGACY_KEYS[k] ?? k));
  const values = {};
  if (keys.has('sealed-at') && record.loggedAt !== undefined) values.loggedAt = record.loggedAt;
  if (keys.has('parent-names')) {
    values.parents = (record.parents ?? []).map((p) => ({
      name: p.name ?? '',
      ...(p.role !== undefined ? { role: p.role } : {}),
      ...(p.individualId !== undefined ? { individualId: p.individualId } : {}),
    }));
  }
  if (keys.has('breeding-method') && record.breedingMethod !== undefined) values.breedingMethod = record.breedingMethod;
  if (keys.has('individual-id')) {
    if (typeof record.refId === 'string') values.individualId = record.refId;
    if (typeof record.animal?.idScheme === 'string') values.idScheme = record.animal.idScheme;
  }
  if (keys.has('attestation-status')) {
    // Round 5 (CONTRACT.md #29): only the bound form, as the site sends it.
    const sha = record.dnaFileSha256 ?? record.dnaFingerprint;
    if (sha !== undefined) values.dnaPairBinding = dnaPairBindingForTest(sha, pairIdentityFor(record), pairSaltFor(record));
  }
  if (keys.has('name') && typeof record.strainName === 'string') values.name = record.strainName;
  if (keys.has('bred-by') && typeof record.bredBy === 'string') values.bredBy = record.bredBy;
  return { show, forFingerprint: record.recordFingerprint ?? null, values };
};

/**
 * The bound form of a DNA report (round 5, CONTRACT.md #29; the site's chain/pairing.ts
 * dnaPairBinding): SHA-256 of the tag "veilcore:v1:dnapair" zero-padded to 32 bytes, then
 * the report's SHA-256, the record's identity and its pairing salt, 32 bytes each.
 */
export const dnaPairBindingForTest = (reportSha256, identity, salt) => {
  const tag = Buffer.alloc(32);
  tag.write('veilcore:v1:dnapair', 'utf8');
  return createHash('sha256')
    .update(Buffer.concat([tag, Buffer.from(reportSha256, 'hex'), Buffer.from(identity, 'hex'), Buffer.from(salt, 'hex')]))
    .digest('hex');
};
/**
 * A test record's identity and pairing salt. The identity is the record's proof code (its
 * fingerprint), as the site binds it; the salt is fixed per record id unless the record names one.
 */
export const pairIdentityFor = (record) => record.recordFingerprint;
export const pairSaltFor = (record) => record.dnaPairSalt
  ?? createHash('sha256').update(`veilcore-test-pair-salt:${record.id}`).digest('hex');

/** What a sender's browser puts in a sealed offer (CONTRACT.md #8), from the source record. */
export const offerFromRecord = (src, { quantity = null, note = null } = {}) => ({
  strainName: src.strainName,
  bredBy: src.bredBy,
  dateCreated: src.dateCreated,
  ...(src.profile !== undefined ? { profile: src.profile } : {}),
  ...(src.taxon !== undefined ? { taxon: src.taxon } : {}),
  refId: src.profile === 'veilcore/profile/animal-individual/v1' && typeof src.refId === 'string' ? src.refId : '',
  ...(src.animal ? { animal: { breed: src.animal.breed ?? '', idScheme: src.animal.idScheme ?? '', sex: src.animal.sex ?? 'unknown' } } : {}),
  quantity,
  note,
});

/**
 * A lab's first report on a delivery with no receipt carries its key's proof (12 Nov 2026,
 * lineage/lab-results.mjs labKeyProofText): the signing key's Ed25519 signature over the
 * delivery and signature ids, as the x-lab-key-proof header. Tests that sign a report remember
 * its key here (rememberSigner); an upload then adds the header for it (labKeyProofHeader).
 */
const signersById = new Map();
export const rememberSigner = (attestationId, kp) => { signersById.set(attestationId, kp); };
export const labKeyProof = async (kp, transferId, attestationId) => {
  const { labKeyProofText } = await import('../lineage/lab-results.mjs');
  const priv = await crypto.subtle.importKey('pkcs8', Buffer.from(kp.privateKey, 'hex'), { name: 'Ed25519' }, false, ['sign']);
  const sig = await crypto.subtle.sign('Ed25519', priv, new TextEncoder().encode(labKeyProofText(transferId, attestationId)));
  return Buffer.from(sig).toString('hex');
};
export const labKeyProofHeader = async (transferId, attestationId) => {
  const kp = signersById.get(attestationId);
  return kp ? { 'x-lab-key-proof': await labKeyProof(kp, transferId, attestationId) } : {};
};
