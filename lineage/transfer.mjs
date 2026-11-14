// Transferring a record between holders.
//
// The moment material changes hands is where provenance is actually established or
// lost. Everything upstream is a breeder's own claim; a transfer is the first point a
// second party is involved, which is what makes the record evidence rather than a note.
//
// A transfer never moves a record. The original stays with the sender, permanently. The
// recipient receives a NEW record that declares the original as its parent — which is
// exactly what happened physically: they hold different material, descended from the
// same source.
//
// SPDX-License-Identifier: Apache-2.0

import { createHash, timingSafeEqual } from 'node:crypto';
import { canonicalise } from 'veilcore-records';
import { partyId } from './routes.mjs';
import { isAnimal } from './animal-profile.mjs';
import { isStrain } from './strain-profile.mjs';
// Holder keys are stored as digests (deep dive, 8 Oct 2026); functions here take the key as
// sent (the claimant's party id is derived from it) and store and compare its digest.
import holderKeys from '../holder-key.js';
// What a sealed offer looks like, and whether a stored record is sealed (sealed.js).
import sealedRows from '../sealed.js';

/**
 * A claim code as stored: its SHA-256, never the code (found by the sealed-records contract
 * test, 16 Oct 2026: the code was in the database file as sent, so a copy of the file, or an
 * off-site backup of it, could claim every open delivery). The code is 128 random bits, so a
 * plain digest is enough. Rows written before keep the code itself and still match.
 */
const CLAIM_DIGEST = 'sha256:';
const claimCodeStored = (code) => `${CLAIM_DIGEST}${createHash('sha256').update(String(code)).digest('hex')}`;
const claimCodeMatches = (stored, given) => {
  if (typeof stored !== 'string' || typeof given !== 'string' || !given) return false;
  const want = Buffer.from(stored.startsWith(CLAIM_DIGEST) ? stored : claimCodeStored(stored));
  const got = Buffer.from(claimCodeStored(given));
  return want.length === got.length && timingSafeEqual(want, got);
};

const { storedHolderKey, asStored, migrateHolderKeys } = holderKeys;
const { sealedProblem, boxOf, isSealedBody, OFFER_MAX_BYTES, CUSTODY_CT_MAX, HANDLE_TAG, HANDLE_TAG_PROBLEM, KNOWN_PROFILES } = sealedRows;

const randomHex = (bytes) =>
  [...crypto.getRandomValues(new Uint8Array(bytes))].map((b) => b.toString(16).padStart(2, '0')).join('');

/**
 * The received record's id. Random, 128 bits, chosen here.
 *
 * It used to be `${source}-R${transferId.slice(3, 7)}`, both halves of which the public
 * pending list handed out. Anyone could store a record under that id first, and the
 * recipient's claim then failed on the primary key, every time, forever (attack round 11).
 */
const receivedRecordId = () => `VEIL-${randomHex(16).toUpperCase()}`;

const MAX = { quantity: 200, note: 2000 };
/** A terms hash (round 2, P7: it was any text of up to 128 characters): SHA-256, lowercase hex. */
const TERMS_HASH = /^[0-9a-f]{64}$/;

/**
 * Open offers (deep dive, 8 Oct 2026, MEDIUM). Any number could be made to one handle, and
 * the public pending list returned them all. Counted per sender and handle together: a cap
 * per handle alone (round 1) let anyone fill a recipient's handle with junk and block every
 * real sender to it for a month (round 2). One sender may have 20 open offers to one
 * handle and 200 in all. Only offers from the last 30 days count; older ones stay
 * claimable with their code. Since sealed records round 2 the handle is a tag the sender's
 * browser makes from the name (sealed.js HANDLE_TAG), the same tag for the same name and
 * vault key, so the count per sender and handle works on it unchanged.
 */
export const OFFER_LIMITS = { perSenderAndHandle: 20, perSender: 200, windowMs: 30 * 86_400_000 };
/** The sender's list, a page at a time. (The public pending list was removed in round 2.) */
export const TRANSFER_PAGE = { sent: { default: 500, max: 1000 } };
const pageOf = ({ limit, offset } = {}, { default: d, max }) => ({
  limit: Math.min(Math.max(Number.parseInt(limit, 10) || d, 1), max),
  offset: Math.max(Number.parseInt(offset, 10) || 0, 0),
});
const tooLong = (v, n) => v !== undefined && v !== null && (typeof v !== 'string' || v.length > n);

// ---- the sample's chain of custody -----------------------------------------------------
//
// Disputes over a lab result turn on the sample, not the chemistry: which tube, sealed how,
// taken from which plant, and whether what arrived is what left. The breeder writes down
// the label and seal when making the lab code (`sample`); the lab confirms or corrects
// each on arrival (`arrival`). Both are optional, plain text, and checked only for shape:
// VeilCore doesn't check a witness or a seal, it records what each side wrote.
//
// The lab's signed receipt covers them. Its signed fields are fixed (veilcore-records
// attestationPayload), and its subject and document must stay this delivery's two
// fingerprints (receiptProblem), so they are carried in the one signed field the signer
// chooses, its id: `att_<16 hex>_sc1_<custodyDigest>`. A receipt with no such suffix (every
// receipt made before this) is checked exactly as before.
//
// Sealed since round 3 of sealed records (the site's CONTRACT.md #27). On a delivery made
// with a sealed offer, each side is a box sealed with the delivery's offer key (the sender
// made it; the lab has it from the lab code), which this registry never receives:
// { v: 1, alg: "A256GCM", kid, iv, ct }, AAD "veilcore:sealed:v1\0custody\0<transferId>\0<side>",
// kid the first 16 hex of SHA-256("veilcore:offer-id:v1:" || offer key). The sender's box
// also holds a 32-byte salt. The lab's receipt then carries custodyDigestV2 (below) as
// `att_<16 hex>_sc2_<digest>`, which this registry can't recompute: it checks each box's
// shape and size only, and the holder's app does the comparing. Deliveries made before
// (no sealed offer) keep plain fields and `_sc1_` receipts, checked as before.

const DATE = /^\d{4}-\d{2}-\d{2}$/;
/** Each side's fields and their limits. A date is YYYY-MM-DD. */
export const CUSTODY_FIELDS = {
  sample: { sampleId: 120, sealNumber: 120, takenFrom: 300, takenOn: 'date', witness: 200 },
  arrival: { sampleId: 120, sealNumber: 120, sealIntact: ['yes', 'no', 'no-seal'], arrivedOn: 'date', condition: 1000, labRef: 200 },
};

/** A real calendar day: 2026-02-31 is refused, not read as 3 March. */
export const isCalendarDate = (t) => {
  if (typeof t !== 'string' || !DATE.test(t)) return false;
  const [y, m, d] = t.split('-').map(Number);
  const at = new Date(Date.UTC(y, m - 1, d));
  return at.getUTCFullYear() === y && at.getUTCMonth() === m - 1 && at.getUTCDate() === d;
};

/**
 * Control and format characters (Unicode Cc, Cf: tabs, line breaks, direction marks such as
 * U+202E and U+2066 to U+2069, zero-width characters) and the line and paragraph separators.
 * Round 2 of the 15 Oct review: a line break in a witness or a lab's condition added lines of
 * its own to the declaration a breeder may sign, and a direction mark reversed the text
 * around it. Refused in every field; `condition` alone may have plain line breaks.
 */
const HIDDEN = /[\p{Cc}\p{Cf}\u2028\u2029]/u;

/**
 * One field's value as stored, or { error }. The site's transfers.ts custodyValue is the
 * same function (its sample-custody.test.ts and this registry's test share vectors): the
 * receipt's digest is over these values, so the two must agree to the character.
 *   - every field: trimmed, then NFC;
 *   - `condition`: CR LF and CR become LF, spaces at line ends go, three or more line
 *     breaks become two, before the trim;
 *   - then refused if it has a hidden character (above; LF allowed in `condition`), is too
 *     long, is not a real date (a date field) or is not one of the choices.
 */
export const custodyValue = (side, k, v) => {
  const limit = CUSTODY_FIELDS[side]?.[k];
  if (limit === undefined) return { error: `${side}.${k} is not a field here` };
  if (typeof v !== 'string') return { error: `${side}.${k} must be a string` };
  let t = v;
  if (k === 'condition') {
    t = t.replace(/\r\n?/g, '\n').split('\n').map((l) => l.trimEnd()).join('\n').replace(/\n{3,}/g, '\n\n');
  }
  t = t.trim().normalize('NFC');
  if (!t) return { value: '' };
  if (HIDDEN.test(k === 'condition' ? t.replace(/\n/g, '') : t)) {
    return {
      error: k === 'condition'
        ? `${side}.${k} can’t contain tabs or hidden characters (such as direction marks or zero-width spaces)`
        : `${side}.${k} can’t contain line breaks, tabs or hidden characters (such as direction marks or zero-width spaces)`,
    };
  }
  if (limit === 'date') {
    if (!isCalendarDate(t)) return { error: `${side}.${k} must be a real date, YYYY-MM-DD` };
  } else if (Array.isArray(limit)) {
    if (!limit.includes(t)) return { error: `${side}.${k} must be one of ${limit.join(', ')}` };
  } else if (t.length > limit) {
    return { error: `${side}.${k} must be at most ${limit} characters` };
  }
  return { value: t };
};

/**
 * One side's fields, normalised (custodyValue), empty ones dropped; or { error }. Unknown
 * fields are refused, so a misspelt one isn't silently lost.
 */
export const custodyFields = (side, input) => {
  const spec = CUSTODY_FIELDS[side];
  if (input === undefined || input === null) return { fields: {} };
  if (typeof input !== 'object' || Array.isArray(input)) return { error: `${side} must be an object` };
  const out = {};
  for (const [k, v] of Object.entries(input)) {
    if (spec[k] === undefined) return { error: `${side}.${k} is not a field here; the fields are ${Object.keys(spec).join(', ')}` };
    if (v === undefined || v === null) continue;
    const r = custodyValue(side, k, v);
    if (r.error) return { error: r.error };
    if (r.value) out[k] = r.value;
  }
  return { fields: out };
};

/** Compare as a person reads them: spacing and letter case aside (the site's custody.ts `same`). */
const same = (a, b) => a.replace(/\s+/g, ' ').trim().toLowerCase() === b.replace(/\s+/g, ' ').trim().toLowerCase();

/**
 * Where what arrived differs from what was sent, one plain line each, saying what each side
 * wrote and nothing about why: "Seal number differs: sent 4471, received 4417". The site's
 * custody.ts custodyDifferences, word for word (both test the same vectors).
 */
export const custodyDifferences = (sample = {}, arrival = {}) => {
  const out = [];
  const pair = (label, sent, got) => {
    if (sent && got && !same(sent, got)) out.push(`${label} differs: sent ${sent}, received ${got}`);
    else if (sent && !got) out.push(`${label} not confirmed on arrival (sent ${sent})`);
  };
  pair('Sample ID', sample.sampleId, arrival.sampleId);
  if (arrival.sealIntact === 'no-seal') {
    if (sample.sealNumber) out.push(`No seal on arrival (sent with seal ${sample.sealNumber})`);
  } else {
    pair('Seal number', sample.sealNumber, arrival.sealNumber);
  }
  if (arrival.sealIntact === 'no') out.push('Seal not intact on arrival');
  return out;
};

/**
 * The digest a receipt's id carries: SHA-256 of the canonical JSON (veilcore-records
 * canonicalise) of what the lab signed for. The site's transfers.ts custodyDigest is the
 * same function; they must agree.
 */
export const custodyDigest = (transferId, sample = {}, arrival = {}) =>
  createHash('sha256')
    .update(canonicalise({ format: 'veilcore/sample-custody/v1', transferId, sample, arrival }), 'utf8')
    .digest('hex');

/** The custody digest an `_sc1_` receipt's id carries, or null for a receipt without one. */
export const receiptCustodyDigest = (attestationId) =>
  /_sc1_([0-9a-f]{64})$/.exec(typeof attestationId === 'string' ? attestationId : '')?.[1] ?? null;

/**
 * The sealed form's digest (CONTRACT.md #27): SHA-256 of the canonical JSON of
 * { format: "veilcore/sample-custody/v2", transferId, salt, sample, arrival }, with each side
 * normalised as custodyFields stores it (the salt is not one of the sample's fields). The
 * salt is 32 random bytes the sender sealed with the sample, so the digest can't be found by
 * trying likely values. The site's transfers.ts custodyDigestV2 is the same function. This
 * registry never computes it for a delivery (it can't open the boxes); the tests and the
 * shared vectors do.
 */
export const custodyDigestV2 = (transferId, salt, sample = {}, arrival = {}) =>
  createHash('sha256')
    .update(canonicalise({ format: 'veilcore/sample-custody/v2', transferId, salt, sample, arrival }), 'utf8')
    .digest('hex');

/** Which digest a receipt's id carries: { format: 1 | 2, digest }, or null for none. */
export const receiptCustodyOf = (attestationId) => {
  const m = /_sc([12])_([0-9a-f]{64})$/.exec(typeof attestationId === 'string' ? attestationId : '');
  return m ? { format: Number(m[1]), digest: m[2] } : null;
};

/** A salt as the sealed sample carries it: 32 bytes, base64url without padding. */
export const CUSTODY_SALT = /^[A-Za-z0-9_-]{43}$/;

const BOX_KEYS = ['v', 'alg', 'kid', 'iv', 'ct'];
/**
 * Whether a side was sent as a sealed box rather than plain fields: it has any key of a box.
 * No plain field is named like one, so a box with a missing part is checked (and refused) as
 * a box, never stored as fields.
 */
export const isCustodyBox = (v) =>
  typeof v === 'object' && v !== null && !Array.isArray(v) && Object.keys(v).some((k) => BOX_KEYS.includes(k));

/** Why a side's box is not one this registry stores, or null: shape, and ct at most CUSTODY_CT_MAX. */
export const custodyBoxProblem = (side, box) => sealedProblem(box, { withKid: true, name: side, ctMax: CUSTODY_CT_MAX });

const plainRefused = (side) =>
  `this delivery's sample details are sealed: send ${side} as a box sealed with the delivery's offer key ({ v, alg, kid, iv, ct }), never as plain fields`;

const parsed = (json) => {
  if (typeof json !== 'string') return {};
  try {
    const v = JSON.parse(json);
    return v && typeof v === 'object' && !Array.isArray(v) ? v : {};
  } catch {
    return {};
  }
};
const stored = (fields) => (Object.keys(fields).length ? JSON.stringify(fields) : null);
/** A stored box, or null. */
const boxIn = (json) => {
  const v = parsed(json);
  return Object.keys(v).length ? v : null;
};
/**
 * Each side as stored: the sealed box when there is one, else the plain fields of a delivery
 * made before sealing ({} when nothing was written).
 */
const sidesOf = (t) => ({
  sample: boxIn(t.sample_custody_sealed) ?? parsed(t.sample_custody),
  arrival: boxIn(t.arrival_custody_sealed) ?? parsed(t.arrival_custody),
});
/** A delivery made with a sealed offer: its sample details are sealed too, never plain. */
const sealedDelivery = (t) => typeof t.offer_sealed === 'string';
const hasSealedCustody = (t) => typeof t.sample_custody_sealed === 'string' || typeof t.arrival_custody_sealed === 'string';

/**
 * For a code made before sealing, from a source still in plain text: the same fields a
 * sealed offer carries, from the sender's record. An allow-list, not a spread of the
 * sender's body (attack round D): private notes, the breeding method, parents and the DNA
 * report fingerprint stay with the sender. A sample of an animal names the animal (its
 * individual ID and scheme, breed and sex), so the lab's record says which animal it is
 * from; its herd and pedigree stay with the sender. Given by the claim, and again to the
 * claimant by offerFor.
 */
const plainOfferOf = (src, t) => ({
  strainName: src.strainName,
  bredBy: src.bredBy,
  dateCreated: src.dateCreated,
  ...(src.profile !== undefined ? { profile: src.profile } : {}),
  ...(src.taxon !== undefined ? { taxon: src.taxon } : {}),
  refId: (isAnimal(src) || isStrain(src)) && typeof src.refId === 'string' ? src.refId : '',
  ...(isStrain(src)
    ? {
        strain: {
          group: typeof src.strain?.group === 'string' ? src.strain.group : 'other',
          deposits: Array.isArray(src.strain?.deposits) ? src.strain.deposits.filter((d) => typeof d === 'string').slice(0, 8) : [],
          generation: typeof src.strain?.generation === 'string' ? src.strain.generation : '',
        },
      }
    : {}),
  ...(isAnimal(src)
    ? {
        animal: {
          breed: typeof src.animal?.breed === 'string' ? src.animal.breed : '',
          idScheme: typeof src.animal?.idScheme === 'string' ? src.animal.idScheme : '',
          sex: typeof src.animal?.sex === 'string' ? src.animal.sex : 'unknown',
        },
      }
    : {}),
  quantity: t.quantity ?? null,
  note: t.note ?? null,
});

export const createTransfers = (db, lineage, { maxRecords = 10_000, maxBytes = 16 * 1024 * 1024 } = {}) => {
  db.exec(`
    CREATE TABLE IF NOT EXISTS transfers (
      id            TEXT PRIMARY KEY,
      source_record TEXT NOT NULL,
      from_holder   TEXT NOT NULL,
      to_handle     TEXT NOT NULL,
      -- The sender hands this to the recipient out of band. Without it a transfer was
      -- claimable by anyone holding its id, and ids are enumerable: /transfers/pending
      -- is public. Nullable so transfers created before this existed stay claimable.
      claim_code    TEXT,
      claimed_by    TEXT,
      claimed_at    INTEGER,
      created_at    INTEGER NOT NULL,
      terms_hash    TEXT,
      quantity      TEXT,
      note          TEXT
    );
    CREATE INDEX IF NOT EXISTS transfers_handle ON transfers(to_handle);
  `);

  // CREATE TABLE IF NOT EXISTS does not alter a table that already exists, so a
  // database created before claim_code existed needs the column added. Transfers
  // predating it keep a null code and stay claimable without one — refusing them
  // would strand material somebody is waiting for.
  const cols = db.prepare('PRAGMA table_info(transfers)').all().map((c) => c.name);
  if (!cols.includes('claim_code')) {
    db.prepare('ALTER TABLE transfers ADD COLUMN claim_code TEXT').run();
  }
  migrateHolderKeys(db);

  // The source record's fingerprint when the offer was made (deep dive, 8 Oct 2026, LOW).
  // A claimed transfer is the sender's consent to a descent edge, and it was read against
  // whatever the source record id held NOW: the sender could change the record, or delete
  // it and let someone else store a record under the id, and the consent moved with it.
  if (!cols.includes('source_fingerprint')) db.exec('ALTER TABLE transfers ADD COLUMN source_fingerprint TEXT');
  db.exec('CREATE INDEX IF NOT EXISTS transfers_from ON transfers(from_holder)');

  // The record a claim created (round 2, MEDIUM). A claimed transfer is the sender's
  // consent to ONE descent edge: from what they sent to what the recipient received. It
  // was read as consent for any record the recipient held. Set when a claim is made; for
  // a claim made before this (or by an older version), found from the record carrying the
  // transfer's id, on every start, for any row still without one.
  if (!db.prepare("SELECT 1 FROM pragma_table_info('transfers') WHERE name = 'received_record'").get()) {
    db.exec('ALTER TABLE transfers ADD COLUMN received_record TEXT');
  }
  // The lab's signed receipt for this delivery (round 3): the id of a chain-of-custody
  // attestation about exactly what this delivery handed over, attached by the lab that
  // claimed it (attachReceipt below). The sender's page reads it.
  if (!db.prepare("SELECT 1 FROM pragma_table_info('transfers') WHERE name = 'receipt_attestation_id'").get()) {
    db.exec('ALTER TABLE transfers ADD COLUMN receipt_attestation_id TEXT');
  }
  // The sample's chain of custody: what the breeder wrote on sending, what the lab wrote
  // on arrival (custodyFields above), as JSON; null when nothing was written.
  for (const col of ['sample_custody', 'arrival_custody']) {
    if (!db.prepare('SELECT 1 FROM pragma_table_info(\'transfers\') WHERE name = ?').get(col)) {
      db.exec(`ALTER TABLE transfers ADD COLUMN ${col} TEXT`);
    }
  }
  // The offer itself, sealed (sealed records, CONTRACT.md #8): what the recipient is told
  // about the material, locked with a key that travels only in the delivery code, so this
  // registry holds it and can't read it. Null for offers made before.
  if (!db.prepare("SELECT 1 FROM pragma_table_info('transfers') WHERE name = 'offer_sealed'").get()) {
    db.exec('ALTER TABLE transfers ADD COLUMN offer_sealed TEXT');
  }
  // The sample details, sealed (CONTRACT.md #27): each side's box as JSON, null when that side
  // wrote nothing. custody_removed: the purge's two-flag run removed this delivery's plain
  // sample details (scripts/purge-plaintext.mjs), so a receipt over them can't be compared.
  for (const col of ['sample_custody_sealed', 'arrival_custody_sealed', 'custody_removed']) {
    if (!db.prepare('SELECT 1 FROM pragma_table_info(\'transfers\') WHERE name = ?').get(col)) {
      db.exec(`ALTER TABLE transfers ADD COLUMN ${col} ${col === 'custody_removed' ? 'INTEGER' : 'TEXT'}`);
    }
  }
  db.exec("CREATE INDEX IF NOT EXISTS records_transfer ON records(json_extract(body, '$.transferId'))");
  db.prepare(`UPDATE transfers SET received_record = (
      SELECT r.id FROM records r
      WHERE json_extract(r.body, '$.transferId') = transfers.id AND r.holder_key = transfers.claimed_by LIMIT 1)
    WHERE claimed_by IS NOT NULL AND received_record IS NULL`).run();
  // source_fingerprint for any row without one, on every start (round 2): rows from before
  // the column, and offers older code made during a rollback. A claimed transfer takes it
  // from the record its claim created (what the recipient received); an open one from the
  // source as it is now (what a claim takes). A row still without one (an unsealed source)
  // takes it at claim time.
  db.prepare(`UPDATE transfers SET source_fingerprint = (
      SELECT json_extract(c.body, '$.receivedFromCommitment') FROM records c
      WHERE c.id = transfers.received_record AND c.holder_key = transfers.claimed_by)
    WHERE claimed_by IS NOT NULL AND source_fingerprint IS NULL AND received_record IS NOT NULL`).run();
  db.prepare(`UPDATE transfers SET source_fingerprint = (
      SELECT json_extract(r.body, '$.recordFingerprint') FROM records r
      WHERE r.id = transfers.source_record AND r.holder_key = transfers.from_holder)
    WHERE claimed_by IS NULL AND source_fingerprint IS NULL`).run();

  const newId = () =>
    'TR-' + [...crypto.getRandomValues(new Uint8Array(4))].map((b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();

  const tableExists = (name) => !!db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?").get(name);

  /**
   * Why an attestation can't be this delivery's signed receipt, or null when it can.
   *
   * The site's lab page signs a receipt over two values (custodySubject in the app's
   * transfers.ts, signed by ClaimTransfer.tsx): the source record's fingerprint as the
   * subject, and the fingerprint of the record the lab's claim created as the document. Both
   * are checked here against what this registry holds for this delivery: the fingerprint
   * the offer was made and claimed with (source_fingerprint), the received record's own
   * receivedFromCommitment, and that record's sealed fingerprint, read from the claimant's
   * own set. An attestation about another plant, or about another delivery of the same
   * plant (another lab's received record), fails one of them.
   *
   * Not checked, because the registry can't: who holds the key that signed it. Attester
   * keys are not tied to holder keys anywhere, so an attestation by any key that signed
   * over exactly this delivery's two values passes; the page shows which key signed it.
   * The other things custodySubject looks at (the record ids, cultivar, quantity, and the
   * source's public fingerprint at the moment of signing) are not part of what is signed.
   */
  const receiptProblem = (t, attestationId) => {
    // Any id /attestations accepts: a string of 1 to 200 characters.
    if (typeof attestationId !== 'string' || attestationId.length === 0 || attestationId.length > 200) {
      return { error: 'attestationId is not valid', code: 400 };
    }
    const row = tableExists('attestations')
      ? db.prepare('SELECT body FROM attestations WHERE attestation_id = ?').get(attestationId)
      : undefined;
    if (!row) return { error: 'no such attestation', code: 404 };
    const a = JSON.parse(row.body);
    if (a.type !== 'chain-of-custody') return { error: 'that attestation is not a receipt (chain-of-custody)', code: 400 };
    if (tableExists('retractions') && db.prepare('SELECT 1 FROM retractions WHERE attestation_id = ?').get(attestationId)) {
      return { error: 'that attestation was withdrawn by whoever signed it', code: 409 };
    }
    const received = t.received_record
      ? db.prepare('SELECT body FROM records WHERE id = ? AND holder_key = ?').get(t.received_record, asStored(t.claimed_by))
      : undefined;
    if (!received) return { error: 'the record this delivery created is no longer stored', code: 409 };
    const r = JSON.parse(received.body);
    if (typeof t.source_fingerprint !== 'string' || a.subjectCommitment !== t.source_fingerprint ||
        a.subjectCommitment !== r.receivedFromCommitment) {
      return { error: 'that attestation is about a different plant, not what this delivery sent', code: 400 };
    }
    if (typeof r.recordFingerprint !== 'string') {
      return { error: 'seal the received record first; the receipt is signed over its fingerprint', code: 409 };
    }
    if (a.documentHash !== r.recordFingerprint) {
      return { error: 'that attestation is about a different delivery', code: 400 };
    }
    // The sample details it was signed over, when its id carries them. Without a suffix (an
    // older receipt, or an older site), nothing more is checked and the details are shown as
    // not covered.
    const carried = receiptCustodyOf(attestationId);
    if (carried?.format === 1) {
      // Plain details (a delivery made before sealing): exactly what this delivery records now.
      if (hasSealedCustody(t)) {
        return { error: "this delivery's sample details are sealed, so its receipt carries them as _sc2_, not _sc1_", code: 400 };
      }
      if (carried.digest !== custodyDigest(t.id, parsed(t.sample_custody), parsed(t.arrival_custody))) {
        return { error: 'that receipt was signed over different sample details than this delivery records; sign it again', code: 400 };
      }
    }
    // Sealed details (CONTRACT.md #27): taken as signed, without recomputing. This registry
    // can't open the boxes; the holder's app compares them with the digest.
    if (carried?.format === 2 && typeof t.sample_custody_sealed !== 'string') {
      return { error: 'this delivery has no sealed sample details for an _sc2_ receipt to cover', code: 400 };
    }
    return null;
  };

  /** Store a checked receipt on a claimed transfer, replacing any earlier one. */
  const storeReceipt = (t, attestationId) => {
    const problem = receiptProblem(t, attestationId);
    if (problem) return problem;
    db.prepare('UPDATE transfers SET receipt_attestation_id = ? WHERE id = ?').run(attestationId, t.id);
    return { transferId: t.id, receiptAttestationId: attestationId };
  };

  return {
    /**
     * Offer a record to a recipient. Creates a claimable transfer, nothing moves yet.
     *
     * The recipient is identified by a handle rather than a holder key, because the
     * sender does not know the recipient's key and should not need to.
     */
    offer({ sourceRecord, fromHolder, toHandle, termsHash, quantity, note, sample, sealedOffer }) {
      if (typeof sourceRecord !== 'string') return { error: 'sourceRecord must be a string' };
      // A tag, never a name (sealed records round 2, P2): the name was stored as typed, and
      // the public pending list showed it to anyone who guessed it.
      if (typeof toHandle !== 'string' || !HANDLE_TAG.test(toHandle)) return { error: HANDLE_TAG_PROBLEM };
      if (termsHash !== undefined && termsHash !== null && (typeof termsHash !== 'string' || !TERMS_HASH.test(termsHash))) {
        return { error: 'termsHash must be 64 lowercase hexadecimal characters' };
      }
      for (const [k, v] of Object.entries({ quantity, note })) {
        if (tooLong(v, MAX[k])) return { error: `${k} must be a string of at most ${MAX[k]} characters` };
      }
      // A sealed offer: { v: 1, alg: "A256GCM", iv, ct }, at most 384 KiB. The quantity and note
      // are inside it, so sent beside it in plain text they are refused rather than stored
      // readable.
      let offerSealed = null;
      if (sealedOffer !== undefined && sealedOffer !== null) {
        const problem = sealedProblem(sealedOffer, { withKid: false, name: 'sealedOffer', ctMax: OFFER_MAX_BYTES });
        if (problem) return { error: problem };
        offerSealed = JSON.stringify(boxOf(sealedOffer, false));
        if (offerSealed.length > OFFER_MAX_BYTES) return { error: `sealedOffer may be at most ${OFFER_MAX_BYTES} bytes` };
        if ((quantity ?? null) !== null || (note ?? null) !== null) {
          return { error: 'quantity and note go inside sealedOffer; sent beside it they would be stored readable' };
        }
      }
      // The sample's label, seal and where it was taken from (optional; custodyFields). With a
      // sealed offer they are sealed too, with the offer key, under this delivery's id, which
      // the sender learns from this answer: so they come next, as a box, to
      // POST /transfers/:id/custody, and are refused here (CONTRACT.md #27).
      if (offerSealed !== null && sample !== undefined && sample !== null) {
        return { error: 'with a sealed offer, the sample details are sealed too: send them as a box to POST /transfers/:id/custody once the code is made' };
      }
      if (isCustodyBox(sample)) return { error: 'sealed sample details go with a sealed offer: they are sealed with its offer key' };
      const sampleFields = custodyFields('sample', sample);
      if (sampleFields.error) return { error: sampleFields.error };
      const claimCode = [...crypto.getRandomValues(new Uint8Array(16))]
        .map((b) => b.toString(16).padStart(2, '0')).join('');
      const sender = storedHolderKey(fromHolder);
      const row = db.prepare('SELECT body FROM records WHERE id = ? AND holder_key = ?')
        .get(sourceRecord, sender);
      if (!row) return { error: 'no such record for this holder' };
      const since = Date.now() - OFFER_LIMITS.windowMs;
      const open = 'claimed_by IS NULL AND claim_code IS NOT NULL AND created_at > ?';
      if (db.prepare(`SELECT COUNT(*) AS n FROM transfers WHERE to_handle = ? AND from_holder = ? AND ${open}`).get(toHandle, sender, since).n >= OFFER_LIMITS.perSenderAndHandle) {
        return { error: `you have ${OFFER_LIMITS.perSenderAndHandle} unclaimed offers from the last 30 days to this handle; wait for some to be claimed`, code: 429 };
      }
      if (db.prepare(`SELECT COUNT(*) AS n FROM transfers WHERE from_holder = ? AND ${open}`).get(sender, since).n >= OFFER_LIMITS.perSender) {
        return { error: `you have ${OFFER_LIMITS.perSender} unclaimed offers from the last 30 days; wait for some to be claimed`, code: 429 };
      }
      const source = JSON.parse(row.body);
      // Dated first, locked copy not here yet (CONTRACT.md #38): there is nothing to send.
      if (source.bodyPending === true && !isSealedBody(source)) {
        return { error: "this record's locked copy isn't on VeilCore yet; save and check your backup first, then send it", code: 409 };
      }
      const sourceFingerprint = source.recordFingerprint;
      // A sealed record's details can only reach the recipient in a sealed offer: the
      // registry can't read them to pass on. Without one, the code could never be claimed.
      if (isSealedBody(source) && offerSealed === null) {
        return { error: "a sealed record is offered with sealedOffer: the offer's details, locked with the delivery code's offer key" };
      }

      let id = newId();
      // 32 bits of transfer id: a collision is unlikely but not impossible, and it must
      // not surface as an internal error.
      for (let i = 0; i < 5 && db.prepare('SELECT 1 FROM transfers WHERE id = ?').get(id); i++) id = newId();
      db.prepare(`INSERT INTO transfers
        (id, source_record, from_holder, to_handle, claim_code, created_at, terms_hash, quantity, note, source_fingerprint, sample_custody, offer_sealed)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`)
        .run(id, sourceRecord, sender, toHandle, claimCodeStored(claimCode), Date.now(), termsHash ?? null, quantity ?? null, note ?? null,
          typeof sourceFingerprint === 'string' ? sourceFingerprint : null, stored(sampleFields.fields), offerSealed);

      // Returned once, to the sender, who passes it to the recipient the same way they
      // agreed the transfer in the first place. It is not recoverable from any public
      // endpoint, which is the whole point.
      return { transferId: id, sourceRecord, toHandle, claimCode };
    },

    /**
     * Claim a transfer. The recipient gets a new record descended from the original.
     *
     * The descent edge is what makes this provenance rather than a copy: the recipient's
     * record is permanently and publicly linked to what it came from, and any obligation
     * on the source now reaches the recipient's material too.
     */
    claim({ transferId, holderKey, claimCode, charge = () => true, receiptAttestationId }) {
      const t = db.prepare('SELECT * FROM transfers WHERE id = ?').get(transferId);
      if (!t) return { error: 'no such transfer' };
      if (t.claimed_by) return { error: 'this transfer has already been claimed' };
      // A sender claiming their own code (round 2): it would write a "received" attestation
      // on their own record with no second party, and leave the lab with nothing to claim.
      // Both sides compared in lower case (round 3): the same key in upper case got past it.
      if (holderKey && asStored(t.from_holder) === storedHolderKey(holderKey)) {
        return { error: 'This is your own code. Send it to the lab instead.', code: 409 };
      }

      // Claiming IS the attestation, so whoever claims becomes the second party whose
      // confirmation makes the sender's record evidence. Nothing checked that they were
      // the intended recipient: the transfer was found by id, and the attestation
      // written onto the sender's record named t.to_handle as the attester — the handle
      // of the party who was SUPPOSED to claim, not the one who did. A stranger with an
      // id produced a receipt confirmation in someone else's name, which is the exact
      // evidence this system exists to make hard to fabricate.
      //
      // The recipient has no holder key when the offer is made — that is why they are
      // identified by a handle — so there is nothing to check them against. The sender
      // is already in contact with them, so the sender carries a code across.
      //
      // A transfer made before claim codes existed has none, and was claimable by anyone
      // holding its id, which the public pending list handed out (deep dive, 8 Oct 2026,
      // LOW). It is refused; the sender offers the material again and gets a code.
      if (!t.claim_code) {
        return { error: 'this transfer was made before claim codes existed and can no longer be claimed; ask the sender to offer it again' };
      }
      if (!claimCodeMatches(t.claim_code, claimCode)) {
        return { error: 'claim code does not match; ask the sender for the code they were given' };
      }

      // The sender's record, held by the sender: a record stored under the same id by
      // someone else after the sender deleted theirs must not be what the claim inherits.
      // A sender key written in plain text by older code (a rollback, a deploy overlap)
      // is compared as the digest it stands for.
      const fromHolder = asStored(t.from_holder);
      const srcRow = db.prepare('SELECT body FROM records WHERE id = ? AND holder_key = ?')
        .get(t.source_record, fromHolder);
      if (!srcRow) return { error: 'the source record no longer exists' };
      const src = JSON.parse(srcRow.body);
      const current = typeof src.recordFingerprint === 'string' ? src.recordFingerprint : null;
      // What was offered is what is claimed. A sender who changed the record afterwards
      // offers it again; a claim must not certify receipt of content nobody offered. An
      // offer with no fingerprint recorded (an unsealed source, or one made by older code)
      // takes the source as it is now, and records it.
      if (t.source_fingerprint !== null && t.source_fingerprint !== undefined && current !== t.source_fingerprint) {
        return { error: "the source record's fingerprint has changed since this offer was made; ask the sender to offer it again" };
      }

      // A code made before records were sealed carries no sealed offer. While the source is
      // still a plaintext row, its details are passed on as before (offerPlain below), so
      // old codes keep working; once the sender's app has sealed it, the registry has
      // nothing it can pass on, and the sender makes a new code.
      const offerSealed = typeof t.offer_sealed === 'string' ? JSON.parse(t.offer_sealed) : null;
      if (offerSealed === null && isSealedBody(src)) {
        return { error: 'this code was made before records were sealed; ask the sender for a new code', code: 409 };
      }

      // The recipient's record is new material descended from the source, and they seal it
      // themselves: it commits to what they actually received, not to the breeder's
      // original claims. Copying the breeder's commitment would be claiming evidence they
      // did not produce.
      //
      // The registry writes only a stub (sealed records): the record's profile, and where it
      // came from. Everything else (the name since round 5, CONTRACT.md #28; breeder, dates,
      // species, an animal's details, quantity, note) reaches the recipient in the offer,
      // which their browser opens, builds the full record from, seals with its own nonce and
      // saves under this id. The registry used to build that record itself, nonce included,
      // from the sender's plaintext, and until round 5 copied the sender's name into the stub
      // in the clear.
      const receivedAt = Date.now();
      const received = {
        id: receivedRecordId(),
        // Only a profile a save would accept (sealed.js KNOWN_PROFILES), or the recipient's
        // browser could never save the record it builds from this.
        ...(KNOWN_PROFILES.includes(src.profile) ? { profile: src.profile } : {}),
        receivedFrom: t.source_record,
        receivedFromCommitment: src.recordFingerprint,
        receivedAt,
        transferId,
      };
      // For a code made before sealing, from a source still in plain text (plainOfferOf).
      const offerPlain = offerSealed !== null ? null : plainOfferOf(src, t);

      // Claiming IS the attestation.
      //
      // A lab attests because they received material — not because they pressed a
      // button labelled attest. The claim is a second party, holding their own key,
      // confirming receipt of a specific record on a specific date. That is the whole
      // substance of an attestation, and manufacturing one any other way would be
      // fabricating the evidence this system exists to produce.
      // The fields are sealed.js REGISTRY_ATTESTATION_FIELDS: a save keeps these and no others.
      const attestation = {
        // A one-way party id, never the recipient's holder key or any part of it. This
        // used to be holderKey.slice(0, 16): 64 bits of the recipient's credential,
        // written into a record the SENDER reads (attack round 11).
        attesterKey: partyId(holderKey),
        // No handle (sealed records round 2, P2). It was written here as `addressedTo` (the
        // handle the sender addressed), and before that as `attesterHandle`: the recipient's
        // name in the sender's record, readable here. The sender's app has the name in its
        // own sealed data.
        type: 'receipt-confirmed',
        confirms: 'a party holding the code the sender issued took delivery',
        transferId,
        attestedAt: receivedAt,
      };

      // All or nothing, and a clash on the new id is retried rather than turned into a
      // 500. Marking the transfer claimed only once the record exists means a failure
      // leaves it claimable.
      const insert = db.prepare(`INSERT INTO records (id, holder_key, body, updated_at, first_seen)
                                 VALUES (?,?,?,?,?)`);
      const claimant = storedHolderKey(holderKey);
      const tx = db.transaction(() => {
        const stillOpen = db.prepare('SELECT claimed_by FROM transfers WHERE id = ?').get(transferId);
        if (stillOpen?.claimed_by) return { error: 'this transfer has already been claimed' };
        // The received record goes into the claimant's set like any record they save, so it
        // meets the same ceilings (round 2, HIGH): it was inserted with no check at all, and
        // offer-claim-repeat filled a set past both for a few bytes of requests. The bytes
        // are also charged to the claiming address's daily allowance.
        const bytes = Buffer.byteLength(JSON.stringify(received));
        const has = db.prepare('SELECT COUNT(*) AS n, COALESCE(SUM(octet_length(body)), 0) AS bytes FROM records WHERE holder_key = ?').get(claimant);
        if (has.n + 1 > maxRecords) return { error: `a holder may keep at most ${maxRecords} records here; this claim would add one more`, code: 413 };
        if (has.bytes + bytes > maxBytes) {
          return { error: `a holder may keep at most ${(maxBytes / (1024 * 1024)).toFixed(1)} MB of records here; this claim would add ${(bytes / 1024).toFixed(1)} KB to ${(has.bytes / (1024 * 1024)).toFixed(1)} MB`, code: 413 };
        }
        if (!charge(bytes)) return { error: 'daily write allowance for this address used up; try again tomorrow', code: 429 };
        let written = false;
        for (let i = 0; i < 5 && !written; i++) {
          if (i > 0) received.id = receivedRecordId();
          try {
            insert.run(received.id, claimant, JSON.stringify(received), receivedAt, receivedAt);
            written = true;
          } catch (e) {
            if (!String(e?.code ?? '').startsWith('SQLITE_CONSTRAINT')) throw e;
          }
        }
        if (!written) return { error: 'could not allocate a record id; try again' };
        db.prepare(`UPDATE transfers SET claimed_by = ?, claimed_at = ?, received_record = ?, from_holder = ?,
                    source_fingerprint = COALESCE(source_fingerprint, ?) WHERE id = ?`)
          .run(claimant, receivedAt, received.id, fromHolder, current, transferId);
        // Only the attestation is written into the sender's record, in place (json_set):
        // the rest of the body is the sender's and, sealed, is not this registry's to
        // rewrite. It used to be parsed and written back whole.
        db.prepare("UPDATE records SET body = json_set(body, '$.attestation', json(?)), updated_at = ? WHERE id = ? AND holder_key = ?")
          .run(JSON.stringify(attestation), receivedAt, t.source_record, fromHolder);
        return null;
      });
      const failed = tx();
      if (failed) return failed;

      // A receipt sent with the claim (round 3). Checked like one sent later, and never a
      // reason to undo the claim: a claim just made has an unsealed record, and a receipt
      // is signed over the sealed one, so this normally says to attach it once sealed.
      let receipt = {};
      if (receiptAttestationId !== undefined && receiptAttestationId !== null && receiptAttestationId !== '') {
        const stored = storeReceipt(db.prepare('SELECT * FROM transfers WHERE id = ?').get(transferId), receiptAttestationId);
        receipt = stored.error ? { receiptError: stored.error } : { receiptAttestationId };
      }

      return {
        ...receipt,
        recordId: received.id,
        descendedFrom: t.source_record,
        parentCommitment: src.recordFingerprint,
        // The recipient seals and declares descent from their own client, because only
        // they can compute a commitment over their own record. The server holding the
        // material's provenance would defeat the point.
        needsSealing: true,
        // What the sender wrote about the material, for the recipient only: the sealed offer
        // exactly as the sender sent it (their browser opens it with the key in the code),
        // or, for a code made before sealing, offerPlain.
        ...(offerSealed !== null ? { offerSealed } : { offerPlain }),
        // The sender's quantity and note on a code made before sealing (null on a sealed
        // one: they are in the offer). They used to be on the public pending list, readable
        // by anyone who guessed the handle.
        quantity: t.quantity ?? null,
        note: t.note ?? null,
        // What the breeder wrote about the sample, for the lab to confirm or correct on
        // arrival: the box sealed with the offer key (the lab's browser opens it with the key
        // in the code), or for a delivery made before sealing the plain fields
        // (custodyFields). {} when nothing was written.
        sample: sidesOf(t).sample,
      };
    },

    /**
     * Write one side of the sample's chain of custody. `sample`: only the sender, and only
     * until the lab has received it (the lab confirms what it was shown). `arrival`: only
     * whoever received the delivery, once received; the lab signs its receipt over these
     * values next (receiptProblem checks the receipt covers what is stored). Each call
     * replaces that side whole. Returns both sides as stored.
     *
     * On a delivery made with a sealed offer each side is a sealed box (CONTRACT.md #27),
     * checked for shape and size only, and plain fields are refused; the lab's box must name
     * the same key (kid) as the sender's. A delivery made before keeps plain fields.
     */
    setCustody({ transferId, holderKey, sample, arrival }) {
      const t = typeof transferId === 'string' ? db.prepare('SELECT * FROM transfers WHERE id = ?').get(transferId) : undefined;
      if (!t) return { error: 'no such transfer', code: 404 };
      if (sample === undefined && arrival === undefined) return { error: 'send sample or arrival', code: 400 };
      if (sample !== undefined && arrival !== undefined) {
        return { error: 'the sender writes sample and the lab writes arrival; send one', code: 400 };
      }
      const caller = holderKey ? storedHolderKey(holderKey) : null;
      if (sample !== undefined) {
        if (!caller || asStored(t.from_holder) !== caller) {
          return { error: 'only whoever made this lab code can write the sample details', code: 403 };
        }
        if (t.claimed_by) return { error: 'the lab has already received this sample; its details can no longer change', code: 409 };
        if (sealedDelivery(t)) {
          if (!isCustodyBox(sample)) return { error: plainRefused('sample'), code: 400 };
          const problem = custodyBoxProblem('sample', sample);
          if (problem) return { error: problem, code: 400 };
          const box = boxOf(sample);
          db.prepare('UPDATE transfers SET sample_custody_sealed = ?, sample_custody = NULL WHERE id = ?').run(JSON.stringify(box), t.id);
          return { transferId: t.id, sample: box, arrival: {} };
        }
        if (isCustodyBox(sample)) {
          return { error: 'this delivery was made before sample details were sealed; send its sample details as plain fields', code: 400 };
        }
        const f = custodyFields('sample', sample);
        if (f.error) return { error: f.error, code: 400 };
        db.prepare('UPDATE transfers SET sample_custody = ? WHERE id = ?').run(stored(f.fields), t.id);
        return { transferId: t.id, sample: f.fields, arrival: {} };
      }
      if (!t.claimed_by) return { error: 'this delivery has not been received yet', code: 409 };
      if (!caller || asStored(t.claimed_by) !== caller) {
        return { error: 'only whoever received this delivery can write how it arrived', code: 403 };
      }
      if (sealedDelivery(t)) {
        if (!isCustodyBox(arrival)) return { error: plainRefused('arrival'), code: 400 };
        const problem = custodyBoxProblem('arrival', arrival);
        if (problem) return { error: problem, code: 400 };
        const sampleBox = boxIn(t.sample_custody_sealed);
        if (sampleBox && sampleBox.kid !== arrival.kid) {
          return { error: 'arrival is sealed with a different key from the sample details; seal it with the offer key in the lab code', code: 400 };
        }
        const box = boxOf(arrival);
        db.prepare('UPDATE transfers SET arrival_custody_sealed = ?, arrival_custody = NULL WHERE id = ?').run(JSON.stringify(box), t.id);
        return { transferId: t.id, sample: sidesOf(t).sample, arrival: box };
      }
      if (isCustodyBox(arrival)) {
        return { error: 'this delivery was made before sample details were sealed; send how it arrived as plain fields', code: 400 };
      }
      const f = custodyFields('arrival', arrival);
      if (f.error) return { error: f.error, code: 400 };
      db.prepare('UPDATE transfers SET arrival_custody = ? WHERE id = ?').run(stored(f.fields), t.id);
      return { transferId: t.id, sample: parsed(t.sample_custody), arrival: f.fields };
    },

    /**
     * Both sides of the sample's chain of custody, for the sender or whoever received it:
     * each a sealed box, or for a delivery made before sealing its plain fields.
     */
    custody({ transferId, holderKey }) {
      const t = typeof transferId === 'string' ? db.prepare('SELECT * FROM transfers WHERE id = ?').get(transferId) : undefined;
      if (!t) return { error: 'no such transfer', code: 404 };
      const caller = holderKey ? storedHolderKey(holderKey) : null;
      const sender = caller !== null && asStored(t.from_holder) === caller;
      const claimant = caller !== null && !!t.claimed_by && asStored(t.claimed_by) === caller;
      if (!sender && !claimant) return { error: 'only the sender or whoever received this delivery can read this', code: 403 };
      return {
        transferId: t.id,
        ...sidesOf(t),
        receiptAttestationId: t.receipt_attestation_id ?? null,
      };
    },

    /**
     * The lab attaches its signed receipt to a delivery it claimed (round 3): the id of a
     * chain-of-custody attestation already posted to /attestations. Only the holder who
     * claimed the delivery, checked as the claim checks a claimant (their holder key). A
     * later one replaces it, on the same checks; nobody else can replace it.
     */
    attachReceipt({ transferId, holderKey, attestationId }) {
      const t = typeof transferId === 'string' ? db.prepare('SELECT * FROM transfers WHERE id = ?').get(transferId) : undefined;
      if (!t) return { error: 'no such transfer', code: 404 };
      if (!t.claimed_by) return { error: 'this delivery has not been received yet', code: 409 };
      if (!holderKey || asStored(t.claimed_by) !== storedHolderKey(holderKey)) {
        return { error: 'only whoever received this delivery can attach its receipt', code: 403 };
      }
      return storeReceipt(t, attestationId);
    },

    /**
     * For the public /verify of a sender's record, under the holder's lab-status grant
     * (server.js): each of its deliveries with a linked receipt, newest first (at most 100),
     * whether that receipt covers the sample details as stored now (receiptCustodyDigest),
     * and where what arrived differs from what was sent (custodyDifferences, only when it
     * covers them, as the site says it). Never the details themselves: a difference line is
     * all of them a stranger sees. Only receipts about the record as it is now (the
     * attestation's subject is `fingerprint`) and not withdrawn by their signer.
     *   covered      the receipt's id carries the digest of exactly what is stored
     *   changed      it carries a digest of other values: changed after signing
     *   not-covered  a receipt from before sample details: it covers none
     *
     * A receipt over sealed details (`_sc2_`, CONTRACT.md #27) is answered
     * { receiptAttestationId, custody: "sealed", receiptNamesSampleDetails: true,
     *   sampleDetailsCheckedBy: "holder" }: the lab's receipt names sample details, which are
     * stored locked, so this registry can't check the receipt against them, nor say whether
     * they match or differ, and never says either (the holder may publish what their app
     * worked out: server.js custodySummary). It used to answer `signedOverSampleDetails: true`,
     * which read as a checked fact for any digest a lab signed (round 4, F11). Details the
     * purge removed are custody: "removed".
     */
    receiptCustody({ sourceRecord, holderKeyStored, fingerprint }) {
      if (typeof sourceRecord !== 'string' || typeof fingerprint !== 'string' || !tableExists('attestations')) return [];
      const retractions = tableExists('retractions');
      const rows = db.prepare(`SELECT id, from_holder, sample_custody, arrival_custody, sample_custody_sealed, arrival_custody_sealed,
                               custody_removed, receipt_attestation_id FROM transfers
                               WHERE source_record = ? AND receipt_attestation_id IS NOT NULL
                               ORDER BY created_at DESC, id LIMIT 100`).all(sourceRecord);
      const out = [];
      for (const t of rows) {
        if (asStored(t.from_holder) !== asStored(holderKeyStored)) continue;
        const att = db.prepare('SELECT subject_commitment FROM attestations WHERE attestation_id = ?').get(t.receipt_attestation_id);
        if (!att || att.subject_commitment !== fingerprint) continue;
        if (retractions && db.prepare('SELECT 1 FROM retractions WHERE attestation_id = ?').get(t.receipt_attestation_id)) continue;
        const carried = receiptCustodyOf(t.receipt_attestation_id);
        if (carried?.format === 2) {
          out.push({ receiptAttestationId: t.receipt_attestation_id, custody: 'sealed', receiptNamesSampleDetails: true, sampleDetailsCheckedBy: 'holder' });
          continue;
        }
        if (carried !== null && t.custody_removed) {
          out.push({ receiptAttestationId: t.receipt_attestation_id, custody: 'removed', receiptNamesSampleDetails: true });
          continue;
        }
        const sample = parsed(t.sample_custody);
        const arrival = parsed(t.arrival_custody);
        const digest = carried?.format === 1 ? carried.digest : null;
        const covered = digest === null ? 'not-covered' : digest === custodyDigest(t.id, sample, arrival) ? 'covered' : 'changed';
        out.push({
          receiptAttestationId: t.receipt_attestation_id,
          covered,
          differences: covered === 'covered' ? custodyDifferences(sample, arrival) : [],
        });
      }
      return out;
    },

    /**
     * The offer of a delivery, for the holder who claimed it, and nobody else (sealed records
     * round 2, L4): { transferId, offerSealed } byte for byte as the sender sent it, or, for
     * a code made before sealing, { transferId, offerPlain } from the sender's record as the
     * claim built it. Everyone else, the sender included, gets the 404 a delivery that does
     * not exist gets: whether it exists, and whether it was claimed, is not theirs to learn.
     * offerPlain needs the sender's record still in plain text and as it was when claimed;
     * otherwise 409, since there is nothing left the registry can read to pass on.
     */
    offerFor({ transferId, holderKey }) {
      const none = { error: 'no such transfer', code: 404 };
      const t = typeof transferId === 'string' ? db.prepare('SELECT * FROM transfers WHERE id = ?').get(transferId) : undefined;
      if (!t || !t.claimed_by || !holderKey || asStored(t.claimed_by) !== storedHolderKey(holderKey)) return none;
      if (typeof t.offer_sealed === 'string') return { transferId: t.id, offerSealed: JSON.parse(t.offer_sealed) };
      const srcRow = db.prepare('SELECT body FROM records WHERE id = ? AND holder_key = ?').get(t.source_record, asStored(t.from_holder));
      if (!srcRow) return { error: 'the source record no longer exists; ask the sender for a new code', code: 409 };
      const src = JSON.parse(srcRow.body);
      if (isSealedBody(src)) return { error: 'this code was made before records were sealed; ask the sender for a new code', code: 409 };
      if (t.source_fingerprint !== null && t.source_fingerprint !== undefined && src.recordFingerprint !== t.source_fingerprint) {
        return { error: "the source record's fingerprint has changed since this delivery; ask the sender for a new code", code: 409 };
      }
      return { transferId: t.id, offerPlain: plainOfferOf(src, t) };
    },

    /**
     * Transfers a holder has sent, newest first, a page at a time. `received_record` is the
     * record the claim created (null until claimed): the breeder's page looks up its public
     * fingerprint to find the lab's receipt for THIS delivery. `receipt_attestation_id` is the
     * receipt the lab attached (null until then; its signature and withdrawal are the page's
     * to check, as for any attestation). Only the sender gets this list.
     */
    sent(holder, paging) {
      const { limit, offset } = pageOf(paging, TRANSFER_PAGE.sent);
      const sender = storedHolderKey(holder);
      return {
        // sample_custody and arrival_custody: the sample's chain of custody as each side wrote
        // it, absent when nothing was written: a box sealed with the delivery's offer key
        // (CONTRACT.md #27; the sender's app opens it), or the plain fields of a delivery made
        // before sealing (custodyFields). The receipt's id says whether its signature covers
        // them; the page checks that.
        transfers: db.prepare(`SELECT id, source_record, to_handle, created_at, claimed_at, received_record, receipt_attestation_id,
                               sample_custody, arrival_custody, sample_custody_sealed, arrival_custody_sealed
                               FROM transfers WHERE from_holder = ? ORDER BY created_at DESC, id LIMIT ? OFFSET ?`).all(sender, limit, offset)
          .map(({ sample_custody, arrival_custody, sample_custody_sealed, arrival_custody_sealed, ...row }) => {
            const sides = sidesOf({ sample_custody, arrival_custody, sample_custody_sealed, arrival_custody_sealed });
            return {
              ...row,
              ...(Object.keys(sides.sample).length ? { sample_custody: sides.sample } : {}),
              ...(Object.keys(sides.arrival).length ? { arrival_custody: sides.arrival } : {}),
            };
          }),
        total: db.prepare('SELECT COUNT(*) AS n FROM transfers WHERE from_holder = ?').get(sender).n,
        limit,
        offset,
      };
    },
  };
};
