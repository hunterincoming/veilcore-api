// Sealed records: what the registry stores in the clear, and the shape of what it stores
// sealed (the site's CONTRACT.md for sealed records, 16 Oct 2026).
//
// A record arrives as a few public fields beside `sealed`, an AES-256-GCM box the holder's
// browser made with a vault key this registry never receives. The registry checks the
// box's shape and the public fields, and nothing else: it cannot open the box, so it
// cannot check that a fingerprint matches what is inside. The holder's browser does that
// after opening each record (integrityCheckedBy: "holder").
//
// Used by server.js (records, licences, grants), lineage/transfer.mjs (sealed offers) and
// scripts/purge-plaintext.mjs (what a legacy row is reduced to). One definition, so the
// three cannot disagree about which fields are public.
// SPDX-License-Identifier: Apache-2.0

/** Record and licence ids: what the registry has always accepted. */
const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
/**
 * Size limits (round 2, L5). The box is base64url, about 4/3 of what it holds, and the
 * browser pads what it seals to a bucket (CONTRACT.md #20) and refuses a padded plaintext
 * over 256 KiB, which is 349,548 characters sealed. The old registry took a record of up to
 * 65,536 characters of JSON; in UTF-8 that is at most 196,608 bytes (three bytes for each
 * character of Japanese or Chinese text), padded 196,608 and sealed 262,166 characters. So
 * every record the old registry could hold converts, and every record the browser lets a
 * holder save fits. Before this the box was limited to 90,000 characters (about 67 KB), and
 * a record with 20,000 characters of Japanese notes could not be converted at all; the purge
 * would then have reduced it to its public fields.
 *   SEALED_CT_MAX     a record's or a licence's sealed.ct, in base64url characters
 *   RECORD_MAX_BYTES  a whole record or licence row as JSON (the box plus the public fields)
 */
const RECORD_MAX_BYTES = 384 * 1024;
const SEALED_CT_MAX = 360_000;
/**
 * A sealed offer (POST /transfers), as JSON (round 2, A4). The offer carries the source
 * record's breeder, date, species, ID and an animal's details, the sender's quantity (at
 * most 200 characters in the app) and note (at most 2,000), padded like a record. A record
 * may hold up to 256 KiB padded, so the largest offer the app can make is about 280 KiB
 * padded, 382,400 characters sealed: 384 KiB fits it, the same as a record row. It was
 * 16 KB, which a padded offer with a long note (or long record fields) went over, and the
 * code was then refused after the holder had typed it.
 */
const OFFER_MAX_BYTES = 384 * 1024;
/**
 * A delivery's sealed sample details (sealed records round 3, CONTRACT.md #27): the box the
 * sender's `sample` or the lab's `arrival` is sealed in, with the delivery's offer key. Its
 * ct may be at most 8,000 base64url characters (about 5,980 bytes sealed). The longest
 * either side can write is under 4.5 KB as UTF-8 JSON, 5 KiB padded.
 */
const CUSTODY_CT_MAX = 8000;

const HEX64 = /^[0-9a-f]{64}$/;
/**
 * An ISO 8601 date and time, with Z or a +hh:mm offset: what the SDK writes in
 * supersedes.effectiveAt (supersedesFor: "2026-10-16T09:30:00Z"; older sites kept the
 * milliseconds). Checked as a real instant too (Date.parse), so 2026-02-31 is refused.
 */
const ISO_DATE_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$/;
const isIsoDateTime = (v) => {
  if (typeof v !== 'string' || !ISO_DATE_TIME.test(v) || Number.isNaN(Date.parse(v))) return false;
  // Date.parse rolls 2026-02-31 over to 3 March; the calendar day must survive as written.
  const [y, m, d] = v.slice(0, 10).split('-').map(Number);
  const day = new Date(Date.UTC(y, m - 1, d));
  return day.getUTCFullYear() === y && day.getUTCMonth() === m - 1 && day.getUTCDate() === d;
};
const KID = /^[0-9a-f]{16}$/;

/**
 * A delivery's recipient, as this registry holds it (round 2, P2): a tag, never a name.
 * The sender's browser sends `toHandle` = lowercase hex HMAC-SHA256(key = the vault key,
 * msg = "veilcore:handle:v1\0" + the name as typed, NFC, trimmed, lower case). The name
 * stays inside the sender's sealed data. Anything else is refused with HANDLE_TAG_PROBLEM.
 */
const HANDLE_TAG = /^[0-9a-f]{64}$/;
const HANDLE_TAG_PROBLEM = 'toHandle is a tag, not a name';
/**
 * What the purge writes in place of a recipient handle stored as typed, before tags: 32
 * random bytes as 64 lowercase hex, a fresh value for every delivery, so the column still
 * has a tag's shape. Nothing of the handle is in it. Until round 3 (P6) it was a plain
 * SHA-256 of the handle, which anyone with a copy of the database could reverse by hashing
 * likely names ("Jane Doe at Example Hill Labs" came back from a short list). The cost: old
 * deliveries to one recipient no longer share a value. Nothing needs them to: the
 * per-sender-and-handle limit counts open offers, and a tag the app makes today never
 * equals one of these.
 */
const legacyHandleReplacement = () => require('node:crypto').randomBytes(32).toString('hex');
// 12 bytes of IV in base64url without padding is exactly 16 characters.
const IV = /^[A-Za-z0-9_-]{16}$/;
const B64URL = /^[A-Za-z0-9_-]+$/;
// The shortest box is an empty plaintext: the 16-byte tag alone, 22 characters.
const CT_MIN = 22;

/**
 * The profiles a record may name (round 2, P7: `profile` was any text of up to 200
 * characters, readable to anyone with the id). The three the site seals under today (plant,
 * animal, and the draft strain profile), and the one older records were exported under (the
 * site's envelope.ts LEGACY_PROFILE; a record sealed before profiles existed has no `profile`
 * at all).
 */
const KNOWN_PROFILES = Object.freeze([
  'veilcore/profile/plant-variety/v1',
  'veilcore/profile/animal-individual/v1',
  // Strain and line records (lineage/strain-profile.mjs; draft, test networks only on the site).
  'veilcore/profile/strain/v1',
  // Document records (lineage/document-profile.mjs; draft, test networks only on the site).
  'veilcore/profile/document/v1',
  'veilcore/profile/cannabis/v0.1',
]);

/**
 * The names `supersedes.changedFields` may hold (round 2, P7: it was a list of any 50
 * strings of up to 64 characters, readable to anyone with the id, so a holder's words could
 * be put there in the clear).
 *
 * THE SITE'S LIST MUST MATCH THIS ONE EXACTLY. It is exported from the site's records code
 * (bboard-ui src/veilcore/records.ts) and the cross-repo contract test checks the two lists
 * are the same. Change both together, or a correction the site makes is refused here.
 *
 * What a correction names: the site's corrections.ts lists the fields that changed as
 * veilcore-records diffRecords reports them, the dotted paths of the record's envelope
 * (envelope.ts toEnvelope) that differ. Those are the envelope paths below, for plant and
 * animal records, the ones older sites wrote (profileData.cultivarName and the rest, before
 * the subject block existed), and the classified names in the SDK's table. Records written
 * by other tools name the app's own fields (StrainRecord in records.ts), so those are known
 * too: corrections the site wrote under 0.13 say ["dateCreated"].
 */
const CHANGED_FIELD_NAMES = Object.freeze([
  // The app's own record fields (records.ts StrainRecord).
  'id', 'nonce', 'strainName', 'bredBy', 'dateCreated', 'notes', 'loggedAt', 'recordFingerprint', 'keyBinding',
  'parents', 'breedingMethod', 'profile', 'taxon', 'animal', 'strain', 'document', 'photoFingerprints', 'refId', 'dnaFingerprint',
  'dnaFileName', 'dnaPairedAt', 'dnaFileSha256', 'dnaResultId', 'attestation', 'supersedes', 'supersededBy',
  'receivedFrom', 'receivedFromCommitment', 'receivedAt', 'transferId', 'quantity', 'licenseIds',
  'deliveryNote', 'labRef', 'resultLock', 'receiptRejected',
  // Envelope paths (envelope.ts toEnvelope, veilcore-records committedFields and diffRecords).
  'attestations', 'commitmentAlgorithm', 'extensions', 'fieldSchema', 'fieldSetRoot', 'formatVersion',
  'holder', 'holder.id', 'identification', 'identification.method', 'identification.reportHash',
  'identification.performedOn', 'jurisdictionBindings', 'ledgerIdentity', 'registrations', 'sealedAt',
  'subject', 'subject.name', 'subject.originator', 'subject.taxon', 'subject.internalDesignation',
  'subject.claimedCreationDate', 'subjectType', 'profileData',
  'profileData.breedingMethod', 'profileData.notes', 'profileData.breed', 'profileData.sex',
  'profileData.individualId', 'profileData.idScheme', 'profileData.herd', 'profileData.parentIds',
  // A strain or line's profileData (the site's envelope.ts toEnvelope, strain branch; 8 Nov 2026,
  // the site review's B2: a strain correction of its method or designation was refused here).
  'profileData.group', 'profileData.designation', 'profileData.deposits', 'profileData.method',
  'profileData.generation', 'profileData.parentDeposits',
  // Envelope paths older sites wrote, and the SDK's other classified names.
  'profileData.cultivarName', 'profileData.breederName', 'profileData.claimedCreationDate',
  'profileData.internalReference', 'profileData.taxon', 'profileData.phenotypeSelection',
]);
const CHANGED_FIELD_SET = new Set(CHANGED_FIELD_NAMES);

/**
 * A record's name is sealed too (round 5, CONTRACT.md #28): a save that carries `strainName`
 * outside the box is refused, whole, with this error (400). The holder's check link carries
 * the name after the # (never sent to any server), and a holder who wants strangers to see it
 * publishes it on purpose with the `name` grant. A row stored before this keeps its clear name
 * until the holder's browser saves it again; the purge removes what is left (scripts/purge-plaintext.mjs).
 */
const NAME_IN_CLEAR = 'strainName belongs inside sealed';
/** Whether a row as stored or sent carries the name in the clear (a row saved before round 5). */
const hasClearName = (r) => isObject(r) && Object.prototype.hasOwnProperty.call(r, 'strainName');

/**
 * Top-level fields a record may carry outside `sealed`. Everything a holder typed goes
 * inside, the record's name included (round 5). The received-record fields and `attestation` are written by this registry;
 * a client's copy is accepted on the wire (the browser sends back what it read) and
 * ignored: the stored value is kept.
 */
const PUBLIC_RECORD_FIELDS = [
  'id', 'profile', 'recordFingerprint', 'keyBinding', 'supersedes', 'supersededBy',
  'receivedFrom', 'receivedFromCommitment', 'receivedAt', 'transferId', 'attestation',
  // Round 6 (CONTRACT.md #33): the name's salted code, SHA-256 of the name, the proof code and
  // a salt kept inside the box. Without the salt (it travels only in the holder's check link,
  // after the #, as `ns`) it says nothing about the name; with the name and the salt from a
  // link, a check page tells whether the link's name is the record's.
  'nameCode',
];
const SERVER_KEPT_FIELDS = ['receivedFrom', 'receivedFromCommitment', 'receivedAt', 'transferId', 'attestation'];
/**
 * `rev` (round 3, L2), optional: the row's revision as the holder's browser numbers it, the
 * same number its sealed payload carries (CONTRACT.md #20), sent in the clear too so this
 * registry can refuse an older copy. A whole number from 0 up. Once a row has one, a save
 * with a lower one, or none, is refused (server.js, PUT /api/records: OLDER_COPY). Stored
 * with the row and returned to its holder; never in a public answer. It tells the registry
 * how many times a row was saved, which the save times already did.
 */
const RECORD_WIRE_FIELDS = new Set([...PUBLIC_RECORD_FIELDS, 'rev', 'sealed']);
const OLDER_COPY = 'older-copy';
const SUPERSEDES_FIELDS = new Set(['recordId', 'changedFields', 'effectiveAt']);
/**
 * A licence is { id, sealed } and, since round 4 (F1), an optional public `rev`: the same
 * number its sealed payload carries, so this registry refuses an older copy of an agreement
 * as it does of a record (PUT /api/licenses: OLDER_COPY). Two tabs or devices used to
 * replace each other's changes to an agreement, a revocation included, without a word.
 */
const LICENCE_WIRE_FIELDS = new Set(['id', 'rev', 'sealed']);

/**
 * Whether a save of one row at `rev` is an older copy than the one held (records and
 * licences, round 3 L2 and round 4 F1): the refusal entry for `rejected`, or null to take it.
 * `heldRev` is the newest rev held (stored, or an earlier copy in the same save), `heldBox`
 * the box held at that rev. A lower rev, or none once a rev is held, is older; the same rev
 * is taken again only as the very same box (one request sent twice), because two tabs that
 * changed the row from the same copy both send that copy's rev + 1.
 */
const olderCopyRefusal = (what, id, rev, heldRev, heldBox, box) => {
  if (heldRev === null) return null;
  if (rev === null || rev < heldRev) {
    return {
      id,
      reason: `older copy: this registry holds rev ${heldRev} of this ${what} and this save is ${rev === null ? 'without a rev' : `rev ${rev}`}; nothing was changed`,
      code: OLDER_COPY,
      status: 409,
      storedRev: heldRev,
    };
  }
  if (rev === heldRev) {
    const same = heldBox && heldBox.iv === box.iv && heldBox.ct === box.ct && heldBox.kid === box.kid;
    if (!same) {
      return {
        id,
        reason: `older copy: this registry holds another copy at rev ${heldRev} of this ${what}, saved since this one was opened; nothing was changed`,
        code: OLDER_COPY,
        status: 409,
        storedRev: heldRev,
      };
    }
  }
  return null;
};

const isObject = (v) => typeof v === 'object' && v !== null && !Array.isArray(v);
const b64urlProblem = (v, name, max) => {
  if (typeof v !== 'string' || !B64URL.test(v)) return `${name} must be base64url without padding`;
  if (v.length % 4 === 1) return `${name} is not a whole number of bytes`;
  if (v.length < CT_MIN) return `${name} is too short to hold the 16-byte tag`;
  if (v.length > max) return `${name} may be at most ${max} characters`;
  return null;
};

/**
 * Why `sealed` is not a well-formed box, or null. `withKid`: a record or licence box names
 * its vault key; an offer box is opened with a key from the delivery code and has none.
 */
const sealedProblem = (s, { withKid = true, name = 'sealed', ctMax = SEALED_CT_MAX } = {}) => {
  if (s === undefined || s === null) return `${name} is required: this registry stores only sealed contents`;
  if (!isObject(s)) return `${name} must be an object`;
  const allowed = withKid ? ['v', 'alg', 'kid', 'iv', 'ct'] : ['v', 'alg', 'iv', 'ct'];
  for (const k of Object.keys(s)) if (!allowed.includes(k)) return `${name}.${k} is not part of a sealed box`;
  if (s.v !== 1) return `${name}.v must be 1`;
  if (s.alg !== 'A256GCM') return `${name}.alg must be "A256GCM"`;
  if (withKid && (typeof s.kid !== 'string' || !KID.test(s.kid))) return `${name}.kid must be 16 lowercase hexadecimal characters`;
  if (typeof s.iv !== 'string' || !IV.test(s.iv)) return `${name}.iv must be 16 base64url characters (12 bytes)`;
  return b64urlProblem(s.ct, `${name}.ct`, ctMax);
};

/** The fields of a box in a fixed order, so what is stored is what is served back. */
const boxOf = (s, withKid = true) => (withKid
  ? { v: s.v, alg: s.alg, kid: s.kid, iv: s.iv, ct: s.ct }
  : { v: s.v, alg: s.alg, iv: s.iv, ct: s.ct });

/**
 * Why a record row from PUT /api/records may not be stored, or null. Shape only: the
 * checks that need the database (whose fingerprint, whose ids, which vault key) are
 * server.js's, made in the transaction that writes.
 */
const recordRowProblem = (item) => {
  if (!isObject(item)) return 'a record must be an object';
  if (typeof item.id !== 'string' || !ID_PATTERN.test(item.id)) return 'id must be 1-128 letters, digits, dots, colons, underscores or hyphens';
  if (hasClearName(item)) return NAME_IN_CLEAR;
  for (const k of Object.keys(item)) {
    if (!RECORD_WIRE_FIELDS.has(k)) return `${k} is not stored in the clear; it belongs inside sealed`;
  }
  if (JSON.stringify(item).length > RECORD_MAX_BYTES) return `a record may be at most ${RECORD_MAX_BYTES} bytes`;
  const box = sealedProblem(item.sealed);
  if (box) return box;
  if (item.rev !== undefined && item.rev !== null && !(Number.isSafeInteger(item.rev) && item.rev >= 0)) {
    return 'rev must be a whole number from 0 up';
  }
  for (const field of ['recordFingerprint', 'keyBinding', 'nameCode']) {
    const v = item[field];
    if (v !== undefined && v !== null && (typeof v !== 'string' || !HEX64.test(v))) return `${field} must be 64 lowercase hexadecimal characters`;
  }
  // The clear fields are not free text (round 2, P7): each is a known value, an id, a list
  // of known names, or a date. Since round 5 none of them is free text: the name is sealed.
  if (item.profile !== undefined && item.profile !== null && !KNOWN_PROFILES.includes(item.profile)) {
    return `profile must be one of ${KNOWN_PROFILES.join(', ')}`;
  }
  if (item.supersededBy !== undefined && item.supersededBy !== null
    && (typeof item.supersededBy !== 'string' || !ID_PATTERN.test(item.supersededBy))) {
    return 'supersededBy must be a record id';
  }
  if (item.supersedes !== undefined && item.supersedes !== null) {
    const s = item.supersedes;
    if (!isObject(s)) return 'supersedes must be an object';
    for (const k of Object.keys(s)) {
      if (!SUPERSEDES_FIELDS.has(k)) return `supersedes.${k} is not stored in the clear; it belongs inside sealed`;
    }
    if (typeof s.recordId !== 'string' || !ID_PATTERN.test(s.recordId)) return 'supersedes.recordId must be a record id';
    if (s.changedFields !== undefined) {
      if (!Array.isArray(s.changedFields) || s.changedFields.length > CHANGED_FIELD_NAMES.length) {
        return `supersedes.changedFields must be a list of at most ${CHANGED_FIELD_NAMES.length} field names`;
      }
      const unknown = s.changedFields.find((f) => typeof f !== 'string' || !CHANGED_FIELD_SET.has(f));
      if (unknown !== undefined) return 'supersedes.changedFields may hold only known record field names';
    }
    if (s.effectiveAt !== undefined && !isIsoDateTime(s.effectiveAt)) {
      return 'supersedes.effectiveAt must be an ISO 8601 date and time, such as 2026-10-16T09:30:00Z';
    }
  }
  return null;
};

/**
 * Dating first (CONTRACT.md #38): a record's proof code goes into the next batch the moment
 * the record is sealed in the browser, before its locked copy can be uploaded (that waits
 * for a checked backup of the vault key, round 3 L1). A dating row is
 * `{ id, recordFingerprint, keyBinding? }` and nothing else: no box, so no vault key id, and
 * nothing typed. The proof code is a salted commitment (a nonce inside the record), so it
 * says nothing about what was typed. It is stored as
 * `{ id, recordFingerprint, keyBinding?, bodyPending: true }`; the locked copy that arrives
 * later must carry the same proof code (server.js, PUT /api/records).
 */
const DATING_WIRE_FIELDS = new Set(['id', 'recordFingerprint', 'keyBinding']);
const DATING_MAX_PER_REQUEST = 100;
const datingRowProblem = (item) => {
  if (!isObject(item)) return 'a dating row must be an object';
  if (typeof item.id !== 'string' || !ID_PATTERN.test(item.id)) return 'id must be 1-128 letters, digits, dots, colons, underscores or hyphens';
  for (const k of Object.keys(item)) {
    if (!DATING_WIRE_FIELDS.has(k)) return `${k} is not part of a dating row: it is { id, recordFingerprint, keyBinding? }`;
  }
  if (typeof item.recordFingerprint !== 'string' || !HEX64.test(item.recordFingerprint)) {
    return 'recordFingerprint must be 64 lowercase hexadecimal characters';
  }
  if (item.keyBinding !== undefined && item.keyBinding !== null && (typeof item.keyBinding !== 'string' || !HEX64.test(item.keyBinding))) {
    return 'keyBinding must be 64 lowercase hexadecimal characters';
  }
  return null;
};
/** Whether a stored body is a dating row still waiting for its locked copy. */
const isDatingOnlyBody = (r) => isObject(r) && r.bodyPending === true && !isObject(r.sealed);
/** A dating row as stored: its proof code (and key binding), marked as waiting for its body. */
const datingBodyOf = (item) => ({
  id: item.id,
  recordFingerprint: item.recordFingerprint,
  ...(typeof item.keyBinding === 'string' ? { keyBinding: item.keyBinding } : {}),
  bodyPending: true,
});
const DIFFERENT_DATED_FINGERPRINT =
  'this id was dated with a different proof code; a record\'s locked copy must carry the proof code it was dated with. Nothing was changed';

/** Why a licence row from PUT /api/licenses may not be stored, or null: { id, rev?, sealed } only. */
const licenceRowProblem = (item) => {
  if (!isObject(item)) return 'a license must be an object with a string id';
  if (typeof item.id !== 'string' || !ID_PATTERN.test(item.id)) return 'id must be 1-128 letters, digits, dots, colons, underscores or hyphens';
  for (const k of Object.keys(item)) {
    if (!LICENCE_WIRE_FIELDS.has(k)) return `${k} is not stored in the clear; a license is { id, rev, sealed }`;
  }
  if (item.rev !== undefined && item.rev !== null && !(Number.isSafeInteger(item.rev) && item.rev >= 0)) {
    return 'rev must be a whole number from 0 up';
  }
  if (JSON.stringify(item).length > RECORD_MAX_BYTES) return `a license may be at most ${RECORD_MAX_BYTES} bytes`;
  return sealedProblem(item.sealed);
};

/** Whether a stored body is sealed (anything else is a legacy plaintext row or a claim's stub). */
const isSealedBody = (r) => isObject(r) && isObject(r.sealed);

/**
 * The public shape of a `supersedes` block: which record, which fields changed, when.
 * The reason and anything else a holder wrote are not part of it, and neither is a field
 * name nobody knows or a date that is not one (round 2, P7: legacy rows may hold them).
 */
const publicSupersedes = (s) => {
  if (!isObject(s)) return undefined;
  const out = {};
  if (typeof s.recordId === 'string' && ID_PATTERN.test(s.recordId)) out.recordId = s.recordId;
  if (Array.isArray(s.changedFields)) out.changedFields = s.changedFields.filter((f) => typeof f === 'string' && CHANGED_FIELD_SET.has(f));
  if (isIsoDateTime(s.effectiveAt)) out.effectiveAt = s.effectiveAt;
  return out.recordId ? out : undefined;
};

/**
 * An attestation as this registry writes it on a claim (lineage/transfer.mjs), and nothing
 * else (round 2, P3). Records from before an attestation had to be earned carry one their
 * holder typed, such as { lab: "<a lab's name>", attestedAt }, and the stored copy was kept
 * whole on every save, so the lab's name stayed readable after the record was sealed. Now
 * only a receipt confirmation is kept, and only the fields the registry sets; anything else
 * (`lab`, and `addressedTo` / `attesterHandle`, the recipient's handle older claims wrote)
 * is dropped on every save and by the purge. Undefined when nothing of it is the registry's.
 */
const REGISTRY_ATTESTATION_FIELDS = ['attesterKey', 'type', 'confirms', 'transferId', 'attestedAt'];
const registryAttestation = (a) => {
  if (!isObject(a) || a.type !== 'receipt-confirmed') return undefined;
  const out = {};
  if (typeof a.attesterKey === 'string' && HEX64.test(a.attesterKey)) out.attesterKey = a.attesterKey;
  out.type = a.type;
  if (typeof a.confirms === 'string' && a.confirms.length <= 200) out.confirms = a.confirms;
  if (typeof a.transferId === 'string' && ID_PATTERN.test(a.transferId)) out.transferId = a.transferId;
  if (typeof a.attestedAt === 'number' && Number.isFinite(a.attestedAt)) out.attestedAt = a.attestedAt;
  return out;
};
/** Whether a stored attestation is exactly what registryAttestation keeps (absent counts). */
const attestationIsClean = (a) => a === undefined
  || JSON.stringify(registryAttestation(a)) === JSON.stringify(a);

/**
 * A stored body with only its public fields (the purge script's reduction of a legacy row):
 * the clear fields as they would be accepted today, and the attestation as the registry
 * writes it.
 */
const publicPartOf = (r) => {
  const out = {};
  for (const k of PUBLIC_RECORD_FIELDS) {
    if (k === 'supersedes') {
      const s = publicSupersedes(r.supersedes);
      if (s) out.supersedes = s;
    } else if (k === 'attestation') {
      const a = registryAttestation(r.attestation);
      if (a) out.attestation = a;
    } else if (k === 'profile') {
      if (KNOWN_PROFILES.includes(r.profile)) out.profile = r.profile;
    } else if (r[k] !== undefined) out[k] = r[k];
  }
  return out;
};

/**
 * Whether a body has anything beyond its public fields as publicPartOf keeps them (a claim's
 * stub has nothing more). A clear name (a row saved before round 5) is not counted here: the
 * purge deals with names on their own (hasClearName), so a claim's stub from before round 5
 * is still a stub, not a plain-text row. A dating row's `bodyPending` is this registry's own
 * mark (CONTRACT.md #38), not something a holder typed: a dating row is public-only too.
 */
const hasPrivateFields = (r) => Object.keys(r).some((k) => !PUBLIC_RECORD_FIELDS.includes(k) && k !== 'contentsRemoved' && k !== 'strainName' && k !== 'bodyPending')
  || (r.supersedes !== undefined && JSON.stringify(publicSupersedes(r.supersedes)) !== JSON.stringify(r.supersedes))
  || !attestationIsClean(r.attestation)
  || (r.profile !== undefined && !KNOWN_PROFILES.includes(r.profile));

module.exports = {
  ID_PATTERN,
  RECORD_MAX_BYTES,
  SEALED_CT_MAX,
  OFFER_MAX_BYTES,
  CUSTODY_CT_MAX,
  KNOWN_PROFILES,
  CHANGED_FIELD_NAMES,
  HANDLE_TAG,
  HANDLE_TAG_PROBLEM,
  legacyHandleReplacement,
  isIsoDateTime,
  PUBLIC_RECORD_FIELDS,
  NAME_IN_CLEAR,
  hasClearName,
  SERVER_KEPT_FIELDS,
  OLDER_COPY,
  olderCopyRefusal,
  REGISTRY_ATTESTATION_FIELDS,
  registryAttestation,
  attestationIsClean,
  sealedProblem,
  boxOf,
  recordRowProblem,
  licenceRowProblem,
  isSealedBody,
  publicSupersedes,
  publicPartOf,
  hasPrivateFields,
  DATING_MAX_PER_REQUEST,
  datingRowProblem,
  isDatingOnlyBody,
  datingBodyOf,
  DIFFERENT_DATED_FINGERPRINT,
};
