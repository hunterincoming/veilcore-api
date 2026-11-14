// The attester registry.
//
// Maps a public key to a claimed identity, and holds signed attestations and their
// retractions. This is the "verifiable data registry" role from the W3C Verifiable
// Credentials model: a place a verifier can look up an issuer.
//
// What this deliberately does NOT do is vouch. An accreditation recorded here is a
// claim by the attester about themselves, with a named accreditor a verifier can check
// independently. A registry that certifies its own members has stopped being neutral,
// and neutrality is the property that lets someone else's registry adopt this format.
//
// Signature verification happens here before anything is stored, so the registry never
// holds an attestation that does not verify — a registry serving unverifiable evidence
// is worse than no registry.
//
// SPDX-License-Identifier: Apache-2.0

import { verifyAttestation, verifyRetraction, attesterId, canonicalise } from 'veilcore-records';

/**
 * How much an attestation is worth, decided by the registry rather than by the signer.
 *
 * The SDK's strengthOf() reads `attester.accreditation` out of the attestation body,
 * which is a field the signer typed. A fresh key naming itself after a real lab, with an
 * inline accreditation, came out "signed-and-accredited" and every verifier said so
 * (attack round 11). Here the top grade means only one thing: the registry operator
 * matched this key's registered name to a public licence or accreditation listing and the
 * lab's own email domain, by the written procedure, within the last 12 months (round 4).
 * It says nothing about the lab's work. Anything else signed is just "signed", whatever it
 * says about itself.
 */
export const strengthFor = (a, vetted) => {
  if (!a?.signature) return 'unsigned';
  return vetted ? 'signed-and-accredited' : 'signed';
};

const MAX = { displayName: 200, role: 64, accreditationField: 200, attestationBytes: 4096, retractionBytes: 2048 };

/**
 * An attestation as stored and served: the fields its signature covers (veilcore-records
 * attestationPayload) and the signature, nothing else (deep dive, 8 Oct 2026, MEDIUM).
 * Everything else a submitter sent, up to 16 KB of it, was stored and handed to anyone who
 * listed the record's attestations, 100 at a time, and parsed on every embed view. Taking
 * fields out changes nothing a verifier checks: the signed payload is built from these.
 */
const ATTESTATION_FIELDS = ['attestationId', 'type', 'subjectCommitment', 'documentHash', 'hashAlgorithm', 'issuedAt', 'signature', 'signatureAlgorithm'];
const ATTESTER_FIELDS = ['publicKey', 'displayName', 'role', 'accreditation'];
const RETRACTION_FIELDS = ['attestationId', 'attesterPublicKey', 'reason', 'retractedAt', 'signature'];
const isPlainObject = (v) => typeof v === 'object' && v !== null && !Array.isArray(v);
const pick = (o, fields) => Object.fromEntries(fields.filter((k) => Object.hasOwn(o, k) && o[k] !== undefined).map((k) => [k, o[k]]));
export const signedAttestation = (a) => ({
  ...pick(a, ATTESTATION_FIELDS),
  ...(isPlainObject(a.attester) ? { attester: pick(a.attester, ATTESTER_FIELDS) } : {}),
});
/** A retraction as stored and served: its signed fields (retractionPayload) and signature. */
export const signedRetraction = (r) => pick(r, RETRACTION_FIELDS);

/**
 * Lab report signatures and the report's hash (round 6, the site's CONTRACT.md #34).
 *
 * A lab report signature used to sign the report file's plain SHA-256, served to anyone with
 * the record's proof code: whoever held a copy of the report could tell which record it was
 * saved to, and the breeder's salted DNA code (#29) added nothing. Since round 6 the lab
 * signs `document` = SHA-256("veilcore:labdoc:v1" 0x00 || report SHA-256 || proof code || s),
 * with s derived from the delivery's offer key, which only the sender and the lab hold. Such a
 * signature's id ends in LAB_DOC_ID_SUFFIX (inside what is signed, so it can't be put on an
 * older one) and is served whole: its `documentHash` says nothing about the file without s.
 *
 * A lab report signature made before then can't be changed (it is signed), and its hash names
 * the file.
 *
 * Who sees a lab's signatures at all (8 Nov 2026). Even with no hash, a signature about a
 * plant's record said which lab handled it: the lab's registered name, whether it is vetted,
 * when it signed, and whether the report was later replaced or withdrawn. Anyone with the
 * record's proof code could read that, so a lab's client list was public. Now these are
 * PRIVATE (isPrivateKind, PRIVATE_SQL):
 *   · every lab report signature (`laboratory-report`), of either form;
 *   · every receipt (`chain-of-custody`): a lab's signed receipt says it took the sample;
 *   · a `genetic-fingerprint` or `inspection` from a lab key: one whose signed attester role
 *     or registered role is "laboratory", or that has signed a lab report or receipt here.
 * A private signature is served only to the record's holder, the delivery's sender and that
 * lab (server.js privateReaderFor, holder key), and to anyone else not at all: not listed, not
 * counted, not in /verify's signed or vetted summary, and not in the per-record ceilings
 * another signer can reach (submit, below), so no count shows that one exists. The holder can
 * choose to publish some on /verify (the grant's sharedAttestations, forIds below), and
 * those are then listed by proof code for everyone too (server.js sharedOnFingerprint, 12 Nov
 * 2026), so the public check of a lab's name on lab-signed numbers that reads the plant's
 * report signature (test network only) finds it when the holder shares it. The salted binding
 * names the lab without it (README, "Lab signatures: who sees them").
 */
export const LAB_DOC_ID_SUFFIX = '_ld1';
export const isBoundLabDocument = (a) =>
  typeof a?.attestationId === 'string' && a.attestationId.endsWith(LAB_DOC_ID_SUFFIX);
/** Whether an attestation, as stored, names a lab report's plain SHA-256 (made before round 6). */
export const namesPlainReportHash = (a) => a?.type === 'laboratory-report' && !isBoundLabDocument(a);
/** Always private, whoever signed. */
export const PRIVATE_TYPES = ['laboratory-report', 'chain-of-custody'];
/** Private when the signer is a lab key. */
export const LAB_KEY_TYPES = ['genetic-fingerprint', 'inspection'];
/** Most attestations one grant may publish (the grant's sharedAttestations). */
export const SHARED_MAX = 50;
const sqlList = (xs) => xs.map((x) => `'${x}'`).join(', ');
const TYPE_OF = (t) => `COALESCE(json_extract(${t}.body, '$.type'), '')`;
/** A lab key, for the row `a`: its signed role, its registered role, or what else it signed. */
const LAB_KEY_SQL = `(lower(COALESCE(json_extract(a.body, '$.attester.role'), '')) = 'laboratory'
  OR EXISTS (SELECT 1 FROM attesters k WHERE k.public_key = a.attester_key AND lower(COALESCE(k.role, '')) = 'laboratory')
  OR EXISTS (SELECT 1 FROM attestations b WHERE b.attester_key = a.attester_key AND ${TYPE_OF('b')} IN (${sqlList(PRIVATE_TYPES)})))`;
/** Whether the stored row `a` is a private signature. */
const PRIVATE_SQL = `(${TYPE_OF('a')} IN (${sqlList(PRIVATE_TYPES)})
  OR (${TYPE_OF('a')} IN (${sqlList(LAB_KEY_TYPES)}) AND ${LAB_KEY_SQL}))`;

/**
 * How many attestations one record may carry (attack round D, 4 Oct 2026). A record's
 * commitment is public, and anyone could sign any number of attestations over a victim's
 * commitment with throwaway keys; every public /verify and /embed of that record then
 * loaded them all.
 *
 * Four ceilings, none shared (13 Nov 2026):
 *   · keys nobody has vetted and keys the operator has vetted are counted apart, so no number
 *     of throwaway keys can keep a vetted lab off a record. Before, the vetted ceiling was a
 *     ceiling on everything, and unvetted signatures counted towards it.
 *   · private signatures (lab reports, receipts, a lab key's other signatures) and the rest
 *     are counted apart (8 Nov 2026): counted together, a stranger could post 99 signatures of
 *     their own and learn from the 100th whether a lab's was already there.
 *
 * Each signature is counted where it was put when it was stored (the ceiling_private and
 * ceiling_vetted columns), never by what the live test says now. A key's genetic-fingerprint
 * signatures turn private (hidden) the moment it signs any lab report, about any record, and
 * counted live they left the 100 public unvetted places and filled the private ones: ten
 * throwaway keys, 100 signatures and one lab report each, and a vetted lab's report or receipt
 * on the victim's record was refused (review of 12 Nov 2026). Stored, a signature stays in the
 * place it took. What is shown still follows the live test, so a lab key's earlier signatures
 * are hidden once it is known to be one.
 */
export const ATTESTATION_LIMITS = {
  unvettedPerSubject: 100,
  vettedPerSubject: 1000,
  unvettedPrivatePerSubject: 100,
  vettedPrivatePerSubject: 1000,
  /** Most rows one read returns. Vetted signers come first, so they are never cut off by junk. */
  page: 100,
};
const shortString = (v, n) => v === undefined || v === null || (typeof v === 'string' && v.length <= n);

/**
 * A name a key gives itself is printed on pages, summaries and a declaration someone may
 * sign (round 2 of the 15 Oct review): a line break in it added lines of its own to the
 * declaration, and a direction mark (U+202E and the like) reversed the text around it. A
 * name with any control or format character (Unicode Cc, Cf: tabs, line breaks, direction
 * marks, zero-width characters) or a line or paragraph separator is refused.
 */
export const HIDDEN_CHARACTER = /[\p{Cc}\p{Cf}\u2028\u2029]/u;
const NAME_WORDS = 'can’t contain line breaks, tabs or hidden characters (such as direction marks or zero-width spaces)';
const badName = (v) => typeof v === 'string' && HIDDEN_CHARACTER.test(v);

const fromHex = (hex) => new Uint8Array((hex.match(/.{1,2}/g) ?? []).map((b) => parseInt(b, 16)));

/** A public key or commitment as veilcore-records 0.15 reads one: 64 lowercase hex. */
const HEX64 = /^[0-9a-f]{64}$/;

/**
 * Ed25519 public keys nobody holds a private key for: the small-order points (libsodium's
 * ge25519_has_small_order list, compared with the x-sign bit cleared) and any y >= p. With
 * one of these, R = that point and S = 0 verifies for EVERY message under the cofactorless
 * check WebCrypto runs, so a "registration signed by the key" proves nothing. The same list
 * veilcore-records 0.15 refuses in verifyAttestation (signing.js), which does not export it.
 */
const SMALL_ORDER = new Set([
  '0000000000000000000000000000000000000000000000000000000000000000',
  '0100000000000000000000000000000000000000000000000000000000000000',
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  'eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
]);
/** Why a 64-lowercase-hex Ed25519 key cannot be anyone's, or null if it can. */
export const unusableKeyReason = (hex) => {
  const y = fromHex(hex);
  y[31] &= 0x7f;
  if (SMALL_ORDER.has(Buffer.from(y).toString('hex'))) return 'a small-order Ed25519 key cannot sign anything';
  if (y[31] === 0x7f && y.subarray(1, 31).every((b) => b === 0xff) && y[0] >= 0xed) {
    return 'the public key is not a canonical Ed25519 encoding';
  }
  return null;
};

/**
 * What an attester signs to register or update its listing. Without a signature anyone
 * could put any name and accreditation on any lab's key (security pass, 1 Oct 2026).
 */
export const registrationPayload = ({ publicKey, displayName, role, accreditation, issuedAt }) =>
  canonicalise({
    type: 'veilcore/attester-registration/v1',
    publicKey,
    ...(displayName === undefined || displayName === null ? {} : { displayName }),
    ...(role === undefined || role === null ? {} : { role }),
    ...(accreditation === undefined || accreditation === null ? {} : { accreditation }),
    issuedAt,
  });

const verifyRegistration = async (reg) => {
  if (!/^[0-9a-fA-F]{128}$/.test(reg.signature ?? '')) return false;
  try {
    const key = await globalThis.crypto.subtle.importKey('raw', fromHex(reg.publicKey), { name: 'Ed25519' }, false, ['verify']);
    return await globalThis.crypto.subtle.verify(
      'Ed25519', key, fromHex(reg.signature), new TextEncoder().encode(registrationPayload(reg)),
    );
  } catch {
    return false;
  }
};

// ---- name checks (round 4) ----
//
// A mark on a key used to be a bare flag and a free-text note. Now it is a record of one
// written procedure (site repo docs/lab-name-checks.md): the operator found the lab in a
// public licence or accreditation listing, had a code signed (or the key's fingerprint
// sent) from an address on the lab's own email domain, and wrote down when and who. The
// label a verifier sees states exactly that and nothing more. A mark without such a
// record, or older than its expiry, reads as "name not checked".

/** Where the name was matched. */
export const CHECK_SOURCES = ['licence-listing', 'accreditation'];
/** Why a mark was taken off. Codes, not free text: the reason is public. */
export const WITHDRAW_REASONS = ['key-compromised', 'lab-closed', 'licence-lapsed', 'name-changed', 'entered-in-error', 'expired', 'other'];
/** A check counts for at most 12 months from the day it was done. */
export const CHECK_MAX_MONTHS = 12;
/** How long a look at a lab's own domain is shown without a newer one (daily looks keep it fresh). */
export const DOMAIN_CHECK_FRESH_DAYS = 7;

const CHECK_FIELDS = ['source', 'sourceUrl', 'licenceNo', 'emailDomain', 'checkedAt', 'checkedBy', 'expiresAt'];
/**
 * Free mail is not a lab's own domain: anyone can make an address there. The check is that
 * the code came back from the domain named in the listing or on the lab's site.
 */
const FREE_MAIL = new Set([
  'gmail.com', 'googlemail.com', 'outlook.com', 'hotmail.com', 'live.com', 'msn.com', 'yahoo.com', 'ymail.com',
  'icloud.com', 'me.com', 'mac.com', 'aol.com', 'proton.me', 'protonmail.com', 'pm.me', 'gmx.com', 'gmx.net',
  'gmx.de', 'mail.com', 'zoho.com', 'yandex.com', 'yandex.ru', 'tutanota.com', 'tuta.io', 'fastmail.com', 'hey.com',
]);
const DOMAIN = /^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const DAY = /^\d{4}-\d{2}-\d{2}$/;
const dayMs = (s) => (typeof s === 'string' && DAY.test(s) ? Date.parse(`${s}T00:00:00Z`) : NaN);
const isDay = (s) => Number.isFinite(dayMs(s)) && new Date(dayMs(s)).toISOString().slice(0, 10) === s;
/** The same calendar day `months` later (31 Jan + 1 month clamps to the month's end). */
const addMonths = (s, months) => {
  const d = new Date(dayMs(s));
  const y = d.getUTCFullYear();
  const m = d.getUTCMonth() + months;
  const last = new Date(Date.UTC(y, m + 1, 0)).getUTCDate();
  return new Date(Date.UTC(y, m, Math.min(d.getUTCDate(), last))).toISOString().slice(0, 10);
};
const today = (now) => new Date(now).toISOString().slice(0, 10);

/**
 * Check the operator's record of a name check. Returns { check } (the record as stored and
 * served) or { error }. Only the listed fields are taken, so nothing personal (a contact's
 * name or address) can ride along into the public answer.
 */
export const validateNameCheck = (check, now = Date.now()) => {
  if (!isPlainObject(check)) return { error: 'check must be an object: { source, sourceUrl, licenceNo, emailDomain, checkedAt, checkedBy, expiresAt? }' };
  const extra = Object.keys(check).filter((k) => !CHECK_FIELDS.includes(k));
  if (extra.length) return { error: `check takes only ${CHECK_FIELDS.join(', ')} (not ${extra.join(', ')}); private notes go in "note"` };
  const { source, sourceUrl, licenceNo, emailDomain, checkedAt, checkedBy, expiresAt } = check;
  if (!CHECK_SOURCES.includes(source)) return { error: `check.source must be one of ${CHECK_SOURCES.join(', ')}` };
  if (typeof sourceUrl !== 'string' || !sourceUrl || sourceUrl.length > 500) {
    return { error: 'check.sourceUrl is required: the public listing where the lab was found' };
  }
  let url;
  try { url = new URL(sourceUrl); } catch { return { error: 'check.sourceUrl must be a full https:// address' }; }
  if (url.protocol !== 'https:' || url.username || url.password || !url.hostname.includes('.')) {
    return { error: 'check.sourceUrl must be a full https:// address with no user name or password in it' };
  }
  if (licenceNo !== undefined && licenceNo !== null &&
      (typeof licenceNo !== 'string' || !/^[\p{L}\p{N}][\p{L}\p{N} ./#:_-]{0,99}$/u.test(licenceNo))) {
    return { error: 'check.licenceNo must be the licence or certificate number as listed (letters, digits, . / # : _ -), at most 100 characters' };
  }
  if (typeof emailDomain !== 'string' || !emailDomain) {
    return { error: 'check.emailDomain is required: the lab’s own email domain the code came back from' };
  }
  const domain = emailDomain.trim().toLowerCase();
  if (domain.includes('@')) return { error: 'check.emailDomain is the domain only (lab.example), never an address' };
  if (!DOMAIN.test(domain)) return { error: 'check.emailDomain must be a domain name such as lab.example' };
  if (FREE_MAIL.has(domain)) return { error: `check.emailDomain ${domain} is a free mail service, not the lab’s own domain` };
  if (!isDay(checkedAt)) return { error: 'check.checkedAt is required: the day the check was done, as YYYY-MM-DD' };
  // A day after today (UTC) is allowed for an operator west of UTC late in the evening.
  if (dayMs(checkedAt) > dayMs(today(now)) + 86_400_000) return { error: 'check.checkedAt is in the future' };
  const latest = addMonths(checkedAt, CHECK_MAX_MONTHS);
  if (dayMs(latest) <= now) return { error: `a check done on ${checkedAt} has already expired; check again` };
  if (typeof checkedBy !== 'string' || !/^[A-Z]{2,4}$/.test(checkedBy)) {
    return { error: 'check.checkedBy is the initials of who did the check, 2 to 4 capital letters' };
  }
  let expires = latest;
  if (expiresAt !== undefined && expiresAt !== null) {
    if (!isDay(expiresAt)) return { error: 'check.expiresAt must be a day as YYYY-MM-DD' };
    if (dayMs(expiresAt) <= dayMs(checkedAt)) return { error: 'check.expiresAt must be after checkedAt' };
    if (dayMs(expiresAt) > dayMs(latest)) return { error: `check.expiresAt can be at most ${CHECK_MAX_MONTHS} months after checkedAt (${latest})` };
    if (dayMs(expiresAt) <= now) return { error: 'check.expiresAt has already passed' };
    expires = expiresAt;
  }
  return {
    check: {
      source,
      sourceUrl: url.href,
      ...(licenceNo ? { licenceNo } : {}),
      emailDomain: domain,
      checkedAt,
      checkedBy,
      expiresAt: expires,
    },
  };
};

/**
 * Where a key's name check stands, from its row. `checked` only for a mark with a check
 * record, unexpired, for the name the key is registered under now.
 */
const nameCheckStatus = (row, now) => {
  if (!row) return { status: 'not-checked', check: null };
  let check = null;
  try { check = row.name_check ? JSON.parse(row.name_check) : null; } catch { check = null; }
  if (row.vetted && check && check.checkedName === (row.display_name ?? null)) {
    if (Number(row.name_check_expires_at) > now) return { status: 'checked', check };
    return { status: 'expired', check };
  }
  if (!row.vetted && row.unvetted_reason) return { status: 'withdrawn', check: null };
  return { status: 'not-checked', check: null };
};

export const createAttesters = (db, { now = () => Date.now() } = {}) => {
  db.exec(`
    CREATE TABLE IF NOT EXISTS attesters (
      public_key    TEXT PRIMARY KEY,
      attester_id   TEXT NOT NULL,
      display_name  TEXT,
      role          TEXT,
      accreditation TEXT,
      registered_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS attestations (
      attestation_id     TEXT PRIMARY KEY,
      subject_commitment TEXT NOT NULL,
      attester_key       TEXT NOT NULL,
      body               TEXT NOT NULL,
      created_at         INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS attestations_subject ON attestations(subject_commitment);
    CREATE TABLE IF NOT EXISTS retractions (
      attestation_id TEXT PRIMARY KEY,
      body           TEXT NOT NULL,
      retracted_at   INTEGER NOT NULL
    );
  `);
  // Operator vetting (attack round 11). A registration is a key naming itself; anyone can
  // make one in a lab's name. `vetted` is set only by the registry operator, after
  // checking out of band that the key belongs to who it says, and it is the only thing
  // that lets a verifier describe a signer as a lab.
  const cols = db.prepare('PRAGMA table_info(attesters)').all().map((c) => c.name);
  if (!cols.includes('vetted')) db.exec('ALTER TABLE attesters ADD COLUMN vetted INTEGER NOT NULL DEFAULT 0');
  if (!cols.includes('vetted_at')) db.exec('ALTER TABLE attesters ADD COLUMN vetted_at INTEGER');
  if (!cols.includes('vetted_note')) db.exec('ALTER TABLE attesters ADD COLUMN vetted_note TEXT');
  // Round 4: the check record behind a mark (JSON, public), when it stops counting (ms),
  // and the last withdrawal. A mark made before this has no record: it reads as "name not
  // checked" from now on, and the operator re-checks the lab to restore it. Intended.
  if (!cols.includes('name_check')) db.exec('ALTER TABLE attesters ADD COLUMN name_check TEXT');
  if (!cols.includes('name_check_expires_at')) db.exec('ALTER TABLE attesters ADD COLUMN name_check_expires_at INTEGER');
  if (!cols.includes('unvetted_at')) db.exec('ALTER TABLE attesters ADD COLUMN unvetted_at INTEGER');
  if (!cols.includes('unvetted_reason')) db.exec('ALTER TABLE attesters ADD COLUMN unvetted_reason TEXT');
  // The lab's own website or DNS listing this key (lab-domain.mjs): the last look, as seen.
  if (!cols.includes('domain_check')) db.exec('ALTER TABLE attesters ADD COLUMN domain_check TEXT');
  // Every mark and unmark, kept. The note is the operator's private working note (what was
  // seen, who replied); it is only ever read back through the operator route.
  db.exec(`
    CREATE TABLE IF NOT EXISTS attester_vetting_log (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      public_key TEXT NOT NULL,
      action     TEXT NOT NULL,
      check_json TEXT,
      reason     TEXT,
      note       TEXT,
      at         INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS attester_vetting_log_key ON attester_vetting_log(public_key);
  `);

  // Rows stored before 8 Oct 2026 carry whatever was submitted around the signed fields.
  // Trimmed once, here; a row already trimmed is left alone, so this is safe on every start.
  // A row whose signed fields alone exceed today's limit is kept as it is: it was accepted,
  // and its signature still verifies.
  {
    const trim = (table, idCol, shape) => {
      let n = 0;
      const update = db.prepare(`UPDATE ${table} SET body = ? WHERE ${idCol} = ?`);
      for (const row of db.prepare(`SELECT ${idCol} AS id, body FROM ${table}`).all()) {
        let parsed;
        try { parsed = JSON.parse(row.body); } catch { continue; }
        if (!isPlainObject(parsed)) continue;
        const trimmed = JSON.stringify(shape(parsed));
        if (trimmed !== row.body) { update.run(trimmed, row.id); n++; }
      }
      return n;
    };
    const counts = db.transaction(() => [trim('attestations', 'attestation_id', signedAttestation), trim('retractions', 'attestation_id', signedRetraction)])();
    if (counts[0] + counts[1] > 0) console.log(`attestations: kept only the signed fields of ${counts[0]} attestations and ${counts[1]} retractions`);
  }

  // A key counts as checked only with an unexpired check record. The name match is also
  // enforced in register(): a rename drops the mark and its record together.
  const CHECKED = `t.vetted = 1 AND t.name_check IS NOT NULL AND t.name_check_expires_at > ?
    AND json_extract(t.name_check, '$.checkedName') IS t.display_name`;
  // The lab key test reads attestations by signer.
  db.exec('CREATE INDEX IF NOT EXISTS attestations_attester ON attestations(attester_key)');
  // Which ceiling each signature counts against, fixed when it is stored (ATTESTATION_LIMITS,
  // 13 Nov 2026). Rows stored before get it once, here, as submit() would have put them then:
  // a genetic-fingerprint or inspection is private if its signed role or its key's registered
  // role is "laboratory", or its key had already signed a lab report or receipt (rowid is the
  // order rows were stored in). The registered role is the one on record now; no older one is
  // kept. Vetted means the key's name check stands now.
  if (!db.prepare("SELECT 1 FROM pragma_table_info('attestations') WHERE name = 'ceiling_private'").get()) {
    db.transaction(() => {
      db.exec('ALTER TABLE attestations ADD COLUMN ceiling_private INTEGER NOT NULL DEFAULT 0');
      db.exec('ALTER TABLE attestations ADD COLUMN ceiling_vetted INTEGER NOT NULL DEFAULT 0');
      db.prepare(`UPDATE attestations AS a SET
          ceiling_private = CASE WHEN ${TYPE_OF('a')} IN (${sqlList(PRIVATE_TYPES)})
            OR (${TYPE_OF('a')} IN (${sqlList(LAB_KEY_TYPES)}) AND (
              lower(COALESCE(json_extract(a.body, '$.attester.role'), '')) = 'laboratory'
              OR EXISTS (SELECT 1 FROM attesters k WHERE k.public_key = a.attester_key AND lower(COALESCE(k.role, '')) = 'laboratory')
              OR EXISTS (SELECT 1 FROM attestations b WHERE b.attester_key = a.attester_key AND b.rowid < a.rowid
                AND ${TYPE_OF('b')} IN (${sqlList(PRIVATE_TYPES)}))))
            THEN 1 ELSE 0 END,
          ceiling_vetted = CASE WHEN EXISTS (SELECT 1 FROM attesters t WHERE t.public_key = a.attester_key AND ${CHECKED})
            THEN 1 ELSE 0 END`).run(now());
    })();
  }
  db.exec('CREATE INDEX IF NOT EXISTS attestations_ceiling ON attestations(subject_commitment, ceiling_private, ceiling_vetted)');
  // Which private signatures on a record this reader may see (8 Nov 2026), as a JSON list of
  // ids for SHOWN. None without a reader test. Bounded by the four ceilings above.
  const shownPrivate = (c, canSee) => {
    if (typeof canSee !== 'function') return '[]';
    // The reader is told when each was stored (server.js privateReaderFor: a holder or sender
    // counts only from before the signature).
    const ids = db.prepare(`SELECT a.body, a.created_at FROM attestations a WHERE a.subject_commitment = ? AND ${PRIVATE_SQL}`)
      .all(c)
      .map((r) => ({ a: signedAttestation(JSON.parse(r.body)), createdAt: r.created_at }))
      .filter(({ a, createdAt }) => canSee(a, { createdAt }) === true)
      .map(({ a }) => a.attestationId);
    return JSON.stringify(ids);
  };
  // Every public attestation, and the private ones listed.
  const SHOWN = `(NOT ${PRIVATE_SQL} OR a.attestation_id IN (SELECT value FROM json_each(?)))`;
  /** Whether a signature not yet stored would be private: its type, and for some, its key. */
  const privateOnSubmit = (a) => {
    if (PRIVATE_TYPES.includes(a.type)) return true;
    if (!LAB_KEY_TYPES.includes(a.type)) return false;
    if (String(a.attester?.role ?? '').toLowerCase() === 'laboratory') return true;
    const k = a.attester?.publicKey;
    if (String(db.prepare('SELECT role FROM attesters WHERE public_key = ?').get(k)?.role ?? '').toLowerCase() === 'laboratory') return true;
    return !!db.prepare(`SELECT 1 FROM attestations b WHERE b.attester_key = ? AND ${TYPE_OF('b')} IN (${sqlList(PRIVATE_TYPES)}) LIMIT 1`).get(k);
  };
  const isVetted = (publicKey) =>
    nameCheckStatus(db.prepare('SELECT * FROM attesters WHERE public_key = ?').get(publicKey), now()).status === 'checked';
  /**
   * The last look at the lab's own domain, while it is recent and found the key listed.
   * Older than DOMAIN_CHECK_FRESH_DAYS (the daily look stopped, or the domain stopped
   * answering), or not listed: nothing is shown.
   */
  const publicDomainCheck = (json) => {
    if (!json) return null;
    let c;
    try {
      c = JSON.parse(json);
    } catch {
      return null;
    }
    const age = now() - Date.parse(c.checkedAt);
    if (!c.listed || !(age >= -60_000 && age <= DOMAIN_CHECK_FRESH_DAYS * 86_400_000)) return null;
    return {
      domain: c.domain, method: c.method, checkedAt: c.checkedAt,
      ...(c.fileSha256 ? { fileSha256: c.fileSha256 } : {}),
      ...(c.listedName ? { listedName: c.listedName } : {}),
      // The key's own signature naming this domain (lab-domain.mjs domainClaimPayload), so
      // anyone can check that direction too, not only the registry.
      ...(c.claimSignature && Number.isSafeInteger(c.claimIssuedAt) ? { claim: { issuedAt: c.claimIssuedAt, signature: c.claimSignature } } : {}),
    };
  };
  /** What the public may read about a key's name check: the record, never a note. */
  const publicNameCheck = (row) => {
    const { status, check } = nameCheckStatus(row, now());
    return {
      vetted: status === 'checked',
      nameCheckStatus: status,
      nameCheck: status === 'checked' ? check : null,
      ...(status === 'expired' ? { nameCheckExpiredOn: check.expiresAt } : {}),
      ...(status === 'withdrawn' ? { withdrawn: { at: new Date(row.unvetted_at).toISOString(), reason: row.unvetted_reason } } : {}),
    };
  };
  // One attestation as served: its signed fields, with strength, vetting and retraction.
  const ROW_SELECT = `
        SELECT a.body, a.created_at AS stored_at, r.body AS retraction, t.display_name, t.accreditation, t.public_key AS registered,
               t.vetted AS vetted_flag, t.domain_check, t.name_check, t.name_check_expires_at, t.unvetted_at, t.unvetted_reason,
               CASE WHEN ${CHECKED} THEN 1 ELSE 0 END AS vetted,
               CASE WHEN ${PRIVATE_SQL} THEN 1 ELSE 0 END AS is_private
        FROM attestations a
        LEFT JOIN attesters t ON t.public_key = a.attester_key
        LEFT JOIN retractions r ON r.attestation_id = a.attestation_id`;
  // `mark`: add `private` (below) to a private row. Only for a reader the row is shown to as
  // its holder, sender or lab (forSubject's markPrivate), never for one it is shown to because
  // the holder shares it (13 Nov 2026): to a stranger the mark said the signer is a lab key.
  const served = (row, mark = false) => {
    // Signed fields only, whatever an older row holds.
    const a = signedAttestation(JSON.parse(row.body));
    const pub = row.registered
      ? publicNameCheck({ ...row, vetted: row.vetted_flag })
      : { vetted: false, nameCheckStatus: 'not-checked', nameCheck: null };
    const vetted = pub.vetted;
    return {
      ...a,
      // Not strengthOf(a): that reads an accreditation the signer typed into the body.
      strength: strengthFor(a, vetted),
      // True only when the registry operator has checked who holds this key.
      vettedAttester: vetted,
      registeredAs: row.registered
        ? {
            displayName: row.display_name,
            accreditation: row.accreditation ? JSON.parse(row.accreditation) : null,
            vetted,
            selfRegistered: !vetted,
            // The record behind the mark: where the name was matched, when, by whom.
            nameCheck: pub.nameCheck,
            nameCheckStatus: pub.nameCheckStatus,
            domainCheck: publicDomainCheck(row.domain_check),
          }
        : null,
      retraction: row.retraction ? signedRetraction(JSON.parse(row.retraction)) : null,
      // A private signature (PRIVATE_SQL, 8 Nov 2026), on a row served to its holder, sender or
      // lab (12 Nov 2026): the holder's app offers to show exactly these on the check link, a lab
      // key's genetic-fingerprint or inspection included, which only this registry can tell
      // apart. Outside the signed fields, like `strength`. Never on a row a stranger reads
      // because the holder shares it (13 Nov 2026): there it would say the key is a lab's.
      ...(mark && row.is_private ? { private: true } : {}),
    };
  };

  const log = db.prepare('INSERT INTO attester_vetting_log (public_key, action, check_json, reason, note, at) VALUES (?,?,?,?,?,?)');

  return {
    /**
     * Register an attester.
     *
     * The public key is the identity. A display name and accreditation are claims the
     * attester makes about themselves — recorded, never verified by us.
     */
    async register(reg) {
      const { publicKey, displayName, role, accreditation, issuedAt } = reg;
      // Lowercase only (veilcore-records 0.15): an attestation signed by an uppercase key no
      // longer verifies, and lookups are by the exact text, so a key registered in capitals
      // would name an attester whose attestations can never be stored.
      if (typeof publicKey !== 'string' || !HEX64.test(publicKey)) {
        return { error: 'publicKey must be a 32-byte ed25519 public key as 64 lowercase hex characters' };
      }
      // Checked before the signature: a small-order key "signs" every message (round D
      // verification, Low), so the signature check below would pass for anyone.
      const unusable = unusableKeyReason(publicKey);
      if (unusable) return { error: unusable };
      if (!Number.isSafeInteger(issuedAt) || Math.abs(Date.now() - issuedAt) > 15 * 60_000) {
        return { error: 'issuedAt must be the signing time in milliseconds, within 15 minutes of now' };
      }
      if (!shortString(displayName, MAX.displayName) || !shortString(role, MAX.role)) {
        return { error: `displayName must be a string of at most ${MAX.displayName} characters, role at most ${MAX.role}` };
      }
      if (badName(displayName)) return { error: `displayName ${NAME_WORDS}` };
      if (accreditation !== undefined && accreditation !== null) {
        const ok = typeof accreditation === 'object' && !Array.isArray(accreditation) &&
          Object.keys(accreditation).length <= 8 &&
          Object.values(accreditation).every((v) => typeof v === 'string' && v.length <= MAX.accreditationField);
        if (!ok) return { error: 'accreditation must be a small object of short strings' };
      }
      if (!(await verifyRegistration(reg))) {
        return { error: 'registration must be signed by the key being registered' };
      }
      const existing = db.prepare('SELECT * FROM attesters WHERE public_key = ?').get(publicKey);
      if (existing && existing.registered_at >= issuedAt) {
        return { error: 'a newer registration for this key is already on record' };
      }
      // Vetting covers the name and accreditation the operator checked. Changing either
      // drops it: otherwise a vetted key could rename itself to anything and keep the
      // badge.
      const accJson = accreditation ? JSON.stringify(accreditation) : null;
      const keepVetting = !!existing?.vetted &&
        existing.display_name === (displayName ?? null) && existing.accreditation === accJson;
      const id = await attesterId(publicKey);
      // The check record goes with the mark. A withdrawal (and its reason) stays: a key
      // taken off as compromised must not lose that by registering again.
      db.prepare(`INSERT OR REPLACE INTO attesters
        (public_key, attester_id, display_name, role, accreditation, registered_at, vetted, vetted_at, vetted_note,
         name_check, name_check_expires_at, unvetted_at, unvetted_reason)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`)
        .run(publicKey, id, displayName ?? null, role ?? null, accJson, issuedAt,
             keepVetting ? 1 : 0, keepVetting ? existing.vetted_at : null, keepVetting ? existing.vetted_note : null,
             keepVetting ? existing.name_check : null, keepVetting ? existing.name_check_expires_at : null,
             existing?.unvetted_at ?? null, existing?.unvetted_reason ?? null);
      if (existing?.vetted && !keepVetting) {
        log.run(publicKey, 'unmark', null, 'name-changed', 'dropped automatically: the key registered a new name or accreditation', now());
      }
      return { attesterId: id, publicKey, displayName, accreditation: accreditation ?? null, vetted: keepVetting && isVetted(publicKey) };
    },

    /**
     * Operator only (the route checks the token): mark a key's name as checked, or take
     * the mark off. The procedure is docs/lab-name-checks.md in the site repo.
     *
     *   mark:   { vetted: true, check: { source, sourceUrl, licenceNo?, emailDomain, checkedAt, checkedBy, expiresAt? }, note? }
     *   unmark: { vetted: false, reason: one of WITHDRAW_REASONS, note? }
     *
     * `note` is private (what was seen, who replied) and never served publicly. Marking
     * again with a fresh check is how a mark is renewed before it expires.
     */
    setVetted(publicKey, body) {
      if (typeof publicKey !== 'string' || !HEX64.test(publicKey)) return { error: 'publicKey must be 64 lowercase hex characters' };
      if (!isPlainObject(body)) return { error: 'body must be { vetted, check | reason, note? }' };
      const { vetted, check, reason, note } = body;
      if (typeof vetted !== 'boolean') return { error: 'vetted must be true or false' };
      if (!shortString(note, 500)) return { error: 'note must be at most 500 characters' };
      const row = db.prepare('SELECT * FROM attesters WHERE public_key = ?').get(publicKey);
      if (!row) return { error: 'not registered' };
      const at = now();
      if (vetted) {
        const out = validateNameCheck(check, at);
        if (out.error) return { error: out.error };
        if (!row.display_name || !row.display_name.trim()) return { error: 'this key has no registered name to check' };
        // A compromised key stays off: whoever has it can sign as the lab. The lab makes a
        // new key and that one is checked.
        if (!row.vetted && row.unvetted_reason === 'key-compromised') {
          return { error: 'this key was taken off as compromised; the lab must make a new key, and that key is checked' };
        }
        const stored = { ...out.check, checkedName: row.display_name };
        const json = JSON.stringify(stored);
        db.transaction(() => {
          db.prepare(`UPDATE attesters SET vetted = 1, vetted_at = ?, vetted_note = NULL, name_check = ?,
            name_check_expires_at = ?, unvetted_at = NULL, unvetted_reason = NULL WHERE public_key = ?`)
            .run(at, json, dayMs(stored.expiresAt), publicKey);
          log.run(publicKey, 'mark', json, null, note ?? null, at);
        })();
        return { publicKey, vetted: true, nameCheck: stored };
      }
      if (!WITHDRAW_REASONS.includes(reason)) {
        return { error: `taking a mark off needs a reason, one of ${WITHDRAW_REASONS.join(', ')}` };
      }
      db.transaction(() => {
        db.prepare(`UPDATE attesters SET vetted = 0, vetted_at = NULL, vetted_note = NULL, name_check = NULL,
          name_check_expires_at = NULL, unvetted_at = ?, unvetted_reason = ? WHERE public_key = ?`)
          .run(at, reason, publicKey);
        log.run(publicKey, 'unmark', null, reason, note ?? null, at);
      })();
      return { publicKey, vetted: false, withdrawn: { at: new Date(at).toISOString(), reason } };
    },

    /** Operator only: every mark and unmark for a key, notes included, newest first. */
    vettingLog(publicKey) {
      return db.prepare('SELECT action, check_json, reason, note, at FROM attester_vetting_log WHERE public_key = ? ORDER BY id DESC LIMIT 200')
        .all(String(publicKey ?? ''))
        .map((r) => ({
          action: r.action,
          ...(r.check_json ? { check: JSON.parse(r.check_json) } : {}),
          ...(r.reason ? { reason: r.reason } : {}),
          ...(r.note ? { note: r.note } : {}),
          at: new Date(r.at).toISOString(),
        }));
    },

    lookup(publicKey) {
      const r = db.prepare('SELECT * FROM attesters WHERE public_key = ?').get(publicKey);
      if (!r) return null;
      return {
        attesterId: r.attester_id,
        publicKey: r.public_key,
        displayName: r.display_name,
        role: r.role,
        // The attester's own claim. Recorded, never verified, unless `vetted` says so.
        accreditation: r.accreditation ? JSON.parse(r.accreditation) : null,
        registeredAt: r.registered_at,
        // True only for a name check on record, unexpired, for this name. A mark made
        // before round 4 has no record and reads false. The private note is never served.
        ...publicNameCheck(r),
        // The lab's own domain lists this key (lab-domain.mjs), as last seen; null otherwise.
        domainCheck: publicDomainCheck(r.domain_check),
      };
    },

    /**
     * The domain the key itself named (a signed claim, lab-domain.mjs verifyDomainClaim), or
     * an error. A claim older than the one on record is refused, so an old signature can't
     * point a lab back at a domain it has left.
     */
    claimDomain(publicKey, domain, issuedAt) {
      const row = db.prepare('SELECT domain_check FROM attesters WHERE public_key = ?').get(publicKey);
      if (!row) return { error: 'not registered' };
      if (issuedAt > now() + 5 * 60_000) return { error: 'issuedAt is in the future' };
      let prev = null;
      try { prev = row.domain_check ? JSON.parse(row.domain_check) : null; } catch { /* unreadable: replaced */ }
      if (prev?.claimIssuedAt && issuedAt <= prev.claimIssuedAt) return { error: 'an older claim than the one on record' };
      return { ok: true, prev };
    },

    /**
     * Record a look at the lab's domain (lab-domain.mjs checkLabDomain's result). `claimIssuedAt`
     * comes from the key's signed claim when the lab asked; a daily look keeps the one on record.
     * A domain not found for 30 days is forgotten.
     */
    setDomainCheck(publicKey, result, { claimIssuedAt, claimSignature, expectDomain } = {}) {
      const row = db.prepare('SELECT domain_check FROM attesters WHERE public_key = ?').get(publicKey);
      if (!row) return { error: 'not registered' };
      let prev = null;
      try { prev = row.domain_check ? JSON.parse(row.domain_check) : null; } catch { /* replaced */ }
      const { domain, listed, method, checkedAt, fileSha256, listedName } = result;
      // A daily look writes only if the lab hasn't named another domain while it looked
      // (second check, 5 Nov 2026: it could put the old domain back).
      if (expectDomain !== undefined && prev?.domain !== expectDomain) return { ok: true, skipped: true };
      const sameDomain = prev?.domain === domain;
      const listedAt = listed ? checkedAt : sameDomain ? prev?.listedAt : undefined;
      const since = sameDomain ? (prev?.since ?? checkedAt) : checkedAt;
      if (!listed && Date.parse(checkedAt) - Date.parse(listedAt ?? since) > 30 * 86_400_000) {
        // Forget the domain but keep the newest claim's time, so an old signed claim can't
        // be replayed afterwards.
        db.prepare('UPDATE attesters SET domain_check = ? WHERE public_key = ?').run(
          JSON.stringify({ forgotten: true, listed: false, claimIssuedAt: claimIssuedAt ?? prev?.claimIssuedAt }),
          publicKey,
        );
        return { ok: true, forgotten: true };
      }
      db.prepare('UPDATE attesters SET domain_check = ? WHERE public_key = ?').run(
        JSON.stringify({
          domain, listed: !!listed, method, checkedAt, fileSha256, listedName, listedAt, since,
          claimIssuedAt: claimIssuedAt ?? (sameDomain ? prev?.claimIssuedAt : undefined),
          claimSignature: claimSignature ?? (sameDomain ? prev?.claimSignature : undefined),
        }),
        publicKey,
      );
      return { ok: true };
    },

    /** Keys with a domain on record whose last look is older than `olderThanMs`, oldest first. */
    domainChecksDue(olderThanMs = 23 * 3_600_000, limit = 500) {
      const before = new Date(now() - olderThanMs).toISOString();
      return db
        .prepare(`SELECT public_key, json_extract(domain_check, '$.domain') AS domain FROM attesters
          WHERE domain_check IS NOT NULL AND json_extract(domain_check, '$.domain') IS NOT NULL
            AND json_extract(domain_check, '$.checkedAt') < ?
          ORDER BY json_extract(domain_check, '$.checkedAt') LIMIT ?`)
        .all(before, limit)
        .map((r) => ({ publicKey: r.public_key, domain: r.domain }));
    },

    /**
     * Store an attestation, but only if its signature verifies.
     *
     * The check happens before storage so the registry can never serve an attestation
     * that does not verify. An unregistered attester is accepted — the signature is
     * what makes it evidence, and registration only adds a name to a key.
     */
    async submit(a) {
      if (typeof a !== 'object' || a === null || Array.isArray(a)) return { error: 'an attestation is a JSON object' };
      // The signer's name inside a signed attestation is printed the same way as a registered one.
      if (typeof a.attester === 'object' && a.attester !== null && badName(a.attester.displayName)) {
        return { error: `attester.displayName ${NAME_WORDS}` };
      }
      if (typeof a.attestationId !== 'string' || !a.attestationId || a.attestationId.length > 200) {
        return { error: 'attestationId required, at most 200 characters' };
      }
      // Lowercase only. Record fingerprints are lowercase, so an uppercase subject was stored
      // against nothing any lookup would find (round D verification, Low); 0.15 also refuses
      // to verify one. Checked first so the answer says what is wrong.
      if (typeof a.subjectCommitment !== 'string' || !HEX64.test(a.subjectCommitment)) {
        return { error: 'subjectCommitment must be a 32-byte commitment as 64 lowercase hex characters' };
      }
      // Only the signed fields are kept (deep dive, 8 Oct 2026); what is stored is what
      // was verified. veilcore-records 0.15: never throws, and false for an uppercase or
      // small-order key, a missing signed field or a malformed signature.
      const signed = signedAttestation(a);
      if (!(await verifyAttestation(signed))) {
        return { error: 'signature does not verify' };
      }
      const body = JSON.stringify(signed);
      if (Buffer.byteLength(body) > MAX.attestationBytes) {
        return { error: `an attestation's signed fields may be at most ${MAX.attestationBytes} bytes` };
      }
      a = signed;
      // First write wins. With INSERT OR REPLACE anyone could sign their own attestation
      // under a lab's attestation id and the lab's would disappear.
      const prior = db.prepare('SELECT body FROM attestations WHERE attestation_id = ?').get(a.attestationId);
      if (prior) {
        return prior.body === body
          ? { attestationId: a.attestationId, strength: strengthFor(a, isVetted(a.attester.publicKey)), registered: !!this.lookup(a.attester.publicKey) }
          : { error: 'that attestation id is already used by another attestation' };
      }
      // Per-record ceilings (round D). After the duplicate check, so re-sending an
      // attestation that is already stored stays idempotent.
      // Four ceilings, none shared (ATTESTATION_LIMITS): private or not, vetted or not, each
      // as stored with the signature, so nothing done later moves a signature into another's
      // place and no other signer's answer depends on whether a lab's signature is stored.
      const priv = privateOnSubmit(a);
      const vetted = isVetted(a.attester.publicKey);
      const most = vetted
        ? (priv ? ATTESTATION_LIMITS.vettedPrivatePerSubject : ATTESTATION_LIMITS.vettedPerSubject)
        : (priv ? ATTESTATION_LIMITS.unvettedPrivatePerSubject : ATTESTATION_LIMITS.unvettedPerSubject);
      const what = priv ? 'lab signatures (reports, receipts and other signatures from lab keys)' : 'attestations';
      const onSubject = db.prepare(`SELECT COUNT(*) AS n FROM attestations
        WHERE subject_commitment = ? AND ceiling_private = ? AND ceiling_vetted = ?`)
        .get(a.subjectCommitment, priv ? 1 : 0, vetted ? 1 : 0).n;
      if (onSubject >= most) {
        return vetted
          ? { error: `a record may carry at most ${most} ${what} from vetted keys` }
          : {
              error: `this record already carries ${most} ${what} from keys nobody has vetted; ` +
                'ask the registry operator to vet your key',
            };
      }
      db.prepare(`INSERT INTO attestations
        (attestation_id, subject_commitment, attester_key, body, created_at, ceiling_private, ceiling_vetted)
        VALUES (?,?,?,?,?,?,?)`)
        .run(a.attestationId, a.subjectCommitment, a.attester.publicKey, body, Date.now(), priv ? 1 : 0, vetted ? 1 : 0);
      return { attestationId: a.attestationId, strength: strengthFor(a, isVetted(a.attester.publicKey)), registered: !!this.lookup(a.attester.publicKey) };
    },

    /**
     * Retract an attestation.
     *
     * Verified against the attestation it retracts, so only the issuing key can retract
     * and a holder cannot suppress one. The attestation is not deleted — it happened,
     * and pretending otherwise is the same failure as voiding a record.
     */
    async retract(r) {
      const row = db.prepare('SELECT body FROM attestations WHERE attestation_id = ?').get(r.attestationId);
      if (!row) return { error: 'no such attestation' };
      const a = JSON.parse(row.body);
      if (!isPlainObject(r)) return { error: 'a retraction is a JSON object' };
      const signed = signedRetraction(r);
      if (!(await verifyRetraction(signed, a))) {
        return { error: 'retraction does not verify, or was not signed by the issuing key' };
      }
      // A retraction had no size limit at all, and is served with its attestation.
      const body = JSON.stringify(signed);
      if (Buffer.byteLength(body) > MAX.retractionBytes) {
        return { error: `a retraction's signed fields may be at most ${MAX.retractionBytes} bytes; shorten the reason` };
      }
      db.prepare('INSERT OR REPLACE INTO retractions (attestation_id, body, retracted_at) VALUES (?,?,?)')
        .run(r.attestationId, body, Date.now());
      return { attestationId: r.attestationId, retracted: true };
    },

    /**
     * Attestations about a record, with retraction status and strength, a page at a time.
     *
     * One query. This used to run a lookup and a retraction query per row, for every row,
     * on every public verify of the record, and an attacker chose the row count (round D).
     * Vetted signers come first, then oldest first, so a page of junk never hides a lab.
     *
     * Private signatures (8 Nov 2026) are in it only where canSeePrivate says so: the record's
     * holder, the delivery's sender and that lab (server.js privateReaderFor). Left out in the
     * query, not after it, so pages and totals are the same as if they weren't stored.
     *
     * markPrivate: the reader test that may see a private row's `private` mark (the holder's,
     * sender's or lab's own); a row shown only because canSeePrivate lets it through for another
     * reason (the holder shares it) goes out unmarked.
     */
    forSubject(commitment, { limit = ATTESTATION_LIMITS.page, offset = 0, canSeePrivate, markPrivate } = {}) {
      const n = Math.min(Math.max(Number.parseInt(limit, 10) || ATTESTATION_LIMITS.page, 1), ATTESTATION_LIMITS.page);
      const skip = Math.max(Number.parseInt(offset, 10) || 0, 0);
      const c = String(commitment ?? '');
      return db.prepare(`${ROW_SELECT}
        WHERE a.subject_commitment = ? AND ${SHOWN}
        ORDER BY vetted DESC, a.created_at, a.attestation_id
        LIMIT ? OFFSET ?`).all(now(), c, shownPrivate(c, canSeePrivate), n, skip)
        .map((row) => served(row, !!row.is_private && typeof markPrivate === 'function' &&
          markPrivate(signedAttestation(JSON.parse(row.body)), { createdAt: row.stored_at }) === true));
    },

    /**
     * The attestations a holder chose to publish (the grant's sharedAttestations, 8 Nov 2026),
     * in the order named: only those about `commitment`, and a private one only where
     * canSeePrivate (the record holder's reader) still says so. Anything else named is
     * left out, never reported as missing. Served to strangers (/verify, the embed), so never
     * with the `private` mark.
     */
    forIds(commitment, ids, { canSeePrivate } = {}) {
      const c = String(commitment ?? '');
      if (!Array.isArray(ids) || !ids.length) return [];
      const named = ids.filter((id) => typeof id === 'string').slice(0, SHARED_MAX);
      const rows = db.prepare(`${ROW_SELECT}
        WHERE a.subject_commitment = ? AND a.attestation_id IN (SELECT value FROM json_each(?))`)
        .all(now(), c, JSON.stringify(named));
      const isPriv = db.prepare(`SELECT ${PRIVATE_SQL} AS p FROM attestations a WHERE a.attestation_id = ?`);
      const byId = new Map(rows.map((r) => [JSON.parse(r.body).attestationId, r]));
      const out = [];
      for (const id of new Set(named)) {
        const row = byId.get(id);
        if (!row) continue;
        const a = signedAttestation(JSON.parse(row.body));
        if (isPriv.get(id).p && !(typeof canSeePrivate === 'function' && canSeePrivate(a, { createdAt: row.stored_at }) === true)) continue;
        out.push(served(row));
      }
      return out;
    },

    /** Whether a stored attestation is private (8 Nov 2026); undefined if there is none. */
    isPrivate(attestationId) {
      const r = db.prepare(`SELECT ${PRIVATE_SQL} AS p FROM attestations a WHERE a.attestation_id = ?`).get(String(attestationId ?? ''));
      return r ? !!r.p : undefined;
    },

    /** One stored attestation's signed fields, or null. */
    signedFields(attestationId) {
      const r = db.prepare('SELECT body FROM attestations WHERE attestation_id = ?').get(String(attestationId ?? ''));
      return r ? signedAttestation(JSON.parse(r.body)) : null;
    },

    /** When the registry stored an attestation (ms), or undefined. */
    storedAt(attestationId) {
      return db.prepare('SELECT created_at FROM attestations WHERE attestation_id = ?').get(String(attestationId ?? ''))?.created_at;
    },

    /**
     * How many attestations a record carries (for paging): the same rows forSubject would
     * list for this reader, so a total never counts a private signature they can't see.
     */
    countForSubject(commitment, { canSeePrivate } = {}) {
      const c = String(commitment ?? '');
      return db.prepare(`SELECT COUNT(*) AS n FROM attestations a WHERE a.subject_commitment = ? AND ${SHOWN}`)
        .get(c, shownPrivate(c, canSeePrivate)).n;
    },

    /**
     * What /verify reports, in two indexed lookups whatever the row count: is there any
     * signed, unretracted attestation, and is one of them from a vetted key. Every stored
     * attestation is signed (submit refuses any that does not verify). Private signatures
     * never count (8 Nov 2026): /verify is public, and "a vetted lab signed" about a plant
     * whose only signature is a lab's report or receipt says which lab handled it.
     */
    summaryFor(commitment) {
      const c = String(commitment ?? '');
      const live = `FROM attestations a WHERE a.subject_commitment = ? AND NOT ${PRIVATE_SQL}
        AND NOT EXISTS (SELECT 1 FROM retractions r WHERE r.attestation_id = a.attestation_id)`;
      const signed = !!db.prepare(`SELECT 1 ${live} LIMIT 1`).get(c);
      const vetted = signed && !!db.prepare(`SELECT 1 ${live}
        AND EXISTS (SELECT 1 FROM attesters t WHERE t.public_key = a.attester_key AND ${CHECKED}) LIMIT 1`).get(c, now());
      return { signed, vetted };
    },
  };
};
