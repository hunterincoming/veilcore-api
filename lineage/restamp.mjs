// The evidence re-stamp: once a year (and when the operator asks), one Bitcoin stamp over a
// fingerprint of every piece of evidence this registry holds.
//
// Why (the site's docs/design/hash-based-signatures.md, section 4, and docs/restamp.md): if
// elliptic-curve or RSA signatures are ever broken, a lab signature, a withdrawal or an RFC
// 3161 token keeps its weight only if something shows it existed before the break. Bitcoin's
// dates rest on SHA-256 and proof of work, not on signatures, so they survive. Every hourly
// batch root is already stamped; the signatures and tokens are not. This stamps all of them.
// It is the long-term archive method of RFC 4998 (Evidence Record Syntax), in VeilCore's own
// formats: no new cryptography.
//
// What goes in, per item (an "entry", 64 lowercase hex):
//
//   entry = SHA256_hex( "veilcore:restamp:v1:" || kind || ":" || SHA256_hex(item bytes) )
//
// hashed as UTF-8 text, the way SPEC 5.2 hashes a batch's nodes. The kinds, and the item
// bytes for each (the exact bytes anyone holding the item can produce again):
//
//   batch-root   the batch root as 32 raw bytes (root.bin, the file OpenTimestamps stamps)
//   attestation  the attestation as served (signedAttestation), canonical JSON (SDK canonicalise)
//   withdrawal   the signed withdrawal of an attestation (signedRetraction), canonical JSON
//   enrolment    a key's registration as it signed it (registrationPayload), canonical JSON
//   rfc3161      an RFC 3161 token, DER (a batch's root.tst, or a proof code's own token)
//
// The entries become one root exactly as SPEC 5 builds a batch (veilcore-records buildBatch:
// sorted, de-duplicated, "00"/"01" prefixes, odd node promoted), so a re-stamp proof is a
// SPEC 5 inclusion proof and every existing checker folds it. The tag sits in each entry, not
// in the tree: an entry is the hash of a "veilcore:restamp:v1:" string, never a record's
// fingerprint, so a re-stamp root can't be passed off as a batch of records.
//
// What is published: the root, its .ots, and the sorted list of entries with how many of each
// kind. Hashes only. Each entry hashes an item carrying a 64-byte signature (or a batch root,
// already public), so nobody learns an item from its entry. The list does not say which entry
// is which kind: only the counts.
//
// What this never does: publish an item, sign anything, touch a wallet, or change a batch.
//
// SPDX-License-Identifier: Apache-2.0

import { createHash } from 'node:crypto';
import { buildBatch, verifyInclusion, canonicalise } from 'veilcore-records';
import { stampRoot, upgradeAnswer, otsFile, rootDigest, OtsError, DEFAULT_CALENDARS, explorersFrom } from './ots.mjs';
import { signedAttestation, signedRetraction, registrationPayload } from './attesters.mjs';

export const RESTAMP_FORMAT = 'veilcore/restamp/v1';
export const ENTRY_PREFIX = 'veilcore:restamp:v1:';
/** Every kind, in the order the counts are listed. */
export const KINDS = Object.freeze(['batch-root', 'attestation', 'withdrawal', 'enrolment', 'rfc3161']);

const HEX64 = /^[0-9a-f]{64}$/;
const sha256Hex = (b) => createHash('sha256').update(b).digest('hex');
const utf8 = (s) => Buffer.from(s, 'utf8');

/** The entry for one item: `kind` from KINDS, `bytes` the item's exact bytes. */
export const entryFor = (kind, bytes) => {
  if (!KINDS.includes(kind)) throw new Error(`unknown kind ${kind}`);
  return sha256Hex(utf8(`${ENTRY_PREFIX}${kind}:${sha256Hex(Buffer.from(bytes))}`));
};

/**
 * The exact bytes of an item, from what the registry serves (or what its holder kept):
 *   batch-root   the root as 64 hex characters, or its 32 raw bytes
 *   attestation  the attestation object as served by /attestations/subject/:commitment
 *   withdrawal   the withdrawal object (attestationId, attesterPublicKey, reason, retractedAt, signature)
 *   enrolment    { publicKey, displayName, role, accreditation, registeredAt } as /attesters/:key serves it
 *                (registeredAt is the issuedAt the key signed), or the signed registration with issuedAt
 *   rfc3161      the token's DER bytes
 */
export const itemBytes = (kind, item) => {
  switch (kind) {
    case 'batch-root': {
      if (typeof item === 'string' && HEX64.test(item)) return Buffer.from(item, 'hex');
      if (item instanceof Uint8Array && item.length === 32) return Buffer.from(item);
      throw new Error('a batch root is 64 lowercase hex characters or 32 bytes');
    }
    case 'attestation': return utf8(canonicalise(signedAttestation(item)));
    case 'withdrawal': return utf8(canonicalise(signedRetraction(item)));
    case 'enrolment': return utf8(registrationPayload({ ...item, issuedAt: item.issuedAt ?? item.registeredAt }));
    case 'rfc3161': {
      if (!(item instanceof Uint8Array) || item.length === 0) throw new Error('an RFC 3161 token is its DER bytes');
      return Buffer.from(item);
    }
    default: throw new Error(`unknown kind ${kind}`);
  }
};

/** The root over a list of entries: SPEC 5, as a batch. Throws on an empty list. */
export const rootOf = async (entries) => (await buildBatch(entries, 'restamp', '1970-01-01T00:00:00Z')).root;

/**
 * Check one item against a re-stamp, offline: its entry is the one the proof is for, the path
 * folds to the root, and (when given) that root is the re-stamp's. Returns { ok, entry, root }
 * or { ok: false, reason }. The root's date is then the re-stamp's root.bin.ots (`ots verify`,
 * or the evidence bundle's verify.html), checked separately as for a batch.
 */
export const checkRestampItem = async ({ kind, bytes, proof, root }) => {
  let entry;
  try { entry = entryFor(kind, bytes); } catch (e) { return { ok: false, reason: e.message }; }
  if (typeof proof !== 'object' || proof === null) return { ok: false, entry, reason: 'no proof' };
  if (proof.commitment !== entry) return { ok: false, entry, reason: 'the proof is for a different item' };
  if (root !== undefined && proof.root !== root) return { ok: false, entry, reason: 'the proof leads to a different root' };
  if (!(await verifyInclusion(proof))) return { ok: false, entry, reason: 'the path does not lead to the root' };
  return { ok: true, entry, root: proof.root };
};

/**
 * Check a published manifest on its own: entries sorted, distinct, 64 hex each, as many as the
 * counts say, and folding to the root it names. Returns { ok, root } or { ok: false, reason }.
 */
export const checkManifest = async (m) => {
  if (m?.format !== RESTAMP_FORMAT) return { ok: false, reason: `not a ${RESTAMP_FORMAT} manifest` };
  const e = m.entries;
  if (!Array.isArray(e) || e.length === 0) return { ok: false, reason: 'no entries' };
  for (let i = 0; i < e.length; i++) {
    if (typeof e[i] !== 'string' || !HEX64.test(e[i])) return { ok: false, reason: `entry ${i} is not 64 lowercase hex characters` };
    if (i > 0 && !(e[i - 1] < e[i])) return { ok: false, reason: `entries are not sorted and distinct at ${i}` };
  }
  const total = Object.values(m.counts ?? {}).reduce((a, n) => a + (Number.isSafeInteger(n) ? n : NaN), 0);
  if (total !== e.length) return { ok: false, reason: 'the counts do not add up to the entries' };
  const root = await rootOf(e);
  return root === m.root ? { ok: true, root } : { ok: false, reason: 'the entries fold to a different root' };
};

// ---- the settings ----

/**
 * VEILCORE_RESTAMP: off (unset, the default) | manual | on.
 *   off     nothing: no table is made, no route answers but to say it is off
 *   manual  the operator's POST /restamps makes one; stamps already made are upgraded
 *   on      manual, plus one automatically every VEILCORE_RESTAMP_EVERY_DAYS (365; 1 to 366)
 * A setting that can't be read keeps it off, and says why.
 */
export const restampSettings = (env = process.env) => {
  const problems = [];
  const raw = String(env.VEILCORE_RESTAMP ?? '').trim().toLowerCase();
  if (!['', 'off', 'manual', 'on'].includes(raw)) problems.push('VEILCORE_RESTAMP must be off, manual or on');
  let days = 365;
  const d = String(env.VEILCORE_RESTAMP_EVERY_DAYS ?? '').trim();
  if (d !== '') {
    const n = Number(d);
    if (!Number.isSafeInteger(n) || n < 1 || n > 366) problems.push('VEILCORE_RESTAMP_EVERY_DAYS must be a whole number from 1 to 366');
    else days = n;
  }
  const mode = problems.length ? 'off' : raw === 'on' || raw === 'manual' ? raw : 'off';
  return { mode, everyMs: days * 86_400_000, problems };
};

// ---- collecting the items ----

const hasTable = (db, name) => !!db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?").get(name);
const hasColumn = (db, table, col) => !!db.prepare(`SELECT 1 FROM pragma_table_info('${table}') WHERE name = ?`).get(col);

/**
 * Every entry this registry can make now, by kind: { byKind: { kind: Set }, skipped: { kind: n } }.
 * An item that can't be put in canonical form (a malformed old row) is left out and counted,
 * never guessed at. Tables that don't exist (yet) give nothing.
 */
export const collectEntries = (db) => {
  const byKind = Object.fromEntries(KINDS.map((k) => [k, new Set()]));
  const skipped = Object.fromEntries(KINDS.map((k) => [k, 0]));
  const add = (kind, item) => {
    try { byKind[kind].add(entryFor(kind, itemBytes(kind, item))); } catch { skipped[kind]++; }
  };
  const json = (s) => { try { return JSON.parse(s); } catch { return undefined; } };
  if (hasTable(db, 'batches')) {
    for (const r of db.prepare('SELECT root FROM batches').iterate()) add('batch-root', r.root);
    if (hasColumn(db, 'batches', 'tsa_token')) {
      for (const r of db.prepare('SELECT tsa_token AS t FROM batches WHERE tsa_token IS NOT NULL').iterate()) add('rfc3161', r.t);
    }
  }
  if (hasTable(db, 'batch_timestamps')) {
    for (const r of db.prepare('SELECT token AS t FROM batch_timestamps WHERE token IS NOT NULL').iterate()) add('rfc3161', r.t);
  }
  if (hasTable(db, 'record_timestamps')) {
    for (const r of db.prepare('SELECT token AS t FROM record_timestamps WHERE token IS NOT NULL').iterate()) add('rfc3161', r.t);
  }
  if (hasTable(db, 'attestations')) {
    for (const r of db.prepare('SELECT body FROM attestations').iterate()) add('attestation', json(r.body));
  }
  if (hasTable(db, 'retractions')) {
    for (const r of db.prepare('SELECT body FROM retractions').iterate()) add('withdrawal', json(r.body));
  }
  if (hasTable(db, 'attesters')) {
    for (const r of db.prepare('SELECT public_key, display_name, role, accreditation, registered_at FROM attesters').iterate()) {
      const accreditation = r.accreditation === null ? undefined : json(r.accreditation);
      if (r.accreditation !== null && accreditation === undefined) { skipped.enrolment++; continue; }
      add('enrolment', { publicKey: r.public_key, displayName: r.display_name, role: r.role, accreditation, registeredAt: r.registered_at });
    }
  }
  return { byKind, skipped };
};

// ---- the store ----

/** Stamp retries per re-stamp before the timer stops trying (the operator route still works). */
const MAX_STAMP_ATTEMPTS = 10;

/**
 * The re-stamps of this registry. `stamp` and `upgrade` are ots.mjs's, replaceable in tests;
 * `otsOn` is false under VEILCORE_OTS=off (then nothing is made: a re-stamp is its stamp).
 */
export const createRestamps = (db, { stamp = stampRoot, upgrade = upgradeAnswer, now = Date.now, otsOn = () => process.env.VEILCORE_OTS !== 'off', calendars = DEFAULT_CALENDARS } = {}) => {
  db.exec(`
    CREATE TABLE IF NOT EXISTS restamps (
      restamp_id     TEXT PRIMARY KEY,
      root           TEXT NOT NULL UNIQUE,
      made_at        INTEGER NOT NULL,
      counts         TEXT NOT NULL,
      entries        BLOB NOT NULL,
      ots            BLOB,
      ots_status     TEXT,
      ots_error      TEXT,
      ots_attempts   INTEGER NOT NULL DEFAULT 0,
      bitcoin_height INTEGER,
      bitcoin_time   TEXT
    );
    CREATE TABLE IF NOT EXISTS restamp_ots_answers (
      id             INTEGER PRIMARY KEY AUTOINCREMENT,
      restamp_id     TEXT NOT NULL,
      calendar       TEXT NOT NULL,
      answer         BLOB NOT NULL,
      received_at    INTEGER NOT NULL,
      bitcoin_height INTEGER,
      bitcoin_time   TEXT
    );
    CREATE INDEX IF NOT EXISTS restamp_ots_answers_id ON restamp_ots_answers(restamp_id);
  `);
  const st = (sql) => db.prepare(sql);
  let running = false;
  // Built trees for proofs, by re-stamp id: the last few asked about (there is about one a year).
  const trees = new Map();
  const remember = (id, batch) => {
    trees.delete(id);
    trees.set(id, batch);
    while (trees.size > 3) trees.delete(trees.keys().next().value);
  };

  const newId = (t) => 'RS-' + new Date(t).toISOString().slice(0, 10).replace(/-/g, '') + '-' +
    [...crypto.getRandomValues(new Uint8Array(2))].map((b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();
  const entriesOf = (blob) => {
    const b = Buffer.from(blob);
    const out = [];
    for (let i = 0; i < b.length; i += 32) out.push(b.subarray(i, i + 32).toString('hex'));
    return out;
  };
  const seconds = (t) => new Date(t).toISOString().replace(/\.\d{3}Z$/, 'Z');

  /** Rebuild the served .ots and the status from the stored answers. */
  const rebuild = (id, root) => {
    const rows = st('SELECT calendar, answer, bitcoin_height, bitcoin_time FROM restamp_ots_answers WHERE restamp_id = ? ORDER BY id').all(id);
    if (rows.length === 0) return;
    const first = rows.filter((r) => r.bitcoin_height !== null).sort((a, b) => a.bitcoin_height - b.bitcoin_height)[0];
    st('UPDATE restamps SET ots = ?, ots_status = ?, bitcoin_height = ?, bitcoin_time = ? WHERE restamp_id = ?')
      .run(otsFile(rootDigest(root), rows.map((r) => r.answer)), first ? 'bitcoin' : 'pending', first?.bitcoin_height ?? null, first?.bitcoin_time ?? null, id);
  };

  const stampOne = async (id) => {
    const r = st('SELECT root FROM restamps WHERE restamp_id = ?').get(id);
    if (!r) return { error: 'no such re-stamp', code: 404 };
    st('UPDATE restamps SET ots_attempts = ots_attempts + 1 WHERE restamp_id = ?').run(id);
    try {
      const out = await stamp(r.root, { calendars });
      db.transaction(() => {
        const ins = st('INSERT INTO restamp_ots_answers (restamp_id, calendar, answer, received_at) VALUES (?,?,?,?)');
        for (const a of out.answers) ins.run(id, a.calendar, a.answer, now());
        rebuild(id, r.root);
        st('UPDATE restamps SET ots_error = ? WHERE restamp_id = ?').run(out.failures.length ? `some calendars did not answer: ${out.failures.join('; ')}` : null, id);
      })();
      return { status: 'pending', calendars: out.calendars };
    } catch (e) {
      const message = e instanceof OtsError ? e.message : 'stamping failed';
      st("UPDATE restamps SET ots_status = 'failed', ots_error = ? WHERE restamp_id = ?").run(message, id);
      return { error: message, code: 502 };
    }
  };

  const upgradeOne = async (id, options = {}) => {
    const r = st('SELECT root FROM restamps WHERE restamp_id = ?').get(id);
    const digest = rootDigest(r.root);
    const errors = [];
    for (const row of st('SELECT id, calendar, answer FROM restamp_ots_answers WHERE restamp_id = ? AND bitcoin_height IS NULL').all(id)) {
      try {
        const out = await upgrade(row.answer, digest, { calendars, explorers: explorersFrom(process.env.VEILCORE_BTC_EXPLORER), ...options });
        errors.push(...out.errors.map((e) => `${row.calendar}: ${e}`));
        if (out.bitcoin) {
          st('UPDATE restamp_ots_answers SET answer = ?, bitcoin_height = ?, bitcoin_time = ? WHERE id = ?').run(out.answer, out.bitcoin.height, out.bitcoin.time, row.id);
        }
      } catch (e) {
        errors.push(`${row.calendar}: ${e instanceof OtsError ? e.message : 'upgrade failed'}`);
      }
    }
    rebuild(id, r.root);
    st('UPDATE restamps SET ots_error = ? WHERE restamp_id = ?').run(errors.length ? errors.join('; ') : null, id);
  };

  const describe = (r) => ({
    restampId: r.restamp_id,
    root: r.root,
    madeAt: seconds(r.made_at),
    counts: JSON.parse(r.counts),
    entries: Buffer.from(r.entries).length / 32,
    status: r.ots_status ?? 'none',
    ...(r.bitcoin_height !== null ? { bitcoinBlockHeight: r.bitcoin_height, bitcoinBlockTime: r.bitcoin_time ?? undefined } : {}),
    manifest: `/restamps/${r.restamp_id}/manifest.json`,
    rootBin: `/restamps/${r.restamp_id}/root.bin`,
    ots: `/restamps/${r.restamp_id}/root.bin.ots`,
  });
  const newest = () => st('SELECT * FROM restamps ORDER BY made_at DESC, restamp_id DESC LIMIT 1').get();

  return {
    /**
     * Make a re-stamp now: collect every entry, build the root, store the list, stamp it.
     * Refused while one is running, while OpenTimestamps is off, when there is nothing, and
     * when nothing changed since the last one (its root would be the same).
     */
    async run() {
      if (!otsOn()) return { error: 'OpenTimestamps is off on this registry (VEILCORE_OTS=off); a re-stamp is its Bitcoin stamp', code: 409 };
      if (running) return { error: 'a re-stamp is already running', code: 409 };
      running = true;
      try {
        const { byKind, skipped } = collectEntries(db);
        const counts = Object.fromEntries(KINDS.map((k) => [k, byKind[k].size]));
        const all = [...new Set(KINDS.flatMap((k) => [...byKind[k]]))].sort();
        if (all.length === 0) return { error: 'nothing to re-stamp yet', code: 409 };
        const t = now();
        const id = newId(t);
        const batch = await buildBatch(all, id, seconds(t));
        const last = newest();
        if (last && last.root === batch.root) return { error: `nothing new since ${last.restamp_id}`, code: 409, restampId: last.restamp_id };
        st('INSERT INTO restamps (restamp_id, root, made_at, counts, entries, ots_status) VALUES (?,?,?,?,?,?)')
          .run(id, batch.root, t, JSON.stringify(counts), Buffer.concat(all.map((e) => Buffer.from(e, 'hex'))), 'requested');
        remember(id, batch);
        const stamped = await stampOne(id);
        const skippedAny = Object.values(skipped).some((n) => n > 0);
        return { ...describe(newest()), ...(stamped.error ? { stampError: stamped.error } : {}), ...(skippedAny ? { skipped } : {}) };
      } finally {
        running = false;
      }
    },

    /** Whether the timer should make one now: none yet, or the newest is `everyMs` old. */
    due(everyMs) {
      const last = newest();
      return !last || now() - last.made_at >= everyMs;
    },

    /** The timer's upkeep: retry stamps that failed, upgrade pending ones to Bitcoin. */
    async upkeep() {
      if (!otsOn()) return;
      for (const { restamp_id: id } of st("SELECT restamp_id FROM restamps WHERE ots_status IN ('requested', 'failed') AND ots_attempts < ? ORDER BY made_at").all(MAX_STAMP_ATTEMPTS)) {
        await stampOne(id);
      }
      for (const { restamp_id: id } of st("SELECT restamp_id FROM restamps WHERE ots_status = 'pending' ORDER BY made_at").all()) {
        await upgradeOne(id);
      }
    },

    /** Every re-stamp, newest first. */
    list() {
      return st('SELECT * FROM restamps ORDER BY made_at DESC, restamp_id DESC').all().map(describe);
    },

    /** The published list: everything needed to rebuild the root. Undefined for no such re-stamp. */
    manifest(id) {
      const r = st('SELECT * FROM restamps WHERE restamp_id = ?').get(id);
      if (!r) return undefined;
      return {
        format: RESTAMP_FORMAT,
        restampId: r.restamp_id,
        madeAt: seconds(r.made_at),
        root: r.root,
        entryRule: 'entry = SHA256_hex("veilcore:restamp:v1:" + kind + ":" + SHA256_hex(item bytes)), as UTF-8 text',
        treeRule: 'SPEC 5 (veilcore-sdk): entries sorted, "00" leaf and "01" node prefixes, an odd node carried up',
        stamps: 'the root as 32 raw bytes (root.bin), with OpenTimestamps (root.bin.ots)',
        counts: JSON.parse(r.counts),
        entries: entriesOf(r.entries),
      };
    },

    /** The root, .ots and status of one re-stamp, or undefined. */
    otsFor(id) {
      const r = st('SELECT root, ots, ots_status FROM restamps WHERE restamp_id = ?').get(id);
      return r ? { root: r.root, ots: r.ots ? Buffer.from(r.ots) : null, status: r.ots_status ?? 'none' } : undefined;
    },

    /** The SPEC 5 inclusion proof of one entry, or { error, code }. */
    async proofFor(id, entry) {
      if (typeof entry !== 'string' || !HEX64.test(entry)) return { error: 'an entry is 64 lowercase hex characters', code: 400 };
      if (!trees.has(id)) {
        const r = st('SELECT made_at, entries FROM restamps WHERE restamp_id = ?').get(id);
        if (!r) return { error: 'no such re-stamp', code: 404 };
        remember(id, await buildBatch(entriesOf(r.entries), id, seconds(r.made_at)));
      }
      const proof = trees.get(id).proofs[entry];
      return proof ? { proof } : { error: 'this entry is not in that re-stamp', code: 404 };
    },
  };
};
