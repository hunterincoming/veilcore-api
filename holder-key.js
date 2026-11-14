// Holder keys at rest.
//
// A holder key is the holder's only credential: whoever sends it in x-holder-key IS that
// holder. It was stored as sent, in records, licenses, disclosure_grants, transfers and
// obligations_v2, so anyone with a copy of the database (a backup, a volume snapshot, a
// leaked file) could act as every holder (deep dive, 8 Oct 2026).
//
// What is stored now is a one-way digest of the key. Every lookup is by equality, so a
// plain hash fits: the registry hashes what arrives and compares digests. No secret is
// needed: a holder key is 32 random bytes (holder.ts in the app), far beyond guessing, so
// the digest cannot be reversed; and a server-side secret would be one more thing whose
// loss locks every holder out. Keys sent before round 11 could be any string, but those
// were refused from then on (server.js HOLDER_KEY), so none of them works as a key today.
//
// Distinct from partyId (lineage/routes.mjs), the public id of a beneficiary: a different
// domain string, so a stored digest is never something already published.
//
// SPDX-License-Identifier: Apache-2.0

const { createHash } = require('node:crypto');
// A record is corrected once (corrections.js): moving a holder's rows to another stored key
// must not put two corrections of one record under one holder.
const { settleCorrectionClashes, CORRECTED } = require('./corrections.js');

/** Marks a stored digest, so the migration below can tell converted rows from old ones. */
const STORED_PREFIX = 'h1:';

/**
 * A holder key as compared: lower-case hex (round 3). Keys used to be compared exactly as
 * sent, and the registry accepts upper-case hex (a restored key may be pasted that way), so
 * one key had 2^64 spellings: the same holder, sending their key in upper case, was a
 * different holder. That let a sender claim their own delivery code (the self-claim check
 * compared spellings, not keys). Anything that is not 64 hex characters (keys refused since
 * round 11, still in old rows) is left as it is.
 */
const HEX64 = /^[0-9a-fA-F]{64}$/;
const canonicalHolderKey = (raw) => (typeof raw === 'string' && HEX64.test(raw) ? raw.toLowerCase() : raw);

const digestOf = (s) => STORED_PREFIX + createHash('sha256').update(`veilcore:holder-key:v1:${s}`).digest('hex');

/** What is stored for a holder key: the digest of its lower-case form. */
const storedHolderKey = (raw) => digestOf(canonicalHolderKey(raw));

/**
 * What was stored for a key before round 3: the digest of the key exactly as sent. The
 * same for a lower-case key (every key the app makes), so only rows written with an upper-
 * or mixed-case key differ, and those are moved to storedHolderKey when the key next
 * arrives (adoptPlaintextKey). A digest cannot be undone, so there is no other way to find
 * them.
 */
const legacyStoredHolderKey = (raw) => digestOf(raw);

/**
 * A holder as named to other people (lineage/routes.mjs partyId): a hash of the lower-case
 * key, so every spelling of one key is one party. Before round 3 it hashed the key as sent.
 */
const partyIdOf = (raw) => createHash('sha256').update(`veilcore:party:${canonicalHolderKey(raw)}`).digest('hex');
const legacyPartyIdOf = (raw) => createHash('sha256').update(`veilcore:party:${raw}`).digest('hex');

/** Every column that held a holder key in plain text. */
const HOLDER_KEY_COLUMNS = [
  ['records', 'holder_key'],
  ['licenses', 'holder_key'],
  ['disclosure_grants', 'holder_key'],
  ['transfers', 'from_holder'],
  ['transfers', 'claimed_by'],
  ['obligations_v2', 'beneficiary_key'],
  // The first holder of each fingerprint (fingerprint-holders.js, 9 Nov 2026): a key moved to
  // its stored form keeps the fingerprints it held first.
  ['fingerprint_holders', 'holder_key'],
];

/** Columns among HOLDER_KEY_COLUMNS that exist in this database. */
const presentColumns = (db) => {
  const tables = new Set(db.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all().map((t) => t.name));
  return HOLDER_KEY_COLUMNS.filter(([t, c]) =>
    tables.has(t) && db.prepare(`SELECT 1 FROM pragma_table_info('${t}') WHERE name = ?`).get(c));
};

/** A holder column's value as stored now: a plain-text key (from older code) is digested. */
const asStored = (v) => (typeof v === 'string' && !v.startsWith(STORED_PREFIX) ? storedHolderKey(v) : v);

/**
 * Rollback safety (round 2). Code from before this change writes keys in plain text: during
 * a deploy (the old container answers until the new one is healthy) or after a rollback.
 * Converting only at startup would leave those rows invisible to this version until the
 * next restart. So whenever a key arrives, any row still holding it in plain text is
 * converted first, and every lookup that follows finds it. Indexed, so a request that
 * finds nothing (every request, normally) costs a few index probes.
 */
const adoptStatements = new WeakMap();
const hasBeneficiaryIds = (db) =>
  !!db.prepare("SELECT 1 FROM pragma_table_info('obligations_v2') WHERE name = 'beneficiary_id'").get();
const adoptPlaintextKey = (db, raw) => {
  let cached = adoptStatements.get(db);
  if (!cached || cached.columns < HOLDER_KEY_COLUMNS.length || !cached.beneficiaries) {
    const present = presentColumns(db);
    const statements = present.map(([t, c]) => db.prepare(`UPDATE ${t} SET ${c} = ? WHERE ${c} = ?`));
    const beneficiaries = hasBeneficiaryIds(db);
    // A party id from an upper-case key (round 3). An obligation already held under the new
    // id for the same record is the same holder's: the old row goes, and an obligation in
    // force under either stays in force.
    const party = beneficiaries && {
      rows: db.prepare('SELECT record, obligation, status FROM obligations_v2 WHERE beneficiary_id = ?'),
      clash: db.prepare('SELECT status FROM obligations_v2 WHERE record = ? AND obligation = ? AND beneficiary_id = ?'),
      open: db.prepare("UPDATE obligations_v2 SET status = 'open' WHERE record = ? AND obligation = ? AND beneficiary_id = ?"),
      drop: db.prepare('DELETE FROM obligations_v2 WHERE record = ? AND obligation = ? AND beneficiary_id = ?'),
      move: db.prepare('UPDATE obligations_v2 SET beneficiary_id = ? WHERE record = ? AND obligation = ? AND beneficiary_id = ?'),
    };
    cached = {
      columns: present.length,
      beneficiaries,
      run: db.transaction((pairs, parties) => {
        for (const [from, to] of pairs) {
          settleCorrectionClashes(db, from, to);
          for (const stmt of statements) stmt.run(to, from);
        }
        if (!party) return;
        for (const [from, to] of parties) {
          for (const r of party.rows.all(from)) {
            const there = party.clash.get(r.record, r.obligation, to);
            if (there) {
              if (r.status === 'open' && there.status !== 'open') party.open.run(r.record, r.obligation, to);
              party.drop.run(r.record, r.obligation, from);
            } else {
              party.move.run(to, r.record, r.obligation, from);
            }
          }
        }
      }),
    };
    adoptStatements.set(db, cached);
  }
  const digest = storedHolderKey(raw);
  // Plain text as sent, and its lower-case form, from older code (a rollback, a deploy
  // overlap); and the digest older code made of an upper- or mixed-case key (round 3).
  const pairs = [[raw, digest]];
  const lower = canonicalHolderKey(raw);
  const parties = [];
  if (lower !== raw) {
    pairs.push([lower, digest], [legacyStoredHolderKey(raw), digest]);
    parties.push([legacyPartyIdOf(raw), partyIdOf(raw)]);
  }
  // IMMEDIATE: the write lock is taken first, with the busy timeout. The transaction reads
  // before it writes (corrections.js settleCorrectionClashes), and a deferred one that holds a
  // read lock when another connection is committing gets SQLITE_BUSY at once, not a wait.
  cached.run.immediate(pairs, parties);
};

/**
 * Replace every plain-text holder key with its digest. Safe to run on every start: a row
 * already converted carries the prefix and is left alone, an empty database or a missing
 * table changes nothing. One transaction, so a crash leaves all rows as they were or all
 * converted. When anything was converted the file is rebuilt (VACUUM), so the old keys do
 * not linger in freed pages of the database file.
 *
 * Returns { 'table.column': rows converted }.
 */
const migrateHolderKeys = (db, { log = console.log, vacuum = true } = {}) => {
  const present = presentColumns(db);
  // Every holder column indexed, for adoptPlaintextKey (records, licenses and from_holder
  // already were).
  for (const [t, c] of present) db.exec(`CREATE INDEX IF NOT EXISTS ${t}_${c}_holder ON ${t}(${c})`);
  db.function('veilcore_stored_holder_key', { deterministic: true }, (v) => (v === null ? null : storedHolderKey(String(v))));
  const converted = {};
  let total = 0;
  const secureDelete = db.pragma('secure_delete', { simple: true });
  db.pragma('secure_delete = ON');
  try {
    db.transaction(() => {
      // Records that correct another, one plain-text key at a time: two spellings of one key
      // (or a key and its digest) may each hold a correction of the same record, and moving
      // them together would put both under one holder (corrections.js). Settled first, then
      // moved; the bulk statement below converts the rest.
      if (present.some(([t]) => t === 'records')) {
        const keys = db.prepare(
          `SELECT DISTINCT holder_key AS k FROM records
           WHERE ${CORRECTED} IS NOT NULL AND substr(holder_key, 1, ${STORED_PREFIX.length}) != '${STORED_PREFIX}'`,
        ).all().map((r) => r.k);
        const move = db.prepare('UPDATE records SET holder_key = ? WHERE holder_key = ?');
        for (const k of keys) {
          const to = storedHolderKey(k);
          settleCorrectionClashes(db, k, to, { log });
          const n = move.run(to, k).changes;
          if (n) converted['records.holder_key'] = (converted['records.holder_key'] ?? 0) + n;
          total += n;
        }
      }
      for (const [t, c] of present) {
        const n = db.prepare(`UPDATE ${t} SET ${c} = veilcore_stored_holder_key(${c})
                              WHERE ${c} IS NOT NULL AND substr(${c}, 1, ${STORED_PREFIX.length}) != '${STORED_PREFIX}'`).run().changes;
        if (n) converted[`${t}.${c}`] = (converted[`${t}.${c}`] ?? 0) + n;
        total += n;
      }
    }).immediate(); // reads before it writes: the write lock first (see adoptPlaintextKey)
  } finally {
    db.pragma(`secure_delete = ${secureDelete ? 'ON' : 'OFF'}`);
  }
  if (total > 0 && vacuum) {
    // The conversion is committed either way; a failed rebuild (no disk space for the copy)
    // must not stop the service. Said so, and worth running by hand later.
    try {
      db.exec('VACUUM');
    } catch (e) {
      console.warn(`WARNING: holder keys converted, but VACUUM failed (${e.message}); old keys may remain in freed pages of the file until it is run`);
    }
  }
  if (total > 0) {
    log(`holder keys: stored ${total} plain-text key${total === 1 ? '' : 's'} as digests (${Object.entries(converted).map(([k, n]) => `${k} ${n}`).join(', ')})`);
  }
  return converted;
};

module.exports = {
  STORED_PREFIX,
  canonicalHolderKey,
  storedHolderKey,
  legacyStoredHolderKey,
  partyIdOf,
  asStored,
  migrateHolderKeys,
  adoptPlaintextKey,
  HOLDER_KEY_COLUMNS,
};
