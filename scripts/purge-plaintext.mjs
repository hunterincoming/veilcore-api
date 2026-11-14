// Remove what this registry still holds in plain text from before sealed records
// (sealed records CONTRACT.md #12, with the round 2 guard, #24). Run by hand by the
// registry operator, against the registry's own database file:
//
//   node scripts/purge-plaintext.mjs              counts only, and which holders it would
//                                                 skip; nothing is changed
//   node scripts/purge-plaintext.mjs --apply      makes the changes; the file is not rebuilt
//   node scripts/purge-plaintext.mjs --apply --vacuum
//                                                 makes the changes, then rebuilds the file
//                                                 (VACUUM). Only in a maintenance window:
//                                                 VACUUM locks the whole file while it copies
//                                                 it, and the server's requests fail once its
//                                                 5 s busy timeout runs out (round 3)
//   node scripts/purge-plaintext.mjs --db <path>  another file (default: DB_PATH, else veilcore.db)
//   --include-unconverted --i-understand-this-deletes-text
//                                                 both together, with --apply: also strip the
//                                                 holders who have not converted (below)
//
// Who it touches (the guard, round 2: L5, L6, L7). Run early, the purge used to strip every
// row a holder's browser had not converted yet down to its public fields, and the browser
// keeps no copy to fall back on. Now:
//   · a holder is CONVERTED once at least one of their records or licences is sealed: their
//     browser has run the sealing site and holds a vault key. Only converted holders are
//     touched;
//   · a converted holder's rows that are still plain text are REPORTED, never stripped: their
//     browser tried and could not convert them (too large, or a fingerprint that does not
//     match), and the holder still needs them;
//   · a holder with no sealed row is SKIPPED, and listed, unless --include-unconverted and
//     --i-understand-this-deletes-text are both given. Then their plain rows are stripped:
//     what they typed is gone for good unless their own browser still has it.
//
// What --apply does, for each holder it touches:
//   · records: each sealed row's clear fields are cut to what a save accepts today
//     (cleanSealedRow below): its `attestation` to what this registry writes (sealed.js
//     registryAttestation: a `lab` a holder typed, and the recipient's handle an older claim
//     wrote as `addressedTo` or `attesterHandle`, are dropped), and any words in `profile` or
//     the correction links. A plain row that is not stripped (a converted holder's, or one
//     skipped) loses only that handle: for EVERY holder, converted or not (round 4, F6),
//     because it is a third party's name and nothing of the holder's is lost with it. A plain row of an unconverted holder (with both flags)
//     keeps only its public fields (sealed.js publicPartOf: a known profile,
//     fingerprint, key binding, correction links, received-from details, the registry's
//     attestation) and gains `contentsRemoved: true`, so the holder's app can say what
//     happened. A claim's stub has nothing more and is left as it is;
//   · licences: a plain licence of an unconverted holder (with both flags) becomes
//     { id, contentsRemoved: true }; a converted holder's is reported;
//   · transfers they sent: the plain-text quantity and note are emptied (sealed offers carry
//     them);
//   · every transfer, whoever sent it (round 4, F6): a recipient handle stored as typed is
//     replaced with 32 random bytes in hex (sealed.js legacyHandleReplacement), a fresh value
//     per delivery. Not a hash of the handle: a hash of a guessable name is undone by
//     hashing likely names (round 3, P6);
//   · sample details written before sealing (a delivery's plain sample_custody and
//     arrival_custody; since round 3 they are sealed with the delivery's offer key,
//     CONTRACT.md #27): always REPORTED, by count, and removed only by the two-flag run
//     (--include-unconverted --i-understand-this-deletes-text), for every delivery. A lab
//     receipt over them then reads custody "removed": nothing is left to compare it with;
//   · record names in the clear (round 5, CONTRACT.md #28: a record's name is sealed now): a
//     row saved before then still carries `strainName` beside its box, and its box was sealed
//     before names went inside, so the clear name is the only copy of it anywhere: the backup
//     file holds keys, not records, and the proof code covers the name, so without it the
//     record no longer matches its proof code. Since round 6 (CONTRACT.md #37, the fifth
//     review's finding 8) the guarded run REPORTS these names, by count, and removes none: a
//     row that still has one is a row its holder's app has not saved again (it may not match
//     its proof code, or be an older copy), and the app moves the name inside the box when it
//     does. Only the two-flag run removes them, from sealed rows, claims' stubs and the plain
//     rows it reduces. A plain row that stays plain keeps it, with everything else in it;
//   · DNA values a grant published before round 5 (`dnaFileSha256`, the report's plain
//     SHA-256, and `dnaFingerprint`, its pairing code): removed from every grant's values,
//     for every holder, converted or not, on every --apply (round 6, CONTRACT.md #37, the fifth
//     review's finding 7). Since round 5 a saved report is published only bound with the
//     record's salt (dnaPairBinding), and the registry no longer answers the plain values;
//     a holder who never came back kept them in the file and in every backup;
//   · disclosure grants made before grant values existed: the keys that publish values are
//     dropped (the holder's app sends them again with values); `existence` and
//     `descent-clean` need no values and are never dropped. A grant left with no keys goes.
//     A grant on a record whose row stays in plain text after this run is SKIPPED (round 3,
//     L6): that record has not been converted, its app copies the grant's keys into the
//     sealed record when it converts it, and a cut list would stop publishing what the
//     holder chose (parent names, say) for good;
//   · with --vacuum only: VACUUM, so the file is rebuilt and nothing is left in free pages.
//     Without it, what is removed is still overwritten with zeros as it goes (secure_delete),
//     but the file keeps its size and its free pages.
//
// Take a backup first (POST /admin/backup), then rotate the backup key afterwards
// (docs/rotate-backup-key.md): backups taken before the purge still hold what it removes.
// It prints counts, and identifies holders only by the first 12 characters of the digest
// this database stores for them (never a key, an id or any contents).
// SPDX-License-Identifier: Apache-2.0

import { createRequire } from 'node:module';
import { existsSync } from 'node:fs';
import Database from 'better-sqlite3';

const require = createRequire(import.meta.url);
const {
  isSealedBody, publicPartOf, hasPrivateFields, registryAttestation, publicSupersedes, KNOWN_PROFILES, ID_PATTERN,
  HANDLE_TAG, legacyHandleReplacement, hasClearName,
} = require('../sealed.js');

/**
 * A sealed row's clear fields as a save would accept them today (round 2, P3 and P7): the
 * attestation as the registry writes it, a known profile, correction links with known
 * field names and a real date. A row the real site saved is unchanged by this; one saved
 * before round 2 with words in those fields (or an older holder-typed `lab`) loses them.
 */
const cleanSealedRow = (r) => {
  const next = { ...r };
  const a = registryAttestation(r.attestation);
  if (a) next.attestation = a; else delete next.attestation;
  if (r.profile !== undefined && !KNOWN_PROFILES.includes(r.profile)) delete next.profile;
  if (r.supersededBy !== undefined && !(typeof r.supersededBy === 'string' && ID_PATTERN.test(r.supersededBy))) delete next.supersededBy;
  if (r.supersedes !== undefined) {
    const s = publicSupersedes(r.supersedes);
    if (s) next.supersedes = s; else delete next.supersedes;
  }
  return next;
};

const FLAGS = ['--apply', '--vacuum', '--include-unconverted', '--i-understand-this-deletes-text'];
const args = process.argv.slice(2);
const apply = args.includes('--apply');
const includeUnconverted = args.includes('--include-unconverted');
const understood = args.includes('--i-understand-this-deletes-text');
const vacuum = args.includes('--vacuum');
const dbAt = args.indexOf('--db');
const path = dbAt >= 0 ? args[dbAt + 1] : process.env.DB_PATH || 'veilcore.db';
const USAGE = 'usage: node scripts/purge-plaintext.mjs [--db <path>] [--apply [--vacuum]] [--include-unconverted --i-understand-this-deletes-text]';
for (const [i, a] of args.entries()) {
  if (!FLAGS.includes(a) && a !== '--db' && !(i === dbAt + 1 && dbAt >= 0)) {
    console.error(`unknown argument; ${USAGE}`);
    process.exit(2);
  }
}
if (includeUnconverted !== understood) {
  console.error('--include-unconverted deletes the text of holders who have not converted yet, so it needs --i-understand-this-deletes-text too (and the other way round); nothing was changed');
  process.exit(2);
}
if (vacuum && !apply) {
  console.error('--vacuum rebuilds the file after --apply, so it needs --apply; nothing was changed');
  process.exit(2);
}
const stripUnconverted = includeUnconverted && understood;
if (!path || path === ':memory:' || !existsSync(path)) {
  console.error('no database file there; give --db <path> or set DB_PATH');
  process.exit(2);
}

const db = new Database(path, { fileMustExist: true });
// Whatever is overwritten is zeroed in the file, not left in free space (as server.js).
db.pragma('secure_delete = ON');
// Wait for the server's own short writes rather than fail on them.
db.pragma('busy_timeout = 30000');

const tableExists = (name) => !!db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?").get(name);
const hasColumn = (table, col) => !!db.prepare(`SELECT 1 FROM pragma_table_info('${table}') WHERE name = ?`).get(col);
const parse = (body) => {
  try {
    const v = JSON.parse(body);
    return v && typeof v === 'object' && !Array.isArray(v) ? v : null;
  } catch {
    return null;
  }
};
/** How a holder is named in what this prints: the start of the stored digest, never a key. */
const label = (holderKey) => String(holderKey ?? '').replace(/^h1:/, '').slice(0, 12) || '(none)';
/** A grant key that publishes values the holder sends (server.js VALUE_KEYS); the others need none. */
const NO_VALUE_KEYS = new Set(['existence', 'descent-clean', 'own', 'lineage']);

const counts = {
  records: { sealed: 0, publicOnly: 0, toReduce: 0, reported: 0, skipped: 0, clearFieldsCut: 0, recipientNamesRemoved: 0 },
  names: { removed: 0, reported: 0, kept: 0 },
  plainDnaValues: { grants: 0 },
  licences: { sealed: 0, toEmpty: 0, reported: 0, skipped: 0 },
  transfers: { withPlainQuantityOrNote: 0, plainHandles: 0, skipped: 0, plainCustody: 0, custodyRemoved: 0 },
  grants: { keysDropped: 0, grantsDropped: 0, skipped: 0, recordStillPlain: 0 },
};
/** Record rows (id and holder) that are still in plain text after this run: their grants are left alone. */
const plainAfter = new Set();
const rowKey = (id, holder) => `${id}\0${holder}`;
/** Per holder: { records, licences } still in plain text; for the lists printed at the end. */
const stillPlain = new Map();
const notePlain = (holder, kind) => {
  const e = stillPlain.get(holder) ?? { records: 0, licences: 0 };
  e[kind]++;
  stillPlain.set(holder, e);
};

const work = db.transaction(() => {
  // Converted holders: at least one sealed record or licence.
  const converted = new Set();
  for (const table of ['records', 'licenses']) {
    if (!tableExists(table)) continue;
    for (const { holder_key: h } of db.prepare(`SELECT DISTINCT holder_key FROM ${table} WHERE json_extract(body, '$.sealed') IS NOT NULL`).all()) {
      converted.add(h);
    }
  }
  const touches = (holder) => converted.has(holder) || stripUnconverted;
  /**
   * A claim's stub keeps its clear name unless both flags are given: the recipient's app takes
   * the name from the sender's offer when it finishes receiving, but a code made before offers
   * were sealed has no offer to take it from once the sender's row is sealed.
   */
  const withoutStubName = (r, holder) => {
    if (!hasClearName(r)) return null;
    if (!stripUnconverted) { counts.names.kept++; return null; }
    return withoutStubNameBody(r, holder);
  };
  /**
   * A sealed row's body without its clear name, counted; null when its name stays. A sealed row
   * with a clear name was last saved before round 5 (a save since is refused with one), so its
   * box doesn't hold the name: reported and kept, unless both flags are given (round 6).
   */
  const withoutName = (r) => {
    if (!hasClearName(r)) return null;
    if (!stripUnconverted) { counts.names.reported++; return null; }
    counts.names.removed++;
    const { strainName: _n, ...rest } = r;
    return rest;
  };
  /** A claim's stub or a reduced row: the same, counted as kept rather than reported. */
  const withoutStubNameBody = (r) => {
    counts.names.removed++;
    const { strainName: _n, ...rest } = r;
    return rest;
  };

  if (tableExists('records')) {
    const update = db.prepare('UPDATE records SET body = ? WHERE id = ? AND holder_key = ?');
    for (const row of db.prepare('SELECT id, holder_key, body FROM records').all()) {
      const r = parse(row.body);
      const isConverted = converted.has(row.holder_key);
      if (r && isSealedBody(r)) {
        counts.records.sealed++;
        // A sealed row's holder is always converted, so always touched.
        const next = cleanSealedRow(withoutName(r) ?? r);
        if (JSON.stringify(next) !== JSON.stringify(r)) {
          counts.records.clearFieldsCut++;
          if (apply) update.run(JSON.stringify(next), row.id, row.holder_key);
        }
        continue;
      }
      if (r && !hasPrivateFields(r)) {
        // A claim's stub (or a row the purge reduced before): only its clear name may go.
        counts.records.publicOnly++;
        const next = withoutStubName(r, row.holder_key);
        if (next && apply) update.run(JSON.stringify(next), row.id, row.holder_key);
        continue;
      }
      notePlain(row.holder_key, 'records');
      if (isConverted || !stripUnconverted) plainAfter.add(rowKey(row.id, row.holder_key));
      if (isConverted || !stripUnconverted) {
        // Reported (converted) or skipped (not yet converted), not stripped. Either way the
        // recipient's name an older claim wrote into the sender's record (`addressedTo`,
        // `attesterHandle`) is taken out (round 4, F6): it is a third party's name, and
        // nothing of the holder's own is lost with it. It used to stay for holders not yet
        // converted.
        if (isConverted) counts.records.reported++;
        else counts.records.skipped++;
        const a = r?.attestation;
        if (a && typeof a === 'object' && ('addressedTo' in a || 'attesterHandle' in a)) {
          counts.records.recipientNamesRemoved++;
          const rest = { ...a };
          delete rest.addressedTo;
          delete rest.attesterHandle;
          if (apply) update.run(JSON.stringify({ ...r, attestation: rest }), row.id, row.holder_key);
        }
        continue;
      }
      counts.records.toReduce++;
      // publicPartOf keeps no name (round 5): counted with the other names that go.
      if (r && hasClearName(r)) counts.names.removed++;
      if (apply) update.run(JSON.stringify({ ...(r ? publicPartOf(r) : {}), id: row.id, contentsRemoved: true }), row.id, row.holder_key);
    }
  }
  if (tableExists('licenses')) {
    const update = db.prepare('UPDATE licenses SET body = ?, record_id = NULL WHERE id = ? AND holder_key = ?');
    for (const row of db.prepare('SELECT id, holder_key, body FROM licenses').all()) {
      const l = parse(row.body);
      if (l && isSealedBody(l)) { counts.licences.sealed++; continue; }
      if (l && l.contentsRemoved === true && Object.keys(l).length === 2) continue; // emptied before
      notePlain(row.holder_key, 'licences');
      if (converted.has(row.holder_key)) { counts.licences.reported++; continue; }
      if (!stripUnconverted) { counts.licences.skipped++; continue; }
      counts.licences.toEmpty++;
      if (apply) update.run(JSON.stringify({ id: row.id, contentsRemoved: true }), row.id, row.holder_key);
    }
  }
  if (tableExists('transfers')) {
    const clear = db.prepare('UPDATE transfers SET quantity = NULL, note = NULL WHERE id = ?');
    const retag = db.prepare('UPDATE transfers SET to_handle = ? WHERE id = ?');
    for (const t of db.prepare('SELECT id, from_holder, to_handle, quantity, note FROM transfers').all()) {
      const plainText = t.quantity !== null || t.note !== null;
      const plainHandle = typeof t.to_handle === 'string' && !HANDLE_TAG.test(t.to_handle);
      if (!plainText && !plainHandle) continue;
      // A recipient's name stored as typed is replaced for EVERY delivery, whether or not the
      // sender has converted (round 4, F6; CONTRACT.md #15 says every): it is a third party's
      // name, the sender's app never reads it back (it keeps the name sealed), and nothing of
      // the sender's is lost. It used to stay for senders who had not been back since sealing.
      if (plainHandle) {
        counts.transfers.plainHandles++;
        if (apply) retag.run(legacyHandleReplacement(), t.id);
      }
      if (!plainText) continue;
      if (!touches(t.from_holder)) { counts.transfers.skipped++; continue; }
      counts.transfers.withPlainQuantityOrNote++;
      if (apply) clear.run(t.id);
    }
    // Sample details written before sealing: reported always, removed only by the two-flag run.
    if (hasColumn('transfers', 'sample_custody') && hasColumn('transfers', 'arrival_custody')) {
      if (stripUnconverted && apply && !hasColumn('transfers', 'custody_removed')) {
        db.exec('ALTER TABLE transfers ADD COLUMN custody_removed INTEGER');
      }
      const removeCustody = stripUnconverted && apply
        ? db.prepare('UPDATE transfers SET sample_custody = NULL, arrival_custody = NULL, custody_removed = 1 WHERE id = ?')
        : null;
      for (const t of db.prepare('SELECT id FROM transfers WHERE sample_custody IS NOT NULL OR arrival_custody IS NOT NULL').all()) {
        counts.transfers.plainCustody++;
        if (stripUnconverted) {
          counts.transfers.custodyRemoved++;
          if (removeCustody) removeCustody.run(t.id);
        }
      }
    }
  }
  if (tableExists('disclosure_grants') && hasColumn('disclosure_grants', 'grant_values')) {
    // The plain DNA values a grant published before round 5: removed from every grant, always.
    const setValues = db.prepare('UPDATE disclosure_grants SET grant_values = ? WHERE record_id = ? AND holder_key = ?');
    for (const g of db.prepare(`SELECT record_id, holder_key, grant_values FROM disclosure_grants
        WHERE grant_values IS NOT NULL AND (json_type(grant_values, '$.dnaFileSha256') IS NOT NULL
          OR json_type(grant_values, '$.dnaFingerprint') IS NOT NULL)`).all()) {
      const v = parse(g.grant_values);
      if (!v) continue;
      const { dnaFileSha256: _s, dnaFingerprint: _f, ...rest } = v;
      counts.plainDnaValues.grants++;
      if (apply) setValues.run(JSON.stringify(rest), g.record_id, g.holder_key);
    }
  }
  if (tableExists('disclosure_grants')) {
    // A database the sealed server has never opened has no grant_values column: every
    // grant in it predates values.
    const where = hasColumn('disclosure_grants', 'grant_values') ? 'grant_values IS NULL' : '1';
    const setShow = db.prepare('UPDATE disclosure_grants SET show = ? WHERE record_id = ? AND holder_key = ?');
    const drop = db.prepare('DELETE FROM disclosure_grants WHERE record_id = ? AND holder_key = ?');
    for (const g of db.prepare(`SELECT record_id, holder_key, show FROM disclosure_grants WHERE ${where}`).all()) {
      const show = parse(`{"s":${g.show}}`)?.s;
      const keys = Array.isArray(show) ? show.filter((k) => typeof k === 'string') : [];
      const kept = keys.filter((k) => NO_VALUE_KEYS.has(k));
      if (kept.length === keys.length && keys.length > 0) continue; // nothing in it needs values
      if (!touches(g.holder_key)) { counts.grants.skipped++; continue; }
      if (plainAfter.has(rowKey(g.record_id, g.holder_key))) { counts.grants.recordStillPlain++; continue; }
      counts.grants.keysDropped += keys.length - kept.length;
      if (kept.length === 0) {
        counts.grants.grantsDropped++;
        if (apply) drop.run(g.record_id, g.holder_key);
      } else if (apply) setShow.run(JSON.stringify(kept), g.record_id, g.holder_key);
    }
  }
  return converted;
});
const converted = work();

if (apply && vacuum) {
  // Rebuild the file: deleted and overwritten contents leave no free pages behind. Only when
  // asked (--vacuum, round 3): it holds a lock on the whole file for as long as the copy
  // takes, and a live server's writes fail once their busy timeout runs out.
  db.exec('VACUUM');
  if (db.pragma('journal_mode', { simple: true }) === 'wal') db.pragma('wal_checkpoint(TRUNCATE)');
}
db.close();

const c = counts;
const did = (done, todo) => (apply ? done : todo);
console.log(apply ? 'applied:' : 'dry run, nothing changed (run with --apply to make these changes):');
if (apply) {
  console.log(vacuum
    ? 'file rebuilt (VACUUM)'
    : 'file not rebuilt: what was removed is overwritten with zeros, but the file keeps its free pages; to rebuild it, run again with --apply --vacuum in a maintenance window');
}
console.log(`holders: ${converted.size} converted (at least one sealed row)${stripUnconverted ? '; holders not yet converted are included (--include-unconverted)' : ''}`);
console.log(`records: ${c.records.sealed} sealed, ${c.records.publicOnly} with public fields only, ${c.records.toReduce} ${did('reduced', 'to reduce')} to public fields, ${c.records.reported} still plain under converted holders (reported, not stripped), ${c.records.skipped} of holders not yet converted (skipped)`);
console.log(`recipient names an older claim wrote into a sender's plain record: ${c.records.recipientNamesRemoved} ${did('removed', 'to remove')} (for every holder, converted or not)`);
console.log(`sealed records: ${c.records.clearFieldsCut} whose clear fields ${did('were', 'are to be')} cut to what a save accepts (attestation, profile, correction links, a name in the clear)`);
console.log(stripUnconverted
  ? `record names in the clear: ${c.names.removed} ${did('removed', 'to remove')} (--include-unconverted). A sealed row's name removed this way is gone for good: its lock was made before names went inside it, the backup file holds keys, not records, and the record no longer matches its proof code without it`
  : `record names in the clear: ${c.names.reported} on sealed rows locked before names went inside the lock (reported, not removed: this is the only copy of each, and the holder's app moves it inside when it saves the row again), ${c.names.kept} on claims' stubs (kept); only --include-unconverted --i-understand-this-deletes-text removes them`);
console.log(`DNA values grants published before round 5 (the report's plain SHA-256 and its pairing code): ${c.plainDnaValues.grants} grants ${did('cleared of them', 'to clear of them')} (for every holder, converted or not)`);
console.log(`licences: ${c.licences.sealed} sealed, ${c.licences.toEmpty} ${did('emptied', 'to empty')}, ${c.licences.reported} still plain under converted holders (reported, not stripped), ${c.licences.skipped} of holders not yet converted (skipped)`);
console.log(`transfers: ${c.transfers.withPlainQuantityOrNote} with a plain-text quantity or note${did(', now emptied', ', to empty')}, ${c.transfers.plainHandles} recipient handles stored as typed${did(', now random values', ', to replace with random values')} (for every sender, converted or not), ${c.transfers.skipped} quantities or notes of senders not yet converted (skipped)`);
console.log(stripUnconverted
  ? `sample details written before sealing: ${c.transfers.plainCustody} deliveries with them in plain text, ${c.transfers.custodyRemoved} ${did('removed', 'to remove')} (--include-unconverted)`
  : `sample details written before sealing: ${c.transfers.plainCustody} deliveries with them in plain text (reported, not removed; only --include-unconverted --i-understand-this-deletes-text removes them)`);
console.log(`disclosure grants without values: ${c.grants.keysDropped} keys that publish values ${did('dropped', 'to drop')}, ${c.grants.grantsDropped} grants left with no keys ${did('dropped', 'to drop')} (existence and descent-clean are kept), ${c.grants.recordStillPlain} on records still in plain text (skipped: the app converts them with their values), ${c.grants.skipped} of holders not yet converted (skipped)`);

const reported = [...stillPlain].filter(([h]) => converted.has(h)).sort(([a], [b]) => (a < b ? -1 : 1));
const skipped = [...stillPlain].filter(([h]) => !converted.has(h)).sort(([a], [b]) => (a < b ? -1 : 1));
if (reported.length) {
  console.log('converted holders with rows still in plain text (reported, not stripped; their app could not convert these):');
  for (const [h, e] of reported) console.log(`  holder ${label(h)}: ${e.records} records, ${e.licences} licences`);
}
if (skipped.length) {
  console.log(stripUnconverted
    ? `holders not yet converted, whose plain rows were ${did('stripped', 'to be stripped')} (--include-unconverted):`
    : 'holders not yet converted (skipped; nothing of theirs is changed except recipient names typed before tags, which are replaced):');
  for (const [h, e] of skipped) console.log(`  holder ${label(h)}: ${e.records} records, ${e.licences} licences`);
}
