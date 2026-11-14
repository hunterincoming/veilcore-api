// A record is corrected once (8 Nov 2026).
//
// A correction is a new record whose `supersedes.recordId` names the record it corrects. The
// site refuses to correct a record that already has a correction (the site's records.ts
// issueCorrection), but two devices saving at nearly the same moment both passed that check
// and both reached this registry, which stored both: two live corrections of one record, and
// no way to tell which one the holder meant. Only the registry sees every save, so only it can
// rule that out.
//
// It does so with a unique index, not a lookup before the write: one row per holder and
// corrected record. SQLite refuses the second row however the two saves interleave, in one
// process or several on the same file. PUT /api/records turns that refusal into a per-row
// 409 with code "already-corrected"; a second copy of the stored correction itself (the same
// id, or the same fingerprint) is an idempotent retry and is answered with the existing one.
//
// Per holder, because a record id is scoped to its holder (SPEC 4.5, the "unchanged" claim: a
// match on recordId counts only when both records have the same holder). A global index would let anyone who
// guessed a record id store a "correction" of it first and lock the real holder out.
//
// A database that already holds two corrections of one record (written before this) can't take
// the index as it is. Nothing is deleted: every correction but one per record is marked with
// `correction_conflict` (the id of the one kept), the index leaves marked rows out, and each
// case is said in the log at every start until the holder removes the extra one. The one kept
// is the one the corrected record's own `supersededBy` names, if it names one of them;
// otherwise the one this registry saw first.
//
// SPDX-License-Identifier: Apache-2.0

/** The record a stored row corrects, as SQLite reads it from the row's body. */
const CORRECTED = "json_extract(body, '$.supersedes.recordId')";

const INDEX_NAME = 'records_one_correction';
const INDEX_SQL = `CREATE UNIQUE INDEX IF NOT EXISTS ${INDEX_NAME}
  ON records(holder_key, ${CORRECTED})
  WHERE ${CORRECTED} IS NOT NULL AND correction_conflict IS NULL`;

/** The code a refused second correction carries in PUT /api/records `rejected`. */
const ALREADY_CORRECTED = 'already-corrected';

const alreadyCorrectedRefusal = (id, recordId, correctionId) => ({
  id,
  reason: `already corrected: record ${recordId} already has a correction here (${correctionId}). `
    + `A record is corrected once, so correct ${correctionId} instead; nothing was changed`,
  code: ALREADY_CORRECTED,
  status: 409,
  recordId,
  correctionId,
});

/**
 * The code a row carries in PUT /api/records `rejected` when it would remove or change the
 * `supersededBy` this registry holds for that record (8 Nov 2026, the site review's B1). A
 * correction is permanent, so once a record names its correction the link stays: a save that
 * drops it (a stale copy at a higher rev, after an answer was lost) would leave the record
 * looking uncorrected while its correction still stands, and the one-correction index would
 * then refuse every new correction of it, for good. The one exception: the correction the
 * link names is no longer held by this holder (it was removed), so the link names nothing.
 */
const SUPERSEDED_BY_LOCKED = 'supersededby-locked';

const supersededByLockedRefusal = (id, heldBy, sent) => ({
  id,
  reason: `this registry holds record ${id} as corrected by ${heldBy}, and a correction is permanent: `
    + `this save would ${typeof sent === 'string' ? `change that to ${sent}` : 'remove that link'}. `
    + 'Read the record again; nothing was changed',
  code: SUPERSEDED_BY_LOCKED,
  status: 409,
  supersededBy: heldBy,
});

/**
 * The code a correction carries in PUT /api/records `rejected` when the record it corrects was
 * in the same save and was refused (the joint review, round 3): a correction and its record are
 * stored together or not at all. A correction stored while its record was refused as an older
 * copy (another tab saved it a moment before) left the record unlinked, and the one-correction
 * index then refused every later correction of it. `recordCode` is the record's own refusal.
 */
const RECORD_REFUSED = 'record-refused';

const recordRefusedRefusal = (id, recordId, recordCode) => ({
  id,
  reason: `the record this corrects (${recordId}) was refused in this save (${recordCode}), and a correction `
    + 'is stored only together with its record. Read the record again; nothing was changed',
  code: RECORD_REFUSED,
  status: 409,
  recordId,
  recordCode,
});

/** Whether an error is SQLite refusing a row because of the one-correction index. */
const isSecondCorrection = (e) =>
  !!e && e.code === 'SQLITE_CONSTRAINT_UNIQUE' && typeof e.message === 'string' && e.message.includes(INDEX_NAME);

/**
 * Every holder and record with more than one correction not yet marked: { holder_key,
 * recordId, ids: [correction ids, the one to keep first] }.
 */
const findConflicts = (db) => {
  const groups = db.prepare(
    `SELECT holder_key, ${CORRECTED} AS recordId FROM records
     WHERE ${CORRECTED} IS NOT NULL AND correction_conflict IS NULL
     GROUP BY holder_key, ${CORRECTED} HAVING COUNT(*) > 1`,
  ).all();
  const rows = db.prepare(
    `SELECT id FROM records
     WHERE holder_key = ? AND ${CORRECTED} = ? AND correction_conflict IS NULL
     ORDER BY first_seen IS NULL, first_seen, id`,
  );
  const named = db.prepare("SELECT json_extract(body, '$.supersededBy') AS by FROM records WHERE id = ? AND holder_key = ?");
  return groups.map((g) => {
    const ids = rows.all(g.holder_key, g.recordId).map((r) => r.id);
    const by = named.get(g.recordId, g.holder_key)?.by;
    const keep = ids.includes(by) ? by : ids[0];
    return { holder_key: g.holder_key, recordId: g.recordId, ids: [keep, ...ids.filter((i) => i !== keep)] };
  });
};

/**
 * Make sure the index is in place. Safe on every start. In one transaction: the column, the
 * marks for any record already corrected twice, the index. Then, every start: a marked row
 * whose record no longer has an unmarked correction (the kept one was removed) takes its
 * place, and every marked row still there is said in the log.
 *
 * Returns { marked: [{ recordId, kept, others }], stillMarked: [{ id, recordId, kept }] }.
 * Record ids only: never a holder key or its digest.
 */
const ensureOneCorrection = (db, { log = console.log } = {}) => {
  const marked = [];
  db.transaction(() => {
    if (!db.prepare("SELECT 1 FROM pragma_table_info('records') WHERE name = 'correction_conflict'").get()) {
      db.exec('ALTER TABLE records ADD COLUMN correction_conflict TEXT');
    }
    const mark = db.prepare('UPDATE records SET correction_conflict = ? WHERE id = ? AND holder_key = ?');
    for (const c of findConflicts(db)) {
      const [kept, ...others] = c.ids;
      for (const id of others) mark.run(kept, id, c.holder_key);
      marked.push({ recordId: c.recordId, kept, others });
    }
    // A marked row whose record has no unmarked correction any more: the earliest takes the
    // free place, so the record is held to one correction again.
    const orphans = db.prepare(
      `SELECT m.id, m.holder_key FROM records m
       WHERE m.correction_conflict IS NOT NULL AND json_extract(m.body, '$.supersedes.recordId') IS NOT NULL
         AND NOT EXISTS (SELECT 1 FROM records k
                         WHERE k.holder_key = m.holder_key AND k.correction_conflict IS NULL
                           AND json_extract(k.body, '$.supersedes.recordId') = json_extract(m.body, '$.supersedes.recordId'))
       ORDER BY m.first_seen IS NULL, m.first_seen, m.id`,
    ).all();
    const freed = new Map(); // holder and record -> the correction that took the place
    const unmark = db.prepare('UPDATE records SET correction_conflict = NULL WHERE id = ? AND holder_key = ?');
    const targetOf = db.prepare(`SELECT ${CORRECTED} AS t FROM records WHERE id = ? AND holder_key = ?`);
    for (const o of orphans) {
      const slot = `${o.holder_key}\0${targetOf.get(o.id, o.holder_key).t}`;
      if (freed.has(slot)) mark.run(freed.get(slot), o.id, o.holder_key);
      else {
        freed.set(slot, o.id);
        unmark.run(o.id, o.holder_key);
      }
    }
    // A marked row that no longer corrects anything has nothing to be marked for.
    db.exec(`UPDATE records SET correction_conflict = NULL WHERE correction_conflict IS NOT NULL AND ${CORRECTED} IS NULL`);
    // Every marked row names the correction its record holds now: the one kept may since have
    // been removed and another made, and the log would name a correction that is gone.
    db.exec(`UPDATE records AS m SET correction_conflict = (
               SELECT k.id FROM records k
               WHERE k.holder_key = m.holder_key AND k.correction_conflict IS NULL
                 AND json_extract(k.body, '$.supersedes.recordId') = json_extract(m.body, '$.supersedes.recordId'))
             WHERE m.correction_conflict IS NOT NULL
               AND EXISTS (SELECT 1 FROM records k
                           WHERE k.holder_key = m.holder_key AND k.correction_conflict IS NULL
                             AND json_extract(k.body, '$.supersedes.recordId') = json_extract(m.body, '$.supersedes.recordId')
                             AND k.id != m.correction_conflict)`);
    db.exec(INDEX_SQL);
  })();
  for (const m of marked) {
    log(`one correction per record: record ${m.recordId} had ${m.others.length + 1} corrections; kept ${m.kept} in the index, marked ${m.others.join(', ')} (nothing deleted)`);
  }
  const stillMarked = db.prepare(
    `SELECT id, ${CORRECTED} AS recordId, correction_conflict AS kept FROM records
     WHERE correction_conflict IS NOT NULL ORDER BY id`,
  ).all();
  if (stillMarked.length) {
    log(`one correction per record: ${stillMarked.length} extra correction${stillMarked.length === 1 ? '' : 's'} from before the rule, still held: ${
      stillMarked.map((s) => `${s.id} (corrects ${s.recordId}; kept: ${s.kept})`).join('; ')}`);
  }
  return { marked, stillMarked };
};

/**
 * Before a holder's rows move from one stored key to another (holder-key.js: a plain-text key
 * to its digest, or an older digest of an upper-case key to today's), settle every record
 * corrected under both: moving them as they are would put two corrections of one record under
 * one holder, and the index would refuse the move (a 500 on every request from that holder,
 * or a failed start). Settled as the start-up check does: the one the record's `supersededBy`
 * names is kept, or else the first seen; the other is marked `correction_conflict` (the id of
 * the one kept) and said in the log. Nothing is deleted.
 *
 * A no-op on a database without the column (before ensureOneCorrection first ran): there is
 * no index yet, and ensureOneCorrection marks any duplicate the move leaves.
 *
 * Returns [{ recordId, kept, marked }]. Record ids only in the log, never a holder key.
 */
const settleCorrectionClashes = (db, from, to, { log = console.log } = {}) => {
  if (from === to) return [];
  if (!db.prepare("SELECT 1 FROM pragma_table_info('records') WHERE name = 'correction_conflict'").get()) return [];
  const moving = db.prepare(
    `SELECT id, ${CORRECTED} AS recordId, first_seen FROM records
     WHERE holder_key = ? AND ${CORRECTED} IS NOT NULL AND correction_conflict IS NULL`,
  ).all(from);
  if (moving.length === 0) return [];
  const there = db.prepare(
    `SELECT id, first_seen FROM records WHERE holder_key = ? AND ${CORRECTED} = ? AND correction_conflict IS NULL`,
  );
  const named = db.prepare(
    "SELECT json_extract(body, '$.supersededBy') AS by FROM records WHERE id = ? AND holder_key IN (?, ?)",
  );
  const mark = db.prepare('UPDATE records SET correction_conflict = ? WHERE id = ? AND holder_key IN (?, ?)');
  // Rows already marked as extras of the one now losing its place point at the one kept.
  const repoint = db.prepare('UPDATE records SET correction_conflict = ? WHERE correction_conflict = ? AND holder_key IN (?, ?)');
  const settled = [];
  for (const m of moving) {
    const other = there.get(to, m.recordId);
    if (!other) continue;
    const by = named.get(m.recordId, from, to)?.by;
    const earlier = (a, b) => {
      if (a.first_seen === null && b.first_seen !== null) return b;
      if (b.first_seen === null && a.first_seen !== null) return a;
      if (a.first_seen !== b.first_seen) return a.first_seen < b.first_seen ? a : b;
      return a.id < b.id ? a : b;
    };
    const kept = by === m.id ? m : by === other.id ? other : earlier(m, other);
    const loser = kept === m ? other : m;
    mark.run(kept.id, loser.id, from, to);
    repoint.run(kept.id, loser.id, from, to);
    settled.push({ recordId: m.recordId, kept: kept.id, marked: loser.id });
    log(`one correction per record: record ${m.recordId} had a correction under each of two spellings of one holder key; kept ${kept.id} in the index, marked ${loser.id} (nothing deleted)`);
  }
  return settled;
};

module.exports = {
  RECORD_REFUSED,
  recordRefusedRefusal,
  SUPERSEDED_BY_LOCKED,
  supersededByLockedRefusal,
  settleCorrectionClashes,
  CORRECTED,
  INDEX_NAME,
  ALREADY_CORRECTED,
  alreadyCorrectedRefusal,
  isSecondCorrection,
  findConflicts,
  ensureOneCorrection,
};
