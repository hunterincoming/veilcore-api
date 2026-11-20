// The registry's own seal timer (reliability audit, 19 Nov 2026, Tier 1 item 5).
//
// Before this, a batch was sealed only when the sponsor's anchoring job asked
// (POST /batches/seal), and the sponsor asks only while its wallet is synced. So a Midnight,
// Blockfrost, proof-server or wallet problem stopped all three dates for new records: Midnight,
// and with it Bitcoin (OpenTimestamps) and the RFC 3161 timestamp, which need a sealed root.
// With this on, the registry seals pending records itself and asks for the Bitcoin stamp and
// the timestamp at once (batches.seal starts the stamp; afterSeal runs the TSA upkeep). The
// sponsor then only anchors sealed batches on Midnight, oldest first, as it already does
// (sponsor/src/anchorer.ts pickBatch in hunterincoming/veilcore).
//
// One sealer, exactly once:
//   - Every seal in this process goes through sealIfDue, one at a time (a promise chain), so
//     the timer and the operator route never call batches.seal together. batches.seal has its
//     own one-at-a-time flag and a plain INSERT per record's proof, so even a second process on
//     the same database cannot put a record in two batches.
//   - The rule for "due" is the sponsor's (ANCHOR_EVERY_MINUTES 60, ANCHOR_AT_PENDING 25), read
//     against the newest batch in the database, not a clock in memory: a restart, or a batch
//     the sponsor sealed, counts. So the two can't take turns sealing twice as often.
//   - With the timer on, POST /batches/seal goes through sealIfDue too: it seals only when the
//     timer would, and otherwise answers `400 { error: 'nothing pending', notDue: true }`,
//     which every sponsor build reads as "nothing sealed this run" (registry.ts seal). No
//     sponsor change is needed, and it does not count as a failure there.
//
// Settings (README "Environment"), all off by default:
//   VEILCORE_SEAL_TIMER=on            turn it on
//   VEILCORE_SEAL_EVERY_MINUTES=60    seal at least this often while anything is pending (5 to 1440)
//   VEILCORE_SEAL_AT_PENDING=25       seal straight away once this many are pending (1 to 100000)
//   VEILCORE_SEAL_CHECK_MS=300000     how often the timer looks (1000 to 3600000)
//
// SPDX-License-Identifier: Apache-2.0

'use strict';

const int = (raw, def, min, max, name, problems) => {
  if (raw === undefined || String(raw).trim() === '') return def;
  const n = Number(String(raw).trim());
  if (!Number.isSafeInteger(n) || n < min || n > max) {
    problems.push(`${name} must be a whole number from ${min} to ${max}`);
    return def;
  }
  return n;
};

/** The timer's settings from the environment, and any problems with them. */
const sealTimerSettings = (env = process.env) => {
  const problems = [];
  const raw = String(env.VEILCORE_SEAL_TIMER ?? '').trim().toLowerCase();
  if (raw !== '' && raw !== 'on' && raw !== 'off') problems.push('VEILCORE_SEAL_TIMER must be on or off');
  const everyMinutes = int(env.VEILCORE_SEAL_EVERY_MINUTES, 60, 5, 24 * 60, 'VEILCORE_SEAL_EVERY_MINUTES', problems);
  const atPending = int(env.VEILCORE_SEAL_AT_PENDING, 25, 1, 100_000, 'VEILCORE_SEAL_AT_PENDING', problems);
  const checkMs = int(env.VEILCORE_SEAL_CHECK_MS, 5 * 60_000, 1000, 3_600_000, 'VEILCORE_SEAL_CHECK_MS', problems);
  // A setting that can't be read keeps the timer off: sealing then stays with the sponsor, as
  // before, rather than running on a guess.
  return { on: raw === 'on' && problems.length === 0, everyMs: everyMinutes * 60_000, atPending, checkMs, problems };
};

/**
 * The seal timer. `batches` is lineage/batches.mjs; `db` the same database (for the newest
 * batch's sealing time). `afterSeal(batchId)` runs after each seal this makes (the TSA upkeep);
 * it is never awaited and its failure never undoes a seal.
 */
const createSealTimer = ({ batches, db, everyMs = 60 * 60_000, atPending = 25, now = Date.now, afterSeal = () => {}, log = () => {} }) => {
  const newest = db.prepare('SELECT MAX(sealed_at) AS t FROM batches');
  let chain = Promise.resolve();
  const status = { lastRunAt: null, lastSealedBatch: null, lastError: null };

  /** When the next seal is due by time alone, for a newest batch sealed at `last`. */
  const dueAt = (last) => (last ? last + everyMs : 0);

  const once = async () => {
    status.lastRunAt = new Date(now()).toISOString();
    const pending = batches.pending().length;
    if (pending === 0) return { sealed: false, pending: 0 };
    const last = newest.get()?.t ?? null;
    const due = pending >= atPending || now() >= dueAt(last);
    if (!due) return { sealed: false, pending, notDue: true, nextSealAt: new Date(dueAt(last)).toISOString() };
    const out = await batches.seal();
    if (out.error) {
      // 'nothing pending' here means the records went away while sealing: not a problem.
      if (out.error !== 'nothing pending') {
        status.lastError = out.error;
        log('warn', `seal timer: ${out.error}`);
      }
      return { sealed: false, pending, ...out };
    }
    status.lastSealedBatch = out.batchId;
    status.lastError = null;
    log('info', `seal timer: sealed ${out.batchId} (${out.recordCount} records)`);
    try {
      void Promise.resolve(afterSeal(out.batchId)).catch(() => {});
    } catch {
      /* the seal stands */
    }
    return { sealed: true, ...out };
  };

  /**
   * Seal what is pending if it is due, one call at a time. Never throws: an error becomes
   * `{ sealed: false, error }`.
   */
  const sealIfDue = () => {
    const run = chain.then(once).catch((e) => {
      status.lastError = 'the seal failed';
      log('error', `seal timer: ${e?.message ?? e}`);
      return { sealed: false, error: 'the seal failed', code: 500 };
    });
    chain = run.then(() => undefined);
    return run;
  };

  return {
    sealIfDue,
    status: () => ({ ...status, everyMinutes: Math.round(everyMs / 60_000), atPending }),
  };
};

module.exports = { sealTimerSettings, createSealTimer };
