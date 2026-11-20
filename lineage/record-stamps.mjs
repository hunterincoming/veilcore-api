// A timestamp of its own for each record, in seconds (RFC 3161, lineage/tsa.mjs).
//
// A batch root gets a timestamp token within the hour, and a Midnight date when its batch is
// anchored. A holder who has just sealed a record waits for both. So the moment the registry
// takes a record's proof code (PUT /api/records with a proof code new to that record, or PUT
// /api/records/dating), it asks the same Time Stamping Authority for a token on that proof
// code alone: the 32 raw bytes of the proof code, as the SDK stamps a record commitment (SPEC
// 3.2, anchor kind `rfc3161`). The record's page and its check page can then say "timestamped
// at 14:03:12 by <the TSA>" within seconds, and that the Midnight date follows with the batch.
//
// VEILCORE_TSA_URL may list several TSAs (reliability audit, 19 Nov 2026): each proof code is
// queued for each one, each TSA keeps its own pace and its own pauses, and a reader gets every
// token that came back, each its own fact.
//
// Rules this keeps (per TSA):
//   - Never in the way. Taking a proof code only adds a row to a queue (one SQLite insert);
//     the request runs afterwards, one at a time. A TSA that is slow, down or refusing never
//     holds up or fails a save.
//   - The provider's limits. At most one request in flight, at least `minIntervalMs` apart
//     (VEILCORE_TSA_RECORD_MIN_INTERVAL_MS; some free TSAs ask for 15 s), and a pause that
//     doubles after each failure, up to ten minutes.
//   - The batch is the fallback. A proof code still waiting after `maxWaitMs`, tried
//     `maxAttempts` times, or arriving while `maxQueue` others wait, gets no token of its own
//     and is marked `batch`: its batch's token (tsa.mjs) dates it, as before.
//   - Checked before stored: requestTimestamp verifies the token against the proof code, the
//     nonce, that its time is now, and the pinned signer when one is set.
//   - Only a proof code a record still has. One whose record was deleted or changed before its
//     turn is dropped from the queue, not stamped.
//
// What a token shows: that this proof code existed by the time the TSA states. Nothing
// earlier, and nothing about what the record says. The TSA learns a SHA-256 of the proof
// code and when it was asked; nothing else. Whether the TSA is qualified is only what the
// operator states (VEILCORE_TSA_QUALIFIED_SCHEME), as for batches.
//
// SPDX-License-Identifier: Apache-2.0

const HEX64 = /^[0-9a-f]{64}$/;

export const RECORD_STAMP_NOTE =
  'Shows this proof code existed by genTime, the time the TSA states; nothing earlier. Requested by the registry when it took the proof code. Its batch is dated on Midnight separately. Whether the TSA is qualified is checked on the trusted list named, not here.';

/** Settings from the environment, with defaults. Unparseable or out-of-range values use the default. */
export const recordStampSettings = (env = process.env) => {
  const int = (name, dflt, min, max) => {
    const v = Number.parseInt(String(env[name] ?? ''), 10);
    return Number.isInteger(v) && v >= min && v <= max ? v : dflt;
  };
  return {
    on: String(env.VEILCORE_TSA_RECORDS ?? '').trim().toLowerCase() !== 'off',
    minIntervalMs: int('VEILCORE_TSA_RECORD_MIN_INTERVAL_MS', 2_000, 0, 600_000),
    maxWaitMs: int('VEILCORE_TSA_RECORD_MAX_WAIT_MS', 30 * 60_000, 1_000, 24 * 3_600_000),
    maxQueue: int('VEILCORE_TSA_RECORD_MAX_QUEUE', 1_000, 1, 100_000),
  };
};

/**
 * @param db  better-sqlite3 database
 * @param opts.request   (commitmentHex, cfg) => Promise<{ token, genTime, signerSubject } | { error }>
 * @param opts.stillHeld (recordId, commitment) => boolean: a record still carries this proof code
 */
export const createRecordStamps = (
  db,
  {
    request,
    stillHeld = () => true,
    now = Date.now,
    minIntervalMs = 2_000,
    maxWaitMs = 30 * 60_000,
    maxQueue = 1_000,
    maxAttempts = 3,
    backoffMs = 30_000,
    maxBackoffMs = 10 * 60_000,
    setTimer = (fn, ms) => {
      const t = setTimeout(fn, ms);
      t.unref?.();
      return t;
    },
    clearTimer = (t) => clearTimeout(t),
  } = {},
) => {
  // One row per proof code and TSA (VEILCORE_TSA_URL may list several, tsa.mjs tsaConfig).
  db.exec(`
    CREATE TABLE IF NOT EXISTS record_timestamps (
      commitment TEXT NOT NULL,
      tsa_url TEXT NOT NULL,
      record_id TEXT NOT NULL,
      state TEXT NOT NULL,
      queued_at INTEGER NOT NULL,
      attempts INTEGER NOT NULL DEFAULT 0,
      tried_at INTEGER,
      error TEXT,
      token BLOB,
      tsa_qualified TEXT,
      gen_time TEXT,
      signer TEXT,
      PRIMARY KEY (commitment, tsa_url)
    );
    CREATE INDEX IF NOT EXISTS record_timestamps_queue ON record_timestamps (tsa_url, state, queued_at);
  `);
  const st = (sql) => db.prepare(sql);
  const insert = st(
    `INSERT INTO record_timestamps (commitment, tsa_url, record_id, state, queued_at, error) VALUES (?, ?, ?, ?, ?, ?)
     ON CONFLICT(commitment, tsa_url) DO NOTHING`,
  );
  const waiting = st(`SELECT COUNT(*) AS n FROM record_timestamps WHERE tsa_url = ? AND state = 'queued'`);
  const next = st(`SELECT commitment, record_id, queued_at, attempts FROM record_timestamps
    WHERE tsa_url = ? AND state = 'queued' ORDER BY queued_at, commitment LIMIT 1`);
  const toBatch = st(`UPDATE record_timestamps SET state = 'batch', error = ? WHERE commitment = ? AND tsa_url = ? AND state = 'queued'`);
  const drop = st(`DELETE FROM record_timestamps WHERE commitment = ? AND state = 'queued'`);
  const tried = st(`UPDATE record_timestamps SET attempts = attempts + 1, tried_at = ?, error = ? WHERE commitment = ? AND tsa_url = ?`);
  const stamped = st(
    `UPDATE record_timestamps SET state = 'stamped', token = ?, tsa_qualified = ?, gen_time = ?, signer = ?, error = NULL
     WHERE commitment = ? AND tsa_url = ? AND state = 'queued'`,
  );
  const rowsOf = st(`SELECT * FROM record_timestamps WHERE commitment = ? ORDER BY tsa_url`);

  /** Per TSA: its settings and its own pace, so one that is slow or down never holds up another. */
  let lanes = [];
  const idleWaiters = [];

  const quiet = () => lanes.every((l) => !l.running && !l.timer);
  const settleIdle = () => {
    if (!quiet()) return;
    while (idleWaiters.length) idleWaiters.shift()();
  };

  const schedule = (lane, delay = 0) => {
    if (lane.running || lane.timer || !lanes.includes(lane)) return settleIdle();
    lane.timer = setTimer(() => {
      lane.timer = null;
      void pump(lane);
    }, Math.max(0, delay));
  };

  /** Work through one TSA's queue, one request at a time, until it is empty or must wait. */
  const pump = async (lane) => {
    if (lane.running || !lanes.includes(lane)) return settleIdle();
    lane.running = true;
    const svc = lane.svc;
    try {
      for (;;) {
        const row = next.get(svc.url);
        if (!row) break;
        if (!stillHeld(row.record_id, row.commitment)) {
          drop.run(row.commitment);
          continue;
        }
        if (now() - row.queued_at > maxWaitMs) {
          toBatch.run('waited too long; its batch is timestamped instead', row.commitment, svc.url);
          continue;
        }
        const wait = lane.nextAllowedAt - now();
        if (wait > 0) {
          lane.running = false;
          return schedule(lane, wait);
        }
        let r;
        try {
          r = await request(row.commitment, svc);
        } catch {
          r = { error: 'the request failed' };
        }
        lane.nextAllowedAt = now() + minIntervalMs;
        if (!r || r.error || !r.token) {
          const error = String(r?.error ?? 'no token').slice(0, 300);
          tried.run(now(), error, row.commitment, svc.url);
          lane.failures++;
          lane.nextAllowedAt = now() + Math.min(maxBackoffMs, backoffMs * 2 ** (lane.failures - 1));
          if (row.attempts + 1 >= maxAttempts)
            toBatch.run(`no token after ${maxAttempts} tries (${error}); its batch is timestamped instead`, row.commitment, svc.url);
          continue;
        }
        lane.failures = 0;
        tried.run(now(), null, row.commitment, svc.url);
        stamped.run(
          Buffer.from(r.token, 'base64'),
          svc.qualified ? JSON.stringify(svc.qualified) : null,
          r.genTime,
          r.signerSubject ?? null,
          row.commitment,
          svc.url,
        );
      }
    } finally {
      lane.running = false;
    }
    settleIdle();
  };

  const qualifiedOf = (v) => {
    try {
      const q = v ? JSON.parse(v) : null;
      return q && typeof q.scheme === 'string' ? q : null;
    } catch {
      return null;
    }
  };

  return {
    /**
     * The TSA settings (tsa.mjs tsaConfig: one TSA, or `services` for several), or null for off.
     * Queued rows from before a restart resume.
     */
    configure(cfg) {
      for (const l of lanes) if (l.timer) clearTimer(l.timer);
      const services = !cfg || !cfg.url ? [] : Array.isArray(cfg.services) && cfg.services.length ? cfg.services : [cfg];
      lanes = services.map((svc) => ({ svc, running: false, timer: null, nextAllowedAt: 0, failures: 0 }));
      for (const l of lanes) schedule(l);
      settleIdle();
    },

    /** Whether proof codes are being timestamped one by one now. */
    get on() {
      return lanes.length > 0;
    },

    /**
     * Queue these proof codes for a token from each TSA. Synchronous and cheap: never awaits a
     * TSA. A proof code already queued or stamped there is left as it is. `items`: [{ id, commitment }].
     */
    enqueue(items) {
      if (lanes.length === 0 || !Array.isArray(items) || items.length === 0) return 0;
      const ok = items.filter((it) => it && typeof it.id === 'string' && typeof it.commitment === 'string' && HEX64.test(it.commitment));
      if (ok.length === 0) return 0;
      let added = 0;
      const t = now();
      const touched = new Set();
      db.transaction(() => {
        for (const lane of lanes) {
          let room = maxQueue - waiting.get(lane.svc.url).n;
          for (const it of ok) {
            const full = room <= 0;
            const info = insert.run(it.commitment, lane.svc.url, it.id, full ? 'batch' : 'queued', t, full ? 'the queue was full; its batch is timestamped instead' : null);
            if (info.changes) {
              added++;
              if (!full) {
                room--;
                touched.add(lane);
              }
            }
          }
        }
      })();
      for (const lane of touched) schedule(lane);
      return added;
    },

    /**
     * What a reader is told about one proof code: every token it has (one per TSA), how many are
     * still being asked for, or that its batch's token dates it instead; null for nothing.
     * Errors are not published.
     */
    instantFor(commitment) {
      if (!HEX64.test(String(commitment))) return null;
      const rows = rowsOf.all(commitment);
      if (rows.length === 0) return null;
      const tokens = rows
        .filter((r) => r.state === 'stamped' && r.token)
        .map((r) => ({
          kind: 'rfc3161',
          token: Buffer.from(r.token).toString('base64'),
          tsa: r.tsa_url,
          ...(qualifiedOf(r.tsa_qualified) ? { qualified: qualifiedOf(r.tsa_qualified) } : {}),
          genTime: r.gen_time,
          ...(r.signer ? { signer: r.signer } : {}),
        }));
      const queued = rows.filter((r) => r.state === 'queued').length;
      if (tokens.length === 0) return queued ? { status: 'queued' } : { status: 'batch' };
      return { status: 'stamped', stamps: 'the proof code as 32 raw bytes', tokens, ...(queued ? { stillAsking: queued } : {}), note: RECORD_STAMP_NOTE };
    },

    /** The DER token for a proof code from one TSA (the first stamped one when none is named), or null. */
    tokenFor(commitment, tsaUrl) {
      if (!HEX64.test(String(commitment))) return null;
      const r = rowsOf.all(commitment).find((x) => x.state === 'stamped' && x.token && (tsaUrl === undefined || x.tsa_url === tsaUrl));
      return r ? Buffer.from(r.token) : null;
    },

    /** Resolves once nothing is in flight or scheduled (tests). */
    idle() {
      return new Promise((resolve) => {
        idleWaiters.push(resolve);
        settleIdle();
      });
    },
  };
};
