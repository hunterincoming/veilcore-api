// Batch anchoring for the registry.
//
// Anchoring every record individually would require every holder to run a funded
// wallet — a barrier no lab technician will cross — and one transaction per record,
// which does not survive volume. So commitments are aggregated and only the root is
// anchored. One transaction covers thousands of records.
//
// The registry's job here is narrow on purpose: collect commitments, seal a batch,
// store the proofs. Anchoring the root is a separate act, and a proof stays useful
// whether or not this service is still running.
//
// SPDX-License-Identifier: Apache-2.0

import { buildBatch } from 'veilcore-records';
import { stampRoot, upgradeAnswer, otsFile, parseOtsFile, serialiseTimestamp, rootDigest, OtsError, DEFAULT_CALENDARS, explorersFrom } from './ots.mjs';

/**
 * What a batch accepts as a commitment: exactly 64 lowercase hex characters. veilcore-records
 * 0.15's buildBatch throws on anything else, so a single malformed fingerprint left in an
 * old row would stop every seal (and anchoring with it). Such rows are left out of the
 * batch and reported instead.
 */
const SEALABLE = /^[0-9a-f]{64}$/;
const UNSEALABLE_REASON = 'recordFingerprint is not 64 lowercase hex characters; left out of batches';

/**
 * A ledger anchor as this registry serves it. Stored anchors are never rewritten; what goes
 * out adds `testNetwork` (false only for `mainnet`), and `network` is filled in as
 * `unknown` when missing, so a client that falls back to its own network when `network` is
 * absent (the site's SettlementStatus does) cannot mistake an older anchor for its own.
 * A test network can be reset; its dates carry no evidential weight.
 *
 * `testNetwork` is only on the anchor. A client that reads just `/verify`'s top-level
 * `anchored` still sees `true` for a batch anchored on Preview; `anchored` means "on some
 * ledger". `/verify`'s `priorPossession` is the field that means a mainnet anchor
 * (server.js), and the embed names the network.
 */
export const describeAnchor = (anchor) => {
  if (!anchor || typeof anchor !== 'object' || Array.isArray(anchor)) return null;
  const network = typeof anchor.network === 'string' && anchor.network ? anchor.network : 'unknown';
  return { ...anchor, network, testNetwork: network !== 'mainnet' };
};

/**
 * How far an anchor's date may sit outside [sealed, now]: the operator's clock, the chain's
 * block time and this server's clock disagree by seconds, not hours.
 */
export const ANCHOR_CLOCK_SKEW_MS = 5 * 60_000;

/** Thrown inside a seal's write when a pending record went away while the batch was built. */
const PENDING_CHANGED = new Error('pending set changed');

/** What GET /batches lists for each batch. */
const LIST_COLS = 'batch_id, root, sealed_at, record_count, anchor, ots_status, ots_error, ots_bitcoin_height, ots_bitcoin_time, ots IS NOT NULL AS has_ots';

/** Stamp retries per batch before the timer stops trying (the operator route still works). */
const MAX_STAMP_ATTEMPTS = 10;

export const createBatches = (db) => {
  db.exec(`
    CREATE TABLE IF NOT EXISTS batches (
      batch_id     TEXT PRIMARY KEY,
      root         TEXT NOT NULL,
      sealed_at    INTEGER NOT NULL,
      record_count INTEGER NOT NULL,
      anchor       TEXT
    );
    CREATE TABLE IF NOT EXISTS batch_proofs (
      commitment TEXT PRIMARY KEY,
      batch_id   TEXT NOT NULL,
      proof      TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS batch_proofs_batch ON batch_proofs(batch_id);

    -- Each calendar's validated answer, kept separately, so a bad one can never damage
    -- the others. The .ots file served is rebuilt from these.
    CREATE TABLE IF NOT EXISTS batch_ots_answers (
      id             INTEGER PRIMARY KEY AUTOINCREMENT,
      batch_id       TEXT NOT NULL,
      calendar       TEXT NOT NULL,
      answer         BLOB NOT NULL,
      received_at    INTEGER NOT NULL,
      bitcoin_height INTEGER,
      bitcoin_time   TEXT,
      upgraded_at    INTEGER
    );
    CREATE INDEX IF NOT EXISTS batch_ots_answers_batch ON batch_ots_answers(batch_id);

    -- An anchor a later one took the place of, kept as it was stored (11 Oct 2026). Only a
    -- test-network anchor is ever superseded, by one on another network (a Preview-era
    -- batch anchored again on mainnet); recording used to overwrite it and lose it.
    CREATE TABLE IF NOT EXISTS batch_anchor_history (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      batch_id    TEXT NOT NULL,
      anchor      TEXT NOT NULL,
      replaced_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS batch_anchor_history_batch ON batch_anchor_history(batch_id);
  `);
  // Added October 2026. Each column is added only if missing, so a database from before
  // (every batch on main) keeps its rows; those batches have no stamp until one is asked for.
  //   ots                the .ots file served (rebuilt from batch_ots_answers)
  //   ots_status         null (never stamped) | requested | pending | bitcoin | failed
  //   ots_error          the last problem, summarised (no upstream text)
  const cols = new Set(db.prepare('PRAGMA table_info(batches)').all().map((c) => c.name));
  for (const [name, type] of [
    ['ots', 'BLOB'], ['ots_calendars', 'TEXT'], ['ots_status', 'TEXT'], ['ots_error', 'TEXT'],
    ['ots_bitcoin_height', 'INTEGER'], ['ots_bitcoin_time', 'TEXT'], ['ots_attempts', 'INTEGER NOT NULL DEFAULT 0'],
    ['ots_checked_at', 'INTEGER'],
    // November 2026: an RFC 3161 timestamp on the root from a TSA (tsa.mjs), when one is set.
    //   tsa_token  the DER TimeStampToken, verified against the root before it was stored
    ['tsa_token', 'BLOB'], ['tsa_url', 'TEXT'], ['tsa_qualified', 'TEXT'], ['tsa_gen_time', 'TEXT'],
    ['tsa_signer', 'TEXT'], ['tsa_error', 'TEXT'], ['tsa_attempts', 'INTEGER NOT NULL DEFAULT 0'],
    ['tsa_tried_at', 'INTEGER'], ['tsa_tried_url', 'TEXT'],
  ]) {
    if (!cols.has(name)) db.exec(`ALTER TABLE batches ADD COLUMN ${name} ${type}`);
  }

  // 19 November 2026 (reliability audit): tokens from the second and later TSAs in
  // VEILCORE_TSA_URL, one row per batch and TSA. The first TSA's token stays in the columns
  // above, as before, so every reader of a single token is unchanged.
  db.exec(`CREATE TABLE IF NOT EXISTS batch_timestamps (
    batch_id TEXT NOT NULL,
    tsa_url TEXT NOT NULL,
    token BLOB,
    tsa_qualified TEXT,
    gen_time TEXT,
    signer TEXT,
    error TEXT,
    attempts INTEGER NOT NULL DEFAULT 0,
    tried_at INTEGER,
    PRIMARY KEY (batch_id, tsa_url)
  )`);

  // Every statement is prepared once, on first use (a records table without holder_key,
  // as in some tests, must not stop the rest from working).
  const cache = new Map();
  const st = (sql) => {
    if (!cache.has(sql)) cache.set(sql, db.prepare(sql));
    return cache.get(sql);
  };

  // A file stored by the first version of this branch, before answers were kept apart:
  // validate it and keep it as one answer, or drop it and say so.
  for (const b of st("SELECT batch_id, root, ots FROM batches WHERE ots IS NOT NULL AND batch_id NOT IN (SELECT batch_id FROM batch_ots_answers)").all()) {
    try {
      const ts = parseOtsFile(b.ots, rootDigest(b.root));
      st('INSERT INTO batch_ots_answers (batch_id, calendar, answer, received_at) VALUES (?,?,?,?)').run(b.batch_id, 'imported', serialiseTimestamp(ts), Date.now());
      st("UPDATE batches SET ots_status = COALESCE(ots_status, 'pending') WHERE batch_id = ?").run(b.batch_id);
    } catch (e) {
      st("UPDATE batches SET ots = NULL, ots_calendars = NULL, ots_status = 'failed', ots_error = ? WHERE batch_id = ?")
        .run(`stored .ots failed validation (${e instanceof OtsError ? e.message : 'unreadable'}); restamp`, b.batch_id);
    }
  }

  const otsEnabled = () => process.env.VEILCORE_OTS !== 'off';
  const inFlight = new Set();
  let sealing = false;

  const newBatchId = () =>
    'B-' + new Date().toISOString().slice(0, 10).replace(/-/g, '') + '-' +
    [...crypto.getRandomValues(new Uint8Array(2))].map((b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();

  /** Rebuild the served .ots and the batch's status from its stored answers. */
  const rebuild = (batchId, root) => {
    const rows = st('SELECT calendar, answer, bitcoin_height, bitcoin_time FROM batch_ots_answers WHERE batch_id = ? ORDER BY id').all(batchId);
    if (rows.length === 0) return;
    const file = otsFile(rootDigest(root), rows.map((r) => r.answer));
    const confirmed = rows.filter((r) => r.bitcoin_height !== null).sort((a, b) => a.bitcoin_height - b.bitcoin_height)[0];
    st(`UPDATE batches SET ots = ?, ots_calendars = ?, ots_status = ?, ots_bitcoin_height = ?, ots_bitcoin_time = ? WHERE batch_id = ?`).run(
      file, JSON.stringify([...new Set(rows.map((r) => r.calendar))]), confirmed ? 'bitcoin' : 'pending',
      confirmed?.bitcoin_height ?? null, confirmed?.bitcoin_time ?? null, batchId,
    );
  };

  /**
   * The OpenTimestamps entry for a proof or an export. `pending` is a calendar's promise,
   * not a Bitcoin timestamp, and says so.
   */
  const otsEntry = (b) => {
    if (!b.ots) return null;
    const status = b.ots_status === 'bitcoin' ? 'bitcoin' : 'pending';
    return {
      kind: 'opentimestamps',
      status,
      stamps: 'the batch root as 32 raw bytes (root.bin)',
      root: `/batches/${b.batch_id}/root.bin`,
      ots: `/batches/${b.batch_id}/root.bin.ots`,
      calendars: JSON.parse(b.ots_calendars || '[]'),
      ...(status === 'bitcoin' ? { bitcoinBlockHeight: b.ots_bitcoin_height, bitcoinBlockTime: b.ots_bitcoin_time ?? undefined } : {}),
      note: status === 'bitcoin'
        ? 'Upgraded to a Bitcoin block; `ots verify root.bin.ots` checks it against a Bitcoin node.'
        : 'Pending: the calendars have promised to put this root into a Bitcoin transaction. Until `ots upgrade` fetches that from them, this is not a Bitcoin timestamp and needs the calendars to become one.',
    };
  };

  /**
   * The RFC 3161 entry (SDK SPEC 9.2, kind `rfc3161`): the token, the TSA, whether the operator
   * states it is qualified, and the date it gives. Checked offline by verifyAnchor with the
   * batch root's 32 raw bytes, or by `openssl ts -verify -data root.bin -in root.tst`.
   */
  const qualifiedOf = (v) => {
    if (typeof v !== 'string') return null;
    try {
      const q = JSON.parse(v);
      return q && typeof q.scheme === 'string' ? q : null;
    } catch {
      return null;
    }
  };
  const tsaEntry = (b) => {
    if (!b?.tsa_token) return null;
    return {
      kind: 'rfc3161',
      token: Buffer.from(b.tsa_token).toString('base64'),
      tsa: b.tsa_url,
      // SDK SPEC 9.2: { scheme, trustedList? } as the operator stated it, or absent.
      ...(qualifiedOf(b.tsa_qualified) ? { qualified: qualifiedOf(b.tsa_qualified) } : {}),
      genTime: b.tsa_gen_time,
      ...(b.tsa_signer ? { signer: b.tsa_signer } : {}),
      stamps: 'the batch root as 32 raw bytes (root.bin)',
      tst: `/batches/${b.batch_id}/root.tst`,
      ...(Date.parse(b.tsa_gen_time) - b.sealed_at > 2 * 3_600_000 ? { requestedAfterSeal: true } : {}),
      note: 'Shows the batch root existed by genTime, the time the TSA states; nothing earlier. Whether the TSA is qualified is checked on the trusted list named, not here.',
    };
  };

  // Prepared once here, not on first use: an export prepares a fixed number of statements
  // whatever it holds (attack-ots.test.mjs).
  const otherTsaRows = db.prepare('SELECT * FROM batch_timestamps WHERE batch_id = ? AND token IS NOT NULL ORDER BY tsa_url');
  /** The tokens from the second and later TSAs, as rfc3161 entries, in the order of their URLs. */
  const otherTsaEntries = (b) => {
    if (!b?.batch_id) return [];
    return otherTsaRows.all(b.batch_id).map((t) => ({
      kind: 'rfc3161',
      token: Buffer.from(t.token).toString('base64'),
      tsa: t.tsa_url,
      ...(qualifiedOf(t.tsa_qualified) ? { qualified: qualifiedOf(t.tsa_qualified) } : {}),
      genTime: t.gen_time,
      ...(t.signer ? { signer: t.signer } : {}),
      stamps: 'the batch root as 32 raw bytes (root.bin)',
      tst: `/batches/${b.batch_id}/root.tst?tsa=${encodeURIComponent(t.tsa_url)}`,
      ...(Date.parse(t.gen_time) - b.sealed_at > 2 * 3_600_000 ? { requestedAfterSeal: true } : {}),
      note: 'Shows the batch root existed by genTime, the time the TSA states; nothing earlier. Whether the TSA is qualified is checked on the trusted list named, not here.',
    }));
  };

  /** A stored proof with the batch's anchors folded in. */
  const foldAnchors = (proof, b) => {
    if (b?.anchor) proof.anchor = describeAnchor(JSON.parse(b.anchor));
    const ots = b ? otsEntry(b) : null;
    const tsa = tsaEntry(b);
    const others = otherTsaEntries(b);
    if (ots || tsa || others.length)
      proof.anchors = [...(proof.anchor ? [{ kind: 'ledger', ...proof.anchor }] : []), ...(ots ? [ots] : []), ...(tsa ? [tsa] : []), ...others];
    return proof;
  };

  const BATCH_COLS = 'batch_id, root, sealed_at, record_count, anchor, ots, ots_calendars, ots_status, ots_error, ots_bitcoin_height, ots_bitcoin_time, tsa_token, tsa_url, tsa_qualified, tsa_gen_time, tsa_signer';

  /** Unbatched commitments, split into ones a batch accepts and ones it would refuse. */
  const scanPending = () => {
    const rows = st(`
      SELECT r.id, json_extract(r.body, '$.recordFingerprint') AS commitment
      FROM records r
      WHERE commitment IS NOT NULL
        AND commitment NOT IN (SELECT commitment FROM batch_proofs)
    `).all().filter((r) => r.commitment);
    // Deal messages (deals.mjs): their fingerprints are dated the same way, so the hourly
    // anchor covers statements and replies too. The table exists once deals.mjs has loaded.
    const hasDeals = st("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'deal_messages'").get();
    if (hasDeals) {
      rows.push(...st(`
        SELECT 'deal-message' AS id, fingerprint AS commitment
        FROM deal_messages
        WHERE fingerprint NOT IN (SELECT commitment FROM batch_proofs)
      `).all());
    }
    const ok = [];
    const skipped = [];
    for (const r of rows) {
      if (typeof r.commitment === 'string' && SEALABLE.test(r.commitment)) ok.push(r);
      // The record id only: the malformed value itself is not echoed back.
      else skipped.push({ recordId: r.id, reason: UNSEALABLE_REASON });
    }
    return { ok, skipped };
  };

  return {
    /** Commitments that exist, are not yet in any batch, and a batch can take. */
    pending() {
      return scanPending().ok;
    },

    /** Unbatched records whose fingerprint a batch cannot take: { recordId, reason }. */
    unsealable() {
      return scanPending().skipped;
    },

    /**
     * Seal every pending commitment into a batch.
     *
     * The batch is sealed before it is anchored, and says so. A holder gets a proof
     * immediately that upgrades when the root lands on chain — the same pattern
     * OpenTimestamps uses, and it is honest at every stage rather than only at the end.
     */
    async seal() {
      // One seal at a time (attack round D). Two seals in flight both read the same
      // pending set across the await below and both wrote a batch; proofs were INSERT OR
      // REPLACE, so the second batch's proofs replaced the first's and left a batch row
      // with records counted and no proofs. stamp() already had this guard; seal had none.
      if (sealing) return { error: 'a seal is already in progress; try again shortly', code: 409 };
      sealing = true;
      try {
        const scan = scanPending();
        let rows = scan.ok;
        const report = scan.skipped.length ? { skipped: scan.skipped } : {};
        if (rows.length === 0) return { error: 'nothing pending', ...report };

        // An id not already used. It is the day and four random hex digits, so two batches on
        // one day had a 1 in 65,536 chance of the same id, and the insert below then failed
        // as if another seal had got there first (found 15 Oct 2026, the likely cause of a
        // seal in the test suite failing once). Checked here, under the one-seal-at-a-time
        // flag; a second process on the same database is still caught by the plain INSERT.
        const usedId = st('SELECT 1 FROM batches WHERE batch_id = ?');
        let batchId = newBatchId();
        for (let tries = 1; usedId.get(batchId) && tries < 100; tries++) batchId = newBatchId();
        if (usedId.get(batchId)) return { error: 'no unused batch id is left for today; seal again tomorrow', code: 503 };

        const insertBatch = st(
          'INSERT INTO batches (batch_id, root, sealed_at, record_count, anchor, ots_status) VALUES (?,?,?,?,NULL,?)');
        // Plain INSERT: a commitment already in a batch is a conflict that aborts the whole
        // seal, never a silent overwrite of a proof someone may already hold. That also
        // covers a second registry process sharing this database, which the flag cannot.
        const insertProof = st('INSERT INTO batch_proofs (commitment, batch_id, proof) VALUES (?,?,?)');
        // A record deleted (or changed) while the batch was built is not dated: checked again
        // inside the write. Those rows are left out and the tree built again from the rest, so
        // the set only shrinks and steady deletes can't keep a seal from finishing.
        const stillThere = st(`SELECT 1 FROM records WHERE id = ? AND json_extract(body, '$.recordFingerprint') = ?`);
        let batch;
        let leftOut = 0;
        for (;;) {
          batch = await buildBatch(rows.map((r) => r.commitment), batchId);
          let gone = [];
          try {
            db.transaction(() => {
              gone = rows.filter((r) => r.id !== 'deal-message' && !stillThere.get(r.id, r.commitment));
              if (gone.length) throw PENDING_CHANGED;
              insertBatch.run(batchId, batch.root, Date.now(), rows.length, otsEnabled() ? 'requested' : null);
              for (const [commitment, proof] of Object.entries(batch.proofs)) {
                insertProof.run(commitment, batchId, JSON.stringify(proof));
              }
            })();
          } catch (e) {
            if (e === PENDING_CHANGED) {
              const out = new Set(gone);
              rows = rows.filter((r) => !out.has(r));
              leftOut += gone.length;
              if (rows.length === 0) return { error: 'nothing pending', ...report };
              continue;
            }
            if (String(e?.code ?? '').startsWith('SQLITE_CONSTRAINT')) {
              return { error: 'the pending set changed while sealing (another seal got there first); nothing was written, seal again', code: 409 };
            }
            throw e;
          }
          break;
        }
        if (leftOut) report.leftOutWhileSealing = leftOut;

        // A second, independent date on Bitcoin. In the background: a slow calendar must not
        // hold up sealing. A failure is recorded on the batch and retried by the timer.
        if (otsEnabled()) void this.stamp(batchId).catch(() => {});
        return { batchId, root: batch.root, recordCount: rows.length, anchored: false, opentimestamps: otsEnabled() ? 'requested' : 'off', ...report };
      } finally {
        sealing = false;
      }
    },

    /**
     * Stamp a batch root with OpenTimestamps and store each calendar's answer. A batch that
     * already has a proof is refused unless `force`, and then the fresh answers are merged
     * in beside the old ones, never in place of them. Returns { error, code } on failure.
     */
    async stamp(batchId, { force = false, ...options } = {}) {
      const b = st('SELECT root FROM batches WHERE batch_id = ?').get(batchId);
      if (!b) return { error: 'no such batch', code: 404 };
      const held = st('SELECT COUNT(*) AS n FROM batch_ots_answers WHERE batch_id = ?').get(batchId).n;
      if (held > 0 && !force) {
        return { error: 'this batch already has an OpenTimestamps proof; add ?force=1 to add fresh calendar answers to it', code: 409 };
      }
      if (inFlight.has(batchId)) return { error: 'a stamp for this batch is already running', code: 409 };
      inFlight.add(batchId);
      st('UPDATE batches SET ots_attempts = ots_attempts + 1, ots_checked_at = ? WHERE batch_id = ?').run(Date.now(), batchId);
      try {
        const out = await stampRoot(b.root, options);
        db.transaction(() => {
          const ins = st('INSERT INTO batch_ots_answers (batch_id, calendar, answer, received_at) VALUES (?,?,?,?)');
          for (const a of out.answers) ins.run(batchId, a.calendar, a.answer, Date.now());
          rebuild(batchId, b.root);
          st('UPDATE batches SET ots_error = ? WHERE batch_id = ?')
            .run(out.failures.length ? `some calendars did not answer: ${out.failures.join('; ')}` : null, batchId);
        })();
        const now = st('SELECT ots_status FROM batches WHERE batch_id = ?').get(batchId);
        return { batchId, status: now.ots_status, calendars: out.calendars, failures: out.failures };
      } catch (e) {
        const message = e instanceof OtsError ? e.message : 'stamping failed';
        if (held > 0) st('UPDATE batches SET ots_error = ? WHERE batch_id = ?').run(message, batchId);
        else st("UPDATE batches SET ots_status = 'failed', ots_error = ? WHERE batch_id = ?").run(message, batchId);
        return { error: message, code: 502 };
      } finally {
        inFlight.delete(batchId);
      }
    },

    /**
     * Ask the calendars whether this batch's pending answers have reached a Bitcoin block,
     * and store the path to it once every block it names has been checked.
     */
    async upgrade(batchId, options = {}) {
      const b = st('SELECT root, ots_status FROM batches WHERE batch_id = ?').get(batchId);
      if (!b) return { error: 'no such batch', code: 404 };
      const rows = st('SELECT id, calendar, answer FROM batch_ots_answers WHERE batch_id = ? AND bitcoin_height IS NULL').all(batchId);
      if (rows.length === 0) {
        const n = st('SELECT COUNT(*) AS n FROM batch_ots_answers WHERE batch_id = ?').get(batchId).n;
        if (n === 0) return { error: 'this batch has no OpenTimestamps proof to upgrade', code: 409 };
      }
      const digest = rootDigest(b.root);
      const errors = [];
      let upgraded = 0;
      for (const row of rows) {
        try {
          const out = await upgradeAnswer(row.answer, digest, {
            calendars: DEFAULT_CALENDARS, explorers: explorersFrom(process.env.VEILCORE_BTC_EXPLORER), ...options,
          });
          errors.push(...out.errors.map((e) => `${row.calendar}: ${e}`));
          if (out.bitcoin) {
            st('UPDATE batch_ots_answers SET answer = ?, bitcoin_height = ?, bitcoin_time = ?, upgraded_at = ? WHERE id = ?')
              .run(out.answer, out.bitcoin.height, out.bitcoin.time, Date.now(), row.id);
            upgraded++;
          }
        } catch (e) {
          errors.push(`${row.calendar}: ${e instanceof OtsError ? e.message : 'upgrade failed'}`);
        }
      }
      rebuild(batchId, b.root);
      st('UPDATE batches SET ots_error = ?, ots_checked_at = ? WHERE batch_id = ?').run(errors.length ? errors.join('; ') : null, Date.now(), batchId);
      const now = st('SELECT ots_status, ots_bitcoin_height, ots_bitcoin_time FROM batches WHERE batch_id = ?').get(batchId);
      return {
        batchId, status: now.ots_status, upgraded,
        ...(now.ots_status === 'bitcoin' ? { bitcoinBlockHeight: now.ots_bitcoin_height, bitcoinBlockTime: now.ots_bitcoin_time } : {}),
        ...(errors.length ? { errors } : {}),
      };
    },

    /**
     * One pass of the timer: retry stamps that were requested but never finished (a
     * restart) or failed, then try to upgrade every pending batch. Sequential, to be gentle
     * with the calendars.
     */
    async otsMaintenance(options = {}) {
      const out = { stamped: [], upgraded: [] };
      const retry = st(`SELECT batch_id FROM batches WHERE ots_status IN ('requested', 'failed') AND ots_attempts < ? ORDER BY sealed_at`).all(MAX_STAMP_ATTEMPTS);
      for (const { batch_id: id } of retry) out.stamped.push({ batchId: id, ...(await this.stamp(id, options)) });
      for (const { batch_id: id } of st("SELECT batch_id FROM batches WHERE ots_status = 'pending' ORDER BY sealed_at").all()) {
        out.upgraded.push(await this.upgrade(id, options));
      }
      return out;
    },

    /** The .ots file for a batch and its status, or undefined for no such batch. */
    otsFor(batchId) {
      const b = st(`SELECT ${BATCH_COLS} FROM batches WHERE batch_id = ?`).get(batchId);
      if (!b) return undefined;
      return {
        root: b.root,
        ots: b.ots ? Buffer.from(b.ots) : null,
        calendars: b.ots_calendars ? JSON.parse(b.ots_calendars) : [],
        status: b.ots ? (b.ots_status === 'bitcoin' ? 'bitcoin' : 'pending') : (b.ots_status ?? 'none'),
        bitcoinBlockHeight: b.ots_bitcoin_height ?? undefined,
        bitcoinBlockTime: b.ots_bitcoin_time ?? undefined,
      };
    },

    /**
     * For /alerts `ots-behind` (reliability audit, 19 Nov 2026): a batch sealed in the last week,
     * over a day ago, was sent for a Bitcoin stamp and is still not in a Bitcoin block. A
     * calendar's transaction normally confirms within a few hours. Batches sealed while
     * stamping was off (no status) don't count, nor do ones older than a week, so one old
     * failure can't hold the alarm on for good.
     */
    otsBehind(now = Date.now()) {
      return !!st(`SELECT 1 FROM batches WHERE ots_status IN ('requested', 'pending', 'failed')
        AND sealed_at < ? AND sealed_at > ? LIMIT 1`).get(now - 24 * 3_600_000, now - 7 * 86_400_000);
    },

    /**
     * Record where a batch root was anchored.
     *
     * Separate from sealing because the anchor is a chain transaction made by whoever
     * runs this registry, and a batch is a real, useful object before that happens.
     */
    recordAnchor(batchId, anchor) {
      const b = st('SELECT batch_id, sealed_at, anchor FROM batches WHERE batch_id = ?').get(batchId);
      if (!b) return { error: 'no such batch', code: 404 };
      // The date is the operator's word until someone looks the transaction up, but it can
      // at least be possible (deep dive, 8 Oct 2026, MEDIUM): a root cannot be anchored
      // before the batch that has it was sealed, nor in the future. Any date used to be
      // accepted, so a batch sealed today could carry an anchor dated years ago.
      const at = Date.parse(anchor?.anchoredAt);
      if (Number.isFinite(at)) {
        if (at < b.sealed_at - ANCHOR_CLOCK_SKEW_MS) {
          return { error: `anchoredAt is before this batch was sealed (${new Date(b.sealed_at).toISOString()}); its root did not exist yet`, code: 400 };
        }
        if (at > Date.now() + ANCHOR_CLOCK_SKEW_MS) return { error: 'anchoredAt is in the future', code: 400 };
      }
      if (b.anchor === null) {
        st('UPDATE batches SET anchor = ? WHERE batch_id = ?').run(JSON.stringify(anchor), batchId);
        return { batchId, anchor: describeAnchor(anchor) };
      }

      // The batch already has an anchor (11 Oct 2026). Recording used to overwrite it, so a
      // mainnet anchor could be replaced by a later or a made-up one, and the earlier date
      // was gone. The first anchor on a network stands; the same transaction sent again
      // changes nothing; and a test-network anchor superseded by one on another network
      // (a Preview-era batch anchored again on mainnet) is kept in batch_anchor_history.
      let prev = null;
      try { prev = JSON.parse(b.anchor); } catch { /* unreadable: kept below, never matched */ }
      const before = describeAnchor(prev);
      if (before && before.network === anchor.network) {
        const same = (before.chain ?? 'midnight') === anchor.chain && before.contractAddress === anchor.contractAddress
          && before.txHash === anchor.txHash;
        if (same) return { batchId, anchor: before, unchanged: true };
        return {
          error: `this batch is already anchored on ${before.network} (transaction ${before.txHash}); an anchor is never replaced by another on the same network`,
          code: 409,
        };
      }
      if (before && !before.testNetwork) {
        return { error: 'this batch is already anchored on mainnet; that anchor is never replaced', code: 409 };
      }
      db.transaction(() => {
        st('INSERT INTO batch_anchor_history (batch_id, anchor, replaced_at) VALUES (?,?,?)').run(batchId, b.anchor, Date.now());
        st('UPDATE batches SET anchor = ? WHERE batch_id = ?').run(JSON.stringify(anchor), batchId);
      })();
      return { batchId, anchor: describeAnchor(anchor), supersedes: before };
    },

    /** Anchors a later one took the place of, oldest first (empty for almost every batch). */
    earlierAnchors(batchId) {
      return st('SELECT anchor, replaced_at FROM batch_anchor_history WHERE batch_id = ? ORDER BY id').all(batchId)
        .map((h) => {
          let a = null;
          try { a = JSON.parse(h.anchor); } catch { /* unreadable */ }
          return { ...(describeAnchor(a) ?? { unreadable: true }), replacedAt: new Date(h.replaced_at).toISOString() };
        });
    },

    /**
     * Everything about one record's batch for its evidence bundle (GET /records/:id/evidence):
     * the proof with its anchors, the batch's root and sealing time, every anchor it has had
     * (the current one and any it replaced), and the .ots file itself so the bundle needs no
     * second call. Null when the commitment is not in a batch yet.
     */
    evidenceFor(commitment) {
      const row = st('SELECT proof, batch_id FROM batch_proofs WHERE commitment = ?').get(commitment);
      if (!row) return null;
      const b = st(`SELECT ${BATCH_COLS} FROM batches WHERE batch_id = ?`).get(row.batch_id);
      const proof = foldAnchors(JSON.parse(row.proof), b);
      if (!b) return { proof, batch: null };
      const ots = otsEntry(b);
      return {
        proof,
        batch: {
          batchId: b.batch_id,
          root: b.root,
          sealedAt: new Date(b.sealed_at).toISOString(),
          recordCount: b.record_count,
          anchor: b.anchor ? describeAnchor(JSON.parse(b.anchor)) : null,
          earlierAnchors: this.earlierAnchors(b.batch_id),
          opentimestamps: ots
            ? {
                available: true,
                status: ots.status,
                stamps: 'the batch root as 32 raw bytes (root.bin)',
                calendars: ots.calendars,
                ...(ots.status === 'bitcoin' ? { bitcoinBlockHeight: ots.bitcoinBlockHeight, bitcoinBlockTime: ots.bitcoinBlockTime } : {}),
                ots: Buffer.from(b.ots).toString('base64'),
                note: ots.note,
              }
            : { available: false, status: b.ots_status ?? 'none' },
          rfc3161: tsaEntry(b) ?? { available: false },
          // From the second and later TSAs (VEILCORE_TSA_URL lists several): each its own token.
          ...(otherTsaEntries(b).length ? { rfc3161Others: otherTsaEntries(b) } : {}),
        },
      };
    },

    /**
     * For /alerts: a TSA is set and a batch sealed in the last week, over three hours ago, still
     * has no token. Older batches being filled in after a TSA is first set don't count.
     */
    tsaBehind() {
      const t = Date.now();
      return !!st('SELECT 1 FROM batches WHERE tsa_token IS NULL AND sealed_at < ? AND sealed_at > ? LIMIT 1').get(t - 3 * 3_600_000, t - 7 * 86_400_000);
    },

    /**
     * The stored RFC 3161 token for a batch (DER), or null; undefined for no such batch. With
     * `tsaUrl`, the token from that TSA (the first one's, or a later one's).
     */
    tsaFor(batchId, tsaUrl) {
      const b = st('SELECT tsa_token, tsa_error, tsa_url FROM batches WHERE batch_id = ?').get(batchId);
      if (!b) return undefined;
      if (tsaUrl === undefined || tsaUrl === b.tsa_url) return { token: b.tsa_token ? Buffer.from(b.tsa_token) : null, error: b.tsa_error };
      const t = st('SELECT token, error FROM batch_timestamps WHERE batch_id = ? AND tsa_url = ?').get(batchId, tsaUrl);
      return { token: t?.token ? Buffer.from(t.token) : null, error: t?.error ?? null };
    },

    /**
     * Ask the TSA (tsa.mjs requestTimestamp) for every batch without a token, oldest first.
     * Five quick tries, then once a day, and afresh whenever the TSA setting changes, so an
     * outage or a wrong setting never leaves a batch without one for good. A batch sealed before
     * a TSA was set gets a token dated now: the token says when it was made (requestedAfterSeal).
     */
    async tsaMaintenance(cfg, { request, limit = 50 } = {}) {
      if (!cfg?.url) return [];
      // Several TSAs (tsa.mjs tsaConfig `services`): each asked separately and at the same time,
      // so one that is slow or down never holds up the others. The first one's token goes where
      // it always went; the others' into batch_timestamps.
      const services = Array.isArray(cfg.services) && cfg.services.length ? cfg.services : [cfg];
      const all = await Promise.all(services.map((svc, i) => (i === 0 ? this.tsaPrimary(svc, { request, limit }) : this.tsaOther(svc, { request, limit }))));
      return all.flat();
    },

    /** The first TSA: its token in the batches table, as before several were allowed. */
    async tsaPrimary(cfg, { request, limit = 50 } = {}) {
      const out = [];
      const day = Date.now() - 86_400_000;
      const due = st(`SELECT batch_id, root FROM batches WHERE tsa_token IS NULL
        AND (tsa_attempts < 5 OR tsa_tried_at IS NULL OR tsa_tried_at < ? OR tsa_tried_url IS NOT ?)
        ORDER BY sealed_at LIMIT ?`).all(day, cfg.url, limit);
      for (const b of due) {
        st(`UPDATE batches SET tsa_attempts = CASE WHEN tsa_tried_url IS ? THEN tsa_attempts + 1 ELSE 1 END,
          tsa_tried_at = ?, tsa_tried_url = ? WHERE batch_id = ?`).run(cfg.url, Date.now(), cfg.url, b.batch_id);
        let r;
        try {
          r = await request(b.root, cfg);
        } catch {
          r = { error: 'the request failed' };
        }
        if (r.error) {
          st('UPDATE batches SET tsa_error = ? WHERE batch_id = ?').run(r.error, b.batch_id);
          out.push({ batchId: b.batch_id, error: r.error });
          continue;
        }
        st('UPDATE batches SET tsa_token = ?, tsa_url = ?, tsa_qualified = ?, tsa_gen_time = ?, tsa_signer = ?, tsa_error = NULL WHERE batch_id = ? AND tsa_token IS NULL')
          .run(Buffer.from(r.token, 'base64'), cfg.url, cfg.qualified ? JSON.stringify(cfg.qualified) : null, r.genTime, r.signerSubject ?? null, b.batch_id);
        out.push({ batchId: b.batch_id, genTime: r.genTime });
      }
      return out;
    },

    /** A second or later TSA: its token in batch_timestamps, with the same tries as the first. */
    async tsaOther(cfg, { request, limit = 50 } = {}) {
      const out = [];
      const day = Date.now() - 86_400_000;
      const due = st(`SELECT b.batch_id, b.root FROM batches b
        LEFT JOIN batch_timestamps t ON t.batch_id = b.batch_id AND t.tsa_url = ?
        WHERE t.token IS NULL AND (t.attempts IS NULL OR t.attempts < 5 OR t.tried_at IS NULL OR t.tried_at < ?)
        ORDER BY b.sealed_at LIMIT ?`).all(cfg.url, day, limit);
      for (const b of due) {
        st(`INSERT INTO batch_timestamps (batch_id, tsa_url, attempts, tried_at) VALUES (?, ?, 1, ?)
          ON CONFLICT(batch_id, tsa_url) DO UPDATE SET attempts = attempts + 1, tried_at = excluded.tried_at`).run(b.batch_id, cfg.url, Date.now());
        let r;
        try {
          r = await request(b.root, cfg);
        } catch {
          r = { error: 'the request failed' };
        }
        if (r.error) {
          st('UPDATE batch_timestamps SET error = ? WHERE batch_id = ? AND tsa_url = ?').run(r.error, b.batch_id, cfg.url);
          out.push({ batchId: b.batch_id, tsa: cfg.url, error: r.error });
          continue;
        }
        st(`UPDATE batch_timestamps SET token = ?, tsa_qualified = ?, gen_time = ?, signer = ?, error = NULL
          WHERE batch_id = ? AND tsa_url = ? AND token IS NULL`)
          .run(Buffer.from(r.token, 'base64'), cfg.qualified ? JSON.stringify(cfg.qualified) : null, r.genTime, r.signerSubject ?? null, b.batch_id, cfg.url);
        out.push({ batchId: b.batch_id, tsa: cfg.url, genTime: r.genTime });
      }
      return out;
    },

    /** The proof for a commitment, with the anchors folded in if the batch has any. */
    proofFor(commitment) {
      const row = st('SELECT proof, batch_id FROM batch_proofs WHERE commitment = ?').get(commitment);
      if (!row) return null;
      return foldAnchors(JSON.parse(row.proof), st(`SELECT ${BATCH_COLS} FROM batches WHERE batch_id = ?`).get(row.batch_id));
    },

    /**
     * Every proof and batch behind one holder's records, in two set-based queries. The
     * export used to look each record up on its own and scan every batch in the registry.
     */
    exportFor(holderKey) {
      const { byId, batches } = this.exportBatchesFor(holderKey);
      const proofs = {};
      for (let after = ''; ;) {
        const page = this.exportProofsPage(holderKey, after, 1000, byId);
        for (const [commitment, proof] of page.proofs) proofs[commitment] = proof;
        if (page.last === null) break;
        after = page.last;
      }
      return { proofs, batches };
    },

    /**
     * The export a piece at a time (round 2): the batches behind a holder's records (few:
     * one per seal), then their proofs a page at a time in record-id order. `last` is the
     * record id to continue after, or null at the end.
     */
    exportProofsPage(holderKey, afterRecordId, limit, byId) {
      const rows = st(`
        SELECT r.id AS record_id, bp.commitment, bp.batch_id, bp.proof
        FROM records r JOIN batch_proofs bp ON bp.commitment = json_extract(r.body, '$.recordFingerprint')
        WHERE r.holder_key = ? AND r.id > ? ORDER BY r.id LIMIT ?`).all(holderKey, afterRecordId, limit);
      return {
        proofs: rows.map((p) => [p.commitment, foldAnchors(JSON.parse(p.proof), byId.get(p.batch_id))]),
        last: rows.length === limit ? rows[rows.length - 1].record_id : null,
      };
    },

    exportBatchesFor(holderKey) {
      const batchRows = st(`
        SELECT ${BATCH_COLS} FROM batches WHERE batch_id IN (
          SELECT bp.batch_id FROM records r JOIN batch_proofs bp ON bp.commitment = json_extract(r.body, '$.recordFingerprint')
          WHERE r.holder_key = ?)
        ORDER BY sealed_at DESC`).all(holderKey);
      const byId = new Map(batchRows.map((b) => [b.batch_id, b]));
      const batches = batchRows.map((b) => {
        const ots = otsEntry(b);
        return {
          batchId: b.batch_id, root: b.root, sealedAt: new Date(b.sealed_at).toISOString(), recordCount: b.record_count,
          anchor: b.anchor ? describeAnchor(JSON.parse(b.anchor)) : null,
          // The .ots file itself, not a link to this server: an export must stand on its own.
          opentimestamps: ots ? {
            status: ots.status, stamps: 'the batch root as 32 raw bytes', ots: Buffer.from(b.ots).toString('base64'), calendars: ots.calendars,
            ...(ots.status === 'bitcoin' ? { bitcoinBlockHeight: ots.bitcoinBlockHeight, bitcoinBlockTime: ots.bitcoinBlockTime } : {}),
            note: ots.note,
          } : null,
          rfc3161: tsaEntry(b),
          ...(otherTsaEntries(b).length ? { rfc3161Others: otherTsaEntries(b) } : {}),
        };
      });
      return { byId, batches };
    },

    /**
     * Every batch, newest first. With `limit`, one page of them (public mirror, 18 Nov 2026):
     * `before` is the batchId the previous page ended on, and the next page starts after it in
     * the same order (sealed_at, then batch_id, both descending). A cursor, not an offset, so a
     * batch sealed while a mirror is paging lands on the first page and never shifts a later
     * one. Returns { batches, next } with `next` null on the last page, or `{ error }` for a
     * `before` that names no batch. Without `limit`, the whole list as before.
     */
    list({ limit, before } = {}) {
      if (limit === undefined) return this.rows(st(`SELECT ${LIST_COLS} FROM batches ORDER BY sealed_at DESC, batch_id DESC`).all());
      let rows;
      if (before === undefined) {
        rows = st(`SELECT ${LIST_COLS} FROM batches ORDER BY sealed_at DESC, batch_id DESC LIMIT ?`).all(limit + 1);
      } else {
        const at = st('SELECT sealed_at FROM batches WHERE batch_id = ?').get(before);
        if (!at) return { error: 'before names no batch' };
        rows = st(`SELECT ${LIST_COLS} FROM batches WHERE sealed_at < ? OR (sealed_at = ? AND batch_id < ?)
                   ORDER BY sealed_at DESC, batch_id DESC LIMIT ?`).all(at.sealed_at, at.sealed_at, before, limit + 1);
      }
      const more = rows.length > limit;
      const page = this.rows(more ? rows.slice(0, limit) : rows);
      return { batches: page, next: more ? page[page.length - 1].batch_id : null };
    },

    rows(listRows) {
      const superseded = new Set(st('SELECT DISTINCT batch_id FROM batch_anchor_history').all().map((r) => r.batch_id));
      return listRows
        .map(({ has_ots: hasOts, ots_status: s, ots_error: err, ots_bitcoin_height: h, ots_bitcoin_time: t, ...b }) => ({
          ...b,
          anchor: b.anchor ? describeAnchor(JSON.parse(b.anchor)) : null,
          ...(superseded.has(b.batch_id) ? { earlierAnchors: this.earlierAnchors(b.batch_id) } : {}),
          opentimestamps: {
            status: hasOts ? (s === 'bitcoin' ? 'bitcoin' : 'pending') : (s ?? 'none'),
            ...(h !== null ? { bitcoinBlockHeight: h, bitcoinBlockTime: t } : {}),
            ...(err ? { error: err } : {}),
          },
        }));
    },
  };
};
