// Lab results going back to the breeder, locked so only the breeder can open them.
//
// Before: a lab emailed a PDF. Anyone the email passed through could read it, nothing
// showed which lab it came from, and nothing tied it to the sample.
//
// Now the breeder's delivery code carries a public key made from the plant's own record
// secret (the app's lab-results.ts). The lab's browser locks the report to that key (the
// open `age` file format) and signs the report's fingerprint with the lab's own key (an
// attestation, posted separately like any other). This stores only the locked file.
//
// What the registry can and can't do with it:
//   - it can't read a report: the key to open it is made from a secret that never leaves
//     the breeder's devices, and the lab got the lock out of band, in the delivery code,
//     so the registry never had a chance to hand the lab a lock of its own;
//   - it refuses anything that isn't an age file, so a report can't be stored readable
//     by mistake;
//   - it could withhold or swap a file. A swapped file fails: the breeder's app opens it
//     only if its fingerprint matches one the lab signed.
//
// Who may do what: only the holder who claimed the delivery (the lab) can add results to
// it; only the sender (the breeder) can read them; both can list them. Either can remove
// one: the sender's delete removes it entirely; the lab's is a withdrawal, which removes
// the file but keeps a line saying it was withdrawn, so the breeder sees that it was. A
// corrected result names the one it replaces (`replaces`; not a withdrawn one). Up to 5 results (not counting
// withdrawn ones) per delivery, 15 MB each.
//
// Where the files live (round 2). The locked files are NOT in the database: only their
// details are (size, fingerprint, dates). The files sit in a folder next to it
// (LAB_RESULTS_DIR, by default <database folder>/lab-results), one file per result, named
// by its id. Kept out of the database so large reports don't swell every database backup;
// the off-site backup (backup.mjs) sends each file once, separately, as it is (locked to the
// breeder). One that arrived after the last backup is lost with the volume, and the breeder
// asks the lab to resend. A result whose file is gone says so instead of failing quietly.
//
// Limits. Results are kept 180 days, then deleted (the breeder's app keeps its own copy
// once downloaded). All stored files together may take LAB_RESULTS_MAX_BYTES (2 GiB by
// default); past that, uploads get 507 "storage full". Each lab (the delivery's receiver)
// may send 50 files or 300 MB in any 24 hours.
//
// One sender can't take the whole store (round 3). Results on the deliveries one holder
// sent may take LAB_RESULTS_MAX_BYTES_PER_SENDER together (300 MB by default; withdrawn
// ones don't count). A holder could send deliveries to a second key of their own and fill
// the store from both ends; so the last 10% of the total is kept for senders whose results
// stay under 50 MB, and a breeder with a few reports can still get one when the rest is
// full. Holder keys cost nothing to make, so these slow one party down; they don't stop
// one with many keys. The daily allowance per lab still applies.
//
// SPDX-License-Identifier: Apache-2.0

import { createHash, createPublicKey, verify as verifySignature } from 'node:crypto';
import { closeSync, fsyncSync, mkdirSync, openSync, readdirSync, readFileSync, renameSync, rmSync, statSync, writeSync } from 'node:fs';
import { join } from 'node:path';
import holderKeys from '../holder-key.js';

const { storedHolderKey, asStored } = holderKeys;

/**
 * What a lab's key signs to tie its first report on a delivery to itself (12 Nov 2026): the
 * text `veilcore:lab-result-key:v1`, the delivery id and the signature id, each on its own line,
 * signed (Ed25519) by the key that signed the report and sent as the x-lab-key-proof header
 * (128 lowercase hex). The site's lab-results.ts labKeyProofText makes the same text.
 */
export const LAB_KEY_PROOF_TAG = 'veilcore:lab-result-key:v1';
export const labKeyProofText = (transferId, attestationId) => `${LAB_KEY_PROOF_TAG}\n${transferId}\n${attestationId}`;
/** Whether `proof` is `publicKey`'s Ed25519 signature over labKeyProofText; never throws. */
const keyProofHolds = (publicKey, proof, transferId, attestationId) => {
  if (typeof proof !== 'string' || !/^[0-9a-f]{128}$/.test(proof) || typeof publicKey !== 'string' || !/^[0-9a-f]{64}$/.test(publicKey)) return false;
  try {
    const key = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(publicKey, 'hex').toString('base64url') }, format: 'jwk' });
    return verifySignature(null, Buffer.from(labKeyProofText(transferId, attestationId)), key, Buffer.from(proof, 'hex'));
  } catch {
    return false;
  }
};

export const RESULT_LIMITS = {
  maxBytes: 15 * 1024 * 1024,
  /** Live results on all deliveries one holder sent. LAB_RESULTS_MAX_BYTES_PER_SENDER overrides it (server.js). */
  perSenderBytes: 300 * 1024 * 1024,
  /** The share of maxTotalBytes kept for small senders, and what counts as small. */
  reserveShare: 0.1,
  reserveSenderBytes: 50 * 1024 * 1024,
  /** Live (not withdrawn) results per delivery. */
  perTransfer: 5,
  /** Every row per delivery, withdrawn ones included, so withdraw-and-resend has an end. */
  rowsPerTransfer: 20,
  keepMs: 180 * 86_400_000,
  /** All stored files together. LAB_RESULTS_MAX_BYTES overrides it (server.js). */
  maxTotalBytes: 2 * 1024 ** 3,
  /** Per receiver, in any 24 hours. */
  perReceiverDailyCount: 50,
  perReceiverDailyBytes: 300 * 1024 * 1024,
  sweepEveryMs: 60_000,
  /** A temporary file this old is a write that never finished, not one in progress. */
  staleTempMs: 60 * 60_000,
};

/** Every age file starts with this line (age-encryption.org/v1). */
const AGE_HEADER = Buffer.from('age-encryption.org/v1\n');
const RESULT_ID = /^LR-[0-9A-F]{32}$/;
const ATTESTATION_ID = /^[A-Za-z0-9._:-]{1,100}$/;
const DAY = 86_400_000;

const randomHex = (bytes) =>
  [...crypto.getRandomValues(new Uint8Array(bytes))].map((b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();

/** Locked files kept in memory: for a database that is itself in memory (tests). */
export const memoryFiles = () => {
  const m = new Map();
  const at = new Map();
  return {
    put: (id, bytes) => {
      m.set(id, Buffer.from(bytes));
      at.set(id, Date.now());
    },
    get: (id) => m.get(id),
    remove: (id) => {
      m.delete(id);
      at.delete(id);
    },
    ids: () => [...m.keys()],
    mtime: (id) => at.get(id),
  };
};

/**
 * Locked files in a folder, one per result, named by its id. A write goes to a temporary
 * name, is flushed to disk, then renamed into place and the folder flushed, so a crash
 * never leaves half a file under a result's name, and a file written is still there after
 * a power cut.
 *
 * The folder belongs to one database: it holds the id of the database it belongs to
 * (STORE_FILE), and createLabResults refuses a folder that names another one. That stops
 * two different databases sharing a folder, but not a COPY of the database (a backup
 * restored for a check, a volume snapshot): a copy has the same id. A copy knows nothing of
 * files written after it was made, so nothing is deleted for having no row while it could
 * still be live (round 3): a file with no row goes only once it is older than any result
 * is kept (180 days, by the file's own time), and a temporary only once it is an hour old.
 */
const STORE_FILE = '.veilcore-store-id';
const STORE_ID = /^[0-9A-F]{32}$/;

export const folderFiles = (dir) => {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const path = (id) => {
    if (!RESULT_ID.test(id)) throw new Error('bad result id');
    return join(dir, id);
  };
  const syncDir = () => {
    // A rename is only lasting once the folder itself is flushed. Not every system lets a
    // folder be opened for that; there the rename is as lasting as the system makes it.
    let fd;
    try {
      fd = openSync(dir, 'r');
      fsyncSync(fd);
    } catch {
      /* not supported here */
    } finally {
      if (fd !== undefined) closeSync(fd);
    }
  };
  const writeWhole = (final, data) => {
    const bytes = typeof data === 'string' ? Buffer.from(data) : data;
    const tmp = `${final}.tmp-${randomHex(6)}`;
    const fd = openSync(tmp, 'wx', 0o600);
    try {
      try {
        // One write() can put down less than it was given and still succeed: a nearly full
        // disk, a file-size limit. Kept as it was, that was a cut-short file under the
        // result's name, and on the move out of the database the only whole copy was then
        // dropped (found 15 Oct 2026 when the disk ran low under the tests). Write until it
        // is all down; the next write on a full disk throws, and nothing is kept.
        for (let done = 0; done < bytes.length; ) done += writeSync(fd, bytes, done, bytes.length - done);
        fsyncSync(fd);
      } finally {
        closeSync(fd);
      }
      renameSync(tmp, final);
    } catch (e) {
      rmSync(tmp, { force: true });
      throw e;
    }
    syncDir();
  };
  return {
    put: (id, bytes) => writeWhole(path(id), bytes),
    get(id) {
      try {
        return readFileSync(path(id));
      } catch (e) {
        if (e.code === 'ENOENT') return undefined;
        throw e;
      }
    },
    remove: (id) => rmSync(path(id), { force: true }),
    ids: () => readdirSync(dir).filter((n) => RESULT_ID.test(n)),
    /** When a file was last written, or undefined if it is gone. */
    mtime(id) {
      try {
        return statSync(path(id)).mtimeMs;
      } catch (e) {
        if (e.code === 'ENOENT') return undefined;
        throw e;
      }
    },
    /** The id of the database this folder belongs to, if it has one yet. */
    owner() {
      try {
        const v = readFileSync(join(dir, STORE_FILE), 'utf8').trim();
        return STORE_ID.test(v) ? v : undefined;
      } catch (e) {
        if (e.code === 'ENOENT') return undefined;
        throw e;
      }
    },
    setOwner: (id) => writeWhole(join(dir, STORE_FILE), `${id}\n`),
    /**
     * Leftovers from a write that never finished. Only once the folder is known to be ours,
     * and only those older than `olderThanMs`: a younger one may be a write in progress (by
     * this database, or by the live one when this is a copy).
     */
    clearTemps(olderThanMs, nowMs = Date.now()) {
      for (const name of readdirSync(dir)) {
        if (!name.includes('.tmp-')) continue;
        try {
          if (nowMs - statSync(join(dir, name)).mtimeMs > olderThanMs) rmSync(join(dir, name), { force: true });
        } catch (e) {
          if (e.code !== 'ENOENT') throw e;
        }
      }
    },
  };
};

export const createLabResults = (db, { now = () => Date.now(), files = memoryFiles(), limits = {} } = {}) => {
  const L = { ...RESULT_LIMITS, ...limits };
  db.exec(`
    CREATE TABLE IF NOT EXISTS lab_results (
      id             TEXT PRIMARY KEY,
      transfer_id    TEXT NOT NULL,
      size           INTEGER NOT NULL,
      sha256         TEXT NOT NULL,
      attestation_id TEXT,
      created_at     INTEGER NOT NULL,
      receiver       TEXT,
      replaces       TEXT,
      withdrawn_at   INTEGER
    );
    CREATE INDEX IF NOT EXISTS lab_results_transfer ON lab_results(transfer_id);
  `);
  // Bind the folder to this database before touching anything in it (see folderFiles).
  if (files.owner) {
    db.exec('CREATE TABLE IF NOT EXISTS lab_results_store (id TEXT NOT NULL)');
    let mine = db.prepare('SELECT id FROM lab_results_store LIMIT 1').get()?.id;
    if (!mine) {
      mine = randomHex(16);
      db.prepare('INSERT INTO lab_results_store (id) VALUES (?)').run(mine);
    }
    const theirs = files.owner();
    if (theirs && theirs !== mine) {
      throw new Error('LAB_RESULTS_DIR holds the lab results of another database; give this database a separate folder');
    }
    if (!theirs) files.setOwner(mine);
    files.clearTemps(L.staleTempMs, now());
  }
  const columns = new Set(db.prepare("SELECT name FROM pragma_table_info('lab_results')").all().map((c) => c.name));
  for (const [name, type] of [['receiver', 'TEXT'], ['replaces', 'TEXT'], ['withdrawn_at', 'INTEGER']]) {
    if (!columns.has(name)) db.exec(`ALTER TABLE lab_results ADD COLUMN ${name} ${type}`);
  }
  // A database written by the first version kept the files inside it: they move out, once.
  // One row at a time (all of them at once could be gigabytes in memory). Stopped halfway,
  // nothing is lost: the column is dropped only after every file is written, and the next
  // start writes them all again (a write replaces a file whole).
  if (columns.has('ciphertext')) {
    for (const r of db.prepare('SELECT id, ciphertext FROM lab_results').iterate()) files.put(r.id, r.ciphertext);
    db.exec('ALTER TABLE lab_results DROP COLUMN ciphertext');
  }
  // Dropping the column frees its pages but does not shrink the file, and backup.mjs
  // measures the file (pages in use or not) and refuses one over 128 MB: the move out was
  // for that. So a file mostly free space is rebuilt. Also covers a stop between the drop
  // and this.
  {
    const pageSize = db.pragma('page_size', { simple: true });
    if (db.pragma('freelist_count', { simple: true }) * pageSize > 32 * 1024 * 1024) db.exec('VACUUM');
  }
  db.exec(`
    CREATE INDEX IF NOT EXISTS lab_results_created ON lab_results(created_at);
    CREATE INDEX IF NOT EXISTS lab_results_receiver ON lab_results(receiver, created_at);
  `);
  /**
   * Files with no row (a crash between writing the file and the row, a row removed by
   * hand) that are older than any result is kept. A younger one is left alone, whatever
   * this database says: this may be a copy, and the file a live result written after the
   * copy was made (round 3: a copy started against the live folder deleted them).
   */
  const clearOldOrphans = () => {
    if (!files.mtime) return 0;
    const known = new Set(db.prepare('SELECT id FROM lab_results').all().map((r) => r.id));
    const cutoff = now() - L.keepMs;
    let n = 0;
    for (const id of files.ids()) {
      if (known.has(id)) continue;
      const m = files.mtime(id);
      if (m !== undefined && m < cutoff) {
        files.remove(id);
        n++;
      }
    }
    return n;
  };
  clearOldOrphans();

  let lastSweep = -Infinity;
  /** Deletes results older than 180 days, at most once a minute unless forced. A forced sweep also clears old orphans. */
  const sweep = (force = false) => {
    const t = now();
    if (!force && t - lastSweep < L.sweepEveryMs) return 0;
    lastSweep = t;
    const old = db.prepare('SELECT id FROM lab_results WHERE created_at < ?').all(t - L.keepMs);
    for (const { id } of old) {
      db.prepare('DELETE FROM lab_results WHERE id = ?').run(id);
      files.remove(id);
    }
    if (force) clearOldOrphans();
    return old.length;
  };

  /** transfer.mjs adds the column; a database without it (tests of this file alone) has no receipts. */
  const hasReceiptColumn = () =>
    !!db.prepare("SELECT 1 FROM pragma_table_info('transfers') WHERE name = 'receipt_attestation_id'").get();
  const transfer = (id) =>
    typeof id === 'string' ? db.prepare('SELECT id, from_holder, claimed_by FROM transfers WHERE id = ?').get(id) : undefined;
  const isSender = (t, holder) => !!holder && asStored(t.from_holder) === storedHolderKey(holder);
  const isClaimant = (t, holder) => !!holder && !!t.claimed_by && asStored(t.claimed_by) === storedHolderKey(holder);
  const listOf = (transferId) =>
    db
      .prepare(
        `SELECT id, size, sha256, attestation_id AS attestationId, created_at AS createdAt,
                replaces, withdrawn_at AS withdrawnAt
         FROM lab_results WHERE transfer_id = ? ORDER BY created_at, id`,
      )
      .all(transferId)
      .map((r) => ({
        id: r.id,
        size: r.size,
        sha256: r.sha256,
        createdAt: r.createdAt,
        expiresAt: r.createdAt + L.keepMs,
        ...(r.attestationId ? { attestationId: r.attestationId } : {}),
        ...(r.replaces ? { replaces: r.replaces } : {}),
        ...(r.withdrawnAt ? { withdrawnAt: r.withdrawnAt } : {}),
      }));

  /**
   * The signature a result names (?attestationId=, 8 Nov 2026). It used to be stored unchecked,
   * so a lab could name anyone's signature on its own result, and the result's tie is what
   * lets a delivery's sender and lab read a private signature (server.js privateReaderFor).
   * Now it must be a stored lab report signature, not withdrawn, about the plant this delivery
   * sent (its source fingerprint), and by this lab's key: the key of the receipt tied to the
   * delivery, or of a receipt it signed for the record its claim made, or of the signatures on
   * its earlier results here. With none of those yet (a first report sent before any receipt,
   * which the site allows), the first signature sets the key, and only with the key's own proof
   * that it chose this delivery (`keyProof`, labKeyProofText). null when it is fine.
   */
  const signatureProblem = (delivery, attestationId, keyProof) => {
    const t = db.prepare('SELECT * FROM transfers WHERE id = ?').get(delivery.id);
    const has = (table) => !!db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?").get(table);
    const row = has('attestations') ? db.prepare('SELECT body, attester_key, created_at FROM attestations WHERE attestation_id = ?').get(attestationId) : undefined;
    if (!row) return { error: 'no such signature: post the lab report signature to /attestations first', code: 404 };
    let a;
    try { a = JSON.parse(row.body); } catch { a = {}; }
    if (a.type !== 'laboratory-report') return { error: 'that signature is not a lab report signature (laboratory-report)', code: 400 };
    if (typeof t.source_fingerprint !== 'string' || a.subjectCommitment !== t.source_fingerprint) {
      return { error: 'that signature is about a different plant, not what this delivery sent', code: 400 };
    }
    if (has('retractions') && db.prepare('SELECT 1 FROM retractions WHERE attestation_id = ?').get(attestationId)) {
      return { error: 'that signature was withdrawn by whoever signed it', code: 409 };
    }
    const keyOf = (id) => (id ? db.prepare('SELECT attester_key FROM attestations WHERE attestation_id = ?').get(id)?.attester_key : undefined);
    const keys = new Set();
    const tied = keyOf(t.receipt_attestation_id);
    if (tied) keys.add(tied);
    if (!keys.size && t.received_record) {
      const rec = db.prepare('SELECT body FROM records WHERE id = ?').get(t.received_record);
      let fp;
      try { fp = rec ? JSON.parse(rec.body).recordFingerprint : undefined; } catch { fp = undefined; }
      if (typeof fp === 'string') {
        for (const r of db.prepare(`SELECT attester_key FROM attestations WHERE subject_commitment = ?
            AND json_extract(body, '$.type') = 'chain-of-custody' AND json_extract(body, '$.documentHash') = ?`).all(t.source_fingerprint, fp)) {
          keys.add(r.attester_key);
        }
      }
    }
    if (!keys.size) {
      for (const r of db.prepare('SELECT attestation_id FROM lab_results WHERE transfer_id = ? AND attestation_id IS NOT NULL').all(t.id)) {
        const k = keyOf(r.attestation_id);
        if (k) keys.add(k);
      }
    }
    if (keys.size && !keys.has(row.attester_key)) {
      return { error: "that signature is not by this lab's key (the key of its receipt or its earlier reports on this delivery)", code: 403 };
    }
    if (!keys.size) {
      // No key on this delivery yet: the first report sets it, and only by its own key's word
      // (12 Nov 2026). Without that, a lab that had claimed its own delivery of the plant, with
      // no receipt or result yet, could tie another lab's report id as its first result (one
      // signed after its claim, before that lab tied it on) and then read that lab's report
      // with its name. Only whoever holds the signing key can sign this delivery's id.
      if (!keyProofHolds(row.attester_key, keyProof, t.id, attestationId)) {
        return {
          error: "this delivery has no receipt yet, so the report's key must prove it is this lab's: send x-lab-key-proof (the key's signature over this delivery and signature), or sign the receipt first",
          code: 403,
        };
      }
      // No key on this delivery yet: the first report sets it (9 Nov 2026). It used to be any
      // report about the plant, so a lab that claimed another delivery of the same plant could
      // tie a leaked id of another lab's report as its first, and then read that lab's
      // signatures on the plant. Now the signature must have been stored after this delivery
      // was claimed, and its key must not be another delivery's lab key on this plant.
      if (!Number.isFinite(t.claimed_at) || !(row.created_at >= t.claimed_at)) {
        return { error: 'that signature was made before this delivery was received; sign the report again', code: 403 };
      }
      const others = db.prepare(`SELECT id, claimed_by, received_record, receipt_attestation_id FROM transfers
        WHERE source_fingerprint = ? AND id != ? AND claimed_by IS NOT NULL`).all(t.source_fingerprint, t.id)
        .filter((o) => asStored(o.claimed_by) !== asStored(t.claimed_by));
      const theirKey = (o) => {
        const ks = new Set();
        const k = keyOf(o.receipt_attestation_id);
        if (k) ks.add(k);
        for (const r of db.prepare('SELECT attestation_id FROM lab_results WHERE transfer_id = ? AND attestation_id IS NOT NULL').all(o.id)) {
          const rk = keyOf(r.attestation_id);
          if (rk) ks.add(rk);
        }
        const rec = o.received_record ? db.prepare('SELECT body FROM records WHERE id = ?').get(o.received_record) : undefined;
        let fp;
        try { fp = rec ? JSON.parse(rec.body).recordFingerprint : undefined; } catch { fp = undefined; }
        if (typeof fp === 'string') {
          for (const r of db.prepare(`SELECT attester_key FROM attestations WHERE subject_commitment = ?
              AND json_extract(body, '$.type') = 'chain-of-custody' AND json_extract(body, '$.documentHash') = ?`).all(t.source_fingerprint, fp)) {
            ks.add(r.attester_key);
          }
        }
        return ks;
      };
      if (others.some((o) => theirKey(o).has(row.attester_key))) {
        return { error: "that signature is by another delivery's lab key", code: 403 };
      }
    }
    return null;
  };

  return {
    sweep: () => sweep(true),

    /** The lab adds a locked result to a delivery it claimed. `replaces`: a result on the same delivery it corrects. */
    add({ transferId, holder, bytes, attestationId, replaces, keyProof }) {
      sweep();
      const t = transfer(transferId);
      if (!t) return { error: 'no such delivery', code: 404 };
      if (!t.claimed_by) return { error: 'this delivery has not been received yet', code: 409 };
      if (!isClaimant(t, holder)) return { error: 'only whoever received this delivery can send its results', code: 403 };
      if (!Buffer.isBuffer(bytes) || bytes.length === 0) return { error: 'no file was sent', code: 400 };
      if (bytes.length > L.maxBytes) return { error: 'the file is over 15 MB', code: 413 };
      if (!bytes.subarray(0, AGE_HEADER.length).equals(AGE_HEADER)) {
        return { error: 'only locked (age) files are accepted, never a readable report', code: 400 };
      }
      if (attestationId !== undefined && attestationId !== '' && !ATTESTATION_ID.test(String(attestationId))) {
        return { error: 'attestationId is not valid', code: 400 };
      }
      if (attestationId !== undefined && attestationId !== '') {
        const bad = signatureProblem(t, String(attestationId), keyProof);
        if (bad) return bad;
      }
      if (replaces !== undefined && replaces !== '') {
        const r = RESULT_ID.test(String(replaces))
          ? db.prepare('SELECT withdrawn_at FROM lab_results WHERE id = ? AND transfer_id = ?').get(String(replaces), t.id)
          : undefined;
        if (!r) return { error: 'replaces must name a result on this delivery', code: 400 };
        // A withdrawn result has nothing left to correct (round 3); a new result after a
        // withdrawal is sent on its own.
        if (r.withdrawn_at) return { error: 'that result was withdrawn; send the new one without replaces', code: 400 };
      }
      const counts = db
        .prepare('SELECT COUNT(*) AS rows, COUNT(*) FILTER (WHERE withdrawn_at IS NULL) AS live FROM lab_results WHERE transfer_id = ?')
        .get(t.id);
      if (counts.live >= L.perTransfer || counts.rows >= L.rowsPerTransfer) {
        return { error: 'this delivery has all the results it can take', code: 409 };
      }
      const receiver = asStored(t.claimed_by);
      const today = db
        .prepare('SELECT COUNT(*) AS n, COALESCE(SUM(size), 0) AS bytes FROM lab_results WHERE receiver = ? AND created_at > ?')
        .get(receiver, now() - DAY);
      if (today.n >= L.perReceiverDailyCount || today.bytes + bytes.length > L.perReceiverDailyBytes) {
        return { error: 'this lab has sent as many results as it can today; try again tomorrow', code: 429 };
      }
      const stored = db.prepare('SELECT COALESCE(SUM(size), 0) AS bytes FROM lab_results WHERE withdrawn_at IS NULL').get().bytes;
      if (stored + bytes.length > L.maxTotalBytes) return { error: 'storage full', code: 507 };
      // Per sender, and the reserve for small senders (round 3, see the top of this file).
      // The sender is the holder who made the delivery; a row from older code may still
      // hold their key in plain text, so both forms are counted.
      const senderLive = db
        .prepare(`SELECT COALESCE(SUM(r.size), 0) AS bytes FROM lab_results r JOIN transfers t ON t.id = r.transfer_id
                  WHERE t.from_holder IN (?, ?) AND r.withdrawn_at IS NULL`)
        .get(t.from_holder, asStored(t.from_holder)).bytes;
      if (senderLive + bytes.length > L.perSenderBytes) {
        return {
          error: `the deliveries this breeder sent already hold ${Math.round(L.perSenderBytes / (1024 * 1024))} MB of lab reports, the most kept for one breeder; they can delete old ones to make room`,
          code: 507,
        };
      }
      if (stored + bytes.length > L.maxTotalBytes * (1 - L.reserveShare) && senderLive + bytes.length > L.reserveSenderBytes) {
        return { error: 'storage full', code: 507 };
      }

      const id = `LR-${randomHex(16)}`;
      const sha256 = createHash('sha256').update(bytes).digest('hex');
      // The file first: a row never points at a file that was not written. If the row then
      // fails, the file goes too.
      files.put(id, bytes);
      try {
        db.prepare(
          `INSERT INTO lab_results (id, transfer_id, size, sha256, attestation_id, created_at, receiver, replaces)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        ).run(id, t.id, bytes.length, sha256, attestationId || null, now(), receiver, replaces || null);
      } catch (e) {
        files.remove(id);
        throw e;
      }
      return { id, sha256, size: bytes.length };
    },

    /** The results on a delivery, without the files: for its sender or its receiver. */
    list({ transferId, holder }) {
      sweep();
      const t = transfer(transferId);
      if (!t) return { error: 'no such delivery', code: 404 };
      const sender = isSender(t, holder);
      if (!sender && !isClaimant(t, holder)) {
        return { error: 'only the sender or the receiver of this delivery can see its results', code: 403 };
      }
      // The sender also gets the record the lab's claim created, so their page can check
      // that the lab key that signed a report also signed receipt of THIS delivery.
      const received = sender ? db.prepare('SELECT received_record FROM transfers WHERE id = ?').get(t.id)?.received_record : null;
      // And the lab's signed receipt, when it attached one (transfer.mjs attachReceipt).
      const receipt = sender && hasReceiptColumn()
        ? db.prepare('SELECT receipt_attestation_id FROM transfers WHERE id = ?').get(t.id)?.receipt_attestation_id
        : null;
      return {
        results: listOf(t.id),
        ...(received ? { receivedRecord: received } : {}),
        ...(receipt ? { receiptAttestationId: receipt } : {}),
      };
    },

    /** One locked file, for the sender only. */
    file({ transferId, resultId, holder }) {
      const t = transfer(transferId);
      if (!t || !RESULT_ID.test(String(resultId))) return { error: 'no such result', code: 404 };
      if (!isSender(t, holder)) return { error: 'only the sender of this delivery can download its results', code: 403 };
      const r = db
        .prepare('SELECT withdrawn_at, created_at FROM lab_results WHERE id = ? AND transfer_id = ?')
        .get(resultId, t.id);
      if (!r || now() - r.created_at > L.keepMs) return { error: 'no such result', code: 404 };
      if (r.withdrawn_at) return { error: 'the lab withdrew this result', code: 410 };
      const bytes = files.get(resultId);
      if (!bytes) return { error: 'this result is no longer stored here; ask the lab to send it again', code: 410 };
      return { bytes };
    },

    /**
     * Remove a result. The sender's delete removes it entirely. The receiver's (the lab's)
     * is a withdrawal: the file goes, and the line stays with the time it was withdrawn.
     */
    remove({ transferId, resultId, holder }) {
      const t = transfer(transferId);
      if (!t || !RESULT_ID.test(String(resultId))) return { error: 'no such result', code: 404 };
      const sender = isSender(t, holder);
      if (!sender && !isClaimant(t, holder)) {
        return { error: 'only the sender or the receiver of this delivery can remove its results', code: 403 };
      }
      const r = db.prepare('SELECT withdrawn_at FROM lab_results WHERE id = ? AND transfer_id = ?').get(resultId, t.id);
      if (!r) return { error: 'no such result', code: 404 };
      if (sender) {
        db.prepare('DELETE FROM lab_results WHERE id = ?').run(resultId);
        files.remove(resultId);
        return { ok: true };
      }
      if (!r.withdrawn_at) db.prepare('UPDATE lab_results SET withdrawn_at = ? WHERE id = ?').run(now(), resultId);
      files.remove(resultId);
      return { ok: true, withdrawn: true };
    },
  };
};
