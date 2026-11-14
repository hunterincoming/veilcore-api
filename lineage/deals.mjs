// The deal channel: where the two sides of one license leave each other messages.
//
// Royalty statements, acceptances, payment notices and confirmations pass between a
// licensor and a licensee for as long as a license lasts. Their browsers encrypt and sign
// every message (the site's veilcore/deal.ts) with keys only the two of them hold: the
// keys whose public halves went into the 6-digit code they read to each other. So this is
// a mailbox that cannot read, forge or alter what it carries:
//   - the channel's id and its write token are derived from the two parties' shared
//     secret; the registry learns the id and only the SHA-256 of the token;
//   - a message is an IV and an AES-GCM ciphertext, at most 16 KB;
//   - each message's fingerprint (SHA-256 of "iv.ct") joins the next batch, so the hourly
//     anchor dates it on Midnight. Neither side can later claim a statement was sent at
//     another time, and the registry cannot quietly remove one without the batch proof
//     disagreeing.
//
// What the registry can still do is drop, delay or replay messages, or withhold a newer one
// (an issuer's changed payout account, say). Pages order messages by their signed time and
// count a replayed copy once; a side that downloads the deal's signed record can show what
// it holds against the batch proofs.
//
// Opening a channel needs the issuer's token for a license invite whose licensee has revealed
// (license-invites.mjs), and one invite opens one channel (review round 3, H2, N2). The two
// sides' deal keys (the invite's issuer and licensee nonces: the public halves both people
// checked with the 6-digit code) are copied onto the channel when it opens, because the invite
// itself expires after 30 days. They let the registry check a side's signed word about its own
// deal without reading the deal: the licensor's license notices and the licensee's registration
// and answers (server.js, license notices). A channel
// nobody wrote to within a week is deleted. Messages are kept as long as the deal lasts.
// Limits per client and per deal keep growth slow; there is deliberately no total cap, which an
// attacker could fill to stop every honest license (review round 3, N1): the operator watches
// the database's size instead.
//
// SPDX-License-Identifier: Apache-2.0

import { createHash, timingSafeEqual } from 'node:crypto';
import { wider } from './license-invites.mjs';

export const DEAL_LIMITS = {
  /** Messages in one deal: years of monthly statements with every reply, and room to spare. */
  maxMessages: 2_000,
  /** Base64url characters of ciphertext: 16 KB of message. */
  maxCt: 22_000,
  /** New deals one client (an IPv6 client by its /48) may open in a UTC day. */
  perClientDaily: 50,
  /** Messages one client may post in a UTC day, across deals. */
  perClientMessagesDaily: 500,
  /**
   * Messages one client may post to one deal in a UTC day: a month of statements takes a handful.
   * One side filling a deal to its cap, so the other can't answer, now takes 20 client-days
   * instead of four (attack pass 21 Oct, finding 7; the rest is a known limit).
   */
  perClientPerDealDaily: 100,
  /** A channel with no message this long after it was opened is deleted. */
  emptyTtlMs: 7 * 86_400_000,
};

const DEAL_ID = /^[0-9a-f]{32}$/;
const HEX64 = /^[0-9a-f]{64}$/;
/** 16 bytes, base64url, no padding. */
const TOKEN = /^[A-Za-z0-9_-]{22}$/;
const IV = /^[A-Za-z0-9_-]{16}$/;
const B64U = /^[A-Za-z0-9_-]+$/;

export const dealTokenHash = (token) => createHash('sha256').update(String(token), 'utf8').digest('hex');

/** What is dated: SHA-256 of "iv.ct", hex. */
export const messageFingerprint = (iv, ct) => createHash('sha256').update(`${iv}.${ct}`, 'utf8').digest('hex');

const sameHash = (a, b) => {
  const x = Buffer.from(String(a), 'hex');
  const y = Buffer.from(String(b), 'hex');
  return x.length === 32 && y.length === 32 && timingSafeEqual(x, y);
};

export const createDeals = (db, { now = () => Date.now(), limits = {}, invites } = {}) => {
  const L = { ...DEAL_LIMITS, ...limits };
  db.exec(`
    CREATE TABLE IF NOT EXISTS deals (
      deal_id     TEXT PRIMARY KEY,
      write_hash  TEXT NOT NULL,
      invite_id   TEXT UNIQUE,
      created_at  INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS deal_messages (
      deal_id     TEXT NOT NULL,
      seq         INTEGER NOT NULL,
      iv          TEXT NOT NULL,
      ct          TEXT NOT NULL,
      fingerprint TEXT NOT NULL UNIQUE,
      received_at INTEGER NOT NULL,
      PRIMARY KEY (deal_id, seq)
    );
  `);
  // The two sides' deal keys, kept with the channel (above). A database from before has the
  // columns added once, and filled from the invites still on file.
  for (const col of ['issuer_key', 'licensee_key']) {
    if (!db.prepare("SELECT 1 FROM pragma_table_info('deals') WHERE name = ?").get(col)) {
      db.exec(`ALTER TABLE deals ADD COLUMN ${col} TEXT`);
    }
  }
  if (db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'license_invites'").get()) {
    db.exec(`UPDATE deals SET
        issuer_key = (SELECT issuer_nonce FROM license_invites WHERE license_invites.id = deals.invite_id),
        licensee_key = (SELECT licensee_nonce FROM license_invites WHERE license_invites.id = deals.invite_id)
      WHERE licensee_key IS NULL AND invite_id IS NOT NULL`);
  }
  const st = (sql) => db.prepare(sql);
  const counts = new Map();
  let day = '';
  const count = (key) => {
    const today = new Date(now()).toISOString().slice(0, 10);
    if (today !== day) {
      counts.clear();
      day = today;
    }
    const n = (counts.get(key) ?? 0) + 1;
    counts.set(key, n);
    return n;
  };

  let lastSweep = -Infinity;
  /** Channels nobody wrote to within emptyTtlMs: deleted, at most once a minute. */
  const sweep = () => {
    const t = now();
    if (t - lastSweep < 60_000) return;
    lastSweep = t;
    st('DELETE FROM deals WHERE created_at < ? AND deal_id NOT IN (SELECT DISTINCT deal_id FROM deal_messages)').run(t - L.emptyTtlMs);
  };

  const auth = (dealId, token) => {
    if (typeof dealId !== 'string' || !DEAL_ID.test(dealId)) return { error: 'no such deal', code: 404 };
    const d = st('SELECT write_hash FROM deals WHERE deal_id = ?').get(dealId);
    if (!d) return { error: 'no such deal', code: 404 };
    if (typeof token !== 'string' || !TOKEN.test(token) || !sameHash(dealTokenHash(token), d.write_hash)) {
      return { error: 'this deal needs its token', code: 403 };
    }
    return { ok: true };
  };

  return {
    /** Open a deal. Opening one that exists with the same token is fine (both sides open it). */
    open(body, client) {
      const { dealId, writeTokenHash, inviteId, token } = body ?? {};
      if (typeof dealId !== 'string' || !DEAL_ID.test(dealId)) return { error: 'dealId must be 32 hex characters' };
      if (typeof writeTokenHash !== 'string' || !HEX64.test(writeTokenHash)) {
        return { error: 'writeTokenHash must be 64 hex characters' };
      }
      const had = st('SELECT write_hash FROM deals WHERE deal_id = ?').get(dealId);
      if (had) {
        return sameHash(had.write_hash, writeTokenHash)
          ? { dealId, opened: false }
          : { error: 'that deal id is taken', code: 409 };
      }
      // A new channel: only by the issuer, with its own token for an invite whose licensee has
      // revealed; one channel per invite. The licensee never opens one (it only reads the one the
      // issuer opened), so whoever else holds the licensee's link can't take the slot first.
      if (!invites || typeof inviteId !== 'string' || !invites.revealedFor(inviteId, token, { issuerOnly: true })) {
        return { error: 'opening a deal needs the license link it belongs to', code: 403 };
      }
      if (st('SELECT 1 FROM deals WHERE invite_id = ?').get(inviteId)) {
        return { error: 'that license already has a deal', code: 409 };
      }
      sweep();
      if (client !== undefined && count(`open ${wider(String(client))}`) > L.perClientDaily) {
        return { error: 'too many new deals from here today; try again tomorrow', code: 429 };
      }
      const keys = invites.get?.(inviteId);
      st('INSERT INTO deals (deal_id, write_hash, invite_id, created_at, issuer_key, licensee_key) VALUES (?,?,?,?,?,?)')
        .run(dealId, writeTokenHash, inviteId, now(), keys?.issuerNonce ?? null, keys?.licenseeNonce ?? null);
      return { dealId, opened: true };
    },

    /** Leave a message. Returns its number and fingerprint. The same message twice is one message. */
    post(dealId, body, client) {
      const { token, iv, ct } = body ?? {};
      const a = auth(dealId, token);
      if (a.error) return a;
      if (typeof iv !== 'string' || !IV.test(iv)) return { error: 'iv must be 12 bytes, base64url' };
      if (typeof ct !== 'string' || !B64U.test(ct) || ct.length < 24 || ct.length > L.maxCt) {
        return { error: `ct must be base64url, at most ${L.maxCt} characters` };
      }
      const fingerprint = messageFingerprint(iv, ct);
      const same = st('SELECT deal_id, seq, received_at FROM deal_messages WHERE fingerprint = ?').get(fingerprint);
      if (same && same.deal_id !== dealId) return { error: 'that message belongs to another deal', code: 409 };
      if (same) return { seq: same.seq, fingerprint, receivedAt: same.received_at, duplicate: true };
      if (client !== undefined) {
        const bucket = wider(String(client));
        if (count(`post ${bucket}`) > L.perClientMessagesDaily || count(`deal ${dealId} ${bucket}`) > L.perClientPerDealDaily) {
          return { error: 'too many messages from here today; try again tomorrow', code: 429 };
        }
      }
      return db.transaction(() => {
        const n = st('SELECT COUNT(*) AS n, COALESCE(MAX(seq), 0) AS top FROM deal_messages WHERE deal_id = ?').get(dealId);
        if (n.n >= L.maxMessages) return { error: 'this deal holds the most messages it can', code: 409 };
        const seq = n.top + 1;
        const at = now();
        st('INSERT INTO deal_messages (deal_id, seq, iv, ct, fingerprint, received_at) VALUES (?,?,?,?,?,?)')
          .run(dealId, seq, iv, ct, fingerprint, at);
        return { seq, fingerprint, receivedAt: at };
      })();
    },

    /**
     * The deal holding the message with this fingerprint, with its two sides' keys (null when
     * not on file), or undefined when no deal here holds it.
     */
    partiesOf(fingerprint) {
      if (typeof fingerprint !== 'string' || !HEX64.test(fingerprint)) return undefined;
      const r = st(`SELECT d.deal_id, d.issuer_key, d.licensee_key FROM deal_messages m
        JOIN deals d ON d.deal_id = m.deal_id WHERE m.fingerprint = ?`).get(fingerprint);
      return r ? { dealId: r.deal_id, issuerKey: r.issuer_key ?? null, licenseeKey: r.licensee_key ?? null } : undefined;
    },

    /** Messages after `after`, oldest first, at most 200 at a time. */
    list(dealId, token, after = 0) {
      const a = auth(dealId, token);
      if (a.error) return a;
      const from = Number.isSafeInteger(Number(after)) && Number(after) > 0 ? Number(after) : 0;
      const rows = st(
        'SELECT seq, iv, ct, fingerprint, received_at FROM deal_messages WHERE deal_id = ? AND seq > ? ORDER BY seq LIMIT 200',
      ).all(dealId, from);
      return {
        messages: rows.map((r) => ({ seq: r.seq, iv: r.iv, ct: r.ct, fingerprint: r.fingerprint, receivedAt: r.received_at })),
      };
    },
  };
};
