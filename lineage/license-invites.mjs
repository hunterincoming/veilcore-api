// A real two-party license without copying codes back and forth.
//
// On chain a license takes three calls by two people (contract veilcore.compact):
//   1. the LICENSEE makes a license secret and, from it, a license commitment against the
//      issuer's record (licenseCommit(secret, issuerHead)); the secret never leaves them;
//   2. the ISSUER sends issueLicense(commitment): the license is PENDING;
//   3. the LICENSEE sends countersignLicense, proving the secret: the license is ACTIVE.
// This mailbox carries the messages between their browsers: the commitment from the licensee
// to the issuer, then each side's transaction id to the other.
//
// The registry is a mailbox and is never believed, as with prove requests:
//   - the commitment is no secret (issueLicense publishes it), but this mailbox could swap it
//     for one of its own. So both people read each other a 6-digit code before the issuer
//     issues, made with a commit-then-reveal exchange (the short authentication string of
//     ZRTP and Bluetooth pairing): the licensee first posts only a HASH of its commitment and
//     a random nonce; the issuer then posts its own random nonce; only then does the licensee
//     reveal. The code is made from all of it. A mailbox that swapped the commitment had to
//     fix its own before seeing the issuer's nonce, and give the licensee a nonce before
//     seeing the licensee's, so it can't steer the two codes to match: one guess in a million,
//     with a person checking each try. A short code alone was not enough: the mailbox sees the
//     real commitment first and could grind its own to match the first 8 characters
//     (re-attack, 20 Oct). The issuer also checks the commitment names its own head;
//   - every transaction id is read from the network by the page that receives it: it must be
//     the right call, on VeilCore's contract, for this license.
// A registry that dropped, swapped or invented messages could only stall a license, never
// make one. Nothing here needs a holder key, and the app sends none.
//
// Who may write what. The issuer's browser makes two random tokens and gives the registry
// only their SHA-256: the ACCEPT token travels in the licensee's link fragment
// (/license/LI-…#t=…), which browsers never send to a server, and lets the licensee post the
// commitment and the activation; the ISSUER token stays with the issuer and lets them post
// the issue. Knowing an invite id is enough to read it (the licensee's page needs that, and
// nothing in it is secret) but never to write.
//
// Each step is taken once: a second, different commitment or transaction id is refused, so
// whoever holds the link first cannot be replaced by someone who saw it later. The label is
// the issuer's own words for the licensee (shown to them), cleaned like a prove request's
// asker. Ids and tokens are 128 random bits. Invites expire after 30 days.
//
// SPDX-License-Identifier: Apache-2.0

import { createHash, timingSafeEqual } from 'node:crypto';
import { cleanText } from './clean-text.mjs';

export const INVITE_LIMITS = {
  ttlMs: 30 * 86_400_000,
  labelMax: 80,
  /** Invites alive at once. Past this, inviting is refused until old ones expire. */
  maxLive: 50_000,
  /**
   * Invites one client may make in a UTC day; counted in memory only. An IPv6 client is
   * counted by its /48, not the /64 server.js buckets by: one cheap /48 holds 65,536 /64s,
   * which filled the whole table in an afternoon (attack round, 20 Oct).
   */
  perClientDaily: 50,
  /**
   * Invites one client may make for one record in a UTC day. Not a cap per record: a record's
   * on-chain identity is public, and a cap per record let anyone fill it and lock the owner out
   * (re-attack, 20 Oct). In memory only, like the daily count.
   */
  perClientPerIdentityDaily: 10,
  sweepEveryMs: 60_000,
};

const HEX64 = /^[0-9a-f]{64}$/;
const ID = /^LI-[0-9A-F]{32}$/;
/** 16 bytes as base64url, no padding. */
const TOKEN = /^[A-Za-z0-9_-]{22}$/;

const randomHex = (bytes) =>
  [...crypto.getRandomValues(new Uint8Array(bytes))].map((b) => b.toString(16).padStart(2, '0')).join('');

/** What a link's token is checked against: SHA-256 of the token's text, as hex. */
export const inviteTokenHash = (token) => createHash('sha256').update(String(token), 'utf8').digest('hex');

const sameHash = (a, b) => {
  const x = Buffer.from(String(a), 'hex');
  const y = Buffer.from(String(b), 'hex');
  return x.length === 32 && y.length === 32 && timingSafeEqual(x, y);
};

const hex64 = (v) => String(v ?? '').toLowerCase().replace(/^0x/, '');

/** What the licensee commits to first: SHA-256 of commitment, issuer record and nonce (raw bytes), hex. */
export const commitHashOf = (commitment, issuerRecord, licenseeNonce) =>
  createHash('sha256')
    .update(Buffer.from(`${commitment}${issuerRecord}${licenseeNonce}`, 'hex'))
    .digest('hex');

/** server.js's bucket, widened for IPv6 from its /64 to the /48 it sits in (an IPv4 address stays as it is). */
export const wider = (bucket) => {
  const m = /^([0-9a-f]{0,4}):([0-9a-f]{0,4}):([0-9a-f]{0,4}):[0-9a-f]{0,4}::\/64$/i.exec(bucket);
  return m ? `${m[1]}:${m[2]}:${m[3]}::/48` : bucket;
};

export const createLicenseInvites = (db, { now = () => Date.now(), limits = {} } = {}) => {
  const L = { ...INVITE_LIMITS, ...limits };
  db.exec(`
    CREATE TABLE IF NOT EXISTS license_invites (
      id                 TEXT PRIMARY KEY,
      identity           TEXT NOT NULL,
      label              TEXT NOT NULL DEFAULT '',
      created_at         INTEGER NOT NULL,
      accept_token_hash  TEXT NOT NULL,
      issuer_token_hash  TEXT NOT NULL,
      commit_hash        TEXT,
      accepted_at        INTEGER,
      issuer_nonce       TEXT,
      nonce_at           INTEGER,
      commitment         TEXT,
      issuer_record      TEXT,
      licensee_nonce     TEXT,
      revealed_at        INTEGER,
      issue_tx           TEXT,
      issued_at          INTEGER,
      activate_tx        TEXT,
      activated_at       INTEGER
    )
  `);
  db.exec('CREATE INDEX IF NOT EXISTS license_invites_created ON license_invites(created_at)');

  const asks = new Map();
  const maxTrackedClients = 50_000;
  const countAsk = (client) => {
    const day = Math.floor(now() / 86_400_000);
    const prev = asks.get(client);
    const n = (prev && prev.day === day ? prev.n : 0) + 1;
    asks.delete(client);
    asks.set(client, { day, n });
    if (asks.size > maxTrackedClients) {
      for (const [k, v] of asks) if (v.day !== day) asks.delete(k);
      for (const k of asks.keys()) {
        if (asks.size <= maxTrackedClients) break;
        asks.delete(k);
      }
    }
    return n;
  };

  let lastSweep = -Infinity;
  const sweep = () => {
    const t = now();
    if (t - lastSweep < L.sweepEveryMs) return;
    lastSweep = t;
    db.prepare('DELETE FROM license_invites WHERE created_at < ?').run(t - L.ttlMs);
  };
  const liveCount = () =>
    db.prepare('SELECT COUNT(*) AS n FROM license_invites WHERE created_at >= ?').get(now() - L.ttlMs).n;
  const row = (id) =>
    ID.test(String(id)) ? db.prepare('SELECT * FROM license_invites WHERE id = ?').get(String(id)) : undefined;
  const live = (r) => r && now() - r.created_at <= L.ttlMs;
  const tokenOk = (token, hash) => typeof token === 'string' && TOKEN.test(token) && sameHash(inviteTokenHash(token), hash);
  const view = (r) => ({
    id: r.id,
    identity: r.identity,
    label: r.label,
    createdAt: r.created_at,
    expiresAt: r.created_at + L.ttlMs,
    commitHash: r.commit_hash ?? null,
    acceptedAt: r.accepted_at ?? null,
    issuerNonce: r.issuer_nonce ?? null,
    commitment: r.commitment ?? null,
    issuerRecord: r.issuer_record ?? null,
    licenseeNonce: r.licensee_nonce ?? null,
    revealedAt: r.revealed_at ?? null,
    issueTx: r.issue_tx ?? null,
    issuedAt: r.issued_at ?? null,
    activateTx: r.activate_tx ?? null,
    activatedAt: r.activated_at ?? null,
  });
  const LINK_REFUSED = {
    error: 'this needs the whole link it was sent with; open the link again exactly as you got it',
    code: 403,
  };
  const GONE = { error: 'no such invite, or it has expired', code: 404 };

  return {
    /**
     * The issuer invites. `identity` is the issuer record's on-chain identity (its origin);
     * the two hashes are SHA-256 (hex) of the accept and issuer tokens. Returns the id.
     */
    invite({ identity, label, acceptTokenHash, issuerTokenHash } = {}, client) {
      const i = hex64(identity);
      const a = hex64(acceptTokenHash);
      const s = hex64(issuerTokenHash);
      if (!HEX64.test(i)) return { error: 'identity must be 64 hex characters', code: 400 };
      if (!HEX64.test(a)) return { error: 'acceptTokenHash must be 64 hex characters', code: 400 };
      if (!HEX64.test(s)) return { error: 'issuerTokenHash must be 64 hex characters', code: 400 };
      if (a === s) return { error: 'the accept and issuer tokens must differ', code: 400 };
      const l = cleanText(label, L.labelMax);
      if (l === null || [...l].length > L.labelMax) {
        return { error: `label must be text of at most ${L.labelMax} characters`, code: 400 };
      }
      sweep();
      if (client !== undefined && countAsk(wider(String(client))) > L.perClientDaily) {
        return { error: 'too many invites from this address today; try again tomorrow', code: 429 };
      }
      if (client !== undefined && countAsk(`${wider(String(client))} ${i}`) > L.perClientPerIdentityDaily) {
        return { error: 'too many invites for this record from this address today; try again tomorrow', code: 429 };
      }
      if (liveCount() >= L.maxLive) return { error: 'busy, try later', code: 503 };
      const id = `LI-${randomHex(16).toUpperCase()}`;
      const t = now();
      db.prepare(
        `INSERT INTO license_invites (id, identity, label, created_at, accept_token_hash, issuer_token_hash)
         VALUES (?, ?, ?, ?, ?, ?)`,
      ).run(id, i, l, t, a, s);
      return { id, expiresAt: t + L.ttlMs };
    },

    /** Read an invite: both pages show it and poll it for the other side's step. */
    /**
     * Whether `token` is one of this live invite's two tokens, and the licensee has revealed:
     * what opening its deal channel needs (deals.mjs), so a stranger can't open channels.
     */
    revealedFor(id, token, { issuerOnly = false } = {}) {
      const r = row(id);
      if (!live(r) || !r.commitment) return false;
      return tokenOk(token, r.issuer_token_hash) || (!issuerOnly && tokenOk(token, r.accept_token_hash));
    },

    get(id) {
      const r = row(id);
      return live(r) ? view(r) : null;
    },

    /**
     * The licensee accepts, committing first: `commitHash` is SHA-256 of its commitment,
     * issuer record and nonce (license-invites.ts commitHashOf), with the accept token. Once:
     * the same hash again is fine (a retried send), a different one is refused.
     */
    accept(id, { commitHash, token } = {}) {
      const r = row(id);
      if (!live(r)) return GONE;
      if (!tokenOk(token, r.accept_token_hash)) return LINK_REFUSED;
      const h = hex64(commitHash);
      if (!HEX64.test(h)) return { error: 'commitHash must be 64 hex characters', code: 400 };
      if (r.commit_hash) return r.commit_hash === h ? { ok: true } : { error: 'this invite was already accepted', code: 409 };
      db.prepare('UPDATE license_invites SET commit_hash = ?, accepted_at = ? WHERE id = ?').run(h, now(), r.id);
      return { ok: true };
    },

    /** The issuer's random nonce, with the issuer token, after the licensee committed. Once. */
    nonce(id, { issuerNonce, token } = {}) {
      const r = row(id);
      if (!live(r)) return GONE;
      if (!tokenOk(token, r.issuer_token_hash)) return LINK_REFUSED;
      if (!r.commit_hash) return { error: 'the licensee has not accepted yet', code: 409 };
      const n = hex64(issuerNonce);
      if (!HEX64.test(n)) return { error: 'issuerNonce must be 64 hex characters', code: 400 };
      if (r.issuer_nonce) return r.issuer_nonce === n ? { ok: true } : { error: 'this invite already has a nonce', code: 409 };
      db.prepare('UPDATE license_invites SET issuer_nonce = ?, nonce_at = ? WHERE id = ?').run(n, now(), r.id);
      return { ok: true };
    },

    /**
     * The licensee reveals what it committed to, with the accept token, after the issuer's
     * nonce: the commitment, the issuer record it names and its nonce. Refused unless they
     * hash to the commitHash it posted (the issuer's page checks the same). Once.
     */
    reveal(id, { commitment, issuerRecord, licenseeNonce, token } = {}) {
      const r = row(id);
      if (!live(r)) return GONE;
      if (!tokenOk(token, r.accept_token_hash)) return LINK_REFUSED;
      if (!r.issuer_nonce) return { error: 'the issuer has not answered yet', code: 409 };
      const c = hex64(commitment);
      const h = hex64(issuerRecord);
      const n = hex64(licenseeNonce);
      if (![c, h, n].every((x) => HEX64.test(x))) {
        return { error: 'commitment, issuerRecord and licenseeNonce must be 64 hex characters each', code: 400 };
      }
      if (commitHashOf(c, h, n) !== r.commit_hash) return { error: 'that is not what this invite was accepted with', code: 409 };
      if (r.commitment) return { ok: true };
      db.prepare(
        'UPDATE license_invites SET commitment = ?, issuer_record = ?, licensee_nonce = ?, revealed_at = ? WHERE id = ?',
      ).run(c, h, n, now(), r.id);
      return { ok: true };
    },

    /** The issuer's issueLicense transaction id, with the issuer token. After an accept, once. */
    issued(id, { txId, token } = {}) {
      const r = row(id);
      if (!live(r)) return GONE;
      if (!tokenOk(token, r.issuer_token_hash)) return LINK_REFUSED;
      if (!r.commitment) return { error: 'the licensee has not revealed yet', code: 409 };
      const t = hex64(txId);
      if (!HEX64.test(t)) return { error: 'txId must be 64 hex characters', code: 400 };
      if (r.issue_tx) return r.issue_tx === t ? { ok: true } : { error: 'this invite was already issued', code: 409 };
      db.prepare('UPDATE license_invites SET issue_tx = ?, issued_at = ? WHERE id = ?').run(t, now(), r.id);
      return { ok: true };
    },

    /** The licensee's countersignLicense transaction id, with the accept token. After an issue, once. */
    activated(id, { txId, token } = {}) {
      const r = row(id);
      if (!live(r)) return GONE;
      if (!tokenOk(token, r.accept_token_hash)) return LINK_REFUSED;
      if (!r.issue_tx) return { error: 'the issuer has not issued it yet', code: 409 };
      const t = hex64(txId);
      if (!HEX64.test(t)) return { error: 'txId must be 64 hex characters', code: 400 };
      if (r.activate_tx) {
        return r.activate_tx === t ? { ok: true } : { error: 'this invite was already activated', code: 409 };
      }
      db.prepare('UPDATE license_invites SET activate_tx = ?, activated_at = ? WHERE id = ?').run(t, now(), r.id);
      return { ok: true };
    },
  };
};
