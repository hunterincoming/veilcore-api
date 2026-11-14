// "Prove you hold it" without copying codes back and forth.
//
// Before: the checker made a challenge on the record's page, copied it to the holder, the
// holder answered on chain and copied a transaction id back, and the checker pasted it.
// Now the registry carries both messages: the checker posts the challenge, the holder opens
// a link, taps once, and the answer's transaction id comes back to the checker's page.
//
// The registry is a mailbox and is never believed:
//   - the challenge is made in the checker's browser and kept there; the checker's page
//     only accepts an answer to a challenge it made itself (ownership-check.ts);
//   - the answer is a transaction id, and the checker's page reads the transaction from the
//     network: it must be a proveOwnership call, answer that challenge, from that identity.
// A registry that dropped, swapped or invented messages could only make a check fail, never
// pass. So nothing here needs a holder key, and the app sends none: a holder key would let
// the registry join a holder to their on-chain identity, which record-keys.ts keeps apart.
//
// Who may answer (round 2). Knowing the request id used to be enough to answer, so anyone
// who saw an id could fill its answer slots with junk and the real answer was turned away.
// Now the checker's browser makes a random answer token, sends the registry only its
// SHA-256, and puts the token itself in the link's fragment (/prove/PR-…#t=…), which
// browsers never send to a server. An answer is taken only with the token. The id alone
// still reads the request: the holder's page needs that, and it says nothing secret.
//
// Ids and tokens are 128 random bits. Requests expire after 7 days. Each answer keeps the
// time it came in (answeredAt): the checker's page gives a transaction the network doesn't
// know yet 15 minutes to appear, then refuses it.
//
// SPDX-License-Identifier: Apache-2.0

import { cleanText } from './clean-text.mjs';
import { createHash, timingSafeEqual } from 'node:crypto';

export const PROVE_LIMITS = {
  ttlMs: 7 * 86_400_000,
  maxAnswers: 5,
  askerMax: 80,
  /** Requests alive at once. Past this, asking is refused until old ones expire. */
  maxLive: 50_000,
  /**
   * Requests one client address (server.js's bucket: IPv4 address, IPv6 /64) may make in a
   * UTC day. Without it one address filled all 50,000 in about seven minutes at the write
   * rate limit, and nobody could ask for a week. Counted in memory only: the registry does
   * not store addresses.
   */
  perClientDaily: 100,
  /** Expired requests are deleted at most this often. */
  sweepEveryMs: 60_000,
};

const HEX64 = /^[0-9a-f]{64}$/;
const ID = /^PR-[0-9A-F]{32}$/;
/** 16 bytes as base64url, no padding. */
const TOKEN = /^[A-Za-z0-9_-]{22}$/;

const randomHex = (bytes) =>
  [...crypto.getRandomValues(new Uint8Array(bytes))].map((b) => b.toString(16).padStart(2, '0')).join('');

/** What the link's token is checked against: SHA-256 of the token's text, as hex. */
export const tokenHash = (token) => createHash('sha256').update(String(token), 'utf8').digest('hex');

/** The asker's name, cleaned to plain text (clean-text.mjs): at most PROVE_LIMITS.askerMax characters. */
export const cleanAsker = (v) => cleanText(v, PROVE_LIMITS.askerMax);

const sameHash = (a, b) => {
  const x = Buffer.from(String(a), 'hex');
  const y = Buffer.from(String(b), 'hex');
  return x.length === 32 && y.length === 32 && timingSafeEqual(x, y);
};

export const createProveRequests = (db, { now = () => Date.now(), limits = {} } = {}) => {
  const L = { ...PROVE_LIMITS, ...limits };
  db.exec(`
    CREATE TABLE IF NOT EXISTS prove_requests (
      id         TEXT PRIMARY KEY,
      identity   TEXT NOT NULL,
      challenge  TEXT NOT NULL,
      asker      TEXT NOT NULL DEFAULT '',
      created_at INTEGER NOT NULL,
      answers    TEXT NOT NULL DEFAULT '[]'
    )
  `);
  // A table made before answer tokens: the column is added, and its rows (which have no
  // token) can be read but never answered. None exist outside development.
  if (!db.prepare("SELECT 1 FROM pragma_table_info('prove_requests') WHERE name = 'answer_token_hash'").get()) {
    db.exec('ALTER TABLE prove_requests ADD COLUMN answer_token_hash TEXT');
  }
  db.exec('CREATE INDEX IF NOT EXISTS prove_requests_created ON prove_requests(created_at)');

  /** client -> { day, n }. Bounded: past maxTrackedClients, other days' entries go, then the oldest. */
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
    db.prepare('DELETE FROM prove_requests WHERE created_at < ?').run(t - L.ttlMs);
  };
  const liveCount = () =>
    db.prepare('SELECT COUNT(*) AS n FROM prove_requests WHERE created_at >= ?').get(now() - L.ttlMs).n;
  const row = (id) =>
    ID.test(String(id)) ? db.prepare('SELECT * FROM prove_requests WHERE id = ?').get(String(id)) : undefined;
  const live = (r) => r && now() - r.created_at <= L.ttlMs;
  /** Answers as stored: { txId, answeredAt }. Rows from before answeredAt held bare ids. */
  const answersOf = (r) =>
    JSON.parse(r.answers).map((a) => (typeof a === 'string' ? { txId: a, answeredAt: r.created_at } : a));
  const view = (r) => ({
    id: r.id,
    identity: r.identity,
    challenge: r.challenge,
    asker: r.asker,
    createdAt: r.created_at,
    expiresAt: r.created_at + L.ttlMs,
    answers: answersOf(r),
  });

  return {
    /**
     * The checker asks. `answerTokenHash` is the SHA-256 (hex) of the token in the link's
     * fragment. `client` is the asking address's rate-limit bucket (server.js); omitted, no
     * per-address count is kept. Returns the request's id, which goes in the holder's link.
     */
    ask({ identity, challenge, asker, answerTokenHash } = {}, client) {
      const i = String(identity ?? '').toLowerCase();
      const c = String(challenge ?? '').toLowerCase();
      const h = String(answerTokenHash ?? '').toLowerCase();
      if (!HEX64.test(i)) return { error: 'identity must be 64 hex characters', code: 400 };
      if (!HEX64.test(c)) return { error: 'challenge must be 64 hex characters', code: 400 };
      if (!HEX64.test(h)) return { error: 'answerTokenHash must be 64 hex characters', code: 400 };
      const a = cleanAsker(asker);
      if (a === null) return { error: `asker must be text of at most ${L.askerMax} characters`, code: 400 };
      sweep();
      if (client !== undefined && countAsk(String(client)) > L.perClientDaily) {
        return { error: 'too many requests from this address today; try again tomorrow', code: 429 };
      }
      if (liveCount() >= L.maxLive) return { error: 'busy, try later', code: 503 };
      const id = `PR-${randomHex(16).toUpperCase()}`;
      const t = now();
      db.prepare(
        'INSERT INTO prove_requests (id, identity, challenge, asker, created_at, answer_token_hash) VALUES (?, ?, ?, ?, ?, ?)',
      ).run(id, i, c, a, t, h);
      return { id, expiresAt: t + L.ttlMs };
    },

    /** Read a request: the holder's page shows it, the checker's page polls it for answers. */
    get(id) {
      const r = row(id);
      return live(r) ? view(r) : null;
    },

    /**
     * The holder's answer: the id of the proveOwnership transaction, with the token from
     * the link. The transaction is checked by the checker, not here.
     */
    answer(id, txId, token) {
      const r = row(id);
      if (!live(r)) return { error: 'no such request, or it has expired', code: 404 };
      if (
        typeof token !== 'string' ||
        !TOKEN.test(token) ||
        !r.answer_token_hash ||
        !sameHash(tokenHash(token), r.answer_token_hash)
      ) {
        return { error: 'this answer needs the whole link it was sent with; open the link again exactly as you got it', code: 403 };
      }
      const t = String(txId ?? '').toLowerCase().replace(/^0x/, '');
      if (!HEX64.test(t)) return { error: 'txId must be 64 hex characters', code: 400 };
      const answers = answersOf(r);
      if (answers.some((a) => a.txId === t)) return { ok: true, answers: answers.length };
      if (answers.length >= L.maxAnswers) return { error: 'this request has all the answers it can take', code: 409 };
      answers.push({ txId: t, answeredAt: now() });
      db.prepare('UPDATE prove_requests SET answers = ? WHERE id = ?').run(JSON.stringify(answers), r.id);
      return { ok: true, answers: answers.length };
    },
  };
};
