// The account copy: one locked copy of a person's keys, opened by several ways in.
//
// It replaces one-copy-per-passkey (passkey-vault.mjs, kept for copies made before this and for
// moving them over). The browser makes an account key once (32 random bytes). The copy is
// sealed with it. Each way in (a passkey today; a recovery sheet, a password, or another person
// of a shared space later) is a "slot": the account key, sealed with a key only that way in can
// make. The registry stores the copy and the slots, never a key that opens either.
//
// What the registry holds and learns:
//   - per copy: an id, a write token's SHA-256, one AES-GCM ciphertext (padded to a size bucket
//     in the browser), when it was made and last saved, and its slots;
//   - per slot: an id, which copy it opens, its kind ("passkey" ...), a read token's SHA-256 and
//     the sealed account key. Every id and token comes from a secret in the browser (the
//     account key, or a passkey's PRF output), never from anything that names a person.
//   - which slots open which copy, and when a copy is saved or checked. A save right after a
//     holder's record write, from the same address, lets the registry guess which holder a copy
//     belongs to: the browser waits a random few seconds and saves at most every 30 to 60
//     seconds, which makes that harder, not impossible. The registry is not told, and the docs
//     no longer say it can't tie a copy to a holder.
//
// Two kinds of token (security review S3): a slot's token only reads that slot's sealed
// account key. Everything else (saving, reading or deleting the copy, adding or removing a
// slot) needs the copy's own write token, which only the account key makes. So the token of a
// way in that leaks (a phished password, later) can't delete or replace anything.
//
// What it can still do is withhold the copy, serve an older one it kept, or drop a slot. The
// copy carries its own counter and date inside the sealed part, and its own list of slots (the
// browser compares it with what the registry answers); the browser refuses an older copy and
// shows the date before a restore.
//
// SPDX-License-Identifier: Apache-2.0

import { createHash, timingSafeEqual } from 'node:crypto';
import { wider } from './license-invites.mjs';

export const ACCOUNT_LIMITS = {
  /** Base64url characters of ciphertext: the browser pads to powers of two up to 2 MiB. */
  maxCt: 2_900_000,
  /** Base64url characters of a slot's sealed account key (32 bytes + tag, with room to spare). */
  maxWrapCt: 512,
  /** Ways in one copy may have. */
  maxSlots: 20,
  /** New copies one client (an IPv6 client by its /48) may start in a UTC day. */
  perClientNewDaily: 20,
  /**
   * Saves (and slot changes) one copy may take in a UTC day (security review S9). Counted per
   * copy, proven by its write token, not per address: many people behind one mobile carrier's
   * address share an address, and a stranger on it could use it up on purpose.
   */
  perCopyWritesDaily: 500,
};

/** What a slot can be. Only "passkey" is made today; the rest are reserved so they need no migration. */
export const SLOT_KINDS = new Set(['passkey', 'recovery', 'password', 'member']);

const ID = /^[0-9a-f]{32}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const TOKEN = /^[A-Za-z0-9_-]{43}$/; // 32 bytes, base64url
const IV = /^[A-Za-z0-9_-]{16}$/; // 12 bytes
const B64U = /^[A-Za-z0-9_-]+$/;

/** What a save names as the copy it replaces: SHA-256 of "iv.ct", hex (as passkey-vault.mjs). */
export const copyFingerprint = (iv, ct) => createHash('sha256').update(`${iv}.${ct}`, 'utf8').digest('hex');

export const tokenHash = (token) => createHash('sha256').update(String(token), 'utf8').digest('hex');

const sameHash = (a, b) => {
  const x = Buffer.from(String(a), 'hex');
  const y = Buffer.from(String(b), 'hex');
  return x.length === 32 && y.length === 32 && timingSafeEqual(x, y);
};

const NO_COPY = { error: 'no such copy', code: 404 };
const NO_SLOT = { error: 'no such way in', code: 404 };
const NEEDS_KEY = { error: 'this copy needs its key', code: 403 };

export const createAccountCopies = (db, { now = () => Date.now(), limits = {} } = {}) => {
  const L = { ...ACCOUNT_LIMITS, ...limits };
  db.exec(`
    CREATE TABLE IF NOT EXISTS account_copies (
      copy_id     TEXT PRIMARY KEY,
      write_hash  TEXT NOT NULL,
      iv          TEXT NOT NULL,
      ct          TEXT NOT NULL,
      created_at  INTEGER NOT NULL,
      updated_at  INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS account_slots (
      slot_id     TEXT PRIMARY KEY,
      copy_id     TEXT NOT NULL,
      kind        TEXT NOT NULL,
      read_hash   TEXT NOT NULL,
      iv          TEXT NOT NULL,
      ct          TEXT NOT NULL,
      created_at  INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS account_slots_copy ON account_slots (copy_id);
  `);
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
  const overCopyLimit = (id) =>
    count(`copy ${id}`) > L.perCopyWritesDaily ? { error: 'too many saves of this copy today; try again tomorrow', code: 429 } : undefined;

  /** The copy's row, when the token is its write token. */
  const owned = (id, token) => {
    if (typeof id !== 'string' || !ID.test(id)) return NO_COPY;
    const row = st('SELECT * FROM account_copies WHERE copy_id = ?').get(id);
    if (!row) return NO_COPY;
    if (typeof token !== 'string' || !TOKEN.test(token) || !sameHash(tokenHash(token), row.write_hash)) return NEEDS_KEY;
    return { row };
  };

  const slotsOf = (id) =>
    st('SELECT slot_id, kind, created_at FROM account_slots WHERE copy_id = ? ORDER BY created_at, slot_id')
      .all(id)
      .map((s) => ({ slotId: s.slot_id, kind: s.kind, createdAt: s.created_at }));

  /** A slot as a save or an add sends it; an error, or the fields to store. */
  const slotIn = (slot) => {
    const { slotId, kind, tokenHash: th, iv, ct } = slot ?? {};
    if (typeof slotId !== 'string' || !ID.test(slotId)) return { error: 'slotId must be 32 hex characters' };
    if (typeof kind !== 'string' || !SLOT_KINDS.has(kind)) return { error: 'kind must be passkey, recovery, password or member' };
    if (typeof th !== 'string' || !HEX64.test(th)) return { error: "tokenHash must be the slot token's SHA-256, 64 hex" };
    if (typeof iv !== 'string' || !IV.test(iv)) return { error: 'iv must be 12 bytes, base64url' };
    if (typeof ct !== 'string' || !B64U.test(ct) || ct.length < 24 || ct.length > L.maxWrapCt) {
      return { error: `the slot's ct must be base64url, at most ${L.maxWrapCt} characters` };
    }
    return { slotId, kind, th, iv, ct };
  };

  const insertSlot = (copyId, s, at) =>
    st('INSERT INTO account_slots (slot_id, copy_id, kind, read_hash, iv, ct, created_at) VALUES (?,?,?,?,?,?,?)').run(
      s.slotId,
      copyId,
      s.kind,
      s.th,
      s.iv,
      s.ct,
      at,
    );

  return {
    /**
     * Save the copy. The first save makes it, and must bring its first way in (`slot`), so no
     * copy exists that nothing opens; it sets the write token. Later saves need the token and
     * replace the copy, but only the copy the browser last saw: `prev` is that copy's
     * fingerprint, or 'none' for a first save (as passkey-vault.mjs: 409 when another device
     * saved since, and the browser merges and saves again).
     */
    put(id, body, client) {
      const { token, iv, ct, prev, slot } = body ?? {};
      if (typeof id !== 'string' || !ID.test(id)) return { error: 'id must be 32 hex characters' };
      if (typeof token !== 'string' || !TOKEN.test(token)) return { error: 'token must be 32 bytes, base64url' };
      if (typeof iv !== 'string' || !IV.test(iv)) return { error: 'iv must be 12 bytes, base64url' };
      if (typeof ct !== 'string' || !B64U.test(ct) || ct.length < 24 || ct.length > L.maxCt) {
        return { error: `ct must be base64url, at most ${L.maxCt} characters`, code: ct?.length > L.maxCt ? 413 : 400 };
      }
      if (prev !== 'none' && !(typeof prev === 'string' && HEX64.test(prev))) {
        return { error: "prev must be the copy's fingerprint (64 hex characters) or 'none'" };
      }
      const row = st('SELECT write_hash, iv, ct FROM account_copies WHERE copy_id = ?').get(id);
      if (row && !sameHash(tokenHash(token), row.write_hash)) return NEEDS_KEY;
      if (row && prev !== copyFingerprint(row.iv, row.ct)) {
        return { error: 'the copy changed since this device last saw it', code: 409 };
      }
      if (!row && prev !== 'none') return { error: 'the copy changed since this device last saw it', code: 409 };
      let first;
      if (!row) {
        first = slotIn(slot);
        if (first.error) return { error: `a new copy needs its first way in: ${first.error}` };
        if (st('SELECT 1 FROM account_slots WHERE slot_id = ?').get(first.slotId)) {
          return { error: 'that way in already opens another copy', code: 409 };
        }
        if (client !== undefined && count(`new ${wider(String(client))}`) > L.perClientNewDaily) {
          return { error: 'too many new copies from here today; try again tomorrow', code: 429 };
        }
      }
      const limited = overCopyLimit(id);
      if (limited) return limited;
      const at = now();
      if (row) {
        st('UPDATE account_copies SET iv = ?, ct = ?, updated_at = ? WHERE copy_id = ?').run(iv, ct, at, id);
      } else {
        db.transaction(() => {
          st('INSERT INTO account_copies (copy_id, write_hash, iv, ct, created_at, updated_at) VALUES (?,?,?,?,?,?)').run(
            id,
            tokenHash(token),
            iv,
            ct,
            at,
            at,
          );
          insertSlot(id, first, at);
        })();
      }
      return { saved: true, updatedAt: at, fingerprint: copyFingerprint(iv, ct) };
    },

    /** The copy and its slots' ids and kinds, with the write token (a POST: no token in a URL). */
    read(id, token) {
      const a = owned(id, token);
      if (a.error) return a;
      return { iv: a.row.iv, ct: a.row.ct, updatedAt: a.row.updated_at, slots: slotsOf(id) };
    },

    /**
     * Whether there is a newer copy, cheaply: its fingerprint, when it was saved, and its slots.
     * Needs the write token too (review N7), so an id seen in a log can't be probed.
     */
    head(id, token) {
      const a = owned(id, token);
      if (a.error) return a;
      return { fingerprint: copyFingerprint(a.row.iv, a.row.ct), updatedAt: a.row.updated_at, slots: slotsOf(id) };
    },

    /** Delete the copy and every way in to it. */
    remove(id, token) {
      const a = owned(id, token);
      if (a.error) return a;
      db.transaction(() => {
        st('DELETE FROM account_slots WHERE copy_id = ?').run(id);
        st('DELETE FROM account_copies WHERE copy_id = ?').run(id);
      })();
      return { deleted: true };
    },

    /** Add a way in, with the copy's write token (only the account key makes it). */
    addSlot(id, slotId, body) {
      const { token, ...slot } = body ?? {};
      const a = owned(id, token);
      if (a.error) return a;
      const s = slotIn({ ...slot, slotId });
      if (s.error) return s;
      const existing = st('SELECT copy_id FROM account_slots WHERE slot_id = ?').get(slotId);
      if (existing) {
        return existing.copy_id === id
          ? { error: 'this copy already has that way in', code: 409 }
          : { error: 'that way in already opens another copy', code: 409 };
      }
      if (slotsOf(id).length >= L.maxSlots) return { error: `a copy has at most ${L.maxSlots} ways in`, code: 409 };
      const limited = overCopyLimit(id);
      if (limited) return limited;
      const at = now();
      insertSlot(id, s, at);
      return { added: true, createdAt: at };
    },

    /** Remove a way in, with the copy's write token. Never the last: nothing would open the copy. */
    removeSlot(id, slotId, token) {
      const a = owned(id, token);
      if (a.error) return a;
      if (typeof slotId !== 'string' || !ID.test(slotId)) return NO_SLOT;
      const row = st('SELECT 1 FROM account_slots WHERE slot_id = ? AND copy_id = ?').get(slotId, id);
      if (!row) return NO_SLOT;
      if (slotsOf(id).length <= 1) return { error: 'the last way in to a copy can’t be removed; delete the copy instead', code: 409 };
      const limited = overCopyLimit(id);
      if (limited) return limited;
      st('DELETE FROM account_slots WHERE slot_id = ?').run(slotId);
      return { removed: true };
    },

    /** A way in: which copy it opens and its sealed account key, with the slot's own token only. */
    readSlot(slotId, token) {
      if (typeof slotId !== 'string' || !ID.test(slotId)) return NO_SLOT;
      const row = st('SELECT copy_id, kind, read_hash, iv, ct FROM account_slots WHERE slot_id = ?').get(slotId);
      if (!row) return NO_SLOT;
      if (typeof token !== 'string' || !TOKEN.test(token) || !sameHash(tokenHash(token), row.read_hash)) {
        return { error: 'this way in needs its own key', code: 403 };
      }
      return { copyId: row.copy_id, kind: row.kind, iv: row.iv, ct: row.ct };
    },
  };
};
