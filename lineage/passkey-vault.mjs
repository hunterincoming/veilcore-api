// The passkey copy of a backup: what lets someone who lost their phone get everything back.
//
// A VeilCore backup file holds every key a person has. People lose files, and growers lose
// phones. So a browser can also keep an encrypted copy of the backup here, under a key only
// the person's passkey can make (WebAuthn's PRF extension, the approach Bitwarden and
// 1Password use). Passkeys sync through iCloud Keychain and Google Password Manager, so a new
// phone signed into the same account makes the same key and opens the copy.
//
// What the registry holds and learns:
//   - a vault id, a write token's SHA-256, and one AES-GCM ciphertext per id. The id, the
//     token and the encryption key all come from the passkey's PRF output in the browser
//     (site veilcore/passkey-backup.ts). The registry can't open the copy or change it without
//     the browser noticing. It can guess which holder a copy belongs to from when and from
//     where it is saved (a save right after a record write, from the same address);
//   - nothing else: no account, no email, no passkey public key.
//
// Since the account copy (account-copy.mjs, November 2026) the site makes no new copies here: it
// reads an existing one once, moves it into an account copy, and deletes it here.
//
// What it can still do is withhold the copy or serve an older one. The copy carries its own
// date inside the ciphertext, and the page shows it before restoring.
//
// The backup file stays the other way back in: a passkey that is deleted takes its copy's key
// with it, so the site never offers this as the only backup (W3C WebAuthn editor's advice,
// Cappalli 2025).
//
// SPDX-License-Identifier: Apache-2.0

import { createHash, timingSafeEqual } from 'node:crypto';
import { wider } from './license-invites.mjs';

export const VAULT_LIMITS = {
  /** Base64url characters of ciphertext: about 2 MB of backup, many hundreds of records. */
  maxCt: 2_800_000,
  /** New copies one client (an IPv6 client by its /48) may start in a UTC day. */
  perClientNewDaily: 20,
  /** Updates one client may make in a UTC day. */
  perClientWritesDaily: 300,
};

const VAULT_ID = /^[0-9a-f]{32}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const TOKEN = /^[A-Za-z0-9_-]{43}$/; // 32 bytes, base64url
const IV = /^[A-Za-z0-9_-]{16}$/; // 12 bytes
const B64U = /^[A-Za-z0-9_-]+$/;

/** What a save names as the copy it replaces: SHA-256 of "iv.ct", hex. */
export const boxFingerprint = (iv, ct) => createHash('sha256').update(`${iv}.${ct}`, 'utf8').digest('hex');

export const vaultTokenHash = (token) => createHash('sha256').update(String(token), 'utf8').digest('hex');

const sameHash = (a, b) => {
  const x = Buffer.from(String(a), 'hex');
  const y = Buffer.from(String(b), 'hex');
  return x.length === 32 && y.length === 32 && timingSafeEqual(x, y);
};

export const createPasskeyVault = (db, { now = () => Date.now(), limits = {} } = {}) => {
  const L = { ...VAULT_LIMITS, ...limits };
  db.exec(`
    CREATE TABLE IF NOT EXISTS passkey_vaults (
      vault_id    TEXT PRIMARY KEY,
      write_hash  TEXT NOT NULL,
      iv          TEXT NOT NULL,
      ct          TEXT NOT NULL,
      created_at  INTEGER NOT NULL,
      updated_at  INTEGER NOT NULL
    );
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

  const auth = (id, token) => {
    if (typeof id !== 'string' || !VAULT_ID.test(id)) return { error: 'no such copy', code: 404 };
    const row = st('SELECT write_hash FROM passkey_vaults WHERE vault_id = ?').get(id);
    if (!row) return { error: 'no such copy', code: 404 };
    if (typeof token !== 'string' || !TOKEN.test(token) || !sameHash(vaultTokenHash(token), row.write_hash)) {
      return { error: 'this copy needs its passkey', code: 403 };
    }
    return { ok: true };
  };

  return {
    /**
     * Save a copy: the first save sets the token; later saves need it and replace the copy, but
     * only the copy the browser last saw. `prev` is that copy's fingerprint (SHA-256 of "iv.ct",
     * hex), or 'none' for a first save. Two devices on one synced passkey would otherwise
     * overwrite each other's records silently (attack pass 21 Oct, finding 2): a stale save is
     * refused with 409 and the browser merges the newer copy in and saves again.
     */
    put(id, body, client) {
      const { token, iv, ct, prev } = body ?? {};
      if (typeof id !== 'string' || !VAULT_ID.test(id)) return { error: 'id must be 32 hex characters' };
      if (typeof token !== 'string' || !TOKEN.test(token)) return { error: 'token must be 32 bytes, base64url' };
      if (typeof iv !== 'string' || !IV.test(iv)) return { error: 'iv must be 12 bytes, base64url' };
      if (typeof ct !== 'string' || !B64U.test(ct) || ct.length < 24 || ct.length > L.maxCt) {
        return { error: `ct must be base64url, at most ${L.maxCt} characters`, code: ct?.length > L.maxCt ? 413 : 400 };
      }
      if (prev !== 'none' && !(typeof prev === 'string' && HEX64.test(prev))) {
        return { error: "prev must be the copy's fingerprint (64 hex characters) or 'none'" };
      }
      const row = st('SELECT write_hash, iv, ct FROM passkey_vaults WHERE vault_id = ?').get(id);
      if (row && !sameHash(vaultTokenHash(token), row.write_hash)) {
        return { error: 'this copy needs its passkey', code: 403 };
      }
      if (row && prev !== boxFingerprint(row.iv, row.ct)) {
        return { error: 'the copy changed since this device last saw it', code: 409 };
      }
      if (client !== undefined) {
        const bucket = wider(String(client));
        if (!row && count(`new ${bucket}`) > L.perClientNewDaily) {
          return { error: 'too many new copies from here today; try again tomorrow', code: 429 };
        }
        if (count(`write ${bucket}`) > L.perClientWritesDaily) {
          return { error: 'too many saves from here today; try again tomorrow', code: 429 };
        }
      }
      const at = now();
      if (row) {
        st('UPDATE passkey_vaults SET iv = ?, ct = ?, updated_at = ? WHERE vault_id = ?').run(iv, ct, at, id);
      } else {
        st('INSERT INTO passkey_vaults (vault_id, write_hash, iv, ct, created_at, updated_at) VALUES (?,?,?,?,?,?)')
          .run(id, vaultTokenHash(token), iv, ct, at, at);
      }
      return { saved: true, updatedAt: at };
    },

    /** The copy, with the token (asked by POST so the token never sits in a URL or a log). */
    read(id, token) {
      const a = auth(id, token);
      if (a.error) return a;
      const row = st('SELECT iv, ct, updated_at FROM passkey_vaults WHERE vault_id = ?').get(id);
      return { iv: row.iv, ct: row.ct, updatedAt: row.updated_at };
    },

    /** Delete the copy, with the token. */
    remove(id, token) {
      const a = auth(id, token);
      if (a.error) return a;
      st('DELETE FROM passkey_vaults WHERE vault_id = ?').run(id);
      return { deleted: true };
    },
  };
};
