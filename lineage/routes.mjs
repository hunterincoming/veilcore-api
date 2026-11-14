// Lineage endpoints: descent, obligations, and clean-descent checks.
//
// The graph and the obligation set live here rather than in a browser because they
// are shared state: one holder's obligation has to be visible to everyone checking
// descent. Rebuilt from the database on boot, so a restart loses nothing.
//
// SECURITY PASS 30 SEP 2026. This layer had the holes the on-chain lineage contract
// had, and worse, because "authentication" was any non-empty x-holder-key header:
//
//   · anyone could attach an obligation to anyone's record, and INSERT OR REPLACE let
//     them overwrite a real one;
//   · anyone could DELETE any record's obligation — the holder key was required but
//     never compared with anything;
//   · a parent link was declared by the child alone, so a seller whose real mother was
//     encumbered could name any clean record as their parent.
//
// It follows the same consent rules as the on-chain contract (contract/src/veilcore.compact
// in hunterincoming/veilcore), but it is NOT backed by the chain: nothing here is read
// from or written to the contract, and the operator could alter it. Every response is
// labelled registry-attested (server.js). The contract is the source of truth.
//
//   DESCENT      the child's holder proposes a parent; the parent's holder confirms.
//                A claimed transfer counts as the parent's consent: the sender offered
//                the material, so the recipient's proposal naming it is confirmed.
//   OBLIGATIONS  a holder may claim against their own record in one step (a breeder
//                marking a licensed mother); anyone else proposes and the record's
//                holder accepts. Only the beneficiary releases. A record may carry
//                several obligations.
//
// Who can see an obligation (round 3, P5). There was an open listing of every obligation
// with its beneficiary's party id, one per holder: with two record links a stranger saw
// that both carry a royalty licence, when each was signed, and that one holder owns both,
// and the whole listing gave every holder's royalty portfolio. The listing is gone. The
// only public answer is per record: /lineage/verify says whether that record, or anything
// in its declared ancestry, carries an obligation in force. And a new obligation is stored
// under a per-record beneficiary id, not the per-holder party id (beneficiaryIdFor below).
//
// A record's holder is whoever stored the record with that fingerprint. If more than
// one holder has stored the same fingerprint, nobody may consent for it: the registry
// cannot tell which of them the material belongs to.
//
// SPDX-License-Identifier: Apache-2.0

import { createHash } from 'node:crypto';
import { DescentGraph } from './descent.mjs';
import { pureCircuits as C } from './managed/contract/index.js';
// Holder keys are stored as digests (deep dive, 8 Oct 2026). Functions here take the key
// as sent, because a party id is derived from it, and compare or store its digest.
import holderKeys from '../holder-key.js';

const { storedHolderKey, migrateHolderKeys, partyIdOf } = holderKeys;

const hex = (u) => Buffer.from(u).toString('hex');
/** Parse a 32-byte commitment. Anything else is a client error, not a crash. */
const bytes = (h) => {
  const clean = String(h ?? '').replace(/^0x/, '');
  if (!/^[0-9a-fA-F]{64}$/.test(clean)) {
    throw new Error('expected a 32-byte hex commitment (64 hex characters)');
  }
  const b = Uint8Array.from(Buffer.from(clean, 'hex'));
  if (b.every((x) => x === 0)) throw new Error('an all-zero commitment is not a record');
  return b;
};
/**
 * A beneficiary as shown to other people: a hash of their holder key, never the key.
 * A holder key is a credential; publishing it would let anyone act as that holder.
 */
// Of the key in lower case (round 3, holder-key.js partyIdOf): one key, one party, however
// it is spelled. Hashed as sent before, so an upper-case spelling was a second party.
export const partyId = (holderKey) => partyIdOf(holderKey);

/**
 * The beneficiary id a new obligation is stored under (round 3, P5): one per record, so two
 * obligations of one holder do not share an id that links them. The holder's browser sends
 * its own, `beneficiary`: lowercase hex HMAC-SHA256 under a key derived from its vault key
 * (which this registry never receives), of "veilcore:beneficiary:v1\0" + the record's
 * fingerprint; only the holder can link two of them. A client that sends none gets this,
 * made here from the stored digest of its key and the record: per record too, and not
 * something a stranger can make, but the registry could link them (as it can anyway: it
 * stores whose key made each obligation, beneficiary_key, to know who may release it).
 */
export const beneficiaryIdFor = (holderKey, record) =>
  createHash('sha256').update(`veilcore:beneficiary:v1\0${storedHolderKey(holderKey)}\0${record}`).digest('hex');
const BENEFICIARY = /^[0-9a-f]{64}$/;

/** Thrown for a request the caller is not allowed to make. Routes map it to 403. */
export class Forbidden extends Error {
  name = 'Forbidden';
}

/**
 * A page of a listing. Every list here was returned whole, and anyone with a
 * holder key could make it longer (attack round D), so the caller of a public route
 * chose the response size. Bounded, with the total so a client can tell it was cut.
 */
export const LISTING_PAGE = { default: 500, max: 1000 };
export const page = ({ limit, offset } = {}) => ({
  limit: Math.min(Math.max(Number.parseInt(limit, 10) || LISTING_PAGE.default, 1), LISTING_PAGE.max),
  offset: Math.max(Number.parseInt(offset, 10) || 0, 0),
});

export const createLineage = (db) => {
  db.exec(`
    CREATE TABLE IF NOT EXISTS descent_edges (
      child       TEXT NOT NULL,
      parent      TEXT NOT NULL,
      declared_at INTEGER NOT NULL,
      PRIMARY KEY (child, parent)
    );
    CREATE TABLE IF NOT EXISTS descent_proposals (
      child       TEXT PRIMARY KEY,
      parent      TEXT NOT NULL,
      proposed_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS obligations_v2 (
      record          TEXT NOT NULL,
      obligation      TEXT NOT NULL,
      beneficiary_key TEXT NOT NULL,
      beneficiary_id  TEXT NOT NULL,
      status          TEXT NOT NULL CHECK (status IN ('proposed', 'open')),
      created_at      INTEGER NOT NULL,
      PRIMARY KEY (record, obligation, beneficiary_id)
    );
    CREATE INDEX IF NOT EXISTS obligations_v2_open ON obligations_v2(record, status);
    CREATE INDEX IF NOT EXISTS obligations_v2_beneficiary ON obligations_v2(beneficiary_id);
  `);

  // One-time migration from the single-obligation table. Every row there was written
  // by the licensing flow, which encumbers the holder's own record in the holder's
  // favour — so each becomes an open self-claim, the only kind that flow can make.
  const hasOld = db
    .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='obligations'")
    .get();
  if (hasOld) {
    const move = db.prepare(`INSERT OR IGNORE INTO obligations_v2
      (record, obligation, beneficiary_key, beneficiary_id, status, created_at) VALUES (?,?,?,?, 'open', ?)`);
    db.transaction(() => {
      for (const r of db.prepare('SELECT record, obligation, holder_key, created_at FROM obligations').all()) {
        move.run(r.record, r.obligation, r.holder_key, partyId(r.holder_key), r.created_at);
      }
      db.exec('DROP TABLE obligations');
    })();
  }
  // After the move above, which needs the old table's plain keys for the party ids.
  migrateHolderKeys(db);

  const graph = new DescentGraph();
  for (const r of db.prepare('SELECT child, parent FROM descent_edges').all()) {
    graph.observe(bytes(r.child), bytes(r.parent));
  }

  /** The stored holder key (a digest) of the record with this fingerprint, or why there is none. */
  const holderOfRecord = (fingerprint) => {
    const rows = db
      .prepare("SELECT DISTINCT holder_key FROM records WHERE json_extract(body, '$.recordFingerprint') = ?")
      .all(fingerprint);
    if (rows.length === 0) return { error: 'no record with that fingerprint is stored here' };
    if (rows.length > 1) return { error: 'more than one holder has stored that fingerprint, so nobody can consent for it' };
    return { holder: rows[0].holder_key };
  };
  const requireHolder = (fingerprint, holderKey, what) => {
    const h = holderOfRecord(fingerprint);
    if (h.error) throw new Forbidden(`${what}: ${h.error}`);
    if (h.holder !== storedHolderKey(holderKey)) throw new Forbidden(`${what}: only the record's holder can do this`);
  };

  const isClean = (fingerprint) =>
    !db.prepare("SELECT 1 FROM obligations_v2 WHERE record = ? AND status = 'open' LIMIT 1").get(fingerprint);

  /** A digest of the open obligation set: changes whenever an obligation opens or closes. */
  const stateDigest = () => {
    const h = createHash('sha256').update('veilcore:obligations');
    for (const r of db
      .prepare("SELECT record, obligation, beneficiary_id FROM obligations_v2 WHERE status = 'open' ORDER BY record, obligation, beneficiary_id")
      .all()) {
      h.update(`${r.record}${r.obligation}${r.beneficiary_id}`);
    }
    return h.digest('hex');
  };
  const EMPTY_DIGEST = createHash('sha256').update('veilcore:obligations').digest('hex');

  const addEdge = (c, p) => {
    graph.observe(bytes(c), bytes(p));
    db.prepare('INSERT OR IGNORE INTO descent_edges (child, parent, declared_at) VALUES (?,?,?)').run(c, p, Date.now());
    db.prepare('DELETE FROM descent_proposals WHERE child = ?').run(c);
    return { edge: hex(C.descentEdge(bytes(c), bytes(p))), confirmed: true };
  };

  /**
   * Did the parent's holder hand THIS material to the child's holder by transfer?
   *
   * Only for the record the claim created (round 2): one claimed transfer was read as the
   * sender's consent for any record of the recipient to descend from the source.
   *
   * Only for the fingerprint the transfer carried (fixed when it was offered), and only
   * while that record is still held by the holder who sent it (deep dive, 8 Oct 2026). It
   * used to follow the source record id to whatever it held now, so a record changed after
   * the transfer, or stored under the id by someone else after the sender deleted theirs,
   * inherited the sender's consent.
   */
  const transferredFrom = (parentFingerprint, childFingerprint, childHolderKey) => {
    try {
      return !!db
        .prepare(`SELECT 1 FROM transfers t
                  JOIN records r ON r.id = t.source_record AND r.holder_key = t.from_holder
                  JOIN records c ON c.id = t.received_record AND c.holder_key = t.claimed_by
                  WHERE t.source_fingerprint = ? AND json_extract(r.body, '$.recordFingerprint') = t.source_fingerprint
                    AND json_extract(c.body, '$.recordFingerprint') = ?
                    AND t.claimed_by = ? LIMIT 1`)
        .get(parentFingerprint, childFingerprint, storedHolderKey(childHolderKey));
    } catch {
      return false; // no transfers table yet: nothing was transferred
    }
  };

  return {
    /** Kept for existing clients: a digest of the open obligations, not a Merkle root. */
    root: () => stateDigest(),
    emptyRoot: EMPTY_DIGEST,

    /**
     * As the CHILD's holder: name a parent. Becomes an edge when the parent's holder
     * confirms — or at once if the parent's holder transferred this material to you.
     */
    proposeParent(child, parent, holderKey) {
      const c = hex(bytes(child)), p = hex(bytes(parent));
      if (c === p) throw new Error('a record is not its own parent');
      requireHolder(c, holderKey, 'proposing a parent');
      if (transferredFrom(p, c, holderKey)) return addEdge(c, p);
      if (db.prepare('SELECT 1 FROM descent_proposals WHERE child = ?').get(c)) {
        throw new Error('this record already has a parentage proposal outstanding; withdraw it first');
      }
      db.prepare('INSERT INTO descent_proposals (child, parent, proposed_at) VALUES (?,?,?)').run(c, p, Date.now());
      return { edge: hex(C.descentEdge(bytes(c), bytes(p))), confirmed: false };
    },

    /** As the PARENT's holder: accept being named by this child. */
    confirmParent(child, parent, holderKey) {
      const c = hex(bytes(child)), p = hex(bytes(parent));
      requireHolder(p, holderKey, 'confirming a parent');
      const row = db.prepare('SELECT parent FROM descent_proposals WHERE child = ?').get(c);
      if (!row) throw new Error('no parentage proposed for that record');
      if (row.parent !== p) throw new Error('that record proposed a different parent');
      return addEdge(c, p);
    },

    /** As the child's holder: retract your own proposal. */
    withdrawParent(child, holderKey) {
      const c = hex(bytes(child));
      requireHolder(c, holderKey, 'withdrawing a proposal');
      const info = db.prepare('DELETE FROM descent_proposals WHERE child = ?').run(c);
      if (info.changes === 0) throw new Error('no parentage proposed for that record');
      return { withdrawn: true };
    },

    /**
     * Attach an obligation. On your own record it is in force at once, in your
     * favour. On anyone else's it is a proposal until their holder accepts it.
     * `beneficiary` (optional): the caller's per-record beneficiary id (beneficiaryIdFor).
     */
    encumber(record, obligation, holderKey, beneficiary) {
      const r = hex(bytes(record)), o = hex(bytes(obligation));
      let bid;
      if (beneficiary === undefined || beneficiary === null) bid = beneficiaryIdFor(holderKey, r);
      else if (typeof beneficiary !== 'string' || !BENEFICIARY.test(beneficiary)) {
        throw new Error('beneficiary must be 64 lowercase hexadecimal characters: a per-record beneficiary id');
      } else if (beneficiary === partyId(holderKey)) {
        throw new Error('beneficiary must be a per-record id, not your party id: that one is the same on every record');
      } else bid = beneficiary;
      // The record must be stored here, under one holder. A proposal used to be written
      // against any 32 bytes at all, so rows were free to create and no holder would
      // ever see them (attack round D).
      const h = holderOfRecord(r);
      if (h.error) throw new Error(`cannot attach an obligation: ${h.error}`);
      const own = h.holder === storedHolderKey(holderKey);
      // One per caller, whatever beneficiary id they send: by whose key made it.
      const exists = db
        .prepare('SELECT status FROM obligations_v2 WHERE record = ? AND obligation = ? AND beneficiary_key = ?')
        .get(r, o, storedHolderKey(holderKey));
      if (exists) throw new Error(`that obligation is already ${exists.status === 'open' ? 'in force' : 'proposed'}`);
      if (db.prepare('SELECT 1 FROM obligations_v2 WHERE record = ? AND obligation = ? AND beneficiary_id = ?').get(r, o, bid)) {
        throw new Error('that beneficiary id is already used for this obligation on this record');
      }
      db.prepare(`INSERT INTO obligations_v2 (record, obligation, beneficiary_key, beneficiary_id, status, created_at)
                  VALUES (?,?,?,?,?,?)`).run(r, o, storedHolderKey(holderKey), bid, own ? 'open' : 'proposed', Date.now());
      return { record: r, obligation: o, beneficiary: bid, status: own ? 'open' : 'proposed', root: stateDigest() };
    },

    /** As the record's holder: accept an obligation, naming the beneficiary you agreed with. */
    acceptObligation(record, obligation, beneficiaryId, holderKey) {
      const r = hex(bytes(record)), o = hex(bytes(obligation));
      requireHolder(r, holderKey, 'accepting an obligation');
      const info = db
        .prepare(`UPDATE obligations_v2 SET status = 'open'
                  WHERE record = ? AND obligation = ? AND beneficiary_id = ? AND status = 'proposed'`)
        .run(r, o, String(beneficiaryId ?? ''));
      if (info.changes === 0) throw new Error('no such obligation proposed against your record');
      return { record: r, obligation: o, status: 'open', root: stateDigest() };
    },

    /** Proposals waiting on a holder's decision, for records they hold. */
    proposalsFor(holderKey, paging) {
      const { limit, offset } = page(paging);
      return db
        .prepare(`SELECT o.record, o.obligation, o.beneficiary_id AS beneficiary, o.created_at
                  FROM obligations_v2 o
                  WHERE o.status = 'proposed' AND o.record IN (
                    SELECT json_extract(body, '$.recordFingerprint') FROM records WHERE holder_key = ?)
                  ORDER BY o.created_at LIMIT ? OFFSET ?`)
        .all(storedHolderKey(holderKey), limit, offset);
    },

    /**
     * Release an obligation, or withdraw a proposal. ONLY THE BENEFICIARY: the caller's
     * key is compared with the one that created it. This used to delete whatever
     * obligation sat on the record for any caller with any key at all. Compared by the
     * stored digest of the key (beneficiary_key), not the beneficiary id: since round 3 that
     * is per record, and may be one the holder's browser chose.
     */
    discharge(record, obligation, holderKey) {
      const r = hex(bytes(record)), o = hex(bytes(obligation));
      const info = db
        .prepare('DELETE FROM obligations_v2 WHERE record = ? AND obligation = ? AND beneficiary_key = ?')
        .run(r, o, storedHolderKey(holderKey));
      if (info.changes === 0) throw new Forbidden('no such obligation in your favour');
      return { record: r, obligation: o, released: true, root: stateDigest() };
    },

    /**
     * Decide a clean-descent claim. The verifier walks the confirmed graph; the caller
     * supplies only the ancestors they claim are clean, and every ancestor found must
     * be among them and carry no obligation in force.
     */
    verifyDescent(record, claimedChain) {
      let r, chain;
      try {
        r = bytes(record);
        if (claimedChain.length > 1000) throw new Error('a claimed chain may name at most 1000 ancestors');
        chain = claimedChain.map(bytes);
      } catch (e) {
        return { ok: false, reason: e.message };
      }
      // A commitment nothing here carries has no descent to be clean. This answered
      // ok:true for any 64 hex characters, so a buyer could be shown "accepted" for a
      // record that does not exist (attack round 11).
      const stored = db
        .prepare("SELECT 1 FROM records WHERE json_extract(body, '$.recordFingerprint') = ? LIMIT 1")
        .get(hex(r));
      if (!stored) {
        return { ok: false, reason: 'no record with that commitment is stored in this registry, so there is nothing to check' };
      }
      if (!isClean(hex(r))) return { ok: false, reason: 'this record carries an unmet obligation' };

      const walked = graph.verifyDescent(r, chain.map(hex));
      if (!walked.ok) return { ok: false, reason: walked.reason };

      for (const a of graph.ancestorsOf(r)) {
        if (!isClean(a)) return { ok: false, reason: 'an ancestor carries an unmet obligation' };
      }
      return {
        ok: true,
        generationsChecked: walked.ancestorsChecked,
        ...(walked.ancestorsChecked === 0
          ? { note: 'no confirmed ancestry for this record, so nothing upstream was checked' }
          : {}),
      };
    },

    /** Everything upstream of a record, per the CONFIRMED graph. */
    ancestorsOf(record) {
      return graph.ancestorsOf(bytes(record));
    },
  };
};
