// Every fingerprint ever held, and its first holder (fingerprint takeover, 9 Nov 2026).
//
// The guard on saving a record (server.js otherHolder) used to look only at records stored
// now. Once a holder deleted a record, or edited it so its fingerprint changed, anyone with the
// old proof code could store a record with it, become its holder, offer a delivery of it, and
// read every lab signature about it. A fingerprint now stays with the key that first held it:
// no other key may store it, and the visibility rule (server.js privateReaderFor) counts that
// key, from that time, as its holder.
//
// Written by triggers, so every path that stores a record (a save, dating first, a claim's
// record once sealed) records it. Backfilled once, when the table is first made, from the
// earliest evidence of who held each fingerprint: the records stored now (first_seen) and the
// deliveries sent from it (transfers.created_at). So a fingerprint taken over before this keeps
// the key that held it first, not the one holding it now.
//
// SPDX-License-Identifier: Apache-2.0

'use strict';

const HEX64 = /^[0-9a-f]{64}$/;

const tableExists = (db, name) => !!db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?").get(name);

/**
 * Make the table and its triggers, and backfill it if it is new. `asStored` turns a holder key
 * as some older row holds it into the stored form (holder-key.js asStored). Returns how many
 * fingerprints the backfill recorded (0 when the table was there already).
 */
const setupFingerprintHolders = (db, asStored) => {
  const had = tableExists(db, 'fingerprint_holders');
  db.exec(`
    CREATE TABLE IF NOT EXISTS fingerprint_holders (
      fingerprint TEXT PRIMARY KEY,
      holder_key  TEXT NOT NULL,
      first_at    INTEGER NOT NULL
    );
    -- No OR IGNORE: inside a trigger, the conflict clause of the statement that fired it wins
    -- (an upsert's ON CONFLICT made it a plain insert, and a second save of a held fingerprint
    -- failed on the primary key). The WHEN clause skips one already recorded instead. Made
    -- again on every start, so a fix here reaches a database that has the older trigger.
    DROP TRIGGER IF EXISTS fingerprint_holders_insert;
    CREATE TRIGGER fingerprint_holders_insert AFTER INSERT ON records
      WHEN json_extract(NEW.body, '$.recordFingerprint') IS NOT NULL
        AND NOT EXISTS (SELECT 1 FROM fingerprint_holders WHERE fingerprint = json_extract(NEW.body, '$.recordFingerprint'))
      BEGIN
        INSERT INTO fingerprint_holders (fingerprint, holder_key, first_at)
          VALUES (json_extract(NEW.body, '$.recordFingerprint'), NEW.holder_key, COALESCE(NEW.first_seen, NEW.updated_at));
      END;
    DROP TRIGGER IF EXISTS fingerprint_holders_update;
    CREATE TRIGGER fingerprint_holders_update AFTER UPDATE OF body ON records
      WHEN json_extract(NEW.body, '$.recordFingerprint') IS NOT NULL
        AND NOT EXISTS (SELECT 1 FROM fingerprint_holders WHERE fingerprint = json_extract(NEW.body, '$.recordFingerprint'))
      BEGIN
        INSERT INTO fingerprint_holders (fingerprint, holder_key, first_at)
          VALUES (json_extract(NEW.body, '$.recordFingerprint'), NEW.holder_key, COALESCE(NEW.first_seen, NEW.updated_at));
      END;
  `);
  if (had) return 0;

  const earliest = new Map(); // fingerprint -> { holder, at }
  const seen = (fp, holder, at) => {
    if (typeof fp !== 'string' || !HEX64.test(fp) || typeof holder !== 'string' || !holder) return;
    const when = Number.isFinite(at) ? at : Number.MAX_SAFE_INTEGER;
    const prior = earliest.get(fp);
    if (!prior || when < prior.at) earliest.set(fp, { holder: asStored(holder), at: when });
  };
  const recordCols = db.prepare('PRAGMA table_info(records)').all().map((c) => c.name);
  const recordAt = recordCols.includes('first_seen') ? 'COALESCE(first_seen, updated_at)' : 'updated_at';
  for (const r of db.prepare(`SELECT json_extract(body, '$.recordFingerprint') AS fp, holder_key, ${recordAt} AS at
      FROM records WHERE json_extract(body, '$.recordFingerprint') IS NOT NULL`).iterate()) {
    seen(r.fp, r.holder_key, r.at);
  }
  if (tableExists(db, 'transfers')) {
    const cols = db.prepare('PRAGMA table_info(transfers)').all().map((c) => c.name);
    if (cols.includes('source_fingerprint')) {
      for (const t of db.prepare('SELECT source_fingerprint AS fp, from_holder, created_at AS at FROM transfers WHERE source_fingerprint IS NOT NULL').iterate()) {
        seen(t.fp, t.from_holder, t.at);
      }
    }
  }
  const put = db.prepare('INSERT OR IGNORE INTO fingerprint_holders (fingerprint, holder_key, first_at) VALUES (?,?,?)');
  db.transaction(() => {
    for (const [fp, e] of earliest) put.run(fp, e.holder, e.at === Number.MAX_SAFE_INTEGER ? 0 : e.at);
  })();
  if (earliest.size) console.log(`fingerprint holders: recorded the first holder of ${earliest.size} fingerprints`);
  return earliest.size;
};

module.exports = { setupFingerprintHolders };
