// Records a holder deleted (DELETE /api/records).
//
// Without this the registry forgot a deleted id at once: a save already on its way, another tab
// or device, or a restored backup put the row straight back, proof code and check link included.
// An id stays deleted for every holder, so it can't be reused for something else either. The
// proof code is kept so a check link can still say whether it was dated before the deletion.
//
// SPDX-License-Identifier: Apache-2.0

const DELETED_CODE = 'deleted';
const DELETED_REASON = 'this record was deleted by its holder; it can’t be saved again';

const setupTombstones = (db) => {
  db.exec(`
    CREATE TABLE IF NOT EXISTS record_tombstones (
      id          TEXT PRIMARY KEY,
      holder_key  TEXT NOT NULL,
      fingerprint TEXT,
      deleted_at  INTEGER NOT NULL
    );
  `);
  const getOne = db.prepare('SELECT id, holder_key, fingerprint, deleted_at FROM record_tombstones WHERE id = ?');
  const put = db.prepare(
    `INSERT INTO record_tombstones (id, holder_key, fingerprint, deleted_at) VALUES (?, ?, ?, ?)
     ON CONFLICT(id) DO NOTHING`,
  );
  return {
    /** The tombstone for this id, or undefined. */
    of: (id) => (typeof id === 'string' ? getOne.get(id) : undefined),
    isDeleted: (id) => typeof id === 'string' && !!getOne.get(id),
    mark: (id, holder, fingerprint, at) => put.run(id, holder, typeof fingerprint === 'string' ? fingerprint : null, at),
    /** The per-row refusal for a save of a deleted id. */
    refusal: (id) => ({ id: String(id).slice(0, 128), reason: DELETED_REASON, code: DELETED_CODE }),
    /** The per-row refusal for a save whose correction link names a deleted id. */
    linkRefusal: (id, field) => ({
      id: String(id).slice(0, 128),
      reason: `${field} names a record that was deleted by its holder; nothing was changed`,
      code: DELETED_CODE,
    }),
  };
};

module.exports = { setupTombstones, DELETED_CODE, DELETED_REASON };
