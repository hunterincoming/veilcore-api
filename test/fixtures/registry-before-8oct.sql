-- A registry database written by the code at cfb2ee9 (before the 8 Oct 2026 fixes), through
-- its own routes: holder keys in plain text in records, licenses, disclosure_grants,
-- transfers and obligations_v2. Used by test/holder-key-migration.test.mjs.
-- Holder keys: sha256 hex of 'fixture:breeder', 'fixture:lab', 'fixture:other', and of
-- 'fixture:upper' in upper case. Open transfer TR-2F83F0FA claim code 785e24dfbc403f5cb1082bfdc48c05c1.
CREATE TABLE records (
    id         TEXT PRIMARY KEY,
    holder_key TEXT NOT NULL,
    body       TEXT NOT NULL,
    updated_at INTEGER NOT NULL
  , first_seen INTEGER);
INSERT INTO "records" VALUES ('OLD-MOTHER','5177aed5f27e630d108fa8c6119c4e549a2798851fde4f1d0080fbaf0554f1bd','{"id":"OLD-MOTHER","strainName":"S-OLD-MOTHER","bredBy":"B","dateCreated":"2026-01-01","loggedAt":"2026-01-02T00:00:00Z","nonce":"1111111111111111111111111111111111111111111111111111111111111111","notes":"private note OLD-MOTHER","parents":[],"photoFingerprints":[],"breedingMethod":"m","refId":"","recordFingerprint":"986c2325af714176efa3de6bec82a4ab5d6a4602fd691dfe2b1c8ff705f85754"}',1791502600779,1791502600779);
INSERT INTO "records" VALUES ('OLD-DAUGHTER','5177aed5f27e630d108fa8c6119c4e549a2798851fde4f1d0080fbaf0554f1bd','{"id":"OLD-DAUGHTER","strainName":"S-OLD-DAUGHTER","bredBy":"B","dateCreated":"2026-01-01","loggedAt":"2026-01-02T00:00:00Z","nonce":"2222222222222222222222222222222222222222222222222222222222222222","notes":"private note OLD-DAUGHTER","parents":[],"photoFingerprints":[],"breedingMethod":"m","refId":"","recordFingerprint":"c37cf9c1bfece86aadce81fb76ab061e1681242dba039e1269dc12d93bde8e1b","attestation":{"attesterKey":"cd80a791d0654e67e9273c8bb22dd86147f528ff58031499dab745b569941647","addressedTo":"lab@example.com","type":"receipt-confirmed","confirms":"a party holding the code the sender issued took delivery","transferId":"TR-57AF56DB","attestedAt":1791502600841}}',1791502600841,1791502600779);
INSERT INTO "records" VALUES ('OLD-OTHER','5c27a078f08e1a4c71395583be561fd7e9fc5cde8c737ee8b309f37fee34ade0','{"id":"OLD-OTHER","strainName":"S-OLD-OTHER","bredBy":"B","dateCreated":"2026-01-01","loggedAt":"2026-01-02T00:00:00Z","nonce":"3333333333333333333333333333333333333333333333333333333333333333","notes":"private note OLD-OTHER","parents":[],"photoFingerprints":[],"breedingMethod":"m","refId":"","recordFingerprint":"5b4b21194abf49d4cda79f9ba9022d648affb7b96c2f54b3bd675e9e0ddf2ce0"}',1791502600790,1791502600790);
INSERT INTO "records" VALUES ('OLD-UPPER','801FDB97022D7296663C76E993155A5B05702859D47C75A4AE31FF33BEC6FDE7','{"id":"OLD-UPPER","strainName":"S-OLD-UPPER","bredBy":"B","dateCreated":"2026-01-01","loggedAt":"2026-01-02T00:00:00Z","nonce":"4444444444444444444444444444444444444444444444444444444444444444","notes":"private note OLD-UPPER","parents":[],"photoFingerprints":[],"breedingMethod":"m","refId":"","recordFingerprint":"c3a69fd49f676c6bcea169f4bc207c738d73888faef61ff07cbabcae7630995f"}',1791502600797,1791502600797);
INSERT INTO "records" VALUES ('VEIL-A92302166859EF589AB8E6FBB27DF298','980d4881ce4f3ce6af22d5a60c4a68e64880366089639b4cc0d178142fd60f92','{"strainName":"S-OLD-DAUGHTER","bredBy":"B","dateCreated":"2026-01-01","notes":"","breedingMethod":"","parents":[],"photoFingerprints":[],"refId":"","licenseIds":[],"id":"VEIL-A92302166859EF589AB8E6FBB27DF298","receivedFrom":"OLD-DAUGHTER","receivedFromCommitment":"c37cf9c1bfece86aadce81fb76ab061e1681242dba039e1269dc12d93bde8e1b","receivedAt":1791502600841,"transferId":"TR-57AF56DB","quantity":"5","nonce":"34e365566ae970eeebaf2cba4d005de6b6c74f117cd4b9caa271dee8de9e2f6a","loggedAt":1791502600841}',1791502600841,1791502600841);
CREATE TABLE licenses (
    id         TEXT PRIMARY KEY,
    holder_key TEXT NOT NULL,
    record_id  TEXT,
    body       TEXT NOT NULL,
    updated_at INTEGER NOT NULL
  );
INSERT INTO "licenses" VALUES ('LIC-1','5177aed5f27e630d108fa8c6119c4e549a2798851fde4f1d0080fbaf0554f1bd','OLD-MOTHER','{"id":"LIC-1","recordId":"OLD-MOTHER","terms":"x"}',1791502600804);
CREATE TABLE collections (
    key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at INTEGER NOT NULL
  );
CREATE TABLE disclosure_grants (
    record_id  TEXT PRIMARY KEY,
    holder_key TEXT NOT NULL,
    show       TEXT NOT NULL,
    updated_at INTEGER NOT NULL
  );
INSERT INTO "disclosure_grants" VALUES ('OLD-MOTHER','5177aed5f27e630d108fa8c6119c4e549a2798851fde4f1d0080fbaf0554f1bd','["existence","parent-names"]',1791502600811);
CREATE TABLE descent_edges (
      child       TEXT NOT NULL,
      parent      TEXT NOT NULL,
      declared_at INTEGER NOT NULL,
      PRIMARY KEY (child, parent)
    );
CREATE TABLE descent_proposals (
      child       TEXT PRIMARY KEY,
      parent      TEXT NOT NULL,
      proposed_at INTEGER NOT NULL
    );
CREATE TABLE obligations_v2 (
      record          TEXT NOT NULL,
      obligation      TEXT NOT NULL,
      beneficiary_key TEXT NOT NULL,
      beneficiary_id  TEXT NOT NULL,
      status          TEXT NOT NULL CHECK (status IN ('proposed', 'open')),
      created_at      INTEGER NOT NULL,
      PRIMARY KEY (record, obligation, beneficiary_id)
    );
INSERT INTO "obligations_v2" VALUES ('986c2325af714176efa3de6bec82a4ab5d6a4602fd691dfe2b1c8ff705f85754','8e232a78a47b90e37a158cb931da1d7d77e8ad37822c3d245b8b8a1f61a4f612','5177aed5f27e630d108fa8c6119c4e549a2798851fde4f1d0080fbaf0554f1bd','eb959219d5fcbb5bf326b84f940308681c3d202caba1d6577e24aefebe476973','open',1791502600817);
INSERT INTO "obligations_v2" VALUES ('986c2325af714176efa3de6bec82a4ab5d6a4602fd691dfe2b1c8ff705f85754','2033d1267e7b6f56ec5175b1e7e4236653301ffaa5862dab892404089580580e','5c27a078f08e1a4c71395583be561fd7e9fc5cde8c737ee8b309f37fee34ade0','d45e7e9e7ced9edcd7f5816ec05269bea63fe6a14368d95ffd9044824ae0ac83','proposed',1791502600822);
CREATE TABLE transfers (
      id            TEXT PRIMARY KEY,
      source_record TEXT NOT NULL,
      from_holder   TEXT NOT NULL,
      to_handle     TEXT NOT NULL,
      -- The sender hands this to the recipient out of band. Without it a transfer was
      -- claimable by anyone holding its id, and ids are enumerable: /transfers/pending
      -- is public. Nullable so transfers created before this existed stay claimable.
      claim_code    TEXT,
      claimed_by    TEXT,
      claimed_at    INTEGER,
      created_at    INTEGER NOT NULL,
      terms_hash    TEXT,
      quantity      TEXT,
      note          TEXT
    );
INSERT INTO "transfers" VALUES ('TR-57AF56DB','OLD-DAUGHTER','5177aed5f27e630d108fa8c6119c4e549a2798851fde4f1d0080fbaf0554f1bd','lab@example.com','5ff7bc8955f3ada841871f273c4385f5','980d4881ce4f3ce6af22d5a60c4a68e64880366089639b4cc0d178142fd60f92',1791502600841,1791502600830,NULL,'5',NULL);
INSERT INTO "transfers" VALUES ('TR-2F83F0FA','OLD-MOTHER','5177aed5f27e630d108fa8c6119c4e549a2798851fde4f1d0080fbaf0554f1bd','lab@example.com','785e24dfbc403f5cb1082bfdc48c05c1',NULL,NULL,1791502600848,NULL,NULL,NULL);
INSERT INTO "transfers" VALUES ('TR-LEGACY0','OLD-MOTHER','5177aed5f27e630d108fa8c6119c4e549a2798851fde4f1d0080fbaf0554f1bd','lab@example.com',NULL,NULL,NULL,1700000000000,NULL,NULL,NULL);
CREATE TABLE batches (
      batch_id     TEXT PRIMARY KEY,
      root         TEXT NOT NULL,
      sealed_at    INTEGER NOT NULL,
      record_count INTEGER NOT NULL,
      anchor       TEXT
    , ots BLOB, ots_calendars TEXT, ots_status TEXT, ots_error TEXT, ots_bitcoin_height INTEGER, ots_bitcoin_time TEXT, ots_attempts INTEGER NOT NULL DEFAULT 0, ots_checked_at INTEGER);
CREATE TABLE batch_proofs (
      commitment TEXT PRIMARY KEY,
      batch_id   TEXT NOT NULL,
      proof      TEXT NOT NULL
    );
CREATE TABLE batch_ots_answers (
      id             INTEGER PRIMARY KEY AUTOINCREMENT,
      batch_id       TEXT NOT NULL,
      calendar       TEXT NOT NULL,
      answer         BLOB NOT NULL,
      received_at    INTEGER NOT NULL,
      bitcoin_height INTEGER,
      bitcoin_time   TEXT,
      upgraded_at    INTEGER
    );
CREATE TABLE attesters (
      public_key    TEXT PRIMARY KEY,
      attester_id   TEXT NOT NULL,
      display_name  TEXT,
      role          TEXT,
      accreditation TEXT,
      registered_at INTEGER NOT NULL
    , vetted INTEGER NOT NULL DEFAULT 0, vetted_at INTEGER, vetted_note TEXT);
CREATE TABLE attestations (
      attestation_id     TEXT PRIMARY KEY,
      subject_commitment TEXT NOT NULL,
      attester_key       TEXT NOT NULL,
      body               TEXT NOT NULL,
      created_at         INTEGER NOT NULL
    );
INSERT INTO "attestations" VALUES ('ATT-OLD-1','986c2325af714176efa3de6bec82a4ab5d6a4602fd691dfe2b1c8ff705f85754','93c094134bdfd549426fd039e64b0f804349819d4cdd23904a3504969f6177fe','{"type":"laboratory-report","attestationId":"ATT-OLD-1","subjectCommitment":"986c2325af714176efa3de6bec82a4ab5d6a4602fd691dfe2b1c8ff705f85754","documentHash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","hashAlgorithm":"sha256","issuedAt":"2026-10-01T00:00:00Z","attester":{"publicKey":"93c094134bdfd549426fd039e64b0f804349819d4cdd23904a3504969f6177fe","displayName":"Old Lab","extra":"unsigned"},"signature":"864b236e10d48b453502c93d85704e4ee7b977f3e6f2a0a7173026da048e20a5ccc87c14cce210530a7b0b2b8acbfefddc18d21431e65984e8344efd0cb5cb00","signatureAlgorithm":"ed25519","padding":"pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp"}',1791502600882);
CREATE TABLE retractions (
      attestation_id TEXT PRIMARY KEY,
      body           TEXT NOT NULL,
      retracted_at   INTEGER NOT NULL
    );
CREATE INDEX records_holder ON records(holder_key);
CREATE INDEX licenses_holder ON licenses(holder_key);
CREATE INDEX records_fingerprint ON records(json_extract(body, '$.recordFingerprint'));
CREATE INDEX obligations_v2_open ON obligations_v2(record, status);
CREATE INDEX transfers_handle ON transfers(to_handle);
CREATE INDEX batch_proofs_batch ON batch_proofs(batch_id);
CREATE INDEX batch_ots_answers_batch ON batch_ots_answers(batch_id);
CREATE INDEX attestations_subject ON attestations(subject_commitment);
