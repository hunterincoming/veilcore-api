// VeilCore record store. Genetics and DNA report files never arrive here.
//
// Since 16 Oct 2026 a record is stored sealed (sealed.js): what the holder typed (breeder,
// dates, notes, parents, method, terms, the nonce behind the fingerprint) is inside an
// AES-256-GCM box made with a vault key that stays in the holder's browser, so this
// registry cannot read it. Since round 5 (17 Oct) the record's name is inside the box too.
// In the clear: the record's profile id, fingerprint and key binding, correction links (ids, known field names, a date), the
// received-record fields and attestation this registry writes, when it first saw the
// record, and the values a holder chose to publish with a disclosure grant; for a delivery,
// a tag the sender's browser makes from the recipient's name, never the name (round 2). Rows written before then stay in plain text until their holder's
// browser re-saves them sealed, or scripts/purge-plaintext.mjs reduces them; those are
// served in full only to their own holder.
//
// Records are scoped to a holder key derived client-side from the holder's own secret.
// Everything public (/verify, /records, /embed) returns the same short view: id,
// fingerprint (and a name only when its holder published it), and facts the registry itself can stand behind, plus only the values the
// holder has granted (round D). Security pass 1 Oct 2026: /records/:localId used to return
// the whole stored body, nonce included, to anyone.
// SPDX-License-Identifier: Apache-2.0

const express = require('express');
const cors = require('cors');
const Database = require('better-sqlite3');

const { operatorToken, persistenceWarning, OPERATOR_TOKEN_MIN } = require('./startup-checks.js');

const DB_PATH = process.env.DB_PATH || 'veilcore.db';
// Said loudly at every start until it is fixed: without a volume, a redeploy deletes every
// record (README, "Keeping the data"). Behaviour is unchanged; this only warns.
{
  const warning = persistenceWarning(process.env, DB_PATH);
  if (warning) console.warn(`WARNING: ${warning}`);
}
const db = new Database(DB_PATH);
// How long a query waits for a lock another connection holds on the file (round 3): the
// purge, or anything else an operator runs against it. better-sqlite3 already waits 5 s by
// default; it is set here so it does not rest on a library default, and a test pins it.
// The wait blocks this process (every query here is synchronous), and a longer hold, such
// as the purge's VACUUM on a large file, still fails requests with 500s once it runs out:
// the purge is run in a maintenance window (README, "The purge").
const SQLITE_BUSY_TIMEOUT_MS = 5000;
db.pragma(`busy_timeout = ${SQLITE_BUSY_TIMEOUT_MS}`);
db.exec(`
  CREATE TABLE IF NOT EXISTS records (
    id         TEXT PRIMARY KEY,
    holder_key TEXT NOT NULL,
    body       TEXT NOT NULL,
    updated_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS records_holder ON records(holder_key);

  CREATE TABLE IF NOT EXISTS licenses (
    id         TEXT PRIMARY KEY,
    holder_key TEXT NOT NULL,
    record_id  TEXT,
    body       TEXT NOT NULL,
    updated_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS licenses_holder ON licenses(holder_key);

  CREATE TABLE IF NOT EXISTS collections (
    key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at INTEGER NOT NULL
  );
`);
// When this registry first saw each record. Set once, never by the holder: the date in
// a record (loggedAt) is the holder's own statement and can be anything they like.
if (!db.prepare("SELECT 1 FROM pragma_table_info('records') WHERE name = 'first_seen'").get()) {
  db.exec('ALTER TABLE records ADD COLUMN first_seen INTEGER');
  db.exec('UPDATE records SET first_seen = updated_at WHERE first_seen IS NULL');
}
db.exec("CREATE INDEX IF NOT EXISTS records_fingerprint ON records(json_extract(body, '$.recordFingerprint'))");
// What the holder lets a stranger with the record id see beyond the public base (round D:
// ?show= was written by whoever had the link, so the holder's choice controlled nothing).
// One row per record, written only by that record's holder. holder_key is kept so a grant
// never outlives the holder who made it: if the id is later stored by someone else, the
// old grant does not apply to their record.
db.exec(`
  CREATE TABLE IF NOT EXISTS disclosure_grants (
    record_id  TEXT PRIMARY KEY,
    holder_key TEXT NOT NULL,
    show       TEXT NOT NULL,
    updated_at INTEGER NOT NULL
  );
`);
// The values a grant publishes (sealed records): the registry can no longer read them from
// the record, so the holder's browser sends exactly what it chose to show, with the
// fingerprint of the record those values were taken from. A value is answered only while
// that fingerprint is the record's current one.
for (const col of ['grant_values', 'for_fingerprint']) {
  if (!db.prepare("SELECT 1 FROM pragma_table_info('disclosure_grants') WHERE name = ?").get(col)) {
    db.exec(`ALTER TABLE disclosure_grants ADD COLUMN ${col} TEXT`);
  }
}

// What a record's holder says, publicly, about royalties on licenses from it (the site's
// veilcore/license-notices.ts), and what the licensee answers (license notices, below). One row
// per (record, ref); `ref` is made from the deal message it is about (the licensee's statement),
// so both sides can name it. Nothing else can be stored: no amount, name, period or text.
db.exec(`
  CREATE TABLE IF NOT EXISTS license_notices (
    record_id  TEXT NOT NULL,
    ref        TEXT NOT NULL,
    holder_key TEXT NOT NULL,
    kind       TEXT NOT NULL,
    day        TEXT NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (record_id, ref)
  );
  CREATE TABLE IF NOT EXISTS license_answers (
    statement      TEXT NOT NULL,
    answer         TEXT NOT NULL,
    reference_hash TEXT,
    signature      TEXT NOT NULL,
    received_at    INTEGER NOT NULL,
    PRIMARY KEY (statement, answer)
  );
`);
// Added with license-notices-v2: the statement a line is about (a deal message's fingerprint,
// never public), when this registry first received a notice of breach for it, and the day
// a revoked line was first accepted. A database from before has them added once, empty.
for (const [col, type] of [['statement', 'TEXT'], ['breach_at', 'INTEGER'], ['revoked_at', 'INTEGER']]) {
  if (!db.prepare("SELECT 1 FROM pragma_table_info('license_notices') WHERE name = ?").get(col)) {
    db.exec(`ALTER TABLE license_notices ADD COLUMN ${col} ${type}`);
  }
}
// Added with license-notices-v3: the licensor's signature over a line with their deal key (a row
// without it is from before and is never shown), and the due date the licensee registered for a
// statement (an answer of type "statement"). Added once, empty.
for (const [table, col] of [['license_notices', 'line_sig'], ['license_answers', 'due_on']]) {
  if (!db.prepare(`SELECT 1 FROM pragma_table_info('${table}') WHERE name = ?`).get(col)) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${col} TEXT`);
  }
}

// Holder keys are stored as digests (holder-key.js). A database written before 8 Oct 2026
// has them in plain text: converted here, once, before any request is answered. The
// lineage and transfer modules run the same idempotent step for the tables they create.
const { storedHolderKey, migrateHolderKeys, adoptPlaintextKey, asStored: asStoredKey } = require('./holder-key.js');
const { setupFingerprintHolders } = require('./fingerprint-holders.js');
// Whatever is deleted or overwritten is zeroed in the file, not left in free space: a
// holder key converted to its digest, a record a holder removed.
db.pragma('secure_delete = ON');
migrateHolderKeys(db);

// Every fingerprint ever held, and its first holder (fingerprint takeover, 9 Nov 2026):
// fingerprint-holders.js. Made, and backfilled once, before anything is stored.
setupFingerprintHolders(db, asStoredKey);
const firstHolderOf = db.prepare('SELECT holder_key, first_at FROM fingerprint_holders WHERE fingerprint = ?');
// Ids a holder deleted stay deleted (tombstones.js): no save, dating row or restore brings one back.
const { setupTombstones } = require('./tombstones.js');
// How close an anchor and a deletion can be before /verify says their order is unknown: the
// anchor skew allowed in lineage/batches.mjs (ANCHOR_CLOCK_SKEW_MS) plus the minute deletedAt
// is rounded to.
const DELETION_ORDER_WINDOW_MS = 5 * 60_000 + 60_000;
const tombstones = setupTombstones(db);
/**
 * The same conversion, on a timer, without the file rebuild (round 2). Rows written in
 * plain text by older code after this one started (a deploy overlap, a rollback) are also
 * converted whenever their holder's key arrives (below); this catches the holders who send
 * nothing. Exported for tests.
 */
const convertPlaintextNow = () => migrateHolderKeys(db, { vacuum: false });
setInterval(() => { try { convertPlaintextNow(); } catch (e) { console.error('holder key conversion failed:', e.message); } }, 10 * 60_000).unref();

// A holder's records and licences are read a page at a time, by id, and the whole set
// newest first (GET /api/records, /api/licenses). Both orders come from an index, so a read
// touches only the rows it returns (deep dive, 8 Oct 2026).
db.exec(`
  CREATE INDEX IF NOT EXISTS records_holder_id ON records(holder_key, id);
  CREATE INDEX IF NOT EXISTS records_holder_updated ON records(holder_key, updated_at);
  CREATE INDEX IF NOT EXISTS licenses_holder_id ON licenses(holder_key, id);
  CREATE INDEX IF NOT EXISTS licenses_holder_updated ON licenses(holder_key, updated_at);
`);

// A record is corrected once (corrections.js): a unique index on the holder and the record a
// correction names, so a second correction is refused by SQLite itself however two saves
// interleave. After the holder key conversion above, so the index sees each holder under one
// key. A database already holding two corrections of one record keeps both (one is marked and
// left out of the index) and the log says which, at every start.
const { ensureOneCorrection, isSecondCorrection, alreadyCorrectedRefusal, supersededByLockedRefusal, recordRefusedRefusal, CORRECTED } = require('./corrections.js');
ensureOneCorrection(db);

// Lineage is loaded dynamically: the contract artifacts are ESM and this file is
// CommonJS, so a top-level import is not possible.
let lineage = null;
let transfers = null;
let batches = null;
// One RFC 3161 token per proof code, in seconds (lineage/record-stamps.mjs), set once loaded.
let recordStamps = null;
let attesters = null;
let proveRequests = null; // lineage/prove-requests.mjs, set once loaded
let licenseInvites = null; // lineage/license-invites.mjs, set once loaded
let deals = null; // lineage/deals.mjs, set once loaded
let paymentReceipts = null; // lineage/payment-receipts.mjs, set once loaded
let passkeyVault = null; // lineage/passkey-vault.mjs, set once loaded
let accountCopies = null; // lineage/account-copy.mjs, set once loaded
let labResults = null; // lineage/lab-results.mjs, set once loaded
let embed = null;
// The commitment checker (lineage/conformance.mjs). Until sealed records (16 Oct 2026) it
// recomputed every record's fingerprint before storing it. A sealed record's contents are
// unreadable here, so it is no longer on the write path: the holder's browser recomputes
// each fingerprint after opening the record, and PUT /api/records says so
// (integrityCheckedBy: "holder"). It is still loaded, and /health still requires it: it is
// part of this build, it pins the veilcore-records version the tests check against, and a
// build where it does not load is a broken build.
//
// It once failed silently: package.json pinned veilcore-records at ^0.5.0 while the
// published package was 0.11.0, which semver does not widen for a zero major.
let conformance = null;
// How many of the three loads below have not finished, for /health: while any is running
// the service is starting; once all have finished, anything still missing failed to load.
// The commitment checker is counted too (round 2): when it loaded last, /health said
// "failed" in the meantime.
let loadsRunning = 3;
import('./lineage/conformance.mjs')
  .then((m) => { conformance = m; console.log('commitment verification ready'); })
  .catch((e) => {
    console.error('FATAL: commitment verification unavailable:', e.message);
    console.error('Refusing to start. The commitment checker is part of this build; without it the install is broken.');
    process.exit(1);
  })
  .finally(() => { loadsRunning--; });
import('./lineage/embed.mjs')
  .then((m) => { embed = m; console.log('embed verifier ready'); })
  .catch((e) => console.error('embed verifier unavailable:', e.message))
  .finally(() => { loadsRunning--; });
import('./lineage/routes.mjs')
  .then(async ({ createLineage }) => {
    lineage = createLineage(db);
    const { createTransfers } = await import('./lineage/transfer.mjs');
    // A claim writes a record into the claimant's set, so it meets the same ceilings a save
    // does (round 2).
    transfers = createTransfers(db, lineage, { maxRecords: MAX_PER_HOLDER, maxBytes: HOLDER_MAX_BYTES });
    const { createBatches } = await import('./lineage/batches.mjs');
    batches = createBatches(db);
    // Before the TSA timer below, which turns it on when a TSA is set.
    const { createRecordStamps, recordStampSettings } = await import('./lineage/record-stamps.mjs');
    const { requestTimestamp } = await import('./lineage/tsa.mjs');
    const stampSettings = recordStampSettings(process.env);
    const fpOfRecord = db.prepare(`SELECT 1 FROM records WHERE id = ? AND json_extract(body, '$.recordFingerprint') = ?`);
    recordStamps = createRecordStamps(db, {
      request: requestTimestamp,
      stillHeld: (id, fp) => !!fpOfRecord.get(id, fp),
      minIntervalMs: stampSettings.minIntervalMs,
      maxWaitMs: stampSettings.maxWaitMs,
      maxQueue: stampSettings.maxQueue,
      perHolderPerDay: stampSettings.perHolderPerDay,
      perTsaPerDay: stampSettings.perTsaPerDay,
    });
    startOtsTimer();
    startTsaTimer().catch((e) => console.error('RFC 3161 timestamps off:', e.message));
    const { createAttesters } = await import('./lineage/attesters.mjs');
    attesters = createAttesters(db);
    // Before prove requests: /health lists these, and test/fixtures/health-child.mjs holds
    // back a module that loads after every part /health lists.
    const { createLicenseInvites } = await import('./lineage/license-invites.mjs');
    licenseInvites = createLicenseInvites(db);
    const { createDeals } = await import('./lineage/deals.mjs');
    deals = createDeals(db, { invites: licenseInvites, now });
    const { createPaymentReceipts } = await import('./lineage/payment-receipts.mjs');
    paymentReceipts = createPaymentReceipts(db, attesters);
    const { createPasskeyVault } = await import('./lineage/passkey-vault.mjs');
    passkeyVault = createPasskeyVault(db);
    const { createAccountCopies } = await import('./lineage/account-copy.mjs');
    accountCopies = createAccountCopies(db);
    const { createProveRequests } = await import('./lineage/prove-requests.mjs');
    proveRequests = createProveRequests(db);
    const { createLabResults, folderFiles, memoryFiles } = await import('./lineage/lab-results.mjs');
    const path = require('node:path');
    // The locked files live next to the database, not in it (lab-results.mjs, "Where the
    // files live"); the off-site backup copies them separately, each once (backup.mjs).
    // A database in memory keeps its files in memory too: its rows are gone at the next
    // start, so files on disk would only be deleted then (and a folder belongs to one
    // database; lab-results.mjs refuses one that names another).
    const resultsDir = DB_PATH === ':memory:'
      ? null
      : process.env.LAB_RESULTS_DIR || path.join(path.dirname(DB_PATH), 'lab-results');
    if (DB_PATH === ':memory:' && process.env.LAB_RESULTS_DIR) console.log('LAB_RESULTS_DIR ignored: DB_PATH is :memory:');
    const maxTotal = Number(process.env.LAB_RESULTS_MAX_BYTES);
    const maxPerSender = Number(process.env.LAB_RESULTS_MAX_BYTES_PER_SENDER);
    // A folder that can't be made or read turns off lab results only (503), not the rest.
    try {
      labResults = createLabResults(db, {
        files: resultsDir ? folderFiles(resultsDir) : memoryFiles(),
        limits: {
          ...(Number.isSafeInteger(maxTotal) && maxTotal > 0 ? { maxTotalBytes: maxTotal } : {}),
          ...(Number.isSafeInteger(maxPerSender) && maxPerSender > 0 ? { perSenderBytes: maxPerSender } : {}),
        },
      });
      // Results older than 180 days are deleted (also checked on every upload and listing).
      setInterval(() => { try { labResults.sweep(); } catch (e) { console.error('lab results sweep failed:', e.message); } }, 60 * 60_000).unref();
      if (!resultsDir) console.log('lab result files kept in memory (DB_PATH is :memory:)');
    } catch (e) {
      console.error('lab results unavailable:', e.message);
    }
    console.log('lineage layer ready, root', lineage.root().slice(0, 16));
    console.log('transfers ready');
    console.log('batch anchoring ready');
    console.log('attester registry ready');
    console.log('prove requests ready');
    console.log('lab results ready');
  })
  .catch((e) => console.error('lineage layer unavailable:', e.message))
  .finally(() => { loadsRunning--; });

// Off-site backups (backup.mjs): a daily encrypted copy of this database, sent somewhere
// that is not this volume. Off unless the BACKUP_* settings are all set. Not part of
// /health: a failed backup must not take the registry down, and is reported to the
// operator instead (GET /admin/backup, and the deploy log).
let backups = null;
import('./backup.mjs')
  .then(({ startBackups }) => {
    // The lab-result files go too (backup.mjs), from the same folder lab results use.
    const labDir = DB_PATH === ':memory:' ? null : process.env.LAB_RESULTS_DIR || require('node:path').join(require('node:path').dirname(DB_PATH), 'lab-results');
    backups = startBackups({ db, labDir });
  })
  .catch((e) => console.error('BACKUP: the backup module did not load, so no backups are being made:', e.message));

/**
 * Where batch roots are anchored. Published at /.well-known and enforced on every anchor.
 *
 * Both VEILCORE_ANCHOR_NETWORK and VEILCORE_ANCHOR_CONTRACT must be set, and well formed,
 * before any anchor is recorded (mainnet readiness, 6 Oct 2026). With only the network set,
 * an anchor naming any contract on that network was accepted while /.well-known listed
 * none; a malformed contract variable is treated as unset, and said so at startup, rather
 * than published as the registry's contract.
 */
const NAME = /^[a-z][a-z0-9-]{0,31}$/;
const ADDRESS = /^(0x)?[0-9a-fA-F]{64}$/;
const normaliseHex = (h) => String(h).toLowerCase().replace(/^0x/, '');
/** An ISO 8601 date and time with Z or a ±hh:mm offset: one instant wherever it is read. */
const ISO_INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d{1,9})?)?(Z|[+-]\d{2}:\d{2})$/;
const ANCHOR_CONFIG = (() => {
  const chain = process.env.VEILCORE_ANCHOR_CHAIN || 'midnight';
  const network = (process.env.VEILCORE_ANCHOR_NETWORK || '').trim() || null;
  const contract = (process.env.VEILCORE_ANCHOR_CONTRACT || '').trim() || null;
  const problems = [];
  if (!NAME.test(chain)) problems.push('VEILCORE_ANCHOR_CHAIN is not a short lower-case name');
  if (network !== null && !NAME.test(network)) problems.push('VEILCORE_ANCHOR_NETWORK is not a short lower-case name');
  if (contract !== null && !ADDRESS.test(contract)) problems.push('VEILCORE_ANCHOR_CONTRACT is not 64 hex characters');
  if ((network === null) !== (contract === null)) problems.push('set both VEILCORE_ANCHOR_NETWORK and VEILCORE_ANCHOR_CONTRACT, or neither');
  if (problems.length) {
    console.error(`anchoring disabled: ${problems.join('; ')}`);
    return { chain, network: null, contractAddress: null, configured: false };
  }
  const configured = network !== null && contract !== null;
  return { chain, network, contractAddress: configured ? normaliseHex(contract) : null, configured };
})();

/**
 * OpenTimestamps upkeep: retry stamps that failed or never finished, and upgrade pending
 * proofs once the calendars' Bitcoin transactions confirm. Off with VEILCORE_OTS=off.
 */
function startOtsTimer() {
  if (process.env.VEILCORE_OTS === 'off') return;
  const every = Number.parseInt(process.env.VEILCORE_OTS_INTERVAL_MS ?? '', 10) || 30 * 60_000;
  let running = false;
  setInterval(async () => {
    if (running || !batches || process.env.VEILCORE_OTS === 'off') return;
    running = true;
    try { await batches.otsMaintenance(); } catch { /* recorded per batch */ } finally { running = false; }
  }, every).unref();
}

/**
 * RFC 3161 upkeep (lineage/tsa.mjs): a token from the TSA in VEILCORE_TSA_URL for every
 * batch that has none. Off when VEILCORE_TSA_URL is unset. Hourly, so a new batch is
 * stamped within the hour of being sealed.
 */
let tsaOn = false;
async function startTsaTimer() {
  const { tsaConfig, requestTimestamp } = await import('./lineage/tsa.mjs');
  const cfg = tsaConfig(process.env);
  if (!cfg) return;
  if (cfg.error) { console.error(`RFC 3161 timestamps off: ${cfg.error}`); return; }
  for (const svc of cfg.services ?? [cfg])
    console.log(`RFC 3161 timestamps on (${new URL(svc.url).host}${svc.pins.length ? ', signer pinned' : ''}${svc.qualified ? `, stated qualified under ${svc.qualified.scheme}` : ''})`);
  tsaOn = true;
  // Each new proof code too, in seconds (lineage/record-stamps.mjs), unless VEILCORE_TSA_RECORDS=off.
  const { recordStampSettings } = await import('./lineage/record-stamps.mjs');
  const s = recordStampSettings(process.env);
  if (recordStamps && s.on) {
    recordStamps.configure(cfg);
    console.log(`RFC 3161 timestamps per record on (at least ${s.minIntervalMs} ms apart; the batch's token after ${Math.round(s.maxWaitMs / 60_000)} min)`);
  }
  let running = false;
  const run = async () => {
    if (running || !batches) return;
    running = true;
    try { await batches.tsaMaintenance(cfg, { request: requestTimestamp }); }
    catch (e) { console.error('RFC 3161 upkeep failed:', e.message); }
    finally { running = false; }
  };
  setTimeout(run, 60_000).unref();
  setInterval(run, 3_600_000).unref();
}

const app = express();
// Railway puts exactly one proxy in front of this service, and that proxy appends the
// address it saw to X-Forwarded-For. Trusting one hop makes req.ip that appended entry —
// the rightmost — so anything a client writes into the header itself sits to the left
// and is ignored. Trusting more hops, or `true`, would let a client choose its own
// rate-limit bucket. Overridable for a deployment with a different proxy chain.
// test/attack-round11.test.mjs puts a one-hop proxy in front and checks this.
const TRUST_PROXY_HOPS = Number.parseInt(process.env.TRUST_PROXY_HOPS ?? '1', 10);
app.set('trust proxy', Number.isFinite(TRUST_PROXY_HOPS) ? TRUST_PROXY_HOPS : 1);
app.disable('x-powered-by');
app.use(cors());
app.use((req, res, next) => {
  res.set('X-Content-Type-Options', 'nosniff');
  res.set('Referrer-Policy', 'no-referrer');
  res.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.set('Cross-Origin-Opener-Policy', 'same-origin');
  // The embed is meant to be framed by other sites; nothing else is. Everything else
  // is JSON, which needs no scripts, styles or frames at all.
  // form-action and base-uri do not fall back to default-src, so they are named.
  // (OWASP ZAP, 3 October 2026: "CSP: Failure to Define Directive with No Fallback".)
  if (!req.path.startsWith('/embed')) {
    res.set('X-Frame-Options', 'DENY');
    res.set('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'; form-action 'none'; base-uri 'none'");
  } else if (req.path !== '/embed.js') {
    // The embed fragment is markup only: embed.js fetches it and supplies the styles.
    // Opened or framed on its own it may load nothing and submit nothing; any site may
    // frame it, which is what an embed is for.
    res.set('Content-Security-Policy', "default-src 'none'; form-action 'none'; base-uri 'none'; frame-ancestors *");
  }
  next();
});

// Holder data (records, licences, the export) is sealed, but rows from before sealing are
// plain text until re-saved, and grants carry what the holder chose to publish. No cache,
// shared or browser, may keep a copy.
app.use('/api', (_req, res, next) => { res.set('Cache-Control', 'no-store'); next(); });

/**
 * The bucket a client's requests count against. IPv6 by /64: a single host is routinely
 * handed a whole /64, so per-address limits on IPv6 were per-request limits for anyone
 * who rotated through their own prefix.
 */
const net = require('node:net');
const clientBucket = (ip) => {
  const addr = String(ip ?? '');
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(addr);
  if (mapped) return mapped[1];
  if (!net.isIPv6(addr)) return addr;
  // Expand :: so the first four groups are the first 64 bits.
  const [head, tail = ''] = addr.split('::');
  const h = head ? head.split(':') : [];
  const t = addr.includes('::') ? (tail ? tail.split(':') : []) : [];
  const groups = addr.includes('::') ? [...h, ...Array(8 - h.length - t.length).fill('0'), ...t] : h;
  return `${groups.slice(0, 4).map((g) => g.toLowerCase().replace(/^0+(?=.)/, '')).join(':')}::/64`;
};

/**
 * Bounded per-key counters. When full, expired entries go first, then the oldest. It
 * used to clear everything at 50,000 keys, which reset every client's count — a flood of
 * fresh addresses bought everyone else a clean slate.
 */
const MAX_TRACKED = 50_000;
const boundedSet = (map, key, value, isExpired) => {
  map.delete(key); // re-insert so iteration order is least recently touched first
  map.set(key, value);
  if (map.size <= MAX_TRACKED) return;
  for (const [k, v] of map) {
    if (map.size <= MAX_TRACKED * 0.9) break;
    if (isExpired(v)) map.delete(k);
  }
  for (const k of map.keys()) {
    if (map.size <= MAX_TRACKED * 0.9) break;
    map.delete(k);
  }
};

/**
 * A small fixed-window rate limit per client. No dependency: in memory, per process,
 * which is what one Railway instance needs. Writes are tighter than reads.
 */
const windows = new Map();
// Paddle's webhook has its own, wider window: Paddle sends from a few shared addresses, and
// a burst of renewals must not be refused. It is checked by signature before anything else.
const LIMITS = { write: 120, read: 600, webhook: 1200 }; // per minute
const isRead = (req) => req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS';
const isPaddleWebhook = (req) => req.method === 'POST' && req.path === '/api/billing/paddle';
const rateLimit = (req, res, next) => {
  const kind = isPaddleWebhook(req) ? 'webhook' : isRead(req) ? 'read' : 'write';
  const minute = Math.floor(Date.now() / 60_000);
  const key = `${kind}:${clientBucket(req.ip)}`;
  const w = windows.get(key);
  const n = w && w.minute === minute ? w.n + 1 : 1;
  boundedSet(windows, key, { minute, n }, (v) => v.minute !== minute);
  if (n > LIMITS[kind]) return res.status(429).json({ error: 'too many requests; try again in a minute' });
  next();
};
app.use(rateLimit);

/**
 * A daily ceiling on write bytes per client, so the database cannot be filled cheaply.
 * The rate limit alone allowed 120 × 512 KB a minute — tens of gigabytes a day from one
 * address. Generous on purpose: the app re-sends a holder's whole record set on each
 * save, so a large holder legitimately writes a lot.
 */
const WRITE_BYTES_PER_DAY = Number.parseInt(process.env.WRITE_BYTES_PER_DAY ?? String(200 * 1024 * 1024), 10);
const writeBytes = new Map();
/** Count `n` bytes against this address's day; false once the allowance is spent. */
const chargeWriteBytes = (req, n) => {
  const day = Math.floor(Date.now() / 86_400_000);
  const key = clientBucket(req.ip);
  const prev = writeBytes.get(key);
  const bytes = (prev && prev.day === day ? prev.bytes : 0) + n;
  boundedSet(writeBytes, key, { day, bytes }, (v) => v.day !== day);
  return bytes <= WRITE_BYTES_PER_DAY;
};
const countWriteBytes = (req, _res, buf) => {
  if (isRead(req)) return;
  if (!chargeWriteBytes(req, buf.length)) {
    const err = new Error('daily write allowance for this address used up; try again tomorrow');
    err.status = 429;
    throw err;
  }
};
// A holder's full record set travels on every save, so that one route takes more: as much
// as a holder may keep (HOLDER_MAX_BYTES, below), so a full save always fits.
app.put('/api/records', express.json({ limit: '40mb', verify: countWriteBytes }));
// The app re-sends every licence on each save too. 512 KB carried a holder's licences in
// plain text. Sealed, each is base64url (4/3) in a box, and padded to a bucket first
// (CONTRACT.md #20: the next KiB below 16 KiB), so a set of small licences can grow
// several times over: 512 KB of 190-byte licences is about 2,760 of them, 1 KiB each once
// padded, about 4 MB sealed (round 2, L5; it was 704 KB, which a full set of small licences
// from before sealing could not fit into once converted).
const LICENCE_BODY_LIMIT = 4 * 1024 * 1024;
app.put('/api/licenses', express.json({ limit: LICENCE_BODY_LIMIT, verify: countWriteBytes }));
// A passkey copy of a backup can be larger than other bodies (lineage/passkey-vault.mjs).
app.put('/vault/:id', express.json({ limit: '3mb', verify: countWriteBytes }));
// So can the account copy (lineage/account-copy.mjs): padded to a power of two, up to 2 MiB.
app.put('/account-copy/:id', express.json({ limit: '3mb', verify: countWriteBytes }));
// Paddle's webhook for paid plans (billing.js): its signature is over the body's exact bytes,
// so it gets them raw, before the JSON parser below. Off unless BILLING=on.
app.post('/api/billing/paddle', express.raw({ type: '*/*', limit: '256kb' }), (req, res) => billing.webhook(req, res));
app.use(express.json({ limit: '512kb', verify: countWriteBytes }));

/**
 * A holder key is 32 random bytes in hex, generated in the browser (holder.ts). Any
 * non-empty string used to be accepted, so a one-character key was a valid credential
 * and anyone could share or guess one (attack round 11). Upper-case hex is accepted
 * because the restore box in the app accepts it and stores what was pasted. Every lookup
 * compares the key in lower case (holder-key.js, round 3): it used to compare it as sent,
 * so one key in two spellings was two holders.
 */
const HOLDER_KEY = /^[0-9a-fA-F]{64}$/;
app.use((req, res, next) => {
  const given = req.get('x-holder-key');
  if (given !== undefined && given.trim() !== '' && !HOLDER_KEY.test(given.trim())) {
    return res.status(400).json({ error: 'x-holder-key must be 64 hexadecimal characters' });
  }
  // Rows older code wrote with this key in plain text are converted before anything looks
  // for them, so every lookup below finds them (holder-key.js adoptPlaintextKey).
  if (given !== undefined && given.trim() !== '') adoptPlaintextKey(db, given.trim());
  next();
});

/** Most records one request may write, and one holder may keep. */
// The app re-sends a holder's whole set on every save, so a request must be able to
// carry everything a holder may keep (the body limit on this route is raised to match).
const MAX_PER_REQUEST = 10_000;
const MAX_PER_HOLDER = 10_000;
/**
 * Paid plans (billing.js). Off unless BILLING=on: then every holder's ceiling is
 * MAX_PER_HOLDER, as it always was. On, a holder without a paid plan may have the free number
 * (BILLING_FREE_RECORDS) of proof codes dated, or what they held on the day it was switched on
 * plus that: the plan limits dates made, not records kept. Receiving a delivery
 * (lineage/transfer.mjs) needs free room too: the recipient seals and dates the received record
 * as their own content. Licences are not counted against a plan.
 */
const { createBilling } = require('./billing.js');
const billing = createBilling(db, { env: process.env, hardCap: MAX_PER_HOLDER });
/** The refusal when a save would go past a holder's ceiling: says which ceiling it is. */
const capRefusal = (cap) =>
  cap < MAX_PER_HOLDER
    ? { error: `the free plan dates ${cap} records here; a paid plan dates more`, code: 'plan-limit', cap }
    : { error: `a holder may keep at most ${MAX_PER_HOLDER} records here` };
/** The same, as one row's entry in `rejected`: a save refuses only its new rows past a ceiling. */
const capRowRefusal = (id, cap) => {
  const r = capRefusal(cap);
  return { id, reason: r.error, ...(r.code ? { code: r.code, cap } : {}) };
};
/**
 * Most bytes one holder may keep, in records and (separately) in licences. The count alone
 * allowed 10,000 × 64 KB, about 640 MB under one key anyone can make, and every read of the
 * set loaded all of it (deep dive, 8 Oct 2026, HIGH). It is what one save can carry (the
 * body limit on PUT /api/records), since the app re-sends the whole set. It was 16 MB
 * before records were sealed. Sealed, a record is base64url (4/3) and padded to a bucket
 * first (CONTRACT.md #20), up to half again for a record just over 16 KiB: a set at the old
 * 16 MB ceiling made of such records is about 32 MB sealed. 40 MB holds it with room (round
 * 2, L5; 24 MB, the limit before, did not).
 */
const HOLDER_MAX_BYTES = Number.parseInt(process.env.HOLDER_MAX_BYTES ?? '', 10) || 40 * 1024 * 1024;
const megabytes = (n) => `${(n / (1024 * 1024)).toFixed(1)} MB`;

/**
 * A holder key arrives as a request header. That matters for what this server
 * must never do.
 *
 * Nothing here logs a request. There is no morgan, no winston, no pino, no
 * access table, and the verify path at /verify/:id reads and never writes. So
 * the registry cannot say who checked which record.
 *
 * That property holds because no request logger exists, not because anything
 * prevents one. A single app.use(morgan(...)) would capture headers, and
 * x-holder-key would land in the log alongside the record id being verified.
 *
 * test/no-request-logging.test.mjs fails if a request logger appears.
 */
const holderOf = (req) => (req.get('x-holder-key') || '').trim();
/**
 * The holder key as this database stores it: a digest, never the key (holder-key.js).
 * Routes that query holder-scoped tables themselves use this; the lineage and transfer
 * modules take the key as sent, because a party id is derived from it, and store digests.
 */
const storedKeyOf = (req) => {
  const raw = holderOf(req);
  return raw ? storedHolderKey(raw) : '';
};

// Paid plans (billing.js): open a checkout on Paddle's own page, and read the holder's plan.
const recordsHeldBy = db.prepare('SELECT COUNT(*) AS n FROM records WHERE holder_key = ?');
app.post('/api/billing/checkout', (req, res) => billing.checkout(storedKeyOf(req), req.body, res, req.ip));
app.get('/api/billing/plan', (req, res) => {
  const holder = storedKeyOf(req);
  return billing.planOf(holder, holder ? recordsHeldBy.get(holder).n : 0, res);
});

/**
 * Registry operations, as distinct from holder operations.
 *
 * Sealing a batch and recording where its root was anchored are things the registry
 * does, not things a holder does — so a holder key is the wrong credential and using
 * one would say something untrue about who acted. Both routes had no credential at
 * all: anyone could seal a batch, and anyone could record an anchor for it.
 *
 * The anchor case is the one that matters. A proof names a transaction so a verifier
 * can look it up, which is the whole basis on which a date rests on a ledger rather
 * than on this registry's word. Sixty-four hex characters of anything passed the shape
 * check, and every proof in that batch would then cite a transaction that does not
 * exist or belongs to something unrelated. A verifier who checks finds nothing; one
 * who does not believes the date.
 */
// At least 32 characters, or operator routes stay disabled (startup-checks.js).
const OPERATOR_TOKEN = operatorToken(process.env);
const { createHash, timingSafeEqual } = require('node:crypto');
const digest = (s) => createHash('sha256').update(String(s)).digest();
const isOperator = (req) => {
  if (!OPERATOR_TOKEN) return false;
  const given = (req.get('x-operator-token') || '').trim();
  // Constant-time over fixed-length digests (round D, informational). A timing oracle on
  // a random token was never practical; this costs nothing and removes the question.
  return given.length > 0 && timingSafeEqual(digest(given), digest(OPERATOR_TOKEN));
};
const requireOperator = (req, res) => {
  if (!OPERATOR_TOKEN) {
    res.status(503).json({
      error: `VEILCORE_OPERATOR_TOKEN is not set (or is shorter than ${OPERATOR_TOKEN_MIN} characters, which counts as not set), so registry operations are disabled; it must be at least ${OPERATOR_TOKEN_MIN} characters`,
    });
    return false;
  }
  if (!isOperator(req)) {
    res.status(401).json({ error: 'registry operator token required' });
    return false;
  }
  return true;
};
// The registry's clock. A test can move it (VEILCORE_TEST_CLOCK=on, below): only so a browser
// test can see a license notice's cure period run out against a real registry. Never on a
// deployed registry: it refuses to start on Railway with it set.
let testClockOffset = 0;
const now = () => Date.now() + testClockOffset;
/** A request from this machine itself, by the socket's own address (never a forwarded header). */
const isLoopback = (addr) => addr === '127.0.0.1' || addr === '::1' || addr === '::ffff:127.0.0.1';
if (process.env.VEILCORE_TEST_CLOCK !== undefined) {
  // Refused on Railway, and on any registry set up for mainnet, wherever it runs (review round 3, M2).
  if (
    process.env.VEILCORE_TEST_CLOCK !== 'on' ||
    Object.keys(process.env).some((k) => k.startsWith('RAILWAY_')) ||
    String(process.env.VEILCORE_ANCHOR_NETWORK ?? '').trim().toLowerCase() === 'mainnet'
  ) {
    console.error('FATAL: VEILCORE_TEST_CLOCK is for browser tests on a laptop only ("on"), never on a deployed or mainnet registry.');
    process.exit(1);
  }
  console.log('TEST CLOCK ON: POST /__test/clock moves this registry\'s clock, from this machine only. Never deploy this.');
  /** Moves the clock: { offsetMs } from the real time (an integer, at most 400 days either way). Loopback only. */
  app.post('/__test/clock', (req, res, next) => (isLoopback(req.socket.remoteAddress) ? next() : res.status(404).json({ error: 'not found' })), express.json(), (req, res) => {
    const off = req.body?.offsetMs;
    if (!Number.isSafeInteger(off) || Math.abs(off) > 400 * 86_400_000) return res.status(400).json({ error: 'offsetMs must be an integer' });
    testClockOffset = off;
    res.json({ now: now() });
  });
}
/** ?limit= and ?offset= for a public listing: a caller never chooses an unbounded response. */
const pageOf = (q, def, max) => ({
  limit: Math.min(Math.max(Number.parseInt(q?.limit, 10) || def, 1), max),
  offset: Math.max(Number.parseInt(q?.offset, 10) || 0, 0),
});

/**
 * Readiness, for Railway's health check. It answered { ok: true } whether or not the
 * lineage, transfer, batch, attester and embed modules had loaded, so a deploy on which
 * every route but /api/records answered 503 looked healthy (deep dive, 8 Oct 2026). Now
 * 200 only when everything is loaded; 503 while starting, and for good if a module failed
 * (the deploy log says which and why). Names only: no error text, no paths.
 *
 * Ready also means every load has finished. Prove requests and lab results load after the
 * attester registry, in the same chain, so every part above was there a moment before
 * they were, and /health said ok while their routes still answered 503 (found 15 Oct 2026:
 * a slow disk read of either module was enough). They are not in the list because a lab
 * results folder that can't be used turns off lab results only, not the whole registry.
 */
/**
 * `features` names what this build serves, for the site's deploy preflights: they refuse to
 * deploy a site build against a registry that lacks something it uses (sealed records
 * CONTRACT.md #13). Lab results are listed only once their routes answer: a results folder
 * that can't be used turns them off.
 */
const featuresServed = () => [
  'sealed-records-v1',
  ...(labResults ? ['lab-results-v1'] : []),
  'animal-profile-v1',
  'strain-profile-v1',
  // Document records (lineage/document-profile.mjs, draft): stored, recomputed, and named as a
  // document on a check page (subjectKind).
  'document-profile-v1',
  // GET /transfers/:id/offer: the holder who claimed a delivery reads its offer again, to
  // finish receiving a record left as a stub (sealed records round 2, CONTRACT.md #22).
  'claimant-offer-v1',
  // Sample details sealed with the delivery's offer key, `_sc2_` receipts (sealed records
  // round 3, CONTRACT.md #27). A site that seals them needs a registry that stores boxes.
  'sealed-custody-v1',
  // PUT /api/records takes a public `rev` and refuses an older copy by id, with code
  // "older-copy" (round 3, L2). A site that sends `rev` needs a registry that keeps it: an
  // older one refuses the unknown field and the whole save fails.
  'record-rev-v1',
  // A record is corrected once (corrections.js): a second correction of a record is refused by
  // id, with code "already-corrected" and status 409 in its `rejected` entry.
  'one-correction-v1',
  // PUT /api/licenses takes a public `rev` too and refuses an older copy of an agreement by
  // id, with code "older-copy" (round 4, F1). A site that sends it needs a registry that
  // keeps it: an older one refuses the unknown field.
  'license-rev-v1',
  // A record's name is sealed (round 5, CONTRACT.md #28): a save with a clear `strainName` is
  // refused, public answers give a name only from the holder's `name` grant (or a row saved
  // before this, until it is saved again), and a claim's stub carries none. A site that seals
  // the name needs a registry that stores rows without one: an older one refuses the save.
  'sealed-name-v1',
  // A DNA report is published only bound (round 5, CONTRACT.md #29): grant value
  // `dnaPairBinding`, never the file's SHA-256 or its pairing fingerprint. A site that sends
  // the binding needs a registry that takes it: an older one refuses the unknown value.
  'dna-pair-binding-v1',
  // Who bred it as a fact a holder may share (persona review, 17 Oct): grant key `bred-by`,
  // value `bredBy`. A site that offers it needs a registry that takes it: an older one
  // refuses the unknown key's value and nothing is shared.
  'bred-by-grant-v1',
  // A record may carry `nameCode`, the salted code of its name (round 6, CONTRACT.md #33),
  // served publicly so a check page can tell whether the name in a link is the record's. A site
  // that publishes it needs a registry that takes it: an older one refuses the unknown field.
  'name-code-v1',
  // Lab report signatures (round 6, CONTRACT.md #34): one made since signs a code bound with
  // the record's proof code and a salt only the sender and the lab hold (its id ends in
  // `_ld1`), and is served whole. One made before signs the report's plain SHA-256: served
  // whole only to the delivery's sender and lab (holder key), and publicly only as "a lab
  // signed a report for this record" with its date.
  'lab-doc-binding-v1',
  // Dating first (CONTRACT.md #38): PUT /api/records/dating takes a record's proof code alone,
  // before its locked copy, so the record goes into the next batch at once; the locked copy
  // later must carry the same proof code. A site that dates first needs a registry that takes it.
  'dating-first-v1',
  // Paid plans (billing.js): listed only while BILLING=on and fully configured, so a site built
  // with paid plans (VITE_PAID_PLANS=on) refuses to deploy against a registry without them.
  ...(billing.enabled ? ['billing-v1'] : []),
  // Lab signatures are private (8 Nov 2026, README "Lab signatures: who sees them"): lab reports,
  // receipts and a lab key's other signatures are served only to the holder, the delivery's
  // parties and the lab, and /verify answers the ones the holder shares (grant value
  // `sharedAttestations`). A site deploy needs a registry that says so: the site's check page
  // reads them from there, and the old one says no lab signed when it gets none.
  'private-lab-signatures-v1',
  // The signatures a proof code's holder shares are answered on /attestations/subject too (12
  // Nov 2026, sharedOnFingerprint): the site's claim check page names a plant only by proof
  // code, and reads the lab's shared report there. Without it that page can't name the lab.
  'shared-by-proof-code-v1',
  // PUT/DELETE /api/records/:id/license-notices/:ref and `licenseNotices` on /verify/:id: a
  // record's holder says a royalty statement is overdue, or a license was revoked for
  // non-payment, with a date and nothing else (the site's veilcore/license-notices.ts).
  'license-notices-v1',
  // License notices tied to the deal's statement (license notices, in this file): a notice of
  // breach dated by this registry, "revoked for non-payment" refused until the cure period has
  // run out by this registry's clock with nothing paid on file, and the licensee's own signed
  // answer (paid or disputed, POST /license-answers) beside the line, which the licensor can't
  // remove. A site that publishes notices needs this: the v1 shape alone is refused.
  'license-notices-v2',
  // License notices signed with the deal's licensor key, on one record per statement; a notice
  // of breach only for a statement the licensee registered (its due date, signed with their deal
  // key), from the day after that date; POST /license-answers/lookup (review round 3, B2, L1). A
  // site that publishes notices needs this: the unsigned v2 shape is refused.
  'license-notices-v3',
  // A deleted record stays deleted (tombstones.js): saves and dating rows of its id are refused
  // with code "deleted", and /verify/:id answers `deleted: true`. The site's delete needs it.
  'record-tombstones-v1',
  // POST/GET /license-invites (lineage/license-invites.mjs): the mailbox a real two-party
  // license needs between issuer and licensee. A site that makes real licenses needs it.
  ...(licenseInvites ? ['license-invites-v1'] : []),
  ...(deals ? ['deals-v1'] : []),
  ...(paymentReceipts ? ['payment-receipts-v1'] : []),
  ...(passkeyVault ? ['passkey-vault-v1'] : []),
  // The account copy (lineage/account-copy.mjs): one locked copy of a person's keys, opened by
  // several ways in, saved by itself. A site that saves it needs a registry with these routes.
  ...(accountCopies ? ['account-copy-v1'] : []),
  // A lab's key on its own website (lineage/lab-domain.mjs): did:web documents read too, and a
  // key the website stopped listing served as `domainWithdrawn`. A site reads both if present.
  'lab-domain-withdrawn-v1',
  // A timestamp of its own for each new proof code (lineage/record-stamps.mjs): GET
  // /proof/:commitment/instant answers the RFC 3161 token, "queued", or "batch" (its batch's
  // token dates it instead). Listed whether or not a TSA is set: without one every answer is
  // 404 and the site shows nothing. A site that reads it needs a registry with the route.
  ...(recordStamps ? ['record-timestamp-v1'] : []),
];
app.get('/health', (_req, res) => {
  // licenseChecks: what checking a signed license notice or answer needs (license notices, below).
  const parts = { conformance, embed, lineage, transfers, batches, attesters, licenseInvites, deals, paymentReceipts, passkeyVault, accountCopies, licenseChecks: licenseChecksReady() };
  const notReady = Object.keys(parts).filter((k) => !parts[k]);
  if (notReady.length === 0 && loadsRunning === 0) return res.json({ ok: true, features: featuresServed() });
  res.status(503).json({ ok: false, status: loadsRunning > 0 ? 'starting' : 'failed', notReady, features: featuresServed() });
});

/**
 * The public shape of a `supersedes` block: which record, which fields changed, when
 * (sealed.js). It used to be echoed verbatim, so whatever JSON a holder put there — the
 * private reason text for a correction, or half a megabyte of anything — went to every
 * stranger with the id (attack round 11). A sealed record may carry only these three in
 * the clear; a legacy row may still hold more, and this keeps it from being served.
 */
const {
  ID_PATTERN, RECORD_MAX_BYTES, SERVER_KEPT_FIELDS, OLDER_COPY, olderCopyRefusal, recordRowProblem, licenceRowProblem, boxOf, publicSupersedes,
  registryAttestation, NAME_IN_CLEAR, hasClearName,
  DATING_MAX_PER_REQUEST, datingRowProblem, isDatingOnlyBody, datingBodyOf, DIFFERENT_DATED_FINGERPRINT,
} = require('./sealed.js');

/**
 * `supersededBy` as the public may see it: only when the correction it names is held by
 * the same holder (or not stored at all). A pointer at someone else's record is how an
 * attacker who squatted a correction id made a victim's record say "corrected — see
 * mine" (attack round 11). Writes now refuse that; this also covers rows stored before.
 */
const holderOfId = db.prepare('SELECT holder_key FROM records WHERE id = ?');
const publicSupersededBy = (r, holderKey) => {
  if (typeof r.supersededBy !== 'string' || !r.supersededBy || r.supersededBy.length > 128) return undefined;
  const target = holderOfId.get(r.supersededBy);
  if (target && holderKey && target.holder_key !== holderKey) return undefined;
  return r.supersededBy;
};

/**
 * What anyone may learn about a record from its id. Read only from the record's public
 * fields, never from anything else in the body: a sealed record has nothing else readable,
 * and a legacy plaintext row's notes, parents, method and nonce are the holder's.
 */
// An animal record (lineage/animal-profile.mjs, the site's docs/animal-profile.md): sealed
// under this profile, its name is the animal's and its parents are a sire and a dam.
const ANIMAL_PROFILE = 'veilcore/profile/animal-individual/v1';
const isAnimalRecord = (r) => r?.profile === ANIMAL_PROFILE;
// A strain or line record (lineage/strain-profile.mjs): a microbial strain, cell line or insect line.
const STRAIN_PROFILE = 'veilcore/profile/strain/v1';
const isStrainRecord = (r) => r?.profile === STRAIN_PROFILE;
// A document record (lineage/document-profile.mjs): a permit, a COA, a contract, sealed by its files.
const DOCUMENT_PROFILE = 'veilcore/profile/document/v1';
const isDocumentRecord = (r) => r?.profile === DOCUMENT_PROFILE;

/**
 * The record's name as anyone with its id may see it (round 5, CONTRACT.md #28): only what its
 * holder published on purpose with the `name` grant, and only while that value was taken
 * from the record as it is now (dropStale takes a stale `name` out of `granted`). A row saved
 * before names were sealed still has its name in the clear, as every such row always showed
 * it; that goes when the holder's browser saves the row again, sealed. Otherwise none: the
 * holder's check link carries the name after the #, which never reaches this registry.
 */
const publicName = (r, granted, values) => {
  if (granted.has('name') && typeof values?.name === 'string') return values.name;
  return hasClearName(r) && typeof r.strainName === 'string' ? r.strainName : undefined;
};

const publicView = (row, granted = new Set(), values = {}) => {
  const r = JSON.parse(row.body);
  const name = publicName(r, granted, values);
  return {
    found: true,
    id: r.id,
    // The record's name (a plant's cultivar or an animal's name), only when its holder
    // published it (publicName); for an animal, `subjectKind: 'animal'` says so, so a check
    // page labels it as an animal. Absent: a plant.
    ...(name !== undefined ? { cultivar: name } : {}),
    ...(isAnimalRecord(r)
      ? { subjectKind: 'animal' }
      : isStrainRecord(r)
        ? { subjectKind: 'strain' }
        : isDocumentRecord(r)
          ? { subjectKind: 'document' }
          : {}),
    recordFingerprint: r.recordFingerprint,
    // The name's salted code (round 6, CONTRACT.md #33): SHA-256 of "veilcore:name:v1", the
    // name, the proof code and a salt that only the holder's check link carries (after the #,
    // `ns`). It tells a check page whether the name in a link is the record's; without the salt
    // it says nothing about the name.
    ...(typeof r.nameCode === 'string' && /^[0-9a-f]{64}$/.test(r.nameCode) ? { nameCode: r.nameCode } : {}),
    // The holder's own statement of when it was logged. Committed, so it cannot change
    // after storage, but the holder chose it, and whether a stranger sees it is theirs to
    // decide: it is the same date the `sealed-at` grant governs, and printing it here
    // regardless made that grant decorative (round D). Answered from the grant's values,
    // never the body.
    ...(granted.has('sealed-at') ? { loggedAtClaimedByHolder: values.loggedAt ?? null } : {}),
    // When this registry first received THIS fingerprint. The registry's word, not a
    // ledger's. Reset whenever the stored fingerprint changes (see PUT /api/records), so
    // it never vouches for content the registry had not yet seen.
    registryFirstSeen: row.first_seen ? new Date(row.first_seen).toISOString() : null,
    supersededBy: publicSupersededBy(r, row.holder_key),
    supersedes: publicSupersedes(r.supersedes),
  };
};

/**
 * Whether a record carries a signed, unretracted attestation, and whether one is from a
 * vetted key. Nothing a holder typed counts. Two indexed lookups: this used to load every
 * attestation on the record, and anyone could add as many as they liked (round D).
 */
const attestationSummary = (fingerprint) =>
  attesters && fingerprint ? attesters.summaryFor(fingerprint) : { signed: false, vetted: false };

// ---- holder-controlled disclosure (round D) ----
//
// The disclosure vocabulary the app uses (bboard-ui/src/veilcore/disclosure.ts), and the
// older names links were made with before it. Both spellings are accepted everywhere.
// `individual-id` (an animal's individual ID and its scheme) is new with animal records; its
// "older" name is only for the `disclosed` list, which uses older names throughout.
// `name` (round 5, CONTRACT.md #28): the record's name, off unless its holder turns it on; it
// has no older name, and is listed as `name` in `disclosed` too. Last, in the order the site
// lists the keys (its saveGrant compares the two in order).
// `bred-by` (persona review, 17 Oct): who bred it, as the holder wrote it, off unless the holder
// turns it on, so a buyer can see who the material is from. Last, after `name`, in the order
// the site lists the keys. No older name: `disclosed` lists it as `bredBy`.
const DISCLOSURE_KEYS = ['existence', 'attestation-status', 'descent-clean', 'sealed-at', 'parent-names', 'breeding-method', 'individual-id', 'name', 'bred-by'];
const LEGACY_DISCLOSURE = {
  own: 'existence', dna: 'attestation-status', lineage: 'descent-clean', sealed: 'sealed-at',
  parents: 'parent-names', method: 'breeding-method', individualId: 'individual-id', name: 'name', bredBy: 'bred-by',
  others: 'holder-portfolio', agreementTerms: 'terms-full',
};
const CURRENT_TO_LEGACY = Object.fromEntries(Object.entries(LEGACY_DISCLOSURE).map(([l, c]) => [c, l]));
/** Facts about the HOLDER rather than the record. Never granted, never answered. */
const NEVER_DISCLOSED = ['holder-portfolio', 'terms-full'];
const NEVER_DISCLOSED_REASON = 'these disclosed facts about the holder rather than this record, and are never answered';
const toCurrent = (k) => LEGACY_DISCLOSURE[k] ?? k;
const inOrder = (set) => DISCLOSURE_KEYS.filter((k) => set.has(k));

const grantRow = db.prepare('SELECT show, holder_key, updated_at, grant_values, for_fingerprint FROM disclosure_grants WHERE record_id = ?');
const parsedOr = (json, fallback) => {
  if (typeof json !== 'string') return fallback;
  try { return JSON.parse(json); } catch { return fallback; }
};
/**
 * What the holder of this record has granted: the keys, as current names, the values the
 * holder sent with them (null for a grant made before values existed), and the record
 * fingerprint those values were taken from. Nothing stored: nothing granted.
 */
const grantFor = (row, id) => {
  const g = grantRow.get(id);
  // A grant made by whoever held this id before does not speak for the holder now.
  if (!g || g.holder_key !== row.holder_key) return { show: new Set(), values: null, forFingerprint: null };
  const show = parsedOr(g.show, []);
  const values = parsedOr(g.grant_values, null);
  return {
    show: new Set(Array.isArray(show) ? show.filter((k) => DISCLOSURE_KEYS.includes(k)) : []),
    values: values && typeof values === 'object' && !Array.isArray(values) ? values : null,
    forFingerprint: typeof g.for_fingerprint === 'string' ? g.for_fingerprint : null,
  };
};

/**
 * Grant values (sealed records). The registry can't read a sealed record, so a key whose
 * answer comes from the record's contents is answered from what the holder sent with the
 * grant, and only while those values were taken from the record as it is now: the grant's
 * forFingerprint equals the record's current fingerprint. A record changed since (or a
 * grant made before values existed) leaves those values stale: the key is listed under
 * `staleGrant` and its holder-written answer is left out, until the holder's browser sends
 * the grant again.
 *
 * Only what the holder wrote goes stale. existence and descent-clean are the registry's own
 * facts. attestation-status is mostly the registry's own facts too (signed and vetted
 * attestations, lab receipts and their custody differences): those are always answered
 * while the key is granted, and only its DNA pairing values (dnaPairedByHolder,
 * dnaPairBinding) go stale. sealed-at, parent-names, breeding-method, individual-id and name
 * are nothing but the holder's values, so a stale one is answered with nothing at all.
 */
const VALUE_KEYS = ['attestation-status', 'sealed-at', 'parent-names', 'breeding-method', 'individual-id', 'name', 'bred-by'];
/** Keys answered from the holder's values alone: stale, they are taken out of the answer. */
const HOLDER_ONLY_KEYS = ['sealed-at', 'parent-names', 'breeding-method', 'individual-id', 'name', 'bred-by'];
/**
 * Each value field and the key it answers (CONTRACT.md #7). Round 5: `name` (#28), and the DNA
 * report only as `dnaPairBinding` (#29): H("veilcore:v1:dnapair", the report's SHA-256, the
 * record's identity, the record's pairing salt), which says nothing about the file without the
 * salt. The salt travels only in the holder's check link, after the #, so someone the holder
 * sends the link and the file to can check the match, and nobody else can tell whether they
 * hold the same file.
 */
const VALUE_FIELDS = {
  loggedAt: 'sealed-at',
  parents: 'parent-names',
  breedingMethod: 'breeding-method',
  individualId: 'individual-id',
  idScheme: 'individual-id',
  dnaPairBinding: 'attestation-status',
  custodySummary: 'attestation-status',
  sharedAttestations: 'attestation-status',
  name: 'name',
  bredBy: 'bred-by',
};
/**
 * Value fields no grant may publish any more (round 5, CONTRACT.md #29): the DNA report's plain
 * SHA-256, and its pairing fingerprint (the contract's commit over it), which anyone holding
 * the same file can compute and compare. Grants stored with them are answered without them
 * (only "a report is saved") until the holder's app sends them again in the bound form.
 */
/** Most signatures one grant publishes (lineage/attesters.mjs SHARED_MAX). */
const SHARED_MAX = 50;
const UNSALTED_DNA_VALUES = ['dnaFileSha256', 'dnaFingerprint'];
/** String limits on grant values: those a record's fields had before they were sealed. */
const GRANT_VALUE_LIMITS = {
  loggedAt: 64, breedingMethod: 5_000, individualId: 500, idScheme: 500, name: 500, bredBy: 500,
};
const PARENT_VALUE_LIMITS = { name: 500, role: 16, individualId: 500 };
const GRANT_VALUES_MAX_BYTES = 64 * 1024;
const MAX_PARENTS = 100;

/**
 * `custodySummary` (sealed records round 3, CONTRACT.md #27): what the holder's app worked
 * out about each lab receipt over sealed sample details, which this registry can't open:
 * per receipt id, covered | changed | not-covered and the names of the fields that differ.
 * Only computed values: anything else, a field's value above all, is refused.
 */
const CUSTODY_SUMMARY_STATES = ['covered', 'changed', 'not-covered'];
const CUSTODY_FIELD_NAMES = ['sampleId', 'sealNumber', 'takenFrom', 'takenOn', 'witness', 'sealIntact', 'arrivedOn', 'condition', 'labRef'];
const custodySummaryOf = (v) => {
  if (!Array.isArray(v) || v.length > 100) return { error: 'values.custodySummary must be a list of at most 100' };
  const out = [];
  for (const e of v) {
    if (!e || typeof e !== 'object' || Array.isArray(e)) return { error: 'each of values.custodySummary must be an object' };
    for (const k of Object.keys(e)) {
      if (!['receiptAttestationId', 'covered', 'differingFields'].includes(k)) {
        return { error: `values.custodySummary[].${k} is not published; an entry is { receiptAttestationId, covered, differingFields }` };
      }
    }
    if (typeof e.receiptAttestationId !== 'string' || !e.receiptAttestationId || e.receiptAttestationId.length > 200) {
      return { error: 'values.custodySummary[].receiptAttestationId must be an attestation id' };
    }
    if (!CUSTODY_SUMMARY_STATES.includes(e.covered)) {
      return { error: `values.custodySummary[].covered must be one of ${CUSTODY_SUMMARY_STATES.join(', ')}` };
    }
    const fields = e.differingFields ?? [];
    if (!Array.isArray(fields) || fields.some((f) => !CUSTODY_FIELD_NAMES.includes(f)) || new Set(fields).size !== fields.length) {
      return { error: `values.custodySummary[].differingFields must list field names (${CUSTODY_FIELD_NAMES.join(', ')}), each once, never their values` };
    }
    out.push({ receiptAttestationId: e.receiptAttestationId, covered: e.covered, differingFields: [...fields] });
  }
  return { value: out };
};

/**
 * The granted keys (in `on`) whose holder-written values are stale, in order. The
 * holder-only ones are taken out of `on`; attestation-status stays in (its registry facts are
 * still answered) and `pairingStale` says its DNA pairing values must not be.
 */
const dropStale = (on, grant, r) => {
  const current = grant.values !== null && typeof r.recordFingerprint === 'string' && grant.forFingerprint === r.recordFingerprint;
  if (current) return { stale: [], pairingStale: false };
  const stale = VALUE_KEYS.filter((k) => on.has(k));
  for (const k of HOLDER_ONLY_KEYS) on.delete(k);
  return { stale: inOrder(new Set(stale)), pairingStale: on.has('attestation-status') };
};

/**
 * The values a holder sent with a grant, checked: { values } as stored, or { error }. Only
 * for keys being granted. A parent's linked record id is the holder's and is dropped: no
 * public answer uses it, and descent goes by fingerprint.
 */
const grantValuesOf = (input, granted) => {
  if (input === undefined || input === null) return { values: {} };
  if (typeof input !== 'object' || Array.isArray(input)) return { error: 'values must be an object' };
  if (JSON.stringify(input).length > GRANT_VALUES_MAX_BYTES) return { error: `values may be at most ${GRANT_VALUES_MAX_BYTES} bytes` };
  const out = {};
  for (const [k, v] of Object.entries(input)) {
    if (UNSALTED_DNA_VALUES.includes(k)) {
      return { error: `values.${k} is no longer published: send dnaPairBinding, the report's SHA-256 bound with the record's pairing salt` };
    }
    const key = VALUE_FIELDS[k];
    if (!key) return { error: `values.${k} is not a value a grant publishes; they are ${Object.keys(VALUE_FIELDS).join(', ')}` };
    if (!granted.has(key)) return { error: `values.${k} is accepted only with the ${key} grant` };
    if (v === undefined || v === null) continue;
    if (k === 'parents') {
      if (!Array.isArray(v) || v.length > MAX_PARENTS) return { error: `values.parents must be a list of at most ${MAX_PARENTS}` };
      const parents = [];
      for (const p of v) {
        if (!p || typeof p !== 'object' || Array.isArray(p)) return { error: 'each of values.parents must be an object' };
        const clean = {};
        for (const [pk, pv] of Object.entries(p)) {
          if (pk === 'recordId') continue;
          const max = PARENT_VALUE_LIMITS[pk];
          if (max === undefined) return { error: `values.parents[].${pk} is not published; a parent is { name, role, individualId }` };
          if (pv === undefined || pv === null) continue;
          if (typeof pv !== 'string' || pv.length > max) return { error: `values.parents[].${pk} must be a string of at most ${max} characters` };
          clean[pk] = pv;
        }
        if (typeof clean.name !== 'string') return { error: 'each of values.parents needs a name' };
        parents.push(clean);
      }
      out.parents = parents;
    } else if (k === 'custodySummary') {
      const c = custodySummaryOf(v);
      if (c.error) return { error: c.error };
      out.custodySummary = c.value;
    } else if (k === 'sharedAttestations') {
      // Which signatures the holder publishes on /verify (8 Nov 2026). Shape here; that each
      // is about this record and one this holder can see is checked by the route.
      if (!Array.isArray(v) || v.length > SHARED_MAX || new Set(v).size !== v.length ||
          !v.every((id) => typeof id === 'string' && id.length > 0 && id.length <= 200)) {
        return { error: `values.sharedAttestations must be a list of at most ${SHARED_MAX} different attestation ids` };
      }
      out.sharedAttestations = [...v];
    } else if (k === 'dnaPairBinding') {
      if (typeof v !== 'string' || !/^[0-9a-f]{64}$/.test(v)) return { error: 'values.dnaPairBinding must be 64 lowercase hexadecimal characters' };
      out.dnaPairBinding = v;
    } else if (k === 'loggedAt' && typeof v === 'number') {
      // The app's own records keep the date as milliseconds; others as text.
      if (!Number.isFinite(v)) return { error: 'values.loggedAt must be a finite number or a string' };
      out.loggedAt = v;
    } else {
      const max = GRANT_VALUE_LIMITS[k];
      if (typeof v !== 'string' || v.length > max) return { error: `values.${k} must be a string of at most ${max} characters` };
      out[k] = v;
    }
  }
  return { values: out };
};

/**
 * What a public request may see: the holder's grant, narrowed by ?show= when the caller
 * gives one. ?show= can only remove; a key the holder did not grant is reported back in
 * `notGranted` and answered with nothing.
 */
const effectiveDisclosure = (granted, show) => {
  if (show === undefined) return { on: granted, notGranted: [], refused: [] };
  const asked = new Set(String(show).split(',').map((k) => k.trim()).filter(Boolean).slice(0, 20).map(toCurrent));
  return {
    on: new Set([...asked].filter((k) => granted.has(k))),
    notGranted: inOrder(new Set([...asked].filter((k) => DISCLOSURE_KEYS.includes(k) && !granted.has(k)))),
    refused: NEVER_DISCLOSED.filter((k) => asked.has(k)),
  };
};

// ---- records, scoped to the holder ----

/**
 * Reading a holder's records or licences (deep dive, 8 Oct 2026, HIGH). It returned the
 * whole set in one answer, and a set could be ~640 MB.
 *
 *   ?limit=&cursor=   a page: { records|licenses: [...], nextCursor, limit }, in id order,
 *                     at most 100 items and about 1 MB; pass nextCursor back for the next
 *                     page (null at the end). Id order, so a save between pages cannot
 *                     make a page skip or repeat anything.
 *   neither           the plain array the app reads today, newest first, at most 1000
 *                     items and about 4 MB. When cut, X-VeilCore-Truncated: true, and the
 *                     rest is reachable by paging. Limited per holder key and per address,
 *                     like the export.
 */
const LIST_PAGE = { default: 100, max: 100, bytes: 1024 * 1024 };
/**
 * Whole-set reads: at most 30 a minute per holder key (per collection), and per address at
 * most WHOLE_SET_READ_BYTES_PER_MINUTE (default 64 MB) served. Round 1 limited an address
 * to 60 reads a minute; the site reloads every 30 s and shows "no records" for any
 * refusal, so a few dozen people behind one NAT would have seen their records vanish
 * (round 2). Real sets are small, so a byte budget leaves them alone and still stops one
 * address pulling large sets over and over.
 */
const WHOLE_SET = {
  max: 1000,
  bytes: 4 * 1024 * 1024,
  perHolder: 30,
  bytesPerClientMinute: Number.parseInt(process.env.WHOLE_SET_READ_BYTES_PER_MINUTE ?? '', 10) || 64 * 1024 * 1024,
};
const wholeSetBytes = new Map();
const holderList = (table) => {
  const page = db.prepare(`SELECT id, body FROM ${table} WHERE holder_key = ? AND id > ? ORDER BY id LIMIT ?`);
  const newest = db.prepare(`SELECT id FROM ${table} WHERE holder_key = ? ORDER BY updated_at DESC, id LIMIT ?`);
  const bodyOf = db.prepare(`SELECT body FROM ${table} WHERE id = ? AND holder_key = ?`);
  return (req, res) => {
    const holder = storedKeyOf(req);
    if (!holder) return res.status(401).json({ error: 'holder key required' });
    const q = req.query ?? {};
    if (q.limit === undefined && q.cursor === undefined) {
      const minute = Math.floor(Date.now() / 60_000);
      const bucket = clientBucket(req.ip);
      const spent = wholeSetBytes.get(bucket);
      const used = spent && spent.minute === minute ? spent.bytes : 0;
      const holderOk = exportAllowed(`list:${table}:holder:${holder}`, WHOLE_SET.perHolder);
      if (!holderOk || used >= WHOLE_SET.bytesPerClientMinute) {
        return res.status(429).json({ error: 'whole-set reads are limited; page with ?limit= and ?cursor=, or try again in a minute' });
      }
      const ids = newest.all(holder, WHOLE_SET.max + 1);
      let truncated = ids.length > WHOLE_SET.max;
      const out = [];
      let bytes = 0;
      for (const { id } of ids.slice(0, WHOLE_SET.max)) {
        const row = bodyOf.get(id, holder);
        if (!row) continue;
        if (out.length > 0 && bytes + row.body.length > WHOLE_SET.bytes) { truncated = true; break; }
        bytes += row.body.length;
        out.push(JSON.parse(row.body));
      }
      boundedSet(wholeSetBytes, bucket, { minute, bytes: used + bytes }, (v) => v.minute !== minute);
      if (truncated) res.set('X-VeilCore-Truncated', 'true').set('Access-Control-Expose-Headers', 'X-VeilCore-Truncated');
      return res.json(out);
    }
    const limit = Math.min(Math.max(Number.parseInt(q.limit, 10) || LIST_PAGE.default, 1), LIST_PAGE.max);
    const cursor = typeof q.cursor === 'string' ? q.cursor.slice(0, 256) : '';
    const out = [];
    let bytes = 0;
    let lastId = null;
    let more = false;
    for (const row of page.iterate(holder, cursor, limit + 1)) {
      if (out.length === limit || (out.length > 0 && bytes + row.body.length > LIST_PAGE.bytes)) { more = true; break; }
      bytes += row.body.length;
      out.push(JSON.parse(row.body));
      lastId = row.id;
    }
    res.json({ [table]: out, nextCursor: more ? lastId : null, limit });
  };
};

app.get('/api/records', holderList('records'));

/**
 * What a holder may store (sealed records, CONTRACT.md #6; sealed.js has the rules). A
 * record is its public fields beside `sealed`; anything else at the top level is refused
 * by name, so nothing a holder typed is stored readable by mistake. New plaintext writes
 * are always refused: there is no setting that lets them back in.
 *
 * Until 16 Oct 2026 each record was checked against its commitment here (conformance.mjs)
 * and its private fields had per-field limits. Neither can be done on a box this registry
 * can't open. The holder's browser recomputes each fingerprint after opening a record and
 * refuses to save one that doesn't match; the answer says who checked
 * (integrityCheckedBy: "holder"), rather than a `verified` count that would now be untrue.
 */
/** The vault key a holder's sealed rows are under (its `kid`), or null before the first. */
const sealedKidOf = (table) => db.prepare(
  `SELECT json_extract(body, '$.sealed.kid') AS kid FROM ${table}
   WHERE holder_key = ? AND json_extract(body, '$.sealed.kid') IS NOT NULL LIMIT 1`,
);
const recordKid = sealedKidOf('records');
const licenceKid = sealedKidOf('licenses');
const vaultKidOf = (holder) => recordKid.get(holder)?.kid ?? licenceKid.get(holder)?.kid ?? null;
const DIFFERENT_VAULT_KEY = "sealed with a different vault key than this holder's other records; nothing was changed";

app.put('/api/records', (req, res) => {
  const holder = storedKeyOf(req);
  if (!holder) return res.status(401).json({ error: 'holder key required' });
  if (!Array.isArray(req.body)) return res.status(400).json({ error: 'expected an array' });
  if (req.body.length > MAX_PER_REQUEST) {
    return res.status(413).json({ error: `at most ${MAX_PER_REQUEST} records per request` });
  }
  // A record's name is sealed (round 5, CONTRACT.md #28): a save that sends it in the clear is
  // refused whole, before anything is stored, so a site that still sends it learns at once.
  if (req.body.some(hasClearName)) return res.status(400).json({ error: NAME_IN_CLEAR });
  const isMine = db.prepare('SELECT 1 FROM records WHERE id = ? AND holder_key = ?');

  // first_seen is when the registry first saw THIS content. Keeping it across an update
  // that changed the commitment let a holder store a placeholder, swap in different
  // content months later under the same id, and have /verify say the new content was
  // "unaltered since" the placeholder's date (attack round 11). The app re-saves a
  // holder's whole set on every change, so an update with the same commitment (DNA
  // paired, marked superseded, an attestation landing) keeps its date; a different
  // commitment is new content and starts again from now.
  const upsert = db.prepare(
    `INSERT INTO records (id, holder_key, body, updated_at, first_seen) VALUES (?, ?, ?, ?, ?)
     ON CONFLICT(id) DO UPDATE SET
       body = excluded.body,
       updated_at = excluded.updated_at,
       first_seen = CASE
         WHEN json_extract(records.body, '$.recordFingerprint') IS NOT NULL
          AND json_extract(records.body, '$.recordFingerprint') = json_extract(excluded.body, '$.recordFingerprint')
           THEN records.first_seen
         ELSE excluded.first_seen
       END,
       -- A correction marked as an extra one from before the one-correction rule
       -- (corrections.js) stays marked only while it still corrects the same record: one that
       -- now names another record is held to the rule like any other.
       correction_conflict = CASE
         WHEN json_extract(records.body, '$.supersedes.recordId') IS json_extract(excluded.body, '$.supersedes.recordId')
           THEN records.correction_conflict
         ELSE NULL
       END
     WHERE records.holder_key = excluded.holder_key`
  );
  // A fingerprint belongs to whoever stored it first. Before this, anyone could read a
  // record, store an exact copy under their own key, and the lineage layer would then
  // see two holders and refuse the real one everything.
  const otherHolder = db.prepare(
    // Also any key that held it before (fingerprint_holders): a fingerprint released by a
    // deletion or an edit is not free for someone else to take.
    `SELECT 1 FROM records WHERE json_extract(body, '$.recordFingerprint') = :fp AND holder_key != :holder
     UNION ALL SELECT 1 FROM fingerprint_holders WHERE fingerprint = :fp AND holder_key != :holder LIMIT 1`,
  );
  // Shape first: a row this registry would not store is that row's problem, never the
  // batch's, and is reported by id.
  const rejected = [];
  const shaped = [];
  for (const item of req.body) {
    if (!item || typeof item.id !== 'string' || !item.id) continue;
    const problem = recordRowProblem(item);
    if (problem) rejected.push({ id: item.id.slice(0, 128), reason: problem });
    else if (tombstones.isDeleted(item.id)) rejected.push(tombstones.refusal(item.id));
    else shaped.push(item);
  }

  // Count what the database actually wrote. The upsert carries
  // WHERE records.holder_key = excluded.holder_key, so a record whose id already
  // belongs to another holder conflicts, skips the update and changes nothing —
  // correctly, since one holder must not overwrite another's record. Reporting the
  // attempt as the result told that holder their record was saved when it was not,
  // and they would find out by reading it back and seeing nothing.
  //
  // Every rule that depends on what is stored is checked here, inside the one
  // synchronous transaction that writes, so no other save can come between the check and
  // the write:
  //   · supersede links name only this holder's records (attack round 11);
  //   · fingerprint first-writer (two holders racing to store one fingerprint);
  //   · one vault key per holder: a row sealed under another key could never be opened
  //     beside the others, and is most likely a second browser with a different vault;
  //   · the per-holder ceiling (two concurrent saves could each pass it; round D);
  //   · `attestation` and the received-record fields (receivedFrom, receivedFromCommitment,
  //     receivedAt, transferId): written by this registry when a transfer is claimed, never
  //     by the holder. The stored values are kept and whatever the client sent is ignored,
  //     so a holder can't type a receipt confirmation into their own record, and a re-save
  //     from a stale copy can't erase the real one. The attestation is kept only in the
  //     shape this registry writes (sealed.js registryAttestation, round 2): a lab name a
  //     holder typed into an older record, or the handle an older claim wrote, is dropped;
  //   · the per-holder byte ceiling (deep dive, 8 Oct 2026): what the holder would hold
  //     after this save, counting each record as it would be stored. A save that does not
  //     grow the set is always allowed, so a holder already over it can still re-save;
  //   · `rev` (round 3, L2): once a row is stored with a rev, a copy with a lower one (or
  //     none) is an older copy and is refused, by id, with code "older-copy" and status 409
  //     in its `rejected` entry. The browser re-sends a holder's whole set on every save, so
  //     a stale tab, or two saves arriving out of order, overwrote the newer copy here.
  //     Equal is allowed: an unchanged row is re-sent with the same rev.
  const notWritten = [];
  const storedBody = db.prepare('SELECT body FROM records WHERE id = ? AND holder_key = ?');
  // A received record's stub (a claim wrote it; the recipient hasn't sealed it yet).
  const isReceivedStub = (b) => typeof b?.receivedFrom === 'string' && !b.recordFingerprint;
  const heldCorrection = db.prepare(
    `SELECT id, body FROM records WHERE holder_key = ? AND ${CORRECTED} = ? AND correction_conflict IS NULL`,
  );
  const sameAsHeld = [];
  const relinks = []; // records linked again to the correction this holder holds of them
  const heldNow = db.prepare('SELECT COUNT(*) AS n FROM records WHERE holder_key = ?');
  const heldBytes = db.prepare('SELECT COALESCE(SUM(octet_length(body)), 0) AS n FROM records WHERE holder_key = ?');
  let written = 0;
  let toStamp = []; // { id, commitment } written with a proof code new to the record (lineage/record-stamps.mjs)
  let projectedBytes = 0;
  const capRefused = new Set(); // new ids refused for a ceiling: not stored, so nothing may name them
  const freeCorrections = new Set(); // ids that are a record's one correction: not counted on a plan
  const tx = db.transaction((items) => {
    let kid = vaultKidOf(holder);
    // One entry per id, the last copy sent (round 2): the same id several times in one
    // save was each counted against the stored row, so small copies followed by a big one
    // read as a save that shrank the set, while the big one was what got stored.
    const priorLinkBody = db.prepare('SELECT body FROM records WHERE id = ? AND holder_key = ?');
    const newLinkToDeleted = (id, field, target) => {
      const gone = tombstones.of(target);
      if (!gone) return false;
      if (gone.holder_key !== holder) return true;
      const prior = priorLinkBody.get(id, holder);
      if (!prior) return true;
      const b = JSON.parse(prior.body);
      return (field === 'supersedes' ? b.supersedes?.recordId : b.supersededBy) !== target;
    };
    const plan = new Map();
    for (const item of items) {
      // A record may only be marked superseded by a record of the same holder. Ids were
      // guessable, so an attacker stored the predicted correction id first; the victim's
      // original then pointed at the attacker's record, publicly (attack round 11).
      if (typeof item.supersededBy === 'string') {
        const target = holderOfId.get(item.supersededBy);
        if (target && target.holder_key !== holder) {
          rejected.push({ id: item.id, reason: 'supersededBy names a record that belongs to another holder; nothing was changed' });
          continue;
        }
        // A deleted id can't become a link target, or a stranger's record could publicly
        // "correct" it. A link this holder already stored is left as it was.
        if (!target && newLinkToDeleted(item.id, 'supersededBy', item.supersededBy)) {
          rejected.push(tombstones.linkRefusal(item.id, 'supersededBy'));
          continue;
        }
      }
      // The same for the other direction: a record may only claim to correct a record of
      // its own holder, or the public view would say it corrects someone else's.
      const corrected = item.supersedes?.recordId;
      if (typeof corrected === 'string') {
        const target = holderOfId.get(corrected);
        if (target && target.holder_key !== holder) {
          rejected.push({ id: item.id, reason: 'supersedes names a record that belongs to another holder' });
          continue;
        }
        if (!target && newLinkToDeleted(item.id, 'supersedes', corrected)) {
          rejected.push(tombstones.linkRefusal(item.id, 'supersedes'));
          continue;
        }
      }
      if (item.recordFingerprint && otherHolder.get({ fp: item.recordFingerprint, holder })) {
        rejected.push({ id: item.id, reason: 'this fingerprint is already registered by another holder' });
        continue;
      }
      if (kid === null) kid = item.sealed.kid;
      else if (item.sealed.kid !== kid) {
        rejected.push({ id: item.id, reason: DIFFERENT_VAULT_KEY });
        continue;
      }
      const prior = storedBody.get(item.id, holder);
      const priorBody = prior ? JSON.parse(prior.body) : {};
      // Dated first (CONTRACT.md #38): the row holds only the proof code the browser sent when
      // the record was sealed, and its batch may already be anchored. The locked copy must be
      // the record that proof code was made from: a different one is refused, so a date can't
      // be moved to other contents.
      if (isDatingOnlyBody(priorBody) && item.recordFingerprint !== priorBody.recordFingerprint) {
        rejected.push({ id: item.id, reason: DIFFERENT_DATED_FINGERPRINT });
        continue;
      }
      const rev = Number.isSafeInteger(item.rev) ? item.rev : null;
      // The newest this registry holds: the stored row's, or an earlier copy in this save.
      const earlier = plan.get(item.id);
      const held = [priorBody.rev, earlier?.rev].filter(Number.isSafeInteger);
      const heldRev = held.length ? Math.max(...held) : null;
      // A lower rev (or none) is an older copy; the same rev is taken again only as the very
      // same box (the same request sent twice). Two tabs or devices that each changed the row
      // from the same copy both send that copy's rev + 1; the second used to be taken over
      // the first, and its change lost. Now it is refused as an older copy, and that browser
      // reads the registry's copy back (sealed.js olderCopyRefusal, shared with licences).
      const heldBox = earlier && earlier.rev === heldRev ? boxOf(earlier.item.sealed) : priorBody.sealed;
      const older = olderCopyRefusal('record', item.id, rev, heldRev, heldBox, item.sealed);
      if (older) {
        rejected.push(older);
        // A record cut off from its correction (the correction stored, the record not linked to
        // it, as an older registry could leave one) is linked again by any copy that names it,
        // even an older one: only the link is taken, and the stored copy is otherwise kept.
        if (prior && typeof item.supersededBy === 'string' && typeof priorBody.supersededBy !== 'string'
            && heldCorrection.get(holder, item.id)?.id === item.supersededBy) {
          relinks.push({ id: item.id, supersededBy: item.supersededBy });
        }
        continue;
      }
      // A record's link to its correction is permanent (corrections.js SUPERSEDED_BY_LOCKED):
      // a save may not remove or change the supersededBy stored here, unless the correction it
      // names is no longer this holder's (it was removed). A stale copy at a higher rev, after
      // a lost answer, used to strip it, and the record could then never be corrected again.
      const heldLink = priorBody.supersededBy;
      if (typeof heldLink === 'string' && heldLink !== item.supersededBy
          && holderOfId.get(heldLink)?.holder_key === holder) {
        rejected.push(supersededByLockedRefusal(item.id, heldLink, item.supersededBy));
        continue;
      }
      // No name in the clear (round 5, CONTRACT.md #28): it is inside the box. A row stored
      // before keeps its clear name until this save replaces it, without one.
      const toStore = { id: item.id };
      if (rev !== null) toStore.rev = rev;
      if (item.profile !== undefined && item.profile !== null) toStore.profile = item.profile;
      if (item.recordFingerprint !== undefined && item.recordFingerprint !== null) toStore.recordFingerprint = item.recordFingerprint;
      if (item.keyBinding !== undefined && item.keyBinding !== null) toStore.keyBinding = item.keyBinding;
      // The name's salted code (round 6, CONTRACT.md #33): public, and nothing without the salt.
      if (item.nameCode !== undefined && item.nameCode !== null) toStore.nameCode = item.nameCode;
      const supersedes = publicSupersedes(item.supersedes);
      if (supersedes) toStore.supersedes = supersedes;
      if (typeof item.supersededBy === 'string') toStore.supersededBy = item.supersededBy;
      for (const k of SERVER_KEPT_FIELDS) {
        const kept = k === 'attestation' ? registryAttestation(priorBody[k]) : priorBody[k];
        if (kept !== undefined) toStore[k] = kept;
      }
      toStore.sealed = boxOf(item.sealed);
      plan.delete(item.id);
      plan.set(item.id, { item, body: JSON.stringify(toStore), prior, rev });
    }
    // The ceilings, row by row: only rows past one are refused, and the rest of the save is
    // stored, so a holder at their plan's ceiling can always save edits that keep the content
    // (DNA paired, marked superseded) even while a new record waits in their browser. The free
    // plan counts proof codes dated, so new content under an old id counts like a new record. An
    // id held by another holder isn't written here, so it counts for nothing.
    // A record's one correction doesn't count on a plan: the registry takes one correction per
    // record (corrections.js), and a correction of a correction counts, so no chain of them
    // dates new proof codes for free. A correction of a received record counts.
    const bodyTarget = (body) => {
      const t = JSON.parse(body).supersedes?.recordId;
      return typeof t === 'string' ? t : undefined;
    };
    const isPlainRecord = (id) => {
      const held = storedBody.get(id, holder);
      if (held) {
        const b = JSON.parse(held.body);
        return b.supersedes === undefined && b.receivedFrom === undefined;
      }
      const inSave = plan.get(id);
      return !!inSave && bodyTarget(inSave.body) === undefined && JSON.parse(inSave.body).receivedFrom === undefined;
    };
    const freeTargets = new Map(); // free correction id -> the record it corrects
    for (const [id, r] of plan) {
      const t = bodyTarget(r.body);
      // Free only as it first arrives: a new id, or one dated first as a bare proof code. A held
      // record turned into a correction, or a free correction given new content, dates a new
      // version and counts like any other.
      const arriving = !r.prior || isDatingOnlyBody(JSON.parse(r.prior.body));
      if (arriving && t !== undefined && t !== id && isPlainRecord(t) && billing.correctionIsFree(holder, t)) {
        freeCorrections.add(id);
        freeTargets.set(id, t);
      }
    }
    let hardRoom = MAX_PER_HOLDER - heldNow.get(holder).n;
    const room = billing.planRoom(holder);
    const fpOf = (body) => {
      const fp = JSON.parse(body).recordFingerprint;
      return typeof fp === 'string' && fp ? fp : undefined;
    };
    const countingFps = new Set(); // proof codes this save would date anew on the plan
    for (const [id, r] of [...plan]) {
      const mine = !!isMine.get(id, holder);
      if (!mine && holderOfId.get(id)) continue;
      const fp = fpOf(r.body);
      const changed = fp !== undefined && (!mine || !r.prior || fp !== fpOf(r.prior.body));
      const counts =
        changed && !freeCorrections.has(id) && !countingFps.has(fp) && !billing.wasCounted(holder, fp);
      // Sealing a received record's stub uses the slot the claim reserved for it, and is never
      // refused for the plan: the claim was allowed (or came before billing), and a plan that
      // lapsed since must not leave a received record that can never be sealed.
      const sealsStub = counts && mine && r.prior && isReceivedStub(JSON.parse(r.prior.body));
      if (sealsStub) room.room++;
      const cap = !mine && hardRoom <= 0 ? MAX_PER_HOLDER : counts && !sealsStub && room.room <= 0 ? room.cap : 0;
      if (cap) {
        plan.delete(id);
        rejected.push(capRowRefusal(id, cap));
        capRefused.add(id);
        continue;
      }
      if (!mine) hardRoom--;
      if (counts) {
        room.room--;
        countingFps.add(fp);
      }
    }
    const before = heldBytes.get(holder).n;
    let after = before;
    for (const [id, { body, prior }] of plan) {
      // An id held by someone else is not written (below), so it adds nothing.
      if (prior) after += Buffer.byteLength(body) - Buffer.byteLength(prior.body);
      else if (!holderOfId.get(id)) after += Buffer.byteLength(body);
    }
    if (after > HOLDER_MAX_BYTES && after > before) { projectedBytes = after; return 'bytes'; }
    // A record is corrected once (corrections.js), and a correction and its record are one
    // thing: neither is left behind without the other.
    //   · A correction whose record is in this save and was refused (an older copy, a locked
    //     link, anything) is not stored either: code "record-refused" (or "already-corrected"
    //     when the record holds another correction). Two tabs used to leave the correction
    //     stored and the record unlinked, and the index then refused every later correction.
    //   · A row whose supersededBy names a correction this save does not store is refused.
    //   · The unique index refuses a second correction of a record, each row in a savepoint
    //     of its own. A second copy of the held correction (the same fingerprint under another
    //     id) is not stored again and counts as saved (`existing`).
    // What the index or an id held by another holder refuses is only known on writing. When
    // that happens the writes are undone and made again with that row decided first, so every
    // rule above sees it: at most once per such row, and normally never.
    const rows = [...plan.values()];
    const targetOf = (r) => {
      const t = JSON.parse(r.body).supersedes?.recordId;
      return typeof t === 'string' ? t : undefined;
    };
    const priorTargetOf = (r) => (r.prior ? JSON.parse(r.prior.body).supersedes?.recordId : undefined);
    const sentIds = new Set(req.body.filter((x) => x && typeof x.id === 'string').map((x) => x.id));
    const relinkedIds = new Set(relinks.map((x) => x.id));
    const base = { rejected: rejected.length, notWritten: notWritten.length, same: sameAsHeld.length };
    const found = new Map(); // id -> what writing it found: { kind: 'rejected' | 'same' | 'notWritten', value }
    const writeRow = db.transaction((id, body, t) => upsert.run(id, holder, body, t, t));
    const relink = db.prepare("UPDATE records SET body = json_set(body, '$.supersededBy', ?), updated_at = ? WHERE id = ? AND holder_key = ?");
    const REDO = Symbol('redo');
    const attempt = db.transaction(() => {
      rejected.length = base.rejected;
      notWritten.length = base.notWritten;
      sameAsHeld.length = base.same;
      written = 0;
      // Refused in this save: shape and plan refusals (a relinked record's content is refused,
      // but it is linked to its correction, so its correction is not refused for it).
      const refused = new Set(rejected.map((x) => x.id).filter((id) => !relinkedIds.has(id)));
      const notStored = new Set(capRefused); // ids in this save this registry will not hold
      const decided = new Set();
      const decide = (r, out) => {
        const id = r.item.id;
        if (out.kind === 'rejected') rejected.push(out.value);
        else if (out.kind === 'notWritten') notWritten.push(id);
        else { sameAsHeld.push(out.value); written++; } // saved: the one held is this correction
        if (out.kind !== 'same') refused.add(id);
        if (!r.prior || out.kind === 'notWritten') notStored.add(id);
        decided.add(id);
      };
      for (const r of rows) if (found.has(r.item.id)) decide(r, found.get(r.item.id));
      for (let changed = true; changed;) {
        changed = false;
        for (const r of rows) {
          const id = r.item.id;
          if (decided.has(id)) continue;
          const target = targetOf(r);
          // A new correction (or one now naming another record) of a record refused in this save.
          if (target !== undefined && target !== priorTargetOf(r) && sentIds.has(target) && refused.has(target)) {
            const held = heldCorrection.get(holder, target);
            const why = rejected.find((x) => x.id === target)?.code ?? (notWritten.includes(target) ? 'not-written' : 'refused');
            decide(r, { kind: 'rejected', value: held && held.id !== id ? alreadyCorrectedRefusal(id, target, held.id) : recordRefusedRefusal(id, target, why) });
            changed = true;
            continue;
          }
          if (typeof r.item.supersededBy === 'string' && notStored.has(r.item.supersededBy)) {
            // Its own correction, as this registry holds it (the one to correct instead), if any.
            decide(r, { kind: 'rejected', value: alreadyCorrectedRefusal(id, id, heldCorrection.get(holder, id)?.id ?? null) });
            changed = true;
          }
        }
      }
      const fresh = new Map();
      const inserted = []; // ids this save added for this holder
      const writtenFps = []; // proof codes this save dated anew (countingFps that were written)
      const newProofCodes = []; // { id, commitment }: a proof code this record didn't have before, for its own timestamp
      for (const r of [...rows.filter((x) => targetOf(x) !== undefined), ...rows.filter((x) => targetOf(x) === undefined)]) {
        if (decided.has(r.item.id)) continue;
        try {
          const info = writeRow(r.item.id, r.body, now());
          if (info.changes === 0) fresh.set(r.item.id, { kind: 'notWritten' });
          else {
            written++;
            if (!r.prior) inserted.push(r.item.id);
            // Dated first as a bare proof code (counted then), now stored as a free correction.
            else if (freeCorrections.has(r.item.id) && isDatingOnlyBody(JSON.parse(r.prior.body))) {
              billing.noteFreeCorrection(holder, freeTargets.get(r.item.id), fpOf(r.body));
            }
            const fp = fpOf(r.body);
            if (fp !== undefined && countingFps.has(fp)) writtenFps.push(fp);
            if (typeof fp === 'string' && fp !== (typeof r.prior?.body === 'string' ? fpOf(r.prior.body) : undefined)) newProofCodes.push({ id: r.item.id, commitment: fp });
          }
        } catch (e) {
          if (!isSecondCorrection(e)) throw e;
          const recordId = targetOf(r);
          const held = heldCorrection.get(holder, recordId);
          const fp = r.item.recordFingerprint;
          const heldFp = held ? JSON.parse(held.body).recordFingerprint : undefined;
          fresh.set(r.item.id, held && typeof fp === 'string' && fp === heldFp
            ? { kind: 'same', value: { id: r.item.id, existingId: held.id, recordId } }
            : { kind: 'rejected', value: alreadyCorrectedRefusal(r.item.id, recordId, held?.id ?? null) });
        }
      }
      if (fresh.size) {
        for (const [id, out] of fresh) found.set(id, out);
        throw REDO;
      }
      for (const { id, supersededBy } of relinks) relink.run(supersededBy, now(), id, holder);
      billing.noteAdded(holder, writtenFps);
      for (const id of inserted) {
        if (freeTargets.has(id)) billing.noteFreeCorrection(holder, freeTargets.get(id), fpOf(plan.get(id).body));
      }
      toStamp = newProofCodes;
    });
    for (;;) {
      try {
        attempt();
        break;
      } catch (e) {
        if (e !== REDO) throw e;
      }
    }
    return 'ok';
  });
  const outcome = tx(shaped);
  // Each proof code new to its record gets a timestamp of its own (lineage/record-stamps.mjs):
  // queued only, after the save is written. Never awaited, and never a reason to fail the save.
  if (outcome === 'ok' && toStamp.length) {
    try {
      // A record whose proof code changed: the old proof code's timestamps go (TSA-4).
      for (const { id, commitment } of toStamp) recordStamps?.forgetRecord(id, commitment);
      recordStamps?.enqueue(toStamp, holder);
    } catch (e) {
      console.error('record timestamp queue failed:', e.message);
    }
  }
  if (outcome === 'bytes') {
    return res.status(413).json({
      error: `a holder may keep at most ${megabytes(HOLDER_MAX_BYTES)} of records here; this save would make it ${megabytes(projectedBytes)}. Nothing was changed.`,
    });
  }

  res.json({
    ok: rejected.length === 0 && notWritten.length === 0,
    count: written,
    // The registry can't open a sealed record, so it can't say whether its fingerprint
    // matches its contents. The holder's browser checks that when it opens the record.
    integrityCheckedBy: 'holder',
    ...(rejected.length ? { rejected } : {}),
    // Second copies of a correction this registry already holds (the same fingerprint under
    // another id): not stored again; the one held is the correction (corrections.js).
    ...(sameAsHeld.length ? { existing: sameAsHeld } : {}),
    // Records whose content was refused (an older copy) but whose link to the correction this
    // holder holds of them was missing and is now set: { id, supersededBy }.
    ...(relinks.length ? { relinked: relinks } : {}),
    ...(notWritten.length
      ? {
          notWritten,
          reason: 'these ids already belong to another holder; nothing was changed',
        }
      : {}),
  });
});

/**
 * Dating first (CONTRACT.md #38). PUT /api/records/dating takes `[{ id, recordFingerprint,
 * keyBinding? }]`: a record's proof code, sent by the holder's browser the moment the record
 * is sealed, so it goes into the next batch at once. Its locked copy follows later, once the
 * vault key is in a checked backup (round 3, L1), and must carry the same proof code (PUT
 * /api/records refuses another).
 *
 * What it does not do, on purpose:
 *   · store anything typed: there is no box, and the proof code is a salted commitment;
 *   · tie a vault key to the holder: a dating row has no `kid`, so a browser whose key never
 *     reached a backup can't lock its holder out (vaultKidOf reads only boxes);
 *   · publish more than PUT /api/records would: the same public fields, and `bodyPending`
 *     only to the holder.
 *
 * The rules PUT /api/records keeps for a proof code are kept here, in one transaction: an id
 * belongs to its first holder (notWritten), a proof code to the first holder who stored it, and
 * an id already holding a proof code keeps it (the same one again is fine, and changes
 * nothing). The per-holder count applies. A row already holding a locked copy is left as it is.
 */
const putDating = db.prepare(
  `INSERT INTO records (id, holder_key, body, updated_at, first_seen) VALUES (?, ?, ?, ?, ?)
   ON CONFLICT(id) DO NOTHING`,
);
app.put('/api/records/dating', (req, res) => {
  const holder = storedKeyOf(req);
  if (!holder) return res.status(401).json({ error: 'holder key required' });
  if (!Array.isArray(req.body)) return res.status(400).json({ error: 'expected an array of { id, recordFingerprint, keyBinding? }' });
  if (req.body.length > DATING_MAX_PER_REQUEST) {
    return res.status(413).json({ error: `at most ${DATING_MAX_PER_REQUEST} dating rows per request` });
  }
  const rejected = [];
  const notWritten = [];
  const dated = [];
  const newProofCodes = []; // dated here for the first time: each gets a timestamp of its own
  const otherHolder = db.prepare(
    // Also any key that held it before (fingerprint_holders): a fingerprint released by a
    // deletion or an edit is not free for someone else to take.
    `SELECT 1 FROM records WHERE json_extract(body, '$.recordFingerprint') = :fp AND holder_key != :holder
     UNION ALL SELECT 1 FROM fingerprint_holders WHERE fingerprint = :fp AND holder_key != :holder LIMIT 1`,
  );
  const mineBody = db.prepare('SELECT body FROM records WHERE id = ? AND holder_key = ?');
  const heldNow = db.prepare('SELECT COUNT(*) AS n FROM records WHERE holder_key = ?');
  const tx = db.transaction((items) => {
    let held = heldNow.get(holder).n;
    const room = billing.planRoom(holder);
    const seen = new Set();
    for (const item of items) {
      const problem = datingRowProblem(item);
      if (problem) {
        rejected.push({ id: typeof item?.id === 'string' ? item.id.slice(0, 128) : '?', reason: problem });
        continue;
      }
      if (seen.has(item.id)) continue;
      seen.add(item.id);
      if (tombstones.isDeleted(item.id)) {
        rejected.push(tombstones.refusal(item.id));
        continue;
      }
      const owner = holderOfId.get(item.id);
      if (owner && owner.holder_key !== holder) {
        notWritten.push(item.id);
        continue;
      }
      if (owner) {
        const body = JSON.parse(mineBody.get(item.id, holder).body);
        if (body.recordFingerprint === item.recordFingerprint) dated.push(item.id);
        else rejected.push({ id: item.id, reason: DIFFERENT_DATED_FINGERPRINT });
        continue;
      }
      if (otherHolder.get({ fp: item.recordFingerprint, holder })) {
        rejected.push({ id: item.id, reason: 'this fingerprint is already registered by another holder' });
        continue;
      }
      // A proof code that counted before (dated, then deleted) doesn't count again.
      const counts = !billing.wasCounted(holder, item.recordFingerprint);
      const cap = held + 1 > MAX_PER_HOLDER ? MAX_PER_HOLDER : counts && room.room <= 0 ? room.cap : 0;
      if (cap) {
        rejected.push(capRowRefusal(item.id, cap));
        continue;
      }
      const t = now();
      const info = putDating.run(item.id, holder, JSON.stringify(datingBodyOf(item)), t, t);
      if (info.changes === 0) notWritten.push(item.id);
      else {
        held++;
        if (counts) room.room--;
        billing.noteAdded(holder, [item.recordFingerprint]);
        dated.push(item.id);
        newProofCodes.push({ id: item.id, commitment: item.recordFingerprint });
      }
    }
  });
  tx(req.body);
  // Queued only (lineage/record-stamps.mjs): never awaited, never a reason to fail the request.
  if (newProofCodes.length) {
    try {
      recordStamps?.enqueue(newProofCodes, holder);
    } catch (e) {
      console.error('record timestamp queue failed:', e.message);
    }
  }
  res.json({
    ok: rejected.length === 0 && notWritten.length === 0,
    dated,
    ...(rejected.length ? { rejected } : {}),
    ...(notWritten.length ? { notWritten, reason: 'these ids already belong to another holder; nothing was changed' } : {}),
  });
});

/**
 * Remove records this holder owns.
 *
 * Corrections supersede rather than delete, and that is right for a record someone
 * else may be relying on. It is not right for a record a holder created by mistake
 * and nobody has ever seen: there was no way to remove one at all, which is a
 * different property from tamper-evidence and nobody asked for it.
 *
 * Scoped to the holder, like every other write here. A record already handed to a
 * counterparty is not recalled by this — they hold their copy, its commitment still
 * verifies, and any anchor still stands. What goes is this registry's copy.
 */
app.delete('/api/records', (req, res) => {
  const holder = storedKeyOf(req);
  if (!holder) return res.status(401).json({ error: 'holder key required' });
  const ids = Array.isArray(req.body?.ids) ? req.body.ids.filter((i) => typeof i === 'string') : null;
  if (!ids || ids.length === 0) return res.status(400).json({ error: 'expected { ids: [...] }' });

  const del = db.prepare('DELETE FROM records WHERE id = ? AND holder_key = ?');
  const bodyOf = db.prepare('SELECT body FROM records WHERE id = ? AND holder_key = ?');
  const delGrant = db.prepare('DELETE FROM disclosure_grants WHERE record_id = ? AND holder_key = ?');
  const delNotices = db.prepare('DELETE FROM license_notices WHERE record_id = ? AND holder_key = ?');
  // A record with a live correction would leave that correction naming a deleted record: refused,
  // as the site does. (Licence lines are the holder's own notices and go with the record; the
  // licensee's answers stay theirs. Licences themselves are sealed, so only the site can see them.)
  const correctionsOf = db.prepare(
    "SELECT id FROM records WHERE holder_key = ? AND json_extract(body, '$.supersedes.recordId') = ?",
  );
  // Deleting a correction takes the corrected record's link to it too, so nothing points at a
  // tombstone (the site's "take back a correction" deletes the correction).
  const clearLinkTo = db.prepare(
    `UPDATE records SET body = json_remove(body, '$.supersededBy'), updated_at = ?
     WHERE id = ? AND holder_key = ? AND json_extract(body, '$.supersededBy') = ?`,
  );
  const removed = [];
  const notYours = [];
  const refused = [];
  const tx = db.transaction((list) => {
    const t = now();
    const asked = new Set(list);
    for (const id of list) {
      const row = bodyOf.get(id, holder);
      if (row) {
        if (correctionsOf.all(holder, id).some((c) => !asked.has(c.id))) {
          refused.push({ id, code: 'linked', reason: 'a correction of this record still exists; delete the correction first' });
          continue;
        }
      }
      const info = row ? del.run(id, holder) : { changes: 0 };
      if (info.changes > 0) {
        removed.push(id);
        let fp = null;
        let corrects = null;
        try {
          const b = JSON.parse(row.body);
          fp = b.recordFingerprint ?? null;
          corrects = typeof b.supersedes?.recordId === 'string' ? b.supersedes.recordId : null;
        } catch {
          // A malformed body still gets its tombstone, just without a proof code.
        }
        tombstones.mark(id, holder, fp, t);
        // Its own timestamps go with it, in the same transaction (security review of PR #145,
        // TSA-4): a deleted record stays deleted, and the registry keeps less, not more.
        recordStamps?.forgetRecord(id);
        if (corrects) clearLinkTo.run(t, corrects, holder, id);
        delGrant.run(id, holder);
        delNotices.run(id, holder);
      } else notYours.push(id);
    }
  });
  tx(ids);

  // Reports what was removed rather than what was asked for. An id belonging to
  // another holder changes nothing, and saying so beats a count that looks like
  // success.
  res.json({
    ok: notYours.length === 0 && refused.length === 0,
    removed,
    ...(notYours.length ? { notRemoved: notYours, reason: 'no such record under this holder key' } : {}),
    ...(refused.length ? { refused } : {}),
  });
});

// ---- disclosure grants, same scoping ----
//
// The holder decides what a stranger with the record id sees beyond the public base. See
// README "Disclosure" for the contract the app builds against.

const ownedRecord = db.prepare('SELECT 1 FROM records WHERE id = ? AND holder_key = ?');
const ownedBody = db.prepare('SELECT body FROM records WHERE id = ? AND holder_key = ?');

/**
 * The ids a grant may publish (values.sharedAttestations, 8 Nov 2026): each a stored signature
 * about this record's current fingerprint that this holder key can see. One answer for an id
 * that doesn't exist, is about another record, or is private to someone else, so a grant
 * can't be used to find out which ids exist. null when all are fine, else the error.
 */
const unshareable = (ids, recordId, holder) => {
  if (!ids?.length) return null;
  if (!attesters) return 'values.sharedAttestations: the attester registry is not ready; try again shortly';
  const fp = parsedOr(ownedBody.get(recordId, holder)?.body, {}).recordFingerprint;
  const canSee = privateReaderFor(holder);
  for (const id of ids) {
    const a = attesters.signedFields(id);
    const ok = !!a && typeof fp === 'string' && a.subjectCommitment === fp && (!attesters.isPrivate(id) || canSee(a, { createdAt: attesters.storedAt(id) }));
    if (!ok) return `values.sharedAttestations: ${id.slice(0, 80)} is not a signature about this record that this holder key can see`;
  }
  return null;
};

// PUT body { show, forFingerprint, values } (sealed records, CONTRACT.md #7). `values` are
// what the holder's browser read from the record for the keys being granted; they are
// published as sent, and answered only while forFingerprint is the record's current
// fingerprint (dropStale above).
app.put('/api/records/:id/disclosure', (req, res) => {
  const holder = storedKeyOf(req);
  if (!holder) return res.status(401).json({ error: 'holder key required' });
  // One answer for "no such record" and "someone else's record": which ids exist is not
  // this caller's business.
  if (!ownedRecord.get(req.params.id, holder)) {
    return res.status(404).json({ error: 'no such record under this holder key' });
  }
  const show = req.body?.show;
  if (!Array.isArray(show) || show.length > 32 || !show.every((k) => typeof k === 'string' && k.length <= 64)) {
    return res.status(400).json({ error: 'expected { "show": [ ...disclosure keys ], "forFingerprint", "values" }', allowed: DISCLOSURE_KEYS });
  }
  const asked = show.map((k) => k.trim()).filter(Boolean).map(toCurrent);
  const refused = NEVER_DISCLOSED.filter((k) => asked.includes(k));
  if (refused.length) {
    return res.status(400).json({ error: `${refused.join(', ')} cannot be granted: ${NEVER_DISCLOSED_REASON}`, refused });
  }
  const unknown = [...new Set(asked.filter((k) => !DISCLOSURE_KEYS.includes(k)))];
  if (unknown.length) {
    return res.status(400).json({ error: `unknown disclosure keys: ${unknown.join(', ')}`, unknown, allowed: DISCLOSURE_KEYS });
  }
  const forFingerprint = req.body?.forFingerprint ?? null;
  if (forFingerprint !== null && (typeof forFingerprint !== 'string' || !/^[0-9a-f]{64}$/.test(forFingerprint))) {
    return res.status(400).json({ error: 'forFingerprint must be the record fingerprint the values were read from: 64 lowercase hexadecimal characters' });
  }
  const grantedSet = new Set(asked);
  const checked = grantValuesOf(req.body?.values, grantedSet);
  if (checked.error) return res.status(400).json({ error: checked.error });
  const notShareable = unshareable(checked.values.sharedAttestations, req.params.id, holder);
  if (notShareable) return res.status(400).json({ error: notShareable });
  const granted = inOrder(grantedSet);
  const t = now();
  db.prepare(`INSERT INTO disclosure_grants (record_id, holder_key, show, updated_at, grant_values, for_fingerprint) VALUES (?,?,?,?,?,?)
              ON CONFLICT(record_id) DO UPDATE SET holder_key = excluded.holder_key, show = excluded.show,
                updated_at = excluded.updated_at, grant_values = excluded.grant_values, for_fingerprint = excluded.for_fingerprint`)
    .run(req.params.id, holder, JSON.stringify(granted), t, JSON.stringify(checked.values), forFingerprint);
  res.json({ recordId: req.params.id, show: granted, forFingerprint, values: checked.values, updatedAt: new Date(t).toISOString() });
});

app.get('/api/records/:id/disclosure', (req, res) => {
  const holder = storedKeyOf(req);
  if (!holder) return res.status(401).json({ error: 'holder key required' });
  if (!ownedRecord.get(req.params.id, holder)) {
    return res.status(404).json({ error: 'no such record under this holder key' });
  }
  const g = grantRow.get(req.params.id);
  const mine = g && g.holder_key === holder;
  const grant = mine ? grantFor({ holder_key: holder }, req.params.id) : null;
  res.json({
    recordId: req.params.id,
    show: grant ? inOrder(grant.show) : [],
    forFingerprint: grant ? grant.forFingerprint : null,
    values: grant ? grant.values : null,
    updatedAt: mine ? new Date(g.updated_at).toISOString() : null,
  });
});

/**
 * Every grant this holder has made: [{ recordId, show, forFingerprint, values, updatedAt }],
 * by record id. The browser compares forFingerprint with each record's fingerprint, and
 * values with what it would publish now, after a save, and sends again the grants that
 * differ (a DNA pairing changes values without changing the fingerprint).
 */
const holderGrants = db.prepare('SELECT record_id, show, for_fingerprint, updated_at, grant_values FROM disclosure_grants WHERE holder_key = ? ORDER BY record_id');
app.get('/api/disclosures', (req, res) => {
  const holder = storedKeyOf(req);
  if (!holder) return res.status(401).json({ error: 'holder key required' });
  res.json(holderGrants.all(holder).map((g) => {
    const show = parsedOr(g.show, []);
    const values = parsedOr(g.grant_values, null);
    return {
      recordId: g.record_id,
      show: Array.isArray(show) ? inOrder(new Set(show)) : [],
      forFingerprint: g.for_fingerprint ?? null,
      // What the grant publishes now (null before grant values). A DNA pairing is outside the
      // fingerprint, so the browser compares these with what it would send, not only the
      // fingerprint, and sends the grant again when they differ.
      values: values && typeof values === 'object' && !Array.isArray(values) ? values : null,
      updatedAt: new Date(g.updated_at).toISOString(),
    };
  }));
});

// ---- license notices: overdue, notice of breach, revoked for non-payment; the licensee's answer ----
//
// A record's holder (the licensor) says publicly, about one royalty statement on a license from
// the record: it is overdue since a date; they sent a notice of breach; the license was revoked
// for non-payment. The licensee answers in their own name: paid, or disputed. Rules:
//
//   - A line is about one statement, a message in a deal held here, named by its fingerprint
//     (never public). Its `ref` is made from that fingerprint (licenseNoticeRef), so both sides
//     can name it. The deal gives both sides' deal keys (deals.mjs partiesOf).
//   - Every line is signed with the deal's LICENSOR key, over the record it goes on
//     (`veilcore/license-line/v1\n` + canonical { recordId, ...line }), as well as sent under the
//     record's holder key. So only that deal's licensor can say anything about its statements,
//     and a stranger who learned a fingerprint can't (review round 3, L1). A statement's lines
//     live on one record: the first one its licensor put a line on, until they take it off.
//   - The licensee REGISTERS each of their statements, signed with their deal key: "this is my
//     royalty statement, its payment is due on <dueOn>" (POST /license-answers, type
//     "statement"; the site does it by itself). The first registration stands.
//   - PUT body exactly { kind: "overdue" | "breach", since, statement, signature } or
//     { kind: "revoked", reason: "non-payment", on, statement, signature }: any other field, kind
//     or reason is refused, so a line never carries an amount, a name, a term or text. Dates are
//     UTC days, never after this registry's today.
//   - "overdue" is the licensor's word alone, and the public page says so. Once the due date the
//     licensee registered has passed, its "since" must be after that date.
//   - Once a notice of breach is on file, or the line is revoked, a resend of the same or an
//     earlier stage changes nothing: the date, the kind and the licensor's signature over them stay
//     (review round 4, N3).
//   - "breach" puts the overdue line up with "a notice of breach was sent", dated by THIS
//     registry the first time it is received (breach_at). It is accepted only for a statement the
//     licensee registered, and only after the due date they registered, by this registry's clock
//     (review round 3, B2): a licensor's own message can't stand in for a statement, a notice
//     can't be sent before anything was due, and the cure period can't start before the licensee
//     knew about it. Neither the licensor's device nor a resend can date it back or move it.
//   - "revoked" is accepted only with a notice of breach on file for that line, received at
//     least LICENSE_CURE_DAYS full UTC days earlier by this registry's clock, and no "paid" on
//     file for the statement: the licensee's own answer, or a vetted payment partner's receipt.
//     Otherwise 409, and the site falls back to a plain revoke that says nothing about payment.
//     Its date is fixed when first accepted: a resend doesn't move it.
//   - The licensee's answer (POST /license-answers, "paid" or "disputed") is signed with their
//     deal key and kept against the statement, first one of each type standing; the licensor can
//     neither remove nor change it. Public: only its type and date.
//   - A deal opened before the deal keys were kept here (and whose invite has expired) has no
//     keys on file: nothing about its statements can be filed or put up (code `predates`).
// Anyone with the record's id reads its lines on /verify/:id, labelled as the holder's word, with
// the licensee's answers beside them labelled as theirs. Lines from before the signature (no
// statement, or not signed) stay in the database and are never shown (review round 3, M3). At
// most LICENSE_NOTICES_MAX lines per record.

const nodeCrypto = require('node:crypto');
// veilcore-records is an ES module that other parts of this file import() while the registry
// starts. A require() of it here raced those imports and stopped the registry on Node 24
// (ERR_REQUIRE_ESM_RACE_CONDITION, review round 3, B1). It is loaded the same way as the rest,
// and the routes that need it answer 503 until it is.
let canonicalJson = null;
import('veilcore-records')
  .then((m) => { canonicalJson = m.canonicalise; })
  .catch((e) => console.error('license notices: veilcore-records unavailable:', e.message));
/** Small-order and non-canonical Ed25519 keys are refused, as for a payment partner's (attesters.mjs). */
let unusableKeyOf = null;
import('./lineage/attesters.mjs').then((m) => { unusableKeyOf = m.unusableKeyReason; }).catch((e) => console.error('license answers: key check unavailable:', e.message));
/** What checking a signed line or answer needs, loaded. */
const licenseChecksReady = () => typeof canonicalJson === 'function' && typeof unusableKeyOf === 'function';
const LICENSE_NOTICES_MAX = 20;
/** Days a licensee has to pay after a notice of breach (the site's royalty-ledger.ts CURE_DAYS). */
const LICENSE_CURE_DAYS = 30;
const NOTICE_REF = /^[0-9a-f]{32}$/;
const FP = /^[0-9a-f]{64}$/;
const SIG128 = /^[0-9a-f]{128}$/;
/** SHA-256 of the empty string: a "paid" with no payment reference at all is refused (review round 3, L5). */
const EMPTY_SHA256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
const DAY_MS = 86_400_000;
const utcDayOf = (ms) => new Date(ms).toISOString().slice(0, 10);
const startOfDay = (ms) => Math.floor(ms / DAY_MS) * DAY_MS;
const isCalendarDay = (d) => {
  if (typeof d !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(d)) return false;
  const t = Date.parse(`${d}T00:00:00Z`);
  return Number.isFinite(t) && new Date(t).toISOString().slice(0, 10) === d;
};
const isDay = (d) => isCalendarDay(d) && d <= utcDayOf(now());
/** A line's reference: 32 hex of SHA-256 over "veilcore/license-notice/v2\n" and the statement's fingerprint. */
const licenseNoticeRef = (statement) =>
  nodeCrypto.createHash('sha256').update(`veilcore/license-notice/v2\n${statement}`, 'utf8').digest('hex').slice(0, 32);
/** The first UTC day a revoked line is accepted after a notice of breach received at `breachAt`. */
const revocableFrom = (breachAt) => utcDayOf(startOfDay(breachAt) + (LICENSE_CURE_DAYS + 1) * DAY_MS);

/** Whether `sigHex` is `keyHex`'s Ed25519 signature over `bytes` (a refused key never is). */
const signedBy = (keyHex, bytes, sigHex) => {
  if (typeof keyHex !== 'string' || !FP.test(keyHex) || unusableKeyOf(keyHex)) return false;
  try {
    const key = nodeCrypto.createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(keyHex, 'hex').toString('base64url') }, format: 'jwk' });
    return nodeCrypto.verify(null, bytes, key, Buffer.from(sigHex, 'hex'));
  } catch {
    return false;
  }
};

/** What the licensor signs for a line: "veilcore/license-line/v1\n" + canonical { recordId, ...line }. */
const LICENSE_LINE_V = 'veilcore/license-line/v1';
const lineBytes = (recordId, line) => Buffer.from(`${LICENSE_LINE_V}\n${canonicalJson({ ...line, recordId })}`, 'utf8');

/** The line a body asks for, or the reason it is refused. */
const noticeOf = (b) => {
  if (!b || typeof b !== 'object' || Array.isArray(b)) return { error: 'expected a JSON object' };
  const keys = Object.keys(b).sort().join(',');
  const shape = 'expected exactly { "kind": "overdue" | "breach", "since": "YYYY-MM-DD", "statement": "<64 hex>", "signature": "<128 hex>" } or { "kind": "revoked", "reason": "non-payment", "on": "YYYY-MM-DD", "statement": "<64 hex>", "signature": "<128 hex>" }';
  if (typeof b.statement !== 'string' || !FP.test(b.statement)) return { error: shape };
  if (typeof b.signature !== 'string' || !SIG128.test(b.signature)) return { error: shape };
  const { signature, ...line } = b;
  if ((b.kind === 'overdue' || b.kind === 'breach') && keys === 'kind,signature,since,statement') {
    return isDay(b.since) ? { kind: b.kind, day: b.since, statement: b.statement, signature, line } : { error: 'since must be a UTC date, YYYY-MM-DD, not after today' };
  }
  if (b.kind === 'revoked' && keys === 'kind,on,reason,signature,statement' && b.reason === 'non-payment') {
    return isDay(b.on) ? { kind: 'revoked', day: b.on, statement: b.statement, signature, line } : { error: 'on must be a UTC date, YYYY-MM-DD, not after today' };
  }
  return { error: shape };
};
// A line counts only once its licensor signed it (line_sig): older rows stay, unseen (M3).
const noticeRows = db.prepare(`SELECT ref, holder_key, kind, day, statement, breach_at, updated_at FROM license_notices
  WHERE record_id = ? AND statement IS NOT NULL AND line_sig IS NOT NULL ORDER BY day, ref`);
const noticeRow = db.prepare('SELECT * FROM license_notices WHERE record_id = ? AND ref = ?');
const noticeCount = db.prepare('SELECT COUNT(*) AS n FROM license_notices WHERE record_id = ? AND holder_key = ? AND ref <> ?');
const putNotice = db.prepare(`INSERT INTO license_notices (record_id, ref, holder_key, kind, day, statement, breach_at, revoked_at, line_sig, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)
  ON CONFLICT(record_id, ref) DO UPDATE SET holder_key = excluded.holder_key, kind = excluded.kind, day = excluded.day,
    statement = excluded.statement, breach_at = excluded.breach_at, revoked_at = excluded.revoked_at, line_sig = excluded.line_sig, updated_at = excluded.updated_at`);
const delNotice = db.prepare('DELETE FROM license_notices WHERE record_id = ? AND ref = ? AND holder_key = ?');
/** A signed line about the same statement on another record: a statement's lines live on one record. */
const lineElsewhere = db.prepare('SELECT 1 FROM license_notices WHERE statement = ? AND line_sig IS NOT NULL AND record_id <> ? LIMIT 1');
const answerRows = db.prepare("SELECT answer, received_at FROM license_answers WHERE statement = ? AND answer IN ('paid', 'disputed') ORDER BY received_at, answer");
const answerOne = db.prepare('SELECT answer, reference_hash, due_on, signature, received_at FROM license_answers WHERE statement = ? AND answer = ?');
const putAnswer = db.prepare('INSERT INTO license_answers (statement, answer, reference_hash, due_on, signature, received_at) VALUES (?,?,?,?,?,?)');
const rowsForStatement = db.prepare(`SELECT n.record_id, n.ref, n.holder_key, n.kind, n.day, n.statement, n.breach_at, n.updated_at
  FROM license_notices n JOIN records r ON r.id = n.record_id AND r.holder_key = n.holder_key
  WHERE n.statement = ? AND n.line_sig IS NOT NULL ORDER BY n.day`);

/** The licensee's answers to a statement, public: each type with the day it was first filed. */
const answersOf = (statement) =>
  statement ? answerRows.all(statement).map((a) => ({ type: a.answer, on: utcDayOf(a.received_at) })) : [];

/** The licensee's registration of a statement (its due date, and the day it was filed), or undefined. */
const registrationOf = (statement) => {
  const r = answerOne.get(statement, 'statement');
  return r ? { dueOn: r.due_on, on: utcDayOf(r.received_at) } : undefined;
};

/** Paid, by the licensee's own answer or a vetted payment partner's receipt: why a revoked line is refused. */
const paidOnFile = (statement) => {
  if (answerOne.get(statement, 'paid')) return 'the licensee says it was paid';
  if ((paymentReceipts.forStatement(statement).receipts ?? []).some((r) => r.partner?.nameChecked)) {
    return 'a payment partner filed a receipt for it';
  }
  return null;
};

/** One line as anyone sees it. Its last change is given as a UTC day, no finer (review round 3, L2). */
const publicLine = (n) => {
  const answers = answersOf(n.statement);
  return {
    ref: n.ref,
    kind: n.kind,
    ...(n.kind === 'overdue' ? { since: n.day } : { reason: 'non-payment', on: n.day }),
    ...(n.breach_at ? { breachNoticeOn: utcDayOf(n.breach_at) } : {}),
    ...(answers.length ? { answers } : {}),
    updatedAt: utcDayOf(n.updated_at),
  };
};

/**
 * The lines anyone with the record's id sees, written by the record's current holder only:
 * a line whose holder no longer holds the id (it was deleted and stored again by someone
 * else) is not answered, as a grant is not.
 */
const publicNotices = (recordId, holderKey) =>
  noticeRows.all(recordId).filter((n) => n.holder_key === holderKey).map(publicLine);

const requireDealsHere = (res) => {
  if (!deals) { res.status(503).json({ error: 'deals not ready' }); return false; }
  return true;
};
const requireLicenseChecks = (res) => {
  if (!licenseChecksReady()) { res.status(503).json({ error: 'starting, try again in a moment' }); return false; }
  return true;
};
const PREDATES = 'this license’s deal was opened before VeilCore’s registry kept the two sides’ deal keys, so nothing about it can be filed here';

app.put('/api/records/:id/license-notices/:ref', (req, res) => {
  const holder = storedKeyOf(req);
  if (!holder) return res.status(401).json({ error: 'holder key required' });
  if (!ownedRecord.get(req.params.id, holder)) return res.status(404).json({ error: 'no such record under this holder key', code: 'no-record' });
  if (!NOTICE_REF.test(req.params.ref)) return res.status(400).json({ error: 'ref must be 32 lowercase hexadecimal characters' });
  const n = noticeOf(req.body);
  if (n.error) return res.status(400).json({ error: n.error });
  if (licenseNoticeRef(n.statement) !== req.params.ref) return res.status(400).json({ error: 'ref is not the reference of that statement' });
  if (!requireDealsHere(res) || !requireLicenseChecks(res)) return;
  const parties = deals.partiesOf(n.statement);
  if (!parties) return res.status(409).json({ error: 'that statement is not a message in a deal held here', code: 'no-deal' });
  if (!parties.issuerKey || !parties.licenseeKey) return res.status(409).json({ error: PREDATES, code: 'predates' });
  if (!signedBy(parties.issuerKey, lineBytes(req.params.id, n.line), n.signature)) {
    return res.status(403).json({ error: 'the signature is not this deal’s licensor’s, for this record', code: 'not-licensor' });
  }
  if (lineElsewhere.get(n.statement, req.params.id)) {
    return res.status(409).json({ error: 'that statement’s lines are on another record', code: 'other-record' });
  }
  if (noticeCount.get(req.params.id, holder, req.params.ref).n >= LICENSE_NOTICES_MAX) {
    return res.status(409).json({ error: `a record carries at most ${LICENSE_NOTICES_MAX} notices`, code: 'full' });
  }
  const t = now();
  const had = noticeRow.get(req.params.id, req.params.ref);
  const prior = had && had.holder_key === holder && had.statement === n.statement && had.line_sig ? had : undefined;
  const kind = n.kind === 'breach' ? 'overdue' : n.kind;
  const day = n.day;
  let breachAt = prior?.breach_at ?? null;
  let revokedAt = prior?.revoked_at ?? null;
  // A line that has moved on (a notice of breach on file, or revoked) keeps what it says, its
  // date and the licensor's signature over it: a resend of the same or an earlier stage changes
  // nothing, so "overdue since" can't be moved back and a revoked line is never left under a
  // signature over something else (review round 4, N3). It is answered as it stands.
  const stage = (k) => ({ overdue: 0, breach: 1, revoked: 2 })[k];
  const priorStage = prior ? (prior.kind === 'revoked' ? 2 : prior.breach_at ? 1 : 0) : -1;
  if (priorStage >= 1 && stage(n.kind) <= priorStage) {
    return res.json({ recordId: req.params.id, ...publicLine(prior), now: t });
  }
  // "Overdue since" is never on or before the due date the licensee registered, once that date
  // has passed (the same rule as for a notice of breach, below): the licensor can't date it back.
  // A registered due date still to come doesn't silence the plain overdue line, which is only the
  // licensor's word and is labelled so: otherwise a licensee could keep it off for good by
  // registering a far-off date. Their page shows that line with a Dispute.
  const registered = registrationOf(n.statement);
  if (kind === 'overdue' && registered && registered.dueOn < utcDayOf(t) && n.day <= registered.dueOn) {
    return res.status(409).json({ error: `the licensee registered this statement as due on ${registered.dueOn}: it can be overdue only from the day after`, code: 'not-due', dueOn: registered.dueOn, now: t });
  }
  if (n.kind === 'breach' && !breachAt) {
    const reg = registered;
    if (!reg) {
      return res.status(409).json({ error: 'the licensee has not registered this statement here yet, so a notice of breach about it can’t be filed', code: 'not-registered', now: t });
    }
    if (utcDayOf(t) <= reg.dueOn || n.day <= reg.dueOn) {
      return res.status(409).json({ error: `the licensee registered this statement as due on ${reg.dueOn}: a notice of breach is filed from the day after`, code: 'not-due', dueOn: reg.dueOn, now: t });
    }
    breachAt = t;
  }
  if (n.kind === 'revoked') {
    // (A line already revoked was answered above, as it stands: its date was fixed when first accepted.)
    if (!breachAt) return res.status(409).json({ error: 'no notice of breach for this statement is on file here', code: 'no-breach' });
    const from = revocableFrom(breachAt);
    if (utcDayOf(t) < from) {
      return res.status(409).json({ error: `the time to pay after the notice of breach runs until the day before ${from}`, code: 'cure-not-over', revocableFrom: from, now: t });
    }
    if (n.day < from) return res.status(409).json({ error: `a revocation for non-payment can't be dated before ${from}`, code: 'cure-not-over', revocableFrom: from, now: t });
    // Whether a payment partner's receipt is on file can't be answered until they have loaded.
    if (!paymentReceipts) return res.status(503).json({ error: 'payment receipts not ready, try again in a moment' });
    const paid = paidOnFile(n.statement);
    if (paid) return res.status(409).json({ error: `not revoked for non-payment: ${paid}`, code: 'paid' });
    revokedAt = t;
  }
  putNotice.run(req.params.id, req.params.ref, holder, kind, day, n.statement, breachAt, revokedAt, n.signature, t);
  res.json({ recordId: req.params.id, ...publicLine({ ref: req.params.ref, kind, day, statement: n.statement, breach_at: breachAt, updated_at: t }), now: t });
});

app.delete('/api/records/:id/license-notices/:ref', (req, res) => {
  const holder = storedKeyOf(req);
  if (!holder) return res.status(401).json({ error: 'holder key required' });
  if (!ownedRecord.get(req.params.id, holder)) return res.status(404).json({ error: 'no such record under this holder key', code: 'no-record' });
  if (!NOTICE_REF.test(req.params.ref)) return res.status(400).json({ error: 'ref must be 32 lowercase hexadecimal characters' });
  const info = delNotice.run(req.params.id, req.params.ref, holder);
  if (info.changes === 0) return res.status(404).json({ error: 'no such notice' });
  res.json({ recordId: req.params.id, ref: req.params.ref, removed: true });
});

/** The holder's own lines on a record, as /verify shows them, with this registry's time. */
app.get('/api/records/:id/license-notices', (req, res) => {
  const holder = storedKeyOf(req);
  if (!holder) return res.status(401).json({ error: 'holder key required' });
  if (!ownedRecord.get(req.params.id, holder)) return res.status(404).json({ error: 'no such record under this holder key', code: 'no-record' });
  res.set('Cache-Control', 'no-store');
  res.json({ licenseNotices: publicNotices(req.params.id, holder), now: now(), cureDays: LICENSE_CURE_DAYS });
});

/** What the licensee signs: "veilcore/license-answer/v1\n" + the canonical answer. */
const LICENSE_ANSWER_V = 'veilcore/license-answer/v1';
const answerBytes = (a) => Buffer.from(`${LICENSE_ANSWER_V}\n${canonicalJson(a)}`, 'utf8');
const ANSWER_KEYS = {
  paid: 'referenceHash,statement,type,v',
  disputed: 'statement,type,v',
  statement: 'dueOn,statement,type,v',
};
const answerProblem = (a) => {
  if (!a || typeof a !== 'object' || Array.isArray(a)) return 'answer must be a JSON object';
  if (!Object.hasOwn(ANSWER_KEYS, a.type) || Object.keys(a).sort().join(',') !== ANSWER_KEYS[a.type]) {
    return 'answer must be exactly { v, statement, type: "disputed" }, { v, statement, type: "paid", referenceHash } or { v, statement, type: "statement", dueOn }';
  }
  if (a.v !== LICENSE_ANSWER_V) return `answer.v must be ${LICENSE_ANSWER_V}`;
  if (typeof a.statement !== 'string' || !FP.test(a.statement)) return 'statement must be the statement message’s fingerprint, 64 lowercase hex';
  if (a.type === 'paid') {
    if (typeof a.referenceHash !== 'string' || !FP.test(a.referenceHash)) return 'referenceHash must be the SHA-256 of the payment reference, 64 lowercase hex';
    if (a.referenceHash === EMPTY_SHA256) return 'the payment reference is empty';
  }
  if (a.type === 'statement' && !isCalendarDay(a.dueOn)) return 'dueOn must be the payment’s due date, a UTC date, YYYY-MM-DD';
  return null;
};

/**
 * The licensee's own word about a statement, signed with the licensee's deal key, which the deal
 * holding the statement names; no holder key, and the licensor's can't write it:
 *   - "statement": registers it as their royalty statement, with its payment's due date (what a
 *     notice of breach needs, above);
 *   - "paid", with the SHA-256 of the payment reference (never the reference), or "disputed".
 * The first of each type stands; the same one again is fine. Body exactly { answer, signature }.
 */
app.post('/license-answers', (req, res) => {
  if (!requireDealsHere(res) || !requireLicenseChecks(res)) return;
  const b = req.body;
  if (!b || typeof b !== 'object' || Array.isArray(b) || Object.keys(b).sort().join(',') !== 'answer,signature') {
    return res.status(400).json({ error: 'expected exactly { "answer": {…}, "signature": "<128 hex>" }' });
  }
  const { answer, signature } = b;
  const problem = answerProblem(answer);
  if (problem) return res.status(400).json({ error: problem });
  if (typeof signature !== 'string' || !SIG128.test(signature)) return res.status(400).json({ error: 'signature must be 128 hex characters' });
  const parties = deals.partiesOf(answer.statement);
  if (!parties) return res.status(404).json({ error: 'no deal held here has that statement', code: 'no-deal' });
  if (!parties.licenseeKey) return res.status(409).json({ error: PREDATES, code: 'predates' });
  if (unusableKeyOf(parties.licenseeKey)) return res.status(409).json({ error: 'the licensee’s key on file for this deal is not a usable key' });
  if (!signedBy(parties.licenseeKey, answerBytes(answer), signature)) return res.status(403).json({ error: 'the signature is not the licensee’s for this deal' });
  const had = answerOne.get(answer.statement, answer.type);
  const t = now();
  if (!had) {
    putAnswer.run(answer.statement, answer.type, answer.type === 'paid' ? answer.referenceHash : null,
      answer.type === 'statement' ? answer.dueOn : null, signature, t);
  }
  res.json({
    filed: !had,
    type: answer.type,
    on: utcDayOf(had ? had.received_at : t),
    ...(answer.type === 'statement' ? { dueOn: had ? had.due_on : answer.dueOn } : {}),
    now: t,
  });
});

/**
 * What is on file about one statement, for the two sides' pages: the licensee's registration and
 * answers, and the licensor's signed lines about it (on one record, which isn't named). The
 * fingerprint is known only to the deal's two sides and this registry.
 */
const statementView = (statement) => {
  const registered = registrationOf(statement);
  const parties = deals?.partiesOf(statement);
  return {
    answers: answersOf(statement),
    lines: rowsForStatement.all(statement).map(({ record_id, holder_key, ...n }) => publicLine(n)),
    ...(registered ? { registered } : {}),
    // In a deal from before the deal keys were kept here: nothing about it can be filed (M1).
    ...(parties && (!parties.licenseeKey || !parties.issuerKey) ? { predates: true } : {}),
  };
};

app.get('/license-answers/:statement', (req, res) => {
  if (!FP.test(req.params.statement)) return res.status(400).json({ error: 'expected a statement fingerprint, 64 lowercase hex' });
  res.set('Cache-Control', 'no-store');
  res.json({ ...statementView(req.params.statement), now: now(), cureDays: LICENSE_CURE_DAYS });
});

/** The same for up to 100 statements at once (a deal's): body exactly { statements: [<64 hex>…] }. */
const LOOKUP_MAX = 100;
app.post('/license-answers/lookup', (req, res) => {
  const b = req.body;
  const list = b && typeof b === 'object' && !Array.isArray(b) && Object.keys(b).join(',') === 'statements' ? b.statements : undefined;
  if (!Array.isArray(list) || list.length === 0 || list.length > LOOKUP_MAX || !list.every((s) => typeof s === 'string' && FP.test(s)) || new Set(list).size !== list.length) {
    return res.status(400).json({ error: `expected exactly { "statements": [1 to ${LOOKUP_MAX} different statement fingerprints, 64 lowercase hex] }` });
  }
  res.set('Cache-Control', 'no-store');
  res.json({ results: list.map((statement) => ({ statement, ...statementView(statement) })), now: now(), cureDays: LICENSE_CURE_DAYS });
});

// ---- licences, same scoping ----

app.get('/api/licenses', holderList('licenses'));

// A page at a time, in id order (round 2): the export is written out in pieces.
const exportRecords = db.prepare('SELECT id, body, first_seen FROM records WHERE holder_key = ? AND id > ? ORDER BY id LIMIT ?');
const exportLicences = db.prepare('SELECT id, body FROM licenses WHERE holder_key = ? AND id > ? ORDER BY id LIMIT ?');
const EXPORT_CHUNK = 200;
const exportGrants = db.prepare('SELECT record_id, show, grant_values, for_fingerprint FROM disclosure_grants WHERE holder_key = ? ORDER BY record_id');

const EXPORT_LIMITS = { holder: 3, client: 10 }; // per minute
const exportWindows = new Map();
const exportAllowed = (key, limit) => {
  const minute = Math.floor(Date.now() / 60_000);
  const w = exportWindows.get(key);
  const n = w && w.minute === minute ? w.n + 1 : 1;
  boundedSet(exportWindows, key, { minute, n }, (v) => v.minute !== minute);
  return n <= limit;
};

/**
 * Everything this registry holds for a holder, in one download: records and licences as
 * stored (sealed ones stay sealed: the holder's app opens them with its vault key),
 * disclosure grants with the values they publish, each record's inclusion proof (with its anchors, including the OpenTimestamps file's
 * location), and the batches those proofs belong to. So that leaving VeilCore, or
 * VeilCore stopping, never means losing anything: every proof in it verifies with the
 * open specification and no help from us.
 */
app.get('/api/export', async (req, res) => {
  const holder = storedKeyOf(req);
  if (!holder) return res.status(401).json({ error: 'holder key required' });
  // An export walks every proof a holder has. It was the cheapest way to load this
  // service down (attack on branch ots, 4 Oct 2026): one address, 600 a minute, ~0.7 s
  // each at 10,000 records. Limited per holder key and per address; both checked so a
  // fresh key per request does not reset the count.
  const clientOk = exportAllowed(`client:${clientBucket(req.ip)}`, EXPORT_LIMITS.client);
  const holderOk = exportAllowed(`holder:${holder}`, EXPORT_LIMITS.holder);
  if (!clientOk || !holderOk) {
    return res.status(429).json({ error: 'exports are limited to a few a minute; try again shortly' });
  }
  // Written out a page at a time (round 2, HIGH): it was built whole in memory, however
  // large the set, and sets past the byte ceiling exist (stored before it). Each piece is
  // at most EXPORT_CHUNK rows, and the next is read only once the client has taken the
  // last, so memory per export stays small whatever the holder holds. Same JSON as before;
  // records and licences are now in id order.
  const head = JSON.stringify({
    format: 'veilcore-registry-export/v1',
    exportedAt: new Date().toISOString(),
    note: 'What this registry holds for this holder key, except: deliveries (with their locked offers and sample details), lab reports, royalty obligations, and requests to prove a record\'s key. Those are not in this export: the app shows each delivery, its sample details and lab reports; obligations are answered per record by the lineage check; prove requests are deleted after 7 days. Records and licences are stored sealed: what you typed is locked with the vault key kept in your browser and your backup file, and VeilCore can\'t open it; this export has them as stored, and the app opens them. Readable here: each record\'s profile, proof code (its fingerprint) and key binding, correction links (which record, which fields changed, and when, never why), the received-from details and receipt confirmations this registry writes, when it first saw each record, how many times and when each record and licence was saved, the size bucket of each locked row, and the values you chose to publish with a disclosure grant (a record\'s name only if you chose to show it; a DNA report only in a form that means nothing without the salt in your check link). A record saved before names were locked keeps its name readable here until your app saves it again. For each delivery the registry also reads which record it was sent from, which holder account received it, when it was made and received, and a tag your app makes from the recipient\'s name; a delivery made before tags has the name as typed until the registry\'s purge replaces it. Records saved before sealing are in plain text until your app saves them again, and the registry\'s off-site backups made before then hold them until its backup key is rotated (docs/rotate-backup-key.md). The sample details on a delivery (sample ID, seal number, where and when it was taken, a witness, and what the lab wrote on arrival) are stored locked with a key that travels in the lab code, and VeilCore doesn\'t have that key. Sample details written before sealing stay readable here until the registry\'s purge removes them. When a licence with an offspring royalty is countersigned, your app also registers an obligation on the record\'s fingerprint, under the agreement\'s fingerprint: the registry reads which record carries one and when it was made, answers anyone only whether a given record is clean, and never lists them. Genetic data was never sent here and is not in it; it stays on your own device. Locked lab reports a lab sends back to you are stored here encrypted, so VeilCore cannot read them, and are deleted after 180 days. Every inclusion proof verifies with the open specification (veilcore-sdk SPEC.md) and needs nothing from VeilCore. An OpenTimestamps proof marked "pending" is a calendar\'s promise, not yet a Bitcoin timestamp: it still needs the calendars named in it (`ots upgrade`) until it has been upgraded; one marked "bitcoin" verifies against Bitcoin alone.',
  }).slice(0, -1);
  res.status(200).type('application/json').set('Content-Disposition', 'attachment; filename="veilcore-export.json"');
  const send = async (s) => {
    if (res.destroyed) throw new Error('client went away');
    if (!res.write(s)) await new Promise((ok) => { res.once('drain', ok); res.once('close', ok); });
  };
  // Rows of a holder-scoped table in id order, each piece read only when the last is sent.
  const rows = async (stmt, map) => {
    let first = true;
    for (let after = ''; ;) {
      const page = stmt.all(holder, after, EXPORT_CHUNK);
      if (page.length) {
        await send(page.map((r) => { const s = (first ? '' : ',') + JSON.stringify(map(r)); first = false; return s; }).join(''));
      }
      if (page.length < EXPORT_CHUNK) return;
      after = page[page.length - 1].id;
    }
  };
  try {
    await send(`${head},"records":[`);
    await rows(exportRecords, (r) => ({ ...JSON.parse(r.body), registryFirstSeen: r.first_seen ? new Date(r.first_seen).toISOString() : undefined }));
    await send('],"licenses":[');
    await rows(exportLicences, (r) => JSON.parse(r.body));
    const grants = exportGrants.all(holder);
    const disclosures = Object.fromEntries(grants.map((g) => [g.record_id, parsedOr(g.show, [])]));
    // What each grant publishes, and the fingerprint it was taken from (absent for a grant
    // made before grant values).
    const disclosureValues = Object.fromEntries(grants.filter((g) => g.grant_values !== null)
      .map((g) => [g.record_id, { forFingerprint: g.for_fingerprint ?? null, values: parsedOr(g.grant_values, {}) }]));
    await send(`],"disclosures":${JSON.stringify(disclosures)},"disclosureValues":${JSON.stringify(disclosureValues)},"proofs":{`);
    const { byId, batches: batchList } = batches ? batches.exportBatchesFor(holder) : { byId: new Map(), batches: [] };
    if (batches) {
      const seen = new Set();
      for (let after = ''; ;) {
        const page = batches.exportProofsPage(holder, after, EXPORT_CHUNK, byId);
        const parts = [];
        for (const [commitment, proof] of page.proofs) {
          if (seen.has(commitment)) continue; // two records of one holder with one fingerprint
          parts.push(`${seen.size ? ',' : ''}${JSON.stringify(commitment)}:${JSON.stringify(proof)}`);
          seen.add(commitment);
        }
        if (parts.length) await send(parts.join(''));
        if (page.last === null) break;
        after = page.last;
      }
    }
    await send(`},"batches":${JSON.stringify(batchList)}}`);
    res.end();
  } catch {
    // Headers are gone, so there is no error answer to give: cut the response, which a
    // client sees as an incomplete download rather than a valid-looking partial export.
    res.destroy();
  }
});

app.put('/api/licenses', (req, res) => {
  const holder = storedKeyOf(req);
  if (!holder) return res.status(401).json({ error: 'holder key required' });
  if (!Array.isArray(req.body)) return res.status(400).json({ error: 'expected an array' });

  const upsert = db.prepare(
    `INSERT INTO licenses (id, holder_key, record_id, body, updated_at) VALUES (?, ?, ?, ?, ?)
     ON CONFLICT(id) DO UPDATE SET body = excluded.body, record_id = excluded.record_id, updated_at = excluded.updated_at
     WHERE licenses.holder_key = excluded.holder_key`
  );
  if (req.body.length > MAX_PER_REQUEST) {
    return res.status(413).json({ error: `at most ${MAX_PER_REQUEST} licenses per request` });
  }
  // The app re-sends every licence on each save, so count only ids this holder lacks.
  const heldLicences = db.prepare('SELECT COUNT(*) AS n FROM licenses WHERE holder_key = ?').get(holder).n;
  const isHeldLicence = db.prepare('SELECT 1 FROM licenses WHERE id = ? AND holder_key = ?');
  const newLicences = req.body.filter((i) => !(typeof i?.id === 'string' && isHeldLicence.get(i.id, holder))).length;
  if (heldLicences + newLicences > MAX_PER_HOLDER) {
    return res.status(413).json({ error: `a holder may keep at most ${MAX_PER_HOLDER} licenses here` });
  }
  // Licences had no validation at all: any JSON under any id (attack round 11). Since
  // sealed records a licence is { id, sealed } and nothing else (sealed.js) but, since round
  // 4, an optional public `rev` checked like a record's (an older copy is refused): its terms,
  // parties and the record it is about are all inside the box, and the licence row does not
  // name its record either (record_id stays null). One trace stays outside it (round 3, P5):
  // when a licence with an offspring royalty is countersigned, the holder's browser
  // registers an obligation on the record's fingerprint (POST /lineage/obligations), keyed
  // by the agreement's fingerprint, with when it was made and whose key made it. So this
  // registry can tell which records carry a royalty licence and since when. It answers that
  // only per record (POST /lineage/verify), never in a listing, and stores each obligation
  // under a per-record beneficiary id, so one holder's royalty licences are not linked by id.
  const rejected = [];
  const valid = [];
  for (const item of req.body) {
    const problem = licenceRowProblem(item);
    if (problem) rejected.push({ id: typeof item?.id === 'string' ? item.id.slice(0, 128) : null, reason: problem });
    else valid.push(item);
  }
  // The same byte ceiling as records, counted separately (deep dive, 8 Oct 2026).
  const notWritten = [];
  let written = 0;
  let projectedBytes = 0;
  const priorLicence = db.prepare('SELECT body FROM licenses WHERE id = ? AND holder_key = ?');
  const licenceOwner = db.prepare('SELECT 1 FROM licenses WHERE id = ?');
  const heldLicenceBytes = db.prepare('SELECT COALESCE(SUM(octet_length(body)), 0) AS n FROM licenses WHERE holder_key = ?');
  const tx = db.transaction((items) => {
    // One vault key per holder, as for records (the same key seals both).
    let kid = vaultKidOf(holder);
    // One entry per id, the last copy sent (round 2), as for records.
    const last = new Map();
    // `rev` (round 4, F1): an agreement is refused as an older copy exactly as a record is.
    // Without it two tabs or devices replaced each other's changes to an agreement (a
    // revocation undone by a royalty entry), and neither was told.
    const revs = new Map();
    for (const item of items) {
      if (kid === null) kid = item.sealed.kid;
      else if (item.sealed.kid !== kid) {
        rejected.push({ id: item.id, reason: DIFFERENT_VAULT_KEY });
        continue;
      }
      const prior = priorLicence.get(item.id, holder);
      const priorBody = prior ? JSON.parse(prior.body) : {};
      const rev = Number.isSafeInteger(item.rev) ? item.rev : null;
      const earlier = revs.get(item.id);
      const held = [priorBody.rev, earlier?.rev].filter(Number.isSafeInteger);
      const heldRev = held.length ? Math.max(...held) : null;
      const heldBox = earlier && earlier.rev === heldRev ? earlier.box : priorBody.sealed;
      const older = olderCopyRefusal('license', item.id, rev, heldRev, heldBox, item.sealed);
      if (older) {
        rejected.push(older);
        continue;
      }
      revs.set(item.id, { rev, box: boxOf(item.sealed) });
      last.delete(item.id);
      last.set(item.id, JSON.stringify({ id: item.id, ...(rev !== null ? { rev } : {}), sealed: boxOf(item.sealed) }));
    }
    const before = heldLicenceBytes.get(holder).n;
    let after = before;
    for (const [id, body] of last) {
      const prior = priorLicence.get(id, holder);
      if (prior) after += Buffer.byteLength(body) - Buffer.byteLength(prior.body);
      else if (!licenceOwner.get(id)) after += Buffer.byteLength(body);
    }
    if (after > HOLDER_MAX_BYTES && after > before) { projectedBytes = after; return false; }
    for (const [id, body] of last) {
      const info = upsert.run(id, holder, null, body, now());
      if (info.changes === 0) notWritten.push(id);
      else written++;
    }
    return true;
  });
  if (!tx(valid)) {
    return res.status(413).json({
      error: `a holder may keep at most ${megabytes(HOLDER_MAX_BYTES)} of licenses here; this save would make it ${megabytes(projectedBytes)}. Nothing was changed.`,
    });
  }
  res.json({
    ok: notWritten.length === 0 && rejected.length === 0,
    count: written,
    ...(rejected.length ? { rejected } : {}),
    ...(notWritten.length ? { notWritten, reason: 'these ids already belong to another holder; nothing was changed' } : {}),
  });
});

/**
 * Remove licences this holder owns (sealed records): a licence sealed with a vault key the
 * holder's browser no longer has can't be opened, edited or sent, but its holder can still
 * take it off VeilCore, as with a locked record. Scoped to the holder; reports what went.
 */
app.delete('/api/licenses', (req, res) => {
  const holder = storedKeyOf(req);
  if (!holder) return res.status(401).json({ error: 'holder key required' });
  const ids = Array.isArray(req.body?.ids) ? req.body.ids.filter((i) => typeof i === 'string') : null;
  if (!ids || ids.length === 0) return res.status(400).json({ error: 'expected { ids: [...] }' });
  if (ids.length > MAX_PER_REQUEST) return res.status(413).json({ error: `at most ${MAX_PER_REQUEST} licenses per request` });
  const del = db.prepare('DELETE FROM licenses WHERE id = ? AND holder_key = ?');
  const removed = [];
  const notYours = [];
  db.transaction((list) => {
    for (const id of list) (del.run(id, holder).changes > 0 ? removed : notYours).push(id);
  })(ids);
  res.json({
    ok: notYours.length === 0,
    removed,
    ...(notYours.length ? { notRemoved: notYours, reason: 'no such license under this holder key' } : {}),
  });
});

// ---- public verification ----

/**
 * Public. No holder key, so whoever has a record id can call this, and what comes
 * back is what a stranger learns.
 *
 * Two layers (round D):
 *   BASE, always: id, fingerprint, the registry's first-seen date, correction links, the
 *     anchor, and whether signed attestations exist. All of it is either the registry's own
 *     word or public elsewhere already (/records, /proof, /attestations). The name only for a
 *     row saved before names were sealed (round 5, publicName).
 *   GRANTED, only if the record's holder said so with PUT /api/records/:id/disclosure:
 *     prior possession, DNA pairing (whether a lab report is saved and, since round 5, which
 *     one only in the bound form, dnaPairBinding), lineage status, the holder's
 *     stated date, parent names, breeding method. Nothing stored means nothing granted.
 *
 * Since sealed records, nothing here reads the record's body beyond its public fields:
 * every holder-written answer comes from the values the holder sent with the grant, and
 * only while they were taken from the record as it is now. Otherwise the key is listed in
 * `staleGrant` (older names, like `disclosed`) and its holder-written answer is left out
 * (dropStale). For `dna` that is only the DNA pairing: it stays in `disclosed`, and the
 * registry's own facts under it (custody of each lab receipt) are still answered.
 *
 * ?show= is written by whoever has the link, not by the holder, so it can only narrow
 * the grant. It used to be the whole mechanism: the app put the holder's choice in the
 * URL, and anyone could edit the URL to read parent names and breeding method.
 *
 * `disclosed` is always present and lists, in the older names this page was built
 * against, exactly the granted facts in this response. A granted fact's field is present
 * if and only if its key is listed; an absent field means "not shared", never "false".
 *
 * `holder-portfolio` and `terms-full` are never answered. They were scoped to the HOLDER
 * rather than the record: one id returned how many other records that breeder owned and
 * the status of licences on records the caller had never been shown.
 *
 * Genetics are never returned.
 */
/** A 64-character hex value, lowercased; anything else is undefined (never echoed). */
const hex64 = (v) => (typeof v === 'string' && /^[0-9a-fA-F]{64}$/.test(v) ? v.toLowerCase() : undefined);

/**
 * The lab receipts on a record's deliveries and their sample details, for the public answers
 * (/verify, /embed, /records/:id) under the attestation-status grant (transfer.mjs
 * receiptCustody). A receipt over sealed details says only that the lab's receipt names
 * sample details, which this registry can't check (custody "sealed"); when the holder published what their app worked out
 * (values.custodySummary, current with the record), it is added as theirs:
 * `custodySummary` and `custodySummaryBy: "holder"`. Never the details themselves.
 */
const publicCustody = (recordId, row, r, values, pairingStale) => {
  if (!transfers || typeof r.recordFingerprint !== 'string') return [];
  const list = transfers.receiptCustody({ sourceRecord: recordId, holderKeyStored: row.holder_key, fingerprint: r.recordFingerprint });
  const summaries = !pairingStale && Array.isArray(values?.custodySummary) ? values.custodySummary : [];
  // A receipt's id only when the holder shares that receipt (values.sharedAttestations, 8 Nov
  // 2026), checked as /verify's sharedAttestations are: the id is how a reader finds the
  // receipt, and the receipt names the lab. Otherwise the line says only what the custody was.
  const shared = new Set(sharedFor(row, r, values).map((a) => a.attestationId));
  return list.map((e) => {
    const s = e.custody === 'sealed' ? summaries.find((x) => x.receiptAttestationId === e.receiptAttestationId) : undefined;
    const line = s
      ? { ...e, custodySummary: { covered: s.covered, differingFields: [...s.differingFields] }, custodySummaryBy: 'holder' }
      : { ...e };
    if (!shared.has(e.receiptAttestationId)) delete line.receiptAttestationId;
    return line;
  });
};
/**
 * The signatures the holder publishes (values.sharedAttestations), as /verify serves them:
 * still about the record as it is now, and a private one only while its holder can see it.
 */
const sharedFor = (row, r, values) =>
  attesters && typeof r.recordFingerprint === 'string' && Array.isArray(values?.sharedAttestations) && values.sharedAttestations.length
    ? attesters.forIds(r.recordFingerprint, values.sharedAttestations, { canSeePrivate: privateReaderFor(row.holder_key) })
    : [];

app.get('/verify/:id', (req, res) => {
  // The answer is the holder's grant as it is now, shared lab signatures included, and the
  // holder can change or take it back at any time: no cache keeps an older one (12 Nov 2026).
  res.set('Cache-Control', 'no-store');
  const row = db.prepare('SELECT body, holder_key, first_seen FROM records WHERE id = ?').get(req.params.id);
  if (!row) {
    // A deleted record says so, and still says whether it was dated before the deletion: the
    // anchor is on the ledger whatever happens here. 404, so older check pages read "not found".
    const gone = tombstones.of(req.params.id);
    if (!gone) return res.status(404).json({ found: false });
    const evidence = batches && gone.fingerprint ? batches.evidenceFor(gone.fingerprint) : null;
    const proof = evidence?.proof ?? null;
    // The proof code is public (it is what a check link carries), so a page can tie its link
    // to this record before it reports any date. The time is to the minute: enough to read.
    const anchoredAt = proof?.anchor ? Date.parse(proof.anchor.anchoredAt) : NaN;
    // anchoredAt is the operator's report and may be off by the anchor skew, and deletedAt is
    // given to the minute: inside that window, before or after can't be told.
    const window = DELETION_ORDER_WINDOW_MS;
    const sealedAt = evidence?.batch ? Date.parse(evidence.batch.sealedAt) : NaN;
    return res.status(404).json({
      found: false,
      deleted: true,
      deletedBy: 'record-holder',
      deletedAt: new Date(Math.floor(gone.deleted_at / 60_000) * 60_000).toISOString(),
      ...(gone.fingerprint ? { recordFingerprint: gone.fingerprint } : {}),
      anchored: Boolean(proof && proof.anchor),
      ...(proof && proof.anchor
        ? {
            anchor: proof.anchor,
            anchorCheckedOnChain: false,
            // A batch sealed before the deletion can be anchored after it.
            anchoredRelativeToDeletion: !Number.isFinite(anchoredAt)
              ? 'unknown'
              : anchoredAt < gone.deleted_at - window
                ? 'before'
                : anchoredAt > gone.deleted_at + window
                  ? 'after'
                  : 'unknown',
          }
        : {}),
      // Both times are this registry's own clock, so the order of sealing and deletion is exact.
      ...(Number.isFinite(sealedAt)
        ? { sealedRelativeToDeletion: sealedAt < gone.deleted_at ? 'before' : 'after' }
        : {}),
    });
  }
  const r = JSON.parse(row.body);
  const grant = grantFor(row, req.params.id);
  const { on, notGranted, refused } = effectiveDisclosure(grant.show, req.query.show);
  // A plant record has no individual ID: the key is never answered (or listed) for one.
  if (!isAnimalRecord(r)) on.delete('individual-id');
  const { stale, pairingStale } = dropStale(on, grant, r);
  const values = grant.values ?? {};

  const out = publicView(row, on, values);
  // Whether the record names its own key (lineage/key-binding.mjs). The binding itself is
  // never sent: it says nothing without the key's salt, which only the holder's links
  // carry. A check page uses this to refuse a link to a bound record that leaves the key's
  // parts out, rather than showing it with the weaker, older-record wording.
  out.keyBound = typeof r.keyBinding === 'string';
  // Only what the registry can stand behind. A holder's own "attestation" field, DNA
  // pairing and licence statuses are things they typed; reporting them as facts let a
  // verify page say "Lab attested" and "N active licences" on the holder's word alone.
  // A valid signature says only that whoever holds some key signed. Anyone can make a
  // key, register it under a lab's name and sign their own record, and this said
  // `attested: true` — which the site rendered as "Signed lab attestation on record"
  // (attack round 11). Two answers now:
  //   signedAttestation    any valid, unretracted signature — the signer is unknown
  //   attestedByVettedLab  one from a key the registry operator has checked
  // Neither counts a private signature (8 Nov 2026, attesters.mjs summaryFor): this is
  // public, and it would say a lab handled the plant. What the holder chose to publish is
  // `sharedAttestations`, below.
  // `attested` is kept for clients built before the split and means the strong one.
  const summary = attestationSummary(r.recordFingerprint);
  out.signedAttestation = summary.signed;
  out.attestedByVettedLab = summary.vetted;
  out.attested = out.attestedByVettedLab;
  const proof = batches && r.recordFingerprint ? batches.proofFor(r.recordFingerprint) : null;
  out.anchored = Boolean(proof && proof.anchor);
  if (out.anchored) {
    out.anchor = proof.anchor;
    // Who says so (deep dive, 8 Oct 2026, MEDIUM). The registry records the transaction the
    // operator reports and checks its shape, network and contract, never the chain itself.
    // priorPossession below rests on it, so the answer says how to check it.
    out.anchorRecordedBy = 'registry-operator';
    out.anchorCheckedOnChain = false;
    out.anchorNote = `Recorded by the registry operator; this registry has not looked the transaction up on chain. Before relying on the date, check that transaction ${proof.anchor.txHash ?? '(none given)'} on ${proof.anchor.chain ?? 'midnight'} ${proof.anchor.network} calls contract ${proof.anchor.contractAddress ?? '(none given)'} with this record's batch root (/proof/${r.recordFingerprint}).`;
  }

  out.disclosed = inOrder(on).map((k) => CURRENT_TO_LEGACY[k]);

  // The holder's own notices about royalties on licenses from this record: a kind and dates,
  // labelled as the holder's word, with the licensee's own answers beside them, labelled as
  // theirs (license notices, above). Absent when there are none.
  const notices = publicNotices(req.params.id, row.holder_key);
  if (notices.length) {
    out.licenseNotices = notices;
    out.licenseNoticesBy = 'record-holder';
    out.licenseAnswersBy = 'licensee';
  }

  // Reported from what is stored, not asserted. Prior possession rests on a date
  // someone other than the holder fixed: a ledger anchor on a production network. A
  // test network (Preview, preprod) can be reset and its dates carry no evidential weight,
  // so a batch anchored there before the move to mainnet keeps `anchored: true` and its
  // `anchor` (with `network` and `testNetwork: true`, for clients that show it as such),
  // but never `priorPossession: true`. Without a mainnet anchor, all that can be said is
  // that the record is unaltered since the registry first saw it.
  if (on.has('existence')) {
    out.priorPossession = out.anchored && out.anchor?.testNetwork === false;
    // The fingerprint has not changed since the registry first saw it (first_seen resets
    // when it does). Whether it matches the record's contents is not something this
    // registry can check: the contents are sealed. The holder's browser checks it.
    out.unalteredSinceRegistryFirstSeen = Boolean(r.recordFingerprint);
    out.fingerprintCheckedByRegistry = false;
  }
  if (on.has('attestation-status') && !pairingStale) {
    // From the grant's values (whether the holder's record names a lab report, and which),
    // and only while they are current: a stale pairing is left out, never answered as "none".
    // Round 5 (CONTRACT.md #29): which report is said only in the bound form, dnaPairBinding,
    // which means nothing without the pairing salt in the holder's link. It used to be the
    // file's SHA-256 and its pairing fingerprint, which let anyone holding a file tell whether
    // it was this one. A grant stored before with those plain values (dnaFingerprint,
    // dnaFileSha256) says only that a report is saved: they are never answered again.
    const binding = hex64(values.dnaPairBinding);
    out.dnaPairedByHolder = Boolean(binding) || Boolean(values.dnaFingerprint);
    if (binding) out.dnaPairBinding = binding;
  }
  if (on.has('attestation-status')) {
    // The registry's own facts under this grant: answered whether or not the holder's
    // pairing values are current. The signed and vetted attestation summaries are above,
    // in the base. The sample's chain of custody behind each lab receipt linked to this record's
    // deliveries (round 2 of the 15 Oct review): the check page lost a seal mismatch the
    // breeder's own page showed. Under the same grant: per receipt, whether it covers the
    // sample details and the plain difference lines, never the details themselves
    // (transfer.mjs receiptCustody). Absent without the grant, or with no linked receipt.
    // Sealed details (CONTRACT.md #27): "sealed", and the holder's own summary if published.
    const custody = publicCustody(req.params.id, row, r, values, pairingStale);
    if (custody.length) out.custody = custody;
    // The signatures the holder chose to publish (8 Nov 2026), and nothing else: each still
    // about this record as it is now, and a private one only while its holder can see it.
    // Private signatures are otherwise never on this page (attesters.mjs summaryFor).
    const shared = sharedFor(row, r, values);
    if (shared.length) out.sharedAttestations = shared;
  }
  if (on.has('sealed-at')) out.sealedAt = values.loggedAt; // the holder's statement; see loggedAtClaimedByHolder
  if (on.has('descent-clean')) {
    // Descent is not checked here and saying so is the honest answer. Walking it
    // needs the declared graph and a clean proof per ancestor, which is the lineage
    // layer's job, and reporting an unchecked `true` is how a per-record answer gets
    // mistaken for a walked one.
    out.lineageIntact = null;
    out.lineageNote = 'not checked by this endpoint; walk descent against the lineage layer';
  }
  if (on.has('parent-names')) {
    const parents = Array.isArray(values.parents) ? values.parents : [];
    out.parents = parents.map((p) => p?.name).filter((n) => typeof n === 'string' && n);
    // An animal's sire and dam, by name and individual ID, under the same grant: the IDs
    // are how a pedigree is read. Never a linked record's id or anything else.
    if (isAnimalRecord(r)) {
      for (const p of parents) {
        if (!p || (p.role !== 'sire' && p.role !== 'dam') || out[p.role]) continue;
        const name = typeof p.name === 'string' ? p.name : '';
        const individualId = typeof p.individualId === 'string' ? p.individualId : '';
        if (name || individualId) out[p.role] = { name, individualId };
      }
    }
    // A strain's parent strains, by name and deposit number, under the same grant: a deposit
    // number is how a culture collection names a strain. At most two (the profile's limit),
    // never a linked record's id or anything else.
    if (isStrainRecord(r)) {
      out.parentStrains = parents
        .filter((p) => p && typeof p === 'object')
        .slice(0, 2)
        .map((p) => ({
          name: typeof p.name === 'string' ? p.name : '',
          deposit: typeof p.individualId === 'string' ? p.individualId : '',
        }))
        .filter((p) => p.name || p.deposit);
    }
  }
  if (on.has('breeding-method')) out.breedingMethod = values.breedingMethod || null;
  // Who bred it, as the holder wrote it, only if the holder shared it (persona review, 17 Oct).
  if (on.has('bred-by')) out.bredBy = typeof values.bredBy === 'string' ? values.bredBy : '';
  // An animal's individual ID and the scheme it belongs to, only if the holder shared it.
  if (on.has('individual-id')) {
    out.individualId = typeof values.individualId === 'string' ? values.individualId : '';
    out.idScheme = typeof values.idScheme === 'string' ? values.idScheme : '';
  }
  // Granted, but the values were sent for an earlier version of the record (or before
  // grant values existed): not answered until the holder's browser sends them again.
  if (stale.length) {
    out.staleGrant = stale.map((k) => CURRENT_TO_LEGACY[k]);
    out.staleGrantReason = "the record has changed since its holder chose what to share; these are shown again once the holder's app updates them";
  }

  // A caller who asked for something they are not given is told plainly, rather than
  // silently given less than they asked for.
  if (notGranted.length) {
    out.notGranted = notGranted.map((k) => CURRENT_TO_LEGACY[k]);
    out.notGrantedReason = "the record's holder has not chosen to share these";
  }
  if (refused.length) {
    out.unavailable = refused.map((k) => CURRENT_TO_LEGACY[k]);
    out.unavailableReason = NEVER_DISCLOSED_REASON;
  }

  res.json(out);
});

// ---- lineage ----
// Every lineage answer comes from this registry's database, not from chain state, and
// says so: VeilCore attests to it; the contract (verify.ts in hunterincoming/veilcore)
// is what a decision should rest on.
const REGISTRY_ATTESTATION = {
  attestation: 'registry',
  note: 'Answered from the VeilCore registry, not from chain state. Check the contract for anything a decision rests on.',
};
app.use('/lineage', (_req, res, next) => { res.set('X-VeilCore-Attestation', 'registry'); next(); });

const requireLineage = (res) => {
  if (!lineage) { res.status(503).json({ error: 'lineage layer not ready' }); return false; }
  return true;
};

/** Map a lineage error to a status: 403 for "not yours", 400 for a bad request. */
const lineageError = (res, e) =>
  res.status(e?.name === 'Forbidden' || e?.constructor?.name === 'Forbidden' ? 403 : 400).json({ error: e.message });

/** A digest of the open obligations. Public — it reveals nothing by itself. */
app.get('/lineage/root', (_req, res) => {
  if (!requireLineage(res)) return;
  res.json({ root: lineage.root(), emptyRoot: lineage.emptyRoot });
});

/**
 * As the child's holder: propose a parent. It becomes an edge when the parent's
 * holder confirms, or at once if the parent's holder transferred this material to you.
 */
app.post('/lineage/descent', (req, res) => {
  if (!requireLineage(res)) return;
  const holder = holderOf(req);
  if (!holder) return res.status(401).json({ error: 'holder key required' });
  const { child, parent } = req.body || {};
  if (!child || !parent) return res.status(400).json({ error: 'child and parent required' });
  try { res.json(lineage.proposeParent(child, parent, holder)); } catch (e) { lineageError(res, e); }
});

/** As the parent's holder: confirm being named as this child's parent. */
app.post('/lineage/descent/confirm', (req, res) => {
  if (!requireLineage(res)) return;
  const holder = holderOf(req);
  if (!holder) return res.status(401).json({ error: 'holder key required' });
  const { child, parent } = req.body || {};
  if (!child || !parent) return res.status(400).json({ error: 'child and parent required' });
  try { res.json(lineage.confirmParent(child, parent, holder)); } catch (e) { lineageError(res, e); }
});

/** As the child's holder: withdraw your own parentage proposal. */
app.delete('/lineage/descent/:child', (req, res) => {
  if (!requireLineage(res)) return;
  const holder = holderOf(req);
  if (!holder) return res.status(401).json({ error: 'holder key required' });
  try { res.json(lineage.withdrawParent(req.params.child, holder)); } catch (e) { lineageError(res, e); }
});

/**
 * Attach an obligation. On your own record it is in force at once, in your favour; on
 * anyone else's it is a proposal until that record's holder accepts it. `beneficiary`
 * (optional, round 3 P5): the caller's per-record beneficiary id, 64 lowercase hex, which
 * the obligation is stored under (lineage/routes.mjs beneficiaryIdFor); without it the
 * registry makes a per-record one. Never the per-holder party id.
 */
app.post('/lineage/obligations', (req, res) => {
  if (!requireLineage(res)) return;
  const holder = holderOf(req);
  if (!holder) return res.status(401).json({ error: 'holder key required' });
  const { record, obligation, beneficiary } = req.body || {};
  if (!record || !obligation) return res.status(400).json({ error: 'record and obligation required' });
  try { res.json(lineage.encumber(record, obligation, holder, beneficiary)); } catch (e) { lineageError(res, e); }
});

/** As a record's holder: accept a proposed obligation, naming its beneficiary. */
app.post('/lineage/obligations/accept', (req, res) => {
  if (!requireLineage(res)) return;
  const holder = holderOf(req);
  if (!holder) return res.status(401).json({ error: 'holder key required' });
  const { record, obligation, beneficiary } = req.body || {};
  if (!record || !obligation || !beneficiary) {
    return res.status(400).json({ error: 'record, obligation and beneficiary required' });
  }
  try { res.json(lineage.acceptObligation(record, obligation, beneficiary, holder)); } catch (e) { lineageError(res, e); }
});

/** Obligations proposed against records you hold, waiting on your decision. */
app.get('/lineage/obligations/proposals', (req, res) => {
  if (!requireLineage(res)) return;
  const holder = holderOf(req);
  if (!holder) return res.status(401).json({ error: 'holder key required' });
  res.json({ proposals: lineage.proposalsFor(holder, req.query) });
});

/** Release an obligation, or withdraw a proposal. Only the beneficiary. */
app.delete('/lineage/obligations/:record', (req, res) => {
  if (!requireLineage(res)) return;
  const holder = holderOf(req);
  if (!holder) return res.status(401).json({ error: 'holder key required' });
  const { obligation } = req.body || {};
  if (!obligation) return res.status(400).json({ error: 'obligation required' });
  try { res.json(lineage.discharge(req.params.record, obligation, holder)); } catch (e) { lineageError(res, e); }
});

/**
 * Decide a clean-descent claim. Public — a buyer checks this without an account,
 * and learns only accepted or rejected.
 */
app.post('/lineage/verify', (req, res) => {
  if (!requireLineage(res)) return;
  const { record, chain } = req.body || {};
  if (!record) return res.status(400).json({ error: 'record required' });
  try { res.json({ ...lineage.verifyDescent(record, Array.isArray(chain) ? chain : []), ...REGISTRY_ATTESTATION }); } catch (e) { res.status(400).json({ error: e.message }); }
});

/**
 * The open listing of every obligation, edge and proposal is gone (round 3, P5). It carried
 * each obligation's record, when it was made and its beneficiary's party id, one per
 * holder: a stranger could group records by holder and list a holder's royalty licences,
 * which the registry refuses to answer anywhere else. The public answer is per record:
 * POST /lineage/verify (is this record clean through its declared ancestry; "this record
 * carries an unmet obligation" when it is not), and GET /lineage/ancestors/:record. A
 * holder sees the proposals against their own records at /lineage/obligations/proposals.
 */
app.get('/lineage/obligations', (_req, res) => {
  res.status(410).json({
    error: 'the listing of all obligations is no longer published; ask about one record with POST /lineage/verify { record }',
  });
});

/**
 * Declared ancestry of a record. A malformed commitment is a 400: it reached the generic
 * handler as a 500 (round D). Paged (?limit=, ?offset=); `total` is the full count.
 */
app.get('/lineage/ancestors/:record', (req, res) => {
  if (!requireLineage(res)) return;
  let all;
  try { all = lineage.ancestorsOf(req.params.record); } catch (e) { return res.status(400).json({ error: e.message }); }
  const { limit, offset } = pageOf(req.query, 500, 1000);
  res.json({ ancestors: all.slice(offset, offset + limit), total: all.length, limit, offset });
});

// ---- embeddable verifier ----
//
// Verification is the act that spreads the format, so it works anywhere with no
// account, no key and no build step. Served as a plain script tag on purpose.

const publicBase = () => process.env.PUBLIC_BASE || 'https://veilcore-api-production.up.railway.app';

app.get('/embed.js', (_req, res) => {
  if (!embed) return res.status(503).type('application/javascript').send('/* embed unavailable */');
  res.type('application/javascript').set('Cache-Control', 'public, max-age=300').send(embed.embedScript(publicBase()));
});

app.get('/embed/:id', (req, res) => {
  if (!embed || !lineage) return res.status(503).type('html').send('');
  const row = db.prepare('SELECT body, holder_key, first_seen FROM records WHERE id = ?').get(req.params.id);
  if (!row) return res.type('html').send(embed.renderEmbed({ found: false }, publicBase()));
  const r = JSON.parse(row.body);
  // The same rule as /verify: the holder's grant, narrowed (never widened) by ?show=, and
  // holder-written values only from the grant, only while they are current.
  const show = req.query.show;
  const grant = grantFor(row, req.params.id);
  const { on, notGranted, refused } = effectiveDisclosure(grant.show, show);
  const { stale, pairingStale } = dropStale(on, grant, r);

  // The name only as /verify gives it: published by the holder, or a row from before names
  // were sealed (publicName).
  const name = publicName(r, on, grant.values ?? {});
  const out = {
    found: true,
    id: r.id,
    ...(name !== undefined ? { cultivar: name } : {}),
    recordFingerprint: r.recordFingerprint,
    // The holder's own date, labelled as such by the renderer, and only if they chose to
    // show it. The registry's date is separate and always shown, because it is what the
    // record's integrity claim is measured from.
    ...(on.has('sealed-at') ? { sealedAt: grant.values?.loggedAt } : {}),
    registryFirstSeen: row.first_seen ? new Date(row.first_seen).toISOString() : null,
    supersededBy: publicSupersededBy(r, row.holder_key),
    supersedes: publicSupersedes(r.supersedes),
    // Current names here, as before; /verify keeps the older ones its page reads.
    disclosed: inOrder(on),
  };

  // Whether the sealing date rests on a ledger or only on this registry. Reporting a
  // date without saying which would let a reader assume the stronger claim.
  if (batches && r.recordFingerprint) {
    const proof = batches.proofFor(r.recordFingerprint);
    if (proof && proof.anchor) out.anchor = proof.anchor;
  }

  // Attestations differ in weight. The embed reports the difference rather than
  // flattening signed, unsigned and retracted into one word. Public already (anyone can
  // list them by the fingerprint), so not a grant. Never a private signature: the embed
  // reads as a stranger (no reader test), so forSubject leaves them out (8 Nov 2026); a ?show= without attestation-status
  // still leaves them out, as links made before grants expect. One bounded page, vetted
  // signers first (round D).
  if (attesters && r.recordFingerprint && (show === undefined || effectiveDisclosure(new Set(DISCLOSURE_KEYS), show).on.has('attestation-status'))) {
    // One small page: the embed names at most four signers and counts the rest.
    out.attestations = attesters.forSubject(r.recordFingerprint, { limit: EMBED_ATTESTATIONS });
    // A holder's own unsigned "attestation" field is not shown: it is their word.
  }
  // The signatures the holder chose to show (values.sharedAttestations), exactly as /verify
  // answers them (sharedFor) and under the same grant (12 Nov 2026). The embed read only the
  // public list, so with a lab's report shared it still said nobody had confirmed the record.
  if (on.has('attestation-status')) {
    const shared = sharedFor(row, r, grant.values ?? {});
    if (shared.length) {
      const listed = out.attestations ?? [];
      const seen = new Set(listed.map((a) => a.attestationId));
      out.attestations = [...listed, ...shared.filter((a) => !seen.has(a.attestationId))];
    }
  }
  // The lab receipts' sample details, as /verify answers them, under the same grant.
  if (on.has('attestation-status')) {
    const custody = publicCustody(req.params.id, row, r, grant.values ?? {}, pairingStale);
    if (custody.length) out.custody = custody;
  }

  if (notGranted.length) out.notGranted = notGranted;
  if (stale.length) out.staleGrant = stale;
  if (refused.length) {
    out.unavailable = refused;
    out.unavailableReason = NEVER_DISCLOSED_REASON;
  }

  // What the holder shares can be taken back at any time: never kept by a cache.
  res.type('html').set('Access-Control-Allow-Origin', '*').set('Cache-Control', 'no-store').send(embed.renderEmbed(out, publicBase()));
});

// ---- transfers ----
//
// The moment material changes hands is where provenance is established. A transfer does
// not move a record: the recipient receives a new one declaring the original as parent,
// because that is what physically happened.

const requireTransfers = (res) => {
  if (!transfers) { res.status(503).json({ error: 'transfers not ready' }); return false; }
  return true;
};

/** Offer a record to a recipient. Nothing moves until they claim it. */
app.post('/transfers', (req, res) => {
  if (!requireTransfers(res)) return;
  const holder = holderOf(req);
  if (!holder) return res.status(401).json({ error: 'holder key required' });
  // `sample` (optional, deliveries made before sealing only): the sample's label, seal
  // number, where and when it was taken and a witness, as the breeder writes them
  // (transfer.mjs custodyFields). With a sealed offer it is refused here: the sender seals
  // the sample details with the offer key and sends them to POST /transfers/:id/custody.
  // `sealedOffer`: what the recipient is told about the material (name, breeder, quantity,
  // note...), locked with a key that travels only in the delivery code (transfer.mjs).
  const { sourceRecord, toHandle, termsHash, quantity, note, sample, sealedOffer } = req.body || {};
  if (!sourceRecord) return res.status(400).json({ error: 'sourceRecord and toHandle required' });
  // toHandle is checked in transfers.offer: a tag (sealed.js HANDLE_TAG), or 400 "toHandle is a tag, not a name".
  const { code, ...out } = transfers.offer({ sourceRecord, fromHolder: holder, toHandle, termsHash, quantity, note, sample, sealedOffer });
  res.status(out.error ? (code ?? 400) : 200).json(out);
});

/** Claim a transfer offered to you. */
app.post('/transfers/:id/claim', (req, res) => {
  if (!requireTransfers(res)) return;
  const holder = holderOf(req);
  if (!holder) return res.status(401).json({ error: 'holder key required' });
  // The received record is sealed and dated by the recipient as their own content, so on the
  // free plan it needs room. Refused here rather than left as a stub that can never be dated.
  const planRoom = billing.planRoom(storedKeyOf(req));
  if (planRoom.room <= 0) return res.status(413).json(capRefusal(planRoom.cap));
  const { code, ...out } = transfers.claim({
    transferId: req.params.id,
    holderKey: holder,
    claimCode: (req.body || {}).claimCode,
    // The received record is written on this address's behalf: its bytes (the copied
    // profile can be most of 64 KB) count against the daily allowance like a save's.
    charge: (n) => chargeWriteBytes(req, n),
    // Optional: the lab's signed receipt. A claim is never undone over it; the answer has
    // receiptAttestationId when it was attached, receiptError when not (transfer.mjs).
    receiptAttestationId: (req.body || {}).receiptAttestationId,
  });
  res.status(out.error ? (code ?? 400) : 200).json(out);
});

/**
 * The lab attaches its signed receipt to a delivery it claimed: body { attestationId }, the
 * id of a chain-of-custody attestation already posted to /attestations about exactly this
 * delivery. The holder key is checked as for a claim: x-holder-key, or `holderKey` in the
 * body (the same key if both are sent). Only the delivery's claimant; a later one replaces
 * the earlier on the same checks. 404 no such delivery or attestation, 403 not the
 * claimant, 409 not claimed / record not sealed / attestation withdrawn, 400 not about
 * this delivery.
 */
app.post('/transfers/:id/receipt', (req, res) => {
  if (!requireTransfers(res)) return;
  const { holderKey: inBody, attestationId } = req.body || {};
  const header = holderOf(req);
  if (inBody !== undefined && (typeof inBody !== 'string' || !HOLDER_KEY.test(inBody.trim()))) {
    return res.status(400).json({ error: 'holderKey must be 64 hexadecimal characters' });
  }
  if (header && inBody !== undefined && storedHolderKey(header) !== storedHolderKey(inBody.trim())) {
    return res.status(400).json({ error: 'x-holder-key and holderKey name different keys' });
  }
  const holder = header || (inBody ?? '').trim();
  if (!holder) return res.status(401).json({ error: 'holder key required' });
  if (!header) adoptPlaintextKey(db, holder);
  const { code, ...out } = transfers.attachReceipt({ transferId: req.params.id, holderKey: holder, attestationId });
  res.status(out.error ? (code ?? 400) : 200).json(out);
});

/**
 * The sample's chain of custody on a delivery (transfer.mjs custodyFields). POST body
 * { sample } from the sender, until the lab receives it; or { arrival } from whoever
 * received it, which the lab's signed receipt then covers. GET returns { transferId, sample,
 * arrival, receiptAttestationId } to either of them. x-holder-key. 404 no such delivery, 403
 * not that party, 409 not received yet / already received, 400 a field out of shape.
 * On a delivery made with a sealed offer each side is a box sealed with the offer key
 * ({ v, alg, kid, iv, ct }, ct at most 8,000 characters), stored and served unread; plain
 * fields are refused (CONTRACT.md #27).
 */
app.post('/transfers/:id/custody', (req, res) => {
  if (!requireTransfers(res)) return;
  const holder = holderOf(req);
  if (!holder) return res.status(401).json({ error: 'holder key required' });
  const { sample, arrival } = req.body || {};
  const { code, ...out } = transfers.setCustody({ transferId: req.params.id, holderKey: holder, sample, arrival });
  res.status(out.error ? (code ?? 400) : 200).json(out);
});

app.get('/transfers/:id/custody', (req, res) => {
  if (!requireTransfers(res)) return;
  const holder = holderOf(req);
  if (!holder) return res.status(401).json({ error: 'holder key required' });
  const { code, ...out } = transfers.custody({ transferId: req.params.id, holderKey: holder });
  res.status(out.error ? (code ?? 400) : 200).json(out);
});

/**
 * Removed (sealed records round 2, P2): it told anyone who guessed a handle that something
 * was waiting for it, and when, and handles were names and email addresses. The registry
 * now holds only a tag the sender's browser makes from the name, which a stranger can't
 * make, so the list could answer nothing useful. The recipient claims with the id and code
 * the sender passes them, as before. 410 so an older site says plainly that it is gone.
 */
app.get('/transfers/pending/:handle', (_req, res) => {
  res.status(410).json({ error: 'removed' });
});

/**
 * The offer of a delivery, again, for the holder who claimed it (sealed records round 2,
 * L4): { transferId, offerSealed } exactly as the sender sent it, or { transferId,
 * offerPlain } for a code made before sealing (the same fields the claim gave). The claim
 * answer is the only other place it is given, so a browser closed after claiming left the
 * received record a stub for good; with this the app finishes receiving it. Anyone but the
 * claimant, the sender included, gets 404, as for a delivery that does not exist.
 */
app.get('/transfers/:id/offer', (req, res) => {
  if (!requireTransfers(res)) return;
  const holder = holderOf(req);
  if (!holder) return res.status(401).json({ error: 'holder key required' });
  res.set('Cache-Control', 'no-store');
  const { code, ...out } = transfers.offerFor({ transferId: req.params.id, holderKey: holder });
  res.status(out.error ? (code ?? 400) : 200).json(out);
});

/**
 * Transfers this holder has sent: { transfers, total, limit, offset }; ?limit= default 500,
 * most 1000. Each has received_record and receipt_attestation_id (null until set).
 */
app.get('/transfers/sent', (req, res) => {
  if (!requireTransfers(res)) return;
  const holder = holderOf(req);
  if (!holder) return res.status(401).json({ error: 'holder key required' });
  res.json(transfers.sent(holder, req.query));
});

// ---- lab results (lineage/lab-results.mjs) ----
//
// A lab sends results back on the delivery it received, locked to the breeder's key. The
// registry stores the locked file and can't open it. The files are kept in LAB_RESULTS_DIR
// (default: a lab-results folder next to the database), not in the database. The off-site
// backup sends each one once after it arrives (backup.mjs); one that arrived after the last
// backup is lost with the volume, and the breeder asks the lab to send it again. Kept 180 days; LAB_RESULTS_MAX_BYTES (default 2 GiB) caps them all, and
// LAB_RESULTS_MAX_BYTES_PER_SENDER (default 300 MB) those on one holder's deliveries.

const requireResults = (res) => {
  if (!labResults) { res.status(503).json({ error: 'lab results not ready' }); return false; }
  return true;
};

/**
 * The lab adds a locked result (an age file, the request body). ?attestationId= links its
 * signed fingerprint; ?replaces=<result id> names an earlier result on this delivery that
 * this one corrects. A first report on a delivery with no receipt also sends x-lab-key-proof:
 * the signing key's own signature over the delivery and signature ids (lab-results.mjs). 507 when the store is full, 429 past the lab's daily allowance.
 */
app.post(
  '/transfers/:id/results',
  express.raw({ type: 'application/octet-stream', limit: '16mb', verify: countWriteBytes }),
  (req, res) => {
    if (!requireResults(res)) return;
    const holder = holderOf(req);
    if (!holder) return res.status(401).json({ error: 'holder key required' });
    const { code, ...out } = labResults.add({
      transferId: req.params.id,
      holder,
      bytes: Buffer.isBuffer(req.body) ? req.body : undefined,
      attestationId: typeof req.query.attestationId === 'string' ? req.query.attestationId : undefined,
      replaces: typeof req.query.replaces === 'string' ? req.query.replaces : undefined,
      // A first report on a delivery with no receipt: its key's proof (lab-results.mjs labKeyProofText).
      keyProof: (req.get('x-lab-key-proof') || '').trim().toLowerCase() || undefined,
    });
    res.status(out.error ? (code ?? 400) : 200).json(out);
  },
);

/** The results on a delivery (no files): for its sender or its receiver. Each says `replaces` and `withdrawnAt` when set. */
app.get('/transfers/:id/results', (req, res) => {
  if (!requireResults(res)) return;
  const holder = holderOf(req);
  if (!holder) return res.status(401).json({ error: 'holder key required' });
  res.set('Cache-Control', 'no-store');
  const { code, ...out } = labResults.list({ transferId: req.params.id, holder });
  res.status(out.error ? (code ?? 400) : 200).json(out);
});

/** One locked file, for the sender. */
app.get('/transfers/:id/results/:resultId', (req, res) => {
  if (!requireResults(res)) return;
  const holder = holderOf(req);
  if (!holder) return res.status(401).json({ error: 'holder key required' });
  res.set('Cache-Control', 'no-store');
  const out = labResults.file({ transferId: req.params.id, resultId: req.params.resultId, holder });
  if (out.error) return res.status(out.code ?? 400).json({ error: out.error });
  res.type('application/octet-stream').send(out.bytes);
});

/**
 * Remove a result. The sender's delete removes it entirely; the receiver's (the lab's) is a
 * withdrawal: the file is deleted and the listing keeps the line, with `withdrawnAt`.
 */
app.delete('/transfers/:id/results/:resultId', (req, res) => {
  if (!requireResults(res)) return;
  const holder = holderOf(req);
  if (!holder) return res.status(401).json({ error: 'holder key required' });
  const { code, ...out } = labResults.remove({ transferId: req.params.id, resultId: req.params.resultId, holder });
  res.status(out.error ? (code ?? 400) : 200).json(out);
});

// ---- batch anchoring ----
//
// One transaction anchors thousands of records. Holders never need a wallet, and the
// per-record cost of settlement collapses. Sealing and anchoring are separate: a proof
// exists and is useful the moment a batch is sealed, and upgrades when the root lands.

const requireBatches = (res) => {
  if (!batches) { res.status(503).json({ error: 'batching not ready' }); return false; }
  return true;
};

/** Commitments sealed but not yet batched. */
app.get('/batches/pending', (req, res) => {
  // Registry-only: it scans every record, so public it was a cheap way to load us down.
  if (!requireOperator(req, res)) return;
  if (!requireBatches(res)) return;
  const rows = batches.pending();
  const skipped = batches.unsealable();
  res.json({ count: rows.length, records: rows.map((r) => r.id), ...(skipped.length ? { skipped } : {}) });
});

/** Seal everything pending into a batch. */
app.post('/batches/seal', async (req, res) => {
  if (!requireOperator(req, res)) return;
  if (!requireBatches(res)) return;
  const { code, ...out } = await batches.seal();
  res.status(out.error ? (code ?? 400) : 200).json(out);
});

/**
 * Record where a batch root was anchored.
 *
 * Deliberately a separate call: the anchoring transaction is made by whoever operates
 * this registry, from wherever they hold a wallet, and the registry only records it.
 */
app.post('/batches/:id/anchor', (req, res) => {
  if (!requireOperator(req, res)) return;
  if (!requireBatches(res)) return;
  const { chain, network, contractAddress, txHash, blockHeight, anchoredAt } = req.body || {};

  // Nothing is recorded until the registry publishes where it anchors. A proof naming a
  // network /.well-known does not list is the disagreement the rule below exists to stop.
  if (!ANCHOR_CONFIG.configured) {
    return res.status(503).json({
      error: 'anchoring is not configured: set VEILCORE_ANCHOR_NETWORK and VEILCORE_ANCHOR_CONTRACT',
    });
  }

  // Which network and contract are named, never defaulted: a default is a label nobody
  // chose, and it changed once already (preview to preprod) while the discovery document
  // still named the old one. An anchor must match VEILCORE_ANCHOR_*, so a proof and
  // /.well-known/veilcore-registry cannot disagree, and after the move to mainnet a
  // transaction made on Preview or preprod cannot be recorded as a mainnet anchor.
  if (typeof network !== 'string' || !NAME.test(network)) {
    return res.status(400).json({ error: 'network is required (e.g. "preprod" or "mainnet")' });
  }
  if (chain !== undefined && (typeof chain !== 'string' || !NAME.test(chain))) {
    return res.status(400).json({ error: 'chain must be a short lower-case name' });
  }
  if (typeof contractAddress !== 'string' || !ADDRESS.test(contractAddress)) {
    return res.status(400).json({ error: 'contractAddress is required: the 32-byte hex address of the anchoring contract' });
  }
  const anchorChain = chain ?? ANCHOR_CONFIG.chain;
  if (anchorChain !== ANCHOR_CONFIG.chain || network !== ANCHOR_CONFIG.network
    || normaliseHex(contractAddress) !== ANCHOR_CONFIG.contractAddress) {
    return res.status(400).json({
      error: 'this registry publishes a different anchor (see /.well-known/veilcore-registry); change VEILCORE_ANCHOR_* first',
    });
  }

  // A proof naming an anchor nobody can look up is not independently checkable, which
  // is the entire point of the proof. A placeholder here would quietly hollow that out,
  // so the shape is enforced rather than trusted.
  if (typeof txHash !== 'string' || !ADDRESS.test(txHash)) {
    return res.status(400).json({ error: 'txHash must be a 32-byte transaction hash' });
  }
  // The site reads blockHeight as a number and refuses a proof whose anchor says otherwise,
  // so a string here would have hidden every proof in the batch.
  if (blockHeight !== undefined && !(Number.isSafeInteger(blockHeight) && blockHeight >= 0)) {
    return res.status(400).json({ error: 'blockHeight must be a non-negative whole number' });
  }
  // An instant, not a wall-clock reading (round 2): a date with no time zone was stored as
  // sent, so readers in different zones took it to mean different instants, and the
  // checks against the batch's sealing ran in the server's own zone. Z or an offset is
  // required, and what is stored is the same instant in UTC.
  if (anchoredAt !== undefined && (typeof anchoredAt !== 'string' || !ISO_INSTANT.test(anchoredAt) || Number.isNaN(Date.parse(anchoredAt)))) {
    return res.status(400).json({ error: 'anchoredAt must be an ISO 8601 date and time with a time zone, e.g. 2026-10-08T14:03:00Z or 2026-10-08T16:03:00+02:00' });
  }
  // Stored as 64 lowercase hex, the form veilcore-records 0.15 and the site compare.
  const out = batches.recordAnchor(req.params.id, {
    chain: anchorChain,
    network,
    contractAddress: normaliseHex(contractAddress),
    txHash: normaliseHex(txHash),
    ...(blockHeight !== undefined ? { blockHeight } : {}),
    anchoredAt: new Date(anchoredAt ?? Date.now()).toISOString(),
  });
  if (out.error) return res.status(out.code ?? 400).json({ error: out.error });
  res.json(out);
});

/**
 * The inclusion proof for a record. Public, and self-contained.
 *
 * A holder keeps this and can prove their record's age years later with the published
 * package and a chain lookup — with no dependency on this registry still existing.
 */
app.get('/proof/:commitment', (req, res) => {
  if (!requireBatches(res)) return;
  const proof = batches.proofFor(req.params.commitment);
  if (!proof) return res.status(404).json({ error: 'not yet batched' });
  res.json(proof);
});

/**
 * A record's own RFC 3161 timestamp (lineage/record-stamps.mjs), asked for the moment the
 * registry took its proof code. Public, like /proof: the token stamps the proof code's 32 raw
 * bytes, and anyone checks it with `openssl ts -verify` or the SDK's verifyTimestampToken.
 *   200 { status: 'stamped', stamps, tokens: [{ kind: 'rfc3161', token, tsa, genTime, qualified?, signer? }],
 *         stillAsking?, note }   one token per TSA that has answered (VEILCORE_TSA_URL may list several)
 *   202 { status: 'queued' }      asked for, none back yet
 *   404 { status: 'none' }        none of its own (its batch's token dates it), no TSA set, a proof
 *                                 code this registry never took, or one no record carries now: the
 *                                 same answer for each, so it says nothing about which
 */
app.get('/proof/:commitment/instant', (req, res) => {
  if (!/^[0-9a-f]{64}$/.test(req.params.commitment)) return res.status(400).json({ error: 'a proof code is 64 lowercase hex characters' });
  if (!recordStamps) return res.status(503).json({ error: 'starting' });
  const out = recordStamps.instantFor(req.params.commitment);
  if (!out) return res.status(404).json({ status: 'none' });
  if (out.status === 'queued') return res.status(202).json(out);
  if (out.status === 'batch') return res.status(404).json({ status: 'none' });
  res.json(out);
});

/**
 * A token as DER, for `openssl ts -verify -data <proof code as 32 raw bytes> -in instant.tst -token_in`.
 * ?tsa=<url> picks one TSA's token; without it, the first there is.
 */
app.get('/proof/:commitment/instant.tst', (req, res) => {
  if (!/^[0-9a-f]{64}$/.test(req.params.commitment)) return res.status(400).json({ error: 'a proof code is 64 lowercase hex characters' });
  const token = recordStamps?.tokenFor(req.params.commitment, typeof req.query.tsa === 'string' ? req.query.tsa : undefined);
  if (!token) return res.status(404).json({ error: 'no timestamp of its own for this proof code' });
  res.type('application/octet-stream').set('Content-Disposition', 'attachment; filename="instant.tst"').send(token);
});

/**
 * Stamp a batch with OpenTimestamps (for a batch sealed before stamping, or a failed
 * stamp). A batch that already has a proof is refused (409) unless ?force=1, and then the
 * fresh calendar answers are merged in beside the old ones, never in place of them.
 */
app.post('/batches/:id/opentimestamps', async (req, res) => {
  if (!requireOperator(req, res)) return;
  if (!requireBatches(res)) return;
  const out = await batches.stamp(req.params.id, { force: req.query.force === '1' });
  if (out.error) return res.status(out.code ?? 502).json({ error: out.error });
  res.json(out);
});

/** Ask the calendars whether a batch's pending proof has reached a Bitcoin block. */
app.post('/batches/:id/opentimestamps/upgrade', async (req, res) => {
  if (!requireOperator(req, res)) return;
  if (!requireBatches(res)) return;
  const out = await batches.upgrade(req.params.id);
  if (out.error) return res.status(out.code ?? 502).json({ error: out.error });
  res.json(out);
});

/** One pass of what the timer does: retry failed stamps, upgrade pending ones. */
app.post('/batches/opentimestamps/maintenance', async (req, res) => {
  if (!requireOperator(req, res)) return;
  if (!requireBatches(res)) return;
  res.json(await batches.otsMaintenance());
});

/** The batch root as the 32 raw bytes OpenTimestamps stamped. Public. */
app.get('/batches/:id/root.bin', (req, res) => {
  if (!requireBatches(res)) return;
  const b = batches.otsFor(req.params.id);
  if (!b) return res.status(404).json({ error: 'no such batch' });
  res.type('application/octet-stream').set('Content-Disposition', 'attachment; filename="root.bin"').send(Buffer.from(b.root, 'hex'));
});

/**
 * The OpenTimestamps proof for a batch root. Public. Check it with the official client:
 * `ots verify root.bin.ots` beside root.bin (after `ots upgrade` once Bitcoin confirms).
 */
app.get('/batches/:id/root.bin.ots', (req, res) => {
  if (!requireBatches(res)) return;
  const b = batches.otsFor(req.params.id);
  if (!b) return res.status(404).json({ error: 'no such batch' });
  if (!b.ots) return res.status(404).json({ error: 'this batch has no OpenTimestamps proof yet', status: b.status });
  res.type('application/vnd.opentimestamps.v1').set('Content-Disposition', 'attachment; filename="root.bin.ots"')
    .set('X-OpenTimestamps-Status', b.status).send(b.ots);
});

/**
 * The RFC 3161 timestamp token for a batch root (lineage/tsa.mjs). Public. Check it with
 * `openssl ts -verify -data root.bin -in root.tst -token_in -CAfile <the TSA's chain>`.
 */
app.get('/batches/:id/root.tst', (req, res) => {
  if (!requireBatches(res)) return;
  // ?tsa=<url>: the token from that TSA, when VEILCORE_TSA_URL lists several (the proof's
  // rfc3161 anchors name each one's address). Without it, the first TSA's.
  const which = typeof req.query.tsa === 'string' ? req.query.tsa : undefined;
  const b = batches.tsaFor(req.params.id, which);
  if (b === undefined) return res.status(404).json({ error: 'no such batch' });
  if (!b.token) return res.status(404).json({ error: 'this batch has no RFC 3161 timestamp yet' });
  res.type('application/octet-stream').set('Content-Disposition', 'attachment; filename="root.tst"').send(b.token);
});

/**
 * Every batch, anchored or pending, with its OpenTimestamps status. With `?limit=` (1-500),
 * one page, newest first, and `next`: pass it as `?before=` for the page after, null on the
 * last (scripts/mirror). Without `limit`, every batch in one answer, as the site reads it.
 */
const BATCH_PAGE_MAX = 500;
app.get('/batches', (req, res) => {
  if (!requireBatches(res)) return;
  const { limit, before } = req.query;
  if (limit === undefined && before === undefined) return res.json({ batches: batches.list() });
  const n = typeof limit === 'string' && /^[1-9][0-9]{0,3}$/.test(limit) ? Number(limit) : NaN;
  if (!(n <= BATCH_PAGE_MAX)) return res.status(400).json({ error: `limit must be a whole number from 1 to ${BATCH_PAGE_MAX}` });
  if (before !== undefined && (typeof before !== 'string' || !/^[A-Za-z0-9-]{1,64}$/.test(before))) {
    return res.status(400).json({ error: 'before must be a batchId' });
  }
  const out = batches.list({ limit: n, ...(before !== undefined ? { before } : {}) });
  if (out.error) return res.status(400).json({ error: out.error });
  res.json(out);
});

// ---- attester registry ----
//
// Maps a public key to a claimed identity, and holds signed attestations. The registry
// records who vouched for an attester and never vouches itself — a registry that
// certifies its own members has stopped being neutral.

const ATTESTATION_PAGE = 100; // lineage/attesters.mjs ATTESTATION_LIMITS.page
/** What the embed reads per view, vetted signers first (deep dive, 8 Oct 2026). */
const EMBED_ATTESTATIONS = 20;

const requireAttesters = (res) => {
  if (!attesters) { res.status(503).json({ error: 'attester registry not ready' }); return false; }
  return true;
};

/** Register an attester. The public key is the identity; the rest are their claims. */
app.post('/attesters', async (req, res) => {
  if (!requireAttesters(res)) return;
  const out = await attesters.register(req.body || {});
  res.status(out.error ? 400 : 200).json(out);
});

/**
 * Registry operator only: record a name check on a key, or take the mark off. This is the
 * only route by which a signer's name is described anywhere as matched, so it takes the
 * operator token, not a holder key or the attester's own signature. The procedure is the
 * site repo's docs/lab-name-checks.md; the README section "Marking a lab's key" has the
 * bodies. Mark: { vetted: true, check: {...}, note? }. Unmark: { vetted: false, reason, note? }.
 */
app.post('/attesters/:publicKey/vetting', (req, res) => {
  if (!requireOperator(req, res)) return;
  if (!requireAttesters(res)) return;
  const out = attesters.setVetted(req.params.publicKey, req.body);
  res.status(out.error ? (out.error === 'not registered' ? 404 : 400) : 200).json(out);
});

/** Registry operator only: every mark and unmark on a key, with the private notes. */
app.get('/attesters/:publicKey/vetting', (req, res) => {
  if (!requireOperator(req, res)) return;
  if (!requireAttesters(res)) return;
  if (!attesters.lookup(req.params.publicKey)) return res.status(404).json({ error: 'not registered' });
  res.json({ log: attesters.vettingLog(req.params.publicKey) });
});

/**
 * The lab names its website and the registry looks (lineage/lab-domain.mjs; the site repo's
 * docs/lab-domain-keys.md). Body: { domain, issuedAt, signature }, the key's own Ed25519
 * signature over domainClaimPayload, so only the key's holder can name or change its domain
 * (attack, 5 Nov 2026: unsigned, anyone could show their site beside a lab's signatures or
 * wipe the lab's). A signed claim counts against the ten-minute limit only once it verifies.
 */
const lastDomainLook = new Map();
app.post('/attesters/:publicKey/domain', async (req, res) => {
  if (!requireAttesters(res)) return;
  const key = String(req.params.publicKey).toLowerCase();
  const { checkLabDomain, cleanDomain, verifyDomainClaim } = await import('./lineage/lab-domain.mjs');
  const domain = cleanDomain(req.body?.domain);
  if (!domain) return res.status(400).json({ error: 'a plain domain name, like acme-labs.com' });
  const issuedAt = req.body?.issuedAt;
  if (!(await verifyDomainClaim({ publicKey: key, domain, issuedAt, signature: req.body?.signature }))) {
    return res.status(400).json({ error: 'the key\'s signature over this domain does not verify' });
  }
  const claim = attesters.claimDomain(key, domain, issuedAt);
  if (claim.error) return res.status(claim.error === 'not registered' ? 404 : claim.code === 'withdrawn' ? 409 : 400).json({ error: claim.error, ...(claim.code ? { code: claim.code, domain: claim.domain } : {}) });
  const last = lastDomainLook.get(key) ?? 0;
  if (Date.now() - last < 10 * 60_000) return res.status(429).json({ error: 'looked less than ten minutes ago; try again later' });
  lastDomainLook.delete(key);
  lastDomainLook.set(key, Date.now());
  while (lastDomainLook.size > 10_000) lastDomainLook.delete(lastDomainLook.keys().next().value);
  const out = await checkLabDomain(domain, key, labDomainOptions);
  if (out.error) return res.status(400).json(out);
  // The claim is checked again right before the write: the look took time, and a withdrawal
  // or a newer claim recorded meanwhile wins (review, 18 Nov 2026).
  const wrote = attesters.setDomainCheck(key, out, { claimIssuedAt: issuedAt, claimSignature: String(req.body.signature).toLowerCase() });
  if (wrote.error) return res.status(wrote.code === 'withdrawn' ? 409 : 400).json({ error: wrote.error, ...(wrote.code ? { code: wrote.code, domain: wrote.domain } : {}) });
  res.json(out);
});
/** Tests replace the network parts (fetchFile, resolveTxt). */
let labDomainOptions = {};
const setLabDomainOptions = (o) => { labDomainOptions = o; };
/** Tests only: forget the ten-minute limit between looks. */
const lastDomainLookReset = () => lastDomainLook.clear();

/**
 * Look again at every lab domain whose last look is a day old, eight at a time, each look
 * bounded (lab-domain.mjs), so a key a lab removes stops showing and one slow site can't hold
 * up the rest. Runs hourly from the stored times, so a deploy doesn't reset it.
 */
const relookLabDomains = async (olderThanMs) => {
  if (!attesters) return;
  const { checkLabDomain } = await import('./lineage/lab-domain.mjs');
  const due = attesters.domainChecksDue(olderThanMs);
  const work = async () => {
    // Every website the key is watched on: the current one, ones it moved from, a withdrawn one
    // (lab-domain.mjs domainsToLook). A look at one the record no longer watches is skipped.
    for (let d = due.shift(); d; d = due.shift()) {
      for (const domain of d.domains) {
        const out = await checkLabDomain(domain, d.publicKey, labDomainOptions);
        if (!out.error) attesters.setDomainCheck(d.publicKey, out);
      }
    }
  };
  await Promise.all(Array.from({ length: 8 }, work));
};
if (DB_PATH !== ':memory:') {
  let relooking = false;
  const relook = () => {
    if (relooking) return;
    relooking = true;
    relookLabDomains().catch((e) => console.error('lab domain look failed:', e.message)).finally(() => { relooking = false; });
  };
  setTimeout(relook, 120_000).unref();
  setInterval(relook, 3_600_000).unref();
}

/**
 * Look up an attester. Public: knowing who signed something is the point. Carries the
 * name check record (nameCheck, nameCheckStatus), never the operator's private note.
 */
app.get('/attesters/:publicKey', (req, res) => {
  if (!requireAttesters(res)) return;
  const a = attesters.lookup(req.params.publicKey);
  if (!a) return res.status(404).json({ error: 'not registered' });
  res.json(a);
});

/** Submit a signed attestation. Rejected if the signature does not verify. */
app.post('/attestations', async (req, res) => {
  if (!requireAttesters(res)) return;
  const out = await attesters.submit(req.body || {});
  res.status(out.error ? 400 : 200).json(out);
});

/** Retract one. Only the issuing key can, and the attestation is never deleted. */
app.post('/attestations/:id/retract', async (req, res) => {
  if (!requireAttesters(res)) return;
  const out = await attesters.retract({ ...(req.body || {}), attestationId: req.params.id });
  res.status(out.error ? 400 : 200).json(out);
});

/**
 * Who may see a private signature (8 Nov 2026, lineage/attesters.mjs PRIVATE_SQL: every lab
 * report and receipt, and a lab key's genetic-fingerprint or inspection): the record's
 * holder, the delivery's sender and that lab, by holder key. A signature is theirs when
 *   · this key is the first holder of the fingerprint the signature is about
 *     (fingerprint_holders), and held it before the signature was stored;
 *   · this key sent a delivery of that record (transfers.source_fingerprint) before the
 *     signature was stored: the breeder, even after the report's file or the record is gone;
 *   · it is tied to a delivery of that record that this key claimed, or sent before the
 *     signature was stored: a lab report sent back on it (lab_results.attestation_id) or its
 *     receipt (transfers.receipt_attestation_id). The delivery must be of the record the
 *     signature is about: without that, knowing an id and tying it would be enough to read it;
 *   · this key claimed a delivery of that record, and the signature is by the key that signed
 *     that delivery's receipt or a report on it about the same record (that lab's other
 *     signatures on the plant), or it is a receipt for the record that claim made, before the
 *     lab has tied it on.
 * "Before the signature" (9 Nov 2026): a fingerprint takeover, or a delivery offered from a
 * record stored to read what was already signed, always comes after. `meta.createdAt` is when
 * the registry stored the signature; without it only the lab's own rules apply.
 * Anyone else, and any request without a holder key, is not told it exists: it is left out of
 * the list and the totals. Before this, only a lab report made before round 6 was held back (to
 * a stub), and every other was served whole to anyone with the proof code: the lab's name,
 * whether it is vetted, when it signed, and whether it was withdrawn or replaced, so anyone
 * could read which records a lab had handled. `me` is the stored form (storedHolderKey).
 */
const privateReaderFor = (me) => {
  if (!me) return undefined;
  const mine = (v) => typeof v === 'string' && v !== '' && asStoredKey(v) === me;
  const q = (sql) => { try { return db.prepare(sql); } catch { return null; } }; // a table not made yet: nothing tied
  const byResult = q(`SELECT t.from_holder, t.claimed_by, t.created_at FROM lab_results r JOIN transfers t ON t.id = r.transfer_id
    WHERE r.attestation_id = ? AND t.source_fingerprint = ?`);
  const byReceipt = q('SELECT from_holder, claimed_by, created_at FROM transfers WHERE receipt_attestation_id = ? AND source_fingerprint = ?');
  const bySource = q('SELECT id, from_holder, claimed_by, created_at, received_record, receipt_attestation_id FROM transfers WHERE source_fingerprint = ?');
  const resultsOn = q('SELECT attestation_id FROM lab_results WHERE transfer_id = ? AND attestation_id IS NOT NULL');
  const recordOf = db.prepare('SELECT holder_key, body FROM records WHERE id = ?');
  // A tied signature counts only if it is about the same record: a row tied before results
  // were checked (lab-results.mjs signatureProblem) may name another plant's signature.
  const signerOf = db.prepare('SELECT attester_key FROM attestations WHERE attestation_id = ? AND subject_commitment = ?');
  return (a, meta = {}) => {
    const id = a?.attestationId;
    const subject = a?.subjectCommitment;
    if (typeof id !== 'string' || typeof subject !== 'string') return false;
    const at = Number(meta.createdAt);
    const before = (t) => Number.isFinite(at) && Number.isFinite(Number(t)) && Number(t) <= at;
    const sentBefore = (t) => mine(t.from_holder) && before(t.created_at);
    const party = (t) => mine(t.claimed_by) || sentBefore(t);
    if (byResult?.all(id, subject).some(party) || byReceipt?.all(id, subject).some(party)) return true;
    const first = firstHolderOf.get(subject);
    if (first && mine(first.holder_key) && before(first.first_at)) return true;
    for (const t of bySource?.all(subject) ?? []) {
      if (sentBefore(t)) return true;
      if (!mine(t.claimed_by)) continue;
      const tied = [t.receipt_attestation_id, ...(resultsOn?.all(t.id) ?? []).map((r) => r.attestation_id)].filter(Boolean);
      if (tied.some((x) => signerOf.get(x, subject)?.attester_key === a.attester?.publicKey)) return true;
      if (a.type === 'chain-of-custody' && t.received_record) {
        const rec = recordOf.get(t.received_record);
        if (rec && mine(rec.holder_key) && parsedOr(rec.body, {}).recordFingerprint === a.documentHash) return true;
      }
    }
    return false;
  };
};
/** The private reader for this request's holder key; undefined without one. */
const labDocReader = (req) => {
  const raw = holderOf(req);
  return raw ? privateReaderFor(storedHolderKey(raw)) : undefined;
};

/**
 * The signatures a proof code's holder shares (12 Nov 2026), for /attestations/subject: the
 * ids the holder publishes on /verify (values.sharedAttestations, sharedFor), answered by
 * proof code too, so a page that has only the proof code (a claim link names the plant by it)
 * can read what the holder chose to show. Only from a record that
 *   · has `fp` as its fingerprint NOW: an edited record's old proof code answers nothing;
 *   · is held by the proof code's first holder (fingerprint_holders): a record stored under
 *     a taken-over proof code shares nothing, even one older code let in;
 *   · is not corrected: a record whose supersededBy names a correction its holder holds is
 *     replaced, and its old proof code answers nothing here (its /verify is unchanged);
 *   · has the attestation-status grant now;
 *   · is shared by EVERY such record: the holder may keep two records with one proof code,
 *     and unsharing on one of them takes the signature off here (fails closed).
 * Each is checked as /verify's are on every read (still about `fp`, a private one only while
 * the holder can see it). Unsharing, a new grant without it, deleting the record or editing
 * it takes it off at once. A delivery changes nothing: the recipient's record has its own
 * proof code, and only the holder of this one can share signatures about it.
 */
const recordsWithFingerprint = db.prepare(
  "SELECT id, body, holder_key FROM records WHERE json_extract(body, '$.recordFingerprint') = ?",
);
const sharedOnFingerprint = (fp) => {
  const out = new Set();
  if (!attesters || typeof fp !== 'string' || !/^[0-9a-f]{64}$/.test(fp)) return out;
  const first = firstHolderOf.get(fp);
  if (!first) return out;
  // Every current record of the first holder with this proof code must share it (12 Nov 2026):
  // the holder can keep two records with the same proof code, and taking a signature off one
  // of them left it listed here through the other. Unsharing on any one of them takes it off.
  let agreed = null;
  for (const row of recordsWithFingerprint.all(fp)) {
    if (asStoredKey(row.holder_key) !== asStoredKey(first.holder_key)) continue;
    const r = parsedOr(row.body, {});
    if (r.recordFingerprint !== fp) continue;
    if (typeof r.supersededBy === 'string' && holderOfId.get(r.supersededBy)?.holder_key === row.holder_key) continue;
    const grant = grantFor(row, row.id);
    const mine = new Set(grant.show.has('attestation-status') ? sharedFor(row, r, grant.values ?? {}).map((a) => a.attestationId) : []);
    agreed = agreed === null ? mine : new Set([...agreed].filter((id) => mine.has(id)));
    if (!agreed.size) return out;
  }
  for (const id of agreed ?? []) out.add(id);
  return out;
};

/**
 * Attestations about a record, with retraction status and strength. Public. Paged
 * (round D): ?limit= (default and most 100), ?offset=; vetted signers first. `total` is
 * the full count for this reader. A private signature (a lab's) is listed and counted only
 * when the holder key sent is the record holder's, the delivery's sender's or the lab's
 * (privateReaderFor), or when the proof code's holder shares it (sharedOnFingerprint): then it
 * is listed and counted for everyone, as on /verify. For anyone else the answer is the same as
 * if it weren't stored.
 */
app.get('/attestations/subject/:commitment', (req, res) => {
  if (!requireAttesters(res)) return;
  const { limit, offset } = pageOf(req.query, ATTESTATION_PAGE, ATTESTATION_PAGE);
  const personal = labDocReader(req);
  const shared = sharedOnFingerprint(req.params.commitment);
  const canSeePrivate = shared.size
    ? (a, meta) => shared.has(a?.attestationId) || (personal ? personal(a, meta) === true : false)
    : personal;
  // An answer that depends on who asks, or on a share the holder can take back, is never cached.
  if (canSeePrivate) res.set('Cache-Control', 'no-store');
  res.json({
    // The `private` mark only where the holder key's own reader shows the row (13 Nov 2026),
    // never on one listed because the holder shares it: to a stranger it names a lab key.
    attestations: attesters.forSubject(req.params.commitment, { limit, offset, canSeePrivate, markPrivate: personal }),
    total: attesters.countForSubject(req.params.commitment, { canSeePrivate }),
    limit,
    offset,
  });
});

// ---- registry discovery ----
//
// Published so that a verifier holding a qualified identifier can find this registry
// without consulting any central directory. There is no directory to consult: a
// registrar identifies itself by a domain it already controls, and this is how it says
// what it operates.
//
// Serving this makes VeilCore one registry among however many exist, which is the
// arrangement that lets a body run its own without asking us.
// ---- prove requests ----
//
// A mailbox between someone checking a record and its holder (lineage/prove-requests.mjs).
// Public and keyless on purpose: nothing here is believed, the checker's own page checks
// the answer on chain, and a holder key here would tie a holder to their on-chain identity.
// Answering needs the token from the link (only its SHA-256 is stored), so knowing a
// request id is not enough to crowd out the real answer.

const requireProve = (res) => {
  if (!proveRequests) { res.status(503).json({ error: 'prove requests not ready' }); return false; }
  return true;
};

/** A checker asks the holder of an on-chain identity to answer a challenge. */
app.post('/prove-requests', (req, res) => {
  if (!requireProve(res)) return;
  const { code, ...out } = proveRequests.ask(req.body || {}, clientBucket(req.ip));
  res.status(out.error ? (code ?? 400) : 200).json(out);
});

/** The request, for the holder's page; and its answers, for the checker's page. */
app.get('/prove-requests/:id', (req, res) => {
  if (!requireProve(res)) return;
  res.set('Cache-Control', 'no-store');
  const r = proveRequests.get(req.params.id);
  if (!r) return res.status(404).json({ error: 'no such request, or it has expired' });
  res.json(r);
});

/**
 * The holder's answer: the id of their proveOwnership transaction, and the token from the
 * link's fragment (only its hash was given here, so only someone with the link can answer).
 */
app.post('/prove-requests/:id/answers', (req, res) => {
  if (!requireProve(res)) return;
  const { txId, token } = req.body || {};
  const { code, ...out } = proveRequests.answer(req.params.id, txId, token);
  res.status(out.error ? (code ?? 400) : 200).json(out);
});

// ---- license invites ----
//
// A mailbox between a license's issuer and licensee (lineage/license-invites.mjs): the
// licensee's commitment to the issuer, then each side's transaction id to the other. Public
// and keyless like prove requests: each page checks what it receives on chain, and writing
// needs a token from the link (only its hash is stored here).

const requireInvites = (res) => {
  if (!licenseInvites) { res.status(503).json({ error: 'license invites not ready' }); return false; }
  return true;
};
const inviteReply = (res, { code, ...out }) => res.status(out.error ? (code ?? 400) : 200).json(out);

/** The issuer invites a licensee to a license on one of their records. */
app.post('/license-invites', (req, res) => {
  if (!requireInvites(res)) return;
  inviteReply(res, licenseInvites.invite(req.body || {}, clientBucket(req.ip)));
});

/** The invite and how far it has got, for both pages. */
app.get('/license-invites/:id', (req, res) => {
  if (!requireInvites(res)) return;
  res.set('Cache-Control', 'no-store');
  const r = licenseInvites.get(req.params.id);
  if (!r) return res.status(404).json({ error: 'no such invite, or it has expired' });
  res.json(r);
});

/** The licensee accepts: first only a hash of its commitment and nonce, with the link's token. */
app.post('/license-invites/:id/accept', (req, res) => {
  if (!requireInvites(res)) return;
  inviteReply(res, licenseInvites.accept(req.params.id, req.body || {}));
});

/** The issuer's random nonce for the read-aloud code, with the issuer's own token. */
app.post('/license-invites/:id/nonce', (req, res) => {
  if (!requireInvites(res)) return;
  inviteReply(res, licenseInvites.nonce(req.params.id, req.body || {}));
});

/** The licensee reveals what it committed to, with the link's token. */
app.post('/license-invites/:id/reveal', (req, res) => {
  if (!requireInvites(res)) return;
  inviteReply(res, licenseInvites.reveal(req.params.id, req.body || {}));
});

/** The issuer's issueLicense transaction, with the issuer's own token. */
app.post('/license-invites/:id/issued', (req, res) => {
  if (!requireInvites(res)) return;
  inviteReply(res, licenseInvites.issued(req.params.id, req.body || {}));
});

/** The licensee's countersignLicense transaction, with the link's token. */
app.post('/license-invites/:id/activated', (req, res) => {
  if (!requireInvites(res)) return;
  inviteReply(res, licenseInvites.activated(req.params.id, req.body || {}));
});

// --- deals (lineage/deals.mjs): the encrypted channel between the two sides of a license ---

const requireDeals = (res) => {
  if (!deals) { res.status(503).json({ error: 'deals not ready' }); return false; }
  return true;
};

/** Open a deal's channel: its id and the SHA-256 of its write token, both from the parties' shared key. */
app.post('/deals', (req, res) => {
  if (!requireDeals(res)) return;
  inviteReply(res, deals.open(req.body || {}, clientBucket(req.ip)));
});

/** Leave an encrypted message (iv, ct) with the deal's token. */
app.post('/deals/:id/messages', (req, res) => {
  if (!requireDeals(res)) return;
  inviteReply(res, deals.post(req.params.id, req.body || {}, clientBucket(req.ip)));
});

/** Read messages after a number, with the deal's token (a POST, so the token never sits in a URL). */
app.post('/deals/:id/read', (req, res) => {
  if (!requireDeals(res)) return;
  res.set('Cache-Control', 'no-store');
  const { token, after } = req.body || {};
  inviteReply(res, deals.list(req.params.id, token, after));
});

// --- payment receipts (lineage/payment-receipts.mjs): a payment partner's signed word ---

/** A registered payment partner files its signed receipt for a statement it paid. */
app.post('/payment-receipts', (req, res) => {
  if (!paymentReceipts) return res.status(503).json({ error: 'payment receipts not ready' });
  inviteReply(res, paymentReceipts.file(req.body || {}));
});

/** The receipts for one statement (by its deal-message fingerprint), with each partner's listing. */
app.get('/payment-receipts/:fingerprint', (req, res) => {
  if (!paymentReceipts) return res.status(503).json({ error: 'payment receipts not ready' });
  res.set('Cache-Control', 'no-store');
  inviteReply(res, paymentReceipts.forStatement(req.params.fingerprint));
});

// --- passkey copies of backups (lineage/passkey-vault.mjs) ---

const requireVault = (res) => {
  if (!passkeyVault) { res.status(503).json({ error: 'passkey copies not ready' }); return false; }
  return true;
};

/** Save the encrypted copy (iv, ct) with its token; the first save sets the token. */
app.put('/vault/:id', (req, res) => {
  if (!requireVault(res)) return;
  inviteReply(res, passkeyVault.put(req.params.id, req.body || {}, clientBucket(req.ip)));
});

/** Read the copy with its token (a POST, so the token never sits in a URL). */
app.post('/vault/:id/read', (req, res) => {
  if (!requireVault(res)) return;
  res.set('Cache-Control', 'no-store');
  inviteReply(res, passkeyVault.read(req.params.id, (req.body || {}).token));
});

/** Delete the copy with its token. */
app.post('/vault/:id/delete', (req, res) => {
  if (!requireVault(res)) return;
  inviteReply(res, passkeyVault.remove(req.params.id, (req.body || {}).token));
});

// --- the account copy (lineage/account-copy.mjs) ---
//
// Every route but /account-slot/:slotId/read needs the copy's write token, which only the account
// key makes; a way in's own token only reads that way in (security review S3). Tokens travel in
// POST and PUT bodies, never in a URL.

const requireAccount = (res) => {
  if (!accountCopies) { res.status(503).json({ error: 'account copies not ready' }); return false; }
  res.set('Cache-Control', 'no-store');
  return true;
};

/** Save the copy over the one this device last saw; the first save brings its first way in. */
app.put('/account-copy/:id', (req, res) => {
  if (!requireAccount(res)) return;
  inviteReply(res, accountCopies.put(req.params.id, req.body || {}, clientBucket(req.ip)));
});

/** The copy and its ways in. */
app.post('/account-copy/:id/read', (req, res) => {
  if (!requireAccount(res)) return;
  inviteReply(res, accountCopies.read(req.params.id, (req.body || {}).token));
});

/** Whether there is a newer copy: its fingerprint, date and ways in, without the copy. */
app.post('/account-copy/:id/head', (req, res) => {
  if (!requireAccount(res)) return;
  inviteReply(res, accountCopies.head(req.params.id, (req.body || {}).token));
});

/** Delete the copy and every way in to it. */
app.post('/account-copy/:id/delete', (req, res) => {
  if (!requireAccount(res)) return;
  inviteReply(res, accountCopies.remove(req.params.id, (req.body || {}).token));
});

/** Add a way in. */
app.put('/account-copy/:id/slots/:slotId', (req, res) => {
  if (!requireAccount(res)) return;
  inviteReply(res, accountCopies.addSlot(req.params.id, req.params.slotId, req.body || {}));
});

/** Remove a way in (never the last). */
app.post('/account-copy/:id/slots/:slotId/delete', (req, res) => {
  if (!requireAccount(res)) return;
  inviteReply(res, accountCopies.removeSlot(req.params.id, req.params.slotId, (req.body || {}).token));
});

/** A way in: which copy it opens, and the account key sealed for it. Its own token only. */
app.post('/account-slot/:slotId/read', (req, res) => {
  if (!requireAccount(res)) return;
  inviteReply(res, accountCopies.readSlot(req.params.slotId, (req.body || {}).token));
});

app.get('/.well-known/veilcore-registry', (_req, res) => {
  res.set('Access-Control-Allow-Origin', '*').json({
    name: 'VeilCore reference registry',
    api: publicBase(),
    formatVersions: ['0.1'],
    // From VEILCORE_ANCHOR_*, the same values POST /batches/:id/anchor enforces. Empty
    // until they are set: naming a contract nobody configured is how this said "preview"
    // while anchors were recorded on preprod.
    anchors: ANCHOR_CONFIG.network && ANCHOR_CONFIG.contractAddress
      ? [{ chain: ANCHOR_CONFIG.chain, network: ANCHOR_CONFIG.network, contractAddress: ANCHOR_CONFIG.contractAddress }]
      : [],
    specification: 'https://github.com/hunterincoming/veilcore-sdk/blob/main/SPEC.md',
  });
});

/**
 * Backups, for the operator only. GET: when the last one was sent, and whether the last
 * attempt failed (a short code). POST: make one now, e.g. right after setting backups up,
 * to see it land in the bucket rather than wait a day.
 */
/**
 * What an outside monitor (UptimeRobot, a plain HTTP monitor) should alarm on: 200
 * { ok: true, problems: [] } when nothing needs the operator, 503 { ok: false, problems }
 * when something does. Short codes only: no sizes, names or counts. The same contract as
 * the sponsor's /sponsor/alerts. Added after an operations review (5 Nov 2026) found nothing would tell
 * the operator that backups had stopped or the disk was filling before users noticed.
 *   backup-off          on Railway with no off-site backups set up
 *   backup-misconfigured  backups half set up, so none are made
 *   backup-overdue      no successful backup for two periods
 *   backup-failing      the last two or more attempts failed
 *   lab-files-failing   some lab-result files could not be copied off-site
 *   database-large      past 1 GB: plan the volume (backup.mjs LARGE_BYTES)
 *   timestamps-behind   a TSA is set and a batch sealed over three hours ago has no token
 *   disk-low            the volume has less than a fifth free, or less than twice the
 *                       database (a backup needs room for two temporary copies)
 */
app.get('/alerts', (_req, res) => {
  const problems = [];
  const b = backups ? backups.status() : { on: false };
  if (!b.on) {
    if (b.problem) problems.push('backup-misconfigured');
    else if (Object.keys(process.env).some((k) => k.startsWith('RAILWAY_'))) problems.push('backup-off');
  } else {
    if (b.overdue) problems.push('backup-overdue');
    if (b.consecutiveFailures >= 2) problems.push('backup-failing');
    if (b.labFilesFailed > 0) problems.push('lab-files-failing');
    if (b.large) problems.push('database-large');
  }
  if (tsaOn && batches?.tsaBehind()) problems.push('timestamps-behind');
  if (DB_PATH !== ':memory:') {
    try {
      const fsys = require('node:fs').statfsSync(require('node:path').dirname(DB_PATH));
      const free = Number(fsys.bavail) * Number(fsys.bsize);
      const total = Number(fsys.blocks) * Number(fsys.bsize);
      const dbSize = db.pragma('page_count', { simple: true }) * db.pragma('page_size', { simple: true });
      if (free < total / 5 || free < 2 * dbSize) problems.push('disk-low');
    } catch {
      /* not every system reports it; nothing to say then */
    }
  }
  res.status(problems.length ? 503 : 200).json({ ok: problems.length === 0, problems });
});

app.get('/admin/backup', (req, res) => {
  if (!requireOperator(req, res)) return;
  res.json(backups ? backups.status() : { on: false, problem: 'not loaded' });
});
app.post('/admin/backup', async (req, res) => {
  if (!requireOperator(req, res)) return;
  if (!backups) return res.status(503).json({ ok: false, error: 'not loaded' });
  const out = await backups.runNow();
  // Off or half set up: nothing to try (503). Tried and failed: the store or the network (502).
  res.status(out.ok ? 200 : (out.error === 'off' || out.error === 'misconfigured' ? 503 : 502)).json(out);
});

/**
 * One record's evidence, for the holder's evidence bundle (the site's "Download evidence
 * bundle", docs/evidence-bundle.md). Holder-authenticated like /api/export: the stored
 * record, when this registry first saw it, its inclusion proof with every anchor its batch
 * has had, the batch root, the batch's OpenTimestamps file when it has one, and the lab
 * signatures (attestations) about the record's fingerprint. Everything in it except the
 * record and its first-seen date is public already; this puts it in one answer so the
 * bundle doesn't depend on several calls agreeing. A record of another holder, or none,
 * is the same 404: the answer never says an id exists.
 *
 * Nothing here is checked on a chain. The bundle's own verify.html recomputes what can be
 * recomputed and says what to look up.
 */
const EVIDENCE_LIMITS = { holder: 20, client: 60 }; // per minute
const evidenceRow = db.prepare('SELECT body, first_seen FROM records WHERE id = ? AND holder_key = ?');
app.get('/records/:id/evidence', (req, res) => {
  const holder = storedKeyOf(req);
  if (!holder) return res.status(401).json({ error: 'holder key required' });
  const clientOk = exportAllowed(`evidence:client:${clientBucket(req.ip)}`, EVIDENCE_LIMITS.client);
  const holderOk = exportAllowed(`evidence:holder:${holder}`, EVIDENCE_LIMITS.holder);
  if (!clientOk || !holderOk) {
    return res.status(429).json({ error: 'evidence downloads are limited to a few a minute; try again shortly' });
  }
  const row = evidenceRow.get(req.params.id, holder);
  if (!row) return res.status(404).json({ error: 'no such record for this holder key' });
  const record = JSON.parse(row.body);
  const fingerprint = typeof record.recordFingerprint === 'string' && /^[0-9a-f]{64}$/.test(record.recordFingerprint)
    ? record.recordFingerprint
    : null;
  const inBatch = batches && fingerprint ? batches.evidenceFor(fingerprint) : null;
  // The same rule as /attestations/subject: private signatures only for the record holder,
  // the delivery's sender and the lab, listed and counted alike.
  const canSeePrivate = labDocReader(req);
  res.set('Cache-Control', 'no-store').json({
    format: 'veilcore-record-evidence/v1',
    recordId: req.params.id,
    record,
    registryFirstSeen: row.first_seen ? new Date(row.first_seen).toISOString() : null,
    proof: inBatch?.proof ?? null,
    batch: inBatch?.batch ?? null,
    attestations: attesters && fingerprint ? attesters.forSubject(fingerprint, { limit: ATTESTATION_PAGE, canSeePrivate, markPrivate: canSeePrivate }) : [],
    attestationsTotal: attesters && fingerprint ? attesters.countForSubject(fingerprint, { canSeePrivate }) : 0,
    note: 'From this registry, not checked on any chain. registryFirstSeen is this registry\'s own clock. An anchor is the transaction the registry operator reported; look it up on the named network before relying on its date. Lab signatures are as the registry stores them: check each signature yourself (the evidence bundle\'s verify.html does). A batch sealed but not anchored has no date beyond this registry\'s word.',
  });
});

/** A record by its local identifier, for resolution. Public: verification is free. */
app.get('/records/:localId', (req, res) => {
  const row = db.prepare('SELECT body, holder_key, first_seen FROM records WHERE id = ?').get(req.params.localId);
  if (!row) return res.status(404).json({ error: 'no such record' });
  // The holder's grant decides the one grantable field this view carries (their stated
  // date), from the grant's values and only while they are current.
  const grant = grantFor(row, req.params.localId);
  const on = new Set(grant.show);
  const r = JSON.parse(row.body);
  const { stale, pairingStale } = dropStale(on, grant, r);
  // The lab receipts' sample details, as /verify answers them, under the same grant.
  const custody = on.has('attestation-status') ? publicCustody(req.params.localId, row, r, grant.values ?? {}, pairingStale) : [];
  res.set('Access-Control-Allow-Origin', '*').json({
    ...publicView(row, on, grant.values ?? {}),
    ...(custody.length ? { custody } : {}),
    ...(stale.length ? { staleGrant: stale } : {}),
  });
});

// Errors: a message, never a stack trace or a file path.
// Unknown routes answer in JSON with the same headers as every other route. Express's
// default 404 replaces the CSP with its own, shorter one.
app.use((_req, res) => res.status(404).json({ error: 'not found' }));

app.use((err, _req, res, _next) => {
  const status = err?.status ?? err?.statusCode ?? 500;
  res.status(status).json({ error: status === 500 ? 'internal error' : String(err?.message ?? 'bad request') });
});

module.exports = { app, db, convertPlaintextNow, setLabDomainOptions, relookLabDomains, lastDomainLookReset };

if (require.main === module) {
  const port = process.env.PORT || 8787;
  app.listen(port, () => console.log(`VeilCore record store on :${port}`));
}
