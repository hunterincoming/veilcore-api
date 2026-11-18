# veilcore-api

The VeilCore reference registry: a small Node/Express service that stores holder
records sealed, with a key it never receives, so it cannot read what a holder typed
beyond the few public fields listed under "Sealed records" below (and rows from before
sealing, until they are converted or purged; never genetics). It seals their fingerprints
into batches, records where each batch root is anchored, and stamps each root with
OpenTimestamps (Bitcoin). Railway deploys `main`.

Since 8 October 2026 the production registry anchors batches on Midnight mainnet. The first
were anchored by hand ("Mainnet day" below); since 19 October the mainnet sponsor's anchoring
job does it on a schedule, hourly as configured (`sponsor/README.md` in the site and app
repository, [hunterincoming/veilcore](https://github.com/hunterincoming/veilcore)), and this
registry only records where each root went. Every record in it so far is the founders' own
test data.

The record format, its specification (`SPEC.md`) and the SDK are in
[hunterincoming/veilcore-sdk](https://github.com/hunterincoming/veilcore-sdk). "The site"
below means the website and app in hunterincoming/veilcore (`bboard-ui`).

```
npm install
npm test        # sets VEILCORE_OTS=off; no calendar is contacted
npm start       # PORT, default 8787
```

Node 24 (`.nvmrc` 24.11.1, `engines.node` 24.x), so Railway does not pick its own default.

`veilcore-records` (the SDK) is pinned exactly, at 0.15.0: the registry checks every
batch and attestation with it (and the holder's browser every record's fingerprint, since
the registry can no longer open records), so a new version is a deliberate, tested move.
`test/mainnet-readiness.test.mjs` checks records the site wrote under 0.13 still verify.
CI (`.github/workflows/ci.yml`) runs `npm ci`, `npm test` and
`npm audit --omit=dev --audit-level=high` on every push and pull request to `main`. Railway
waits for CI ("Wait for CI" in the service's settings): a push whose checks fail is not
deployed.

## Environment

| Variable | Default | What it does |
|---|---|---|
| `PORT` | `8787` | Port to listen on. |
| `DB_PATH` | `veilcore.db` | SQLite file. `:memory:` in tests. On Railway it must be on a volume: see "Keeping the data". |
| `VEILCORE_OPERATOR_TOKEN` | unset | Token for registry operations (`x-operator-token`): sealing, anchoring, OpenTimestamps routes, marking attester keys (name checks). Unset disables them all (503). At least 32 characters: a shorter one counts as unset, and the deploy log says so (without printing it). `openssl rand -hex 32` makes a good one. |
| `TRUST_PROXY_HOPS` | `1` | Proxies in front of the service (Railway: one). Decides which address rate limits count against. |
| `WRITE_BYTES_PER_DAY` | `209715200` (200 MB) | Daily write allowance per client address. |
| `WHOLE_SET_READ_BYTES_PER_MINUTE` | `67108864` (64 MB) | Most an address may be sent by unpaged `GET /api/records` / `/api/licenses` in a minute. |
| `HOLDER_MAX_BYTES` | `41943040` (40 MB) | Most a holder may keep in records, and separately in licences. A save that would grow the set past it is refused (413); one that does not grow it always works. |
| `BILLING` | unset (off) | `on` switches on paid plans (see "Paid plans"). Off, nothing changes: billing routes answer 404 and every holder keeps up to 10,000 records. |
| `BILLING_PADDLE_WEBHOOK_SECRET` | unset | The secret of Paddle's notification destination. Set it in Railway only. Missing, billing stays off and the deploy log says why. |
| `BILLING_FREE_RECORDS` | unset | How many records a holder without a paid plan may keep. |
| `BILLING_PADDLE_PRICES` | unset | Which Paddle prices are which plan: `pri_…=breeder,pri_…=lab`. A price not listed grants nothing. |
| `BILLING_PADDLE_API` | unset | `https://sandbox-api.paddle.com` or `https://api.paddle.com`, matching the key. |
| `BILLING_PADDLE_API_KEY` | unset | Paddle server API key, used only to open checkouts. Railway only. A sandbox key (`_sdbx`) works only with the sandbox API. |
| `BILLING_PADDLE_CHECKOUT` | unset | The hosted checkout link from Paddle's dashboard (`https://…paddle.io/checkout/hsc_…`). Live accounts need Paddle's approval for hosted checkouts. |
| `PUBLIC_BASE` | `https://veilcore-api-production.up.railway.app` | Public URL, used by the embed and `/.well-known/veilcore-registry`. |
| `VEILCORE_ANCHOR_CHAIN` | `midnight` | Chain batch roots are anchored on. |
| `VEILCORE_ANCHOR_NETWORK` | unset | Network of the anchoring contract: `preview`, `preprod` or `mainnet`. Set together with the next one, or no anchor is recorded. |
| `VEILCORE_ANCHOR_CONTRACT` | unset | Address of the anchoring (main VeilCore) contract, 64 hex; `0x` and capitals accepted, published in lower case. |
| `VEILCORE_OTS` | on | `off` disables automatic OpenTimestamps stamping on seal and the upkeep timer. The operator routes still work. |
| `VEILCORE_OTS_INTERVAL_MS` | `1800000` (30 min) | How often the upkeep timer retries failed stamps and upgrades pending ones. |
| `VEILCORE_TSA_URL` | unset | An RFC 3161 Time Stamping Authority, https (http only with a signer pin). When set, every batch root gets a timestamp token from it within the hour (see "RFC 3161 timestamps"). It is published with each token, so no query string or password. Unset: none. |
| `VEILCORE_TSA_SIGNER_SHA256` | unset | SHA-256 fingerprint(s) of the TSA's signing certificate, comma separated. A token signed by any other certificate is refused. Update it when the TSA renews its certificate (the alert `timestamps-behind` says when tokens stop). |
| `VEILCORE_TSA_QUALIFIED_SCHEME` | unset | `eIDAS` (a qualified service on an EU trusted list) or `JP-MIC` (Japan's accredited time-stamping), only when the operator has checked that list. Published as `qualified: { scheme, trustedList }`; readers check the list themselves. |
| `VEILCORE_TSA_TRUSTED_LIST` | unset | Where a reader checks that status (a URL). |
| `VEILCORE_TSA_AUTHORIZATION` | unset | The `Authorization` header a paid TSA needs (for example `Basic …`). A secret: Railway only. |
| `VEILCORE_BTC_EXPLORER` | `https://blockstream.info/api` | Esplora API used to fetch Bitcoin block headers when checking an upgraded proof. |
| `LAB_RESULTS_DIR` | `lab-results` next to `DB_PATH` | Folder for the locked lab-result files (one file per result). On Railway: `/data/lab-results`, on the same volume. Ignored when `DB_PATH` is `:memory:` (files are then kept in memory). See "Lab results". |
| `LAB_RESULTS_MAX_BYTES` | `2147483648` (2 GiB) | Most all lab-result files together may take. Past it, uploads get 507 "storage full". |
| `LAB_RESULTS_MAX_BYTES_PER_SENDER` | `314572800` (300 MB) | Most the lab-result files on the deliveries one holder sent may take together (507). See "Lab results". |
| `BACKUP_AGE_RECIPIENT`, `BACKUP_S3_ENDPOINT`, `BACKUP_S3_BUCKET`, `BACKUP_S3_KEY_ID`, `BACKUP_S3_SECRET` | unset | Off-site backups: all five, or none. See "Off-site backups". Optional: `BACKUP_S3_REGION` (read from a Backblaze endpoint), `BACKUP_EVERY_HOURS` (24), `BACKUP_PREFIX` (`veilcore-registry`), `BACKUP_PING_URL` (https, called after each success). |

### Keeping the data (Railway volume)

The whole registry is one SQLite file at `DB_PATH`, which defaults to `veilcore.db`
**relative to the app folder**. On Railway that folder is the container's own disk, and a
container is replaced on every deploy: without a volume, **every record, licence,
transfer, batch and attestation is deleted each time `main` deploys**. Nothing in this
repo creates a volume; it is a setting on the Railway service.

At every start the service logs `WARNING: no Railway volume is mounted ...` (or
`... is not on the volume mounted at ...`) when this is wrong. To check and fix it:

1. Railway, service `veilcore-api`: does it have a volume, and is `DB_PATH` (Variables)
   a file under its mount path? If both, nothing to do; the warning will not appear.
2. If not, whatever is stored now lives on the current container and goes with the next
   deploy, including the one that merges this. If any of it must be kept, copy
   `veilcore.db` off the running container first (e.g. `railway ssh`), or have holders
   re-save from the app afterwards (it re-sends a holder's whole set on every save).
3. Add a volume to the service (Add Volume, from the project canvas or the command
   palette), mount path `/data`; set `DB_PATH` = `/data/veilcore.db`; deploy.
4. The deploy log no longer has the warning. Save a record, redeploy, read it back.

### Off-site backups

A volume keeps the data across deploys, but it is still one copy, and Railway deletes a
volume's own backups with the volume. So once a day (`backup.mjs`) the registry:

1. takes a consistent copy of the whole database in memory (no plain copy is written to
   disk), and checks it opens, passes SQLite's integrity check and has a `records` table;
2. gzips it and encrypts it with [age](https://age-encryption.org) to the operator's
   **public** key. The private key never touches the server, so whoever takes over the
   server or the bucket gets ciphertext;
3. uploads it to an S3-compatible bucket (Backblaze B2) under a new name each time
   (`veilcore-registry/<network>/<time>.key-<id>.sqlite.gz.age`), with the body signed
   and MD5-checked. `<id>` names the public key it is sealed to (the first 12 hex
   characters of its SHA-256; `GET /admin/backup` shows it as `recipientId`, and the
   deploy log as `sealed to key <id>`), so after a key rotation the bucket listing shows
   which backups the new key opens. Backups made before 16 Oct 2026 have no `key-` part.

The first one goes 10 minutes after a start, then every 24 hours; a failure is retried
within the hour and logged as `backup FAILED` with the store's own error code
(`SignatureDoesNotMatch`, `AccessDenied`, …). With some but not all five settings, or a
public key that does not check out, nothing is sent and every start logs why. On Railway
with none set, every start logs a warning. A database over 128 MB is refused (this
approach held it in memory). Since 5 November 2026 the copy is made with SQLite's online
backup into a temporary file beside the live one and streamed through gzip and age into a
second temporary file, then uploaded from disk: no memory limit, and the volume needs free
room for those two copies while a backup runs. Past 4 GB it is refused (a single upload
stops at 5 GB); `GET /admin/backup` says `large: true` past 1 GB, the point to plan for it.
Lab-result files go too, each once, under `lab-results/<id>`.

**One address for a monitor: `GET /alerts`.** It answers 200 `{"ok":true,"problems":[]}`,
or 503 with `ok: false` and short codes: `backup-off`, `backup-misconfigured`, `backup-overdue`,
`backup-failing`, `lab-files-failing`, `timestamps-behind` (a TSA is set and a batch sealed
in the last week, over three hours ago, has no token), `database-large` (past 1 GB) and `disk-low` (under a
fifth free, or under twice the database, the room a backup needs). Nothing else: no sizes,
names or counts. In UptimeRobot: a plain HTTP(s) monitor on `https://<registry>/alerts`;
it alarms on anything but 200. The same contract as the sponsor's `/sponsor/alerts`.

**Knowing it stopped.** A backup that quietly stopped is the usual way backups fail.
`GET /admin/backup` has `overdue: true` once two periods pass with no success. Better:
set `BACKUP_PING_URL` to a check on a monitor such as healthchecks.io (free), with a
period of one day and a grace of a few hours. Each success calls it; a missed day sends
an email.

**Setting it up (once).**

1. On the operator's own computer: `brew install age`, then
   `age-keygen -o veilcore-backup-key.txt`. The printed `age1…` line is the public key.
   Put the whole file in a password manager, then delete it. **Lose it and the backups
   cannot be opened by anyone.**
2. Backblaze B2: a **private** bucket with **Object Lock on** and a default retention
   (compliance mode, 30 days): no key, ours or a thief's, can delete or overwrite a backup
   for 30 days. Then an application key for that bucket only, write-only. The key cannot
   delete, so old backups are removed by a lifecycle rule on the bucket (e.g. hide after
   90 days, delete 1 day after hiding); without one they simply pile up, which at a few
   megabytes a day costs nothing for years.
3. Railway variables: the five `BACKUP_*` settings (endpoint as on the bucket page,
   `https://s3.<region>.backblazeb2.com`). Deploy.
4. Check: `POST /admin/backup` with `x-operator-token` makes one now and answers with its
   name and record count; `GET /admin/backup` shows the last success and the last error
   code. The file should appear in the bucket.

**Restoring, or checking a backup can be restored (do this after setup, and now and
then): `restore.mjs`.** On the operator's own computer, with this repository and
`npm ci`: download a `.sqlite.gz.age` file from the bucket, then

```
read -s AGE_IDENTITY        # paste the private key (a note around it is fine), Enter
export AGE_IDENTITY
node restore.mjs --file FILE.sqlite.gz.age --to restored.db
unset AGE_IDENTITY; rm restored.db
```

It prints the record count and `integrity ok`, or `NOT RESTORED` and why. The key is read
from the environment, never an argument, so it stays out of the shell history.

**Putting a backup back into service** (only after a real loss; it replaces the live
database):

1. Railway, service settings: set the start command to `sleep infinity` and redeploy, so
   the container runs with the volume mounted but the registry is not writing to it.
2. Backblaze: make a READ-only application key for the bucket (the service's own key can
   only write). Delete it when this is done.
3. `railway ssh` into the container, `cd /app`, then:
   ```
   read -s AGE_IDENTITY; export AGE_IDENTITY
   read -s BACKUP_S3_KEY_ID; export BACKUP_S3_KEY_ID
   read -s BACKUP_S3_SECRET; export BACKUP_S3_SECRET
   node restore.mjs --from-bucket veilcore-registry/mainnet/<time>.key-<id>.sqlite.gz.age \
     --to /data/veilcore.db --replace --lab-results /data/lab-results
   unset AGE_IDENTITY BACKUP_S3_KEY_ID BACKUP_S3_SECRET
   ```
   (the endpoint and bucket are already in the service's variables). The file it replaces
   is kept beside it as `veilcore.db.before-restore-<time>`, and a leftover journal is
   moved aside so SQLite can't replay it.
4. Set the start command back to empty (the default, `npm start`) and redeploy. Delete
   the read key.

**Deletions and backups.** A record a holder deletes is zeroed in the live file
(`secure_delete`), but stays in the backups taken before, and cannot be removed from them
until their lock runs out (30 days) and the lifecycle rule removes them. The copies are
encrypted to a key the server does not hold, but the operator holds it. The same goes for
what the purge removes (below): backups taken before it still hold every record in plain
text, readable with the operator's key. `docs/rotate-backup-key.md` is the runbook that
ends that: a new key, a fresh backup, and the old private key destroyed. Until it has been
followed, nothing may say VeilCore can't read the backups made before sealing.

### Holder keys at rest

A holder key is the holder's only credential, so the database never stores one: records,
licences, disclosure grants, transfers (`from_holder`, `claimed_by`) and obligations
(`beneficiary_key`) hold `h1:` + SHA-256 of `veilcore:holder-key:v1:<key in lower case>`
(`holder-key.js`). A copy of the database no longer lets anyone act as a holder. Nothing
changes for the app or for holders: the same key works as before.

One key, one holder, however it is spelled (round 3). The registry accepts a key in
upper-case hex (a restored key may be pasted that way) and used to compare it exactly as
sent, so the same key in capitals was a different holder, and a sender could claim their
own delivery code. Every comparison now uses the key in lower case, and so does the public
party id (`partyId`, SHA-256 of `veilcore:party:<key in lower case>`). Keys the app makes
are lower case, so their rows and party ids are unchanged. Rows written under an upper- or
mixed-case key (a digest of it as sent, which cannot be undone) move to the lower-case
digest the next time that key arrives, and so do obligations naming its old party id.
Rolling back past this change: a holder who sends their key in capitals sees an empty set
until this version is back. Party ids already written into records (the `attesterKey` of
a claim made with a capitalised key) stay as they were.

A database from before 8 Oct 2026 is converted on the first start of this version, in one
transaction, before any request is answered, and the file is then rebuilt (`VACUUM`) so
no old key is left in freed pages (`secure_delete` is on from then on). The log says
`holder keys: stored N plain-text keys as digests (...)`. `VACUUM` needs free disk about
the size of the database. The same conversion runs on every start, every 10 minutes, and
for one holder whenever their key arrives, so rows that older code writes in plain text
are found and converted: during a deploy (Railway keeps the old container answering until
the new one is healthy) or after a rollback. It is safe to run any number of times and on
an empty database.

#### Rolling back past this change needs care

The code before it (commits up to `cfb2ee9`) compares holder keys in plain text, so it
**finds none of the converted rows**: while it runs, every holder sees an empty set, and a
save of an existing record is refused as "belongs to another holder". Nothing is lost,
but the app looks empty. So:

1. **Before merging**, take a backup of the database (Railway volume backup, or copy
   `DB_PATH` off the container).
2. **Prefer rolling forward**: fix and redeploy rather than redeploying the old commit.
3. If you must roll back, keep it short, then redeploy this version. Everything the old
   code wrote in between is picked up: plain-text keys are converted (at start, every 10
   minutes, and when each holder next sends their key), offers it made get their
   fingerprint at start (or at claim), and claims it recorded get their received record.
4. Only if this version cannot be redeployed at all: restore the backup from step 1. That
   loses everything written since the merge.

### Anchors and `/.well-known/veilcore-registry`

`/.well-known/veilcore-registry` publishes the anchor from `VEILCORE_ANCHOR_CHAIN`,
`VEILCORE_ANCHOR_NETWORK` and `VEILCORE_ANCHOR_CONTRACT`, and lists none until the last
two are both set and well formed. `POST /batches/:id/anchor` requires `network` and
`contractAddress` in its body (there is no default) and refuses (400) an anchor that does
not match the variables. Until both are set it records nothing (503), and the deploy log
says `anchoring disabled: ...` when one is missing or malformed. So a proof and the
discovery document cannot name different networks, and after the move to mainnet a
transaction made on Preview or preprod cannot be recorded as a mainnet anchor.

An anchor is stored with `txHash` and `contractAddress` as 64 lowercase hex,
`blockHeight` (optional) as a whole number, `anchoredAt` (optional, default now) as an
ISO 8601 date and time **with `Z` or an offset** (`2026-10-08T14:03:00Z`,
`2026-10-08T16:03:00+02:00`; anything else is 400), stored as the same instant in UTC
(`toISOString()`). `anchoredAt` may not be before the batch was sealed nor in the future (5 minutes
of clock skew allowed): 400 otherwise. An anchor is never replaced by another on the same
network (409; the same transaction again changes nothing). Only a test-network anchor can be
followed by one on mainnet (a Preview-era batch anchored again), and the old one is kept.

**The registry does not look anchors up on chain.** It checks the shape, the network and
the contract against the variables, and records what the operator posts; there is no
indexer client in this service. So every answer says so: `/verify` adds
`anchorRecordedBy: "registry-operator"`, `anchorCheckedOnChain: false` and `anchorNote`
(naming the transaction, network and contract to check), and the embed reads "Anchored on
Midnight mainnet, as recorded by this registry's operator: transaction `<txHash>`,
contract `<address>`. This registry has not checked that transaction. ..." with both in
full. `priorPossession` still means "anchored on mainnet", and rests on that unchecked
record; a verifier who needs it checks the transaction (the site's verify page already
labels the tx as "reported by the registry"). Checking on chain needs an indexer
connection: not built.

Every anchor the registry serves (`/verify`, `/proof`, `/batches`, `/api/export`) carries
its own `network` and `testNetwork` (`false` only for `mainnet`). Stored anchors are never
relabelled, so a batch anchored on Preview before the switch stays `network: "preview"`,
`testNetwork: true`, and the embed says "Anchored only on Midnight Preview, a test
network ... carries no evidential weight". A mainnet anchor reads "Anchored on Midnight
mainnet, as recorded by this registry's operator ..." (above). On `/verify`,
`anchored` is true for an anchor on any network (read `anchor.network` and
`anchor.testNetwork` with it; the site's verify page does), while `priorPossession` (when
`existence` is shared) is true only for an anchor on mainnet: a Preview-era record answers
`anchored: true`, `anchor.testNetwork: true`, `priorPossession: false`.

## Mainnet day

**Done 8 October 2026.** The production registry anchors on Midnight mainnet, contract
`a04de0a2684f3713276325649540c7278ffd07cba8b014e7489844f319a02347` (the main VeilCore
contract, pinned as `MAINNET_VEILCORE_ADDRESS` in `api/src/deploy-guard.ts` of
hunterincoming/veilcore). The first mainnet batches were anchored by hand on 11 October;
every record in them is the founders' own test data. The steps are kept for a registry
moving to a new contract. Section 3 is how a batch is anchored by hand; since 19 October the
mainnet sponsor's anchoring job does those steps itself.

### 1. Railway variables (service `veilcore-api`, tab Variables)

| Variable | Before 8 October | Since 8 October |
|---|---|---|
| `VEILCORE_ANCHOR_NETWORK` | `preview` | `mainnet` |
| `VEILCORE_ANCHOR_CONTRACT` | `f75d42dc…` (the 27 Sep Preview contract) | `a04de0a2…2347`, the **main** VeilCore contract's mainnet address (not the claims contract) |

Change both, then deploy the staged changes once. Leave `VEILCORE_ANCHOR_CHAIN` unset
(`midnight`) and every other variable as it is. Nothing checks that the address is
really on mainnet: `mainnet` with the old Preview address would be accepted, so compare
the address character by character with the deploy output.

### 2. Check `/.well-known` after the redeploy

```
curl -s https://veilcore-api-production.up.railway.app/.well-known/veilcore-registry
```

`anchors` must be exactly one entry:

```
"anchors": [{ "chain": "midnight", "network": "mainnet", "contractAddress": "<main address, lower case, no 0x>" }]
```

`"anchors": []` means a variable is missing or malformed: the deploy log has the line
`anchoring disabled: ...`. Nothing is anchored until it is fixed. `GET /health` should
answer `{"ok":true}`.

`GET /health` is a readiness check: `200 {"ok":true}` only once every module (commitment
checks, embed, lineage, transfers, batches, attesters) has loaded; `503 {"ok":false,
"status":"starting"|"failed","notReady":[...]}` otherwise, and the deploy log says why a
module failed. This repo has no `railway.json`/`railway.toml`, so whether Railway uses it
is a service setting: Settings, Deploy, **Healthcheck Path** = `/health`. With it set, a
deploy whose modules fail to load never takes traffic and the previous one keeps running.
Its `features` list names what this build serves, for the site's deploy preflights:
`sealed-records-v1`, `lab-results-v1` (once lab results load), `animal-profile-v1`,
`claimant-offer-v1`, `sealed-custody-v1`, `record-rev-v1`, `one-correction-v1` (a record is
corrected once, below), `license-rev-v1`, and since round 5
`sealed-name-v1` (a record's name is sealed; a clear `strainName` is refused) and
`dna-pair-binding-v1` (a DNA report is published only as `dnaPairBinding`), and since the
persona review (17 Oct) `bred-by-grant-v1` (who bred it, as a fact a holder may share), and
since round 6 `name-code-v1` (a record may carry `nameCode`, its name's salted code) and
`lab-doc-binding-v1` (a lab report signature made before round 6 is served whole only to the
delivery's sender and lab; one made since signs a bound code; since 8 Nov 2026 neither form is
shown to anyone else, see "Lab signatures: who sees them"), and since 8 Nov 2026
`private-lab-signatures-v1` (lab signatures are private, and `/verify` answers only the ones
the holder shares, as `sharedAttestations`; the site's deploy refuses a registry without it),
and since 12 Nov 2026 `shared-by-proof-code-v1` (`/attestations/subject` also answers the
signatures the proof code's holder shares, for the site's claim check page; the site's deploy
refuses a registry without it).

Batches already anchored on Preview keep that anchor and are shown as Preview, a test
network (see above). They can be anchored again on mainnet with the steps below; the
registry's copy then names the mainnet transaction. Proofs holders exported earlier keep
the Preview anchor they were exported with.

### 3. Anchoring a batch on mainnet by hand

Not the usual way any more. Since 19 October 2026 the mainnet sponsor's anchoring job
(`sponsor/src/anchorer.ts` in hunterincoming/veilcore) seals what is pending, sends
`anchorBatch`, checks on chain that the root landed and records the anchor here, with the same
operator routes. These are the same three steps for an operator doing one by hand, when the
job is off or for a registry without one.
`$API` is `https://veilcore-api-production.up.railway.app`, `$TOKEN` the
`VEILCORE_OPERATOR_TOKEN`.

1. **Seal** what is pending:
   ```
   curl -s -X POST "$API/batches/seal" -H "x-operator-token: $TOKEN"
   ```
   Answer: `{ "batchId", "root", "recordCount", "anchored": false, ... }`. `400 nothing
   pending` means there is nothing to anchor; `409` means seal again. An existing batch's
   `batch_id` and `root` are in `GET $API/batches`.
2. **Anchor the root on chain** with the CLI in hunterincoming/veilcore:
   `cd bboard-cli && npm run mainnet`, join the main contract (menu `2`), then main menu option **29. Anchor a batch
   root**, and paste `root` (64 hex). It calls the contract's `anchorBatch` and prints
   `Transaction <txHash> at block <blockHeight>.` The CLI does not tell the registry
   anything; copy both numbers.
3. **Record it in the registry**:
   ```
   curl -s -X POST "$API/batches/<batchId>/anchor" \
     -H "x-operator-token: $TOKEN" -H 'content-type: application/json' \
     -d '{"network":"mainnet","contractAddress":"<main address>","txHash":"<txHash>","blockHeight":<blockHeight>}'
   ```
   Answer: `200 { "batchId", "anchor": { ..., "testNetwork": false } }`. `400` if the
   network or contract differs from the variables, `404` for an unknown batch id.
   An anchor is never replaced: `409` if the batch is already anchored on this network
   with another transaction (the first one stands); the same transaction sent again is
   `200` with `"unchanged": true`. A batch anchored only on a test network (Preview) can
   be anchored on mainnet; the answer's `supersedes` is the old anchor, kept and listed
   under `earlierAnchors` in `GET $API/batches`.
   `anchoredAt` defaults to now; when recording later, pass the block's time (it may not
   be earlier than the batch's `sealed_at`, from `GET $API/batches`).

Check with `GET $API/proof/<a recordFingerprint in that batch>`: `anchor.network` is
`mainnet` and `anchor.testNetwork` is `false`.

## Sealed records: what this registry holds (16 Oct 2026)

The site's `CONTRACT.md` for sealed records is the wire contract; this is the registry's
side of it. (`CONTRACT.md` is a working document that is not in the public site repository;
it is cited below by point number, as `CONTRACT.md #28`.) The holder's browser makes a
32-byte **vault key**, kept beside the holder key
and in the backup file, and never sent here. Every record and licence is sealed with it
(AES-256-GCM, a 12-byte random IV, the tag after the ciphertext, base64url without
padding; the AAD names the table, the id and the key's id). This registry stores the box
and cannot open it.

A record's fingerprint (`recordFingerprint`, the record commitment) is what the site calls its **proof code**; here and in the specification it keeps its technical name.

**Readable here**, and nothing else:

- a record's public fields: `id`; `profile`, one of the known profile ids; `recordFingerprint` and `keyBinding` (hex); `supersededBy` (a record id); and
  `supersedes` as `{ recordId, changedFields, effectiveAt }` only: a record id, names from
  a fixed list of record fields, and an ISO 8601 date and time (never the reason);
- what this registry writes itself: `attestation` (a receipt confirmation: `attesterKey`,
  a one-way party id; `type`; `confirms`; `transferId`; `attestedAt`, and nothing else)
  and a received record's `receivedFrom`, `receivedFromCommitment`, `receivedAt`,
  `transferId`;
- when it first saw each record (`first_seen`), when each record and licence was last
  saved, how many times each was saved (its public `rev`), the box's `kid` (which vault
  key), and roughly how large each box is (the browser pads it to a size bucket first);
- the values a holder chooses to publish with a disclosure grant (below);
- for each delivery: the source record, the sender's and claimant's holder-key digests,
  when it was offered and claimed, the source and received records' fingerprints, the
  lab receipt's id, a `termsHash` if one was sent (64 hex), and the **recipient tag**:
  `toHandle`, a keyed hash the sender's browser makes from the recipient's name with its
  vault key. Never the name: the registry can't turn a tag back into one, or make the tag
  for a name it guesses. The same name from the same sender gives the same tag, so the
  registry can tell that two offers went to the same recipient;
- for a delivery's sample details (sealed, below): that each side wrote some, roughly how
  large each box is, and the box's `kid` (which offer key); and whether the lab's receipt id
  carries a digest of them (`_sc2_`), never what they say;
- a record's `nameCode` (round 6, CONTRACT.md #33): SHA-256 of "veilcore:name:v1", the name,
  the proof code and a salt sealed in the record. Public, and nothing about the name without
  the salt, which only the holder's check link carries (after the #, `ns`); with the link's
  name and salt, a check page tells whether the name is the record's;
- lab report signatures. One made since round 6 (its id ends in `_ld1`, inside what is
  signed) signs `document` = SHA-256("veilcore:labdoc:v1" 0x00 || the report's SHA-256 ||
  the proof code || s), s derived from the delivery's offer key with HKDF, which only the
  sender and the lab hold: nothing about the report without s. One made before signs the
  report's **plain SHA-256**, which this registry can read: with the hash, or the signature
  and a guessed file, anyone holding a copy of the report could tell which record it was
  saved to (the fifth review's finding 3). Both forms are served only to the delivery's
  sender and lab, by holder key (`GET /attestations/subject/:commitment` and
  `/records/:id/evidence` with `x-holder-key`), and to anyone else not at all (8 Nov 2026,
  "Lab signatures: who sees them" under Lab results);
- the holder-key digests, batches, attestations, and the lineage layer: confirmed parent
  links, parentage proposals, and **obligations**. A licence is sealed, but when one with
  an offspring royalty is countersigned the holder's browser registers an obligation on
  the record's fingerprint, keyed by the agreement's fingerprint. So this registry can read
  which records carry a royalty licence, when each obligation was made, and whose key made
  it (`beneficiary_key`, a holder-key digest). It answers that only one record at a time
  and never lists it (below, "Obligations");
- a record's name in the clear, on a row saved before round 5 (CONTRACT.md #28), until the
  holder's browser saves it again or the purge removes it;
- a record dated before its locked copy arrived (dating first, the site's CONTRACT.md #38):
  only its `id`, `recordFingerprint` and `keyBinding`, already listed above, and the
  registry's own mark `bodyPending: true` (served only to its holder) until the locked copy
  replaces it. Nothing typed, no vault key id, nothing more than any record shows;
- rows saved before sealing, until the holder's browser re-saves them or the purge runs;
  until the purge, also older deliveries' recipient handles as typed (the purge replaces
  each with a random value, not a hash of it) and their plain
  quantity and note, the handle older claims wrote into the sender's record
  (`addressedTo`), and sample details written before sealing (`sample_custody`,
  `arrival_custody` in plain text), until the purge's two-flag run removes them.

**Sealed** (in `sealed`, unreadable here): breeder, dates, notes, `loggedAt`, parents and
their record ids, breeding method, species, an animal's details, photo and DNA report
fingerprints and file names, licence ids, quantity, the full `supersedes` (its reason), the
nonce behind the fingerprint, every licence's contents, and a delivery's offer. A
delivery's sample details (sample ID, seal number, where and when it was taken, a witness,
and what the lab wrote on arrival) are sealed too, with the delivery's offer key, in
`sample_custody_sealed` and `arrival_custody_sealed`.

### Saving: `PUT /api/records`

Body: an array of `{ id, profile?, recordFingerprint?, keyBinding?,
supersedes?, supersededBy?, rev?, sealed: { v: 1, alg: "A256GCM", kid, iv, ct } }` (the
received-record fields and `attestation` may be sent back as read; they are ignored, and
the stored attestation keeps only the fields the registry writes: a `lab` an older record's
holder typed, or the handle an older claim wrote, is dropped on the first save).

- The record's name is sealed too (round 5, the site's CONTRACT.md #28): a save in which any
  row carries `strainName` beside its box, whatever its value, is refused whole, `400
  { "error": "strainName belongs inside sealed" }`, and nothing in it is stored. A row stored
  before then keeps its clear name until its holder's browser saves it again (without one),
  and public answers show it until then; `scripts/purge-plaintext.mjs` removes what is left.
- Any other top-level field is refused by name: `notes is not stored in the clear; it
  belongs inside sealed`. A plaintext record is refused; there is no setting to allow it.
- `sealed` is required: `v` 1, `alg` "A256GCM", `kid` 16 lowercase hex, `iv` 16 base64url
  characters, `ct` base64url of at most 360,000 characters. A record row is at most
  384 KiB of JSON. That holds every record the old registry held (at most 65,536
  characters of JSON, up to 196,608 bytes of UTF-8, about 262,000 characters sealed) and
  the largest the browser lets a holder save (256 KiB padded, about 349,500 sealed).
- The clear fields are not free text (round 2): `profile` is one of
  `veilcore/profile/plant-variety/v1`, `veilcore/profile/animal-individual/v1`,
  `veilcore/profile/cannabis/v0.1`, and the draft `veilcore/profile/strain/v1` and
  `veilcore/profile/document/v1` (`sealed.js` `KNOWN_PROFILES`; "profile must be one of
  ..."); `supersededBy` and
  `supersedes.recordId` are record ids; `supersedes.changedFields` holds only names in
  `sealed.js` `CHANGED_FIELD_NAMES` ("supersedes.changedFields may hold only known record
  field names"; the site's list must match it, and the cross-repo contract test checks
  that); `supersedes.effectiveAt` is an ISO 8601 date and time with `Z` or an offset, such
  as `2026-10-16T09:30:00Z` (milliseconds allowed).
  `recordFingerprint` and `keyBinding` are 64 lowercase hex.
- `rev` (optional, round 3): the row's revision, the same number its sealed payload
  carries, a whole number from 0 up ("rev must be a whole number from 0 up"). Once a row is
  stored with one, a save with a lower `rev`, or none, is an **older copy** and that row is
  refused; the rest of the save goes ahead, and the answer is 200 with `ok: false`, as for
  every per-row refusal. Its `rejected` entry is `{ id, reason: "older copy: this registry
  holds rev N of this record and this save is rev M; nothing was changed", code:
  "older-copy", status: 409, storedRev: N }` ("... this save is without a rev ..." when
  none was sent). The same `rev` again is accepted only as the very same box (one request
  sent twice); another box at the same `rev` is refused the same way ("older copy: this
  registry holds another copy at rev N ..."): two tabs or devices that each changed a row
  from the same copy both send that copy's rev + 1, and the second used to replace the
  first. It is returned to the holder with the row and never in a public answer. `/health` lists
  `record-rev-v1`, and the site's deploys require it: a registry without it refuses a row
  that carries `rev` as an unknown field.
- **A record is corrected once** (8 Nov 2026, `corrections.js`). A holder may hold one
  correction of each record: a second row whose `supersedes.recordId` names a record this
  holder already holds a correction of is refused, by id, with `{ id, reason: "already
  corrected: record R already has a correction here (C). A record is corrected once, so
  correct C instead; nothing was changed", code: "already-corrected", status: 409, recordId:
  R, correctionId: C }` in `rejected` (200 with `ok: false`, as every per-row refusal). A row
  in the same save marked `supersededBy` that refused correction is refused the same way, so
  the record never points at a correction this registry does not hold; that holds for a
  correction in a chain too (it is refused if its own `supersededBy` names one), and a
  chain sent in one save is written from its end back. The rule is a unique
  index (`records_one_correction`, on the holder and the corrected record), not a lookup
  before the write: two saves racing, in one process or in two on the same file, leave
  exactly one. Per holder, because a record id is scoped to its holder: a stranger who stores
  a "correction" naming a guessed id first does not stop its holder correcting it.
  The same correction again is a retry: by id (the browser re-sends the whole set), as
  always; by fingerprint under another id, it is not stored again, counts as saved (`count`,
  `ok`), and the answer names the one held in `existing: [{ id, existingId, recordId }]`. A correction that is removed (`DELETE
  /api/records`) frees the record to be corrected again. A chain (a correction of a
  correction) is one correction of each. A database that already held two corrections of one
  record keeps both: at start every one but one is marked (`correction_conflict`, the id of
  the one kept: the one the record's `supersededBy` names, or else the first seen), left out
  of the index, and named in the log at every start until the holder removes it. Nothing is
  deleted. The same holds when an older spelling of a holder key is converted (holder-key.js:
  a plain-text key, or the digest of one sent in capitals) and each spelling held a correction
  of the same record: settled the same way before the rows move, so the move never meets the
  index. `/health` lists `one-correction-v1`.

  **A record's link to its correction is permanent** (`supersededby-locked`). Once this
  registry holds a record's `supersededBy`, a save that would remove it or change it to
  another id is refused, by id, with `{ id, reason, code: "supersededby-locked", status: 409,
  supersededBy: C }` in `rejected`, whatever its `rev`. A stale copy saved at a higher rev
  after a lost answer used to strip the link: the record then looked uncorrected while its
  correction still stood, and the index refused every new correction of it, for good. The one
  exception: the correction the link names is no longer held by this holder (it was removed),
  so the link names nothing and may go. The same link again, at any rev, is an ordinary save.

  **A correction and its record are stored together or not at all** (`record-refused`). A
  correction whose record is in the same save and is refused there (an older copy, a locked
  link, an id another holder holds, anything) is not stored either: `{ id, reason, code:
  "record-refused", status: 409, recordId: R, recordCode: <R's own code> }`, or
  `already-corrected` when R already holds another correction. Before, a correction was
  stored while its record was refused as an older copy (another tab saved it a moment
  earlier), so the record was left unlinked and the index refused every later correction of
  it. A stored correction re-sent beside a stale copy of its record is not refused for it.
  What only writing can find (the index, an id held by another holder) is handled by undoing
  the save's writes and making them again with that row decided first, so the rules see it.

  **A record already cut off from its correction is linked again.** A copy of R refused as an
  older copy that names, in `supersededBy`, the correction this holder holds of R, while the
  stored R has no link, still sets the link: only the link, the stored copy is otherwise kept
  (its box and rev). The answer lists it in `relinked: [{ id, supersededBy }]` beside the
  `older-copy` refusal. The site can send that link once the registry's `already-corrected`
  answer has named the correction (`correctionId`).

  **Rolling back past this change:** the older code doesn't know the index is there, but
  SQLite still enforces it. A save that carries a second correction then fails whole with a
  500 (its other rows too), and a holder whose two key spellings each hold a correction of
  one record gets a 500 on every request. So on rollback, drop the index on the running
  container, against the database file (`DB_PATH`):

  ```
  node -e "require('better-sqlite3')(process.env.DB_PATH).exec('DROP INDEX IF EXISTS records_one_correction')"
  ```

  (or `DROP INDEX records_one_correction;` in `sqlite3`). The `correction_conflict` column
  does no harm and can stay. Rolling forward again rebuilds the index at start, and any
  second corrections the old code stored in between are marked and logged as above, with
  nothing deleted.
- One vault key per holder: a row whose `kid` differs from the holder's other records and
  licences is refused ("sealed with a different vault key"). Once every row under the old
  key is deleted, a new key starts.
- Kept as before: a fingerprint belongs to its first holder; `supersededBy` and
  `supersedes.recordId` may only name the holder's own records; the stored `attestation`
  and received-record fields are kept and the client's are ignored; the count and byte
  ceilings (10,000 records, 40 MB; a save may be up to 40 MB). 40 MB because the browser
  pads each box to a size bucket before sealing: a set at the old 16 MB ceiling made of
  records just over 16 KiB (padded to 24 KiB) is about 32 MB sealed.
- The registry no longer recomputes fingerprints: it can't see what they cover. The
  answer says `integrityCheckedBy: "holder"` where it used to give a `verified` count; the
  site recomputes each fingerprint after opening a record and refuses to save one that
  does not match. `lineage/conformance.mjs` is still loaded and `/health` still needs it.

`GET /api/records` returns rows as stored. A row saved before sealing is returned whole
to its own holder only, so the browser can convert it by saving it sealed; to anyone else,
by any route, only the public fields above are ever answered.

Licences (`PUT /api/licenses`) are `{ id, rev?, sealed }` and nothing else (the AAD says
`licenses`). `rev` is checked exactly as a record's (above): a lower one, none once one is
stored, or another box at the same one is refused as an older copy, by id, with code
`older-copy` and `storedRev` ("older copy: this registry holds rev N of this license ...").
Two tabs or devices used to replace each other's changes to an agreement, a revocation
included, without a word (round 4, F1). `/health` lists `license-rev-v1`, and the site's
deploys require it; which record a licence is about is sealed too, and `record_id` is stored null.
A licence with an offspring royalty is the exception: the obligation it registers names the
record's fingerprint in the clear (below).
The app sends all of a holder's licences in each save; that request may be up to 4 MB (it
was 512 KB in plain text; sealed and padded to the next KiB, a set of small licences grows
several times over). Other requests, apart from `PUT /api/records` (40 MB), stay at 512 KB. `DELETE /api/licenses` with
`{ "ids": [...] }` removes the holder's own licences (as `DELETE /api/records` does records),
so a licence sealed with a vault key the holder no longer has can still be taken off.

### Dating first: `PUT /api/records/dating` (17 Oct 2026, the site's CONTRACT.md #38)

A record's locked copy is uploaded only once its vault key is in a backup the holder's
browser has checked (round 3, L1), so a holder who hadn't checked one never got a record into
a batch: "waiting for a batch", forever. Now the browser sends the record's proof code the
moment the record is sealed, and the locked copy follows later.

Body: an array of at most 100 `{ id, recordFingerprint, keyBinding? }` (64 lowercase hex
each), with the holder key. Nothing else is accepted: no box, no `kid`, no name, no profile.
Stored as `{ id, recordFingerprint, keyBinding?, bodyPending: true }`, it goes into the next
batch like any record's proof code. The proof code is a salted commitment (a nonce sealed in
the record), so it tells this registry nothing about what was typed.

- It ties no vault key to the holder: the one-key-per-holder rule reads only boxes, so a
  browser whose key never reached a backup can't lock its holder out.
- The locked copy that follows (`PUT /api/records`) must carry the same `recordFingerprint`;
  a different one, or none, is refused by id: "this id was dated with a different proof
  code". The first-seen date is the dating row's.
- The id belongs to its first holder (`notWritten` for anyone else) and the proof code to the
  first holder who stored it, as for every record; dating an id again with the same proof code
  changes nothing (it is in `dated`), with another is refused. The per-holder count applies.
- A dating row can't be sent to a lab (`POST /transfers` answers 409 until its locked copy is
  here), can be deleted with `DELETE /api/records`, and is left as it is by the purge.

Answer: `{ ok, dated: [ids], rejected?: [{ id, reason }], notWritten?, reason? }`.
`/health` lists `dating-first-v1`, and the site's deploys require it.

### Deleting: `DELETE /api/records` (17 Nov 2026)

Body `{ "ids": [...] }`, the holder's own ids. Answers `{ ok, removed, notRemoved?, reason?,
refused? }`: `removed` lists what was actually deleted, so an empty list is a failure. A record
that a live correction still corrects is refused (`code: "linked"`) unless the correction is in
the same request. Deleting a correction removes the corrected record's `supersededBy` link to it.

A deleted id stays deleted (`tombstones.js`, table `record_tombstones`). A later save or dating
row of that id is refused per row with `code: "deleted"`, from any holder: a save already on
its way, another tab or a restored backup can't bring it back, and nobody can reuse the id. A
save whose correction link (`supersedes`, `supersededBy`) newly names a deleted id is refused
with `code: "links-deleted"` and `field`: the row itself is live. A proof code not yet in a
batch is never batched: a row deleted or changed while a batch is being built is left out and
the tree built again from the rest (`leftOutWhileSealing`). `GET /verify/:id` answers 404 with
`{ found: false, deleted: true, deletedBy: "record-holder", deletedAt, recordFingerprint?,
anchored, anchor?, anchoredRelativeToDeletion?, sealedRelativeToDeletion? }`: `deletedAt` is to
the minute; the proof code lets a check page tie its link to the record before reporting a
date. `anchoredRelativeToDeletion` is `before` or `after` only outside the anchor skew plus that
minute (otherwise `unknown`), since the anchor time is the operator's report;
`sealedRelativeToDeletion` compares two times on this registry's own clock. `/health` lists
`record-tombstones-v1`.

### Obligations (round 3, P5)

`POST /lineage/obligations` `{ record, obligation, beneficiary? }` (holder key) attaches an
obligation: on the caller's own record it is in force at once, on anyone else's it is a
proposal. The site calls it when a licence with an offspring royalty is countersigned, with
the record's fingerprint and the agreement's fingerprint.

- **No open listing.** `GET /lineage/obligations` used to list every obligation, parent
  link and proposal, each obligation with its record, when it was made, and its
  beneficiary's party id, one id per holder. With two record links a stranger could see
  that both carry a royalty licence, when each was signed, and that one holder holds both;
  with the whole list, every holder's royalty portfolio. It now answers `410` and lists
  nothing. The public answers are per record: `POST /lineage/verify { record, chain }`
  (whether that record, or anything in its declared ancestry, carries an obligation in
  force: `"this record carries an unmet obligation"` / `"an ancestor carries an unmet
  obligation"`), `GET /lineage/ancestors/:record`, and `GET /lineage/root` (a digest of the
  whole open set, which says nothing on its own). A holder sees proposals against their own
  records at `GET /lineage/obligations/proposals`.
- **A per-record beneficiary id.** A new obligation is stored under `beneficiary`, which
  the browser makes per record (the site's `vault.ts` `beneficiaryId`): lowercase hex
  HMAC-SHA256, key = HKDF-SHA256(vault key, no salt, info `"veilcore:vault:beneficiary:v1"`,
  32 bytes), message = utf8(`"veilcore:beneficiary:v1\0"`) + the record's fingerprint in
  lowercase hex. The registry never has the vault key, so only the holder can link two of
  them. It must be 64 lowercase hex and not the caller's party id (400 otherwise). Without
  one, the registry makes a per-record id itself (SHA-256 of
  `"veilcore:beneficiary:v1\0"` + the stored digest of the caller's key + `"\0"` + the
  record): a stranger can't make or link it, the registry can. Obligations stored before
  this keep the party id they were made with.
- Releasing (`DELETE /lineage/obligations/:record { obligation }`) is still only for whoever
  made it, now compared by the stored digest of their key, so the request is unchanged. One
  obligation per caller per record: the same one again, under any beneficiary id, is
  refused (`that obligation is already in force`).

### The purge (`scripts/purge-plaintext.mjs`, run by hand)

```
node scripts/purge-plaintext.mjs [--db <path>]                    # counts, and who would be skipped; nothing changes
node scripts/purge-plaintext.mjs [--db <path>] --apply            # makes the changes; the file is not rebuilt
node scripts/purge-plaintext.mjs [--db <path>] --apply --vacuum   # makes the changes, then rebuilds the file (VACUUM)
```

**Run it in a maintenance window.** The purge works on the live file, beside the running
server. `--apply` is one transaction over every row, and `VACUUM` copies the whole file
while holding a lock on all of it. The server waits up to 5 s for a lock (its SQLite busy
timeout, set in `server.js`) and then answers that request with a 500, so on a large file
saves, and during `VACUUM` reads too, fail while it runs. So: pick a quiet time and tell
people beforehand; take the backup (below); run the dry run, then `--apply --vacuum`;
afterwards check `GET /health` and that the app saves a record. `--vacuum` is refused
without `--apply`. Without `--vacuum` nothing is rebuilt: what the purge removes is still
overwritten with zeros as it goes (`secure_delete`), but the file keeps its size and its
free pages, and the purge says so and how to rebuild it.

**The guard (round 2).** A holder is *converted* once at least one of their records or
licences is sealed. `--apply` touches only converted holders:

- their sealed rows' clear fields are cut to what a save accepts today: the attestation to
  the registry's own fields (a holder-typed `lab` and an older claim's `addressedTo` /
  `attesterHandle` go), and any words in `profile` or the correction links;
- their rows that are still plain text are **reported, not stripped**: their app tried and
  could not convert them (too large, or a fingerprint that doesn't match). Only the
  handle an older claim wrote is taken out of them;
- on the transfers they sent, the plain-text `quantity` and `note` are emptied;
- on **every** transfer, whoever sent it and whether or not they converted (round 4, F6),
  a recipient handle stored as typed is replaced with 32 random bytes as hex, a fresh value
  per delivery, so nothing of the name is left; and the handle an older claim wrote into
  the sender's plain record (`addressedTo`, `attesterHandle`) is taken out. Both are a third
  party's name, and nothing of the holder's own is lost with them. (Until round 3 it became
  `SHA-256("veilcore:legacy-handle:v1\0" + handle)`, which anyone with a copy of the
  database could undo by hashing likely names; a database purged that way still holds
  those hashes, and a second run does not change them, as they already look like tags.)
- names in the clear (round 5, CONTRACT.md #28): **reported, never removed** (round 6,
  #37). A sealed row that still has a clear name was last saved before names went inside
  the lock (a save since is refused with one), so its box doesn't hold the name: the clear
  name is its only copy. The backup file holds keys, not records, and the proof code covers
  the name, so removing it would lose the name and leave the record not matching its proof
  code. The holder's app moves it inside when it saves the row again. Claims' stubs keep
  theirs too (a code made before offers were sealed has no offer to take the name from);
  the two-flag run below removes every one, and says a sealed row's name is then gone for good;
- on **every** grant, whoever made it and whether or not they converted (round 6, #37), the
  DNA values published before round 5 are deleted from its values: `dnaFileSha256` (the
  report's plain SHA-256) and `dnaFingerprint` (its pairing code). The registry stopped
  answering them in round 5; a holder who never came back kept them in the file and in
  every backup;
- on their grants made before grant values, the keys that publish values are dropped (the
  app sends them again); `existence` and `descent-clean` need no values and are never
  dropped. A grant left with no keys goes. A grant on a record whose row is still plain
  text after the run is **skipped** (round 3, L6): the app copies a grant's keys into the
  record when it converts it, so a cut list would stop publishing what the holder chose
  for good.

Sample details written before sealing (a delivery's plain `sample_custody` and
`arrival_custody`, sealed since round 3) are **reported**, by count, by the dry run and by
`--apply`, and are not touched. Only the two-flag run below removes them, for every
delivery: both are set to null and the delivery is marked `custody_removed`, so a lab
receipt over them is then answered as `custody: "removed"`, never as changed. Sealed boxes
are never touched.

A holder with no sealed row is **skipped** (apart from the recipient names above), and
listed by the first 12 characters of the digest this database stores for them, with how
many plain records and licences they have.
Only `--apply --include-unconverted --i-understand-this-deletes-text` (both flags; one
alone is refused) also strips them: each plain record keeps only its public fields and
gains `contentsRemoved: true` (a claim's stub, which has nothing more, loses only its clear
name), every clear name goes (above), each
plain licence becomes `{ id, contentsRemoved: true }`, and the transfer and grant steps
above apply to them too. What that removes is gone for good unless their own browser
still has it. A converted holder's plain rows are never stripped, with or without the
flags.

With `--vacuum` the file is then rebuilt, so nothing is left in free pages. It prints
counts and holder prefixes, never contents, ids or keys. Take a backup first (`POST /admin/backup`), and
afterwards rotate the backup key (`docs/rotate-backup-key.md`): the backups taken before
still hold everything the purge removed.

## Disclosure: what a stranger with a record id sees

The holder decides. A link carries a record id, and anyone can edit a link, so the
`?show=` list in it is a request, never permission. What the registry answers beyond
the public base is what the record's holder has granted, stored here. Since sealed
records, the registry can't read a record's contents, so a key whose answer comes from
them is answered from the **values** the holder's browser sends with the grant, and only
while they were read from the record as it is now.

### Setting the grant (holder only)

```
PUT /api/records/:id/disclosure
x-holder-key: <the record's holder key>
Content-Type: application/json

{ "show": ["existence", "sealed-at", "parent-names"],
  "forFingerprint": "<the record's recordFingerprint the values were read from>",
  "values": { "loggedAt": 1760000000000, "parents": [{ "name": "Mother M3" }] } }
```

- `show` is any subset of the seven keys below, in either spelling. It replaces the
  previous grant, values and all. `[]` withdraws everything (base only).
- `values` (optional, at most 64 KB) holds only values for keys in `show`:
  `loggedAt` (`sealed-at`; a number or a string of at most 64), `parents` (`parent-names`;
  at most 100 of `{ name, role?, individualId? }`, a parent's `recordId` is dropped),
  `breedingMethod` (`breeding-method`, at most 5,000), `individualId` and `idScheme`
  (`individual-id`, at most 500 each), `name` (`name`, at most 500; round 5, CONTRACT.md
  #28: the record's name, published only if its holder turns this on), `bredBy` (`bred-by`,
  at most 500: who bred it, as the holder wrote it; off unless turned on), `dnaPairBinding`
  (`attestation-status`, 64 lowercase hex; round 5, #29: H("veilcore:v1:dnapair", the
  report's SHA-256, the record's identity, its pairing salt), the site's chain/pairing.ts
  dnaPairBinding), `custodySummary` (`attestation-status`) and `sharedAttestations`
  (`attestation-status`, at most 50 different ids: the signatures the holder publishes on
  `/verify`; each must be a stored signature about this record's current fingerprint that this
  holder key can see, or the whole grant is a 400 with one answer for every such id, so a
  grant can't name another holder's signatures or find out which ids exist; see "Lab
  signatures: who sees them"). `dnaFileSha256` and
  `dnaFingerprint` are refused ("is no longer published"): anyone holding the same file
  could compute and compare them. A value for a key not granted, or any other field, is a
  400.
- `forFingerprint`: 64 lowercase hex, or absent/null (then no value is ever answered).
- Answer: `200 { "recordId", "show": [current names, canonical order], "forFingerprint",
  "values", "updatedAt" }`.
- `401` with no holder key. `404` if the record does not exist **or** belongs to another
  holder (same answer for both). `400` for an unknown key, for `holder-portfolio` /
  `terms-full` (or `others` / `agreementTerms`), if `show` is not a list of strings, or
  for a value out of shape. Nothing is stored on any error.

```
GET /api/records/:id/disclosure        (same header)
-> 200 { "recordId", "show": [...], "forFingerprint", "values", "updatedAt": ISO string | null }

GET /api/disclosures                   (same header)
-> 200 [{ "recordId", "show": [...], "forFingerprint", "values", "updatedAt" }]   every grant of this holder, by record id
```

No grant stored means `show: []` and `updatedAt: null`: the base view only. Deleting a
record deletes its grant, and a grant never applies to a record stored later under the
same id by someone else. `GET /api/export` includes `disclosures: { recordId: [keys] }`
and `disclosureValues: { recordId: { forFingerprint, values } }`.

**Stale grants.** When a record's `recordFingerprint` is no longer the grant's
`forFingerprint` (the holder changed it), or the grant has no values (made before sealed
records, or sent without `forFingerprint`), the values the holder sent are not answered, and
the keys they belong to are listed under `staleGrant` (with `staleGrantReason` on `/verify`).
Only what the holder wrote goes stale:

- `sealed-at`, `parent-names`, `breeding-method`, `individual-id`, `name` and `bred-by` are nothing but
  the holder's values, so a stale one is answered with nothing and leaves `disclosed`.
- `attestation-status` stays in `disclosed` and its registry facts are still answered: the
  signed and vetted attestation summaries (in the base) and each lab receipt's `custody`.
  Only its DNA pairing (`dnaPairedByHolder`, `dnaPairBinding`) is left out.
- `existence` and `descent-clean` are the registry's own facts and never go stale.

The site lists its grants with `GET /api/disclosures` after a load or save and sends again
those whose `forFingerprint` is not the record's current one, or whose `values` differ from
what it would publish now: a DNA pairing is not part of the fingerprint, so pairing a new
report changes the values without changing the fingerprint.

### Keys

| Current name | Older name | What it adds to `/verify/:id` |
|---|---|---|
| `existence` | `own` | `priorPossession` (true only when the record's batch is anchored on mainnet; a test-network anchor shows in `anchored` and `anchor`, not here), `unalteredSinceRegistryFirstSeen` (the fingerprint has not changed since the registry first saw it), `fingerprintCheckedByRegistry: false` (whether it matches the contents is the holder's browser's check) |
| `attestation-status` | `dna` | `sharedAttestations`: the signatures named in the grant's `values.sharedAttestations` that are still about this record as it is now (and, for a private one, that its holder can still see), in the grant's order, served whole like `/attestations/subject` rows, and no other private signature; from values: `dnaPairedByHolder` (a `dnaPairBinding` value was sent, or a `dnaFingerprint` in a grant stored before round 5; not lab-confirmed), and the pairing only as `dnaPairBinding` (64 hex; it says nothing about the file without the pairing salt in the holder's check link, so only someone the holder sends the link and the file to can check it; the file's SHA-256 and pairing fingerprint are never answered); and the delivery receipts' `custody` (registry data; each line's `receiptAttestationId` only for a receipt named in `sharedAttestations`; for sealed sample details only `custody: "sealed"`, with the holder's `custodySummary` from values when sent) |
| `descent-clean` | `lineage` | `lineageIntact: null`, `lineageNote` (not checked by this endpoint) |
| `sealed-at` | `sealed` | from values: `sealedAt` and `loggedAtClaimedByHolder` (the holder's own stated date) |
| `parent-names` | `parents` | from values: `parents: [names]`; on an animal record also `sire` and `dam`, each `{ name, individualId }`; on a strain record also `parentStrains`, at most two `{ name, deposit }` (the deposit is the parent's `individualId` as sent) |
| `breeding-method` | `method` | from values: `breedingMethod` |
| `individual-id` | `individualId` | from values: an animal record's `individualId` and `idScheme`. Never answered or listed for a plant record |
| `name` | `name` | from values: `cultivar`, the record's name (round 5). Without it no name is answered, except for a row saved before names were sealed, which shows its clear name until its holder's browser saves it again. Off unless the holder turns it on |
| `bred-by` | `bredBy` | from values: `bredBy`, who bred it as the holder wrote it (persona review, 17 Oct). Off unless the holder turns it on |
| `holder-portfolio` | `others` | never granted, never answered |
| `terms-full` | `agreementTerms` | never granted, never answered |

### Reading: `/verify/:id`, `/embed/:id`, `/records/:id`

What is answered = the holder's grant, narrowed by `?show=` when the caller gives one.
`?show=` can remove granted keys; it cannot add any. No `?show=` = the whole grant.

`GET /verify/:id` always returns the **base**:
`found, id, recordFingerprint, registryFirstSeen, supersededBy, supersedes,
signedAttestation, attestedByVettedLab, attested, anchored, anchor (when anchored), disclosed`,
and `subjectKind: "animal"` for a record sealed under the animal profile
(`veilcore/profile/animal-individual/v1`), `subjectKind: "strain"` under the draft strain
profile (`veilcore/profile/strain/v1`). Absent means a plant record. `cultivar` (the
record's name; an animal's name) only under the `name` grant, or for a row saved before
round 5 that still carries its name in the clear: the holder's check link carries the name
after the #, which never reaches this registry.

- `disclosed` is **always present**: the granted keys in this response, in the **older**
  names (`own`, `dna`, `lineage`, `sealed`, `parents`, `method`), which is what the verify
  page reads. A granted field is present if and only if its key is listed. An absent field
  means "not shared", never "false".
- `notGranted` (with `notGrantedReason`): keys `?show=` asked for that the holder has not
  granted (older names). Only present when there are some.
- `unavailable` (with `unavailableReason`): `others` / `agreementTerms` when asked for.
- `staleGrant` (with `staleGrantReason`): granted keys whose holder-written values are not
  answered because they are stale (above), in the older names. Only present when there are
  some. `dna` can be both here and in `disclosed`: its receipts are answered, its pairing is
  not.

`GET /embed/:id` follows the same rule: the holder's date appears only with `sealed-at`,
from the grant's values; its `staleGrant` uses the current names.
Signed attestations are public anyway (`/attestations/subject/:commitment`), so they are
in the embed's base; a `?show=` without `attestation-status` still leaves them out, as
links made before grants expect. The embed's `disclosed` uses the current names.

`GET /records/:id` is the base view; it carries `loggedAtClaimedByHolder` only with a
current `sealed-at` grant, and `staleGrant` (current names) when the grant is stale.

None of the three reads anything of a record's body beyond its public fields, sealed or
not: a legacy plaintext row's parents, method and dates are never answered.

### What the website needs to do

1. When the holder makes a share link (`Step5ProveDisclosure`), call
   `PUT /api/records/:id/disclosure` with the keys switched on, their values and the
   record's fingerprint, **before** showing the link. Until it does, every link shows the
   base view only. Keeping `?show=` in the link is harmless (it can only narrow). After
   every load and save, send again any grant `GET /api/disclosures` shows as stale.
2. On the verify page, read `disclosed` as "what the holder shared". It is now always
   present, so the page is always in its selective layout; show the signed-attestation
   line there too (it is base data), and render an absent `dnaPairedByHolder` as "not
   shared", not "not paired".
3. One grant per record applies to everyone who has the id. Per-recipient links (one
   buyer sees parents, another does not) need per-link grant tokens; not built.

## Animal records (profile v1, final, 16 Oct 2026)

A record whose `profile` is `veilcore/profile/animal-individual/v1` is one animal (the site's
`docs/animal-profile.md`; SPEC section 11.8). The fingerprint rules are unchanged. What
is sealed is the profile's own fields, made from the stored record the way the site makes
them (`lineage/animal-profile.mjs`): `strainName` is the animal's name, `bredBy` its breeder
or holder, `dateCreated` its stated date of birth (or empty), `taxon` its species, `refId` its
individual ID, `parents` its sire and dam (each with `role` and `individualId`), and `animal`
holds `breed`, `idScheme`, `sex` and `herd`. Since sealed records those fields are inside
`sealed`, so the registry can't check their form; the site's own check (the same rules,
`lineage/animal-profile.mjs` here) runs before it seals. `profile` stays public, so a check
page knows it is an animal. Vectors:
`test/fixtures/animal-individual-v1.json`, a byte-for-byte copy of the site's
`contract/vectors/animal-individual-v1.json`.

A lab code for an animal record gives the lab, in the sealed offer, the animal's individual
ID and scheme, species, breed and sex; never its herd, pedigree or notes.

## Reading a holder's records and licences (8 Oct 2026)

`GET /api/records` and `GET /api/licenses` (with `x-holder-key`) used to return everything
the holder had in one answer; a set could be about 640 MB. Now:

- **Paged**, with `?limit=` (default and most 100) and/or `?cursor=`:
  `{ "records": [...], "nextCursor": "<id>" | null, "limit": n }` (`"licenses"` for
  licences). In id order; a page also stops at about 1 MB. Pass `nextCursor` back as
  `?cursor=` until it is `null`.
- **Unpaged** (no `limit`, no `cursor`): the plain array the app reads today, newest first,
  but at most 1000 items and about 4 MB. When that cuts the set, the answer carries
  `X-VeilCore-Truncated: true` and the rest is only reachable by paging. Unpaged reads
  are limited to 30 a minute per holder key (per collection), and an address to
  `WHOLE_SET_READ_BYTES_PER_MINUTE` (64 MB) of them a minute (429 after that). Not a count
  per address: the site reloads every 30 s, and many people can share one address.

`GET /api/export` is written out in pieces (chunked, a couple of hundred rows at a time)
rather than built whole in memory; the JSON is the same, with records and licences in id
order.

`GET /records/:id/evidence` (holder key, like `/api/export`; at most 20 a minute per holder
key and 60 per address) is what the site's **Download evidence bundle** reads: one record's
stored body (sealed: the site opens it), its first-seen date, its inclusion proof with every anchor its batch has had,
the batch root and `.ots` file, and the lab signatures about it. Another holder's record,
or none, is the same 404. Nothing in it is checked on a chain here; see the site
repository's `docs/evidence-bundle.md`.

**Website changes recommended when this was written** (bboard-ui
`src/veilcore/api-store.ts`, `load`). The site has since taken the first two: a failed answer
is an error, not an empty set, and a cut whole-set read is finished by paging. Nothing
breaks today: a real holder's set is far under 1000 records and 4 MB, and the limits above
leave the current 30-second reload alone. But:

1. A non-200 answer (429, 5xx, a network error) is treated as "no records". It should
   keep what is on screen and try again later; only a 200 with an empty list means empty.
2. Load with `?limit=100` and follow `nextCursor`, reading `body.records` (or
   `body.licenses`), so a large holder is never cut off at 1000 records or 4 MB (and
   check `X-VeilCore-Truncated` until then).
3. Reloading every 30 s re-reads the whole set each time; reloading on focus or after a
   save would cost the holder and the registry far less.

Saves changed with sealed records (above).

## Transfers (8 Oct 2026)

Since sealed records (16 Oct 2026):

- The sender's browser makes a 32-byte offer key per offer; the delivery code carries it as
  a fourth part, `o1<43 base64url characters>`. `POST /transfers` takes
  `sealedOffer: { v: 1, alg: "A256GCM", iv, ct }` (at most 384 KiB as JSON; stored in
  `transfers.offer_sealed`, unread): the offer's `strainName`, `bredBy`, `dateCreated`,
  `profile`, `taxon`, `refId`, `animal` (`breed`, `idScheme`, `sex`), `quantity` and `note`,
  sealed with AAD `veilcore:offer:v1\0<sourceRecordId>\0<sourceFingerprint>`. A sealed
  source must be offered with one (400 otherwise), and `quantity` / `note` beside it are
  refused: they belong inside.
- A claim writes only a stub into the claimant's set: `{ id, profile,
  receivedFrom, receivedFromCommitment, receivedAt, transferId }` (no name since round 5:
  it is in the sealed offer), with no nonce (the
  claimant's browser makes its own when it seals). The answer has `offerSealed`, exactly
  as the sender sent it; the claimant's browser opens it, builds the full record, seals it
  and saves it under the stub's id. The received-record fields stay the registry's.
- A code made before sealing (no sealed offer) whose source is still in plain text works
  as before: the answer has `offerPlain` with the same fields. If the source has since
  been sealed, the claim is refused (409, "ask the sender for a new code").
- The sender's `attestation` is written into the stored record in place (`json_set`); the
  rest of the stored body is never rewritten.
- The sample details on a delivery (custody fields) were unchanged in this round and stayed
  readable; since round 3 they are sealed (below).
- The offer limit was 16 KB until round 2. The browser pads an offer like a record, and
  the offer carries the source record's own fields, which may be up to 256 KiB, so a long
  note or long record fields went over it and the code was refused after it was typed. It
  is now 384 KiB, the same as a record row: that holds the largest offer the app can make
  (any record it lets a holder save, a quantity of up to 200 characters and a note of up to
  2,000, which the app caps with a counter).

Since round 2 of sealed records (16 Oct 2026, the attack reviews):

- `toHandle` is a **tag, not a name**: lowercase hex HMAC-SHA256 with the sender's vault
  key over `"veilcore:handle:v1\0"` + the name (NFC, trimmed, lower case), made in the
  sender's browser. Anything but 64 lowercase hex characters is refused: 400
  `{ "error": "toHandle is a tag, not a name" }`. The name stays in the sender's sealed
  data. `GET /transfers/sent` returns the tag as `to_handle`.
- A claim no longer writes the handle into the sender's record: the attestation is
  `{ attesterKey, type: "receipt-confirmed", confirms, transferId, attestedAt }`.
- `GET /transfers/pending/:handle` is removed: 410 `{ "error": "removed" }`. It told anyone
  who guessed a handle that something was waiting for it.
- `termsHash`, when sent, is 64 lowercase hex (it was any text of up to 128 characters).
- `GET /transfers/:id/offer` (holder key): the offer again, for the holder who claimed the
  delivery, so a record left as a stub (the tab closed after claiming) can be finished:
  `{ transferId, offerSealed }` byte for byte as the sender sent it, or `{ transferId,
  offerPlain }` for a code made before sealing while the source is still plain (409 once it
  is sealed or changed). 404 `{ "error": "no such transfer" }` to anyone else, the sender
  included, and for a delivery nobody has claimed; 401 with no key. `Cache-Control:
  no-store`. `/health` lists `claimant-offer-v1` for it.

- One sender may have at most 20 unclaimed offers made in the last 30 days to one handle
  (one tag), and 200 in all (429 beyond that). Counted per sender, so nobody can block a
  recipient by filling their handle. Older offers stay claimable but stop counting.
- A transfer made before claim codes existed (`claim_code` null) can no longer be claimed
  (400); the sender offers again.
- The claim code is returned once, to the sender, and stored only as its SHA-256
  (`sha256:<hex>`), so a copy of the database can't claim anything. Codes stored as sent
  before 16 Oct 2026 still match.
- An offer fixes the source record's fingerprint. Claiming it is refused if the sender
  changed the record since, and a claimed transfer counts as the sender's consent to a
  descent edge only from that fingerprint, only while the sender still holds it, and only
  to the record the claim created (not any other record of the recipient).
  Transfers from before this get the fingerprint once, on first start: a claimed one from
  the record its claim created, an open one from the source as it is.
- `GET /transfers/sent` answers `{ transfers, total, limit, offset }`, `?limit=` default
  500, most 1000. Each transfer has `received_record`: the id of the record the claim
  created (null until claimed), and `receipt_attestation_id`: the lab's signed receipt
  (null until attached). Only the sender gets this list.
- A sender cannot claim their own code (409 "This is your own code. Send it to the lab
  instead."), with their key in any case. It would put a "received" line on their own
  record with no second party, and leave the lab nothing to claim.

### The lab's signed receipt (round 3)

The lab signs receipt of a delivery with its own key: a `chain-of-custody` attestation,
posted to `/attestations`, whose `subjectCommitment` is the source record's fingerprint
and whose `documentHash` is the fingerprint of the record the lab's claim created (the
site's `custodySubject`). It then tells the registry which attestation that is:

- `POST /transfers/:id/receipt`, body `{ attestationId }`, with the holder key as for a
  claim: `x-holder-key`, or `holderKey` in the body (both must name the same key if both
  are sent). Only the holder who claimed the delivery (403 otherwise; 409 if nobody has).
  A later call replaces the receipt, on the same checks.
- `POST /transfers/:id/claim` also takes an optional `receiptAttestationId`. The claim is
  never refused over it. The answer has `receiptAttestationId` when it was attached and
  `receiptError` when not; just after a claim the received record is not sealed yet, so
  this normally says to attach it once sealed.

The registry checks that the attestation exists (404), is a `chain-of-custody` one (400),
has not been withdrawn by its signer (409), that its subject is the fingerprint this
delivery was offered and claimed with and the one the received record names (400), and
that its `documentHash` is the received record's sealed fingerprint (409 if not sealed,
400 if another). It cannot check who holds the signing key: attester keys are not tied
to holder keys, so any key that signed over exactly this delivery's two fingerprints
passes, and the page says which key it was. A withdrawal after attaching does not clear
it; the page checks withdrawal as for any attestation. The sender reads it in
`GET /transfers/sent` (`receipt_attestation_id`) and `GET /transfers/:id/results`
(`receiptAttestationId`).

The site's `pendingFor` (bboard-ui `src/veilcore/transfers.ts`) called
`/transfers/pending/:handle`, which now answers 410; it has been removed from the site.
`sentByMe` keeps working.

### Sealed sample details (round 3 of sealed records, 16 Oct 2026)

The site's `CONTRACT.md` #27. A delivery's sample details are sealed with the delivery's
**offer key**: the 32-byte key the sender's browser made for the offer, which travels in
the lab code and which the sender's browser keeps inside its own sealed records. This
registry never receives it.

- Each side is a box, the same shape as a record's: `{ v: 1, alg: "A256GCM", kid, iv, ct }`,
  AES-256-GCM with a 12-byte random IV, AAD
  `"veilcore:sealed:v1\0custody\0" + transferId + "\0" + side` (`side` is `sample` or
  `arrival`), and `kid` the first 16 hex characters of
  `SHA-256("veilcore:offer-id:v1:" || offer key)`. The sender's box also holds `salt`
  (32 random bytes, base64url) beside its fields.
- On a delivery made with a sealed offer, `POST /transfers/:id/custody` takes `{ sample:
  <box> }` from the sender (until the lab claims it) and `{ arrival: <box> }` from the lab
  (after). The registry checks only the box's shape and that its `ct` is at most 8,000
  base64url characters, and that the lab's box names the same `kid` as the sender's. Plain
  fields are refused (400), at `POST /transfers` too: the sender's box is bound to the
  delivery's id, so it is sent once the code is made. `GET /transfers/:id/custody`, the
  claim's `sample` and `GET /transfers/sent`'s `sample_custody` / `arrival_custody` return
  the boxes as stored; the two apps open them.
- The lab's receipt carries `custodyDigestV2`: hex SHA-256 of the canonical JSON of
  `{ format: "veilcore/sample-custody/v2", transferId, salt, sample, arrival }` (each side
  normalised as `custodyFields` stores it), in its id: `att_<16 hex>_sc2_<64 hex>`. Without
  the salt the digest can't be found by trying likely values. The registry accepts an
  `_sc2_` receipt on a delivery with a sealed `sample` without recomputing it (it can't);
  it refuses `_sc2_` on a delivery with no sealed sample, and `_sc1_` on one with sealed
  details.
- `/verify`, `/embed` and `/records/:id`, under the `attestation-status` grant, answer such
  a receipt as `{ receiptAttestationId, custody: "sealed", receiptNamesSampleDetails: true,
  sampleDetailsCheckedBy: "holder" }` (`receiptAttestationId` only when the holder shares the
  receipt, 8 Nov 2026; "Lab signatures: who sees them"): the lab's receipt names sample details, and the
  holder's app can check them; this registry can't, so it never says the lab signed over
  them as a checked fact, and never `covered` or `changed`. The holder's app opens both boxes, recomputes the digest and
  works out covered / changed / differences itself; the holder may publish that with the
  grant as `values.custodySummary`: `[{ receiptAttestationId, covered, differingFields }]`,
  `covered` one of `covered`, `changed`, `not-covered`, `differingFields` names from the
  custody field list, never a value. It is answered beside the receipt as `custodySummary`
  with `custodySummaryBy: "holder"`, only for a receipt this registry lists and only while
  the grant is current; stale, it goes like the DNA pairing.
- A delivery made before (no sealed offer) keeps plain fields and `_sc1_` receipts, checked
  exactly as before. Those plain rows stay readable until the purge's two-flag run removes
  them (above); a receipt over removed details is answered `custody: "removed"`.
- `/health` lists `sealed-custody-v1`.

## Marking a lab's key (name checks, round 4)

Anyone can register a key under any lab's name. The operator's mark is the only thing that
lets a page print the name plainly, and it means one thing: the operator matched that name
to a public licence or accreditation listing and to the lab's own email domain, on a given
day. It does not mean VeilCore vouches for the lab's work, its results or any sample. The
procedure is in the site repository (hunterincoming/veilcore),
`docs/lab-name-checks.md`. Follow it before marking.

Mark (operator token in `x-operator-token`):

```
POST /attesters/:publicKey/vetting
{ "vetted": true,
  "check": { "source": "licence-listing",          // or "accreditation"
             "sourceUrl": "https://…",             // the public listing, https only
             "licenceNo": "…",                     // licence or certificate number, as listed
             "emailDomain": "lab.example",         // domain only, never an address; not free mail
             "checkedAt": "2026-10-14",            // the day of the check
             "checkedBy": "AB",                    // initials
             "expiresAt": "2027-03-31" },          // optional; at most 12 months after checkedAt
  "note": "…" }                                    // optional, private: what was seen
```

Refused (400) without `sourceUrl`, `emailDomain`, `checkedAt`, `checkedBy` or `source`,
with any other field in `check`, for a key with no registered name, and for a key last
taken off as `key-compromised` (the lab makes a new key; that one is checked). The mark
lasts until `expiresAt`, 12 months after the check unless set sooner (a licence that runs
out first). Marking again with a fresh check renews it. Renaming the key drops it.

Take a mark off: `{ "vetted": false, "reason": "<code>", "note": "…" }`, reason one of
`key-compromised`, `lab-closed`, `licence-lapsed`, `name-changed`, `entered-in-error`,
`expired`, `other`. The reason is public; the note is not.

What is public: `GET /attesters/:publicKey` and each signer in
`GET /attestations/subject/:commitment` (`registeredAs`) carry `nameCheckStatus`
(`checked`, `expired`, `not-checked`, `withdrawn`) and, only while `checked`, `nameCheck`
(the record above plus `checkedName`, the name it was matched to). A withdrawn key shows
`withdrawn: { at, reason }`; an expired one `nameCheckExpiredOn`. `vetted`,
`vettedAttester`, the `signed-and-accredited` strength, `/verify`'s `attestedByVettedLab`,
the vetted-first ordering and the per-record cap all follow `checked` alone. Notes never
appear in a public answer. `GET /attesters/:publicKey/vetting` (operator token) lists
every mark and unmark with its note, newest first.

A key marked before 14 Oct 2026 has no check record, so it reads as `not-checked` from
this version on. That is intended: re-check the lab by the procedure and mark it again.

## A lab's key on its own website

A lab can list its key where only it can write: a file at
`https://<domain>/.well-known/veilcore-lab.json` (`{"format":"veilcore-lab/v1","name":…,
"keys":[{"publicKey":…}]}`) or a TXT record `veilcore-lab=v1 key=<hex>` at
`_veilcore-lab.<domain>`. `POST /attesters/:publicKey/domain` with `{domain, issuedAt,
signature}`, the key's Ed25519 signature over `veilcore:lab-domain:v1\n<key>\n<domain>\n<issuedAt>`
(only the key names its domain; never a claim older than the one on record; one look per key
per ten minutes). The registry looks again hourly at any domain last looked at a day ago,
eight at a time, so a key the lab removes stops showing; a domain not found for 30 days is
forgotten. It records only what it saw (domain, file
or DNS, time, the file's SHA-256), and `GET /attesters/:publicKey` and every attestation
carry it as `domainCheck` while the last look found the key and is under 7 days old. It is
not a name check and never sets `vetted`. The fetch goes only to public addresses, checked at
connect time, with no redirects, 5 s for the file (body included) and 5 s for the DNS
record, and 16 KiB at most (`lineage/lab-domain.mjs`). `domainCheck.claim` carries the key's
own signature naming the domain, so anyone can check both directions. Why
and what pages say: the site repo's `docs/lab-domain-keys.md`.

## Lab results

A lab sends a lab report back on a delivery it received, locked (an age file) to the
breeder's key. The registry stores the locked file and cannot open it.

- `POST /transfers/:id/results` (the lab that claimed the delivery only), body the age
  file, `application/octet-stream`. `?attestationId=` links the lab's signed fingerprint.
  Since 8 Nov 2026 it must be a stored `laboratory-report` signature, not withdrawn, about the
  plant the delivery sent (its source fingerprint), by this lab's key: the key of the receipt
  tied to the delivery, or of a receipt it signed for the record its claim made, or else of
  its earlier reports on this delivery. With none of those, the first report sets the key: it
  must be stored after this delivery was claimed and not be by another delivery's lab key on
  the same plant (9 Nov 2026), and since 12 Nov 2026 the request must carry
  `x-lab-key-proof`: 128 hex, the signing key's own Ed25519 signature over the text
  `veilcore:lab-result-key:v1`, the delivery id and the signature id, one per line
  (`lineage/lab-results.mjs` `labKeyProofText`). The site sends it with every signed report;
  it is ignored once the delivery has a key.
  404 not stored, 400 another type or another plant, 409 withdrawn, 403 another key. It used
  to be stored unchecked, so a lab could tie anyone's signature to its own result;
  `?replaces=<result id>` names an earlier result on the same delivery that this one
  corrects (any other id, or a withdrawn result, is refused, 400). Readable files are
  refused.
- `GET /transfers/:id/results`: the list, without files, for the sender or the lab. Each
  line has `id`, `size`, `sha256`, `createdAt`, `expiresAt`, and `attestationId`,
  `replaces`, `withdrawnAt` when set. The sender's answer also has `receivedRecord`: the
  record the lab's claim created, so the breeder's page can check that the lab key that
  signed a report also signed receipt of this delivery, and `receiptAttestationId` when
  the lab attached its signed receipt. The lab is not sent either.
- `GET /transfers/:id/results/:resultId`: the locked file, sender only. 410 if the lab
  withdrew it, or if the file is no longer stored here.
- `DELETE /transfers/:id/results/:resultId`: the sender's removes the line and the file.
  The lab's is a withdrawal: the file is deleted, the line stays with `withdrawnAt`.

Limits:

- 15 MB per file. 5 live results per delivery; with withdrawn ones, 20 lines per
  delivery at most, so withdraw-and-send-again has an end.
- Each lab (the key that claimed the delivery): 50 files or 300 MB in any 24 hours (429).
- All files together: `LAB_RESULTS_MAX_BYTES`, 2 GiB by default (507).
- All files on the deliveries one holder sent: `LAB_RESULTS_MAX_BYTES_PER_SENDER`, 300 MB
  by default (507). Withdrawn results don't count. Without it, one holder sending
  deliveries to a second key of their own could fill the whole store.
- The last 10% of `LAB_RESULTS_MAX_BYTES` is kept for senders whose results would stay
  under 50 MB (507 "storage full" for anyone else once the store is 90% full), so a
  breeder with a few reports can still get one.
- These slow one party down. Holder keys cost nothing to make, so they don't stop one
  party using many keys; the per-lab daily allowance is what limits that rate.
- Results are deleted 180 days after they arrive, file and line. The breeder's app keeps
  a copy once downloaded.

Where the files live: `LAB_RESULTS_DIR`, one file per result, named by its id, written to
a temporary name and renamed when complete. Nothing is deleted for having no row while it
could be live (round 3): a file with no row is deleted only once it is older than 180
days (by the file's time), and a temporary only once it is an hour old. So a copy of the
database started against the live folder (a restored backup for a check) deletes nothing
the live one still uses. Don't let such a copy take uploads or deletions: its sweep and
deletes act on the shared files. They go to the off-site backup too, each once (see
"Off-site backups"). The folder holds a small `.veilcore-store-id` file naming the
database it belongs to. A database started on a folder that names another one leaves it
alone and turns lab results off (503), with `lab results unavailable: LAB_RESULTS_DIR
holds the lab results of another database` in the log. Give each database a separate folder.
After restoring a backup onto an empty volume this does not come up: the folder is new.
A database from the first version of this feature, with files inside it, has them moved
out once at start; if stopped halfway, the next start finishes it.

### Lab signatures: who sees them (8 Nov 2026)

When a lab sends a report back, the site signs a `laboratory-report` attestation about the
plant's own record, and a lab's receipt (`chain-of-custody`) is about it too. Until 8 Nov 2026
the registry served these to anyone with the record's proof code, no key needed, and that
said which records a lab had handled: the lab's registered name and whether it is vetted,
when it signed, and whether a report was later replaced or withdrawn. Only the older form of
lab report (plain SHA-256) was held back, and then only its hash and signature.

The rule now: nothing about who handled what is public unless the holder chooses to share it.
These signatures are **private** (`lineage/attesters.mjs` `PRIVATE_SQL`):

- every `laboratory-report`, of either form, and every `chain-of-custody` receipt, whoever
  signed it;
- a `genetic-fingerprint` or `inspection` from a lab key: a key whose signed attester role or
  registered role is `laboratory`, or that has signed a lab report or receipt here.
  `self-documentation` and `other` (a lab's claims-key binding is `other`) stay public.

A private signature is served only to these holder keys (`server.js` `privateReaderFor`):

- the first holder of the fingerprint it is about (`fingerprint_holders`, below), if it held
  it before the signature was stored, even once the record is deleted or changed;
- a key that sent a delivery of that record before the signature was stored;
- a key that claimed the delivery it is tied to, or sent it before the signature was stored:
  a report sent back on it (`lab_results.attestation_id`) or its receipt
  (`receipt_attestation_id`), on a delivery of the record the signature is about. A tie on a
  delivery of some other plant counts for nothing;
- the lab that claimed a delivery of that record, for signatures by the key that signed that
  delivery's receipt or a report on it about the same record, and for its receipt for the
  record its claim made, before it has tied it on.

**A fingerprint stays with its first holder** (9 Nov 2026). The registry can't check a
fingerprint against a sealed record's contents, and the guard on saving only looked at
records stored now. So once a holder deleted a record, or edited it so its fingerprint
changed, anyone with the old proof code could store a record with it, through `PUT
/api/records` or `PUT /api/records/dating`, become its holder, offer a delivery of it, and read
every lab signature about it. Now `fingerprint_holders` (`fingerprint-holders.js`) keeps every
fingerprint ever stored with the key that stored it first and when. Both routes refuse a
fingerprint first held by another key ("already registered by another holder"), the first
holder may store it again, and triggers on `records` keep the table, so every path that
stores a record records it. When the table is first made it is backfilled from the earliest
evidence of each fingerprint's holder: the records stored now (`first_seen`) and the deliveries
sent from it (`transfers.created_at`). So a fingerprint already taken over keeps the key that
held it first. The "before the signature" rule above is the second guard: a takeover, or a
delivery offered to read what was already signed, always comes after.

**What a lab's result may name** (`POST /transfers/:id/results?attestationId=`, see Lab
results): a lab report signature about the plant the delivery sent, by this delivery's lab
key. That key is the key of its receipt, or else of its earlier reports on the delivery. A
first report with neither must be stored after this delivery was claimed, must not be by
another delivery's lab key on the same plant, and must come with the key's own proof
(`x-lab-key-proof`, 12 Nov 2026), so a lab that claimed some other delivery of the plant can't
tie another lab's report id, even one that lab hasn't tied on yet, and read that lab's
signatures. Only whoever holds the signing key can sign the delivery's id.

For anyone else, and for any request without a holder key, every route answers as if it
weren't stored:

- `GET /attestations/subject/:commitment`: not listed, and not in `total`; pages are counted
  without it.
- `GET /records/:id/evidence`: the same rule for `attestations` and `attestationsTotal`.
- `GET /verify/:id`: `signedAttestation`, `attestedByVettedLab` and `attested` never count a
  private signature, for anyone (the route is public).
- `GET /embed/:id`: lists only the ones the holder shares, as `/verify` does (below).
- `POST /attestations`: private signatures have their own per-record ceilings (100 from keys
  without a current name check, 1000 from keys with one), and every other signature is
  counted without them. Counted together, a stranger could post 99 signatures and learn from
  the 100th whether a lab's was already there. Each signature counts where it was put when it
  was stored (13 Nov 2026): a key's `genetic-fingerprint` signatures that turn private later,
  when it signs a lab report, stay in the public places they took, so throwaway keys can't
  move them into the private places and fill those.

**The holder chooses what to publish.** Under the `attestation-status` grant, the holder
names signatures in `values.sharedAttestations` (see "Setting the grant"), and `/verify/:id`
answers exactly those as `sharedAttestations`: each served whole (signed fields, strength,
`vettedAttester`, `registeredAs`, `retraction`), so a check page can verify each signature and
name the lab. `GET /embed/:id` shows the same ones, under the same grant (12 Nov 2026), and
with none it says no signature is shown and that a lab's signatures are private unless the
holder shows them. Rows served to the record's holder, the delivery's sender or the lab, by
their own holder key, carry `private: true` on a private signature (outside the signed
fields), so the holder's app can offer exactly those, a lab key's `genetic-fingerprint` and
`inspection` included. A row anyone else reads because the holder shares it (on `/verify`,
`/embed`, or by proof code) never carries it (13 Nov 2026): it would tell a stranger the key
is a lab's. `/verify` and `/embed` are
`no-store`. Nothing else private is on `/verify`. Each is checked when the grant is stored
(about this record, one this holder can see) and again on every read: a signature about the
record before it changed, or a private one its holder can no longer see, is left out. A
`?show=` without `attestation-status`, or a grant without it, has none.

**A shared signature is shown by proof code too** (12 Nov 2026). A claim link names the plant
its numbers are about only by its proof code, and `/verify` needs the record id, so the
public claim check page could not read the lab report a v1 binding names, and could not name
the lab. `GET /attestations/subject/:commitment` now lists and counts, for everyone, the
signatures the proof code's holder shares, exactly as `/verify` answers them
(`server.js` `sharedOnFingerprint`), and nothing else private. Only from a record that:

- has that proof code as its fingerprint now. A record edited since answers nothing for its
  old proof code;
- is held by the proof code's first holder (`fingerprint_holders`). A record stored under a
  taken-over proof code shares nothing;
- is not corrected. A record whose `supersededBy` names a correction its holder holds answers
  nothing for its proof code here (its `/verify` is unchanged). The correction has its own
  proof code, and only signatures about that one can be shared on it;
- has the `attestation-status` grant now;
- is one of the holder's records with that proof code, and every one of them shares it. A
  holder can keep two records with one proof code; unsharing on either takes it off here.
  (The other choice, the newest record's grant, would let an older record's "show" stand
  after the holder took it back on that record. Requiring all of them fails closed.)

Unsharing, a grant without `attestation-status`, deleting the record or editing it takes the
signature off this route at once (the answer is `no-store` whenever it lists a shared one). A
delivery changes nothing: the recipient's record has its own proof code. So sharing shows a
signature to anyone with the record's check link or its proof code (on the check page, in
the holder's claim links and proof files), and the site says so where the holder chooses.
The holder's choice is the same one: what they mark to show, nothing more.

Why this and not the record id in the claim link: a record id opens the whole check link
(name, parents, breeding method, custody, every fact the holder grants), so putting it in a
link meant to be passed around would show far more than the holder chose to show with a
claim. The proof code is already in the link, and this answers only the signatures the holder
marked to show. It also works for claim links already made.

**What the public check page shows** (`/verify` page, no holder key): only the lab signatures
the holder chose to share. With the site update (veilcore `share-lab-signatures`) the page
reads `sharedAttestations`, checks each signature itself, and shows those with the lab's name.
When the holder shared none, it says the holder hasn't shown any lab signatures and that they
are private unless the holder shows them. It never says no lab signed.

What this costs. **Deploy the site update straight after this.** This build lists
`private-lab-signatures-v1` in `/health`, and the site's mainnet and test deploys refuse to
run against a registry without it, so the site can't go out first. Between this deploy and
the site's, the site already live does not read `sharedAttestations`, and for any record a lab
handled its check page gets none of these signatures and says things that are not true:

- in place of the receipt and report lines: "No lab's receipt or lab report has been signed
  about this record." (`app.verify.noneSigned`);
- the DNA report line, which matched the visitor's file to the lab's report signature and
  named the lab, says instead "No lab signature on this record matches it, so it is the
  holder's own statement." (`ownSha`), or "No lab has signed a lab report about this record,
  so it is the holder's own statement." (`unnamedNone`);
- the custody lines disappear: `/verify` still answers them, but without
  `receiptAttestationId` unless the receipt is shared, and the live page (`custody.ts`
  `publicCustodyOf`) skips a line without one, so a seal mismatch is no longer shown;
- the signed tick and the signature footer drop when lab signatures were the only ones.

The site update fixes all of these. Nothing is lost: rolling the registry back brings the old
page back.

On the test network, the claim check page and the document page named the lab on lab-signed
numbers by finding the lab's report signature on the plant's record (the site's
`claims-key.ts` `findBinding`). They now find none and say "No laboratory has said this key is
theirs for this record. Read the numbers as the holder's own." Lab signing is off on mainnet.
v2 uses the salted binding instead, which names the lab to whoever holds the salt and to
nobody else.

The holder's and the lab's own pages are unchanged: they read with the holder key, and the
evidence bundle carries the signatures for the holder.

What it does not hide.

- A stranger can still fill a record's private ceiling for keys without a name check (100)
  and see whether their last one is refused, so with 100 signatures of their own, all of
  which the holder then sees, they can tell whether an unvetted lab's signature is there.
- A key's `genetic-fingerprint` or `inspection` signatures that were public when stored and
  are hidden later (the key then signed a lab report) still hold their public places. A
  stranger who fills the public ceiling for keys without a name check can count fewer shown
  than held, and so tell that such signatures are there, though not whose. They were public
  when they were made.
- The receipts' `custody` lines on `/verify`, `/embed` and `/records/:id` are still answered
  under `attestation-status`: that a receipt is tied to a delivery of the record, and what its
  sample details say. Each line carries its `receiptAttestationId` only when the holder names
  that receipt in `sharedAttestations` (and it is still one /verify would share); otherwise
  the line has no id, so it doesn't lead a reader to the receipt or the lab. It still says a
  lab received a sample from the record, and whether what arrived matches what was sent; the
  site says so next to "Whether a DNA report is saved".
- A key becomes a lab key by what it signs, so a key's earlier public `genetic-fingerprint`
  or `inspection` signatures turn private once it signs a report or receipt, and anyone who
  read them before has them.
- Whether an id exists still shows in a few answers to someone who already has the id: a
  retraction ("no such attestation" or "does not verify"), a submit under the same id
  ("already used"), and a lab's result upload (404, 400, 403, 409). None names the lab or the
  record to anyone who isn't a party.

**Check once on mainnet: results tied before they were checked.** Before 8 Nov 2026 a lab's
result could name any signature id. The visibility rule already ignores a tie to a signature
about another plant, but a row like that should be looked at. Read-only; run it against a copy
of the database (or with `sqlite3 -readonly`). Every row it prints is a result whose signature
is missing, is not a lab report, or is about a different plant from the delivery's:

```sql
SELECT r.id AS result_id, r.transfer_id, r.attestation_id, r.created_at,
       t.source_fingerprint,
       a.subject_commitment AS signature_subject,
       json_extract(a.body, '$.type') AS signature_type,
       a.attester_key
FROM lab_results r
JOIN transfers t ON t.id = r.transfer_id
LEFT JOIN attestations a ON a.attestation_id = r.attestation_id
WHERE r.attestation_id IS NOT NULL
  AND (a.attestation_id IS NULL
       OR a.subject_commitment IS NOT t.source_fingerprint
       OR json_extract(a.body, '$.type') IS NOT 'laboratory-report')
ORDER BY r.created_at;
```

No rows: nothing to do. Any row: don't delete it (the breeder's result list shows it); send
the ids to whoever reviews registry changes.

## Prove requests

A mailbox between someone checking a record and its holder. Public and keyless; nothing
in it is believed, the checker's page checks the answer on chain.

- `POST /prove-requests` takes `identity`, `challenge` and `answerTokenHash` (each 64
  hex) and an optional `asker` (text, at most 80 characters). The checker's browser makes
  a random answer token, puts it in the link's fragment (`#t=…`, never sent to a server)
  and sends only its SHA-256. The registry stores only that hash.
- `POST /prove-requests/:id/answers` takes `txId` and `token`. Without the token from the
  link it is refused (403), so knowing a request id is not enough to fill its answers.
  Up to 5 answers, each with `answeredAt`.
- Requests expire after 7 days. At most 50,000 live at once (503 "busy" past that), and
  100 a day from one address (429).

## License invites

A mailbox between a license's issuer and its licensee, so a real two-party license needs
no codes copied by hand. Public and keyless; nothing in it is believed: each page checks
what it receives on chain. On chain the licensee builds the license commitment from a
secret only they hold, the issuer sends `issueLicense`, the licensee sends
`countersignLicense`; this carries the messages between them.

Because this mailbox could swap the commitment for one of its own, both people read each
other a 6-digit code before the issuer issues, made with a commit-then-reveal exchange: the
licensee commits to a hash first, the issuer answers with a random nonce, then the licensee
reveals. A swapped commitment can't be steered to show the same code.

- `POST /license-invites` takes the issuer record's `identity`, `acceptTokenHash` and
  `issuerTokenHash` (each 64 hex, the two different) and an optional `label` (the
  issuer's words for the licensee, at most 80 characters, cleaned like a prove request's
  asker). The accept token goes in the licensee's link fragment (`#t=…`), the issuer
  token stays with the issuer; only their SHA-256 is stored.
- `POST /license-invites/:id/accept` takes `commitHash` (SHA-256 of commitment, issuer
  record and the licensee's nonce, as raw bytes) and the accept `token`.
- `POST /license-invites/:id/nonce` takes `issuerNonce` and the issuer `token`.
- `POST /license-invites/:id/reveal` takes `commitment`, `issuerRecord`, `licenseeNonce`
  and the accept `token`; refused unless they hash to `commitHash`.
- `POST /license-invites/:id/issued` takes `txId` and the issuer `token`;
  `POST /license-invites/:id/activated` takes `txId` and the accept `token`.
- A wrong or missing token is refused (403). Each step is taken once and in order (409
  otherwise); the same value again is accepted, a different one is not.
- `GET /license-invites/:id` gives the invite and how far it has got. The token hashes
  are never returned.
- Invites expire after 30 days. At most 50,000 live at once; 50 a day from one client (an
  IPv6 one counted by its /48), and 10 a day from one client for one record. There is no
  cap per record: a record's identity is public, and one would let anyone lock it out.
  `/health` lists `license-invites-v1`.

## Deals

The channel between the two sides of a live license: royalty statements, replies, payment
notices and confirmations (`lineage/deals.mjs`). The browsers encrypt and sign every
message with keys only the two parties hold (the ones behind the 6-digit code), so the
registry stores ciphertext it cannot read, forge or alter.

| Route | Who | What |
|---|---|---|
| `POST /deals` | either side | Open the channel: `dealId` (32 hex), `writeTokenHash` (SHA-256 of the token), and the license invite it belongs to (`inviteId`, with the issuer's token, once the licensee has revealed). One channel per invite. Opening an existing channel again with the same hash needs no invite; another hash is refused |
| `POST /deals/:id/messages` | either side, with the token | `iv` (12 bytes) and `ct` (AES-GCM, at most 16 KB), base64url. Returns `seq`, `fingerprint`, `receivedAt` |
| `POST /deals/:id/read` | either side, with the token | Messages after `after`, oldest first, 200 at a time |

Each message's fingerprint (SHA-256 of `iv.ct`) joins the next batch, so the hourly anchor
dates it on Midnight and `GET /proof/:fingerprint` proves when it was received. Limits:
2,000 messages a deal, 50 new deals and 500 messages a day per client (an
IPv6 client by its /48). A channel nobody wrote to within a week is deleted; messages are kept
for as long as the deal lasts. A batch's `recordCount` counts the deal messages in it too. There is no total cap, which an attacker
could fill to stop every honest license: watch the database's size instead.

## License notices

What a record's holder (the licensor) says, publicly, about one royalty statement on a license
from the record, and what the licensee answers in their own name (the site's
`veilcore/license-notices.ts`, `docs/royalty-pay.md`). A licensor's browser can be modified, so
the registry is the clock and the gate for everything that it can check:

- A line is about one **statement**: a message in a deal held here, named by its fingerprint
  (never shown publicly). Its `ref` is the first 32 hex of SHA-256 over
  `veilcore/license-notice/v2\n` and that fingerprint, so both sides can name it. The deal holding
  it names both sides' deal keys (the invite's nonces, copied onto the deal when it opens).
- Every line is **signed by the deal's licensor** with their deal key, over the record it goes on
  (`veilcore/license-line/v1\n` + canonical `{ recordId, ...line }`), as well as sent under the
  record's holder key. Only that licensor can say anything about its statements, a stranger who
  learned a fingerprint can't, and a statement's lines live on one record (the first one the
  licensor put a line on, until they take it off: `409 other-record`).
- The licensee **registers** each of their statements, signed with their deal key: "this is my
  royalty statement, and its payment is due on `dueOn`". The site's page does it by itself
  whenever it opens, for every statement in the deal (an old or modified page may not). The
  first registration stands.
- **Overdue** is the licensor's word alone. Once the due date the licensee registered has
  passed, its `since` must be after that date (`409 not-due`, with `dueOn` and `now`). A
  registered date still to come doesn't hold it back. This registry can't check the registered
  date against the terms (only the two sides hold them), so a licensee's page can register a
  later one. That delays the notice of breach and moves the earliest "since" to the day after
  the registered date. It can't keep the plain overdue line off: the registered date is public
  by statement (`POST /license-answers/lookup`, `registered`), and the licensor's page dates its
  lines from the day after it once it has passed (the site's docs/royalty-pay.md, review
  round 5, B1). A far-off date (say 9999-12-31) does keep the notice of breach, and so
  "revoked for non-payment", off until then, which in practice is for good; the overdue line
  and the revoke on Midnight still work.
- Once a **notice of breach** is on file, or the line is **revoked**, a resend of the same or
  an earlier stage changes nothing: the kind, the date and the licensor's signature over them
  stay, and the line is answered as it stands (`200`).
- A **notice of breach** is accepted only for a statement the licensee registered (`409
  not-registered`), and only from the day after the due date they registered, by this registry's
  clock (`409 not-due`, with `dueOn`). It is dated by this registry the first time it arrives
  (`breachNoticeOn`): the licensor's device can't date it, and a resend doesn't move it. So the
  licensor's own messages can't stand in for a statement, a notice can't be sent before anything
  was due, and the cure period never starts before the licensee knew about the statement.
- **Revoked for non-payment** is accepted only with a notice of breach on file for that line,
  received at least 30 full UTC days earlier by this registry's clock (accepted from the 31st day,
  `revocableFrom`), and no "paid" on file for the statement: the licensee's own answer or a
  receipt from a payment partner whose name VeilCore checked. Otherwise `409` with `code`
  `no-breach`, `cure-not-over` or `paid`, and the site says nothing about payment. Its date
  can't be inside the cure period, and it is fixed when first accepted. While payment receipts
  are still loading it answers `503`.
- The licensee's **answer** (`paid`, with the SHA-256 of the payment reference, or `disputed`)
  is signed with their deal key. The first of each type stands. The licensor can't remove or
  change it, and it shows beside every line about that statement: its type and date only. A
  `paid` with any reference stops "revoked for non-payment" for good; an empty reference is
  refused.
- A deal opened before the deal keys were kept here, whose invite has since expired, has no keys
  on file: nothing about it can be filed (`409 predates`).
- The licensee can dispute a line about **any** message in their deal, registered or not:
  junk the licensor posted, or one of the licensee's own reports sealed again under a new
  fingerprint. Their page asks about every message in the deal, including the ones it can't
  read, so it shows such a line and offers the dispute.

Known limit: the registry can't tell whether the licensee is a different person from the
licensor. A licensor who accepts their own license invite holds both deal keys, so they can
register a "report" of their own, file a notice of breach and, after the 30 days, get "revoked
for non-payment" accepted on their record. It names no one and no real licensee's deal is
touched, but it is still only the holder's word about some license: the site's public line says
the registry checked the dates, not who the licensee is.

| Route | Who | What |
|---|---|---|
| `PUT /api/records/:id/license-notices/:ref` | the record's holder, signed by the deal's licensor | Body exactly `{ "kind": "overdue" \| "breach", "since": "YYYY-MM-DD", "statement": "<64 hex>", "signature": "<128 hex>" }` or `{ "kind": "revoked", "reason": "non-payment", "on": "YYYY-MM-DD", "statement": "<64 hex>", "signature": "<128 hex>" }`. Dates are UTC days, not after the registry's today. Returns the line as `/verify` shows it, and `now` (the registry's time, ms) |
| `DELETE /api/records/:id/license-notices/:ref` | the record's holder | Takes a line off (the licensee's registration and answers stay on file) |
| `GET /api/records/:id/license-notices` | the record's holder | `{ licenseNotices, now, cureDays }`: the holder's own lines and the registry's time |
| `POST /license-answers` | the licensee | Body exactly `{ answer, signature }`, `answer` exactly `{ v: "veilcore/license-answer/v1", statement, type: "statement", dueOn }`, `{ ..., type: "disputed" }` or `{ ..., type: "paid", referenceHash }`; `signature`: Ed25519 over `veilcore/license-answer/v1\n` + the canonical answer, by the deal's licensee key. Returns `{ filed, type, on, dueOn?, now }` |
| `GET /license-answers/:statement` | either side | `{ answers: [{ type, on }], lines, registered?: { dueOn, on }, predates?: true, now, cureDays }`: what is on file about a statement (the record is not named) |
| `POST /license-answers/lookup` | either side | Body exactly `{ statements: [1 to 100 fingerprints] }`: `{ results: [{ statement, answers, lines, registered?, predates? }], now, cureDays }`, in the order asked |
| `GET /verify/:id` | anyone | `licenseNotices: [{ ref, kind: "overdue", since \| kind: "revoked", reason, on, breachNoticeOn?, answers?: [{ type, on }], updatedAt: "YYYY-MM-DD" }]`, `licenseNoticesBy: "record-holder"` and `licenseAnswersBy: "licensee"`, when there are any |

Nothing else can be stored: any other field, kind or reason is refused, so a line carries no
amount, name, period, term or text, and an answer stores the reference only as its hash. At most
20 lines per record. Deleting the record deletes its lines, and a line written by an earlier
holder of the same id is not answered. Lines from before the licensor's signature (license-notices
v1 rows with no statement, unsigned v2 rows) stay in the database and are never shown. What the
registry can't check is still the licensor's word: that a statement is overdue at all (it sees no
terms and can't read the deal), which is why `/verify` says whose word each part is. Features:
`license-notices-v1`, `license-notices-v2`, `license-notices-v3`.

For a browser test against a real registry only, `VEILCORE_TEST_CLOCK=on` adds
`POST /__test/clock { offsetMs }`, which moves this registry's clock, answered only to a request
from the machine itself (by the socket's address; a forwarded header doesn't count). A registry
with any `RAILWAY_` variable, with `VEILCORE_ANCHOR_NETWORK=mainnet`, or with the variable set to
anything but `on`, refuses to start.

## Payment receipts

VeilCore never moves money. A payment partner (a wallet or payment company, under its own
licences) that pays a royalty statement files a signed receipt here
(`lineage/payment-receipts.mjs`; the partner guide is `docs/PAYMENT-PARTNERS.md` in the site
repository).

| Route | What |
|---|---|
| `POST /payment-receipts` | `{ receipt, signature }`. The receipt names the statement (its deal-message fingerprint), amount, currency, the account paid, the partner's payment reference, when, and the partner's key. Ed25519 over `veilcore/payment-receipt/v1\n` + the canonical receipt |
| `GET /payment-receipts/:fingerprint` | The receipts for one statement, each with the partner's registered name and whether VeilCore checked that name |

Kept only when the signature verifies, the key is registered (`POST /attesters`) with role
`payment-partner` and its name has been checked by VeilCore's operator (the same check as a
lab's, `POST /attesters/:key/vetting`), and the statement is a message held in a deal here.
Receipts are served to anyone with the statement's fingerprint, which only the two parties
and their partner know.

## Passkey copies of backups

`lineage/passkey-vault.mjs`. A browser can keep an encrypted copy of a person's backup here,
under a key only their passkey makes (WebAuthn PRF, then HKDF in the browser; site
`veilcore/passkey-backup.ts`). The registry holds an id, a write token's SHA-256 and the
ciphertext: no account, no email, no passkey public key.

- `PUT /vault/:id` `{ token, iv, ct }`: the first save sets the token; later saves need it
  and replace the copy. Up to about 2 MB of ciphertext.
- `POST /vault/:id/read` `{ token }`: the copy. A POST so the token never sits in a URL.
- `POST /vault/:id/delete` `{ token }`.

Limits per client (an IPv6 client by its /48): 20 new copies and 300 saves a UTC day. No
total cap (the operator watches the database's size). /health lists `passkey-vault-v1`.

## Paid plans (billing.js, switched off by default)

Paddle sells the plans, as merchant of record: it holds the buyer's name, email, address and
card, and handles sales tax. This registry keeps none of those.

- **No account.** A plan belongs to a holder key, like records. Paddle never sees the key.
- **No Paddle code on the site.** `POST /api/billing/checkout { plan }` (holder key) makes a
  billing id (32 random bytes that mean nothing outside this registry), opens a transaction
  with Paddle's API carrying it as `custom_data.veilcoreBillingId`, and answers the hosted
  checkout link for that transaction. The site sends the holder to Paddle's own page; the
  page holding their keys never loads a payment company's script. The billing id is never
  shown to anyone. The last 20 a holder was given keep working, and none goes before it is 7
  days old. A checkout needs a record held (409 otherwise). Ten checkouts Paddle opened an hour
  per holder and twenty per address; attempts (Paddle refusing or down) are limited separately
  (30 per holder, 60 per address), so an outage doesn't use up anyone's checkouts. Paddle
  refusing or unreachable: 502.
- **Webhook.** `POST /api/billing/paddle`, raw body. Counted only with a valid
  `Paddle-Signature` (`ts=…;h1=…`, HMAC-SHA256 of `ts:body` with the destination's secret, any
  `h1` during a rotation), a timestamp within 5 minutes, and an event id not seen in 30 days.
  `subscription.*` events set the holder's plan from the price id (`BILLING_PADDLE_PRICES`),
  never from a name in the payload. An older event than the one applied changes nothing.
  An event that can't be applied yet (an unknown billing id or price) is answered 503 and not
  kept, so Paddle sends it again while the operator fixes it; logged by subscription id only.
  The webhook has its own rate window (1,200 a minute per address).
- **The ceiling.** A paid plan keeps up to 10,000 records, while `active` or `trialing`, while
  `paused` or `canceled` until its period ends plus 7 days, and while `past_due` for 7 days
  from the first failed renewal (cancelled after a failed renewal: to the end of the period
  paid for, plus 7 days, never past 7 days from the failure). Otherwise `BILLING_FREE_RECORDS`
  proof codes dated: the free plan limits dates made, not records kept. Counted per distinct
  proof code (`billing_counted`, digested), never removed: deleting a record doesn't make room,
  the same content saved again doesn't count twice, and new content under an old id counts like
  a new record. Only the rows past a ceiling are refused, each in `rejected` with
  `code: "plan-limit"`; the rest of the save is stored, so a new record waiting in a browser
  never blocks an edit that keeps the content. Nothing already held is touched, and records
  keep verifying.
- **Switching on.** Each time billing goes from off to on: holders over the free number keep
  what they hold and may date the free number again, for good (a cap is only raised), and
  every proof code they hold that counts is counted.
- **Deliveries.** Claiming one needs free room (413 `plan-limit` otherwise): the recipient
  seals the received record with their own content, and that date counts. The claimed stub,
  until it is sealed, holds one slot (`recordsReserved`), so claims can't take more than the
  plan can date; sealing it uses that slot, and deleting it gives the slot back.
- **Not counted.** Licences, and a record's one correction as it first arrives (a new id, or one
  dated first as a bare proof code, correcting the holder's own record that is neither a
  correction nor received, once per record, ever). A held record turned into a correction, a
  free correction given new content, a correction of a correction or of a received record, or
  a correction deleted and made again, counts. The free correction's proof code is kept (marked
  free), so the same correction restored after a delete isn't new.
- `GET /api/billing/plan` (holder key): `{ plan, status, periodEnd, recordsHeld, recordsCounted,
  recordsReserved, recordCap, plans }`.
- The billing tables follow a holder key when its stored form moves (`holder-key.js`).

Stored: billing id digests, holder digest, plan, status, period end, Paddle subscription id,
digests of the proof codes counted on the free plan and of the records whose free correction
was used, event ids for 30 days.

**A change with billing off too:** at the registry's own ceiling (10,000 records), a save now
refuses only its new rows (each in `rejected`, status 200) and stores the rest; it used to
refuse the whole save with a 413. An id held by another holder no longer counts as new, since
it is never written. Pinned in `test/billing-off.test.mjs`. Tests: `test/billing.test.mjs`, `test/billing-off.test.mjs`.

## Other limits worth knowing (round D, 4 Oct 2026)

- `GET /attestations/subject/:commitment` is paged: `?limit=` (default and most 100),
  `?offset=`; answer `{ attestations, total, limit, offset }`, signers with a current name
  check first. A record takes at most 100 attestations from keys without one and 1000 from
  keys with one, counted apart, so no number of keys without a check can keep a checked lab
  off a record (13 Nov 2026); and the same again for private signatures (a lab's), counted
  apart (8 Nov 2026). Each counts where it was put when it was stored.
- (8 Oct 2026) An attestation is stored and served as its signed fields only
  (`attestationId`, `type`, `subjectCommitment`, `documentHash`, `hashAlgorithm`,
  `issuedAt`, `attester` {`publicKey`, `displayName`, `role`, `accreditation`},
  `signature`, `signatureAlgorithm`), at most 4 KB of them; anything else sent with it is
  dropped. A retraction likewise (`attestationId`, `attesterPublicKey`, `reason`,
  `retractedAt`, `signature`), at most 2 KB. Rows stored earlier are trimmed once on start.
  Signatures verify exactly as before. The embed reads at most 20 per view.
- `GET /lineage/obligations/proposals` and `GET /lineage/ancestors/:record` are paged:
  `?limit=` (default 500, most 1000), `?offset=`; ancestors adds `total`. The open listing
  `GET /lineage/obligations` is gone (410) since round 3; see "Obligations".
- `POST /lineage/obligations` is refused (400) for a commitment no record here carries,
  or one more than one holder has stored.
- A record's `attestation` field is written by this registry when a transfer is
  claimed. `PUT /api/records` keeps the stored value and ignores what the client sends.
- A claimed transfer gives the recipient a stub (`profile`, the `receivedFrom*` fields,
  `transferId`; no name since round 5) and the sender's sealed offer; see "Transfers".
  Notes, parents, method, DNA and photo fingerprints and licence ids stay with the sender.
- `POST /batches/seal` answers 409 while another seal is running, or if the pending set
  changed underneath it; nothing is written then. Seal again.
- Only a `recordFingerprint` of exactly 64 lowercase hex characters goes into a batch.
  Any other (an old row from before the stricter SDK) is left out, so it cannot stop
  sealing, and listed by record id under `skipped` in the answers of `POST /batches/seal`
  and `GET /batches/pending`. It is not counted as pending.
- `POST /attesters` takes a `publicKey` of 64 lowercase hex characters and refuses the
  small-order and non-canonical Ed25519 keys (any signature verifies under one, so a
  "signed" registration proved nothing). `POST /attestations` takes a `subjectCommitment`
  of 64 lowercase hex characters, as record fingerprints are; 0.15 refuses to verify
  anything else.
- `lineage/managed/SOURCE.json` records which contract source the vendored compiled
  contract came from; `test/vendored-contract.test.mjs` fails if those files change
  without it.

## RFC 3161 timestamps

With `VEILCORE_TSA_URL` set, every batch root also gets a timestamp token from that Time
Stamping Authority: SHA-256 of the 32 raw root bytes (`root.bin`, the same file
OpenTimestamps stamps), with a random nonce, asking for the TSA's certificate in the token.
The token is stored only after the SDK's `verifyTimestampToken` has checked it against the
root here (imprint, signature, time-stamping key usage), the nonce matches, its time is now,
and, with `VEILCORE_TSA_SIGNER_SHA256`, the signing certificate is the pinned one. Batches
with none, including those sealed before a TSA was set, are stamped hourly, oldest first:
five quick tries, then daily, and afresh when the setting changes. A token says when it was
made, so an older batch's token is dated the day it was asked for, never earlier, and is
marked `requestedAfterSeal`. `/alerts` says `timestamps-behind` when a batch sealed in the last week, over three hours
ago, has none.

It is published as an `rfc3161` anchor (SDK SPEC 9.2: `token`, `tsa`, `qualified` when
stated, plus `genTime` and a `note`) on every inclusion proof, in evidence (`batch.rfc3161`) and in exports, and as
`GET /batches/:id/root.tst`. Anyone checks it without VeilCore:

```
openssl ts -verify -data root.bin -in root.tst -token_in -CAfile <the TSA's certificate chain>
```

Why: a court weighs a blockchain date case by case; a timestamp from a qualified trust
service carries a legal presumption in the EU (eIDAS Article 41(2)), and Japan has its own
accredited services. Which TSA, and whether to pay for a qualified one, is the operator's
choice; nothing here is called qualified unless `VEILCORE_TSA_QUALIFIED_SCHEME` says so.

## OpenTimestamps

Every sealed batch root is stamped with the public calendars (the reference client's
defaults). Each calendar's answer is validated the way python-opentimestamps parses it,
with stricter rules for a fresh answer (pending attestations only, naming the calendar
asked), and stored separately. The `.ots` served at `/batches/:id/root.bin.ots` is
merged from those answers.

A stamp is `pending` (the calendar's promise to put the root in a Bitcoin transaction)
until it is upgraded. The upkeep timer, or `POST /batches/:id/opentimestamps/upgrade`,
asks the calendars for the path to the block, checks the block header against
`VEILCORE_BTC_EXPLORER`, and only then marks it `bitcoin` with the block height and time.
Proofs (`/proof/:commitment`), `/batches` and `/api/export` report the status.

Operator routes (`x-operator-token`):

- `POST /batches/:id/opentimestamps`: stamp a batch. Refused (409) if it already has a
  proof, unless `?force=1`, which adds fresh answers beside the old ones.
- `POST /batches/:id/opentimestamps/upgrade`: try to upgrade one batch now.
- `POST /batches/opentimestamps/maintenance`: one pass of the timer.

Batches sealed before stamping existed are not stamped automatically. Stamp them with
the first route if wanted (the Bitcoin date is then the date of that stamp).
