# How to run your own witness

For anyone outside VeilCore (a university, a lab, a standards body) who wants their own
copy of every batch VeilCore has dated, and a way to check it without trusting us.

## What you get

VeilCore puts the fingerprints of records into batches. Each batch has one **root** (32
bytes). The root is dated three ways: a transaction on Midnight mainnet, an OpenTimestamps
proof on Bitcoin, and an RFC 3161 timestamp token. A record shows **prior possession** by a
date when its fingerprint is in a batch whose root was dated.

A witness keeps a copy of every batch root and its proofs. Each run fetches them again and
compares: every file of every batch while there are up to 200 batches, and past that a quarter
of the finished ones per run, in turn (`--full` fetches everything). If the registry is ever
gone, or quietly changes a root, a date, a token or a proof, your copy is the evidence of what
it said before.

## What you need

- Node.js 22 or newer, git and openssl (most Linux and Mac machines have openssl).
- Under 10 KB of disk per batch.
- Optional, for the Midnight check: a free [Blockfrost](https://blockfrost.io) project for
  **Midnight Mainnet** (its project id), or any other Midnight indexer you trust.
- Optional, for the strongest RFC 3161 check: the time-stamping authority's root certificate,
  from that authority's own website.
- Optional, for the strongest Bitcoin check: your own Bitcoin node and the `ots` client
  (`pip install opentimestamps-client`).

## Steps

```
git clone https://github.com/hunterincoming/veilcore-api
cd veilcore-api
git checkout <a commit you have read>        # pin it; update on purpose, not by accident

node scripts/mirror/witness.mjs mirror ~/veilcore-witness
node scripts/mirror/witness.mjs check  ~/veilcore-witness
```

No `npm install` is needed. With the Midnight check:

```
read -s BLOCKFROST_PROJECT_ID; export BLOCKFROST_PROJECT_ID
node scripts/mirror/witness.mjs check ~/veilcore-witness
```

(or `--indexer <GraphQL URL>`; give two to require that both agree). The project id is never
printed.

With the time-stamping authority's root certificate (see which authority signed a token with
`openssl ts -reply -in root.tst -token_in -text | grep TSA`):

```
node scripts/mirror/witness.mjs check ~/veilcore-witness --tsa-ca <their-root.pem>
```

The full Bitcoin check, per batch, against your own node:

```
cd ~/veilcore-witness/batches/<batchId> && ots verify -f root.bin root.bin.ots
```

**Run it on a schedule** (daily is plenty), and keep the folder in git so your own history
is a second record:

```
cd ~/veilcore-witness && git init      # once
# then each day:
node ~/veilcore-api/scripts/mirror/witness.mjs mirror ~/veilcore-witness ; \
  cd ~/veilcore-witness && git add -A && git commit -qm "mirror $(date -u +%F)"
```

`;`, not `&&`: a run that found a conflict (exit 2) has the other version to commit. Add
`--full` once a week once there are more than 200 batches.

**Exit codes of `mirror`:** 0, done; 2, the registry changed history (below); 1, the run
could not finish: the registry did not answer, or its answer could not be used (not JSON, a
batch with no usable id, the same batch listed twice differently, a page cursor that goes
nowhere). After exit 1 the folder is exactly as it was before the run; try again later.

## Reading the results

Each batch gets four lines:

| Part | OK means | Needs |
|---|---|---|
| files | each file matches the SHA-256 in `index.json`, and `root.bin` is the root | nothing |
| rfc3161 | the token stamps this root, its signature verifies, and its chain leads to the root certificate you gave | `--tsa-ca` (without it: "couldn't check") |
| bitcoin | the proof commits to this root, and the Bitcoin block header holds the Merkle root it claims | a block explorer (blockstream.info by default, `--bitcoin-explorer` for another, `--offline` for none) |
| midnight | the transaction exists, succeeded, made one `anchorBatch` call on VeilCore's mainnet contract, the contract state right after it holds this root, and its block is the one the registry recorded | an indexer |

A batch is OK only when all four are. **COULDN'T CHECK** says why: no tool, no network, a
proof still pending, or an anchor only on a test network (which carries no evidential weight).

**MISMATCH** means something is wrong. **Exit code 2** from `mirror` means the registry now
serves a different history from the one you copied. In either case:

1. Keep the folder as it is. The mirror never overwrote anything; what the registry served
   instead is in `conflicts/`.
2. Tell the registry operator (the security contact in `SECURITY.md` of this repository),
   and anyone relying on those dates.

**After you have looked at a conflict.** Leave `conflicts/` and the `conflicts` note in
`index.json` in place, even once it is explained: they are the record that it happened, and
`check` keeps reporting the batch as a mismatch on purpose. If the operator explains it, write
the explanation down beside it (a `NOTE.md` in that `conflicts/<batchId>/` folder, committed).
Never edit the batch's own files to match the registry.

## What this does not check

- **Individual records.** The registry does not publish which records are in a batch. A
  holder keeps their own proof (record → batch root) in their backup file, and checks it with
  `npx veilcore-records verify`. A witness vouches for the batch roots and their dates.
- **Who holds a record.** A batch shows prior possession by a date, never ownership.
- **The exact contract cell.** The website decodes the contract's `lastBatchRoot` with the
  compiled contract. This checker looks for the root's 32 bytes in the contract state right
  after the call, which would also pass if another cell held the same bytes. Programs that
  import `scripts/mirror/check.mjs` can pass the exact decoder as `rootOf`.
- **A different list shown to different people.** The registry could show you one history
  and someone else another. Compare your `index.json` with another witness's: every batch
  you both have must match exactly.
- **The indexer and the explorer.** They are trusted for what they report. Use two of each,
  or your own nodes, to need two of them to lie.

## Why it is built this way

It borrows from Certificate Transparency monitors and Sigstore witnesses: keep what you saw,
never let a later answer from the log replace it, and raise the alarm when the log's new view
does not extend the old one. From OpenTimestamps it takes the rule for proofs: an upgraded
proof keeps everything the pending one had and only adds the path to a Bitcoin block.

A witness is only as independent as the person running it. That is why one run by someone
outside VeilCore is worth more than any copy we keep ourselves.
