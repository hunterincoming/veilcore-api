// Remove the records this audit created on production.
//
// Everything here was written under holder keys invented for testing, so nothing
// belonging to a real holder is in scope — the delete route is holder-scoped and
// would refuse an id it does not own anyway.
//
//   node cleanup-audit-records.mjs

const B = 'https://veilcore-api-production.up.railway.app';

// Each key with what it created. Keys are the hex strings used during the audit.
const OWNED = {
  ['c'.repeat(64)]: ['AUDIT-1', 'S1', 'S2', 'S3'],
  ['d'.repeat(64)]: ['X1', 'X2'],
  ['e'.repeat(64)]: ['DEPLOY-CHECK'],
  ['f'.repeat(64)]: ['LIVE-1', 'LIVE-2', 'DESCENT-TEST'],
  ['a'.repeat(64)]: ['AUDIT-1'],
  ['b'.repeat(64)]: ['AUDIT-1'],
  ['1a'.repeat(32)]: ['XFER-SRC'],
  ['3a'.repeat(32)]: ['PROD-XFER'],
  // The record Mallory received by claiming a transfer offered to bob. Its id is
  // derived from the transfer, so it is listed after a lookup below rather than here.
  ['9f'.repeat(32)]: [],
  ['7f'.repeat(32)]: [],
  ['2a'.repeat(32)]: [],
  ['8f'.repeat(32)]: [],
};

const headers = (k) => ({ 'Content-Type': 'application/json', 'x-holder-key': k });

const list = (k) => fetch(B + '/api/records', { headers: headers(k) }).then((r) => r.json());
const remove = (k, ids) =>
  fetch(B + '/api/records', {
    method: 'DELETE',
    headers: headers(k),
    body: JSON.stringify({ ids }),
  }).then((r) => r.json());

let total = 0;

for (const key of Object.keys(OWNED)) {
  const held = await list(key);
  if (!Array.isArray(held) || held.length === 0) continue;

  // Delete everything under these keys rather than the hardcoded list: claiming a
  // transfer created records with derived ids nobody wrote down.
  const ids = held.map((r) => r.id).filter(Boolean);
  const out = await remove(key, ids);
  const gone = out.removed?.length ?? 0;
  total += gone;
  console.log(`${key.slice(0, 8)}… ${String(gone).padStart(2)} removed${out.notRemoved?.length ? `, ${out.notRemoved.length} not owned` : ''}`);
  for (const id of out.removed ?? []) console.log(`           ${id}`);
}

console.log(`\n${total} record(s) removed.`);
console.log(`
Not removed, and worth knowing why:

  Lineage edges. declareParent writes an edge into transaction history keyed by
  commitment, and the graph is rebuilt from that history. There is no delete, by
  design — a declared parent that could be withdrawn would let a seller shed an
  inconvenient generation, which is the omission attack this format exists to catch.
  The audit declared edges for 11…/22…/33…, 77…/88… and one real commitment. They
  name commitments of records that never existed and point at nothing.

  Attestations. att_audit_1 was accepted by the registry and is signed by a keypair
  that exists only in that test. It stays, because an attestation is not deleted —
  it is retracted, by the key that issued it, and that key is gone.
`);
