// What /verify/:id hands a stranger.
//
// The endpoint takes no holder key: whoever has a record id can call it, and the
// caller writes ?show=. Since round D (4 Oct 2026) a fact beyond the base is answered
// only if the record's holder granted it (PUT /api/records/:id/disclosure), and ?show=
// can only narrow that grant. The audit holder key below grants nothing, so after that
// change is deployed every "leaked" line here should stay silent.
//
//   node verify-disclosure-check.mjs

const B = 'https://veilcore-api-production.up.railway.app';

const recs = await fetch(B + '/api/records', {
  headers: { 'x-holder-key': 'f'.repeat(64) },
}).then((r) => r.json());

const id = Array.isArray(recs) && recs.length ? recs[0].id : null;
if (!id) {
  console.log('no record under the audit holder key to test with');
  process.exit(0);
}

console.log('record id:', id);

const get = (qs) => fetch(B + '/verify/' + encodeURIComponent(id) + qs).then((r) => r.json());

console.log('\nno ?show= at all — the documented "existence and integrity" case:');
console.log(JSON.stringify(await get(''), null, 2));

console.log('\ncaller asks for everything:');
const everything = await get('?show=own,dna,sealed,lineage,parents,method,others,agreementTerms');
console.log(JSON.stringify(everything, null, 2));

console.log('\nwhat that leaked:');
if (everything.otherRecordCount !== undefined) {
  console.log(`  otherRecordCount = ${everything.otherRecordCount} — the size of this holder's whole portfolio`);
}
if (everything.otherAgreements !== undefined) {
  console.log(`  otherAgreements = ${everything.otherAgreements.length} licences on records this caller was never shown`);
}
for (const f of ['parents', 'breedingMethod', 'dnaPairedByHolder', 'sealedAt', 'loggedAtClaimedByHolder', 'priorPossession']) {
  if (everything[f] !== undefined) console.log(`  ${f} = ${JSON.stringify(everything[f])} — answered without a grant from the holder`);
}
if (everything.lineageIntact !== undefined) {
  console.log(`  lineageIntact = ${everything.lineageIntact} — hardcoded, nothing was checked`);
}
