// The embeddable verifier.
//
// Verification is the act that spreads the format, so it has to work anywhere without
// an account, a key, or our app. A lab drops this on its certificate page; a
// marketplace drops it next to a listing. Every place it appears is a place the format
// spreads without anyone selling anything.
//
// Served as a plain script tag rather than a package, because requiring a build step is
// a toll on the thing we most want to be free.
// SPDX-License-Identifier: Apache-2.0

const CSS = `
.veilcore-verify{font-family:ui-sans-serif,system-ui,-apple-system,sans-serif;border:1px solid rgba(127,127,127,.3);border-radius:10px;padding:14px 16px;max-width:420px;line-height:1.5}
.veilcore-verify .vc-head{display:flex;align-items:center;gap:8px;margin-bottom:8px}
.veilcore-verify .vc-dot{width:9px;height:9px;border-radius:50%;flex:none}
.veilcore-verify .vc-ok{background:#2ff0cf}
.veilcore-verify .vc-no{background:#8a8a8a}
.veilcore-verify .vc-title{font-weight:600;font-size:14px}
.veilcore-verify .vc-fact{font-size:13px;opacity:.85;margin:3px 0}
.veilcore-verify .vc-meta{font-size:11px;opacity:.6;margin-top:10px;font-family:ui-monospace,monospace;word-break:break-all}
.veilcore-verify a{color:inherit;text-decoration:underline;opacity:.7;font-size:11px}
`;

const escapeHtml = (s) =>
  String(s ?? '').replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

/**
 * A name somebody else chose, made fit to print on a third party's page (deep dive, 8 Oct
 * 2026, LOW; round 2). Attester display names and cultivar names were printed as given: a
 * bidi override can make a name render as a different name, and characters that print as
 * nothing hide what it says or make a blank look like a name.
 *
 * Removed: control and format characters (bidi controls, zero-width characters, soft
 * hyphen, BOM, tags), line separators, every default-ignorable code point (U+034F,
 * U+17B4/5, Hangul fillers, variation selectors and the rest of that Unicode property),
 * and U+2800 braille blank. Then normalised (NFC by default; NFKC for display names, so
 * styled lookalikes such as mathematical bold or fullwidth letters read as the letters
 * they look like), cleaned again, whitespace collapsed, and cut to `max` characters. A
 * result with no letter or digit in it is no name at all (''). HTML escaping still
 * happens where it is printed.
 */
const INVISIBLE = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Default_Ignorable_Code_Point}\u2800]/gu;
const LETTER_OR_DIGIT = /[\p{L}\p{N}]/u;
export const DISPLAY_MAX = 64;
export const displayText = (s, max = DISPLAY_MAX, form = 'NFC') => {
  const clean = String(s ?? '').replace(INVISIBLE, '').normalize(form).replace(INVISIBLE, '').replace(/\s+/g, ' ').trim();
  if (!LETTER_OR_DIGIT.test(clean)) return '';
  const chars = [...clean];
  return chars.length > max ? `${chars.slice(0, max - 1).join('').trimEnd()}\u2026` : clean;
};
/** An attester's self-chosen display name, as the embed prints it ('' for none). */
export const displayName = (s) => displayText(s, DISPLAY_MAX, 'NFKC');

/** The ledger an anchor names, in words. Anything unrecognised is named as stored. */
export const ledgerName = (a) => {
  const chain = typeof a?.chain === 'string' && a.chain ? a.chain : 'midnight';
  const network = typeof a?.network === 'string' && a.network ? a.network : 'unknown';
  if (chain === 'midnight') {
    if (network === 'mainnet') return 'Midnight mainnet';
    if (network === 'preview') return 'Midnight Preview';
    if (network === 'preprod') return 'Midnight preprod';
    return `Midnight (${network})`;
  }
  return `${chain} (${network})`;
};

/**
 * What a name check says, in the words the site uses (round 4): where the operator matched
 * the name, the licence or certificate number, and the day. Null for anything that is not
 * a well-formed check record; such a signer is not described as matched.
 */
export const nameCheckWords = (check) => {
  if (!check || typeof check !== 'object' || typeof check.sourceUrl !== 'string') return null;
  let host;
  try {
    const u = new URL(check.sourceUrl);
    if (u.protocol !== 'https:') return null;
    host = u.hostname.replace(/^www\./, '');
  } catch {
    return null;
  }
  if (typeof check.checkedAt !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(check.checkedAt)) return null;
  const no = typeof check.licenceNo === 'string' && check.licenceNo
    ? ` (${check.source === 'accreditation' ? 'certificate' : 'license'} ${displayText(check.licenceNo, 100)})`
    : '';
  return `VeilCore\u2019s operator matched this name to ${host}${no} on ${check.checkedAt}. VeilCore doesn\u2019t vouch for the lab\u2019s work.`;
};

const render = (r, base) => {
  if (!r.found) {
    return `<div class="veilcore-verify">
      <div class="vc-head"><span class="vc-dot vc-no"></span><span class="vc-title">No record found</span></div>
      <div class="vc-fact">This identifier does not match a record in the registry.</div>
    </div>`;
  }
  const facts = [];
  // Pushed unconditionally until now, so a record carrying no commitment at all was
  // rendered on a third party's page saying its commitment matched its contents —
  // with an empty fingerprint in the meta line underneath. Nothing had been checked.
  const sealed = Boolean(r.recordFingerprint);
  // Since sealed records the registry can't open a record, so it can't check that its
  // fingerprint matches its contents (round 4, F3): it used to say so here, on third
  // parties' pages, for any random bytes stored under any fingerprint. Worded as /verify
  // says it (fingerprintCheckedByRegistry: false): the holder's app checks it.
  facts.push(
    sealed
      ? 'Record exists. Its contents are locked, so this registry can\u2019t check them against its proof code; the holder\u2019s app does.'
      : 'Record exists in the registry and has no proof code, so nothing about it can be checked.',
  );
  // A missing or malformed timestamp renders as 1969 rather than as nothing, which
  // looks broken to a reader instead of looking absent. Anything before 2020 is not a
  // real sealing date for this format.
  // Rendered on a server for readers anywhere, so an unambiguous UTC calendar date.
  const day = (d) => `${new Date(d).toISOString().slice(0, 10)} (UTC)`;
  const realDate = (d) => d && !Number.isNaN(new Date(d).getTime()) && new Date(d).getFullYear() > 2019;
  // The record's own date is whatever the holder typed. It used to print as "Sealed
  // <date>." with the line below saying the date rested on the registry, so a holder
  // could put 2021 on a record first stored today and the embed vouched for it (attack
  // round 11). It is now labelled as theirs, and the registry's own date sits beside it.
  if (realDate(r.sealedAt)) {
    facts.push(`Date stated by the holder: ${day(r.sealedAt)}. The holder chose this date; nobody checked it.`);
  }
  if (sealed && realDate(r.registryFirstSeen)) {
    facts.push(`First seen by this registry, in this exact form, on ${day(r.registryFirstSeen)}.`);
  }

  // Anchoring is what fixes the date independently of the holder. Saying a record is
  // sealed without saying whether that date is independently established would let a
  // reader assume the stronger claim.
  // The ledger is named. "Anchored on a public ledger" with no name read as mainnet once
  // mainnet existed, for batches anchored on Preview or preprod before the switch; a test
  // network can be reset, and its dates carry no evidential weight (mainnet readiness).
  // `undeployed` is SPEC 3's value for "never anchored".
  //
  // The registry records the transaction its operator reports and never looks it up (deep
  // dive, 8 Oct 2026). This said the date "does not rest on ... this registry's" word,
  // which is only true once a reader has checked the transaction; so it now says who
  // recorded it and gives the transaction and contract in full, so anyone can.
  if (r.anchor && r.anchor.txHash && r.anchor.network !== 'undeployed') {
    const where = ledgerName(r.anchor);
    const contract = typeof r.anchor.contractAddress === 'string' && r.anchor.contractAddress ? `, contract ${r.anchor.contractAddress}` : '';
    facts.push(
      r.anchor.network === 'mainnet'
        ? `Anchored on ${where}, as recorded by this registry\u2019s operator: transaction ${r.anchor.txHash}${contract}. This registry has not checked that transaction. Look it up on chain; once it matches this record\u2019s batch root, the date rests on the ledger rather than on the holder\u2019s word or this registry\u2019s.`
        : `Anchored only on ${where}, a test network. A test network can be reset, so that date carries no evidential weight; until the record is anchored on mainnet, its date rests on this registry\u2019s word.`,
    );
  } else {
    // "The record is intact" was asserted here too, one line below the fact that said
    // nothing about it could be checked. An unsealed record has no integrity to report.
    facts.push(
      sealed
        ? 'Not yet anchored on a ledger. The record is unaltered since the registry first saw it; that date rests on this registry\u2019s word, not on a ledger.'
        : 'Not anchored, and nothing is sealed. Nothing about its date can be checked.',
    );
  }

  // Attestations differ in weight and must not be reported identically. An unsigned
  // attestation is a claim the registry recorded; a signed one is a statement by whoever
  // holds the key. Only a key whose name the operator matched, with the check record to
  // show for it (round 4), is described by its name: anyone can register a key under a
  // lab's name, and the accreditation a signer types is never shown as a fact (attack
  // round 11). The sentence says what was checked, where and when, and nothing more.
  if (Array.isArray(r.attestations)) {
    const live = r.attestations.filter((a) => !a.retraction);
    const signedLive = live.filter((a) => a.strength !== 'unsigned');
    // The name as it will be printed; one that is nothing but invisible characters is none.
    const nameOf = (a) => displayName(a.registeredAs && a.registeredAs.displayName);
    const matched = (a) => a.vettedAttester === true && nameCheckWords(a.registeredAs && a.registeredAs.nameCheck) !== null;
    const vetted = signedLive.filter(matched);
    const selfRegistered = signedLive.filter((a) => !matched(a) && nameOf(a));
    const anonymous = signedLive.filter((a) => !matched(a) && !nameOf(a));
    const unsigned = live.filter((a) => a.strength === 'unsigned');
    const retracted = r.attestations.length - live.length;

    if (vetted.length) {
      const who = nameOf(vetted[0]);
      const words = nameCheckWords(vetted[0].registeredAs.nameCheck);
      facts.push(who
        ? `Signed by ${who}. ${words}`
        : `Signed by a key whose registered name can\u2019t be shown here. ${words.replace('this name', 'that name')}`);
    }
    for (const a of selfRegistered.slice(0, 3)) {
      facts.push(`Signed by a key named \u201c${nameOf(a)}\u201d (name not checked). Anyone can register a key under any name.`);
    }
    if (anonymous.length) facts.push('Signed by a key nobody has registered. The signature is valid; who holds the key is not known.');
    if (unsigned.length) facts.push('A second party is recorded as confirming this, but did not sign \u2014 treat it as weaker.');
    if (retracted) facts.push(`${retracted} attestation${retracted > 1 ? 's have' : ' has'} been retracted by the attester. Retracted, not deleted.`);
    // Private unless the holder shows them (8 Nov 2026): none here never means no lab signed.
    if (!r.attestations.length) facts.push('No signature is shown here. A lab\u2019s signatures are private unless the holder shows them.');
  } else if (r.attestedByVettedLab !== undefined && r.disclosed === undefined) {
    facts.push(r.attestedByVettedLab
      ? 'Signed by a key whose name VeilCore\u2019s operator matched to a public license or accreditation listing. VeilCore doesn\u2019t vouch for the lab\u2019s work.'
      : 'No signature from a key whose name VeilCore\u2019s operator has matched to a public listing.');
  }

  // A lab's receipt that names sample details stored locked (sealed records round 3): the
  // registry can't check the receipt against them (round 4, F11: it used to say the lab
  // "signed over" them, as a checked fact), nor whether they match. Whatever the holder's
  // app worked out is said as the holder's, only when they chose to show it.
  if (Array.isArray(r.custody)) {
    for (const c of r.custody.filter((x) => x && x.custody === 'sealed').slice(0, 3)) {
      const s = c.custodySummary;
      const theirs = !s ? ''
        : s.covered === 'covered'
          ? s.differingFields.length ? ' The holder’s app found differences between what was sent and what arrived.' : ' The holder’s app found they match what was sent.'
          : s.covered === 'changed' ? ' The holder’s app found they were changed after the lab signed.' : '';
      facts.push(`The lab’s receipt names sample details. They are stored locked, so this page can’t show or check them; the holder’s app can.${theirs}`);
    }
  }

  // A superseded record must say so, or someone acts on a version that was corrected.
  if (r.supersededBy) {
    facts.push('This record was corrected. It remains on file unchanged, and a later record supersedes it.');
  }
  if (r.supersedes) {
    facts.push('This corrects an earlier record, which remains on file.');
  }

  return `<div class="veilcore-verify">
    <div class="vc-head"><span class="vc-dot ${sealed ? 'vc-ok' : 'vc-no'}"></span><span class="vc-title">${escapeHtml(displayText(r.cultivar, 120) || 'Name not shared')}</span></div>
    ${facts.map((f) => `<div class="vc-fact">${escapeHtml(f)}</div>`).join('')}
    <div class="vc-fact" style="opacity:.6">The genetics themselves are never disclosed.</div>
    <div class="vc-meta">${escapeHtml(r.id)}${r.recordFingerprint ? ` &middot; ${escapeHtml(r.recordFingerprint.slice(0, 16))}&hellip;` : ''}</div>
    <a href="${base}/verify/${encodeURIComponent(r.id)}" target="_blank" rel="noopener">Verify independently</a>
  </div>`;
};

/** The script served at /embed.js. Finds elements and fills them in. */
export const embedScript = (base) => `(function(){
  var css = ${JSON.stringify(CSS)};
  if(!document.getElementById('veilcore-embed-css')){
    var s=document.createElement('style');s.id='veilcore-embed-css';s.textContent=css;document.head.appendChild(s);
  }
  var nodes = document.querySelectorAll('[data-veilcore-verify]');
  for (var i=0;i<nodes.length;i++){
    (function(el){
      var id = el.getAttribute('data-veilcore-verify');
      var show = el.getAttribute('data-veilcore-show');
      var url = ${JSON.stringify(base)} + '/embed/' + encodeURIComponent(id) + (show ? '?show=' + encodeURIComponent(show) : '');
      fetch(url).then(function(r){return r.text();}).then(function(html){ el.innerHTML = html; })
        .catch(function(){ el.innerHTML = '<div class="veilcore-verify"><div class="vc-fact">Could not reach the registry.</div></div>'; });
    })(nodes[i]);
  }
})();`;

export const renderEmbed = render;
