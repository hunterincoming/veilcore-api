# A second, independent implementation of the re-stamp rules (lineage/restamp.mjs), in Python
# with the standard library only, from the text of the site's docs/restamp.md and SPEC 5.
# It wrote test/fixtures/restamp-v1.json; restamp.test.mjs checks the JavaScript gets the same
# entries and root from the same items. Run: python3 test/fixtures/restamp_v1_reference.py > test/fixtures/restamp-v1.json
#
# SPDX-License-Identifier: Apache-2.0

import hashlib
import json


def h(text):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def canonical(obj):
    # RFC 8785 for what the fixture holds (strings, whole numbers, objects): sorted keys, no spaces.
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def entry(kind, data):
    return h('veilcore:restamp:v1:' + kind + ':' + hashlib.sha256(data).hexdigest())


def spec5_root(entries):
    level = [h('00' + e) for e in sorted(set(entries))]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            nxt.append(level[i] if i + 1 == len(level) else h('01' + level[i] + level[i + 1]))
        level = nxt
    return level[0]


attestation = {
    'attestationId': 'att-fixture-1',
    'type': 'genetic-fingerprint',
    'subjectCommitment': '11' * 32,
    'documentHash': '22' * 32,
    'hashAlgorithm': 'sha256',
    'issuedAt': '2026-11-01T12:00:00Z',
    'signature': 'ab' * 64,
    'signatureAlgorithm': 'ed25519',
    'attester': {'publicKey': '33' * 32, 'displayName': 'Fixture Lab', 'role': 'laboratory'},
}
withdrawal = {
    'attestationId': 'att-fixture-1',
    'attesterPublicKey': '33' * 32,
    'reason': 'superseded',
    'retractedAt': '2026-11-02T12:00:00Z',
    'signature': 'cd' * 64,
}
enrolment = {'publicKey': '33' * 32, 'displayName': 'Fixture Lab', 'role': 'laboratory', 'registeredAt': 1793534400000}
signed_registration = {
    'type': 'veilcore/attester-registration/v1',
    'publicKey': enrolment['publicKey'],
    'displayName': enrolment['displayName'],
    'role': enrolment['role'],
    'issuedAt': enrolment['registeredAt'],
}

items = [
    {'kind': 'batch-root', 'item': 'aa' * 32, 'bytesHex': 'aa' * 32},
    {'kind': 'batch-root', 'item': '0f' * 32, 'bytesHex': '0f' * 32},
    {'kind': 'attestation', 'item': attestation, 'bytesText': canonical(attestation)},
    {'kind': 'withdrawal', 'item': withdrawal, 'bytesText': canonical(withdrawal)},
    {'kind': 'enrolment', 'item': enrolment, 'bytesText': canonical(signed_registration)},
    {'kind': 'rfc3161', 'item': '3082' + 'ee' * 20, 'bytesHex': '3082' + 'ee' * 20},
    {'kind': 'rfc3161', 'item': '3082' + '5a' * 24, 'bytesHex': '3082' + '5a' * 24},
]
for it in items:
    data = bytes.fromhex(it['bytesHex']) if 'bytesHex' in it else it['bytesText'].encode('utf-8')
    it['entry'] = entry(it['kind'], data)

entries = sorted(it['entry'] for it in items)
print(json.dumps({'items': items, 'entries': entries, 'root': spec5_root(entries)}, indent=2))
