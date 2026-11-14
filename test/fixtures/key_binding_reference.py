# A second, independent checker for records that name their own key (SPEC 3.6.1),
# in Python with only the standard library. Reads a key-bound vector file and checks
# every key, record, check and refusal in it. Prints one JSON line:
#   {"ok": true, "checked": N}   or   {"ok": false, "failures": [...]}
# The canonical form here is json.dumps with sorted keys and no spaces, which equals
# SPEC 4.4 for what the vectors hold (ASCII-sortable keys, integers within 2^53, strings
# in NFC); it is also compared with the vector's own `canonical` text.
#   python3 key_binding_reference.py <key-bound-v1.json>
import hashlib, json, re, sys

HEX64 = re.compile(r'^[0-9a-f]{64}$')

def H(tag, *hexes):
    t = tag.encode('utf-8')
    assert len(t) <= 32
    return hashlib.sha256(t.ljust(32, b'\0') + b''.join(bytes.fromhex(h) for h in hexes)).hexdigest()

def is_hex64(v):
    return isinstance(v, str) and HEX64.match(v) is not None

def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False)

def fingerprint(fields):
    if 'keyBinding' in fields and not is_hex64(fields['keyBinding']):
        raise ValueError('keyBinding must be 64 lowercase hex characters')
    content = hashlib.sha256(canonical(fields).encode('utf-8')).hexdigest()
    return content, (H('veilcore:v1:keyrecord', fields['keyBinding'], content) if 'keyBinding' in fields else content)

def matches(identity, fp, salt, content):
    if not all(is_hex64(v) for v in (identity, fp, salt, content)):
        return False
    return H('veilcore:v1:keyrecord', H('veilcore:v1:keybind', identity, salt), content) == fp

v = json.load(open(sys.argv[1], encoding='utf-8'))
failures, n = [], 0
for k in v['keys']:
    n += 1
    s = k['recordSecret']
    identity, salt = H('veilcore:v1:commit', s), H('veilcore:v1:keysalt', s)
    got = {'identity': identity, 'keySalt': salt, 'keyBinding': H('veilcore:v1:keybind', identity, salt)}
    for name, value in got.items():
        if value != k[name]:
            failures.append(f'key {s[:8]}: {name}')
for r in v['records']:
    n += 1
    if canonical(r['fields']) != r['canonical']:
        failures.append(f"{r['name']}: canonical text")
    content, fp = fingerprint(r['fields'])
    if content != r['contentHash'] or fp != r['fingerprint']:
        failures.append(f"{r['name']}: fingerprint")
for c in v['checks']:
    n += 1
    if matches(c['identity'], c['fingerprint'], c['keySalt'], c['contentHash']) != c['matches']:
        failures.append(f"{c['name']}: match")
for r in v['refusals']:
    n += 1
    try:
        fingerprint(r['fields'])
        failures.append(f"{r['name']}: not refused")
    except ValueError:
        pass
print(json.dumps({'ok': not failures, 'checked': n} if not failures else {'ok': False, 'failures': failures}))
