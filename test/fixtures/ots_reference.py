# Reference checks for lineage/ots.mjs, using the OpenTimestamps project's own Python
# library (pip install opentimestamps). Two modes:
#   answers <digest-hex>    print two calendar-style answers (hex, one per line): the
#                           timestamp nodes a calendar returns for a submitted digest
#   fresh <digest-hex> <uri>...
#                           print one answer per URI, shaped like a real calendar's
#                           answer to a new submission: append(nonce), sha256, pending
#   parse <ots-hex>         parse a detached .ots file and print what it commits to
import sys, os, json
from opentimestamps.core.timestamp import Timestamp, DetachedTimestampFile
from opentimestamps.core.op import OpAppend, OpSHA256, OpPrepend
from opentimestamps.core.notary import PendingAttestation, BitcoinBlockHeaderAttestation
from opentimestamps.core.serialize import BytesSerializationContext, BytesDeserializationContext

def answer(digest, url, extra_fork):
    t = Timestamp(digest)
    a = t.ops.add(OpAppend(os.urandom(16)))
    b = a.ops.add(OpSHA256())
    b.attestations.add(PendingAttestation(url))
    if extra_fork:
        c = t.ops.add(OpPrepend(os.urandom(8)))
        d = c.ops.add(OpSHA256())
        d.attestations.add(BitcoinBlockHeaderAttestation(800000))
    ctx = BytesSerializationContext()
    t.serialize(ctx)
    return ctx.getbytes().hex()

if sys.argv[1] == 'answers':
    d = bytes.fromhex(sys.argv[2])
    print(answer(d, 'https://a.pool.opentimestamps.org', True))
    print(answer(d, 'https://b.pool.opentimestamps.org', False))
elif sys.argv[1] == 'fresh':
    d = bytes.fromhex(sys.argv[2])
    for uri in sys.argv[3:]:
        print(answer(d, uri, False))
elif sys.argv[1] == 'parse':
    raw = bytes.fromhex(sys.argv[2])
    f = DetachedTimestampFile.deserialize(BytesDeserializationContext(raw))
    atts = sorted(str(type(a).__name__) + ':' + (a.uri if hasattr(a, 'uri') else str(getattr(a, 'height', ''))) for _, a in f.timestamp.all_attestations())
    print(json.dumps({'digest': f.file_digest.hex(), 'op': str(f.file_hash_op), 'attestations': atts}))
