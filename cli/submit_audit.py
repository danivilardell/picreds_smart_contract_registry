"""Submit a credential's AuditRecord (and its full report) to the registry.

  python cli/submit_audit.py --credential credentials/x.json
"""

import argparse
import json

from common import check_report_hash, record_tuple, registry, send, w3

ap = argparse.ArgumentParser()
ap.add_argument("--credential", required=True)
a = ap.parse_args()

cred = json.load(open(a.credential))
report = check_report_hash(cred)
record = record_tuple(cred)
signature = bytes.fromhex(cred["proof"]["proofValue"][2:])

w = w3()
reg = registry(w)
signer = cred["issuer"].split(":")[-1]
if not reg.functions.isAttestedSigner(signer).call():
    raise SystemExit(f"signer {signer} is not registered; run cli/register_signer.py first")

send(w, reg.functions.submitAudit(record, signature, report.decode()), "submitAudit")
stored = reg.functions.latestAudit(record[0], record[1]).call()
print(f"on chain: grade {stored[0][5].decode()} score {stored[0][6]} codeHash 0x{stored[0][2].hex()} signer {stored[1]}")
