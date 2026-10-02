"""Request an audit from the auditor and save the credential JSON.

  python cli/request_audit.py --chain 11155111 --address 0x... [--block N] [--out credentials/x.json]
"""

import argparse
import json

import httpx

from common import AUDITOR_URL, ROOT

ap = argparse.ArgumentParser()
ap.add_argument("--chain", type=int, required=True)
ap.add_argument("--address", required=True)
ap.add_argument("--block", type=int)
ap.add_argument("--out")
a = ap.parse_args()

body = {"chainId": a.chain, "address": a.address, "blockNumber": a.block}
print(f"POST {AUDITOR_URL}/audit {body} (this can take several minutes)...", flush=True)
r = httpx.post(f"{AUDITOR_URL}/audit", json=body, timeout=3600)
if r.status_code != 200:
    raise SystemExit(f"auditor returned {r.status_code}: {r.text}")
cred = r.json()
out = a.out or ROOT / "credentials" / f"{a.chain}-{a.address.lower()}.json"
open(out, "w").write(json.dumps(cred, indent=2))

audit = cred["credentialSubject"]["audit"]
print(f"saved {out}")
print(f"grade {audit['grade']} score {audit['score']} confidence {audit['confidence']['level']} "
      f"(intact {cred['credentialSubject']['scaeCheck']['gradeIntact']}, stripped {cred['credentialSubject']['scaeCheck']['gradeStripped']})")
print(audit["summary"])
for f in audit["findings"]:
    print(f"  [{f['severity']}] {f['title']} @ {f['location']}")
print(f"signer {cred['issuer']}  configHash {cred['credentialSubject']['pipeline']['configHash']}  mock={cred['proof']['mock']}")
