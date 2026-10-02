"""Export the registry's audits into a static copy of the frontend (frontend/snapshot.html) for hosting where no
RPC access exists. The page itself is unchanged; its empty <script id="snapshot"> block is filled with JSON.

  python cli/export_snapshot.py
"""

import json
import os
import time

from web3 import Web3

from common import ROOT, env, jwt_header, registry, w3

w = w3()
reg = registry(w)
start = int(env("REGISTRY_DEPLOY_BLOCK"))
latest = w.eth.block_number

signers = {}
for e in reg.events.SignerRegistered().get_logs(from_block=start, to_block=latest):
    addr, jwt = e["args"]["signer"], e["args"]["jwt"]
    digest, att_hash, registered_at = reg.functions.signers(addr).call()
    kid = jwt_header(jwt)["kid"]
    signers[addr.lower()] = {
        "address": addr, "jwt": jwt, "kid": kid, "imageDigest": "0x" + digest.hex(), "attestationHash": "0x" + att_hash.hex(),
        "registeredAt": registered_at, "approved": reg.functions.approvedImages(digest).call(),
        "modulus": "0x" + reg.functions.googleKeys(kid).call().hex(), "txHash": e["transactionHash"].hex(),
    }

audits, code_hashes = [], {}
for e in reg.events.AuditSubmitted().get_logs(from_block=start, to_block=latest):
    r = e["args"]["record"]
    record = {k: ("0x" + v.hex() if isinstance(v, bytes) else v) for k, v in dict(r).items()}
    record["grade"] = r["grade"].decode()
    audits.append({"key": "0x" + e["args"]["key"].hex(), "signer": e["args"]["signer"], "record": record, "report": json.loads(e["args"]["report"]),
                   "blockNumber": e["blockNumber"], "txHash": e["transactionHash"].hex()})
    k = f"{r['chainId']}:{r['contractAddress'].lower()}"
    rpc = os.environ.get(f"RPC_URL_{r['chainId']}") or (w.provider.endpoint_uri if r["chainId"] == w.eth.chain_id else None)
    if k not in code_hashes and rpc:
        code_hashes[k] = "0x" + Web3.keccak(Web3(Web3.HTTPProvider(rpc)).eth.get_code(r["contractAddress"])).hex()

snapshot = {
    "takenAt": int(time.time() * 1000), "block": latest,
    "registry": {"address": reg.address, "chainId": w.eth.chain_id, "owner": reg.functions.owner().call(), "expectedAudience": reg.functions.expectedAudience().call()},
    "audits": audits, "signers": signers, "codeHashes": code_hashes,
}
payload = json.dumps(snapshot, separators=(",", ":")).replace("</", "<\\/")
page = (ROOT / "frontend" / "index.html").read_text()
marker = '<script id="snapshot" type="application/json"></script>'
assert marker in page
(ROOT / "frontend" / "snapshot.html").write_text(page.replace(marker, f'<script id="snapshot" type="application/json">{payload}</script>'))
print(f"frontend/snapshot.html: {len(audits)} audits, {len(signers)} signers, block {latest}")
