"""Verify an on-chain audit record the way a stranger would, given only the registry address.

  python cli/verify_audit.py --chain 11155111 --address 0x... [--credential credentials/x.json]

Checks: record exists; current EXTCODEHASH matches the audited codeHash (else the contract changed);
signer is attested; the signer's registration JWT re-verifies offline against the on-chain Google key
(signature + audience + image digest), and optionally the credential file matches the on-chain hashes.
"""

import argparse
import json
import os
import sys

from web3 import Web3

from common import check_report_hash, env, google_keys, jwt_header, registry, verify_jwt, w3

ap = argparse.ArgumentParser()
ap.add_argument("--chain", type=int, required=True)
ap.add_argument("--address", required=True)
ap.add_argument("--credential")
a = ap.parse_args()

w = w3()
reg = registry(w)
ok = True

try:
    record, signer, submitted_at = reg.functions.latestAudit(a.chain, Web3.to_checksum_address(a.address)).call()
except Exception:
    sys.exit("no audit on chain for this (chain, address)")
chain_id, addr, code_hash, block, deps_hash, grade, score, config_hash, report_hash, issued_at = record
print(f"record: grade {grade.decode()} score {score} block {block} issuedAt {issued_at} signer {signer}")
print(f"        codeHash 0x{code_hash.hex()}\n        configHash 0x{config_hash.hex()}\n        reportHash 0x{report_hash.hex()}")

# 1. Does the audited code still run at that address?
target_rpc = os.environ.get(f"RPC_URL_{a.chain}") or env("SEPOLIA_RPC_URL")
current = Web3(Web3.HTTPProvider(target_rpc)).eth.get_code(Web3.to_checksum_address(a.address))
current_hash = Web3.keccak(current)
if current_hash == code_hash:
    print("code:   current EXTCODEHASH matches the audited codeHash")
else:
    ok = False
    print(f"code:   WARNING current EXTCODEHASH 0x{current_hash.hex()} differs from the audited codeHash: the contract was upgraded or replaced since the audit")

# 2. Is the signer attested, and does its attestation still verify offline?
if not reg.functions.isAttestedSigner(signer).call():
    ok = False
    print("signer: NOT attested")
else:
    image_digest, att_hash, registered_at = reg.functions.signers(signer).call()
    logs = reg.events.SignerRegistered().get_logs(from_block=int(env("REGISTRY_DEPLOY_BLOCK")), argument_filters={"signer": signer})
    token = logs[-1]["args"]["jwt"]
    assert Web3.keccak(text=token) == att_hash, "event JWT does not match stored attestationHash"
    kid = jwt_header(token)["kid"]
    modulus = reg.functions.googleKeys(kid).call() or google_keys().get(kid)
    if not modulus:
        ok = False
        print(f"signer: attested for image sha256:{image_digest.hex()}, but kid {kid} is no longer available anywhere to re-verify")
    else:
        payload = verify_jwt(token, modulus, reg.functions.expectedAudience().call(), check_exp=False)
        assert payload["submods"]["container"]["image_digest"] == "sha256:" + image_digest.hex()
        print(f"signer: attested; JWT re-verified offline (kid {kid}, image sha256:{image_digest.hex()}, "
              f"hwmodel {payload.get('hwmodel')}, dbgstat {payload.get('dbgstat')}, token exp {payload['exp']}, registered {registered_at})")
        if kid.startswith("mock"):
            print("        NOTE: mock dev key, not Google: this registration is a MOCK_TEE development artefact")

# 3. Optional: the credential file reproduces the on-chain hashes.
if a.credential:
    cred = json.load(open(a.credential))
    check_report_hash(cred)
    m = cred["proof"]["eip712"]["message"]
    if m["reportHash"] == "0x" + report_hash.hex() and m["configHash"] == "0x" + config_hash.hex():
        print("report: credential file matches on-chain reportHash and configHash")
    else:
        ok = False
        print("report: credential file does NOT match the on-chain record")

print("RESULT:", "VALID" if ok else "CHECK WARNINGS ABOVE")
