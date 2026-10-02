"""Register the auditor TEE's signer on chain using its attestation JWT.

  python cli/register_signer.py [--credential credentials/x.json]   (default: GET /attestation from the auditor)

Verifies the token offline against the on-chain key for its kid before spending gas. Tokens live about an
hour, so run this right after the auditor boots.
"""

import argparse
import json

import httpx

from common import AUDITOR_URL, jwt_header, registry, send, verify_jwt, w3

ap = argparse.ArgumentParser()
ap.add_argument("--credential")
a = ap.parse_args()

if a.credential:
    cred = json.load(open(a.credential))
    token, signer = cred["proof"]["attestation"], cred["issuer"].split(":")[-1]
else:
    att = httpx.get(f"{AUDITOR_URL}/attestation", timeout=30).json()
    token, signer = att["jwt"], att["signer"]

w = w3()
reg = registry(w)
if reg.functions.isAttestedSigner(signer).call():
    raise SystemExit(f"{signer} is already registered")

kid = jwt_header(token)["kid"]
modulus = reg.functions.googleKeys(kid).call()
if not modulus:
    raise SystemExit(f"kid {kid} is not in the registry's googleKeys; run cli/jwks_keeper.py (or deploy with the dev key for MOCK_TEE)")
payload = verify_jwt(token, modulus, reg.functions.expectedAudience().call())
nonce = payload["eat_nonce"][0] if isinstance(payload["eat_nonce"], list) else payload["eat_nonce"]
assert nonce.lower() == signer.lower(), "token nonce does not match signer"
digest = payload["submods"]["container"]["image_digest"]
print(f"token ok offline: signer {signer}, image {digest}, exp {payload['exp']}")
if not reg.functions.approvedImages(bytes.fromhex(digest.split(':')[1])).call():
    raise SystemExit("image digest is not approved in the registry")

send(w, reg.functions.registerSigner(token), "registerSigner")
print("isAttestedSigner:", reg.functions.isAttestedSigner(signer).call())
