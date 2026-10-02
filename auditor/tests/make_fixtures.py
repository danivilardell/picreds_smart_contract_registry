"""Generate contracts/test/fixtures/fixtures.json: dev RSA key, Confidential-Space-shaped JWTs (valid and
adversarial variants), and an EIP-712-signed AuditRecord, so the Foundry tests exercise real tokens.

Run from the repo root:  MOCK_TEE=1 .venv/bin/python -m auditor.tests.make_fixtures
"""

import hashlib
import json
import sys
import time
from pathlib import Path

import rlp
from eth_account import Account
from eth_utils import keccak, to_checksum_address

from auditor import credential as cred

OUT = Path(__file__).resolve().parents[2] / "contracts" / "test" / "fixtures" / "fixtures.json"
DEPLOYER = "0x1111111111111111111111111111111111111111"  # test deploys the registry from this address, nonce 0
REGISTRY_CHAIN_ID = 31337  # Foundry default


def create_address(deployer: str, nonce: int) -> str:
    return to_checksum_address(keccak(rlp.encode([bytes.fromhex(deployer[2:]), nonce]))[12:])


def main() -> None:
    now = int(time.time())
    key = cred.mock_key()
    header = {"alg": "RS256", "kid": cred.MOCK_KID, "typ": "JWT"}
    registry = create_address(DEPLOYER, 0)
    aud = cred.audience(REGISTRY_CHAIN_ID, registry)
    signer = Account.from_key(keccak(b"picreds-dev-signer"))
    nonce = signer.address.lower()

    def token(hdr=header, **overrides) -> str:
        payload = cred.mock_payload(aud, nonce, now)
        for k, v in overrides.items():
            if k == "image_digest":
                payload["submods"]["container"]["image_digest"] = v
            else:
                payload[k] = v
        return cred.sign_jwt(hdr, payload, key)

    valid = token()
    h, p, s = valid.split(".")
    tampered_payload = json.loads(cred.b64url_decode(p))
    tampered_payload["aud"] = aud + "x"
    tampered = h + "." + cred.b64url(cred.canonical_compact(tampered_payload)) + "." + s

    other_digest = "sha256:" + hashlib.sha256(b"some-other-image").hexdigest()
    approved_digest_claim = f'","submods":{{"container":{{"image_digest":"{cred.MOCK_IMAGE_DIGEST}"}}}},"x":"'
    tokens = {
        "valid": valid,
        "nonceString": token(eat_nonce=nonce),  # Google documents eat_nonce as string-or-array
        "tamperedPayload": tampered,
        "wrongKid": token(hdr={**header, "kid": "unknown-kid"}),
        "algNone": token(hdr={**header, "alg": "none"}),
        "expired": token(exp=now - 1),
        "wrongAud": token(aud="picreds-audit-registry:1:0x0000000000000000000000000000000000000001"),
        "nonceNotAddress": token(eat_nonce=["not-an-address-at-all"]),
        # An unapproved image tries to smuggle the approved digest through attacker-controlled claims.
        "nonceInjection": token(eat_nonce=[nonce + approved_digest_claim], image_digest=other_digest),
        "audInjection": token(aud=aud + approved_digest_claim, image_digest=other_digest),
        "unapprovedImage": token(image_digest=other_digest),
        "debugEnabled": token(dbgstat="enabled"),
    }

    record = {
        "chainId": 11155111,
        "contractAddress": "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238",
        "codeHash": keccak(b"code"),
        "blockNumber": 9_000_000,
        "dependenciesHash": cred.dependencies_hash([]),
        "grade": b"B",
        "score": 78,
        "configHash": keccak(b"config"),
        "reportHash": keccak(b"report"),
        "issuedAt": now,
    }
    sig = cred.Signer("0x" + signer.key.hex()).sign_record(cred.domain(REGISTRY_CHAIN_ID, registry), record)

    fixtures = {
        "kid": cred.MOCK_KID,
        "modulus": "0x" + cred.mock_modulus().hex(),
        "deployer": DEPLOYER,
        "registry": registry,
        "registryChainId": REGISTRY_CHAIN_ID,
        "audience": aud,
        "imageDigest": "0x" + cred.MOCK_IMAGE_DIGEST.split(":")[1],
        "signer": signer.address,
        "signerKey": "0x" + signer.key.hex(),
        "now": now,
        "tokens": tokens,
        "record": {k: ("0x" + v.hex() if isinstance(v, bytes) and k != "grade" else v) for k, v in record.items()}
        | {"grade": "B"},
        "recordSignature": sig,
    }
    OUT.write_text(json.dumps(fixtures, indent=2))
    print(f"wrote {OUT} ({len(valid)}-char token, signer {signer.address}, registry {registry})", file=sys.stderr)


if __name__ == "__main__":
    main()
