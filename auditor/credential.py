"""Credential assembly: Confidential Space attestation (real or mock), EIP-712 signing, W3C VC JSON.

The attestation token is requested from the Confidential Space launcher over its Unix socket with
`aud` = the registry audience and `eat_nonce` = the signer's Ethereum address. With MOCK_TEE=1 a
structurally identical token is signed with a local dev RSA key instead (clearly labelled in the VC).
"""

import base64
import hashlib
import json
import os
import time
from pathlib import Path

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from eth_abi import encode as abi_encode
from eth_account import Account
from eth_utils import keccak

TEE_SOCKET = "/run/container_launcher/teeserver.sock"
TEE_TOKEN_URL = "http://localhost/v1/token"
MOCK_KID = "mock-dev-rsa"
MOCK_IMAGE_DIGEST = "sha256:" + hashlib.sha256(b"picreds-mock-auditor-image").hexdigest()
MOCK_KEY_PATH = Path(os.environ.get("MOCK_RSA_KEY_PATH", Path(__file__).with_name("dev_rsa_key.pem")))

# Must match AuditRegistry.RECORD_TYPEHASH field for field.
EIP712_TYPES = {
    "AuditRecord": [
        {"name": "chainId", "type": "uint256"},
        {"name": "contractAddress", "type": "address"},
        {"name": "codeHash", "type": "bytes32"},
        {"name": "blockNumber", "type": "uint256"},
        {"name": "dependenciesHash", "type": "bytes32"},
        {"name": "grade", "type": "bytes1"},
        {"name": "score", "type": "uint8"},
        {"name": "configHash", "type": "bytes32"},
        {"name": "reportHash", "type": "bytes32"},
        {"name": "issuedAt", "type": "uint64"},
    ]
}


def audience(chain_id: int, registry: str) -> str:
    return f"picreds-audit-registry:{chain_id}:{registry.lower()}"


def domain(chain_id: int, registry: str) -> dict:
    return {"name": "AuditRegistry", "version": "1", "chainId": chain_id, "verifyingContract": registry}


def canonical(obj) -> bytes:
    """Canonical JSON: sorted keys, no whitespace, UTF-8. reportHash = keccak256(canonical(credentialSubject))."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def jwt_payload(token: str) -> dict:
    """Decode (without verifying) a JWT payload."""
    return json.loads(b64url_decode(token.split(".")[1]))


def dependencies_hash(dependencies: list[dict]) -> bytes:
    """keccak256(abi.encode(Subject[])) with Subject = (uint256 chainId, address addr, bytes32 codeHash, uint256 blockNumber)."""
    tuples = [(d["chainId"], d["address"], bytes.fromhex(d["codeHash"][2:]), d["blockNumber"]) for d in dependencies]
    return keccak(abi_encode(["(uint256,address,bytes32,uint256)[]"], [tuples]))


class Signer:
    """secp256k1 signing key generated at startup; its address is the TEE's identity on chain."""

    def __init__(self, private_key: str | None = None):
        self.account = Account.from_key(private_key) if private_key else Account.create()

    @property
    def address(self) -> str:
        return self.account.address

    def sign_record(self, domain_: dict, record: dict) -> str:
        signed = Account.sign_typed_data(self.account.key, domain_, EIP712_TYPES, record)
        return "0x" + signed.signature.hex()


# ------------------------------------------------------------------ attestation


def request_attestation(aud: str, nonce: str) -> str:
    if os.environ.get("MOCK_TEE") == "1":
        return mock_attestation(aud, nonce)
    with httpx.Client(transport=httpx.HTTPTransport(uds=TEE_SOCKET)) as client:
        r = client.post(TEE_TOKEN_URL, json={"audience": aud, "token_type": "OIDC", "nonces": [nonce]})
        r.raise_for_status()
        return r.text.strip()


def mock_key() -> rsa.RSAPrivateKey:
    """Dev RSA key for MOCK_TEE, persisted so the server and the test fixtures agree."""
    if MOCK_KEY_PATH.exists():
        return serialization.load_pem_private_key(MOCK_KEY_PATH.read_bytes(), password=None)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    MOCK_KEY_PATH.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    return key


def mock_modulus() -> bytes:
    return mock_key().public_key().public_numbers().n.to_bytes(256, "big")


def mock_payload(aud: str, nonce: str, now: int | None = None) -> dict:
    """Payload mirroring a real Confidential Space OIDC token (claims and order per Google's reference)."""
    now = now or int(time.time())
    return {
        "aud": aud,
        "exp": now + 3600,
        "iat": now,
        "iss": "https://confidentialcomputing.googleapis.com",
        "nbf": now,
        "sub": "https://www.googleapis.com/compute/v1/projects/picreds-mock/zones/us-central1-a/instances/auditor",
        "eat_nonce": [nonce],
        "eat_profile": "https://cloud.google.com/confidential-computing/confidential-space/docs/reference/token-claims",
        "secboot": True,
        "oemid": 11129,
        "hwmodel": "GCP_INTEL_TDX",
        "swname": "CONFIDENTIAL_SPACE",
        "swversion": ["260900"],
        "dbgstat": "disabled-since-boot",
        "submods": {
            "confidential_space": {"support_attributes": ["LATEST", "STABLE", "USABLE"]},
            "container": {
                "image_reference": "us-docker.pkg.dev/picreds-mock/auditor/auditor:dev",
                "image_digest": MOCK_IMAGE_DIGEST,
                "restart_policy": "Never",
                "image_id": "sha256:" + hashlib.sha256(b"picreds-mock-image-id").hexdigest(),
                "env": {"MOCK_TEE": "1"},
                "args": ["python", "-m", "auditor.main"],
            },
            "gce": {
                "zone": "us-central1-a",
                "project_id": "picreds-mock",
                "project_number": "0",
                "instance_name": "auditor",
                "instance_id": "0",
            },
        },
        "google_service_accounts": ["auditor@picreds-mock.iam.gserviceaccount.com"],
    }


def sign_jwt(header: dict, payload: dict, key: rsa.RSAPrivateKey) -> str:
    signing_input = b64url(canonical_compact(header)) + "." + b64url(canonical_compact(payload))
    sig = key.sign(signing_input.encode(), padding.PKCS1v15(), hashes.SHA256())
    return signing_input + "." + b64url(sig)


def canonical_compact(obj) -> bytes:
    """Compact JSON preserving insertion order (what Go's encoding/json emits)."""
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode()


def mock_attestation(aud: str, nonce: str) -> str:
    return sign_jwt({"alg": "RS256", "kid": MOCK_KID, "typ": "JWT"}, mock_payload(aud, nonce), mock_key())


# ------------------------------------------------------------------ credential


def build_credential(
    *,
    signer: Signer,
    registry_chain_id: int,
    registry: str,
    attestation: str,
    subject: dict,
    dependencies: list[dict],
    not_fetched: list[dict],
    audit: dict,
    scae_check: dict,
    pipeline: dict,
    provenance: dict,
) -> dict:
    """Assemble a W3C VC v2.0 whose proof is an EIP-712 signature over the on-chain AuditRecord."""
    issued_at = int(time.time())
    credential_subject = {
        "id": f"eip155:{subject['chainId']}:{subject['address']}",
        "subject": subject,
        "dependencies": dependencies,
        "notFetched": not_fetched,
        "audit": audit,
        "scaeCheck": scae_check,
        "pipeline": pipeline,
        "provenance": provenance,
    }
    report_hash = keccak(canonical(credential_subject))
    deps_hash = dependencies_hash(dependencies)
    record = {
        "chainId": subject["chainId"],
        "contractAddress": subject["address"],
        "codeHash": bytes.fromhex(subject["codeHash"][2:]),
        "blockNumber": subject["blockNumber"],
        "dependenciesHash": deps_hash,
        "grade": audit["grade"].encode(),
        "score": audit["score"],
        "configHash": bytes.fromhex(pipeline["configHash"][2:]),
        "reportHash": report_hash,
        "issuedAt": issued_at,
    }
    domain_ = domain(registry_chain_id, registry)
    signature = signer.sign_record(domain_, record)
    message = {k: ("0x" + v.hex() if isinstance(v, bytes) else v) for k, v in record.items()}
    return {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiableCredential", "SmartContractAuditCredential"],
        "issuer": f"did:pkh:eip155:{registry_chain_id}:{signer.address}",
        "validFrom": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(issued_at)),
        "credentialSubject": credential_subject,
        "proof": {
            "type": "EthereumEip712Signature2021",
            "verificationMethod": f"did:pkh:eip155:{registry_chain_id}:{signer.address}",
            "eip712": {"domain": domain_, "primaryType": "AuditRecord", "types": EIP712_TYPES, "message": message},
            "proofValue": signature,
            "attestation": attestation,
            "mock": os.environ.get("MOCK_TEE") == "1",
        },
    }
