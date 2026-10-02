"""Shared helpers for the CLI: env, web3 contract handle, transaction sending, offline JWT verification."""

import base64
import json
import os
import sys
from pathlib import Path

import httpx
import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric import rsa
from dotenv import load_dotenv
from eth_account import Account
from eth_utils import keccak
from web3 import Web3

ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / ".env")
ABI = json.load(open(ROOT / "contracts/out/AuditRegistry.sol/AuditRegistry.json"))["abi"]
GOOGLE_JWKS = "https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com"
AUDITOR_URL = os.environ.get("AUDITOR_URL", "http://127.0.0.1:8080")


def env(name: str) -> str:
    v = os.environ.get(name)
    if not v:
        sys.exit(f"missing env {name} (see .env.example)")
    return v


def w3(url: str | None = None) -> Web3:
    return Web3(Web3.HTTPProvider(url or env("SEPOLIA_RPC_URL"), request_kwargs={"timeout": 60}))


def registry(w: Web3):
    return w.eth.contract(address=Web3.to_checksum_address(env("REGISTRY_ADDRESS")), abi=ABI)


def send(w: Web3, fn, label: str) -> dict:
    """Sign with DEPLOYER_PRIVATE_KEY, send, wait, and print the receipt summary."""
    acct = Account.from_key(env("DEPLOYER_PRIVATE_KEY"))
    tx = fn.build_transaction({"from": acct.address, "nonce": w.eth.get_transaction_count(acct.address)})
    signed = acct.sign_transaction(tx)
    h = w.eth.send_raw_transaction(signed.raw_transaction)
    print(f"{label}: tx {h.hex()} ...", flush=True)
    r = w.eth.wait_for_transaction_receipt(h, timeout=300)
    print(f"{label}: {'ok' if r.status == 1 else 'REVERTED'} in block {r.blockNumber}, gas used {r.gasUsed}")
    return r


def jwt_header(token: str) -> dict:
    h = token.split(".")[0]
    return json.loads(base64.urlsafe_b64decode(h + "=" * (-len(h) % 4)))


def verify_jwt(token: str, modulus: bytes, audience: str | None, check_exp: bool = True) -> dict:
    """Verify an RS256 JWT against a raw 2048-bit modulus (e = 65537). Returns the payload."""
    pub = rsa.RSAPublicNumbers(65537, int.from_bytes(modulus, "big")).public_key()
    return pyjwt.decode(
        token, pub, algorithms=["RS256"], audience=audience,
        options={"verify_exp": check_exp, "verify_aud": audience is not None, "verify_iat": False},
    )


def google_keys() -> dict[str, bytes]:
    """kid -> modulus for Google's current Confidential Space signing keys."""
    keys = httpx.get(GOOGLE_JWKS, timeout=30).json()["keys"]
    return {k["kid"]: base64.urlsafe_b64decode(k["n"] + "=" * (-len(k["n"]) % 4)) for k in keys if k["alg"] == "RS256"}


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def record_tuple(credential: dict) -> tuple:
    """The AuditRecord struct, in ABI order, from the credential's EIP-712 message."""
    m = credential["proof"]["eip712"]["message"]
    b32 = lambda h: bytes.fromhex(h[2:])
    return (
        m["chainId"], Web3.to_checksum_address(m["contractAddress"]), b32(m["codeHash"]), m["blockNumber"],
        b32(m["dependenciesHash"]), b32(m["grade"]), m["score"], b32(m["configHash"]), b32(m["reportHash"]), m["issuedAt"],
    )


def check_report_hash(credential: dict) -> bytes:
    report = canonical(credential["credentialSubject"])
    h = keccak(report)
    if "0x" + h.hex() != credential["proof"]["eip712"]["message"]["reportHash"]:
        sys.exit("reportHash does not match credentialSubject")
    return report
