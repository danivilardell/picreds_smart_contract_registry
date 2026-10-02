"""πCred auditor service: POST /audit issues a signed audit credential, GET /attestation serves the TEE's
attestation token (fresh), GET /config serves the pipeline configuration τ behind configHash.

Env: REGISTRY_CHAIN_ID, REGISTRY_ADDRESS (audience binding), MOCK_TEE=1 for local development. API keys come from
the environment locally and from Secret Manager on GCP: Confidential Space copies launch-time env vars into the
attestation token, which this registry publishes on chain, so secrets must never travel as env there.
RPC endpoints live in config.RPC_URLS (part of τ).
"""

import base64
import os
import threading
import time

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from auditor import analyze, config as cfg, credential as cred
from auditor.fetch import FetchError, Fetcher

load_dotenv()

GCP_METADATA = "http://metadata.google.internal/computeMetadata/v1"
SECRETS = {"ANTHROPIC_API_KEY": "picreds-anthropic-api-key", "ETHERSCAN_API_KEY": "picreds-etherscan-api-key"}


def gcp_secret(name: str) -> str | None:
    """Latest version of a Secret Manager secret, via the VM's service account. None when not running on GCP."""
    try:
        with httpx.Client(timeout=5, headers={"Metadata-Flavor": "Google"}) as c:
            project = c.get(f"{GCP_METADATA}/project/project-id").text
            token = c.get(f"{GCP_METADATA}/instance/service-accounts/default/token").json()["access_token"]
            r = c.get(f"https://secretmanager.googleapis.com/v1/projects/{project}/secrets/{name}/versions/latest:access",
                      headers={"Authorization": f"Bearer {token}", "Metadata-Flavor": ""})
            r.raise_for_status()
            return base64.b64decode(r.json()["payload"]["data"]).decode()
    except (httpx.HTTPError, KeyError):
        return None


for _env, _secret in SECRETS.items():
    if not os.environ.get(_env) and (_v := gcp_secret(_secret)):
        os.environ[_env] = _v
if not os.environ.get("ANTHROPIC_API_KEY"):
    raise SystemExit("ANTHROPIC_API_KEY is not set and could not be read from Secret Manager")

app = FastAPI(title="picreds-auditor", version=cfg.AUDITOR_VERSION)

REGISTRY_CHAIN_ID = int(os.environ["REGISTRY_CHAIN_ID"])
REGISTRY_ADDRESS = os.environ["REGISTRY_ADDRESS"]
AUDIENCE = cred.audience(REGISTRY_CHAIN_ID, REGISTRY_ADDRESS)
SIGNER = cred.Signer()  # fresh key per boot; its address is the eat_nonce of the attestation
_attestation: dict = {}
_lock = threading.Lock()


def attestation() -> str:
    """Current attestation token, re-requested when within 5 minutes of expiry (tokens live ~1 hour)."""
    with _lock:
        if not _attestation or _attestation["exp"] - time.time() < 300:
            token = cred.request_attestation(AUDIENCE, SIGNER.address.lower())
            _attestation.update(jwt=token, exp=cred.jwt_payload(token)["exp"])
        return _attestation["jwt"]


class AuditRequest(BaseModel):
    chainId: int
    address: str
    blockNumber: int | None = None


@app.get("/attestation")
def get_attestation():
    return {"signer": SIGNER.address, "audience": AUDIENCE, "jwt": attestation(), "mock": os.environ.get("MOCK_TEE") == "1"}


@app.get("/config")
def get_config():
    return {"configHash": cfg.config_hash(), "config": cfg.config()}


@app.post("/audit")
def post_audit(req: AuditRequest):
    rpc_url = cfg.RPC_URLS.get(str(req.chainId))
    if not rpc_url:
        raise HTTPException(400, f"no RPC configured for chain {req.chainId}")
    fetcher = Fetcher(req.chainId, rpc_url, os.environ.get("ETHERSCAN_API_KEY"), cfg.BUDGETS["maxContracts"], cfg.BUDGETS["maxDepth"])
    try:
        fetcher.pin_block(req.blockNumber)
        primary = fetcher.fetch_contract(req.address, role="primary")
        if primary.proxy and primary.proxy.get("implementation"):
            fetcher.fetch_contract(primary.proxy["implementation"], discovered_in=primary.address, role="implementation")
        token = attestation()  # before the long analysis, so the token is fresh relative to the key
        audit, scae, pipeline = analyze.analyze(fetcher, primary)
    except FetchError as e:
        raise HTTPException(422, str(e))
    except analyze.AuditFailed as e:
        raise HTTPException(502, str(e))
    return cred.build_credential(
        signer=SIGNER,
        registry_chain_id=REGISTRY_CHAIN_ID,
        registry=REGISTRY_ADDRESS,
        attestation=token,
        subject=primary.summary(),  # subject tuple plus name, matchType, proxy info for display
        dependencies=fetcher.dependencies(),
        not_fetched=fetcher.not_fetched,
        audit=audit,
        scae_check=scae,
        pipeline=pipeline,
        provenance=fetcher.provenance,
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8080")))
