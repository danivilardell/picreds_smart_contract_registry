# πCred auditor image for Google Confidential Space.
#
# Reproducibility: the registry approves this image by digest, so anyone must be able to rebuild the digest from
# this source. Everything that goes into the image is pinned: the base image by digest, Python dependencies by
# exact version (add `--require-hashes` with a pip-compile'd lock for full pinning), and the source tree copied
# verbatim. Build with BuildKit and a fixed SOURCE_DATE_EPOCH so layer timestamps are deterministic:
#   DOCKER_BUILDKIT=1 SOURCE_DATE_EPOCH=0 docker build --no-cache --platform linux/amd64 \
#       -f auditor/Dockerfile -t REGION-docker.pkg.dev/PROJECT/picreds/auditor:0.1.0 .
#   docker push ...   # the pushed digest is what `setImageApproval` / IMAGE_DIGESTS takes
# Then compare the digest against the one in the registry (`approvedImages`) before trusting a signer.
#
# Launch policy: no command override; only the registry binding may be set by the operator. RPC endpoints and the
# model/prompt live in auditor/config.py (τ), so the operator cannot redirect data fetching or inference. API keys
# are read from Secret Manager at boot, never passed as env: Confidential Space copies env vars into the
# attestation token, and this registry publishes that token on chain.
FROM python:3.12-slim@sha256:dddfd7e07f9d15aeeca61529320492139d21cac7f0070c00609243e51e4e0016

LABEL "tee.launch_policy.allow_cmd_override"="false"
LABEL "tee.launch_policy.allow_env_override"="REGISTRY_CHAIN_ID,REGISTRY_ADDRESS"
LABEL "tee.launch_policy.log_redirect"="always"

WORKDIR /app
COPY auditor/requirements.txt /app/auditor/requirements.txt
RUN pip install --no-cache-dir --no-compile -r /app/auditor/requirements.txt
COPY auditor /app/auditor

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PORT=8080
EXPOSE 8080
ENTRYPOINT ["python", "-m", "auditor.main"]
