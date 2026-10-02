"""LLM analysis: two passes (source intact, source stripped of comments and string literals), an append-only
tool loop against the Fetcher, structured JSON output, and deterministic rubric enforcement.

Every HTTP request and response body exchanged with the Anthropic API is hashed (sha256) and recorded, so the
part of the pipeline that runs outside the TEE is at least auditable.
"""

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile

import anthropic
from anthropic import Anthropic, DefaultHttpxClient

from auditor import config as cfg
from auditor.fetch import Contract, FetchError, Fetcher

GRADES = "ABCDF"


class AuditFailed(Exception):
    pass


# ------------------------------------------------------------------ source handling

_TOKEN_RE = re.compile(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'|unicode"(?:\\.|[^"\\\n])*"', re.S)


def strip_source(text: str) -> str:
    """Remove comments and blank out string literal contents, respecting string boundaries."""

    def repl(m: re.Match) -> str:
        tok = m.group(0)
        if tok.startswith("//"):
            return ""
        if tok.startswith("/*"):
            return "\n" * tok.count("\n")  # keep line numbers stable
        return tok[0] + tok[-1] if not tok.startswith("unicode") else 'unicode""'

    return _TOKEN_RE.sub(repl, text)


def render_contract(c: Contract, stripped: bool, max_chars: int) -> str:
    header = f"{cfg.DATA_OPEN} address={c.address} role={c.role} codeHash={c.code_hash}"
    if c.source:
        header += f" name={c.source.name} compiler={c.source.compiler} source={c.source.provider}:{c.source.match}"
    if c.proxy:
        header += f" proxy={json.dumps(c.proxy, separators=(',', ':'))}"
    header += ">>>\n"
    if not c.source:
        body = f"SOURCE NOT VERIFIED. Runtime bytecode ({(len(c.code) - 2) // 2} bytes):\n{c.code}\n"
    else:
        parts, used = [], 0
        for path, text in c.source.files.items():
            text = strip_source(text) if stripped else text
            if used + len(text) > max_chars:
                parts.append(f"--- file: {path} --- [omitted: source budget of {max_chars} chars exceeded]\n")
                continue
            used += len(text)
            parts.append(f"--- file: {path} ---\n{text}\n")
        body = "".join(parts)
    return header + body + cfg.DATA_CLOSE + "\n"


# ------------------------------------------------------------------ Anthropic client with body hashing


class HashingClient:
    """Anthropic client whose underlying HTTP hooks record sha256 of every request/response body."""

    def __init__(self):
        self.log: list[dict] = []
        self._pending: dict = {}
        http = DefaultHttpxClient(event_hooks={"request": [self._on_request], "response": [self._on_response]})
        self.client = Anthropic(http_client=http)

    def _on_request(self, request):
        self._pending = {"requestSha256": hashlib.sha256(request.content).hexdigest()}

    def _on_response(self, response):
        response.read()
        self._pending["responseSha256"] = hashlib.sha256(response.content).hexdigest()
        self._pending["status"] = response.status_code

    def create(self, **params) -> anthropic.types.Message:
        msg = self.client.messages.create(**params)
        self.log.append({**self._pending, "model": msg.model, "stopReason": msg.stop_reason,
                         "usage": {"input": msg.usage.input_tokens, "output": msg.usage.output_tokens}})
        return msg


# ------------------------------------------------------------------ the tool loop


class Analyzer:
    def __init__(self, fetcher: Fetcher, client: HashingClient | None = None):
        self.fetcher = fetcher
        self.client = client or HashingClient()
        self.tool_calls = 0
        self.max_chars = cfg.BUDGETS["maxSourceCharsPerContract"]

    def run_pass(self, primary: Contract, stripped: bool) -> dict:
        contracts = list(self.fetcher.contracts.values())
        intro = (
            f"Audit the primary contract {primary.address} on chain {primary.chain_id} at block {primary.block_number}. "
            f"{len(contracts)} contract(s) are provided below ({'comments and string literals stripped' if stripped else 'source intact'}). "
            f"Candidate dependencies found programmatically (not fetched yet): {json.dumps(self.fetcher.candidates(primary))}.\n\n"
        )
        messages = [{"role": "user", "content": intro + "".join(render_contract(c, stripped, self.max_chars) for c in contracts)}]
        start = len(self.client.log)
        while True:
            msg = self.client.create(
                model=cfg.MODEL,
                max_tokens=16000,
                system=[{"type": "text", "text": cfg.SYSTEM_PROMPT, "cache_control": {"type": "ephemeral"}}],
                tools=cfg.TOOLS,
                output_config={"effort": cfg.EFFORT, "format": {"type": "json_schema", "schema": cfg.OUTPUT_SCHEMA}},
                messages=messages,
            )
            if msg.stop_reason == "refusal":
                raise AuditFailed(f"model refused: {msg.stop_details}")
            if msg.stop_reason == "max_tokens":
                raise AuditFailed("model hit max_tokens before finishing")
            messages.append({"role": "assistant", "content": msg.content})
            uses = [b for b in msg.content if b.type == "tool_use"]
            if not uses:
                break
            messages.append({"role": "user", "content": [self._run_tool(b, stripped) for b in uses]})
        text = next(b.text for b in msg.content if b.type == "text")
        audit = json.loads(text)
        audit["_turns"] = [{"pass": "stripped" if stripped else "intact", "turn": i, **e} for i, e in enumerate(self.client.log[start:])]
        return audit

    def _run_tool(self, block, stripped: bool) -> dict:
        self.tool_calls += 1
        if self.tool_calls > cfg.BUDGETS["maxToolCalls"]:
            return self._result(block, "Tool budget exhausted. Write the final audit now with what you have.", error=True)
        args = block.input
        try:
            if block.name == "fetch_contract":
                c = self.fetcher.fetch_contract(args["address"], discovered_in=args["discovered_in"], role=args["role"])
                return self._result(block, render_contract(c, stripped, self.max_chars))
            if block.name == "eth_call":
                return self._result(block, self.fetcher.tool_eth_call(args["address"], args["calldata"]))
            if block.name == "read_storage":
                return self._result(block, self.fetcher.tool_read_storage(args["address"], args["slot"]))
            if block.name == "run_slither":
                return self._result(block, run_slither(self.fetcher.contracts.get(args["address"])))
            return self._result(block, f"unknown tool {block.name}", error=True)
        except (FetchError, KeyError, ValueError) as e:
            return self._result(block, str(e), error=True)

    @staticmethod
    def _result(block, content: str, error: bool = False) -> dict:
        return {"type": "tool_result", "tool_use_id": block.id, "content": content, "is_error": error}


def run_slither(c: Contract | None) -> str:
    if c is None or not c.source:
        return "contract not fetched or source not verified"
    if not shutil.which("slither"):
        return "slither not installed in this image"
    with tempfile.TemporaryDirectory() as d:
        for path, text in c.source.files.items():
            p = os.path.join(d, path.lstrip("/"))
            os.makedirs(os.path.dirname(p), exist_ok=True)
            open(p, "w").write(text)
        r = subprocess.run(["slither", ".", "--json", "-"], cwd=d, capture_output=True, text=True, timeout=600)
    try:
        dets = json.loads(r.stdout)["results"]["detectors"]
        return cfg.DATA_OPEN + " tool=slither>>>\n" + json.dumps(
            [{"check": x["check"], "impact": x["impact"], "description": x["description"]} for x in dets], indent=1
        ) + "\n" + cfg.DATA_CLOSE
    except (json.JSONDecodeError, KeyError):
        return f"slither failed: {r.stderr[-2000:]}"


# ------------------------------------------------------------------ rubric and orchestration


def apply_rubric(audit: dict, fetcher: Fetcher, primary: Contract) -> dict:
    """Deterministic caps on the model's grade; the score is clamped into the final grade's band."""
    severities = {f["severity"] for f in audit["findings"]}
    cap = "A"
    if "critical" in severities:
        cap = cfg.RUBRIC["anyCritical"]
    elif "high" in severities:
        cap = cfg.RUBRIC["anyHigh"]
    impl = fetcher.contracts.get((primary.proxy or {}).get("implementation") or "")
    if primary.source is None or (primary.proxy and (impl is None or impl.source is None)):
        cap = worse(cap, cfg.RUBRIC["unverifiedPrimarySource"])
    if (audit["upgradeability"]["upgradeable"] or primary.proxy) and not audit["upgradeability"]["timelock"]:
        cap = worse(cap, cfg.RUBRIC["upgradeableWithoutTimelock"])
    audit["grade"] = worse(audit["grade"], cap)
    lo, hi = cfg.RUBRIC["scoreBands"][audit["grade"]]
    audit["score"] = max(lo, min(hi, int(audit["score"])))
    return audit


def worse(a: str, b: str) -> str:
    return a if GRADES.index(a) >= GRADES.index(b) else b


def analyze(fetcher: Fetcher, primary: Contract, client: HashingClient | None = None) -> tuple[dict, dict, dict]:
    """Run both passes, merge, and return (audit, scaeCheck, pipeline)."""
    an = Analyzer(fetcher, client)
    intact = apply_rubric(an.run_pass(primary, stripped=False), fetcher, primary)
    stripped = apply_rubric(an.run_pass(primary, stripped=True), fetcher, primary)
    disagreement = intact["grade"] != stripped["grade"]
    final = dict(stripped if worse(stripped["grade"], intact["grade"]) == stripped["grade"] and disagreement else intact)
    if disagreement:
        final["findings"] = final["findings"] + [{
            "severity": "medium",
            "title": "Possible auditor manipulation",
            "description": f"The audit graded {intact['grade']} with comments and strings intact but {stripped['grade']} with them stripped. "
            "Non-code text in the source materially changed the model's judgment; the worse grade is reported.",
            "location": "source comments / string literals",
            "recommendation": "Review comments, NatSpec and string literals for misleading or instruction-like content.",
        }]
    final["scope"] = {
        "analyzed": [c.address for c in fetcher.contracts.values()],
        "skipped": fetcher.not_fetched,
        "sourceVerified": {c.address: c.source is not None for c in fetcher.contracts.values()},
    }
    turns = intact.pop("_turns") + stripped.pop("_turns")
    final.pop("_turns", None)
    scae = {"gradeIntact": intact["grade"], "gradeStripped": stripped["grade"], "disagreement": disagreement}
    pipeline = {"configHash": cfg.config_hash(), "auditorVersion": cfg.AUDITOR_VERSION, "model": cfg.MODEL, "requests": turns}
    return final, scae, pipeline
