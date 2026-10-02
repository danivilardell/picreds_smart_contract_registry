"""The oracle step: whitelisted fetching of bytecode, verified source, proxy targets and dependency candidates.

Every outbound HTTP request is checked against a host whitelist (Sourcify, Etherscan, the configured RPC)
before it leaves the process. Anything else fails closed — this is the paper's wl_i / SSRF defence.
Everything fetched is recorded in `Fetcher.provenance` so the credential is explicit about its scope.
"""

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field

import httpx
from eth_utils import keccak, to_checksum_address

SOURCIFY = "https://sourcify.dev/server"
ETHERSCAN = "https://api.etherscan.io/v2/api"
SOURCE_WHITELIST = ["sourcify.dev", "api.etherscan.io"]  # part of the pipeline configuration τ

# Proxy storage slots (EIP-1967 and the legacy ZeppelinOS slot) and the EIP-1167 minimal-proxy pattern.
SLOT_IMPL = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
SLOT_BEACON = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"
SLOT_ADMIN = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
SLOT_ZOS_IMPL = "0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3"
EIP1167_RE = re.compile(r"^0x363d3d373d3d3d363d73([0-9a-f]{40})5af43d82803e903d91602b57fd5bf3$")
SEL_IMPLEMENTATION = "0x5c60da1b"  # implementation()
ADDRESS_RE = re.compile(r"0x[0-9a-fA-F]{40}")
ZERO = "0x" + "00" * 20


class FetchError(Exception):
    pass


@dataclass
class Source:
    provider: str  # "sourcify" | "etherscan"
    match: str  # "exact_match" | "match" | "etherscan"
    name: str
    compiler: str
    files: dict[str, str]
    url: str
    body_sha256: str
    implementations: list[str] = field(default_factory=list)  # proxy targets reported by the provider


@dataclass
class Contract:
    chain_id: int
    address: str
    block_number: int
    code_hash: str
    code: str
    role: str  # "primary" | "implementation" | "beacon" | "callee"
    depth: int
    discovered_in: str | None
    source: Source | None = None
    proxy: dict | None = None  # {"kind", "implementation", "admin"}

    def subject(self) -> dict:
        return {"chainId": self.chain_id, "address": self.address, "codeHash": self.code_hash, "blockNumber": self.block_number}

    def summary(self) -> dict:
        return {
            **self.subject(),
            "role": self.role,
            "sourceVerified": self.source is not None,
            "matchType": self.source.match if self.source else "none",
            "name": self.source.name if self.source else None,
            "proxy": self.proxy,
        }


class Rpc:
    def __init__(self, url: str, client: httpx.Client):
        self.url, self.client, self._id = url, client, 0

    def call(self, method: str, params: list):
        self._id += 1
        r = self.client.post(self.url, json={"jsonrpc": "2.0", "id": self._id, "method": method, "params": params})
        r.raise_for_status()
        body = r.json()
        if "error" in body:
            raise FetchError(f"rpc {method}: {body['error']}")
        return body["result"]

    def block_number(self) -> int:
        return int(self.call("eth_blockNumber", []), 16)

    def block_hash(self, block: int) -> str:
        return self.call("eth_getBlockByNumber", [hex(block), False])["hash"]

    def get_code(self, address: str, block: int) -> str:
        return self.call("eth_getCode", [address, hex(block)])

    def get_storage(self, address: str, slot: str, block: int) -> str:
        return self.call("eth_getStorageAt", [address, slot, hex(block)])

    def eth_call(self, address: str, data: str, block: int) -> str:
        return self.call("eth_call", [{"to": address, "data": data}, hex(block)])


def word_to_address(word: str) -> str | None:
    """A 32-byte storage word that looks like an address (12 zero bytes then 20 non-zero)."""
    w = word[2:].rjust(64, "0")
    if w[:24] == "0" * 24 and w[24:] != "0" * 40:
        return to_checksum_address("0x" + w[24:])
    return None


class Fetcher:
    def __init__(self, chain_id: int, rpc_url: str, etherscan_key: str | None, max_contracts: int = 8, max_depth: int = 2):
        self.chain_id, self.etherscan_key = chain_id, etherscan_key
        self.max_contracts, self.max_depth = max_contracts, max_depth
        self.allowed_hosts = set(SOURCE_WHITELIST) | {httpx.URL(rpc_url).host}
        self.client = httpx.Client(timeout=60, event_hooks={"request": [self._guard]})
        self.rpc = Rpc(rpc_url, self.client)
        self.block: int | None = None
        self.contracts: dict[str, Contract] = {}
        self.not_fetched: list[dict] = []
        self.provenance: dict = {"rpc": {"url": rpc_url}, "sources": {}, "toolCalls": []}

    def _guard(self, request: httpx.Request) -> None:
        if request.url.host not in self.allowed_hosts:
            raise FetchError(f"host not whitelisted: {request.url.host}")

    # ------------------------------------------------------------------ block pinning

    def pin_block(self, block_number: int | None) -> int:
        self.block = block_number if block_number is not None else self.rpc.block_number()
        self.provenance["rpc"].update(blockNumber=self.block, blockHash=self.rpc.block_hash(self.block))
        return self.block

    # ------------------------------------------------------------------ contracts

    def fetch_contract(self, address: str, discovered_in: str | None = None, role: str = "callee") -> Contract:
        """Fetch bytecode + verified source for `address` at the pinned block, within the budget."""
        address = to_checksum_address(address)
        if address in self.contracts:
            return self.contracts[address]
        depth = 0 if discovered_in is None else self.contracts[to_checksum_address(discovered_in)].depth + 1
        if depth > self.max_depth:
            return self._skip(address, "depth")
        if len(self.contracts) >= self.max_contracts:
            return self._skip(address, "budget")
        code = self.rpc.get_code(address, self.block)
        if code in ("0x", "0x0", ""):
            return self._skip(address, "no_code")

        c = Contract(self.chain_id, address, self.block, "0x" + keccak(hexstr=code).hex(), code, role, depth, discovered_in)
        c.source = self._fetch_source(address)
        c.proxy = self._resolve_proxy(c)
        self.contracts[address] = c
        return c

    def _skip(self, address: str, reason: str) -> None:
        entry = {"address": address, "reason": reason}
        if entry not in self.not_fetched:
            self.not_fetched.append(entry)
        raise FetchError(f"{address} not fetched: {reason}")

    def _fetch_source(self, address: str) -> Source | None:
        url = f"{SOURCIFY}/v2/contract/{self.chain_id}/{address}?fields=all"
        r = self.client.get(url)
        if r.status_code == 200 and r.json().get("match"):
            d = r.json()
            src = Source(
                provider="sourcify",
                match=d["match"],
                name=d["compilation"]["name"],
                compiler=d["compilation"]["compilerVersion"],
                files={path: f["content"] for path, f in d["sources"].items()},
                url=url,
                body_sha256=hashlib.sha256(r.content).hexdigest(),
                implementations=[i["address"] for i in (d.get("proxyResolution") or {}).get("implementations", [])],
            )
        elif self.etherscan_key:
            params = {"chainid": self.chain_id, "module": "contract", "action": "getsourcecode", "address": address, "apikey": self.etherscan_key}
            r = self.client.get(ETHERSCAN, params=params)
            r.raise_for_status()
            res = r.json()["result"][0]
            if not res.get("SourceCode"):
                return None
            url = str(r.url).replace(self.etherscan_key, "<apikey>")
            src = Source(
                provider="etherscan",
                match="etherscan",
                name=res["ContractName"],
                compiler=res["CompilerVersion"],
                files=parse_etherscan_source(res["SourceCode"], res["ContractName"]),
                url=url,
                body_sha256=hashlib.sha256(r.content).hexdigest(),
                implementations=[res["Implementation"]] if res.get("Proxy") == "1" and res.get("Implementation") else [],
            )
        else:
            return None
        self.provenance["sources"][address] = {"provider": src.provider, "url": src.url, "matchType": src.match, "bodySha256": src.body_sha256}
        return src

    def _resolve_proxy(self, c: Contract) -> dict | None:
        """EIP-1967 implementation/beacon slots, the legacy ZeppelinOS slot, EIP-1167 clones, and implementation()."""
        if m := EIP1167_RE.match(c.code.lower()):
            return {"kind": "eip1167", "implementation": to_checksum_address("0x" + m.group(1)), "admin": None}
        admin = word_to_address(self.rpc.get_storage(c.address, SLOT_ADMIN, self.block))
        for kind, slot in (("eip1967", SLOT_IMPL), ("zeppelinos", SLOT_ZOS_IMPL)):
            if impl := word_to_address(self.rpc.get_storage(c.address, slot, self.block)):
                return {"kind": kind, "implementation": impl, "admin": admin}
        if beacon := word_to_address(self.rpc.get_storage(c.address, SLOT_BEACON, self.block)):
            impl = word_to_address(self.rpc.eth_call(beacon, SEL_IMPLEMENTATION, self.block))
            return {"kind": "beacon", "implementation": impl, "beacon": beacon, "admin": admin}
        try:
            impl = word_to_address(self.rpc.eth_call(c.address, SEL_IMPLEMENTATION, self.block))
            if impl and impl != c.address and self.rpc.get_code(impl, self.block) not in ("0x", "0x0"):
                return {"kind": "implementation()", "implementation": impl, "admin": admin}
        except FetchError:
            pass
        return None

    def candidates(self, c: Contract) -> list[str]:
        """Cheap programmatic pass: address literals in the source plus address-shaped words in slots 0..7."""
        found: set[str] = set()
        for text in (c.source.files.values() if c.source else []):
            found.update(to_checksum_address(a) for a in ADDRESS_RE.findall(text))
        for slot in range(8):
            if a := word_to_address(self.rpc.get_storage(c.address, hex(slot), self.block)):
                found.add(a)
        if c.proxy and c.proxy.get("implementation"):
            found.add(c.proxy["implementation"])
        if c.source:
            found.update(to_checksum_address(a) for a in c.source.implementations)
        found -= {c.address, to_checksum_address(ZERO)} | set(self.contracts)
        return sorted(a for a in found if self.rpc.get_code(a, self.block) not in ("0x", "0x0"))

    # ------------------------------------------------------------------ model tools

    def tool_eth_call(self, address: str, calldata: str) -> str:
        result = self.rpc.eth_call(to_checksum_address(address), calldata, self.block)
        self._record("eth_call", {"address": address, "calldata": calldata}, result)
        return result

    def tool_read_storage(self, address: str, slot: str) -> str:
        result = self.rpc.get_storage(to_checksum_address(address), slot, self.block)
        self._record("read_storage", {"address": address, "slot": slot}, result)
        return result

    def _record(self, name: str, args: dict, result: str) -> None:
        self.provenance["toolCalls"].append({"name": name, "args": args, "resultSha256": hashlib.sha256(result.encode()).hexdigest()})

    def dependencies(self) -> list[dict]:
        return [c.summary() for c in self.contracts.values() if c.role != "primary"]


def parse_etherscan_source(source_code: str, name: str) -> dict[str, str]:
    """Etherscan returns a single file, a standard-JSON input wrapped in {{ }}, or a bare {sources} object."""
    s = source_code.strip()
    if s.startswith("{{"):
        return {p: f["content"] for p, f in json.loads(s[1:-1])["sources"].items()}
    if s.startswith("{"):
        obj = json.loads(s)
        return {p: f["content"] for p, f in obj.get("sources", obj).items()}
    return {f"{name}.sol": s}


def to_json(c: Contract) -> dict:
    return asdict(c)
