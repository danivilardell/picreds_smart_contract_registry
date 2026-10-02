// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {JwtVerifier} from "./JwtVerifier.sol";

/// @title AuditRegistry
/// @notice On-chain registry of LLM smart-contract audits issued from inside Google Confidential Space TEEs,
///         in the style of πCreds (Breckenridge, Vilardell et al., 2026). Integrity only: a verifier can check,
///         entirely on chain, that a grade was produced by an approved pipeline image running in a genuine TEE,
///         over exactly the code (chainId, address, codeHash) it claims to cover.
///
/// Flow. An auditor image boots in Confidential Space, generates a secp256k1 key, and obtains a Google-signed
/// attestation JWT whose `eat_nonce` is the key's Ethereum address and whose `aud` names this registry.
/// `registerSigner` verifies that JWT on chain and records the address as a signer for the attested image
/// digest. The TEE then signs EIP-712 `AuditRecord`s that anyone may submit through `submitAudit`.
///
/// Residual trust. The owner controls (a) which Google JWKS moduli are accepted (`setGoogleKey`) and (b) which
/// container image digests are approved (`setImageApproval`). The owner can therefore approve a malicious
/// "auditor" image, but cannot register an arbitrary key for an approved image: every signer must present a
/// Google-signed token binding its address to an approved digest, and anyone can check an approved digest
/// against the reproducible build of the published auditor source. A timelock on `setImageApproval` is the
/// obvious hardening and is deliberately left out of this minimal version.
///
/// Attestation tokens expire after about an hour, so registration must happen right after boot. A signer stays
/// valid after its token expires because the binding was verified while the token was fresh. Google rotates
/// its signing keys often; without a keeper refreshing `googleKeys`, `registerSigner` fails once the stored
/// keys are stale, while existing signers are unaffected.
contract AuditRegistry {
    struct SignerInfo {
        bytes32 imageDigest;
        bytes32 attestationHash; // keccak256 of the JWT, also emitted in full in SignerRegistered
        uint64 registeredAt;
    }

    /// @dev `dependenciesHash` = keccak256(abi.encode(Subject[])) with Subject = (uint256 chainId, address addr,
    ///      bytes32 codeHash, uint256 blockNumber) for every dependency the TEE fetched; the tuples themselves are
    ///      in the report JSON. `reportHash` = keccak256 of the canonical (sorted-key, compact) credentialSubject.
    struct AuditRecord {
        uint256 chainId;
        address contractAddress;
        bytes32 codeHash; // keccak256(bytecode at blockNumber) == EXTCODEHASH
        uint256 blockNumber;
        bytes32 dependenciesHash;
        bytes1 grade; // "A".."D" or "F"
        uint8 score; // 0..100
        bytes32 configHash; // the pipeline configuration τ: model, prompts, tool schemas, rubric, whitelist, version
        bytes32 reportHash;
        uint64 issuedAt;
    }

    struct StoredAudit {
        AuditRecord record;
        address signer;
        uint64 submittedAt;
    }

    bytes32 public constant RECORD_TYPEHASH = keccak256(
        "AuditRecord(uint256 chainId,address contractAddress,bytes32 codeHash,uint256 blockNumber,bytes32 dependenciesHash,bytes1 grade,uint8 score,bytes32 configHash,bytes32 reportHash,uint64 issuedAt)"
    );
    bytes32 public immutable DOMAIN_SEPARATOR;
    /// @notice `aud` every attestation token must carry: "picreds-audit-registry:<chainId>:<this address, lowercase>".
    string public expectedAudience;

    address public owner;
    mapping(string kid => bytes modulus) public googleKeys;
    mapping(bytes32 imageDigest => bool) public approvedImages;
    mapping(address signer => SignerInfo) public signers;

    mapping(bytes32 key => StoredAudit[]) private audits; // key = keccak256(chainId, address, codeHash)
    mapping(bytes32 key => mapping(address signer => mapping(bytes32 configHash => bool))) private submitted;
    mapping(bytes32 addrKey => bytes32 key) private latestKey; // addrKey = keccak256(chainId, address)

    event GoogleKeySet(string kid, bytes modulus);
    event GoogleKeyRemoved(string kid);
    event ImageApprovalSet(bytes32 indexed imageDigest, bool approved);
    event SignerRegistered(address indexed signer, bytes32 indexed imageDigest, string jwt);
    event AuditSubmitted(bytes32 indexed key, address indexed signer, AuditRecord record, string report);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor(address owner_, string[] memory kids, bytes[] memory moduli, bytes32[] memory images) {
        require(kids.length == moduli.length, "kids/moduli length mismatch");
        owner = owner_;
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("AuditRegistry"),
                keccak256("1"),
                block.chainid,
                address(this)
            )
        );
        expectedAudience = string.concat("picreds-audit-registry:", toString(block.chainid), ":", toHex(address(this)));
        for (uint256 i = 0; i < kids.length; i++) _setGoogleKey(kids[i], moduli[i]);
        for (uint256 i = 0; i < images.length; i++) _setImageApproval(images[i], true);
    }

    // ------------------------------------------------------------------ owner

    function setGoogleKey(string calldata kid, bytes calldata modulus) external onlyOwner {
        _setGoogleKey(kid, modulus);
    }

    function removeGoogleKey(string calldata kid) external onlyOwner {
        delete googleKeys[kid];
        emit GoogleKeyRemoved(kid);
    }

    function setImageApproval(bytes32 imageDigest, bool approved) external onlyOwner {
        _setImageApproval(imageDigest, approved);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    function _setGoogleKey(string memory kid, bytes memory modulus) private {
        require(modulus.length == 256, "modulus must be 2048-bit");
        googleKeys[kid] = modulus;
        emit GoogleKeySet(kid, modulus);
    }

    function _setImageApproval(bytes32 imageDigest, bool approved) private {
        approvedImages[imageDigest] = approved;
        emit ImageApprovalSet(imageDigest, approved);
    }

    // ------------------------------------------------------------------ signers

    /// @notice Permissionless. Verifies a Confidential Space attestation token and registers the address in its
    ///         `eat_nonce` as an audit signer for the attested image digest.
    function registerSigner(string calldata jwt) external {
        bytes memory token = bytes(jwt);
        bytes memory modulus = googleKeys[string(JwtVerifier.str(JwtVerifier.claim(JwtVerifier.header(token), "kid")))];
        require(modulus.length != 0, "unknown kid");
        bytes memory payload = JwtVerifier.verify(token, modulus);

        string[] memory keys = new string[](5);
        (keys[0], keys[1], keys[2], keys[3], keys[4]) = ("exp", "aud", "dbgstat", "eat_nonce", "submods");
        bytes[] memory v = JwtVerifier.claims(payload, keys);
        require(JwtVerifier.num(v[0]) > block.timestamp, "token expired");
        require(JwtVerifier.eq(JwtVerifier.str(v[1]), expectedAudience), "wrong audience");
        require(JwtVerifier.eq(JwtVerifier.str(v[2]), "disabled-since-boot"), "debug image");

        bytes memory container = JwtVerifier.claim(v[4], "container");
        bytes32 imageDigest = JwtVerifier.parseSha256Digest(JwtVerifier.str(JwtVerifier.claim(container, "image_digest")));
        require(approvedImages[imageDigest], "image not approved");

        // eat_nonce is documented as string-or-array; a single-element array is unwrapped here.
        bytes memory nonce = v[3];
        if (nonce[0] == "[") nonce = JwtVerifier.slice(nonce, 1, nonce.length - 1);
        address signer = JwtVerifier.parseAddress(JwtVerifier.str(nonce));
        require(signers[signer].registeredAt == 0, "signer already registered");

        signers[signer] = SignerInfo(imageDigest, keccak256(token), uint64(block.timestamp));
        emit SignerRegistered(signer, imageDigest, jwt);
    }

    function isAttestedSigner(address signer) external view returns (bool) {
        return signers[signer].registeredAt != 0;
    }

    // ------------------------------------------------------------------ audits

    /// @notice Permissionless. `report` is the canonical credentialSubject JSON; it must hash to `record.reportHash`
    ///         and is emitted in full so the audit can be reconstructed from the event log.
    function submitAudit(AuditRecord calldata record, bytes calldata signature, string calldata report) external {
        address signer = recover(hashTypedData(record), signature);
        require(signers[signer].registeredAt != 0, "signer not attested");
        require(keccak256(bytes(report)) == record.reportHash, "report hash mismatch");
        require(record.score <= 100, "score out of range");
        bytes1 g = record.grade;
        require(g == "A" || g == "B" || g == "C" || g == "D" || g == "F", "invalid grade");

        bytes32 key = keccak256(abi.encode(record.chainId, record.contractAddress, record.codeHash));
        require(!submitted[key][signer][record.configHash], "duplicate audit");
        submitted[key][signer][record.configHash] = true;
        audits[key].push(StoredAudit(record, signer, uint64(block.timestamp)));
        latestKey[keccak256(abi.encode(record.chainId, record.contractAddress))] = key;
        emit AuditSubmitted(key, signer, record, report);
    }

    function getAudit(uint256 chainId, address contractAddress, bytes32 codeHash)
        external
        view
        returns (StoredAudit[] memory)
    {
        return audits[keccak256(abi.encode(chainId, contractAddress, codeHash))];
    }

    /// @notice Most recently submitted audit for (chainId, address), whatever code it covered. Callers should compare
    ///         `record.codeHash` with the contract's current EXTCODEHASH: a mismatch means it was upgraded since.
    function latestAudit(uint256 chainId, address contractAddress) external view returns (StoredAudit memory) {
        StoredAudit[] storage list = audits[latestKey[keccak256(abi.encode(chainId, contractAddress))]];
        require(list.length != 0, "no audit");
        return list[list.length - 1];
    }

    function hashTypedData(AuditRecord calldata r) public view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                RECORD_TYPEHASH,
                r.chainId,
                r.contractAddress,
                r.codeHash,
                r.blockNumber,
                r.dependenciesHash,
                r.grade,
                r.score,
                r.configHash,
                r.reportHash,
                r.issuedAt
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
    }

    function recover(bytes32 digest, bytes calldata signature) private pure returns (address signer) {
        require(signature.length == 65, "bad signature length");
        bytes32 r = bytes32(signature[0:32]);
        bytes32 s = bytes32(signature[32:64]);
        uint8 v = uint8(signature[64]);
        if (v < 27) v += 27;
        signer = ecrecover(digest, v, r, s);
        require(signer != address(0), "bad signature");
    }

    // ------------------------------------------------------------------ string helpers

    function toString(uint256 n) private pure returns (string memory) {
        if (n == 0) return "0";
        bytes memory buf = new bytes(78);
        uint256 i = 78;
        while (n != 0) {
            buf[--i] = bytes1(uint8(48 + n % 10));
            n /= 10;
        }
        return string(JwtVerifier.slice(buf, i, 78));
    }

    function toHex(address a) private pure returns (string memory) {
        bytes16 alphabet = "0123456789abcdef";
        bytes memory s = new bytes(42);
        (s[0], s[1]) = ("0", "x");
        for (uint256 i = 0; i < 20; i++) {
            uint8 b = uint8(uint160(a) >> (8 * (19 - i)));
            s[2 + 2 * i] = alphabet[b >> 4];
            s[3 + 2 * i] = alphabet[b & 15];
        }
        return string(s);
    }
}
