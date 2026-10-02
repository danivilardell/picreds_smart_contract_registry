// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title JwtVerifier
/// @notice Minimal on-chain verification of Google Confidential Space attestation tokens
///         (OIDC JWTs, RS256, 2048-bit keys, e = 65537).
///
/// Only what AuditRegistry needs is implemented:
///   * `header`  — decode the header segment (to read `kid` before choosing a key).
///   * `verify`  — check the RS256 signature with the `modexp` precompile and return the payload.
///   * `claims`  — one structural pass over a JSON object returning the raw values of several keys.
///   * `str` / `num` / `parseAddress` / `parseSha256Digest` — small value decoders.
///
/// Injection concern. The payload is Google-signed, but `registerSigner` must also reject tokens from
/// *unapproved* images, whose author controls `aud`, container `env` and `args` — and `aud` precedes
/// `submods` in the payload. A flat prefix search for `"image_digest":"` could therefore be spoofed by
/// embedding that text inside `aud`. `claims` instead walks the object structurally: keys are matched only
/// at the requested nesting level and every skipped value (string with escapes, nested object/array,
/// scalar) is skipped as a unit, so no string content can masquerade as a key. Tokens are compact JSON
/// (Go `encoding/json`, no whitespace); whitespace is deliberately unsupported.
///
/// Gas. The EVM charges ~75 gas per byte for any byte-at-a-time loop, so the two passes over the ~2 KB
/// token (base64 decoding and the JSON walk) are written in Yul: base64 is decoded four characters at a
/// time through a lookup table, and all top-level claims are collected in a single walk.
library JwtVerifier {
    /// PKCS#1 v1.5 padding for a 2048-bit key and SHA-256: 0x00 0x01 || 202 × 0xFF || 0x00 || DigestInfo || hash.
    bytes private constant PS = hex"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    /// DER DigestInfo prefix for SHA-256 (RFC 8017 §9.2 note 1).
    bytes private constant DIGEST_INFO_SHA256 = hex"3031300d060960864801650304020105000420";
    /// base64url decode table indexed by ASCII code: 6-bit value, or 0xff for characters outside the alphabet.
    bytes private constant B64_TABLE = hex"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3effff3435363738393a3b3c3dffffffffffffff000102030405060708090a0b0c0d0e0f10111213141516171819ffffffff3fff1a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30313233ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    /// A 2048-bit RS256 signature is 256 bytes = 342 unpadded base64url characters, always.
    uint256 private constant SIG_CHARS = 342;

    // ---------------------------------------------------------------- JWT

    /// @return The decoded header (first segment) of `jwt`.
    function header(bytes memory jwt) internal pure returns (bytes memory) {
        return base64url(jwt, 0, indexOf(jwt, "."));
    }

    /// @notice Verifies `jwt`'s RS256 signature under `modulus` and returns the decoded payload.
    /// @dev Reverts on wrong `alg`, wrong key or signature length, malformed base64, or bad signature.
    function verify(bytes memory jwt, bytes memory modulus) internal view returns (bytes memory payload) {
        require(modulus.length == 256, "JWT: modulus must be 2048-bit");
        uint256 dot1 = indexOf(jwt, ".");
        require(jwt.length > SIG_CHARS + 1, "JWT: malformed token");
        uint256 dot2 = jwt.length - SIG_CHARS - 1;
        require(dot2 > dot1 && jwt[dot2] == ".", "JWT: bad signature length");

        require(eq(str(claim(base64url(jwt, 0, dot1), "alg")), "RS256"), "JWT: alg must be RS256");
        payload = base64url(jwt, dot1 + 1, dot2);
        bytes memory sig = base64url(jwt, dot2 + 1, jwt.length);

        // SHA-256 over the ASCII `header.payload` bytes, straight from memory.
        bytes32 digest;
        assembly {
            if iszero(staticcall(gas(), 2, add(jwt, 32), dot2, 0, 32)) { revert(0, 0) }
            digest := mload(0)
        }

        // Compare the full 256-byte encoded message, not just the trailing hash.
        bytes memory expected = abi.encodePacked(hex"0001", PS, hex"00", DIGEST_INFO_SHA256, digest);
        require(keccak256(modexp(sig, modulus)) == keccak256(expected), "JWT: bad signature");
    }

    /// @dev sig^65537 mod modulus via the EIP-198 precompile at address 5.
    function modexp(bytes memory sig, bytes memory modulus) private view returns (bytes memory out) {
        bytes memory input = abi.encodePacked(uint256(256), uint256(3), uint256(256), sig, uint24(65537), modulus);
        out = new bytes(256);
        assembly {
            if iszero(staticcall(gas(), 5, add(input, 32), mload(input), add(out, 32), 256)) { revert(0, 0) }
        }
    }

    // ---------------------------------------------------------------- JSON

    /// @notice Raw value of a single top-level `key` (see `claims`).
    function claim(bytes memory json, string memory key) internal pure returns (bytes memory) {
        string[] memory keys = new string[](1);
        keys[0] = key;
        return claims(json, keys)[0];
    }

    /// @notice Returns the raw values of top-level `keys` in JSON object `json`, in one pass.
    ///         Strings are returned with their quotes; use `str` / `num`, or call `claims` again on a returned
    ///         object to descend. Reverts if any key is missing or the object is malformed.
    function claims(bytes memory json, string[] memory keys) internal pure returns (bytes[] memory values) {
        uint256 n = keys.length;
        values = new bytes[](n);
        bytes32[] memory wanted = new bytes32[](n);
        for (uint256 i = 0; i < n; i++) wanted[i] = keccak256(bytes(keys[i]));
        uint256 found; // bitmask of keys found so far (keys are unique per object, so each is taken once)

        assembly {
            function bad() {
                mstore(0x00, shl(224, 0x08c379a0)) // Error(string)
                mstore(0x04, 0x20)
                mstore(0x24, 19)
                mstore(0x44, "JWT: malformed json")
                revert(0x00, 0x64)
            }
            // 0x80 in every byte of `v` that is zero, 0x00 elsewhere (exact: no carries cross byte lanes).
            function zeroBytes(v) -> z {
                let m7f := 0x7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f
                z := and(not(or(or(add(and(v, m7f), m7f), v), m7f)), not(m7f))
            }
            // Index (0 = most significant byte) of the first flagged byte in `z`, by binary search.
            function firstByte(z) -> i {
                if iszero(shr(128, z)) { i := 16 z := shl(128, z) }
                if iszero(shr(192, z)) { i := add(i, 8) z := shl(64, z) }
                if iszero(shr(224, z)) { i := add(i, 4) z := shl(32, z) }
                if iszero(shr(240, z)) { i := add(i, 2) z := shl(16, z) }
                if iszero(shr(248, z)) { i := add(i, 1) }
            }
            // q at an opening quote -> position of the matching closing quote, 32 bytes at a time.
            function strEnd(q, end) -> r {
                r := add(q, 1)
                for {} 1 {} {
                    if iszero(lt(r, end)) { bad() }
                    let w := mload(r)
                    let z := or(
                        zeroBytes(xor(w, 0x2222222222222222222222222222222222222222222222222222222222222222)), // '"'
                        zeroBytes(xor(w, 0x5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c)) // '\'
                    )
                    if iszero(z) {
                        r := add(r, 32)
                        continue
                    }
                    r := add(r, firstByte(z))
                    if iszero(lt(r, end)) { bad() }
                    if eq(byte(0, mload(r)), 0x22) { leave }
                    r := add(r, 2) // backslash: skip it and the escaped character
                }
            }
            // q at the start of a value -> position just past it.
            function valEnd(q, end) -> r {
                let c := byte(0, mload(q))
                if eq(c, 0x22) {
                    r := add(strEnd(q, end), 1)
                    leave
                }
                if or(eq(c, 0x7b), eq(c, 0x5b)) {
                    // '{' or '[': skip the whole nested structure
                    let depth := 0
                    for { r := q } 1 { r := add(r, 1) } {
                        if iszero(lt(r, end)) { bad() }
                        c := byte(0, mload(r))
                        switch c
                        case 0x22 { r := strEnd(r, end) }
                        case 0x7b { depth := add(depth, 1) }
                        case 0x5b { depth := add(depth, 1) }
                        case 0x7d { depth := sub(depth, 1) }
                        case 0x5d { depth := sub(depth, 1) }
                        if iszero(depth) {
                            r := add(r, 1)
                            leave
                        }
                    }
                }
                // number / literal: runs until ',' '}' or ']'
                for { r := q } 1 { r := add(r, 1) } {
                    if iszero(lt(r, end)) { bad() }
                    c := byte(0, mload(r))
                    if or(or(eq(c, 0x2c), eq(c, 0x7d)), eq(c, 0x5d)) { leave }
                }
            }

            let p := add(json, 32)
            let end := add(p, mload(json))
            if iszero(eq(byte(0, mload(p)), 0x7b)) { bad() }
            p := add(p, 1)
            let all := sub(shl(n, 1), 1)
            for {} lt(found, all) {} {
                if iszero(lt(p, end)) { bad() }
                let c := byte(0, mload(p))
                if eq(c, 0x7d) { break } // end of object, some key is missing
                if iszero(eq(c, 0x22)) { bad() }
                let kEnd := strEnd(p, end)
                if iszero(eq(byte(0, mload(add(kEnd, 1))), 0x3a)) { bad() }
                let vStart := add(kEnd, 2)
                let vEnd := valEnd(vStart, end)
                let h := keccak256(add(p, 1), sub(sub(kEnd, p), 1))
                for { let i := 0 } lt(i, n) { i := add(i, 1) } {
                    if and(eq(h, mload(add(add(wanted, 32), mul(i, 32)))), iszero(and(found, shl(i, 1)))) {
                        // copy the raw value into a fresh bytes allocation
                        let dst := mload(0x40)
                        let len := sub(vEnd, vStart)
                        mstore(dst, len)
                        for { let o := 0 } lt(o, len) { o := add(o, 32) } {
                            mstore(add(add(dst, 32), o), mload(add(vStart, o)))
                        }
                        mstore(0x40, add(add(dst, 32), and(add(len, 31), not(31))))
                        mstore(add(add(values, 32), mul(i, 32)), dst)
                        found := or(found, shl(i, 1))
                    }
                }
                p := vEnd
                if eq(byte(0, mload(p)), 0x2c) { p := add(p, 1) }
            }
        }
        require(found == (1 << n) - 1, "JWT: claim missing");
    }

    // ---------------------------------------------------------------- value decoders

    /// @notice Strips the quotes from a raw JSON string value.
    function str(bytes memory raw) internal pure returns (bytes memory) {
        require(raw.length >= 2 && raw[0] == '"' && raw[raw.length - 1] == '"', "JWT: not a string");
        return slice(raw, 1, raw.length - 1);
    }

    /// @notice Parses a raw JSON non-negative integer.
    function num(bytes memory raw) internal pure returns (uint256 n) {
        require(raw.length > 0, "JWT: not a number");
        for (uint256 i = 0; i < raw.length; i++) {
            uint8 d = uint8(raw[i]);
            require(d >= 48 && d <= 57, "JWT: not a number");
            n = n * 10 + (d - 48);
        }
    }

    /// @notice Parses `0x` + 40 lowercase hex chars into an address. Reverts on anything else,
    ///         which is what makes `eat_nonce` safe: it cannot contain quotes or spoof a key.
    function parseAddress(bytes memory s) internal pure returns (address) {
        require(s.length == 42 && s[0] == "0" && s[1] == "x", "JWT: nonce is not an address");
        return address(uint160(hexToUint(s, 2, 42)));
    }

    /// @notice Parses `sha256:` + 64 hex chars (the `submods.container.image_digest` format).
    function parseSha256Digest(bytes memory s) internal pure returns (bytes32) {
        require(s.length == 71 && eq(slice(s, 0, 7), "sha256:"), "JWT: bad image digest");
        return bytes32(hexToUint(s, 7, 71));
    }

    function hexToUint(bytes memory s, uint256 start, uint256 end) private pure returns (uint256 v) {
        for (uint256 i = start; i < end; i++) {
            uint8 c = uint8(s[i]);
            if (c >= 48 && c <= 57) v = v * 16 + (c - 48);
            else if (c >= 97 && c <= 102) v = v * 16 + (c - 87);
            else revert("JWT: bad hex");
        }
    }

    function eq(bytes memory a, string memory b) internal pure returns (bool) {
        return a.length == bytes(b).length && keccak256(a) == keccak256(bytes(b));
    }

    // ---------------------------------------------------------------- bytes helpers

    /// @dev Decodes unpadded base64url from `b[start:end]`, four characters (three bytes) per step.
    function base64url(bytes memory b, uint256 start, uint256 end) internal pure returns (bytes memory out) {
        require(start <= end && end <= b.length, "JWT: bad slice");
        uint256 n = end - start;
        require(n % 4 != 1, "JWT: bad base64 length");
        bytes memory table = B64_TABLE;
        assembly {
            let tbl := add(table, 32)
            let src := add(add(b, 32), start)
            let srcEnd := add(src, n)
            out := mload(0x40)
            let outLen := div(mul(n, 3), 4)
            mstore(out, outLen)
            let dst := add(out, 32)
            let bad := 0
            for {} lt(src, srcEnd) { src := add(src, 4) dst := add(dst, 3) } {
                let w := mload(src)
                if gt(add(src, 4), srcEnd) {
                    // final partial group: replace the missing characters with 'A' (value 0)
                    let mask := shl(sub(256, mul(sub(srcEnd, src), 8)), not(0))
                    w := or(and(w, mask), and(shl(224, 0x41414141), not(mask)))
                }
                let v0 := byte(0, mload(add(tbl, byte(0, w))))
                let v1 := byte(0, mload(add(tbl, byte(1, w))))
                let v2 := byte(0, mload(add(tbl, byte(2, w))))
                let v3 := byte(0, mload(add(tbl, byte(3, w))))
                bad := or(bad, or(or(v0, v1), or(v2, v3)))
                mstore(dst, shl(232, or(or(shl(18, v0), shl(12, v1)), or(shl(6, v2), v3))))
            }
            if gt(bad, 63) {
                mstore(0x00, shl(224, 0x08c379a0))
                mstore(0x04, 0x20)
                mstore(0x24, 20)
                mstore(0x44, "JWT: bad base64 char")
                revert(0x00, 0x64)
            }
            mstore(add(add(out, 32), outLen), 0) // zero the slop written past the end
            mstore(0x40, add(add(out, 32), and(add(outLen, 31), not(31))))
        }
    }

    function indexOf(bytes memory b, bytes1 c) private pure returns (uint256 i) {
        for (i = 0; i < b.length; i++) {
            if (b[i] == c) return i;
        }
        revert("JWT: malformed token");
    }

    function slice(bytes memory b, uint256 start, uint256 end) internal pure returns (bytes memory out) {
        require(start <= end && end <= b.length, "JWT: bad slice");
        out = new bytes(end - start);
        assembly {
            let src := add(add(b, 32), start)
            let dst := add(out, 32)
            for { let o := 0 } lt(o, sub(end, start)) { o := add(o, 32) } { mstore(add(dst, o), mload(add(src, o))) }
        }
    }
}
