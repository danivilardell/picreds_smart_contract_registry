// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {console, stdJson} from "forge-std/Test.sol";
import {Fixtures} from "./Fixtures.sol";
import {JwtVerifier} from "../src/JwtVerifier.sol";

contract JwtVerifierTest is Fixtures {
    using stdJson for string;

    function setUp() public {
        loadFixtures();
    }

    function test_ValidToken() public view {
        bytes memory payload = JwtVerifier.verify(bytes(token("valid")), modulus());
        assertTrue(JwtVerifier.eq(JwtVerifier.str(JwtVerifier.claim(payload, "aud")), json.readString(".audience")));
        assertEq(JwtVerifier.num(JwtVerifier.claim(payload, "exp")), block.timestamp + 3600);
        assertTrue(JwtVerifier.eq(JwtVerifier.str(JwtVerifier.claim(payload, "dbgstat")), "disabled-since-boot"));

        bytes memory container = JwtVerifier.claim(JwtVerifier.claim(payload, "submods"), "container");
        bytes32 digest = JwtVerifier.parseSha256Digest(JwtVerifier.str(JwtVerifier.claim(container, "image_digest")));
        assertEq(digest, json.readBytes32(".imageDigest"));

        bytes memory nonce = JwtVerifier.claim(payload, "eat_nonce");
        nonce = JwtVerifier.slice(nonce, 1, nonce.length - 1); // unwrap one-element array
        assertEq(JwtVerifier.parseAddress(JwtVerifier.str(nonce)), json.readAddress(".signer"));
    }

    function test_HeaderKid() public view {
        bytes memory kid = JwtVerifier.str(JwtVerifier.claim(JwtVerifier.header(bytes(token("valid"))), "kid"));
        assertTrue(JwtVerifier.eq(kid, json.readString(".kid")));
    }

    function test_RevertTamperedPayload() public {
        vm.expectRevert("JWT: bad signature");
        this.verifyExternal(token("tamperedPayload"), modulus());
    }

    function test_RevertWrongModulus() public {
        bytes memory wrong = modulus();
        wrong[10] ^= 0x01;
        vm.expectRevert("JWT: bad signature");
        this.verifyExternal(token("valid"), wrong);
    }

    function test_RevertAlgNone() public {
        vm.expectRevert("JWT: alg must be RS256");
        this.verifyExternal(token("algNone"), modulus());
    }

    function test_RevertBadModulusLength() public {
        vm.expectRevert("JWT: modulus must be 2048-bit");
        this.verifyExternal(token("valid"), hex"deadbeef");
    }

    function test_RevertMalformed() public {
        vm.expectRevert("JWT: malformed token");
        this.verifyExternal("not-a-jwt", modulus());
        bytes memory t = bytes(token("valid"));
        string memory sig = string(JwtVerifier.slice(t, t.length - 342, t.length)); // the signature segment
        vm.expectRevert("JWT: bad base64 char");
        this.verifyExternal(string.concat("ab!c.defg.", sig), modulus());
        vm.expectRevert("JWT: bad signature length");
        this.verifyExternal(string.concat("abcd.efgh.", sig, "x"), modulus());
    }

    function test_RevertMissingClaim() public {
        vm.expectRevert("JWT: claim missing");
        this.claimExternal('{"a":"1","b":{"c":2}}', "c"); // nested keys are not visible at the top level
    }

    /// Attacker-controlled claims (`aud`, `eat_nonce`) containing JSON text must not fool the structural lookup.
    function test_ClaimIgnoresInjectedText() public pure {
        bytes memory payload = bytes(
            '{"aud":"x\\",\\"submods\\":{\\"container\\":{\\"image_digest\\":\\"sha256:evil\\"}}","eat_nonce":["0x1\\"","{"],"submods":{"confidential_space":{"support_attributes":["STABLE"]},"container":{"image_reference":"r","image_digest":"sha256:good","env":{"K":"\\"image_digest\\":\\"sha256:evil2\\""}}},"z":1}'
        );
        bytes memory container = JwtVerifier.claim(JwtVerifier.claim(payload, "submods"), "container");
        assertTrue(JwtVerifier.eq(JwtVerifier.str(JwtVerifier.claim(container, "image_digest")), "sha256:good"));
        assertTrue(JwtVerifier.eq(JwtVerifier.claim(payload, "z"), "1"));
    }

    function test_ParseAddressRejectsNonAddresses() public {
        vm.expectRevert("JWT: nonce is not an address");
        this.parseAddressExternal("0x0208D3e32a5e1903EC6d32b83F6eCA09DB7673E7x");
        vm.expectRevert("JWT: bad hex");
        this.parseAddressExternal("0x0208D3e32a5e1903EC6d32b83F6eCA09DB7673E7"); // uppercase rejected
        vm.expectRevert("JWT: nonce is not an address");
        this.parseAddressExternal('0x0208d3e32a5e1903ec6d32b83f6eca09db7673e7","a":"');
    }

    function test_GasVerifyAndClaims() public view {
        bytes memory jwt = bytes(token("valid"));
        bytes memory mod = modulus();
        uint256 g = gasleft();
        bytes memory payload = JwtVerifier.verify(jwt, mod);
        uint256 gVerify = g - gasleft();
        g = gasleft();
        JwtVerifier.claim(JwtVerifier.header(jwt), "kid");
        string[] memory keys = new string[](5);
        (keys[0], keys[1], keys[2], keys[3], keys[4]) = ("exp", "aud", "dbgstat", "eat_nonce", "submods");
        bytes[] memory v = JwtVerifier.claims(payload, keys);
        JwtVerifier.claim(JwtVerifier.claim(v[4], "container"), "image_digest");
        uint256 gClaims = g - gasleft();
        console.log("token length (chars):", jwt.length);
        console.log("gas: verify =", gVerify);
        console.log("gas: kid + 5 top-level claims + image_digest =", gClaims);
        console.log("gas: total =", gVerify + gClaims);
        assertLt(gVerify + gClaims, 300_000);
    }

    // External wrappers so vm.expectRevert can target library calls.
    function verifyExternal(string calldata jwt, bytes calldata mod) external view returns (bytes memory) {
        return JwtVerifier.verify(bytes(jwt), mod);
    }

    function claimExternal(string calldata j, string calldata key) external pure returns (bytes memory) {
        return JwtVerifier.claim(bytes(j), key);
    }

    function parseAddressExternal(string calldata s) external pure returns (address) {
        return JwtVerifier.parseAddress(bytes(s));
    }
}
