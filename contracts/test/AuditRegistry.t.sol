// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {console, stdJson} from "forge-std/Test.sol";
import {Fixtures} from "./Fixtures.sol";
import {AuditRegistry} from "../src/AuditRegistry.sol";

contract AuditRegistryTest is Fixtures {
    using stdJson for string;

    AuditRegistry registry;
    address signer;
    uint256 signerKey;
    AuditRegistry.AuditRecord record;
    string constant REPORT = "report";

    function setUp() public {
        loadFixtures();
        string[] memory kids = new string[](1);
        kids[0] = json.readString(".kid");
        bytes[] memory moduli = new bytes[](1);
        moduli[0] = modulus();
        bytes32[] memory images = new bytes32[](1);
        images[0] = json.readBytes32(".imageDigest");

        // Deploy from the fixed deployer so the address (hence the audience) matches the fixtures.
        address deployer = json.readAddress(".deployer");
        vm.prank(deployer);
        registry = new AuditRegistry(deployer, kids, moduli, images);
        assertEq(address(registry), json.readAddress(".registry"), "fixture registry address");
        assertEq(registry.expectedAudience(), json.readString(".audience"));

        signer = json.readAddress(".signer");
        signerKey = json.readUint(".signerKey");
        assertEq(vm.addr(signerKey), signer);

        record = AuditRegistry.AuditRecord({
            chainId: json.readUint(".record.chainId"),
            contractAddress: json.readAddress(".record.contractAddress"),
            codeHash: json.readBytes32(".record.codeHash"),
            blockNumber: json.readUint(".record.blockNumber"),
            dependenciesHash: json.readBytes32(".record.dependenciesHash"),
            grade: bytes1(bytes(json.readString(".record.grade"))),
            score: uint8(json.readUint(".record.score")),
            configHash: json.readBytes32(".record.configHash"),
            reportHash: keccak256(bytes(REPORT)),
            issuedAt: uint64(json.readUint(".record.issuedAt"))
        });
    }

    function sign(uint256 key, AuditRegistry.AuditRecord memory r) internal view returns (bytes memory) {
        (uint8 v, bytes32 rr, bytes32 s) = vm.sign(key, registry.hashTypedData(r));
        return abi.encodePacked(rr, s, v);
    }

    // ------------------------------------------------------------------ registerSigner

    function test_RegisterSigner() public {
        string memory jwt = token("valid");
        uint256 g = gasleft();
        registry.registerSigner(jwt);
        console.log("gas: registerSigner =", g - gasleft());
        assertTrue(registry.isAttestedSigner(signer));
        (bytes32 digest,,) = registry.signers(signer);
        assertEq(digest, json.readBytes32(".imageDigest"));
    }

    function test_RegisterSignerNonceAsString() public {
        registry.registerSigner(token("nonceString"));
        assertTrue(registry.isAttestedSigner(signer));
    }

    function test_RevertRegisterTwice() public {
        registry.registerSigner(token("valid"));
        vm.expectRevert("signer already registered");
        registry.registerSigner(token("valid"));
    }

    function test_RevertTampered() public {
        vm.expectRevert("JWT: bad signature");
        registry.registerSigner(token("tamperedPayload"));
    }

    function test_RevertWrongKid() public {
        vm.expectRevert("unknown kid");
        registry.registerSigner(token("wrongKid"));
    }

    function test_RevertExpired() public {
        vm.expectRevert("token expired");
        registry.registerSigner(token("expired"));
    }

    function test_RevertWrongAud() public {
        vm.expectRevert("wrong audience");
        registry.registerSigner(token("wrongAud"));
    }

    function test_RevertNonceNotAddress() public {
        vm.expectRevert("JWT: nonce is not an address");
        registry.registerSigner(token("nonceNotAddress"));
    }

    /// Unapproved image smuggling the approved digest inside eat_nonce / aud: the structural lookup still
    /// finds the real digest, so the token is rejected for its image, not for anything the attacker wrote.
    function test_RevertInjection() public {
        vm.expectRevert("image not approved");
        registry.registerSigner(token("nonceInjection"));
        vm.expectRevert("wrong audience");
        registry.registerSigner(token("audInjection"));
    }

    function test_RevertUnapprovedImage() public {
        vm.expectRevert("image not approved");
        registry.registerSigner(token("unapprovedImage"));
    }

    function test_RevertDebugImage() public {
        vm.expectRevert("debug image");
        registry.registerSigner(token("debugEnabled"));
    }

    function test_RevertStaleKeyAfterRemoval() public {
        vm.prank(json.readAddress(".deployer"));
        registry.removeGoogleKey(json.readString(".kid"));
        vm.expectRevert("unknown kid");
        registry.registerSigner(token("valid"));
    }

    // ------------------------------------------------------------------ submitAudit

    function test_RegisterAndSubmit() public {
        registry.registerSigner(token("valid"));
        uint256 g = gasleft();
        registry.submitAudit(record, sign(signerKey, record), REPORT);
        console.log("gas: submitAudit =", g - gasleft());

        AuditRegistry.StoredAudit[] memory list = registry.getAudit(record.chainId, record.contractAddress, record.codeHash);
        assertEq(list.length, 1);
        assertEq(list[0].signer, signer);
        assertEq(list[0].record.grade, bytes1("B"));
        AuditRegistry.StoredAudit memory latest = registry.latestAudit(record.chainId, record.contractAddress);
        assertEq(latest.record.reportHash, record.reportHash);
    }

    /// The Python auditor (eth_account) and the contract must agree on EIP-712 encoding.
    function test_PythonSignatureRecovers() public {
        registry.registerSigner(token("valid"));
        AuditRegistry.AuditRecord memory r = record;
        r.reportHash = json.readBytes32(".record.reportHash");
        // reportHash in the fixture is keccak256("report"), so REPORT still matches.
        assertEq(r.reportHash, keccak256(bytes(REPORT)));
        registry.submitAudit(r, json.readBytes(".recordSignature"), REPORT);
        assertEq(registry.latestAudit(r.chainId, r.contractAddress).signer, signer);
    }

    function test_RevertUnregisteredSigner() public {
        bytes memory sig = sign(0xBEEF, record);
        vm.expectRevert("signer not attested");
        registry.submitAudit(record, sig, REPORT);
    }

    function test_RevertBadSignature() public {
        registry.registerSigner(token("valid"));
        bytes memory sig = sign(signerKey, record);
        for (uint256 i = 0; i < 32; i++) sig[i] = 0; // r = 0: ecrecover returns address(0)
        vm.expectRevert("bad signature");
        registry.submitAudit(record, sig, REPORT);
        vm.expectRevert("bad signature length");
        registry.submitAudit(record, hex"1234", REPORT);
    }

    function test_RevertDuplicate() public {
        registry.registerSigner(token("valid"));
        bytes memory sig = sign(signerKey, record);
        registry.submitAudit(record, sig, REPORT);
        vm.expectRevert("duplicate audit");
        registry.submitAudit(record, sig, REPORT);

        // A newer pipeline configuration may add a record for the same code.
        AuditRegistry.AuditRecord memory r2 = record;
        r2.configHash = keccak256("config-v2");
        registry.submitAudit(r2, sign(signerKey, r2), REPORT);
        assertEq(registry.getAudit(record.chainId, record.contractAddress, record.codeHash).length, 2);
    }

    function test_RevertReportMismatch() public {
        registry.registerSigner(token("valid"));
        bytes memory sig = sign(signerKey, record);
        vm.expectRevert("report hash mismatch");
        registry.submitAudit(record, sig, "something else");
    }

    function test_RevertInvalidGradeOrScore() public {
        registry.registerSigner(token("valid"));
        AuditRegistry.AuditRecord memory r = record;
        r.grade = "E";
        bytes memory sig = sign(signerKey, r);
        vm.expectRevert("invalid grade");
        registry.submitAudit(r, sig, REPORT);
        r = record;
        r.score = 101;
        sig = sign(signerKey, r);
        vm.expectRevert("score out of range");
        registry.submitAudit(r, sig, REPORT);
    }

    function test_OnlyOwner() public {
        vm.expectRevert("not owner");
        registry.setImageApproval(bytes32(0), true);
        vm.expectRevert("not owner");
        registry.setGoogleKey("x", modulus());
    }
}
