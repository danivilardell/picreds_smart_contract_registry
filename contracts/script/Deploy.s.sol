// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {AuditRegistry} from "../src/AuditRegistry.sol";

/// Usage (env): KIDS="kid1,kid2" MODULI="0x..,0x.." IMAGE_DIGESTS="0x..,0x.." [OWNER=0x..]
///   forge script script/Deploy.s.sol --rpc-url sepolia --broadcast --private-key $DEPLOYER_PRIVATE_KEY
/// `python cli/jwks_keeper.py --print-env` prints KIDS/MODULI for Google's current JWKS (or the dev key with --mock).
contract Deploy is Script {
    function run() external {
        string[] memory kids = vm.envString("KIDS", ",");
        bytes[] memory moduli = vm.envBytes("MODULI", ",");
        bytes32[] memory images = vm.envBytes32("IMAGE_DIGESTS", ",");
        address owner = vm.envOr("OWNER", msg.sender);

        vm.startBroadcast();
        AuditRegistry registry = new AuditRegistry(owner, kids, moduli, images);
        vm.stopBroadcast();

        console.log("AuditRegistry deployed at", address(registry));
        console.log("expected audience:", registry.expectedAudience());
    }
}
