// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, stdJson} from "forge-std/Test.sol";

/// Loads fixtures.json produced by `python -m auditor.tests.make_fixtures`.
abstract contract Fixtures is Test {
    using stdJson for string;

    string internal json;

    function loadFixtures() internal {
        json = vm.readFile(string.concat(vm.projectRoot(), "/test/fixtures/fixtures.json"));
        vm.warp(json.readUint(".now"));
    }

    function token(string memory name) internal view returns (string memory) {
        return json.readString(string.concat(".tokens.", name));
    }

    function modulus() internal view returns (bytes memory) {
        return json.readBytes(".modulus");
    }
}
