// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Base64Url} from "../src/lib/Base64Url.sol";
import {FlatJson} from "../src/lib/FlatJson.sol";
import {RsaSha256} from "../src/lib/RsaSha256.sol";

/// @dev External wrappers so reverts surface to vm.expectRevert.
contract LibHarness {
    function decode(bytes memory s) external pure returns (bytes memory) {
        return Base64Url.decode(s);
    }

    function str(bytes memory json, bytes memory key) external pure returns (bytes memory) {
        return FlatJson.getString(json, key);
    }

    function num(bytes memory json, bytes memory key) external pure returns (uint256) {
        return FlatJson.getUint(json, key);
    }

    function verify(bytes memory m, bytes memory s, bytes memory n, bytes memory e) external view returns (bool) {
        return RsaSha256.verify(m, s, n, e);
    }
}

contract LibsTest is Test {
    LibHarness h = new LibHarness();

    function test_base64UrlVectors() public view {
        // RFC 4648 test vectors, unpadded, base64url alphabet.
        assertEq(h.decode(""), "");
        assertEq(h.decode("Zg"), "f");
        assertEq(h.decode("Zm8"), "fo");
        assertEq(h.decode("Zm9v"), "foo");
        assertEq(h.decode("Zm9vYg"), "foob");
        assertEq(h.decode("Zm9vYmE"), "fooba");
        assertEq(h.decode("Zm9vYmFy"), "foobar");
        assertEq(h.decode("-_8"), hex"fbff"); // url-safe characters
    }

    function test_base64UrlRejectsBadInput() public {
        vm.expectRevert(Base64Url.InvalidBase64Url.selector);
        h.decode("Zm9v+g"); // '+' is standard base64, not base64url
        vm.expectRevert(Base64Url.InvalidBase64Url.selector);
        h.decode("Zm9vY"); // a lone trailing character
        vm.expectRevert(Base64Url.InvalidBase64Url.selector);
        h.decode("Zm9v=="); // padding is not allowed in JWTs
    }

    function test_jsonReadsTopLevelMembers() public view {
        bytes memory j = bytes('{ "a" : "x\\"y", "b":12, "c":true, "d":null, "e":"" }');
        assertEq(h.str(j, "a"), bytes('x\\"y')); // raw, escape kept
        assertEq(h.num(j, "b"), 12);
        assertEq(h.str(j, "e"), "");
    }

    function test_jsonMatchesKeysOnlyInKeyPosition() public view {
        bytes memory j = bytes('{"ref":"x\\",\\"id\\":\\"9","id":"7"}');
        assertEq(h.num(j, "id"), 7);
    }

    function test_jsonRejectsNestingAndJunk() public {
        vm.expectRevert(FlatJson.InvalidJson.selector);
        h.str(bytes('{"a":{"b":"c"}}'), "a");
        vm.expectRevert(FlatJson.InvalidJson.selector);
        h.str(bytes('{"a":["c"]}'), "a");
        vm.expectRevert(FlatJson.InvalidJson.selector);
        h.str(bytes('{"a":"c"'), "a");
        vm.expectRevert(FlatJson.InvalidJson.selector);
        h.str(bytes('["a"]'), "a");
        vm.expectRevert(FlatJson.InvalidJson.selector);
        h.str(bytes('{"a":"c"}'), "missing");
    }

    function test_jsonRejectsDuplicateKeys() public {
        vm.expectRevert(FlatJson.DuplicateKey.selector);
        h.str(bytes('{"a":"1","a":"2"}'), "a");
    }

    function test_jsonUintRejectsNonDigits() public {
        vm.expectRevert(FlatJson.InvalidJson.selector);
        h.num(bytes('{"n":"-1"}'), "n");
        vm.expectRevert(FlatJson.InvalidJson.selector);
        h.num(bytes('{"n":1.5}'), "n");
        vm.expectRevert(FlatJson.InvalidJson.selector);
        h.num(bytes('{"n":"123456789012345678901"}'), "n"); // over 20 digits
    }

    function test_rsaAcceptsFixtureAndRejectsTampering() public view {
        string memory f = vm.readFile("test/fixtures/tokens.json");
        bytes memory n = vm.parseJsonBytes(f, ".keys[0].modulus");
        bytes memory msg_ = bytes(
            string.concat(vm.parseJsonString(f, ".tokens[0].header"), ".", vm.parseJsonString(f, ".tokens[0].payload"))
        );
        bytes memory sig = vm.parseJsonBytes(f, ".tokens[0].signature");
        assertTrue(h.verify(msg_, sig, n, hex"010001"));

        bytes memory bad = bytes.concat(msg_, "x");
        assertFalse(h.verify(bad, sig, n, hex"010001"));
        sig[10] ^= 0x01;
        assertFalse(h.verify(msg_, sig, n, hex"010001"));
        assertFalse(h.verify(msg_, new bytes(255), n, hex"010001")); // wrong length
        assertFalse(h.verify(msg_, n, n, hex"010001")); // signature >= modulus
    }
}
