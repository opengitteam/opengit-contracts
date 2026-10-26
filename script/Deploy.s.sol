// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {GitHubKeyRegistry} from "../src/GitHubKeyRegistry.sol";
import {OpenGitEscrow} from "../src/OpenGitEscrow.sol";

/// @notice Deploys GitHubKeyRegistry and OpenGitEscrow.
///
///   forge script script/Deploy.s.sol --rpc-url robinhood_testnet --broadcast --account <keystore>
///
/// Env (all optional except REGISTRY_OWNER):
///   REGISTRY_OWNER   who may add and revoke GitHub keys; use a multisig on mainnet
///   KEY_ADD_DELAY    seconds before a proposed key is usable (default 3 days, minimum 1 day)
///   CLAIM_DELAY      seconds before a first claim takes effect (default 1 day)
///   REBIND_DELAY     seconds before a payout change takes effect (default 7 days)
///   REFUND_AFTER     seconds after a tipper's last tip before an unclaimed tip is refundable (default 365 days)
contract Deploy is Script {
    function run() external returns (GitHubKeyRegistry registry, OpenGitEscrow escrow) {
        address owner = vm.envAddress("REGISTRY_OWNER");
        uint256 keyDelay = vm.envOr("KEY_ADD_DELAY", uint256(3 days));
        uint256 claimDelay = vm.envOr("CLAIM_DELAY", uint256(1 days));
        uint256 rebindDelay = vm.envOr("REBIND_DELAY", uint256(7 days));
        uint256 refundAfter = vm.envOr("REFUND_AFTER", uint256(365 days));

        vm.startBroadcast();
        registry = new GitHubKeyRegistry(owner, keyDelay);
        escrow = new OpenGitEscrow(registry, claimDelay, rebindDelay, refundAfter);
        vm.stopBroadcast();

        console.log("GitHubKeyRegistry", address(registry));
        console.log("OpenGitEscrow    ", address(escrow));
        console.log("chain id         ", block.chainid);
    }
}

/// @notice Proposes every key in script/github-jwks.json (from `node script/github-keys.mjs`)
/// that the registry does not know yet. Must be sent by the registry owner.
///
///   REGISTRY=0x... forge script script/Deploy.s.sol:ProposeKeys --rpc-url robinhood_testnet --broadcast --account <keystore>
contract ProposeKeys is Script {
    function run() external {
        GitHubKeyRegistry registry = GitHubKeyRegistry(vm.envAddress("REGISTRY"));
        string memory json = vm.readFile("script/github-jwks.json");
        uint256 n = abi.decode(vm.parseJson(json, ".keys"), (bytes[])).length;

        vm.startBroadcast();
        for (uint256 i; i < n; ++i) {
            string memory p = string.concat(".keys[", vm.toString(i), "]");
            string memory kid = vm.parseJsonString(json, string.concat(p, ".kid"));
            if (registry.keyInfo(kid).activeFrom != 0) {
                console.log("known   ", kid);
                continue;
            }
            registry.proposeKey(
                kid,
                vm.parseJsonBytes(json, string.concat(p, ".modulus")),
                vm.parseJsonBytes(json, string.concat(p, ".exponent"))
            );
            console.log("proposed", kid);
        }
        vm.stopBroadcast();
    }
}
