// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {SafeTransfer} from "./lib/SafeTransfer.sol";

/// @title RepoVault
/// @notice Holds the funds for one GitHub repo. Its address is fixed by the repo's numeric GitHub
/// id (CREATE2 from OpenGitEscrow), so tips and x402 payments can be sent to it before it exists
/// on-chain. Only the escrow that deployed it can move funds, and only by the escrow's rules.
contract RepoVault {
    address public immutable escrow;

    error NotEscrow();

    constructor() {
        escrow = msg.sender;
    }

    function pull(address token, address to, uint256 amount) external {
        if (msg.sender != escrow) revert NotEscrow();
        SafeTransfer.transfer(token, to, amount);
    }
}
