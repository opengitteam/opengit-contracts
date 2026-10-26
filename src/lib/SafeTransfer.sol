// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice ERC-20 transfers that also accept tokens which return nothing instead of true.
library SafeTransfer {
    error TransferFailed();

    function transfer(address token, address to, uint256 amount) internal {
        _call(token, abi.encodeWithSelector(0xa9059cbb, to, amount));
    }

    function transferFrom(address token, address from, address to, uint256 amount) internal {
        _call(token, abi.encodeWithSelector(0x23b872dd, from, to, amount));
    }

    function _call(address token, bytes memory data) private {
        if (token.code.length == 0) revert TransferFailed();
        (bool ok, bytes memory ret) = token.call(data);
        if (!ok || (ret.length != 0 && !abi.decode(ret, (bool)))) revert TransferFailed();
    }
}
