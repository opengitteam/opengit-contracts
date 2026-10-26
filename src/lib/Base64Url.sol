// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Base64url decoding (RFC 4648 §5, no padding), as used by JWTs.
library Base64Url {
    error InvalidBase64Url();

    /// @dev Maps an ASCII byte to its 6-bit value, or 0xff if it is not in the base64url alphabet.
    function _value(uint8 c) private pure returns (uint8) {
        if (c >= 0x41 && c <= 0x5a) return c - 0x41; // A-Z
        if (c >= 0x61 && c <= 0x7a) return c - 0x61 + 26; // a-z
        if (c >= 0x30 && c <= 0x39) return c - 0x30 + 52; // 0-9
        if (c == 0x2d) return 62; // -
        if (c == 0x5f) return 63; // _
        return 0xff;
    }

    function decode(bytes memory input) internal pure returns (bytes memory out) {
        uint256 len = input.length;
        // A trailing group of 1 character cannot encode a byte.
        if (len % 4 == 1) revert InvalidBase64Url();
        out = new bytes((len * 3) / 4);
        uint256 o;
        uint256 i;
        unchecked {
            while (i < len) {
                uint256 chunk;
                uint256 n;
                for (; n < 4 && i < len; ++n) {
                    uint8 c;
                    assembly {
                        c := byte(0, mload(add(add(input, 0x20), i)))
                    }
                    ++i;
                    uint8 v = _value(c);
                    if (v == 0xff) revert InvalidBase64Url();
                    chunk = (chunk << 6) | v;
                }
                // Left-align a short final group to 24 bits, then emit its whole bytes.
                chunk <<= 6 * (4 - n);
                uint256 emit_ = n - 1; // 2 chars -> 1 byte, 3 -> 2, 4 -> 3
                for (uint256 b; b < emit_; ++b) {
                    uint8 byteVal = uint8(chunk >> (16 - 8 * b));
                    assembly {
                        mstore8(add(add(out, 0x20), o), byteVal)
                    }
                    ++o;
                }
            }
        }
    }
}
