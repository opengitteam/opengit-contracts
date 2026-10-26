// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice RSASSA-PKCS1-v1_5 signature verification with SHA-256 (JWT "RS256"), using the
/// MODEXP precompile at 0x05. Supports any modulus length that is a whole number of bytes.
library RsaSha256 {
    /// @dev DER prefix of DigestInfo for SHA-256 (RFC 8017 §9.2, note 1).
    bytes19 private constant SHA256_DIGEST_INFO = 0x3031300d060960864801650304020105000420;

    /// @return True if `signature` is a valid PKCS#1 v1.5 SHA-256 signature of `message`
    /// under the public key (`modulus`, `exponent`).
    function verify(bytes memory message, bytes memory signature, bytes memory modulus, bytes memory exponent)
        internal
        view
        returns (bool)
    {
        uint256 k = modulus.length;
        // The encoding needs 0x00 0x01, at least 8 bytes of 0xff, 0x00, then 19 + 32 bytes.
        if (k < 62 || signature.length != k) return false;
        if (_cmp(signature, modulus) >= 0) return false; // the signature must be less than n

        bytes memory em = _modexp(signature, exponent, modulus);
        if (em.length != k) return false;

        bytes32 digest = sha256(message);
        uint256 psEnd = k - 52; // index of the 0x00 separator before DigestInfo
        if (em[0] != 0x00 || em[1] != 0x01) return false;
        for (uint256 i = 2; i < psEnd; ++i) {
            if (em[i] != 0xff) return false;
        }
        if (em[psEnd] != 0x00) return false;
        for (uint256 i; i < 19; ++i) {
            if (em[psEnd + 1 + i] != SHA256_DIGEST_INFO[i]) return false;
        }
        for (uint256 i; i < 32; ++i) {
            if (em[psEnd + 20 + i] != digest[i]) return false;
        }
        return true;
    }

    /// @dev Big-endian comparison of equal-length byte strings: -1, 0 or 1.
    function _cmp(bytes memory a, bytes memory b) private pure returns (int256) {
        for (uint256 i; i < a.length; ++i) {
            if (a[i] < b[i]) return -1;
            if (a[i] > b[i]) return 1;
        }
        return 0;
    }

    function _modexp(bytes memory base, bytes memory exponent, bytes memory modulus)
        private
        view
        returns (bytes memory out)
    {
        bytes memory input = abi.encodePacked(
            uint256(base.length), uint256(exponent.length), uint256(modulus.length), base, exponent, modulus
        );
        out = new bytes(modulus.length);
        uint256 outLen = modulus.length;
        bool ok;
        assembly {
            ok := staticcall(gas(), 0x05, add(input, 0x20), mload(input), add(out, 0x20), outLen)
        }
        if (!ok) return new bytes(0);
    }
}
