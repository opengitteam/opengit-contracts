// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Reads top-level members of a flat JSON object, such as a JWT payload.
/// @dev This is a real (small) parser, not a substring search: it walks every member in order,
/// skips escaped characters inside strings, and only matches keys in key position. That matters
/// because some GitHub claims (branch names, workflow refs) are attacker-chosen text, and a
/// substring search could be fooled by a value that contains `"repository_id":"…"`.
/// Nested objects and arrays are rejected, which GitHub's Actions OIDC tokens never contain.
library FlatJson {
    error InvalidJson();
    error DuplicateKey();

    enum Kind {
        Missing,
        String,
        Number,
        Literal // true, false or null
    }

    struct Value {
        Kind kind;
        uint256 start; // inclusive, inside the quotes for strings
        uint256 end; // exclusive
    }

    /// @notice Finds `key` among the top-level members of `json`. Reverts on malformed input and
    /// on a duplicated key, so a token cannot carry two different values for the same claim.
    function get(bytes memory json, bytes memory key) internal pure returns (Value memory) {
        bytes[] memory keys = new bytes[](1);
        keys[0] = key;
        return getAll(json, keys)[0];
    }

    /// @notice Finds every key in `keys` in one pass over `json` (same rules as `get`).
    function getAll(bytes memory json, bytes[] memory keys) internal pure returns (Value[] memory found) {
        found = new Value[](keys.length);
        uint256 len = json.length;
        uint256 i = _ws(json, 0);
        if (i >= len || _at(json, i) != 0x7b) revert InvalidJson(); // {
        i = _ws(json, i + 1);
        if (i < len && _at(json, i) == 0x7d) return found; // }
        while (true) {
            (uint256 ks, uint256 ke, uint256 next) = _string(json, i);
            i = _ws(json, next);
            if (i >= len || _at(json, i) != 0x3a) revert InvalidJson(); // :
            i = _ws(json, i + 1);
            if (i >= len) revert InvalidJson();
            Value memory v;
            uint8 c = _at(json, i);
            if (c == 0x22) {
                (v.start, v.end, next) = _string(json, i);
                v.kind = Kind.String;
            } else if (c == 0x2d || (c >= 0x30 && c <= 0x39)) {
                v.start = i;
                next = i;
                while (next < len && _isNumberChar(_at(json, next))) ++next;
                v.end = next;
                v.kind = Kind.Number;
            } else if (c == 0x74 || c == 0x66 || c == 0x6e) {
                v.start = i;
                next = i;
                while (next < len && _at(json, next) >= 0x61 && _at(json, next) <= 0x7a) ++next;
                v.end = next;
                v.kind = Kind.Literal;
            } else {
                revert InvalidJson(); // objects, arrays and anything else
            }
            for (uint256 k; k < keys.length; ++k) {
                if (_equals(json, ks, ke, keys[k])) {
                    if (found[k].kind != Kind.Missing) revert DuplicateKey();
                    found[k] = v;
                }
            }
            i = _ws(json, next);
            if (i >= len) revert InvalidJson();
            c = _at(json, i);
            if (c == 0x7d) break;
            if (c != 0x2c) revert InvalidJson(); // ,
            i = _ws(json, i + 1);
        }
    }

    /// @notice The string value of `key`, raw (escapes are not decoded). Reverts if absent or not a string.
    function getString(bytes memory json, bytes memory key) internal pure returns (bytes memory) {
        return stringOf(json, get(json, key));
    }

    /// @notice The raw bytes of a string value found by `getAll`. Reverts if missing or not a string.
    function stringOf(bytes memory json, Value memory v) internal pure returns (bytes memory out) {
        if (v.kind != Kind.String) revert InvalidJson();
        out = new bytes(v.end - v.start);
        for (uint256 j; j < out.length; ++j) {
            out[j] = json[v.start + j];
        }
    }

    /// @notice keccak256 of a string value found by `getAll`, without copying it.
    function hashOf(bytes memory json, Value memory v) internal pure returns (bytes32 h) {
        if (v.kind != Kind.String) revert InvalidJson();
        uint256 start = v.start;
        uint256 n = v.end - v.start;
        assembly {
            h := keccak256(add(add(json, 0x20), start), n)
        }
    }

    /// @notice A non-negative integer value of `key`, given either as a JSON number or as a string of
    /// digits (GitHub sends ids as strings). Reverts if absent, signed, fractional or too long.
    function getUint(bytes memory json, bytes memory key) internal pure returns (uint256) {
        return uintOf(json, get(json, key));
    }

    /// @notice A non-negative integer value found by `getAll` (same rules as `getUint`).
    function uintOf(bytes memory json, Value memory v) internal pure returns (uint256 n) {
        if (v.kind != Kind.String && v.kind != Kind.Number) revert InvalidJson();
        if (v.end == v.start || v.end - v.start > 20) revert InvalidJson();
        for (uint256 j = v.start; j < v.end; ++j) {
            bytes1 c = json[j];
            if (c < "0" || c > "9") revert InvalidJson();
            n = n * 10 + (uint8(c) - 48);
        }
    }

    /// @dev Returns the content bounds of the string starting at `i` (a quote) and the index after it.
    /// @dev Byte at `i`. Callers check bounds first.
    function _at(bytes memory json, uint256 i) private pure returns (uint8 c) {
        assembly {
            c := byte(0, mload(add(add(json, 0x20), i)))
        }
    }

    function _string(bytes memory json, uint256 i) private pure returns (uint256 start, uint256 end, uint256 next) {
        uint256 len = json.length;
        if (i >= len || _at(json, i) != 0x22) revert InvalidJson();
        start = i + 1;
        uint256 j = start;
        while (true) {
            if (j >= len) revert InvalidJson();
            uint8 c = _at(json, j);
            if (c == 0x5c) {
                j += 2; // skip the escaped character (\uXXXX's hex digits are plain characters)
                continue;
            }
            if (c == 0x22) break;
            if (c < 0x20) revert InvalidJson(); // control characters must be escaped
            ++j;
        }
        return (start, j, j + 1);
    }

    function _ws(bytes memory json, uint256 i) private pure returns (uint256) {
        uint256 len = json.length;
        while (i < len) {
            uint8 c = _at(json, i);
            if (c != 0x20 && c != 0x0a && c != 0x0d && c != 0x09) break;
            ++i;
        }
        return i;
    }

    function _isNumberChar(uint8 c) private pure returns (bool) {
        return (c >= 0x30 && c <= 0x39) || c == 0x2d || c == 0x2b || c == 0x2e || c == 0x65 || c == 0x45;
    }

    function _equals(bytes memory json, uint256 start, uint256 end, bytes memory key) private pure returns (bool same) {
        uint256 n = end - start;
        if (n != key.length) return false;
        assembly {
            same := eq(keccak256(add(add(json, 0x20), start), n), keccak256(add(key, 0x20), n))
        }
    }
}
