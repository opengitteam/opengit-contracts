// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title GitHubKeyRegistry
/// @notice The RSA public keys GitHub signs Actions OIDC tokens with
/// (https://token.actions.githubusercontent.com/.well-known/jwks), keyed by `kid`.
/// @dev This is the one trusted piece of the system, so it is deliberately narrow and slow:
///  - Adding a key takes `ADD_DELAY` (fixed at deploy), so anyone watching can see a key coming
///    and compare it with GitHub's published keys before it can be used.
///  - Revoking a key is immediate, so a leaked or retired GitHub key can be shut off at once.
///    Revoking can stop new claims, but it can never move funds.
///  - The owner should be a multisig. Ownership transfer is two-step and can be renounced.
contract GitHubKeyRegistry {
    struct Key {
        bytes modulus;
        bytes exponent;
        uint64 activeFrom; // 0 = never proposed
        bool revoked;
    }

    uint256 public immutable ADD_DELAY;
    address public owner;
    address public pendingOwner;

    mapping(bytes32 kidHash => Key) internal _keys;

    event KeyProposed(string kid, bytes modulus, bytes exponent, uint64 activeFrom);
    event KeyRevoked(string kid);
    event OwnershipTransferStarted(address indexed from, address indexed to);
    event OwnershipTransferred(address indexed from, address indexed to);

    error NotOwner();
    error NotPendingOwner();
    error KeyExists();
    error BadKey();
    error DelayTooShort();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor(address initialOwner, uint256 addDelay) {
        if (addDelay < 1 days) revert DelayTooShort();
        ADD_DELAY = addDelay;
        owner = initialOwner;
        emit OwnershipTransferred(address(0), initialOwner);
    }

    /// @notice Announce a key. It can verify tokens once `ADD_DELAY` has passed.
    /// A kid can be proposed once; a revoked kid stays revoked.
    function proposeKey(string calldata kid, bytes calldata modulus, bytes calldata exponent) external onlyOwner {
        Key storage k = _keys[keccak256(bytes(kid))];
        if (k.activeFrom != 0) revert KeyExists();
        // RS256 keys from GitHub are 2048-bit; allow up to 4096. Exponent is normally 65537.
        if (
            modulus.length < 256 || modulus.length > 512 || modulus[0] == 0 || exponent.length == 0
                || exponent.length > 32
        ) {
            revert BadKey();
        }
        uint64 activeFrom = uint64(block.timestamp + ADD_DELAY);
        _keys[keccak256(bytes(kid))] = Key(modulus, exponent, activeFrom, false);
        emit KeyProposed(kid, modulus, exponent, activeFrom);
    }

    /// @notice Stop a key from verifying any further tokens. Immediate and permanent.
    function revokeKey(string calldata kid) external onlyOwner {
        Key storage k = _keys[keccak256(bytes(kid))];
        if (k.activeFrom == 0) revert BadKey();
        k.revoked = true;
        emit KeyRevoked(kid);
    }

    /// @notice The key for `kid` if it is active, or empty bytes.
    function activeKey(bytes memory kid) external view returns (bytes memory modulus, bytes memory exponent) {
        Key storage k = _keys[keccak256(kid)];
        if (k.activeFrom == 0 || k.revoked || block.timestamp < k.activeFrom) return ("", "");
        return (k.modulus, k.exponent);
    }

    function keyInfo(string calldata kid) external view returns (Key memory) {
        return _keys[keccak256(bytes(kid))];
    }

    function transferOwnership(address to) external onlyOwner {
        pendingOwner = to;
        emit OwnershipTransferStarted(owner, to);
    }

    function acceptOwnership() external {
        if (msg.sender != pendingOwner) revert NotPendingOwner();
        emit OwnershipTransferred(owner, msg.sender);
        owner = msg.sender;
        pendingOwner = address(0);
    }

    /// @notice Give up ownership for good: no key can ever be added or revoked again.
    function renounceOwnership() external onlyOwner {
        emit OwnershipTransferred(owner, address(0));
        owner = address(0);
        pendingOwner = address(0);
    }
}
