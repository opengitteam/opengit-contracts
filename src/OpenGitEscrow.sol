// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {GitHubKeyRegistry} from "./GitHubKeyRegistry.sol";
import {RepoVault} from "./RepoVault.sol";
import {Base64Url} from "./lib/Base64Url.sol";
import {FlatJson} from "./lib/FlatJson.sol";
import {RsaSha256} from "./lib/RsaSha256.sol";
import {SafeTransfer} from "./lib/SafeTransfer.sol";

/// @title OpenGitEscrow
/// @notice Holds tips and agent payments for GitHub repos until the repo's maintainer claims them.
///
/// Every repo has a vault at a fixed address derived from its numeric GitHub id (`vaultOf`), so
/// anyone can pay a repo before its maintainer has heard of OpenGit: humans with `tip`, agents
/// with plain transfers (x402 `payTo`). Funds leave a vault in exactly two ways:
///  - to the repo's payout address, once a maintainer has proven control of the repo, or
///  - back to a tipper, if the repo is still unclaimed `REFUND_AFTER` after their last tip.
///
/// Proof of control is a GitHub Actions OIDC token (a JWT signed by GitHub) from a manually run
/// workflow in the repo, with an audience that names this contract, this chain and the payout
/// address. The contract checks GitHub's signature itself; nobody, including OpenGit, can claim
/// or move funds on a maintainer's behalf. There is no owner, no admin, no fee and no upgrade.
/// The only trusted input is the set of GitHub signing keys in `GitHubKeyRegistry`.
///
/// Claims take effect after a delay. While a new payout is pending, the current payout can veto
/// it, unless the repo's GitHub owner changed (a transferred repo), so a collaborator with write
/// access cannot redirect funds, and a previous owner cannot block a repo's new owner.
contract OpenGitEscrow {
    using FlatJson for bytes;

    string public constant ISSUER = "https://token.actions.githubusercontent.com";

    GitHubKeyRegistry public immutable keys;
    /// @notice Wait before a repo's first payout address takes effect.
    uint256 public immutable CLAIM_DELAY;
    /// @notice Wait before a change of payout address takes effect.
    uint256 public immutable REBIND_DELAY;
    /// @notice How long after their last tip a tipper can take an unclaimed tip back.
    uint256 public immutable REFUND_AFTER;

    struct Repo {
        address payout; // active payout, 0 until the first claim is finalized
        uint64 ownerId; // GitHub repository_owner_id at the time of the active claim
        address pending; // proposed payout
        uint64 pendingOwnerId;
        uint64 pendingReadyAt;
    }

    mapping(uint256 repoId => Repo) public repos;
    /// @notice Refundable tips: repo => token => tipper => amount.
    mapping(uint256 => mapping(address => mapping(address => uint256))) public tips;
    mapping(uint256 => mapping(address => uint64)) public lastTipAt;
    /// @notice Token ids (jti) already used, so a token cannot be replayed.
    mapping(bytes32 => bool) public usedTokens;

    uint256 private _lock = 1;

    event Tipped(uint256 indexed repoId, address indexed token, address indexed from, uint256 amount);
    event ClaimStarted(uint256 indexed repoId, address indexed payout, uint64 ownerId, uint64 readyAt, bool vetoable);
    event ClaimFinalized(uint256 indexed repoId, address indexed payout);
    event ClaimVetoed(uint256 indexed repoId, address indexed vetoedPayout);
    event Withdrawn(uint256 indexed repoId, address indexed token, address indexed payout, uint256 amount);
    event Refunded(uint256 indexed repoId, address indexed token, address indexed tipper, uint256 amount);

    error InvalidToken(string reason);
    error NothingPending();
    error NotReady();
    error NotPayout();
    error NotVetoable();
    error Unclaimed();
    error RefundUnavailable();
    error ZeroAmount();
    error Reentrancy();

    modifier nonReentrant() {
        if (_lock != 1) revert Reentrancy();
        _lock = 2;
        _;
        _lock = 1;
    }

    constructor(GitHubKeyRegistry keys_, uint256 claimDelay, uint256 rebindDelay, uint256 refundAfter) {
        keys = keys_;
        CLAIM_DELAY = claimDelay;
        REBIND_DELAY = rebindDelay;
        REFUND_AFTER = refundAfter;
    }

    // ---------------------------------------------------------------- vaults

    /// @notice The address that holds funds for GitHub repo `repoId`, deployed or not.
    function vaultOf(uint256 repoId) public view returns (address) {
        bytes32 h = keccak256(
            abi.encodePacked(bytes1(0xff), address(this), bytes32(repoId), keccak256(type(RepoVault).creationCode))
        );
        return address(uint160(uint256(h)));
    }

    function _vault(uint256 repoId) internal returns (RepoVault) {
        address v = vaultOf(repoId);
        if (v.code.length == 0) new RepoVault{salt: bytes32(repoId)}();
        return RepoVault(v);
    }

    // ---------------------------------------------------------------- paying

    /// @notice Tip a repo. While the repo is unclaimed, your tip is refundable after `REFUND_AFTER`.
    /// Needs an ERC-20 approval for this contract. Plain transfers to `vaultOf(repoId)` also reach
    /// the maintainer, but are not refundable.
    function tip(uint256 repoId, address token, uint256 amount) external nonReentrant {
        if (amount == 0) revert ZeroAmount();
        SafeTransfer.transferFrom(token, msg.sender, vaultOf(repoId), amount);
        if (repos[repoId].payout == address(0)) {
            tips[repoId][token][msg.sender] += amount;
            lastTipAt[repoId][msg.sender] = uint64(block.timestamp);
        }
        emit Tipped(repoId, token, msg.sender, amount);
    }

    // ---------------------------------------------------------------- claiming

    /// @notice The `audience` a maintainer's claim workflow must request for `payout`.
    /// Format: `opengit:<chain id>:<this contract>:<payout>`, addresses as lowercase hex.
    function audienceFor(address payout) public view returns (string memory) {
        return string.concat("opengit:", _uintToString(block.chainid), ":", _hex(address(this)), ":", _hex(payout));
    }

    /// @notice Start a claim with a GitHub Actions OIDC token. Anyone may submit it (a relayer can
    /// pay the gas): the token itself names the payout, so submitting it cannot change who is paid.
    /// @param header The JWT's first part (base64url), as issued.
    /// @param payload The JWT's second part (base64url), as issued.
    /// @param signature The JWT's third part, base64url-decoded.
    function claim(bytes calldata header, bytes calldata payload, bytes calldata signature, address payout) external {
        if (payout == address(0)) revert InvalidToken("payout");
        (uint256 repoId, uint64 ownerId) = _verify(header, payload, signature, payout);

        Repo storage r = repos[repoId];
        bool first = r.payout == address(0);
        // A collaborator's claim on the same owner's repo can be vetoed by the current payout;
        // a claim after the repo moved to a different GitHub owner cannot.
        bool vetoable = !first && ownerId == r.ownerId;
        uint64 readyAt = uint64(block.timestamp + (first ? CLAIM_DELAY : REBIND_DELAY));
        r.pending = payout;
        r.pendingOwnerId = ownerId;
        r.pendingReadyAt = readyAt;
        emit ClaimStarted(repoId, payout, ownerId, readyAt, vetoable);
    }

    /// @notice Make a pending payout active once its delay has passed. Anyone may call it.
    function finalize(uint256 repoId) external {
        Repo storage r = repos[repoId];
        if (r.pending == address(0)) revert NothingPending();
        if (block.timestamp < r.pendingReadyAt) revert NotReady();
        r.payout = r.pending;
        r.ownerId = r.pendingOwnerId;
        r.pending = address(0);
        r.pendingOwnerId = 0;
        r.pendingReadyAt = 0;
        emit ClaimFinalized(repoId, r.payout);
    }

    /// @notice The current payout can cancel a pending change, unless the repo changed owner.
    function veto(uint256 repoId) external {
        Repo storage r = repos[repoId];
        if (r.pending == address(0)) revert NothingPending();
        if (msg.sender != r.payout) revert NotPayout();
        if (r.pendingOwnerId != r.ownerId) revert NotVetoable();
        emit ClaimVetoed(repoId, r.pending);
        r.pending = address(0);
        r.pendingOwnerId = 0;
        r.pendingReadyAt = 0;
    }

    // ---------------------------------------------------------------- withdrawing

    /// @notice Send a claimed repo's whole balance of `token` to its payout. Anyone may call it.
    function withdraw(uint256 repoId, address token) external nonReentrant returns (uint256 amount) {
        address payout = repos[repoId].payout;
        if (payout == address(0)) revert Unclaimed();
        amount = _balanceOf(token, vaultOf(repoId));
        if (amount == 0) revert ZeroAmount();
        _vault(repoId).pull(token, payout, amount);
        emit Withdrawn(repoId, token, payout, amount);
    }

    /// @notice Take back your tips to a repo that is still unclaimed `REFUND_AFTER` after your
    /// last tip to it. Not available while a claim is pending.
    function refund(uint256 repoId, address token) external nonReentrant returns (uint256 amount) {
        Repo storage r = repos[repoId];
        if (r.payout != address(0) || r.pending != address(0)) revert RefundUnavailable();
        if (block.timestamp < uint256(lastTipAt[repoId][msg.sender]) + REFUND_AFTER) revert RefundUnavailable();
        amount = tips[repoId][token][msg.sender];
        if (amount == 0) revert ZeroAmount();
        tips[repoId][token][msg.sender] = 0;
        _vault(repoId).pull(token, msg.sender, amount);
        emit Refunded(repoId, token, msg.sender, amount);
    }

    // ---------------------------------------------------------------- token verification

    function _verify(bytes calldata header, bytes calldata payload, bytes calldata signature, address payout)
        internal
        returns (uint256 repoId, uint64 ownerId)
    {
        bytes memory h = Base64Url.decode(header);
        if (keccak256(h.getString("alg")) != keccak256("RS256")) revert InvalidToken("alg");
        (bytes memory modulus, bytes memory exponent) = keys.activeKey(h.getString("kid"));
        if (modulus.length == 0) revert InvalidToken("kid");
        if (!RsaSha256.verify(bytes.concat(header, ".", payload), signature, modulus, exponent)) {
            revert InvalidToken("signature");
        }

        bytes memory p = Base64Url.decode(payload);
        bytes[] memory names = new bytes[](9);
        names[0] = "iss";
        names[1] = "aud";
        names[2] = "event_name";
        names[3] = "exp";
        names[4] = "nbf";
        names[5] = "jti";
        names[6] = "repository_id";
        names[7] = "repository_owner_id";
        names[8] = "iat";
        FlatJson.Value[] memory v = FlatJson.getAll(p, names);

        if (FlatJson.hashOf(p, v[0]) != keccak256(bytes(ISSUER))) revert InvalidToken("iss");
        if (FlatJson.hashOf(p, v[1]) != keccak256(bytes(audienceFor(payout)))) revert InvalidToken("aud");
        // A manual run needs write access to the repo. Other events (pull requests, schedules) are refused.
        if (FlatJson.hashOf(p, v[2]) != keccak256("workflow_dispatch")) revert InvalidToken("event_name");
        if (FlatJson.uintOf(p, v[3]) <= block.timestamp) revert InvalidToken("exp");
        if (FlatJson.uintOf(p, v[4]) > block.timestamp + 60) revert InvalidToken("nbf");

        bytes32 jti = FlatJson.hashOf(p, v[5]);
        if (usedTokens[jti]) revert InvalidToken("jti");
        usedTokens[jti] = true;

        repoId = FlatJson.uintOf(p, v[6]);
        uint256 owner = FlatJson.uintOf(p, v[7]);
        if (repoId == 0 || owner == 0 || owner > type(uint64).max) revert InvalidToken("repository");
        ownerId = uint64(owner);
    }

    // ---------------------------------------------------------------- helpers

    function _balanceOf(address token, address account) internal view returns (uint256) {
        (bool ok, bytes memory ret) = token.staticcall(abi.encodeWithSelector(0x70a08231, account));
        if (!ok || ret.length < 32) return 0;
        return abi.decode(ret, (uint256));
    }

    function _hex(address a) internal pure returns (string memory) {
        bytes memory out = new bytes(42);
        out[0] = "0";
        out[1] = "x";
        bytes16 digits = "0123456789abcdef";
        uint160 v = uint160(a);
        for (uint256 i = 41; i > 1; --i) {
            out[i] = digits[v & 0xf];
            v >>= 4;
        }
        return string(out);
    }

    function _uintToString(uint256 v) internal pure returns (string memory) {
        if (v == 0) return "0";
        uint256 len;
        for (uint256 t = v; t != 0; t /= 10) {
            ++len;
        }
        bytes memory out = new bytes(len);
        for (; v != 0; v /= 10) {
            out[--len] = bytes1(uint8(48 + (v % 10)));
        }
        return string(out);
    }
}
