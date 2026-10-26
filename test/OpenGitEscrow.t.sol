// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {GitHubKeyRegistry} from "../src/GitHubKeyRegistry.sol";
import {OpenGitEscrow} from "../src/OpenGitEscrow.sol";
import {FlatJson} from "../src/lib/FlatJson.sol";
import {MockToken} from "./MockToken.sol";

/// @dev Tokens come from test/fixtures/tokens.json (python3 -I test/fixtures/gen.py): real
/// GitHub Actions OIDC token layouts, signed with throwaway keys that stand in for GitHub's.
contract OpenGitEscrowTest is Test {
    uint256 constant CHAIN = 46630;
    address constant ESCROW = 0x00000000000000000000000000000000000e5c00;
    address constant A = 0x000000000000000000000000000000000000a11c; // maintainer
    address constant B = 0x000000000000000000000000000000000000b0b0; // new owner after a transfer
    address constant C = 0x000000000000000000000000000000000000C0C0; // collaborator
    uint256 constant REPO = 123456789;
    uint256 constant IAT = 1767225600;
    uint256 constant LATER = IAT + 2 days; // second-round tokens in the fixtures

    uint256 constant CLAIM_DELAY = 1 days;
    uint256 constant REBIND_DELAY = 7 days;
    uint256 constant REFUND_AFTER = 365 days;

    GitHubKeyRegistry registry;
    OpenGitEscrow escrow;
    MockToken usdg;
    string fixtures;

    address tipper = makeAddr("tipper");
    address relayer = makeAddr("relayer");

    struct Jwt {
        bytes header;
        bytes payload;
        bytes signature;
    }

    function setUp() public {
        fixtures = vm.readFile("test/fixtures/tokens.json");
        vm.chainId(CHAIN);

        // Register GitHub's (test) key well before the tokens were issued, so it is active.
        vm.warp(IAT - 4 days);
        registry = new GitHubKeyRegistry(address(this), 3 days);
        registry.proposeKey("test-key-1", vm.parseJsonBytes(fixtures, ".keys[0].modulus"), hex"010001");

        deployCodeTo(
            "OpenGitEscrow.sol:OpenGitEscrow", abi.encode(registry, CLAIM_DELAY, REBIND_DELAY, REFUND_AFTER), ESCROW
        );
        escrow = OpenGitEscrow(ESCROW);
        usdg = new MockToken();
        usdg.mint(tipper, 1_000e6);
        vm.prank(tipper);
        usdg.approve(ESCROW, type(uint256).max);

        vm.warp(IAT + 10); // tokens are valid for 300s from IAT
    }

    // ------------------------------------------------------------ helpers

    function _jwt(string memory name) internal view returns (Jwt memory t) {
        uint256 n = abi.decode(vm.parseJson(fixtures, ".tokens"), (bytes[])).length;
        for (uint256 i; i < n; ++i) {
            string memory p = string.concat(".tokens[", vm.toString(i), "]");
            if (keccak256(bytes(vm.parseJsonString(fixtures, string.concat(p, ".name")))) == keccak256(bytes(name))) {
                t.header = bytes(vm.parseJsonString(fixtures, string.concat(p, ".header")));
                t.payload = bytes(vm.parseJsonString(fixtures, string.concat(p, ".payload")));
                t.signature = vm.parseJsonBytes(fixtures, string.concat(p, ".signature"));
                return t;
            }
        }
        revert(string.concat("no fixture ", name));
    }

    function _claim(string memory name, address payout) internal {
        Jwt memory t = _jwt(name);
        escrow.claim(t.header, t.payload, t.signature, payout);
    }

    function _expectClaimRevert(string memory name, address payout, string memory reason) internal {
        Jwt memory t = _jwt(name);
        vm.expectRevert(abi.encodeWithSelector(OpenGitEscrow.InvalidToken.selector, reason));
        escrow.claim(t.header, t.payload, t.signature, payout);
    }

    function _pending(uint256 repoId) internal view returns (address pending, uint64 readyAt) {
        (,, pending,, readyAt) = escrow.repos(repoId);
    }

    function _payout(uint256 repoId) internal view returns (address payout) {
        (payout,,,,) = escrow.repos(repoId);
    }

    /// @dev A claimed and finalized by the maintainer; the clock is then where second-round tokens are valid.
    function _claimedByA() internal {
        _claim("valid_a", A);
        vm.warp(block.timestamp + CLAIM_DELAY);
        escrow.finalize(REPO);
        vm.warp(LATER + 10);
    }

    // ------------------------------------------------------------ setup checks

    function test_audienceMatchesFixtures() public view {
        assertEq(
            escrow.audienceFor(A),
            string.concat(
                "opengit:46630:0x00000000000000000000000000000000000e5c00:",
                "0x000000000000000000000000000000000000a11c"
            )
        );
    }

    function test_vaultAddressIsFixedAndFundableBeforeDeployment() public {
        address v = escrow.vaultOf(REPO);
        assertEq(v, escrow.vaultOf(REPO));
        assertTrue(v != escrow.vaultOf(REPO + 1));
        assertEq(v.code.length, 0);
        // An agent (x402 payTo) or anyone can send funds straight to it.
        vm.prank(tipper);
        usdg.transfer(v, 25e6);
        assertEq(usdg.balanceOf(v), 25e6);
    }

    // ------------------------------------------------------------ happy path

    function test_claimFinalizeWithdraw() public {
        address v = escrow.vaultOf(REPO);
        vm.prank(tipper);
        usdg.transfer(v, 100e6); // plain transfer, like an x402 payment
        vm.prank(tipper);
        escrow.tip(REPO, address(usdg), 50e6);

        vm.prank(relayer); // anyone can submit; the token names the payout
        _claim("valid_a", A);
        (address pending, uint64 readyAt) = _pending(REPO);
        assertEq(pending, A);
        assertEq(readyAt, block.timestamp + CLAIM_DELAY);

        vm.expectRevert(OpenGitEscrow.NotReady.selector);
        escrow.finalize(REPO);
        vm.expectRevert(OpenGitEscrow.Unclaimed.selector);
        escrow.withdraw(REPO, address(usdg));

        vm.warp(readyAt);
        escrow.finalize(REPO);
        assertEq(_payout(REPO), A);

        vm.prank(relayer); // anyone can trigger a withdrawal; it always goes to the payout
        assertEq(escrow.withdraw(REPO, address(usdg)), 150e6);
        assertEq(usdg.balanceOf(A), 150e6);
        assertEq(usdg.balanceOf(v), 0);
        assertGt(v.code.length, 0);

        // Later payments keep flowing to the maintainer.
        vm.prank(tipper);
        escrow.tip(REPO, address(usdg), 5e6);
        escrow.withdraw(REPO, address(usdg));
        assertEq(usdg.balanceOf(A), 155e6);
    }

    // ------------------------------------------------------------ token checks

    function test_rejectsPayoutNotInAudience() public {
        _expectClaimRevert("valid_a", B, "aud"); // a relayer cannot swap in its own payout
    }

    function test_rejectsReplay() public {
        _claim("valid_a", A);
        _expectClaimRevert("valid_a", A, "jti");
    }

    function test_rejectsPullRequestEvent() public {
        _expectClaimRevert("pull_request", A, "event_name");
    }

    function test_rejectsOtherIssuer() public {
        _expectClaimRevert("wrong_issuer", A, "iss");
    }

    function test_rejectsUnknownKey() public {
        _expectClaimRevert("unknown_key", A, "kid");
    }

    function test_rejectsSignatureFromAnotherKey() public {
        _expectClaimRevert("signed_by_other_key", A, "signature");
    }

    function test_rejectsTamperedPayload() public {
        _expectClaimRevert("tampered", A, "signature");
    }

    function test_rejectsNonRs256() public {
        _expectClaimRevert("alg_hs256", A, "alg");
    }

    function test_rejectsExpiredToken() public {
        vm.warp(IAT + 300);
        _expectClaimRevert("valid_a", A, "exp");
    }

    function test_rejectsRevokedKey() public {
        registry.revokeKey("test-key-1");
        _expectClaimRevert("valid_a", A, "kid");
    }

    function test_rejectsKeyBeforeItIsActive() public {
        vm.warp(IAT - 4 days);
        GitHubKeyRegistry fresh = new GitHubKeyRegistry(address(this), 3 days);
        fresh.proposeKey("test-key-1", vm.parseJsonBytes(fixtures, ".keys[0].modulus"), hex"010001");
        deployCodeTo(
            "OpenGitEscrow.sol:OpenGitEscrow", abi.encode(fresh, CLAIM_DELAY, REBIND_DELAY, REFUND_AFTER), ESCROW
        );
        vm.warp(IAT + 10);
        // Proposed at IAT-4d with a 3-day delay: active. Now one proposed too late:
        vm.warp(IAT - 1 days);
        GitHubKeyRegistry late = new GitHubKeyRegistry(address(this), 3 days);
        late.proposeKey("test-key-1", vm.parseJsonBytes(fixtures, ".keys[0].modulus"), hex"010001");
        deployCodeTo(
            "OpenGitEscrow.sol:OpenGitEscrow", abi.encode(late, CLAIM_DELAY, REBIND_DELAY, REFUND_AFTER), ESCROW
        );
        vm.warp(IAT + 10);
        _expectClaimRevert("valid_a", A, "kid");
    }

    function test_branchNameCannotSmuggleARepoId() public {
        _claim("smuggled_ref", A);
        (address pending,) = _pending(REPO);
        assertEq(pending, A); // the real repository_id
        (address other,) = _pending(424242);
        assertEq(other, address(0));
    }

    function test_rejectsDuplicateClaim() public {
        Jwt memory t = _jwt("duplicate_key");
        vm.expectRevert(FlatJson.DuplicateKey.selector);
        escrow.claim(t.header, t.payload, t.signature, A);
    }

    // ------------------------------------------------------------ hijack and transfer

    function test_collaboratorCannotRedirectWhenVetoed() public {
        _claimedByA();
        _claim("collaborator_c", C); // write access is enough to run the workflow
        (address pending, uint64 readyAt) = _pending(REPO);
        assertEq(pending, C);
        assertEq(readyAt, block.timestamp + REBIND_DELAY);

        vm.prank(C);
        vm.expectRevert(OpenGitEscrow.NotPayout.selector);
        escrow.veto(REPO);

        vm.prank(A);
        escrow.veto(REPO);
        (pending,) = _pending(REPO);
        assertEq(pending, address(0));
        assertEq(_payout(REPO), A);
    }

    function test_rebindWaitsTheLongerDelay() public {
        _claimedByA();
        _claim("collaborator_c", C);
        vm.warp(block.timestamp + CLAIM_DELAY);
        vm.expectRevert(OpenGitEscrow.NotReady.selector);
        escrow.finalize(REPO);
        vm.warp(block.timestamp + REBIND_DELAY - CLAIM_DELAY);
        escrow.finalize(REPO);
        assertEq(_payout(REPO), C); // an unwatched payout loses to a patient collaborator: the veto is the defense
    }

    function test_previousOwnerCannotBlockATransferredRepo() public {
        _claimedByA();
        _claim("transferred_b", B); // repository_owner_id changed: the repo moved to a new owner
        vm.prank(A);
        vm.expectRevert(OpenGitEscrow.NotVetoable.selector);
        escrow.veto(REPO);
        vm.warp(block.timestamp + REBIND_DELAY);
        escrow.finalize(REPO);
        assertEq(_payout(REPO), B);
    }

    function test_maintainerCanReplaceAPendingClaim() public {
        _claim("collaborator_c_early", C); // a collaborator gets in first, before any payout exists
        _claim("valid_a", A); // the maintainer claims too: latest claim wins and the timer restarts
        (address pending, uint64 readyAt) = _pending(REPO);
        assertEq(pending, A);
        assertEq(readyAt, block.timestamp + CLAIM_DELAY);
    }

    // ------------------------------------------------------------ refunds

    function test_refundUnclaimedTipAfterWindow() public {
        vm.prank(tipper);
        escrow.tip(REPO, address(usdg), 40e6);
        vm.prank(tipper);
        vm.expectRevert(OpenGitEscrow.RefundUnavailable.selector);
        escrow.refund(REPO, address(usdg));

        vm.warp(block.timestamp + REFUND_AFTER);
        vm.prank(tipper);
        assertEq(escrow.refund(REPO, address(usdg)), 40e6);
        assertEq(usdg.balanceOf(tipper), 1_000e6);

        vm.prank(tipper);
        vm.expectRevert(OpenGitEscrow.ZeroAmount.selector);
        escrow.refund(REPO, address(usdg));
    }

    function test_plainTransfersAreNotRefundable() public {
        vm.startPrank(tipper);
        usdg.transfer(escrow.vaultOf(REPO), 10e6);
        vm.warp(block.timestamp + REFUND_AFTER);
        vm.expectRevert(OpenGitEscrow.ZeroAmount.selector);
        escrow.refund(REPO, address(usdg));
        vm.stopPrank();
    }

    function test_noRefundWhileClaimPendingOrAfterClaim() public {
        vm.prank(tipper);
        escrow.tip(REPO, address(usdg), 40e6);
        vm.warp(block.timestamp + REFUND_AFTER);
        // A fresh token can only be valid now if the fixture times allowed; use a pending claim made earlier instead.
        vm.warp(IAT + 10);
        _claim("valid_a", A);
        vm.warp(IAT + 10 + REFUND_AFTER);
        vm.prank(tipper);
        vm.expectRevert(OpenGitEscrow.RefundUnavailable.selector);
        escrow.refund(REPO, address(usdg));

        escrow.finalize(REPO);
        vm.prank(tipper);
        vm.expectRevert(OpenGitEscrow.RefundUnavailable.selector);
        escrow.refund(REPO, address(usdg));
        assertEq(escrow.withdraw(REPO, address(usdg)), 40e6);
    }

    function test_refundWindowRestartsWithEachTip() public {
        vm.prank(tipper);
        escrow.tip(REPO, address(usdg), 10e6);
        vm.warp(block.timestamp + 200 days);
        vm.prank(tipper);
        escrow.tip(REPO, address(usdg), 10e6);
        vm.warp(block.timestamp + 200 days); // 400 days after the first tip, 200 after the last
        vm.prank(tipper);
        vm.expectRevert(OpenGitEscrow.RefundUnavailable.selector);
        escrow.refund(REPO, address(usdg));
    }

    function test_claimGas() public {
        Jwt memory t = _jwt("valid_a");
        uint256 g = gasleft();
        escrow.claim(t.header, t.payload, t.signature, A);
        emit log_named_uint("claim gas", g - gasleft());
    }

    function test_rejectsZeroTip() public {
        vm.prank(tipper);
        vm.expectRevert(OpenGitEscrow.ZeroAmount.selector);
        escrow.tip(REPO, address(usdg), 0);
    }

    // ------------------------------------------------------------ registry

    function test_registryOnlyOwnerAndDelay() public {
        GitHubKeyRegistry r = new GitHubKeyRegistry(address(this), 3 days);
        bytes memory n = vm.parseJsonBytes(fixtures, ".keys[1].modulus");

        vm.prank(relayer);
        vm.expectRevert(GitHubKeyRegistry.NotOwner.selector);
        r.proposeKey("k", n, hex"010001");

        r.proposeKey("k", n, hex"010001");
        (bytes memory m,) = r.activeKey("k");
        assertEq(m.length, 0); // not yet
        vm.warp(block.timestamp + 3 days);
        (m,) = r.activeKey("k");
        assertEq(m, n);

        vm.expectRevert(GitHubKeyRegistry.KeyExists.selector);
        r.proposeKey("k", n, hex"010001");

        r.revokeKey("k");
        (m,) = r.activeKey("k");
        assertEq(m.length, 0);
    }

    function test_registryRejectsWeakKeysAndShortDelay() public {
        vm.expectRevert(GitHubKeyRegistry.DelayTooShort.selector);
        new GitHubKeyRegistry(address(this), 1 hours);
        GitHubKeyRegistry r = new GitHubKeyRegistry(address(this), 1 days);
        vm.expectRevert(GitHubKeyRegistry.BadKey.selector);
        r.proposeKey("short", new bytes(128), hex"010001");
    }

    function test_registryOwnershipIsTwoStepAndRenounceable() public {
        GitHubKeyRegistry r = new GitHubKeyRegistry(address(this), 1 days);
        r.transferOwnership(relayer);
        assertEq(r.owner(), address(this));
        vm.expectRevert(GitHubKeyRegistry.NotPendingOwner.selector);
        r.acceptOwnership();
        vm.prank(relayer);
        r.acceptOwnership();
        assertEq(r.owner(), relayer);
        vm.prank(relayer);
        r.renounceOwnership();
        assertEq(r.owner(), address(0));
    }
}
