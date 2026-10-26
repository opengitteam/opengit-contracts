# OpenGit escrow: specification

Status: prototype, unaudited. Target: Robinhood Chain (chain 4663; testnet 46630), with the same
contracts deployable on Base.

## Goal

Anyone, human or agent, can pay any GitHub repo, before its maintainer has heard of OpenGit. The
money waits in a contract until someone proves control of the repo, then flows to the wallet they
chose. Nobody else can take it, and that includes OpenGit.

## Contracts

| Contract | Role | Admin |
|---|---|---|
| `OpenGitEscrow` | Vault addresses, tips, claims, withdrawals, refunds | None. No owner, no fee, no pause, no upgrade. |
| `RepoVault` | Holds one repo's funds; only the escrow can move them | None |
| `GitHubKeyRegistry` | GitHub's OIDC signing keys | An owner (a multisig on mainnet) can add keys after a delay and revoke keys immediately |

## Repo identity

A repo is its numeric GitHub id (`repository_id`), which survives renames and transfers. Its vault
lives at a CREATE2 address computed from that id (`vaultOf(repoId)`), so it can receive funds
before it is deployed. The site and the x402 `payTo` both use this address.

## Paying a repo

- **`tip(repoId, token, amount)`**: an ERC-20 transfer into the vault, recorded per tipper. While
  the repo is unclaimed, the tip is refundable `REFUND_AFTER` (default 365 days) after the
  tipper's last tip to that repo.
- **Plain transfer to `vaultOf(repoId)`**: how x402 payments arrive. Reaches the maintainer the
  same way, but is not refundable (it paid for a service).

## Claiming

1. The maintainer adds `examples/opengit-claim.yml` to the repo's default branch and runs it from
   the Actions tab with their payout address. Running a `workflow_dispatch` workflow requires
   write access to the repo.
2. The workflow asks GitHub for an Actions OIDC token with
   `audience = "opengit:<chainId>:<escrow>:<payout>"` (lowercase hex addresses).
3. Anyone submits `claim(header, payload, signature, payout)`. The escrow checks:
   - header `alg` is `RS256` and `kid` is an active key in the registry;
   - the RSA signature over `header.payload` (PKCS#1 v1.5, SHA-256, MODEXP precompile);
   - `iss` is `https://token.actions.githubusercontent.com`;
   - `aud` equals `audienceFor(payout)`, binding the token to this contract, this chain and this payout;
   - `event_name` is `workflow_dispatch` (pull requests, schedules and other triggers are refused);
   - `exp` is in the future and `nbf` is not;
   - `jti` has not been used before (no replay);
   - `repository_id` and `repository_owner_id` are present.
4. The claim becomes **pending**: `CLAIM_DELAY` (default 1 day) for a repo's first payout,
   `REBIND_DELAY` (default 7 days) to change an existing one. A newer pending claim replaces an
   older one and restarts the timer.
5. After the delay, anyone calls `finalize(repoId)`. From then on, `withdraw(repoId, token)` (callable
   by anyone) sends the vault's whole balance of that token to the payout.

Because the token names the payout, submitting it on someone's behalf (a relayer paying gas, or
OpenGit's site) cannot change who gets paid. The token is also safe to print in public Actions logs.

### Collaborators and transfers

Write access is enough to run the workflow, so a collaborator could try to redirect a repo's funds.
Two rules handle this:

- **Veto.** While a payout change is pending, the current payout can `veto` it, if the claim comes
  from the same GitHub owner (`repository_owner_id`) as the active one.
- **Transfers.** If the repo has moved to a different GitHub owner, the new owner's claim cannot be
  vetoed by the previous payout; it only waits `REBIND_DELAY`.

A maintainer who never watches their repo's claims can lose a contested payout change after 7 days.
OpenGit's site should notify the current payout (and show the pending change on the repo page) to
make the veto practical.

## Refunds

`refund(repoId, token)` returns a tipper's recorded tips if the repo has no payout and no pending
claim, and `REFUND_AFTER` has passed since their last tip to it. Once a repo is claimed, all its
funds belong to the payout.

## Trust assumptions

- **GitHub** issues Actions OIDC tokens honestly and keeps its signing keys secret.
- **The key registry owner** can add a key that is not GitHub's. Mitigations: keys take
  `KEY_ADD_DELAY` (default 3 days) to activate and every proposal is an on-chain event, so anyone
  can compare it with `https://token.actions.githubusercontent.com/.well-known/jwks`
  (`node script/github-keys.mjs` does this); claims then wait `CLAIM_DELAY`/`REBIND_DELAY` on top.
  A rogue key could still be used against unclaimed repos after those delays, so the owner must be
  a multisig with public signers. Revoking a key can block new claims but never moves funds. The
  owner can renounce, at the cost of no longer following GitHub's key rotation.
- **The token contract** (USDG, USDC) behaves as an ERC-20.

## Not in scope (yet)

- Splitting payouts between several maintainers (a payout can be a splitter contract).
- Solana (planned: the same model with zero-knowledge proofs of the GitHub token).
- Per-tip notes or attribution.

## Gas

A claim costs about 1.6M gas (base64 decoding, one JSON pass and a 2048-bit RSA check). Tips,
finalize, withdraw and refunds are ordinary transfers.
