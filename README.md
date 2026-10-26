# OpenGit contracts

Trustless escrow for paying open source. Anyone (people and AI agents) can send funds to any GitHub
repo. They wait in a contract until the repo's maintainer proves control with a GitHub-signed token,
then go to the wallet the maintainer chose. Nobody else, including OpenGit, can claim or move them.

> **Prototype. Not audited. Do not use with real funds.**

- [SPEC.md](SPEC.md): the full design, checks and trust assumptions
- [examples/opengit-claim.yml](examples/opengit-claim.yml): the workflow a maintainer runs to claim
- Site: [opengit.cc](https://opengit.cc)

## How it works

```
tip / x402 payment ──▶ vaultOf(repoId)          (a fixed address per GitHub repo id)
                              │
maintainer runs a workflow ──▶ GitHub OIDC token (aud = escrow + chain + payout)
                              │
claim(token) ──▶ pending ──(1 day; 7 days to change)──▶ finalize ──▶ withdraw to payout
```

- **No admin over funds.** `OpenGitEscrow` has no owner, fee, pause or upgrade path.
- **GitHub signs the proof.** The escrow verifies the RS256 signature on-chain against GitHub's
  published keys, kept in `GitHubKeyRegistry` (keys take 3 days to activate; revocation is instant).
- **Hijack-resistant.** A collaborator's payout change can be vetoed by the current payout; a
  transferred repo's new owner cannot be blocked by the previous one.
- **Refundable tips.** Unclaimed tips can be taken back a year after the tipper's last tip.

## Contracts

| File | What |
|---|---|
| `src/OpenGitEscrow.sol` | Vaults, tips, claims, withdrawals, refunds |
| `src/RepoVault.sol` | Per-repo vault (CREATE2) |
| `src/GitHubKeyRegistry.sol` | GitHub's Actions OIDC signing keys |
| `src/lib/RsaSha256.sol` | RS256 verification via the MODEXP precompile |
| `src/lib/FlatJson.sol` | Strict single-pass reader for JWT payloads |
| `src/lib/Base64Url.sol` | Base64url decoding |

## Develop

```bash
forge build
forge test -vv
```

Tests use GitHub-shaped tokens signed with throwaway keys (`test/fixtures`). To regenerate them:

```bash
python3 -I test/fixtures/gen.py
```

## Deploy (Robinhood Chain testnet)

```bash
node script/github-keys.mjs                      # fetch GitHub's current keys
REGISTRY_OWNER=0x... forge script script/Deploy.s.sol --rpc-url robinhood_testnet --broadcast --account <keystore>
REGISTRY=0x... forge script script/Deploy.s.sol:ProposeKeys --rpc-url robinhood_testnet --broadcast --account <keystore>
```

Keys become usable 3 days after they are proposed.

## License

[MIT](LICENSE)
