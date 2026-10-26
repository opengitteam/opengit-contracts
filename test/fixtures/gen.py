"""Generates test/fixtures/tokens.json: GitHub Actions OIDC-shaped JWTs signed with throwaway
RSA test keys (standing in for GitHub's), for the escrow tests.

Usage: python3 -I test/fixtures/gen.py   (needs the openssl CLI)

The private keys live in a temp dir and are deleted; only public moduli and signed tokens are kept.
Values here must match the constants in test/OpenGitEscrow.t.sol.
"""
import base64, json, os, subprocess, sys, tempfile

CHAIN = 46630  # Robinhood Chain testnet
ESCROW = "0x00000000000000000000000000000000000e5c00"
PAYOUT_A = "0x000000000000000000000000000000000000a11c"  # maintainer
PAYOUT_B = "0x000000000000000000000000000000000000b0b0"  # new owner after a transfer
PAYOUT_C = "0x000000000000000000000000000000000000c0c0"  # collaborator with write access
REPO, OWNER, NEW_OWNER = 123456789, 1111, 2222
IAT = 1767225600  # 2026-01-01T00:00:00Z
LATER = IAT + 2 * 86400  # second-round tokens, run after the first claim has finalized
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tokens.json")


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def aud(payout: str) -> str:
    return f"opengit:{CHAIN}:{ESCROW}:{payout}"


def claims(**over):
    """A payload shaped like a real token.actions.githubusercontent.com token."""
    c = {
        "jti": "00000000-0000-0000-0000-000000000001",
        "sub": "repo:octo-org/octo-repo:ref:refs/heads/main",
        "aud": aud(PAYOUT_A),
        "ref": "refs/heads/main",
        "sha": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4",
        "repository": "octo-org/octo-repo",
        "repository_owner": "octo-org",
        "repository_owner_id": str(OWNER),
        "run_id": "6900000000",
        "run_number": "1",
        "run_attempt": "1",
        "repository_visibility": "public",
        "repository_id": str(REPO),
        "actor_id": "9999",
        "actor": "octocat",
        "workflow": "OpenGit claim",
        "head_ref": "",
        "base_ref": "",
        "event_name": "workflow_dispatch",
        "ref_protected": "true",
        "ref_type": "branch",
        "workflow_ref": "octo-org/octo-repo/.github/workflows/opengit-claim.yml@refs/heads/main",
        "workflow_sha": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4",
        "job_workflow_ref": "octo-org/octo-repo/.github/workflows/opengit-claim.yml@refs/heads/main",
        "job_workflow_sha": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4",
        "runner_environment": "github-hosted",
        "iss": "https://token.actions.githubusercontent.com",
        "nbf": IAT,
        "exp": IAT + 300,
        "iat": IAT,
    }
    c.update(over)
    return c


def run(*args, data=None):
    return subprocess.run(args, input=data, capture_output=True, check=True).stdout


def main():
    tmp = tempfile.mkdtemp()
    keys = {}
    for kid in ("test-key-1", "test-key-2"):
        pem = os.path.join(tmp, f"{kid}.pem")
        run("openssl", "genrsa", "-out", pem, "2048")
        mod = run("openssl", "rsa", "-in", pem, "-noout", "-modulus").decode().strip().split("=", 1)[1]
        keys[kid] = {"pem": pem, "modulus": "0x" + mod.lower()}

    def token(name, payload, kid="test-key-1", sign_with=None, header=None, raw_payload=None, swap_payload=None):
        h = header or {"alg": "RS256", "kid": kid, "typ": "JWT", "x5t": "test"}
        hb = b64u(json.dumps(h, separators=(",", ":")).encode())
        pb = b64u(raw_payload.encode() if raw_payload is not None else json.dumps(payload, separators=(",", ":")).encode())
        sig = run("openssl", "dgst", "-sha256", "-sign", keys[sign_with or kid]["pem"], data=f"{hb}.{pb}".encode())
        if swap_payload is not None:  # signed one payload, then swap in another
            pb = b64u(json.dumps(swap_payload, separators=(",", ":")).encode())
        return {"name": name, "header": hb, "payload": pb, "signature": "0x" + sig.hex()}

    tokens = [
        token("valid_a", claims()),
        token("valid_a_again", claims(jti="00000000-0000-0000-0000-00000000000a")),
        token("collaborator_c_early", claims(aud=aud(PAYOUT_C), jti="00000000-0000-0000-0000-0000000000c0", actor="mallory")),
        token("collaborator_c", claims(aud=aud(PAYOUT_C), jti="00000000-0000-0000-0000-00000000000c", actor="mallory", iat=LATER, nbf=LATER, exp=LATER + 300)),
        token("transferred_b", claims(aud=aud(PAYOUT_B), jti="00000000-0000-0000-0000-00000000000b", repository_owner_id=str(NEW_OWNER), repository="new-org/octo-repo", repository_owner="new-org", iat=LATER, nbf=LATER, exp=LATER + 300)),
        token("pull_request", claims(event_name="pull_request", jti="00000000-0000-0000-0000-000000000002")),
        token("wrong_issuer", claims(iss="https://evil.example.com", jti="00000000-0000-0000-0000-000000000003")),
        token("unknown_key", claims(jti="00000000-0000-0000-0000-000000000004"), kid="test-key-2"),
        token("signed_by_other_key", claims(jti="00000000-0000-0000-0000-000000000005"), kid="test-key-1", sign_with="test-key-2"),
        token("tampered", claims(jti="00000000-0000-0000-0000-000000000006"), swap_payload=claims(jti="00000000-0000-0000-0000-000000000006", repository_id="424242")),
        token("alg_hs256", claims(jti="00000000-0000-0000-0000-000000000007"), header={"alg": "HS256", "kid": "test-key-1", "typ": "JWT"}),
        # A branch name that tries to smuggle a second repository_id into the payload. Git allows
        # quotes and commas in ref names; JSON escapes the quotes, so it must not match as a key.
        token("smuggled_ref", claims(jti="00000000-0000-0000-0000-000000000008", ref='refs/heads/x","repository_id":"424242', sub='repo:octo-org/octo-repo:ref:refs/heads/x","repository_id":"424242')),
        # A payload with repository_id twice (not something GitHub issues, but the parser must refuse it).
        token("duplicate_key", None, raw_payload=json.dumps(claims(jti="00000000-0000-0000-0000-000000000009"), separators=(",", ":"))[:-1] + ',"repository_id":"424242"}'),
    ]

    out = {
        "chainId": CHAIN,
        "escrow": ESCROW,
        "payoutA": PAYOUT_A,
        "payoutB": PAYOUT_B,
        "payoutC": PAYOUT_C,
        "repoId": REPO,
        "iat": IAT,
        "later": LATER,
        "keys": [{"kid": k, "modulus": v["modulus"]} for k, v in keys.items()],
        "tokens": tokens,
    }
    with open(OUT, "w") as f:
        json.dump(out, f, indent=2)
    for v in keys.values():
        os.remove(v["pem"])
    os.rmdir(tmp)
    print(f"wrote {OUT}: {len(tokens)} tokens")


if __name__ == "__main__":
    sys.exit(main())
