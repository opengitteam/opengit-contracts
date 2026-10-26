// Fetches GitHub's Actions OIDC signing keys and writes script/github-jwks.json in the form
// ProposeKeys.s.sol reads (kid, modulus and exponent as hex). Anyone can run this to check the
// keys proposed to GitHubKeyRegistry against what GitHub publishes.
// Usage: node script/github-keys.mjs
import { writeFileSync } from "node:fs";

const JWKS = "https://token.actions.githubusercontent.com/.well-known/jwks";
const res = await fetch(JWKS);
if (!res.ok) throw new Error(`${JWKS}: ${res.status}`);
const { keys } = await res.json();

const hex = (b64url) => "0x" + Buffer.from(b64url, "base64url").toString("hex");
const out = keys
  .filter((k) => k.kty === "RSA" && (k.alg ?? "RS256") === "RS256" && (k.use ?? "sig") === "sig")
  .map((k) => ({ kid: k.kid, modulus: hex(k.n), exponent: hex(k.e) }));

writeFileSync(new URL("./github-jwks.json", import.meta.url), JSON.stringify({ source: JWKS, fetchedAt: new Date().toISOString(), keys: out }, null, 2) + "\n");
for (const k of out) console.log(`${k.kid}  ${(k.modulus.length - 2) / 2} bytes  e=${k.exponent}`);
