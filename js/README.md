# @pinion/prover-client

JavaScript / TypeScript client for **pinion-prover** storage-proof service.

Implements the SW-Pub challenger role:

- Fetches the server's setup document (public key + block IDs)
- Constructs SW-Pub challenges client-side
- Sends challenges to the prover and receives proofs
- **Cryptographically verifies proofs** using BN254 Ate pairings

Most IPFS pinning clients trust HTTP 200 as proof of storage, but a server
can return 200 without actually holding your data.  This library closes that gap:
the server must solve a cryptographic challenge that is **only solvable by a party
who has the block data**, and you verify the answer with a BN254 pairing equation
in your browser or Node.js process.

Don't want to write JS? [The Go client in this same repo](../go#readme) documents a
no-code path: export a key + roots file from the
[dashboard](https://pinion.build), then run the same audit loop with the
`testclient` CLI. `testclient import` followed by `testclient audit --all --loop`
is the whole workflow, no account needed for the audit itself.

---

## Installation

```bash
npm install @pinion/prover-client
```

Requires Node.js ≥ 18. Works in modern browsers with native `crypto.getRandomValues` and `atob`.

---

## How It Works

The protocol has two distinct phases:

### Setup phase (done once per key)

1. Call `createKey()`.  The server generates a BN254 key pair and stores the private
   scalar α.  You receive:
   - `keyId`: identifier for this key on the server
   - `publicKey`: the public half: `V = α·G₂` (G2 point) and `U[0..s-1]` (G1 points).
     These are the values needed to verify proofs; store them if you want to verify
     independently of the server later.

2. Call `tag(cid, keyId)` for each pinned CID.  The server walks the IPFS DAG,
   computes per-block authentication tags, and stores them.  It returns the **block IDs**
   for that root: the `CID.Bytes()` of every block in the DAG, in TagList order.

3. Call `getSetup(keyId)` to fetch the full setup document.  The response contains:
   - The public key (same as returned by `createKey()`)
   - For each registered root: the complete ordered block ID list

   Both the client and server know these block IDs, and they agree on their order.
   The block ID list is what the challenge is drawn from.

### Audit phase (repeat on a schedule)

Each audit round is independent and stateless with respect to prior rounds:

1. Generate a random 32-byte seed and select `n` blocks to challenge.  Both client
   and server independently apply HMAC-SHA256 to the seed to rank all block IDs and
   select the same `n` blocks in the same order: no extra communication needed.
   Use `buildChallenge(n, total)` for an exact block count, or `audit()` for a
   percentage-based shorthand.

2. Post the challenge `{ suite_id, seed, c, n }` to `POST /prove`.

3. Verify the proof locally using the public key.  The BN254 pairing check
   `e(σ, G₂) == e(A, V)` can only be satisfied by a party that holds the actual
   block data.

Each passing audit round contributes to the cumulative `blocks_audited` counter
on the server (visible in `listKeys()`), giving a long-running record of
proof-of-storage evidence collected over time.

---

## Quick Start

```typescript
import { PinionProverClient } from '@pinion/prover-client';

const client = new PinionProverClient('https://example.com/prover', {
  getToken: async () => myAuthService.getToken(),
});

// ── Setup phase ────────────────────────────────────────────────────────────

// Create a key: returns the key ID and the public half of the key pair.
const { keyId, publicKey } = await client.createKey();

// Tag a pinned CID: the server walks the DAG and stores per-block auth tags.
await client.tag('bafybeigdyrzt...', keyId);

// Fetch the setup document: public key + block ID lists for all tagged roots.
const setup = await client.getSetup(keyId);

// ── Audit phase (repeat on a schedule) ─────────────────────────────────────

// Default: 1% spot-check per round.
const result = await client.audit(keyId, setup);
console.log(result.pass); // true = server cryptographically proved it holds your data
```

---

## Examples

`examples/verify.mjs` is a ready-to-run Node.js script covering the full
flow: find-or-create a key, tag new CIDs, run one audit round:

```sh
PROVER_URL=https://hydrogen.pinion.build/prover \
PINION_TOKEN=eyJh...                            \
node examples/verify.mjs bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi
```

Expected output:

```
[key]   9f3a1c2b-...  (newly created)
[tag]   registering 1 new CID(s)...
[setup] 64 total blocks across 1 root(s)
[audit] 1 block(s) challenged

[pass]  Cryptographic proof: server holds the data.
```

---

## API Reference

### `new PinionProverClient(baseUrl, options?)`

```typescript
const client = new PinionProverClient(
  'https://hydrogen.pinion.build/prover',
  { getToken: async () => 'Bearer ...' }
);
```

`baseUrl` must include the path prefix (e.g., `/prover`). All authenticated endpoints use
`Bearer` tokens obtained from `getToken()`.

---

### Key Lifecycle

#### `client.createKey()` → `CreateKeyResult`

Creates a key pair on the server and returns the key ID and the **public key material**.

```typescript
const { keyId, publicKey } = await client.createKey();
// publicKey.v    G2 point V = α·G₂  (128 bytes, base64)
// publicKey.u    G1 points U[0..s-1] (s × 64 bytes, base64)
// publicKey.name 16-byte file name λ bound into every block tag
```

The private scalar α never leaves the server.  `publicKey` is the WireClientSetup
blob decoded from base64; you can store it and pass it directly to `verifyProof()`
without ever calling `getSetup()` again.

A single key covers many CIDs: you do not need a new key per file.

#### `client.listKeys()` → `ChallengeKeyInfo[]`

Returns all keys for the authenticated user.  Each entry includes:
- `blocks_audited`: cumulative blocks challenged across all audit rounds for this key
- `audit_count`: number of audit rounds completed

These are the long-running metrics that show how much proof-of-storage evidence
has been accumulated over time.

#### `client.deleteKey(keyId)`

Deletes a key and all associated tags.

---

### Setup Phase

#### `client.tag(root, keyId)` → `TagResponse`

```typescript
const { block_ids, block_count } = await client.tag(cid, keyId);
// Exactly one is populated, depending on the key's protocol:
// block_ids:   string[]: base64(CID.Bytes()) for every block, non-chunked
//              protocols only (Ateniese, Erway, BJO), in TagList order
// block_count: number  : super-block count, chunked protocols only
//              (SW-Priv, SW-Pub): no per-block manifest is sent at all
```

Instructs the server to walk the IPFS DAG for `root`, compute per-block
authentication tags, and store them under `keyId`.  The CID must be in the
`"pinned"` lifecycle state for the authenticated account.

For non-chunked protocols, `block_ids` is the full list of blocks for this
root in the order both client and server will use when ranking against a
challenge seed.  For chunked protocols, `block_count` is all the client needs:
challenge ids are synthesized locally via `superBlockId(rootBytes, i)` for
`i` in `[0, block_count)`.  Call `getSetup()` after tagging to get the
combined list/count across all roots.

#### `client.getSetup(keyId)` → `ParsedSetup`

Fetches the complete setup document for a key.

```typescript
const setup = await client.getSetup(keyId);
// setup.clientSetup    WireClientSetup: public key material
// setup.roots          [{ root: string, blockIds: Uint8Array[], chunked: boolean }, ...]
// setup.totalBlocks    total block count across all roots
```

`blockIds` is always ready to pass to `buildChallenge()`/`verifyProof()`
regardless of protocol.  `chunked` tells you whether those ids are real
per-block CIDs (`false`) or synthesized super-block ids (`true`): only
relevant if you need to re-derive or re-export ids yourself; synthesized ids
are not valid CIDs and must never be round-tripped through `CID.decode()`.

Call this once after tagging.  Re-call whenever you add or remove roots.
Pass the returned `ParsedSetup` directly to `audit()`: it does not fetch
the setup for you.

#### `client.deregister(keyId, root)`

Removes the tag data for one root without deleting the key.

---

### Audit Phase

#### `client.audit(keyId, setup, options?)` → `AuditResult`

Convenience wrapper for one full audit round:

1. Derives block count from `challengePct` and the setup's block list
2. Calls `buildChallenge(n, total)` to generate a random challenge
3. Posts it to `POST /prove` via `prove()`
4. Verifies the proof with `verifyProof()`

```typescript
// Default: 1% of blocks (spot-check).
const result = await client.audit(keyId, setup);

// Full audit of all registered roots:
const result = await client.audit(keyId, setup, { challengePct: 100 });

// Audit a subset of roots:
const result = await client.audit(keyId, setup, {
  roots:        [specificCid],
  challengePct: 50,
});
```

`AuditResult`:
```typescript
{
  pass: boolean;          // true = pairing equation satisfied
  blocksChecked: number;  // blocks sampled in this round
  keyId: string;
  roots: string[];
}
```

`AuditOptions`:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `roots` | `string[]` | all roots | Subset of registered CIDs to challenge. |
| `challengePct` | `number` | `1` | Percentage of blocks to sample (0–100). |

Throws `PinNotActiveError` if any root is no longer in the `"pinned"` state.
Throws `ProverError` on HTTP errors from the server.

---

#### Low-level: `buildChallenge` + `prove` + `verifyProof`

Use these when you need an exact block count or want full control over the
challenge parameters.

##### `buildChallenge(n, totalBlocks)` → `string`

```typescript
import { buildChallenge } from '@pinion/prover-client';

const challenge = buildChallenge(10, setup.totalBlocks);
// Returns base64(JSON({ suite_id: 1, seed: <32 random bytes>, c: 10, n: totalBlocks }))
```

Generates a random 32-byte seed and encodes a WireChallenge requesting `n` blocks
out of `totalBlocks`.  Both client and server independently apply HMAC-SHA256 to
the seed to rank all block IDs and arrive at the same `n` blocks in the same order.

##### `client.prove(keyId, roots, challenge)` → `Uint8Array`

```typescript
const proofBytes = await client.prove(keyId, roots, challenge);
```

Posts the challenge to `POST /prove` and returns the raw proof bytes.

##### `verifyProof(params)` → `boolean`

```typescript
import { verifyProof } from '@pinion/prover-client';

const pass = verifyProof({
  clientSetup: setup.clientSetup,  // or publicKey from createKey()
  blockIds,                        // Uint8Array[] from setup.roots[i].blockIds
  challenge,                       // the string returned by buildChallenge()
  proofBytes,                      // raw bytes from prove()
});
```

Runs the BN254 pairing check locally.  Returns `true` only if
`e(σ,G₂) == e(A,V)`.  Safe to call without a client instance: useful for
offline verification or integration with existing infrastructure.

##### Full low-level example

```typescript
import { PinionProverClient, buildChallenge, verifyProof } from '@pinion/prover-client';

const client = new PinionProverClient(proverUrl, { getToken });

// Setup phase
const { keyId } = await client.createKey();
await client.tag(cid, keyId);
const setup = await client.getSetup(keyId);

// Audit phase: exact block count
const root     = setup.roots[0]!;
const blockIds = root.blockIds;
const challenge  = buildChallenge(10, blockIds.length);
const proofBytes = await client.prove(keyId, [root.root], challenge);

const pass = verifyProof({
  clientSetup: setup.clientSetup,
  blockIds,
  challenge,
  proofBytes,
});
```

---

### Standalone Verification

You can verify a proof with no HTTP client at all, as long as you have the
public key and block IDs from a prior setup call:

```typescript
import { buildChallenge, verifyProof, parseClientSetup } from '@pinion/prover-client';

const clientSetup = parseClientSetup(storedClientSetupBase64);

// blockIds from a prior getSetup() call, decoded to Uint8Array[]:
const challenge = buildChallenge(5, blockIds.length);

// ...send challenge to POST /prove yourself, receive proofBytes...

const pass = verifyProof({ clientSetup, blockIds, challenge, proofBytes });
```

---

## Wire Format Specification

This section documents the exact encoding used by pinion-prover for clients
implementing the protocol in other languages.

### Curve

pinion-prover uses **BN254** (also known as alt\_bn128 or Ethereum's precompile curve,
standardised in [EIP-197](https://eips.ethereum.org/EIPS/eip-197)).

| Parameter | Value |
|-----------|-------|
| Curve | BN254 / alt\_bn128 (Ethereum EIP-197) |
| Field prime `p` | `0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47` |
| Group order `r` | `21888242871839275222246405745257275088548364400416034343698204186575808495617` |
| Curve equation | `y² = x³ + 3` over Fp |
| G1 generator | `(1, 2)` |
| G1 wire format | 64 bytes: `X_BE(32) ‖ Y_BE(32)` (no prefix byte) |
| G2 twist | D-type, `y² = x³ + 3/(9+i)` over Fp² |
| G2 wire format | 128 bytes: `X.im(32) ‖ X.re(32) ‖ Y.im(32) ‖ Y.re(32)` (EIP-197 / gnark-crypto `RawBytes`) |
| Hash-to-G1 | RFC 9380 SVDW, `XMD:SHA-256`, DST `"sw-pub-v1-BN254G1_XMD:SHA-256_SVDW_RO_"` |

The G2 format matches gnark-crypto's `G2Affine.RawBytes()`. Each coordinate stores
the imaginary component first: `X.A1 ‖ X.A0 ‖ Y.A1 ‖ Y.A0` where `A0` is real
and `A1` is imaginary.

---

### Challenge (`WireChallenge`)

`POST /prove` body field `challenge`:

```
base64( JSON({ suite_id, seed, c, n }) )
```

| Field | Type | Description |
|-------|------|-------------|
| `suite_id` | `uint8` | Always `1` (SuiteV1 = HMAC-SHA256) |
| `seed` | `base64(32 bytes)` | Cryptographically random seed |
| `c` | `int` | Number of blocks to challenge |
| `n` | `int` | Total blocks in the challenged store |

Example:
```json
{ "suite_id": 1, "seed": "A3Rk...==", "c": 5, "n": 100 }
```

---

### Client Setup (`WireClientSetup`)

Returned by `createKey()` and embedded in the `GET /api/v1/setup` response:

```
base64( JSON({ protocol, suite_id, s, l, name, v, u }) )
```

| Field | Type | Description |
|-------|------|-------------|
| `protocol` | `"swpub"` | Scheme identifier |
| `suite_id` | `uint8` | `1` |
| `s` | `int` | Number of sectors per block |
| `l` | `int` | Challenge size parameter (from the SW-Pub scheme) |
| `name` | `base64(16 bytes)` | File name λ: random, unique per key, bound into every block tag |
| `v` | `base64(128 bytes)` | Public key V = α·G₂ (G2 point, EIP-197 format) |
| `u` | `base64(64 bytes)[]` | Public key U[0..s-1] (G1 points) |

---

### Proof (`WireProof`)

`POST /prove` response body (raw JSON, despite `Content-Type: application/octet-stream`):

```json
{ "sigma": "<base64 64 bytes>", "mu": ["<base64 32 bytes>", ...] }
```

| Field | Type | Description |
|-------|------|-------------|
| `sigma` | `base64(64 bytes)` | Accumulated G1 point σ |
| `mu` | `base64(32 bytes)[]` | s × 32-byte Zr scalars μⱼ (big-endian) |

---

## Verification Equation

The SW-Pub scheme (Shacham & Waters, ASIACRYPT 2008 §3.3) uses the following pairing equation:

```
e(σ, G₂) == e(Σₜ νₜ·H(λ‖idᵢₜ) + Σⱼ μⱼ·uⱼ, V)
```

where:

- `σ`: proof accumulator G1 point (from server)
- `G₂`: G2 generator
- `νₜ, iₜ`: blinding coefficients and block indices (re-derived from seed)
- `H(λ‖id)`: RFC 9380 SVDW hash-to-G1 with DST `"sw-pub-v1-BN254G1_XMD:SHA-256_SVDW_RO_"`
- `μⱼ`: per-sector Zr scalars (from server)
- `uⱼ`: public key G1 elements (from client_setup)
- `V`: public key `V = α·G₂` (from client_setup)

### Hash-to-G1

`H(λ‖id)` uses the RFC 9380 straightline SVDW map-to-curve algorithm
([§6.6.2](https://www.rfc-editor.org/rfc/rfc9380.html#straightline-svdw))
rather than a scalar multiply `SHA-256(λ‖id) mod r · G₁`.

The scalar-multiply approach produces points with known discrete logarithms relative
to the generator, which breaks the scheme's security proof (§3.3 requires H to behave
as a random oracle over G1, not just a scalar multiple of a fixed base). SVDW produces
points that are indistinguishable from uniform random G1 elements.

The DST `"sw-pub-v1-BN254G1_XMD:SHA-256_SVDW_RO_"` is fixed for all keys and matches
the value in `storage-proofs/por/sw/pub.go`. **Changing this DST invalidates all
existing tags**: both sides derive H independently so they must agree.

### Challenge Derivation (`DeriveChallenge`)

Both client and server independently re-derive the same block selection from the
seed using SuiteV1 (HMAC-SHA256):

```
idxKey   = HMAC-SHA256(seed, "indices")
coeffKey = HMAC-SHA256(seed, "coeffs")
rank[i]  = HMAC-SHA256(idxKey, ids[i])   ← sort ascending, take first c positions
coeff[t] = HMAC-SHA256(coeffKey, BE64(t)) mod r
```

`t` is encoded as **big-endian uint64** (8 bytes). The `c` selected block IDs are
the entries with the lowest-ranked HMAC values, in rank order.  Because the ranking
is a deterministic function of the seed, client and server arrive at the same `c`
blocks in the same order without any additional communication.

---

## Testing

Test vectors are generated by a Go program that runs the full Go server pipeline offline:

```bash
# Regenerate test vectors (requires Go)
npm run test:gen

# Run tests
npm test
```

The test suite verifies:
1. Valid proof accepted
2. Tampered sigma rejected
3. Wrong block IDs rejected
4. Wrong public key rejected

---

## Implementation Notes

### Curve operations

G1/G2 arithmetic and the Ate pairing delegate to
[@noble/curves](https://github.com/paulmillr/noble-curves) `bn254`, which implements
the same BN254 curve as gnark-crypto and Ethereum's precompile.

### Hash-to-G1 (SVDW)

[@noble/curves v1.9.7](https://github.com/paulmillr/noble-curves) has the SVDW
map-to-curve for BN254 G1 marked `notImplemented`. This library provides its own
implementation in `src/bn254.ts`, derived directly from gnark-crypto's
`MapToCurve1` in
[ecc/bn254/hash\_to\_g1.go](https://github.com/ConsenSys/gnark-crypto/blob/master/ecc/bn254/hash_to_g1.go).

`expand_message_xmd` (the hash expansion step) is provided by noble/curves and is not
reimplemented here. The custom code is limited to the 35-step straightline SVDW map
(RFC 9380 §6.6.2) plus the Fp arithmetic it requires.

Cross-language correctness is verified by the test suite: `npm run test:gen` runs the
full Go pipeline (gnark-crypto) and emits test vectors that `npm test` then validates
against the JS pairing check.
