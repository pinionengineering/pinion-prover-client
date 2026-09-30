# pinion-prover-client

Client libraries for **pinion-prover**, Pinion's storage-proof service. Both implement
the SW-Pub challenger role: build a challenge, send it, and cryptographically verify
the response with a BN254 pairing check, so you never have to trust an HTTP 200 as proof
that your data is actually still there.

This repo holds two independent, standalone libraries, one per language:

- **[`js/`](js)**: JavaScript / TypeScript, published as
  [`@pinionengineering/prover-client`](https://www.npmjs.com/package/@pinionengineering/prover-client)
  on npm. This is what [pinion.build](https://pinion.build)'s own Storage Proofs
  dashboard is built on, the dashboard is the JS library used in a real, working
  application if you want to see it in practice.
- **[`go/`](go)**: Go, a thin wrapper around the
  [storage-proofs](https://github.com/pinionengineering/storage-proofs) and
  [ipfs-storage-proofs](https://github.com/pinionengineering/ipfs-storage-proofs)
  libraries plus the same ergonomic layer (typed client, async job polling, an
  `Audit()` convenience) the JS client has. Includes `testclient`, a CLI for running
  the whole audit workflow with no code at all.

Pick whichever language fits; both speak the same wire protocol against the same
pinion-prover deployment and are safe to mix (e.g. tag from the dashboard, audit from
a Go cron job).

## Trust model

Both clients verify the same two things before trusting a proof:

1. **The proof answers this client's challenge.** Each round picks a fresh random seed.
   The finished job's envelope echoes the seed, block count, total, and roots it
   answered, and verification re-derives the sampled blocks from them, so both clients
   require the echo to equal what was sent (`CheckProofMatchesChallenge` in Go,
   `checkProofMatchesChallenge` in JS, run by `Audit`/`audit()` right after the wait).
   Without it, a server could return a valid proof of an earlier round or of a seed it
   chose.
2. **The pairing equation holds** for that challenge, under setup and proof signatures
   that check out against the deployment's published trusted key.

A passing proof means the prover holds the challenged blocks, **provided the prover
doesn't also hold the tagging secret α**. Whoever holds α can compute a passing response
for any challenge without the data. For SW-Pub keys created through pinion-prover
(including every key the pinion.build dashboard makes), pinion-prover generates α and
tags the pins itself, as a convenience. Against Pinion, a proof is therefore evidence
that Pinion's storage still returns the tagged bytes (it catches lost, truncated, or
corrupted data), not a cryptographic guarantee that Pinion couldn't answer without
them. Against a storage node that never sees α, it is a full proof. See
[pinion-prover's trust model](https://github.com/pinionengineering/pinion-prover#trust-model-who-holds-the-tagging-key)
for details, including which protocols accept self-computed tags.

## Shared test data

[`testdata/`](testdata) holds cross-language test vectors: `testdata/gen` is a small Go
program that runs the real storage-proofs sw-pub pipeline (tag → challenge → prove →
verify) and writes the result to `testdata/vectors.json`, which the JS test suite
verifies against to confirm the two implementations actually interoperate.
`go run . -short` writes `testdata/vectors-short.json`, the same round over zero-padded
blocks (the shape of a small file), whose proof carries μⱼ = 0 for every sector past
the data; both implementations must accept it.

## Repository layout

```
pinion-prover-client/
  js/          JavaScript/TypeScript client, see js/README.md
  go/          Go client + testclient CLI, see go/README.md
  testdata/    Cross-language test vectors, shared by both
```
