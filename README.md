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

## Shared test data

[`testdata/`](testdata) holds cross-language test vectors: `testdata/gen` is a small Go
program that runs the real storage-proofs sw-pub pipeline (tag → challenge → prove →
verify) and writes the result to `testdata/vectors.json`, which the JS test suite
verifies against to confirm the two implementations actually interoperate.

## Repository layout

```
pinion-prover-client/
  js/          JavaScript/TypeScript client, see js/README.md
  go/          Go client + testclient CLI, see go/README.md
  testdata/    Cross-language test vectors, shared by both
```
