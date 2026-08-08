# pinion-prover-client (Go)

Go client for the **pinion-prover** storage-proof service.

This is a thin wrapper, not a reimplementation. All challenge/proof/verify
cryptography is delegated to [storage-proofs](https://github.com/pinionengineering/storage-proofs)
and [ipfs-storage-proofs](https://github.com/pinionengineering/ipfs-storage-proofs), the
same libraries pinion-prover itself runs on server-side. What this package adds is the
same ergonomic layer the [JavaScript client](../js) has: a `Client` with typed methods,
submit/wait helpers for the async tag/prove jobs with no default deadline (the `ctx` you
pass owns how long to wait), typed errors, and an `Audit()` convenience that runs
challenge → prove → verify in one call.

## Installation

```bash
go get github.com/pinionengineering/pinion-prover-client/go
```

### Upgrading from the fused Tag/Prove API

`Tag` and `Prove` are now **submit-only**: they return a job handle
immediately (`*TagSubmission` / `*ProveSubmission`) instead of blocking
until the job finishes. Call the new `WaitForTag(ctx, jobID, opts?)` /
`WaitForProve(ctx, jobID, opts?)` to wait for a terminal state, or poll
`TagStatus(ctx, jobID)`/`ProveStatus(ctx, jobID)` yourself. There is **no
default deadline anymore**: the old hardcoded 10-minute (`Tag`)/60-second
(`Prove`) timeouts and the `*TagTimeoutError`/`*ProveTimeoutError` types are
gone, since a tag or proof job can legitimately take longer than any fixed
ceiling and the server was never designed to respect one. Waiting is now
bounded purely by the `ctx.Context` you already pass to every call: build
one with `context.WithTimeout` to cap the wait, and check a timeout with
`errors.Is(err, context.DeadlineExceeded)` (or `context.Canceled` for an
explicit cancel).

`Audit(ctx, keyID, setup, protocol, opts)` is unchanged in shape (still one
call that submits, waits, and verifies) but `AuditOptions` now also accepts
`PollInterval`/`OnStatus` so you can report progress during a long-running
round.

## Usage

```go
import proverclient "github.com/pinionengineering/pinion-prover-client/go"

const baseURL = "https://hydrogen.pinion.build/prover"
client := proverclient.NewClient(baseURL,
	proverclient.WithAuthURL(baseURL+"/pat/v1"),
	proverclient.WithToken(func(ctx context.Context) (string, error) {
		return myPAT, nil
	}),
	// Required for Audit: the Ed25519 public key published for whichever
	// pinion-prover deployment baseURL points at. Get this out-of-band --
	// never fetch it from baseURL itself, see WithTrustedKey's doc comment.
	proverclient.WithTrustedKey(hydrogenTrustedPubKey),
)

// Setup phase: done once (or after adding/removing roots)
key, _ := client.CreateKey(ctx, "sw-pub", "my-key")

// Tag submits and returns immediately; WaitForTag has no default deadline,
// so this waits as long as the DAG walk actually takes.
tagJob, _ := client.Tag(ctx, myCID, key.KeyID)
client.WaitForTag(ctx, tagJob.JobID, nil)

setup, _ := client.GetSetup(ctx, key.KeyID)

// Audit phase: repeat on a schedule
result, err := client.Audit(ctx, key.KeyID, setup, "sw-pub", nil)
if err == nil && result.Pass {
	fmt.Println("proof verified")
}
```

For lower-level control (custom challenge sizes, driving `Challenger`/`Validator`
directly, other protocols such as Ateniese/Erway/BJO), see `BuildCombinedIDs` and
`SchemeByProtocol`, which is what `Audit` itself is built from.

## `testclient` CLI

`cmd/testclient` is a no-code way to run the full audit workflow from the command
line, ported from pinion-prover's own test client onto this library. Typical use,
after exporting a key and roots file from the [dashboard](https://pinion.build):

```bash
go run ./cmd/testclient import --key-file key.json --roots-file roots.json
go run ./cmd/testclient audit --all --loop
```

Run `go run ./cmd/testclient --help` for the full command list (`key-create`, `tag`,
`setup`, `import`, `challenge`, `prove`, `verify`, `audit`, `status`).
