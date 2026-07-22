# pinion-prover-client (Go)

Go client for the **pinion-prover** storage-proof service.

This is a thin wrapper, not a reimplementation. All challenge/proof/verify
cryptography is delegated to [storage-proofs](https://github.com/pinionengineering/storage-proofs)
and [ipfs-storage-proofs](https://github.com/pinionengineering/ipfs-storage-proofs), the
same libraries pinion-prover itself runs on server-side. What this package adds is the
same ergonomic layer the [JavaScript client](../js) has: a `Client` with typed methods,
automatic polling of the async tag/prove jobs, typed errors, and an `Audit()` convenience
that runs challenge → prove → verify in one call.

## Installation

```bash
go get github.com/pinionengineering/pinion-prover-client/go
```

## Usage

```go
import proverclient "github.com/pinionengineering/pinion-prover-client/go"

client := proverclient.NewClient("https://hydrogen.pinion.build/prover",
	proverclient.WithTokenFunc(func(ctx context.Context) (string, error) {
		return myPAT, nil
	}),
)

// Setup phase: done once (or after adding/removing roots)
key, _ := client.CreateKey(ctx, "sw-pub", "my-key")
client.Tag(ctx, myCID, key.KeyID, nil) // blocks until tagging is done
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
