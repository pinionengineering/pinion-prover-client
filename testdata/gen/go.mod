module github.com/pinionengineering/pinion-prover-client/testdata/gen

go 1.26.4

require github.com/pinionengineering/storage-proofs v0.0.0

require (
	github.com/bits-and-blooms/bitset v1.24.4 // indirect
	github.com/consensys/gnark-crypto v0.20.1 // indirect
	github.com/klauspost/cpuid/v2 v2.0.9 // indirect
	golang.org/x/sys v0.41.0 // indirect
	lukechampine.com/blake3 v1.4.1 // indirect
)

replace github.com/pinionengineering/storage-proofs => ../../../storage-proofs
