// gen produces a JSON test-vector file that the JS test suite can consume.
//
// The vector is a complete SW-Pub audit round generated entirely in Go using
// the same libraries that pinion-prover uses at runtime:
//
//   storage-proofs/line/swpub   — tag, challenge, prove, verify
//   storage-proofs/blocks       — MapStore with arbitrary-byte IDs
//
// All byte fields are base64-encoded to match the wire format used by the
// pinion-prover HTTP API, so verifyProof() in the JS library can consume
// them without any extra transformation.
//
// Usage:
//
//	go run . > ../vectors.json
package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/pinionengineering/storage-proofs/blocks"
	"github.com/pinionengineering/storage-proofs/line"
	lineSwPub "github.com/pinionengineering/storage-proofs/line/swpub"
	porsw "github.com/pinionengineering/storage-proofs/por/sw"
	"github.com/pinionengineering/storage-proofs/suite"
)

// TestVector matches the JSON consumed by test/verify.test.mjs.
//
// ClientSetup, Challenge, and Proof are string fields containing pre-formed
// base64 strings — using string (not []byte) avoids double-encoding by
// encoding/json, which would base64 a []byte value a second time.
//
// BlockIDs uses [][]byte so encoding/json auto-base64s each element, producing
// the same ["base64_id1", "base64_id2",...] array that TaggedRoot.block_ids uses.
type TestVector struct {
	Description string   `json:"description"`
	ClientSetup string   `json:"client_setup"` // base64(JSON(wireClientSetup))
	BlockIDs    [][]byte `json:"block_ids"`     // each element base64-encoded by json
	Challenge   string   `json:"challenge"`     // base64(JSON(wireChal))
	Proof       string   `json:"proof"`         // base64(wireProof JSON bytes)
}

func main() {
	// Use small parameters so the test runs fast even in CI.
	const (
		s         = 4  // sectors per block (must match what pinion-prover uses)
		l         = 5  // challenge size
		numBlocks = 20 // blocks to tag
		blockSize = 64 // bytes per block
	)

	// -------------------------------------------------------------------------
	// Key generation
	// -------------------------------------------------------------------------
	ps, err := porsw.NewPubScheme(s, l)
	if err != nil {
		log.Fatalf("NewPubScheme: %v", err)
	}

	// -------------------------------------------------------------------------
	// Build a MapStore with random blocks and random arbitrary-byte IDs.
	// Using arbitrary-byte IDs (not IntID) mirrors how pinion-prover stores CIDs.
	// -------------------------------------------------------------------------
	rawBlocks := make([][]byte, numBlocks)
	ids := make([][]byte, numBlocks)
	for i := range numBlocks {
		b := make([]byte, blockSize)
		if _, err := rand.Read(b); err != nil {
			log.Fatalf("rand block %d: %v", i, err)
		}
		rawBlocks[i] = b

		id := make([]byte, 34) // multihash-sized fake CID bytes
		if _, err := rand.Read(id); err != nil {
			log.Fatalf("rand id %d: %v", i, err)
		}
		ids[i] = id
	}
	store, err := blocks.NewMapStore(ids, rawBlocks)
	if err != nil {
		log.Fatalf("NewMapStore: %v", err)
	}

	// -------------------------------------------------------------------------
	// Tag
	// -------------------------------------------------------------------------
	tagger := lineSwPub.NewTagger(ps, suite.SuiteV1)
	if _, err := tagger.TagBlocks(store); err != nil {
		log.Fatalf("TagBlocks: %v", err)
	}
	clientSetupBytes, err := tagger.ClientSetup()
	if err != nil {
		log.Fatalf("ClientSetup: %v", err)
	}
	proverSetupBytes, err := tagger.ProverSetup()
	if err != nil {
		log.Fatalf("ProverSetup: %v", err)
	}

	// -------------------------------------------------------------------------
	// Challenge
	// -------------------------------------------------------------------------
	chalFactory := lineSwPub.NewChallengerFactory()
	challenger, err := chalFactory.NewChallenger(clientSetupBytes, 0)
	if err != nil {
		log.Fatalf("NewChallenger: %v", err)
	}
	chal, validator, err := challenger.Challenge(store.IDs())
	if err != nil {
		log.Fatalf("Challenge: %v", err)
	}

	// -------------------------------------------------------------------------
	// Prove
	// -------------------------------------------------------------------------
	provFactory := lineSwPub.NewProverFactory()
	prover, err := provFactory.NewProver(proverSetupBytes, store)
	if err != nil {
		log.Fatalf("NewProver: %v", err)
	}
	proof, err := prover.Prove(chal, store)
	if err != nil {
		log.Fatalf("Prove: %v", err)
	}

	// -------------------------------------------------------------------------
	// Sanity-check with Go verifier before writing the vector
	// -------------------------------------------------------------------------
	ok, err := validator.Verify(chal, proof)
	if err != nil {
		log.Fatalf("Go Verify error: %v", err)
	}
	if !ok {
		log.Fatalf("Go Verify returned false — test vector is broken")
	}
	fmt.Fprintln(os.Stderr, "Go verification: PASS")

	// -------------------------------------------------------------------------
	// Also test a tampered proof — verifier must return false
	// -------------------------------------------------------------------------
	tampered := make(line.Proof, len(proof))
	copy(tampered, proof)
	tampered[len(tampered)/2] ^= 0xFF
	okTampered, _ := validator.Verify(chal, tampered)
	if okTampered {
		log.Fatalf("Go Verify accepted tampered proof — something is wrong")
	}
	fmt.Fprintln(os.Stderr, "Go tamper check: PASS")

	// -------------------------------------------------------------------------
	// Encode for the JS test
	//
	// JS buildChallenge() returns base64(JSON(wireChal)).
	// line.Challenge is already the raw JSON bytes, so we just base64-encode it.
	//
	// The HTTP /prove response body IS the raw JSON bytes (wireProof JSON).
	// We base64-encode it here so it can be stored as a string in vectors.json,
	// then the JS test does base64ToBytes() to recover the raw JSON bytes that
	// would come from the HTTP response.
	// -------------------------------------------------------------------------
	b64 := base64.StdEncoding.EncodeToString
	challengeB64 := b64(chal)       // base64(wireChal JSON) — matches buildChallenge() output
	proofB64 := b64(proof)          // base64(wireProof JSON) — base64 of HTTP response body

	// clientSetupBytes is already JSON(wireClientSetup).
	// SetupResponse.client_setup is base64(JSON(wireClientSetup)), so base64-encode it.
	clientSetupB64 := b64(clientSetupBytes)

	vec := TestVector{
		Description: fmt.Sprintf("SW-Pub: %d blocks, s=%d, l=%d, block_size=%d", numBlocks, s, l, blockSize),
		ClientSetup: clientSetupB64,
		BlockIDs:    store.IDs(),
		Challenge:   challengeB64,
		Proof:       proofB64,
	}

	out, err := json.MarshalIndent(vec, "", "  ")
	if err != nil {
		log.Fatalf("marshal: %v", err)
	}
	fmt.Println(string(out))
}
