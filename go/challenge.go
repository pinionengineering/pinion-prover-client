package proverclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/pinionengineering/storage-proofs/line"
)

// CheckProofMatchesChallenge checks that a finished prove job answers the
// challenge this client sent. It returns nil on a match, or an error
// describing the first mismatch.
//
// The prove job's envelope carries its own Seed/C/N/Roots. The envelope's
// signature shows the server produced it, not that it answers this client's
// challenge: without this check a server could return a proof for a
// challenge of its own choosing, such as an earlier proof replayed, or a
// seed picked so every sampled block is one it still holds. Run it before
// trusting any verification result for chal/roots.
//
// chal is the challenge sent to Prove, and roots the root list sent with
// it, in the same order.
//
// Mirrors checkProofMatchesChallenge() in this repository's
// js/src/challenge.ts; keep the two in step.
func CheckProofMatchesChallenge(chal line.Challenge, roots []string, result *ProveJobStatusResponse) error {
	var want struct {
		Seed []byte `json:"seed"`
		C    int    `json:"c"`
		N    int    `json:"n"`
	}
	if err := json.Unmarshal(chal, &want); err != nil {
		return fmt.Errorf("challenge could not be decoded: %w", err)
	}
	if !bytes.Equal(result.Seed, want.Seed) {
		return fmt.Errorf("seed differs from the challenge that was sent")
	}
	if result.C != want.C {
		return fmt.Errorf("c is %d, the challenge that was sent has c=%d", result.C, want.C)
	}
	if result.N != want.N {
		return fmt.Errorf("n is %d, the challenge that was sent has n=%d", result.N, want.N)
	}
	if !slices.Equal(result.Roots, roots) {
		return fmt.Errorf("roots %v differ from the requested roots %v", result.Roots, roots)
	}
	return nil
}
