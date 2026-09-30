package proverclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/pinionengineering/storage-proofs/line"
)

func TestCheckProofMatchesChallenge(t *testing.T) {
	seed := []byte("0123456789abcdef0123456789abcdef")
	chal, err := json.Marshal(map[string]any{"suite_id": 1, "seed": seed, "c": 5, "n": 20})
	if err != nil {
		t.Fatal(err)
	}
	roots := []string{"rootA", "rootB"}
	match := func() *ProveJobStatusResponse {
		return &ProveJobStatusResponse{Seed: append([]byte(nil), seed...), C: 5, N: 20, Roots: []string{"rootA", "rootB"}}
	}

	if err := CheckProofMatchesChallenge(line.Challenge(chal), roots, match()); err != nil {
		t.Fatalf("matching envelope rejected: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(r *ProveJobStatusResponse)
		want   string
	}{
		{"seed", func(r *ProveJobStatusResponse) { r.Seed[0] ^= 0xFF }, "seed differs"},
		{"missing seed", func(r *ProveJobStatusResponse) { r.Seed = nil }, "seed differs"},
		{"c", func(r *ProveJobStatusResponse) { r.C = 1 }, "c is 1"},
		{"n", func(r *ProveJobStatusResponse) { r.N = 4 }, "n is 4"},
		{"roots subset", func(r *ProveJobStatusResponse) { r.Roots = []string{"rootA"} }, "roots"},
		{"roots order", func(r *ProveJobStatusResponse) { r.Roots = []string{"rootB", "rootA"} }, "roots"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := match()
			tc.mutate(r)
			err := CheckProofMatchesChallenge(line.Challenge(chal), roots, r)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected a mismatch mentioning %q, got %v", tc.want, err)
			}
		})
	}
}

// A server that ignores the client's challenge and answers one it picked
// itself returns a real proof with a valid envelope signature. The proof
// verifies against the server's own challenge, so only
// CheckProofMatchesChallenge stands between it and a passing audit.
func TestAudit_ServerChosenChallengeRejected(t *testing.T) {
	fx := newSWPubFixture(t, "key-1", 8)
	targetRoots := []string{fx.setup.Roots[0].Root}

	total, idAt, err := BuildCombinedIDs(fx.setup, targetRoots)
	if err != nil {
		t.Fatal(err)
	}
	spec, _ := SchemeByProtocol("sw-pub")
	challenger, err := spec.ChalFactory.NewChallenger(fx.setup.ClientSetup, 2)
	if err != nil {
		t.Fatal(err)
	}
	serverChal, serverValidator, err := challenger.Challenge(total, idAt)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := fx.prover.Prove(serverChal, fx.store)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := serverValidator.Verify(serverChal, proof); err != nil || !ok {
		t.Fatalf("server-chosen proof should verify against its own challenge: ok=%v err=%v", ok, err)
	}
	var w struct {
		Seed []byte `json:"seed"`
		C    int    `json:"c"`
		N    int    `json:"n"`
	}
	if err := json.Unmarshal(serverChal, &w); err != nil {
		t.Fatal(err)
	}
	sig := testSignProof(t, fx.priv, "key-1", w.Seed, w.C, w.N, targetRoots, proof)

	c := newTestServerWithTrustedKey(t, fx.pub, func(rw http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/prove":
			writeJSON(rw, http.StatusAccepted, ProveJobResponse{JobID: "job-replay"})
		case r.Method == http.MethodGet && r.URL.Path == "/prove/job-replay":
			writeJSON(rw, http.StatusOK, ProveJobStatusResponse{
				Status: "prove-done", Proof: proof,
				KeyID: "key-1", Seed: w.Seed, C: w.C, N: w.N, Roots: targetRoots, Sig: sig,
			})
		default:
			rw.WriteHeader(http.StatusNotFound)
		}
	})

	_, err = c.Audit(context.Background(), "key-1", fx.setup, "sw-pub", &AuditOptions{
		Roots:         targetRoots,
		ChallengeSize: 5,
		PollInterval:  5 * time.Millisecond,
	})
	var mismatch *ChallengeMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("expected *ChallengeMismatchError, got %v", err)
	}
	if mismatch.JobID != "job-replay" || !strings.Contains(mismatch.Reason, "seed differs") {
		t.Fatalf("unexpected mismatch detail: %+v", mismatch)
	}
}
