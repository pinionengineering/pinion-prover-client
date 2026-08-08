package proverclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ipfs/go-cid"
	multihash "github.com/multiformats/go-multihash"
	ipfsproof "github.com/pinionengineering/ipfs-storage-proofs"
	"github.com/pinionengineering/storage-proofs/blocks"
	"github.com/pinionengineering/storage-proofs/line"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func newTestServer(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return NewClient(srv.URL,
		WithAuthURL(srv.URL+"/api/v1"),
		WithToken(func(context.Context) (string, error) { return "", nil }),
	)
}

// newTestServerWithTrustedKey is newTestServer plus WithTrustedKey, for the
// Audit tests that need signature verification -- everything else (Tag,
// Prove, WaitFor*, ...) doesn't touch trustedKey at all.
func newTestServerWithTrustedKey(t *testing.T, pub ed25519.PublicKey, handler http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return NewClient(srv.URL,
		WithAuthURL(srv.URL+"/api/v1"),
		WithToken(func(context.Context) (string, error) { return "", nil }),
		WithTrustedKey(pub),
	)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// mapBlockStore is a minimal blocks.BlockStore keyed by arbitrary byte ids,
// for tests that need ids matching a specific scheme's own addressing
// (e.g. ipfsproof.SuperBlockID) rather than blocks.MemStore's sequential
// IntID default.
type mapBlockStore struct {
	ids  [][]byte
	data map[string][]byte
}

func newMapBlockStore(ids [][]byte, contents [][]byte) *mapBlockStore {
	data := make(map[string][]byte, len(ids))
	for i, id := range ids {
		data[string(id)] = contents[i]
	}
	return &mapBlockStore{ids: ids, data: data}
}

func (s *mapBlockStore) Len() int      { return len(s.ids) }
func (s *mapBlockStore) IDs() [][]byte { return s.ids }
func (s *mapBlockStore) Block(id []byte) ([]byte, error) {
	b, ok := s.data[string(id)]
	if !ok {
		return nil, fmt.Errorf("block %x not found", id)
	}
	return b, nil
}
func (s *mapBlockStore) SetBlock(id []byte, data []byte) error {
	s.data[string(id)] = data
	return nil
}

// swPubFixture is a real (not mocked) SW-Pub key + tagged root, built via the
// same storage-proofs primitives pinion-prover itself uses server-side. It
// lets Audit tests exercise genuine BN254 cryptography end-to-end instead of
// asserting only on HTTP/polling plumbing.
type swPubFixture struct {
	setup  *SetupResponse
	store  blocks.BlockStore
	prover line.Prover
	pub    ed25519.PublicKey
	priv   ed25519.PrivateKey
}

func newSWPubFixture(t *testing.T, keyID string, blockCount int) *swPubFixture {
	t.Helper()
	const blockSize = 64
	const sectorsPerBlock = 4

	spec, ok := SchemeByProtocol("sw-pub")
	if !ok {
		t.Fatal("sw-pub scheme not registered")
	}
	tagger, err := spec.NewTagger(0, 0, blockSize, sectorsPerBlock)
	if err != nil {
		t.Fatalf("NewTagger: %v", err)
	}

	mh, err := multihash.Sum([]byte("test-root"), multihash.SHA2_256, -1)
	if err != nil {
		t.Fatalf("multihash.Sum: %v", err)
	}
	rootCID := cid.NewCidV1(cid.Raw, mh)

	ids := make([][]byte, blockCount)
	contents := make([][]byte, blockCount)
	for i := 0; i < blockCount; i++ {
		ids[i] = ipfsproof.SuperBlockID(rootCID, uint64(i))
		contents[i] = bytes.Repeat([]byte{byte(i + 1)}, blockSize)
	}
	store := newMapBlockStore(ids, contents)

	if _, err := tagger.TagBlocks(store); err != nil {
		t.Fatalf("TagBlocks: %v", err)
	}
	clientSetup, err := tagger.ClientSetup()
	if err != nil {
		t.Fatalf("ClientSetup: %v", err)
	}
	proverSetup, err := tagger.ProverSetup()
	if err != nil {
		t.Fatalf("ProverSetup: %v", err)
	}
	prover, err := spec.ProvFactory.NewProver(proverSetup, store)
	if err != nil {
		t.Fatalf("NewProver: %v", err)
	}

	pub, priv := testChalKeySigningKeypair(t)
	return &swPubFixture{
		setup: &SetupResponse{
			ClientSetup:    clientSetup,
			ClientSetupSig: testSignClientSetup(t, priv, keyID, clientSetup),
			Roots: []TaggedRoot{{
				Root:          rootCID.String(),
				BlockCount:    blockCount,
				BlockCountSig: testSignBlockCount(t, priv, keyID, rootCID.String(), blockCount),
			}},
		},
		store:  store,
		prover: prover,
		pub:    pub,
		priv:   priv,
	}
}

// ---------------------------------------------------------------------------
// Tag / WaitForTag
// ---------------------------------------------------------------------------

func TestTag_SubmitOnly(t *testing.T) {
	var getCalls int32
	c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/tag":
			writeJSON(w, http.StatusAccepted, TagJobResponse{JobID: "job-1"})
		case r.Method == http.MethodGet:
			atomic.AddInt32(&getCalls, 1)
			t.Errorf("unexpected GET %s: Tag must not poll", r.URL.Path)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	})

	sub, err := c.Tag(context.Background(), "bafy-root", "key-1")
	if err != nil {
		t.Fatalf("Tag: %v", err)
	}
	if sub.JobID != "job-1" || sub.Root != "bafy-root" || sub.KeyID != "key-1" {
		t.Fatalf("unexpected submission: %+v", sub)
	}
	if atomic.LoadInt32(&getCalls) != 0 {
		t.Fatalf("Tag polled status %d times, want 0", getCalls)
	}
}

func TestWaitForTag_PollsToCompletion(t *testing.T) {
	statuses := []string{"tag-queued", "tag-planning", "tag-running", "tag-done"}
	var call int32
	c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/tag/job-1" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		i := int(atomic.AddInt32(&call, 1)) - 1
		status := statuses[i]
		resp := TagJobStatusResponse{Status: status}
		if status == "tag-done" {
			resp.BlockIDs = []string{"b1", "b2"}
		} else {
			resp.Progress = &TagJobProgress{TotalBlocks: 10, CompletedBlocks: i * 2}
		}
		writeJSON(w, http.StatusOK, resp)
	})

	var progress []string
	var mu sync.Mutex
	start := time.Now()
	result, err := c.WaitForTag(context.Background(), "job-1", &WaitForTagOptions{
		PollInterval: 10 * time.Millisecond,
		OnProgress: func(p TagJobProgress, status string) {
			mu.Lock()
			progress = append(progress, status)
			mu.Unlock()
		},
	})
	if err != nil {
		t.Fatalf("WaitForTag: %v", err)
	}
	if result.Status != "tag-done" || len(result.BlockIDs) != 2 {
		t.Fatalf("unexpected result: %+v", result)
	}
	mu.Lock()
	n := len(progress)
	mu.Unlock()
	if n != 3 {
		t.Fatalf("expected 3 progress calls (queued/planning/running), got %d: %v", n, progress)
	}
	if elapsed := time.Since(start); elapsed < 20*time.Millisecond {
		t.Fatalf("expected at least 2 poll intervals (20ms) to elapse, got %s", elapsed)
	}
}

func TestWaitForTag_Failed(t *testing.T) {
	c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, TagJobStatusResponse{Status: "tag-failed", Error: "boom"})
	})

	_, err := c.WaitForTag(context.Background(), "job-1", &WaitForTagOptions{PollInterval: time.Millisecond})
	var failErr *TagFailedError
	if !errors.As(err, &failErr) {
		t.Fatalf("expected *TagFailedError, got %v (%T)", err, err)
	}
	if failErr.JobID != "job-1" || failErr.Reason != "boom" {
		t.Fatalf("unexpected error: %+v", failErr)
	}
}

// TestWaitForTag_NoDefaultDeadline is the core regression test: the old Tag()
// gave up after a hardcoded 10-minute deadline even though the server was
// never designed to respect one. With no ctx deadline at all, WaitForTag
// must keep polling indefinitely and never manufacture a timeout itself.
func TestWaitForTag_NoDefaultDeadline(t *testing.T) {
	const rounds = 50
	var call int32
	c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		i := atomic.AddInt32(&call, 1)
		if int(i) <= rounds {
			writeJSON(w, http.StatusOK, TagJobStatusResponse{Status: "tag-running"})
			return
		}
		writeJSON(w, http.StatusOK, TagJobStatusResponse{Status: "tag-done"})
	})

	_, err := c.WaitForTag(context.Background(), "job-1", &WaitForTagOptions{PollInterval: time.Millisecond})
	if err != nil {
		t.Fatalf("WaitForTag must never time out on its own with no ctx deadline: %v", err)
	}
	if got := atomic.LoadInt32(&call); got != rounds+1 {
		t.Fatalf("expected %d polls, got %d", rounds+1, got)
	}
}

func TestWaitForTag_CtxCancelIsPrompt(t *testing.T) {
	c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, TagJobStatusResponse{Status: "tag-running"})
	})

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(30*time.Millisecond, cancel)

	start := time.Now()
	_, err := c.WaitForTag(ctx, "job-1", &WaitForTagOptions{PollInterval: 5 * time.Second})
	elapsed := time.Since(start)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if elapsed > time.Second {
		t.Fatalf("cancellation should abort promptly rather than waiting out the poll interval: took %s", elapsed)
	}
}

// ---------------------------------------------------------------------------
// Prove / WaitForProve
// ---------------------------------------------------------------------------

func TestProve_SubmitOnly(t *testing.T) {
	var getCalls int32
	c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/prove":
			writeJSON(w, http.StatusAccepted, ProveJobResponse{JobID: "job-1"})
		case r.Method == http.MethodGet:
			atomic.AddInt32(&getCalls, 1)
			t.Errorf("unexpected GET %s: Prove must not poll", r.URL.Path)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	})

	sub, err := c.Prove(context.Background(), "key-1", []string{"root-a"}, []byte("chal"), "")
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}
	if sub.JobID != "job-1" || string(sub.Challenge) != "chal" || len(sub.Roots) != 1 {
		t.Fatalf("unexpected submission: %+v", sub)
	}
	if atomic.LoadInt32(&getCalls) != 0 {
		t.Fatalf("Prove polled status %d times, want 0", getCalls)
	}
}

func TestProve_PinNotActiveError(t *testing.T) {
	// Mocks the real server envelope (ginmiddleware/apierror.Abort4xx:
	// {code, message, request_id}), not an invented {cid: ...} shape --
	// this test previously mocked a body the real server never sends,
	// which is exactly how the parsing bug it's now guarding against
	// went unnoticed.
	const msg = `the CID "bafy-stale" is not currently in a pinned state; only pinned CIDs can be proved.`
	c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusConflict, map[string]string{"code": "pin_not_active", "message": msg})
	})

	_, err := c.Prove(context.Background(), "key-1", []string{"root-a"}, []byte("chal"), "")
	var pinErr *PinNotActiveError
	if !errors.As(err, &pinErr) || pinErr.Message != msg {
		t.Fatalf("expected *PinNotActiveError{Message: %q}, got %v (%T)", msg, err, err)
	}
}

func TestProve_MalformedResponse(t *testing.T) {
	c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte("not json"))
	})

	_, err := c.Prove(context.Background(), "key-1", []string{"root-a"}, []byte("chal"), "")
	var malErr *MalformedResponseError
	if !errors.As(err, &malErr) {
		t.Fatalf("expected *MalformedResponseError, got %v (%T)", err, err)
	}
}

func TestWaitForProve_PollsToCompletion(t *testing.T) {
	statuses := []string{"prove-queued", "prove-running", "prove-running", "prove-done"}
	var call int32
	c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/prove/job-1" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		i := int(atomic.AddInt32(&call, 1)) - 1
		resp := ProveJobStatusResponse{Status: statuses[i]}
		if statuses[i] == "prove-done" {
			resp.Proof = []byte("real-proof-bytes")
		}
		writeJSON(w, http.StatusOK, resp)
	})

	var seen []string
	var mu sync.Mutex
	proof, err := c.WaitForProve(context.Background(), "job-1", &WaitForProveOptions{
		PollInterval: 10 * time.Millisecond,
		OnStatus: func(status string) {
			mu.Lock()
			seen = append(seen, status)
			mu.Unlock()
		},
	})
	if err != nil {
		t.Fatalf("WaitForProve: %v", err)
	}
	if string(proof) != "real-proof-bytes" {
		t.Fatalf("unexpected proof: %q", proof)
	}
	mu.Lock()
	n := len(seen)
	mu.Unlock()
	if n != 4 {
		t.Fatalf("expected 4 OnStatus calls, got %d: %v", n, seen)
	}
}

func TestWaitForProve_Failed(t *testing.T) {
	c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, ProveJobStatusResponse{Status: "prove-failed", Error: "bad challenge"})
	})

	_, err := c.WaitForProve(context.Background(), "job-1", &WaitForProveOptions{
		PollInterval: time.Millisecond,
		Challenge:    []byte("chal"),
		Roots:        []string{"root-a"},
	})
	var failErr *ProveFailedError
	if !errors.As(err, &failErr) {
		t.Fatalf("expected *ProveFailedError, got %v (%T)", err, err)
	}
	if failErr.Reason != "bad challenge" || string(failErr.Challenge) != "chal" || len(failErr.Roots) != 1 {
		t.Fatalf("unexpected error: %+v", failErr)
	}
}

// TestWaitForProve_NoDefaultDeadline is the core regression test for the
// actual production bug that triggered this redesign: the old Prove() gave
// up after a hardcoded 60-second deadline even when a job had genuinely not
// finished yet, something the server was never designed to respect. With no
// ctx deadline at all, WaitForProve must keep polling past that point
// without manufacturing a timeout of its own.
func TestWaitForProve_NoDefaultDeadline(t *testing.T) {
	const rounds = 50
	var call int32
	c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		i := atomic.AddInt32(&call, 1)
		if int(i) <= rounds {
			writeJSON(w, http.StatusOK, ProveJobStatusResponse{Status: "prove-running"})
			return
		}
		writeJSON(w, http.StatusOK, ProveJobStatusResponse{Status: "prove-done", Proof: []byte("ok")})
	})

	_, err := c.WaitForProve(context.Background(), "job-1", &WaitForProveOptions{PollInterval: time.Millisecond})
	if err != nil {
		t.Fatalf("WaitForProve must never time out on its own with no ctx deadline: %v", err)
	}
	if got := atomic.LoadInt32(&call); got != rounds+1 {
		t.Fatalf("expected %d polls, got %d", rounds+1, got)
	}
}

func TestWaitForProve_CtxCancelIsPrompt(t *testing.T) {
	c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, ProveJobStatusResponse{Status: "prove-running"})
	})

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(30*time.Millisecond, cancel)

	start := time.Now()
	_, err := c.WaitForProve(ctx, "job-1", &WaitForProveOptions{PollInterval: 5 * time.Second})
	elapsed := time.Since(start)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if elapsed > time.Second {
		t.Fatalf("cancellation should abort promptly rather than waiting out the poll interval: took %s", elapsed)
	}
}

// ---------------------------------------------------------------------------
// Audit: real cryptography end-to-end, plus the options-passthrough
// regression this redesign specifically fixes (the old Audit() called Prove
// with zero options passed through, so a caller had no way to configure the
// wait or see the failure detail it produced).
// ---------------------------------------------------------------------------

func TestAudit_RealCryptoPass(t *testing.T) {
	fx := newSWPubFixture(t, "key-1", 8)

	type job struct {
		proof []byte
		polls int32
	}
	var mu sync.Mutex
	jobs := make(map[string]*job)

	c := newTestServerWithTrustedKey(t, fx.pub, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/prove":
			var req ProveRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("decode ProveRequest: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			proof, err := fx.prover.Prove(line.Challenge(req.Challenge), fx.store)
			if err != nil {
				t.Errorf("prover.Prove: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			mu.Lock()
			jobs["job-real"] = &job{proof: proof}
			mu.Unlock()
			writeJSON(w, http.StatusAccepted, ProveJobResponse{JobID: "job-real"})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/prove/"):
			mu.Lock()
			j := jobs[strings.TrimPrefix(r.URL.Path, "/prove/")]
			j.polls++
			polls := j.polls
			mu.Unlock()
			if polls < 3 {
				writeJSON(w, http.StatusOK, ProveJobStatusResponse{Status: "prove-running"})
				return
			}
			writeJSON(w, http.StatusOK, ProveJobStatusResponse{Status: "prove-done", Proof: j.proof})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})

	var onStatus []string
	result, err := c.Audit(context.Background(), "key-1", fx.setup, "sw-pub", &AuditOptions{
		Roots:         []string{fx.setup.Roots[0].Root},
		ChallengeSize: 5,
		PollInterval:  5 * time.Millisecond,
		OnStatus: func(status string) {
			mu.Lock()
			onStatus = append(onStatus, status)
			mu.Unlock()
		},
	})
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if !result.Pass {
		t.Fatal("expected a genuine cryptographic pass, got Pass=false")
	}
	mu.Lock()
	seen := append([]string(nil), onStatus...)
	mu.Unlock()
	if len(seen) < 3 || seen[len(seen)-1] != "prove-done" {
		t.Fatalf("expected AuditOptions.OnStatus to observe polls through to prove-done, got %v", seen)
	}
}

func TestAudit_ProveFailed_PropagatesChallengeAndRoots(t *testing.T) {
	fx := newSWPubFixture(t, "key-1", 4)

	c := newTestServerWithTrustedKey(t, fx.pub, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/prove":
			writeJSON(w, http.StatusAccepted, ProveJobResponse{JobID: "job-1"})
		case r.Method == http.MethodGet:
			writeJSON(w, http.StatusOK, ProveJobStatusResponse{Status: "prove-failed", Error: "server exploded"})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})

	_, err := c.Audit(context.Background(), "key-1", fx.setup, "sw-pub", &AuditOptions{
		Roots:         []string{fx.setup.Roots[0].Root},
		ChallengeSize: 3,
		PollInterval:  time.Millisecond,
	})
	var failErr *ProveFailedError
	if !errors.As(err, &failErr) {
		t.Fatalf("expected *ProveFailedError, got %v (%T)", err, err)
	}
	if failErr.Reason != "server exploded" {
		t.Fatalf("unexpected reason: %q", failErr.Reason)
	}
	if len(failErr.Challenge) == 0 || len(failErr.Roots) == 0 {
		t.Fatalf("expected Audit to pass Challenge/Roots through to WaitForProve so ProveFailedError carries them, got Challenge=%v Roots=%v", failErr.Challenge, failErr.Roots)
	}
}

// TestAudit_TamperedClientSetupSigRejected and
// TestAudit_TamperedBlockCountSigRejected are the actual security-relevant
// checks: not just that a genuine signature passes (already covered above
// and in trustkey_test.go's unit tests), but that Audit refuses to even
// contact the server -- no /prove request should ever be sent -- once the
// setup it was given fails authenticity. A server that only gets hit for
// genuinely-authenticated setups is the whole point.
func TestAudit_TamperedClientSetupSigRejected(t *testing.T) {
	fx := newSWPubFixture(t, "key-1", 4)
	fx.setup.ClientSetupSig[0] ^= 0xFF // flip a byte: still well-formed, no longer valid

	c := newTestServerWithTrustedKey(t, fx.pub, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected request %s %s: Audit must reject before contacting the server", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusInternalServerError)
	})

	_, err := c.Audit(context.Background(), "key-1", fx.setup, "sw-pub", &AuditOptions{
		Roots: []string{fx.setup.Roots[0].Root},
	})
	var untrusted *UntrustedSetupError
	if !errors.As(err, &untrusted) {
		t.Fatalf("expected *UntrustedSetupError, got %v (%T)", err, err)
	}
	if untrusted.Root != "" {
		t.Fatalf("expected the ClientSetup-level failure (empty Root), got Root=%q", untrusted.Root)
	}
}

func TestAudit_TamperedBlockCountSigRejected(t *testing.T) {
	fx := newSWPubFixture(t, "key-1", 4)
	fx.setup.Roots[0].BlockCountSig[0] ^= 0xFF

	c := newTestServerWithTrustedKey(t, fx.pub, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected request %s %s: Audit must reject before contacting the server", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusInternalServerError)
	})

	_, err := c.Audit(context.Background(), "key-1", fx.setup, "sw-pub", &AuditOptions{
		Roots: []string{fx.setup.Roots[0].Root},
	})
	var untrusted *UntrustedSetupError
	if !errors.As(err, &untrusted) {
		t.Fatalf("expected *UntrustedSetupError, got %v (%T)", err, err)
	}
	if untrusted.Root != fx.setup.Roots[0].Root {
		t.Fatalf("expected the BlockCount-level failure naming the tampered root, got Root=%q", untrusted.Root)
	}
}

// A different key's genuine signature must not verify for this key --
// otherwise an attacker with a legitimate key of their own could sign their
// ClientSetup and swap it in wherever they wanted, sidestepping the whole
// point of binding the signature to KeyID.
func TestAudit_ClientSetupSigForWrongKeyRejected(t *testing.T) {
	fx := newSWPubFixture(t, "key-1", 4)
	fx.setup.ClientSetupSig = testSignClientSetup(t, fx.priv, "someone-elses-key", fx.setup.ClientSetup)

	c := newTestServerWithTrustedKey(t, fx.pub, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected request %s %s: Audit must reject before contacting the server", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusInternalServerError)
	})

	_, err := c.Audit(context.Background(), "key-1", fx.setup, "sw-pub", &AuditOptions{
		Roots: []string{fx.setup.Roots[0].Root},
	})
	var untrusted *UntrustedSetupError
	if !errors.As(err, &untrusted) {
		t.Fatalf("expected *UntrustedSetupError, got %v (%T)", err, err)
	}
}
