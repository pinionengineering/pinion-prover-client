// Package proverclient is a thin Go client for the pinion-prover storage-proof
// service. It is deliberately not a reimplementation of any cryptography: all
// challenge/proof/verify logic is delegated to the storage-proofs and
// ipfs-storage-proofs modules (the same libraries pinion-prover itself is
// built on), exactly as pinion-prover's own testclient does. What this
// package adds on top is the same ergonomic layer the JS client
// (@pinionengineering/prover-client) has: a Client with typed methods,
// submit/wait helpers for the async tag/prove jobs (Tag/WaitForTag,
// Prove/WaitForProve, with no default deadline: the ctx you pass owns how
// long to wait), typed errors, and an Audit() convenience that runs
// challenge → prove → verify in one call.
//
// Route structure:
//
//	Unauthenticated:  {baseURL}/prove, {baseURL}/prove/:job_id
//	Authenticated:    {authURL}/*
//
// baseURL is NewClient's argument; authURL is set separately via
// WithAuthURL, since pinion-prover exposes the same authenticated resource
// paths under more than one prefix depending on how the caller
// authenticates (e.g. {baseURL}/pat/v1 for a personal access token,
// {baseURL}/api/v1 for a JWT Bearer token) -- this package has no opinion
// on which one you use and doesn't hardcode either. A Client needs
// WithAuthURL and WithToken (or an already-authenticating http.Client via
// WithHTTPClient) before making any authenticated call, and WithTrustedKey
// before calling Audit.
package proverclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ipfs/go-cid"
	ipfsproof "github.com/pinionengineering/ipfs-storage-proofs"
	"github.com/pinionengineering/storage-proofs/capability"
	"github.com/pinionengineering/storage-proofs/line"
)

// Client is an HTTP client for one pinion-prover deployment.
type Client struct {
	baseURL    string
	authURL    string
	httpClient *http.Client
	getToken   func(ctx context.Context) (string, error)
	trustedKey ed25519.PublicKey
}

// Option configures a Client constructed by NewClient.
type Option func(*Client)

// WithHTTPClient overrides the default http.Client (e.g. for custom timeouts,
// transport-level tracing, or to bring your own auth transport instead of
// WithToken -- e.g. one that already attaches credentials on every request).
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) { c.httpClient = hc }
}

// WithToken supplies a bearer token for authenticated requests, sent as
// "Authorization: Bearer <token>". Called fresh before every authenticated
// request; return ("", nil) if no token is available.
func WithToken(tokenFunc func(ctx context.Context) (string, error)) Option {
	return func(c *Client) { c.getToken = tokenFunc }
}

// WithAuthURL sets the base URL for authenticated requests (everything
// except POST /prove and GET /prove/:job_id, which are always unauthenticated
// and always hang off the plain baseURL passed to NewClient -- see the
// package doc comment). Required before any authenticated call: a Client
// with no auth URL configured returns a clear error rather than guessing
// which of pinion-prover's authenticated route prefixes to use.
func WithAuthURL(url string) Option {
	return func(c *Client) { c.authURL = strings.TrimRight(url, "/") }
}

// WithTrustedKey sets the Ed25519 public key Audit checks ClientSetup/
// BlockCount signatures against (see VerifyClientSetupSig). Required before
// calling Audit: a Client with no trusted key configured returns a clear
// error rather than skipping the check, which would silently defeat its
// entire purpose. pubKey must come from something published and reviewed
// out-of-band for whichever pinion-prover deployment baseURL points at --
// this package has no built-in notion of "the" trusted key, since a value
// baked into the library can't cover a deployment it doesn't know about
// (e.g. a self-hosted one), and a value fetched from baseURL at runtime
// would be verifying the server against itself.
func WithTrustedKey(pubKey ed25519.PublicKey) Option {
	return func(c *Client) { c.trustedKey = pubKey }
}

// NewClient returns a Client for the prover deployment at baseURL, e.g.
// "https://hydrogen.pinion.build/prover". Pass WithAuthURL and WithToken to
// authenticate.
func NewClient(baseURL string, opts ...Option) *Client {
	c := &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: http.DefaultClient,
		getToken:   func(context.Context) (string, error) { return "", nil },
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// ---------------------------------------------------------------------------
// Challenge key lifecycle
// ---------------------------------------------------------------------------

func (c *Client) ListKeys(ctx context.Context) ([]ChallengeKeyInfo, error) {
	path, err := c.authPath("/challenge-keys")
	if err != nil {
		return nil, err
	}
	var out []ChallengeKeyInfo
	if err := c.get(ctx, path, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// CreateKey creates a challenge key on the server. label may be empty.
func (c *Client) CreateKey(ctx context.Context, protocol, label string) (*CreateKeyResponse, error) {
	path, err := c.authPath("/challenge-key")
	if err != nil {
		return nil, err
	}
	var out CreateKeyResponse
	if err := c.post(ctx, path, CreateKeyRequest{Protocol: protocol, Label: label}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) DeleteKey(ctx context.Context, keyID string) error {
	path, err := c.authPath("/challenge-key/" + pathEscape(keyID))
	if err != nil {
		return err
	}
	return c.authDelete(ctx, path)
}

// UpdateKeyLabel renames a key after creation. Pass an empty label to clear it.
func (c *Client) UpdateKeyLabel(ctx context.Context, keyID, label string) error {
	path, err := c.authPath("/challenge-key/" + pathEscape(keyID))
	if err != nil {
		return err
	}
	return c.authPatch(ctx, path, UpdateKeyLabelRequest{Label: label})
}

// ---------------------------------------------------------------------------
// Setup phase
// ---------------------------------------------------------------------------

// GetSetup fetches the setup document for a key: public key material and,
// per registered root, either the block ID list (non-chunked protocols) or
// the super-block count (chunked protocols: SW-Priv, SW-Pub).
func (c *Client) GetSetup(ctx context.Context, keyID string) (*SetupResponse, error) {
	path, err := c.authPath("/setup?key_id=" + pathEscape(keyID))
	if err != nil {
		return nil, err
	}
	var out SetupResponse
	if err := c.get(ctx, path, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Tag asks the server to walk the IPFS DAG for root, compute per-block
// authentication tags, and store them under keyID. root must already be in
// the "pinned" lifecycle state for the authenticated account.
//
// Tag is submit-only: it posts the job and returns immediately with a job
// handle. Tagging itself happens asynchronously on the server; call
// WaitForTag with the returned JobID to block until it reaches a terminal
// state, then GetSetup to get the updated block ID list for the next audit
// cycle.
func (c *Client) Tag(ctx context.Context, root, keyID string) (*TagSubmission, error) {
	path, err := c.authPath("/tag")
	if err != nil {
		return nil, err
	}
	var jobResp TagJobResponse
	if err := c.post(ctx, path, TagRequest{Root: root, KeyID: keyID}, &jobResp); err != nil {
		return nil, fmt.Errorf("tag %s: %w", root, err)
	}
	return &TagSubmission{JobID: jobResp.JobID, Root: root, KeyID: keyID}, nil
}

// WaitForTagOptions configures WaitForTag.
type WaitForTagOptions struct {
	// PollInterval between GET /tag/:job_id polls. Default 1s.
	PollInterval time.Duration
	// OnProgress, if set, is called after every status poll with the latest
	// progress and raw status string.
	OnProgress func(progress TagJobProgress, status string)
}

// WaitForTag polls GET {tier}/tag/:job_id until the job reaches a terminal
// state, returning the completed status (with the block ID list/count) once
// "tag-done", or a *TagFailedError once "tag-failed".
//
// There is no default deadline: WaitForTag waits as long as ctx allows,
// since a DAG walk can legitimately take a long time and the server was
// never designed to respect an arbitrary client-side ceiling. Pass a ctx
// built with context.WithTimeout to bound the wait; a ctx deadline or
// cancellation surfaces as ctx.Err() (check with errors.Is against
// context.DeadlineExceeded/context.Canceled), not a special error type,
// since the ctx already threaded through every call is the one thing that
// should own "how long is too long".
func (c *Client) WaitForTag(ctx context.Context, jobID string, opts *WaitForTagOptions) (*TagJobStatusResponse, error) {
	if opts == nil {
		opts = &WaitForTagOptions{}
	}
	pollInterval := opts.PollInterval
	if pollInterval <= 0 {
		pollInterval = time.Second
	}
	for {
		status, err := c.TagStatus(ctx, jobID)
		if err != nil {
			return nil, err
		}
		if opts.OnProgress != nil && status.Progress != nil {
			opts.OnProgress(*status.Progress, status.Status)
		}
		switch status.Status {
		case "tag-done":
			return status, nil
		case "tag-failed":
			return nil, &TagFailedError{JobID: jobID, Reason: status.Error}
		}
		if err := sleepCtx(ctx, pollInterval); err != nil {
			return nil, err
		}
	}
}

// TagStatus polls the status of a tag job started by Tag, without waiting
// for it to reach a terminal state. Useful for building progress UI.
func (c *Client) TagStatus(ctx context.Context, jobID string) (*TagJobStatusResponse, error) {
	path, err := c.authPath("/tag/" + pathEscape(jobID))
	if err != nil {
		return nil, err
	}
	var out TagJobStatusResponse
	if err := c.get(ctx, path, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListTagJobs lists the caller's tag jobs, most recently created first. Set
// active to list only non-terminal jobs (queued/planning/running/merging),
// what a "tagging in progress" indicator should poll, since it works without
// already knowing a job ID.
func (c *Client) ListTagJobs(ctx context.Context, active bool) ([]TagJobListEntry, error) {
	path, err := c.authPath("/tag")
	if err != nil {
		return nil, err
	}
	if active {
		path += "?active=true"
	}
	var out TagJobListResponse
	if err := c.get(ctx, path, &out); err != nil {
		return nil, err
	}
	return out.Jobs, nil
}

func (c *Client) Deregister(ctx context.Context, keyID, root string) error {
	path, err := c.authPath("/register/" + pathEscape(keyID) + "/" + pathEscape(root))
	if err != nil {
		return err
	}
	return c.authDelete(ctx, path)
}

// ---------------------------------------------------------------------------
// Audit phase
// ---------------------------------------------------------------------------

// Prove posts a challenge to POST /prove (unauthenticated: the server
// resolves the account from keyID) and returns immediately with a job
// handle. Most callers should use Audit instead, which also submits, waits,
// and cryptographically verifies the response in one call.
//
// challengeID is an optional idempotency key; leave it empty for normal
// audit rounds, each of which should be a fresh, independently random
// challenge that must never be deduped against a previous one.
func (c *Client) Prove(ctx context.Context, keyID string, roots []string, challenge []byte, challengeID string) (*ProveSubmission, error) {
	body, err := json.Marshal(ProveRequest{KeyID: keyID, Roots: roots, Challenge: challenge, ChallengeID: challengeID})
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(mustRequest(ctx, http.MethodPost, c.baseURL+"/prove", body, nil))
	if err != nil {
		return nil, fmt.Errorf("prove: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusConflict {
		// The server's error envelope is {code, message, request_id} (see
		// ginmiddleware/apierror.Abort4xx) -- there's no separate "cid"
		// field, message already names the CID in readable prose. Fall
		// back to something non-empty if the body is somehow missing or
		// doesn't match, so this never regresses to a blank message.
		var errBody struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(respBody, &errBody)
		msg := errBody.Message
		if msg == "" {
			msg = "pin not active: " + string(respBody)
		}
		return nil, &PinNotActiveError{Message: msg}
	}
	if resp.StatusCode != http.StatusAccepted {
		return nil, &ProverError{Status: resp.StatusCode, Body: string(respBody)}
	}
	var jobResp ProveJobResponse
	if err := json.Unmarshal(respBody, &jobResp); err != nil {
		return nil, &MalformedResponseError{Status: resp.StatusCode, BodyPreview: preview(respBody), Cause: err}
	}
	return &ProveSubmission{JobID: jobResp.JobID, Challenge: challenge, Roots: roots}, nil
}

// WaitForProveOptions configures WaitForProve.
type WaitForProveOptions struct {
	// PollInterval between GET /prove/:job_id polls. Default 500ms.
	PollInterval time.Duration
	// Challenge/Roots are echoed back on a *ProveFailedError so callers
	// building a retry don't have to thread them separately. Optional.
	Challenge []byte
	Roots     []string
	// OnStatus, if set, is called after every status poll with the raw
	// status string. There's no per-block progress signal for proving
	// (unlike tagging), just the coarse queued/running/done/failed status.
	OnStatus func(status string)
}

// WaitForProve polls GET /prove/:job_id until the job reaches a terminal
// state, returning the raw proof bytes once "prove-done", or a
// *ProveFailedError once "prove-failed".
//
// There is no default deadline: WaitForProve waits as long as ctx allows,
// since a proof round can legitimately take longer than any fixed ceiling
// and the server was never designed to respect one. Pass a ctx built with
// context.WithTimeout to bound the wait; a ctx deadline or cancellation
// surfaces as ctx.Err() (check with errors.Is against
// context.DeadlineExceeded/context.Canceled), not a special error type.
func (c *Client) WaitForProve(ctx context.Context, jobID string, opts *WaitForProveOptions) ([]byte, error) {
	if opts == nil {
		opts = &WaitForProveOptions{}
	}
	pollInterval := opts.PollInterval
	if pollInterval <= 0 {
		pollInterval = 500 * time.Millisecond
	}
	for {
		status, err := c.ProveStatus(ctx, jobID)
		if err != nil {
			return nil, err
		}
		if opts.OnStatus != nil {
			opts.OnStatus(status.Status)
		}
		switch status.Status {
		case "prove-done":
			return status.Proof, nil
		case "prove-failed":
			return nil, &ProveFailedError{JobID: jobID, Reason: status.Error, Challenge: opts.Challenge, Roots: opts.Roots}
		}
		if err := sleepCtx(ctx, pollInterval); err != nil {
			return nil, err
		}
	}
}

// ProveStatus polls the status of a proof job started by Prove.
func (c *Client) ProveStatus(ctx context.Context, jobID string) (*ProveJobStatusResponse, error) {
	var out ProveJobStatusResponse
	if err := c.get(ctx, c.baseURL+"/prove/"+pathEscape(jobID), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// AuditOptions configures Audit.
type AuditOptions struct {
	// Roots to challenge. Defaults to every root in setup.
	Roots []string
	// ChallengeSize is how many blocks (super-blocks, for the chunked
	// protocols) to sample across the selected roots combined. Default 20.
	ChallengeSize int
	// PollInterval between GET /prove/:job_id polls while waiting for the
	// proof. Default 500ms.
	PollInterval time.Duration
	// OnStatus, if set, is called after every status poll with the raw
	// status string, letting a caller show progress during a long-running
	// round. There is no default deadline on the wait; bound it via ctx
	// (context.WithTimeout) if desired.
	OnStatus func(status string)
}

// AuditResult is the outcome of one Audit round.
type AuditResult struct {
	Pass          bool
	BlocksChecked int
	KeyID         string
	Roots         []string
	// Challenge is the wire bytes sent to POST /prove, the same format
	// line.Challenge uses for this protocol.
	Challenge []byte
}

// Audit runs one full round, challenge → prove → cryptographic verify,
// against a pre-fetched SetupResponse. protocol must match the key's
// protocol ("sw-pub" is pinion-prover's default). Building the challenge and
// verifying the response both delegate entirely to the storage-proofs
// module (via SchemeByProtocol); no cryptography is reimplemented here.
func (c *Client) Audit(ctx context.Context, keyID string, setup *SetupResponse, protocol string, opts *AuditOptions) (*AuditResult, error) {
	if opts == nil {
		opts = &AuditOptions{}
	}
	targetRoots := opts.Roots
	if len(targetRoots) == 0 {
		for _, r := range setup.Roots {
			targetRoots = append(targetRoots, r.Root)
		}
	}
	chalSize := opts.ChallengeSize
	if chalSize <= 0 {
		chalSize = 20
	}

	if c.trustedKey == nil {
		return nil, fmt.Errorf("proverclient: no trusted key configured; pass WithTrustedKey(...) to NewClient")
	}
	if err := verifySetupAuthenticity(c.trustedKey, keyID, setup, targetRoots); err != nil {
		return nil, err
	}

	combinedIDs, err := BuildCombinedIDs(setup, targetRoots)
	if err != nil {
		return nil, err
	}
	if len(combinedIDs) == 0 {
		return nil, fmt.Errorf("proverclient: no blocks to audit for roots %v", targetRoots)
	}

	spec, ok := SchemeByProtocol(protocol)
	if !ok {
		return nil, fmt.Errorf("proverclient: unknown protocol %q", protocol)
	}
	challenger, err := spec.ChalFactory.NewChallenger(setup.ClientSetup, chalSize)
	if err != nil {
		return nil, fmt.Errorf("proverclient: new challenger: %w", err)
	}
	chal, validator, err := challenger.Challenge(combinedIDs)
	if err != nil {
		return nil, fmt.Errorf("proverclient: generate challenge: %w", err)
	}

	submission, err := c.Prove(ctx, keyID, targetRoots, chal, "")
	if err != nil {
		return nil, err
	}
	proof, err := c.WaitForProve(ctx, submission.JobID, &WaitForProveOptions{
		PollInterval: opts.PollInterval,
		Challenge:    chal,
		Roots:        targetRoots,
		OnStatus:     opts.OnStatus,
	})
	if err != nil {
		return nil, err
	}

	ok2, err := validator.Verify(chal, line.Proof(proof))
	if err != nil {
		return nil, fmt.Errorf("proverclient: verify: %w", err)
	}

	return &AuditResult{
		Pass:          ok2,
		BlocksChecked: len(combinedIDs),
		KeyID:         keyID,
		Roots:         targetRoots,
		Challenge:     chal,
	}, nil
}

// ---------------------------------------------------------------------------
// Challenge-building helpers (advanced use / other protocols)
// ---------------------------------------------------------------------------

// SchemeByProtocol maps a protocol name ("sw-pub", "sw-priv", "ateniese", …)
// to its capability.SchemeSpec, exactly as pinion-prover's testclient did.
// Exposed for callers that want to drive Challenger/Prover/Validator
// directly instead of going through Audit.
func SchemeByProtocol(protocol string) (*capability.SchemeSpec, bool) {
	for i := range capability.Schemes {
		key := strings.ToLower(strings.ReplaceAll(capability.Schemes[i].Name, " ", "-"))
		if key == protocol {
			return &capability.Schemes[i], true
		}
	}
	return nil, false
}

// BuildCombinedIDs builds the challenge ids for targetRoots from a
// SetupResponse. For chunked protocols (BlockCount > 0), ids are
// rootCID||localIndex, constructed entirely client-side via
// ipfsproof.SuperBlockID; no manifest needed beyond the root CID and the
// block count already in setup. For CID-addressed protocols, ids are the
// real block CIDs in BlockIDs. Roots from different protocols/roots can be
// combined in one call: this is what lets a single challenge span multiple
// independently-tagged pinned files.
func BuildCombinedIDs(setup *SetupResponse, targetRoots []string) ([][]byte, error) {
	byRoot := make(map[string]TaggedRoot, len(setup.Roots))
	for _, r := range setup.Roots {
		byRoot[r.Root] = r
	}

	var combined [][]byte
	for _, r := range targetRoots {
		info, ok := byRoot[r]
		if !ok {
			return nil, fmt.Errorf("proverclient: root %s not in setup", r)
		}
		if info.BlockCount > 0 {
			root, err := cid.Decode(r)
			if err != nil {
				return nil, fmt.Errorf("proverclient: decode root CID %s: %w", r, err)
			}
			for i := 0; i < info.BlockCount; i++ {
				combined = append(combined, ipfsproof.SuperBlockID(root, uint64(i)))
			}
			continue
		}
		for _, cidStr := range info.BlockIDs {
			bc, err := cid.Decode(cidStr)
			if err != nil {
				return nil, fmt.Errorf("proverclient: decode block CID %s: %w", cidStr, err)
			}
			combined = append(combined, bc.Bytes())
		}
	}
	return combined, nil
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

// authPath builds the full URL for an authenticated request, rooted at
// whatever WithAuthURL configured. Errors if it wasn't, rather than
// silently falling back to baseURL and producing a confusing 404/401.
func (c *Client) authPath(suffix string) (string, error) {
	if c.authURL == "" {
		return "", fmt.Errorf("proverclient: no auth URL configured; pass WithAuthURL(...) to NewClient")
	}
	return c.authURL + suffix, nil
}

func pathEscape(s string) string {
	// Path segments here are UUIDs/CIDs, no reserved characters, but escape
	// defensively rather than assume that never changes.
	return strings.ReplaceAll(strings.ReplaceAll(s, "?", "%3F"), "#", "%23")
}

func preview(b []byte) string {
	const max = 200
	if len(b) > max {
		return string(b[:max])
	}
	return string(b)
}

func mustRequest(ctx context.Context, method, url string, body []byte, headers map[string]string) *http.Request {
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, r)
	if err != nil {
		// Only possible if method/url are malformed, which would be a bug in
		// this package, not a runtime condition callers should handle.
		panic(fmt.Sprintf("proverclient: build request: %v", err))
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (c *Client) authHeaders(ctx context.Context) (map[string]string, error) {
	token, err := c.getToken(ctx)
	if err != nil {
		return nil, err
	}
	if token == "" {
		return nil, nil
	}
	return map[string]string{"Authorization": "Bearer " + token}, nil
}

// get, post, authDelete, and authPatch all take a fully-qualified URL, not
// a path relative to baseURL: callers build that themselves, either via
// authPath (for the authenticated routes rooted at authURL) or by
// prepending baseURL directly (for the couple of unauthenticated routes,
// e.g. ProveStatus). Keeping "what's the root for this call" entirely at
// the call site avoids this layer having to guess.
func (c *Client) get(ctx context.Context, url string, out any) error {
	headers, err := c.authHeaders(ctx)
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Do(mustRequest(ctx, http.MethodGet, url, nil, headers))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return decodeOrError(resp, out)
}

func (c *Client) post(ctx context.Context, url string, body, out any) error {
	headers, err := c.authHeaders(ctx)
	if err != nil {
		return err
	}
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Do(mustRequest(ctx, http.MethodPost, url, data, headers))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return decodeOrError(resp, out)
}

func (c *Client) authDelete(ctx context.Context, url string) error {
	headers, err := c.authHeaders(ctx)
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Do(mustRequest(ctx, http.MethodDelete, url, nil, headers))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return decodeOrError(resp, nil)
}

func (c *Client) authPatch(ctx context.Context, url string, body any) error {
	headers, err := c.authHeaders(ctx)
	if err != nil {
		return err
	}
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Do(mustRequest(ctx, http.MethodPatch, url, data, headers))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return decodeOrError(resp, nil)
}

// decodeOrError reads resp fully, returning a ProverError for a non-2xx
// status or a MalformedResponseError if a successful response's body isn't
// valid JSON (e.g. a proxy's HTML error page returned with a 200). out may
// be nil for responses with no useful body (DELETE/PATCH).
func decodeOrError(resp *http.Response, out any) error {
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &ProverError{Status: resp.StatusCode, Body: string(body)}
	}
	if out == nil || len(body) == 0 {
		return nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		return &MalformedResponseError{Status: resp.StatusCode, BodyPreview: preview(body), Cause: err}
	}
	return nil
}
