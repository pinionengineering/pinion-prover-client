// Package proverclient is a thin Go client for the pinion-prover storage-proof
// service. It is deliberately not a reimplementation of any cryptography: all
// challenge/proof/verify logic is delegated to the storage-proofs and
// ipfs-storage-proofs modules (the same libraries pinion-prover itself is
// built on), exactly as pinion-prover's own testclient does. What this
// package adds on top is the same ergonomic layer the JS client
// (@pinionengineering/prover-client) has: a Client with typed methods,
// automatic polling of the async tag/prove jobs, typed errors, and an
// Audit() convenience that runs challenge → prove → verify in one call.
//
// Route structure (baseURL = ".../prover"):
//
//	Authenticated (JWT Bearer):  {baseURL}/api/v1/*
//	Unauthenticated:             {baseURL}/prove, {baseURL}/prove/:job_id
package proverclient

import (
	"bytes"
	"context"
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
	httpClient *http.Client
	getToken   func(ctx context.Context) (string, error)
}

// Option configures a Client constructed by NewClient.
type Option func(*Client)

// WithHTTPClient overrides the default http.Client (e.g. for custom timeouts
// or transport-level tracing).
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) { c.httpClient = hc }
}

// WithTokenFunc supplies a JWT Bearer token for authenticated (/api/v1/*)
// requests. Called fresh before every authenticated request; return ("", nil)
// if no token is available.
func WithTokenFunc(f func(ctx context.Context) (string, error)) Option {
	return func(c *Client) { c.getToken = f }
}

// NewClient returns a Client for the prover deployment at baseURL, e.g.
// "https://hydrogen.pinion.build/prover".
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
	var out []ChallengeKeyInfo
	if err := c.get(ctx, "/api/v1/challenge-keys", &out); err != nil {
		return nil, err
	}
	return out, nil
}

// CreateKey creates a challenge key on the server. label may be empty.
func (c *Client) CreateKey(ctx context.Context, protocol, label string) (*CreateKeyResponse, error) {
	var out CreateKeyResponse
	err := c.post(ctx, "/api/v1/challenge-key", CreateKeyRequest{Protocol: protocol, Label: label}, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) DeleteKey(ctx context.Context, keyID string) error {
	return c.authDelete(ctx, "/api/v1/challenge-key/"+pathEscape(keyID))
}

// UpdateKeyLabel renames a key after creation. Pass an empty label to clear it.
func (c *Client) UpdateKeyLabel(ctx context.Context, keyID, label string) error {
	return c.authPatch(ctx, "/api/v1/challenge-key/"+pathEscape(keyID), UpdateKeyLabelRequest{Label: label})
}

// ---------------------------------------------------------------------------
// Setup phase
// ---------------------------------------------------------------------------

// GetSetup fetches the setup document for a key: public key material and,
// per registered root, either the block ID list (non-chunked protocols) or
// the super-block count (chunked protocols: SW-Priv, SW-Pub).
func (c *Client) GetSetup(ctx context.Context, keyID string) (*SetupResponse, error) {
	var out SetupResponse
	if err := c.get(ctx, "/api/v1/setup?key_id="+pathEscape(keyID), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// TagOptions configures Tag's job-status polling.
type TagOptions struct {
	// PollInterval between GET /tag/:job_id polls. Default 1s.
	PollInterval time.Duration
	// Timeout before giving up and returning TagTimeoutError. Default 10m.
	Timeout time.Duration
	// OnProgress, if set, is called after every status poll with the latest
	// progress and raw status string.
	OnProgress func(progress TagJobProgress, status string)
}

// Tag asks the server to walk the IPFS DAG for root, compute per-block
// authentication tags, and store them under keyID. root must already be in
// the "pinned" lifecycle state for the authenticated account.
//
// Tagging is asynchronous on the server: this posts the job, then polls GET
// /api/v1/tag/:job_id until it reaches a terminal state, so Tag only returns
// once tagging is actually done. Call GetSetup after Tag to get the updated
// block ID list for the next audit cycle.
func (c *Client) Tag(ctx context.Context, root, keyID string, opts *TagOptions) (*TagJobStatusResponse, error) {
	if opts == nil {
		opts = &TagOptions{}
	}
	pollInterval := opts.PollInterval
	if pollInterval <= 0 {
		pollInterval = time.Second
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}

	var jobResp TagJobResponse
	if err := c.post(ctx, "/api/v1/tag", TagRequest{Root: root, KeyID: keyID}, &jobResp); err != nil {
		return nil, fmt.Errorf("tag %s: %w", root, err)
	}

	deadline := time.Now().Add(timeout)
	for {
		status, err := c.TagStatus(ctx, jobResp.JobID)
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
			return nil, &TagFailedError{JobID: jobResp.JobID, Reason: status.Error}
		}
		if time.Now().After(deadline) {
			return nil, &TagTimeoutError{JobID: jobResp.JobID, LastStatus: status.Status}
		}
		if err := sleepCtx(ctx, pollInterval); err != nil {
			return nil, err
		}
	}
}

// TagStatus polls the status of a tag job started by Tag, without waiting
// for it to reach a terminal state. Useful for building progress UI.
func (c *Client) TagStatus(ctx context.Context, jobID string) (*TagJobStatusResponse, error) {
	var out TagJobStatusResponse
	if err := c.get(ctx, "/api/v1/tag/"+pathEscape(jobID), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListTagJobs lists the caller's tag jobs, most recently created first. Set
// active to list only non-terminal jobs (queued/planning/running/merging),
// what a "tagging in progress" indicator should poll, since it works without
// already knowing a job ID.
func (c *Client) ListTagJobs(ctx context.Context, active bool) ([]TagJobListEntry, error) {
	path := "/api/v1/tag"
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
	return c.authDelete(ctx, "/api/v1/register/"+pathEscape(keyID)+"/"+pathEscape(root))
}

// ---------------------------------------------------------------------------
// Audit phase
// ---------------------------------------------------------------------------

// ProveOptions configures Prove's job-status polling.
type ProveOptions struct {
	// PollInterval between GET /prove/:job_id polls. Default 500ms.
	PollInterval time.Duration
	// Timeout before giving up and returning ProveTimeoutError. Default 60s,
	// much shorter than Tag's default, since a proof round is one bounded
	// crypto operation over the sampled blocks, not a per-block DAG walk.
	Timeout time.Duration
}

// Prove posts a challenge to POST /prove (unauthenticated: the server
// resolves the account from keyID) and polls until the job reaches a
// terminal state, returning the raw proof bytes. Most callers should use
// Audit instead, which also cryptographically verifies the response.
//
// challengeID is an optional idempotency key; leave it empty for normal
// audit rounds, each of which should be a fresh, independently random
// challenge that must never be deduped against a previous one.
func (c *Client) Prove(ctx context.Context, keyID string, roots []string, challenge []byte, challengeID string, opts *ProveOptions) ([]byte, error) {
	if opts == nil {
		opts = &ProveOptions{}
	}
	pollInterval := opts.PollInterval
	if pollInterval <= 0 {
		pollInterval = 500 * time.Millisecond
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}

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
		var body struct {
			CID string `json:"cid"`
		}
		_ = json.Unmarshal(respBody, &body)
		return nil, &PinNotActiveError{CID: body.CID}
	}
	if resp.StatusCode != http.StatusAccepted {
		return nil, &ProverError{Status: resp.StatusCode, Body: string(respBody)}
	}
	var jobResp ProveJobResponse
	if err := json.Unmarshal(respBody, &jobResp); err != nil {
		return nil, &MalformedResponseError{Status: resp.StatusCode, BodyPreview: preview(respBody), Cause: err}
	}

	deadline := time.Now().Add(timeout)
	for {
		status, err := c.ProveStatus(ctx, jobResp.JobID)
		if err != nil {
			return nil, err
		}
		switch status.Status {
		case "prove-done":
			return status.Proof, nil
		case "prove-failed":
			return nil, &ProveFailedError{JobID: jobResp.JobID, Reason: status.Error, Challenge: challenge, Roots: roots}
		}
		if time.Now().After(deadline) {
			return nil, &ProveTimeoutError{JobID: jobResp.JobID, LastStatus: status.Status, Challenge: challenge, Roots: roots}
		}
		if err := sleepCtx(ctx, pollInterval); err != nil {
			return nil, err
		}
	}
}

// ProveStatus polls the status of a proof job started by Prove.
func (c *Client) ProveStatus(ctx context.Context, jobID string) (*ProveJobStatusResponse, error) {
	var out ProveJobStatusResponse
	if err := c.get(ctx, "/prove/"+pathEscape(jobID), &out); err != nil {
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

	proof, err := c.Prove(ctx, keyID, targetRoots, chal, "", nil)
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

func (c *Client) get(ctx context.Context, path string, out any) error {
	headers, err := c.authHeaders(ctx)
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Do(mustRequest(ctx, http.MethodGet, c.baseURL+path, nil, headers))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return decodeOrError(resp, out)
}

func (c *Client) post(ctx context.Context, path string, body, out any) error {
	headers, err := c.authHeaders(ctx)
	if err != nil {
		return err
	}
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Do(mustRequest(ctx, http.MethodPost, c.baseURL+path, data, headers))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return decodeOrError(resp, out)
}

func (c *Client) authDelete(ctx context.Context, path string) error {
	headers, err := c.authHeaders(ctx)
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Do(mustRequest(ctx, http.MethodDelete, c.baseURL+path, nil, headers))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return decodeOrError(resp, nil)
}

func (c *Client) authPatch(ctx context.Context, path string, body any) error {
	headers, err := c.authHeaders(ctx)
	if err != nil {
		return err
	}
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Do(mustRequest(ctx, http.MethodPatch, c.baseURL+path, data, headers))
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
