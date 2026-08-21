package proverclient

// Wire request/response types for the pinion-prover HTTP API. These mirror
// pinion-prover's own (private-repo) models package field-for-field, kept as
// a self-contained copy here so this client never needs to import a private
// module just to speak the wire format it already knows.

// WireTagBlock pairs a base64-encoded proof tag with the string representation
// of the IPFS CID of the block it authenticates.
type WireTagBlock struct {
	Tag string `json:"tag"` // base64-encoded tag bytes
	CID string `json:"cid"` // CID.String() representation
}

// CreateKeyRequest is the body for POST /challenge-key.
type CreateKeyRequest struct {
	Protocol string `json:"protocol"`        // "sw-priv" or "sw-pub"
	Label    string `json:"label,omitempty"` // optional human-readable name
}

// CreateKeyResponse is returned by POST /challenge-key. ClientSetup is
// everything the caller needs to act as a Challenger for any root tagged
// under this key.
type CreateKeyResponse struct {
	KeyID       string `json:"key_id"`
	ClientSetup []byte `json:"client_setup"`
	// ClientSetupSig authenticates (KeyID, ClientSetup) against a signing
	// key held only by pinion-prover; see VerifyClientSetupSig. Empty if the
	// server wasn't configured with a signing key.
	ClientSetupSig []byte `json:"client_setup_sig,omitempty"`
	Label          string `json:"label,omitempty"`
}

// UpdateKeyLabelRequest is the body for PATCH /challenge-key/:id.
type UpdateKeyLabelRequest struct {
	Label string `json:"label"`
}

// ChallengeKeyInfo is one entry in the GET /challenge-keys listing.
type ChallengeKeyInfo struct {
	KeyID     string `json:"key_id"`
	Protocol  string `json:"protocol"`
	CreatedAt string `json:"created_at"` // RFC3339
	Label     string `json:"label,omitempty"`

	AuditCount    int64  `json:"audit_count"`
	BlocksAudited int64  `json:"blocks_audited"`
	LastAuditedAt string `json:"last_audited_at,omitempty"` // RFC3339
}

// TaggedRoot is a root CID paired with what the client needs to build a
// challenge for that root. Exactly one of BlockIDs/BlockCount is populated:
// BlockIDs for protocols addressed by real IPFS block CID (Ateniese, Erway,
// BJO); BlockCount for protocols that virtualize each root into uniform
// super-blocks (SW-Priv, SW-Pub); for those, ids are synthesized locally as
// SuperBlockID(root, i) for i in [0, BlockCount), no manifest needed.
type TaggedRoot struct {
	Root       string   `json:"root"`
	BlockIDs   []string `json:"block_ids,omitempty"`
	BlockCount int      `json:"block_count,omitempty"`
	// BlockCountSig authenticates (KeyID, Root, BlockCount) -- KeyID isn't
	// repeated here since it's already the parameter this TaggedRoot was
	// fetched under. See VerifyBlockCountSig. Only set for chunked
	// protocols (SW-Priv, SW-Pub), same as BlockCount.
	BlockCountSig []byte `json:"block_count_sig,omitempty"`
}

// SetupResponse is returned by GET /setup?key_id=<id>.
type SetupResponse struct {
	ClientSetup    []byte       `json:"client_setup"`
	ClientSetupSig []byte       `json:"client_setup_sig,omitempty"` // see CreateKeyResponse.ClientSetupSig
	Roots          []TaggedRoot `json:"roots"`
}

// TagRequest is the body for POST /tag. Root must already be pinned by the
// authenticated account.
type TagRequest struct {
	Root  string `json:"root"`
	KeyID string `json:"key_id"`
}

// TagJobResponse is returned by POST /tag: the tag job has been created and
// queued. Poll GET /tag/:job_id with this JobID for status and, once done,
// the result.
type TagJobResponse struct {
	JobID string `json:"job_id"`
}

// TagSubmission is returned by Client.Tag: the job has been created and
// queued. Pass JobID to WaitForTag to block until it reaches a terminal
// state.
type TagSubmission struct {
	JobID string
	Root  string
	KeyID string
}

// TagJobProgress reports how much of an in-flight tag job has completed.
// NodesWalked/BytesWalked cover the DAG-walk planning phase, before
// TotalBlocks is even known -- both zero once TotalBlocks becomes nonzero.
// EstimatedTotalBytes, looked up once server-side from the pin's own
// recorded size, lets a client render BytesWalked/EstimatedTotalBytes as a
// percentage during that phase; it's an estimate, not exact, since it comes
// from a different size computation than BytesWalked's own sum, and may be
// absent if the size lookup failed.
type TagJobProgress struct {
	TotalBlocks         int    `json:"total_blocks"`
	CompletedBlocks     int    `json:"completed_blocks"`
	NodesWalked         int    `json:"nodes_walked,omitempty"`
	BytesWalked         uint64 `json:"bytes_walked,omitempty"`
	EstimatedTotalBytes uint64 `json:"estimated_total_bytes,omitempty"`
}

// TagJobStatusResponse is returned by GET /tag/:job_id. Status is one of
// "tag-queued" | "tag-planning" | "tag-running" | "tag-merging" | "tag-done" |
// "tag-failed". BlockIDs/BlockCount are populated only once Status is
// "tag-done". Error is populated only once Status is "tag-failed".
type TagJobStatusResponse struct {
	Status     string          `json:"status"`
	Progress   *TagJobProgress `json:"progress,omitempty"`
	BlockIDs   []string        `json:"block_ids,omitempty"`
	BlockCount int             `json:"block_count,omitempty"`
	Error      string          `json:"error,omitempty"`
}

// TagJobListEntry summarizes one tag job as returned by GET /tag.
type TagJobListEntry struct {
	JobID    string          `json:"job_id"`
	Root     string          `json:"root"`
	KeyID    string          `json:"key_id"`
	Status   string          `json:"status"`
	Progress *TagJobProgress `json:"progress,omitempty"`
}

// TagJobListResponse is returned by GET /tag. Jobs are ordered most recently
// created first.
type TagJobListResponse struct {
	Jobs []TagJobListEntry `json:"jobs"`
}

// CreateShareRequest is the body for POST /share. The account must own
// KeyID. ExpiresInSeconds is optional; omitted or zero means the link never
// expires.
type CreateShareRequest struct {
	KeyID            string `json:"key_id"`
	Description      string `json:"description,omitempty"`
	ExpiresInSeconds int64  `json:"expires_in_seconds,omitempty"`
}

// CreateShareResponse is returned by POST /share.
type CreateShareResponse struct {
	Token string `json:"token"`
}

// ShareResolveResponse is returned by GET /share/:token/resolve. Roots
// covers every root currently tagged under KeyID -- the account's whole
// "verification set" under this key, reconstructed fresh at resolve time,
// not frozen at share-creation time. AuditCount/BlocksAudited/
// LastAuditedAt are likewise read fresh at resolve time. ExpiresAt is empty
// when the link has no expiration.
type ShareResolveResponse struct {
	CompanyName    string       `json:"company_name"`
	Description    string       `json:"description,omitempty"`
	KeyID          string       `json:"key_id"`
	ClientSetup    []byte       `json:"client_setup"`
	ClientSetupSig []byte       `json:"client_setup_sig,omitempty"`
	Roots          []TaggedRoot `json:"roots"`

	AuditCount    int64  `json:"audit_count"`
	BlocksAudited int64  `json:"blocks_audited"`
	LastAuditedAt string `json:"last_audited_at,omitempty"`
	ExpiresAt     string `json:"expires_at,omitempty"`
}

// RegisterRequest is the body for POST /register: used when the client has
// tagged the data itself (Ateniese client-side flow) and wants to deposit
// the prover-side material with the service.
type RegisterRequest struct {
	Root        string         `json:"root"`
	Protocol    string         `json:"protocol"`
	KeyID       string         `json:"key_id"`
	ProverSetup []byte         `json:"prover_setup"`
	Tags        []WireTagBlock `json:"tags"`
}

// ProveRequest is the body for POST /prove. POST /prove is unauthenticated:
// the server identifies the account from the ChallengeKey record for KeyID.
type ProveRequest struct {
	KeyID       string   `json:"key_id"`
	Roots       []string `json:"roots"`        // CID strings; empty = all roots for key
	Challenge   []byte   `json:"challenge"`    // opaque bytes from a Challenger
	ChallengeID string   `json:"challenge_id"` // optional client idempotency key
}

// ProveJobResponse is returned by POST /prove: the proof job has been
// created and queued. Poll GET /prove/:job_id with this JobID for status.
type ProveJobResponse struct {
	JobID string `json:"job_id"`
}

// ProveSubmission is returned by Client.Prove: the job has been created and
// queued. Pass JobID to WaitForProve to block until the proof is ready.
type ProveSubmission struct {
	JobID     string
	Challenge []byte
	Roots     []string
}

// ProveJobStatusResponse is returned by GET /prove/:job_id, unauthenticated
// like POST /prove. Status is one of "prove-queued" | "prove-running" |
// "prove-done" | "prove-failed". Error is populated only once Status is
// "prove-failed".
//
// Proof and the fields below it are populated only once Status is
// "prove-done", and together form a self-contained envelope: KeyID, Seed,
// C, N, and Roots are everything needed (beyond the account's public setup
// key) to independently rebuild the challenge and verify Proof, and Sig
// authenticates all of them together -- see VerifyProofSig.
type ProveJobStatusResponse struct {
	Status      string `json:"status"`
	ChallengeID string `json:"challenge_id,omitempty"`
	Error       string `json:"error,omitempty"`

	Proof []byte   `json:"proof,omitempty"`
	KeyID string   `json:"key_id,omitempty"`
	Seed  []byte   `json:"seed,omitempty"`
	C     int      `json:"c,omitempty"`
	N     int      `json:"n,omitempty"`
	Roots []string `json:"roots,omitempty"`
	Sig   []byte   `json:"sig,omitempty"`
}
