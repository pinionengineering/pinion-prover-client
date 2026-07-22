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
	Label       string `json:"label,omitempty"`
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
}

// SetupResponse is returned by GET /setup?key_id=<id>.
type SetupResponse struct {
	ClientSetup []byte       `json:"client_setup"`
	Roots       []TaggedRoot `json:"roots"`
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

// TagJobProgress reports how much of an in-flight tag job has completed.
type TagJobProgress struct {
	TotalBlocks     int `json:"total_blocks"`
	CompletedBlocks int `json:"completed_blocks"`
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

// ProveJobStatusResponse is returned by GET /prove/:job_id, unauthenticated
// like POST /prove. Status is one of "prove-queued" | "prove-running" |
// "prove-done" | "prove-failed". Proof is populated only once Status is
// "prove-done". Error is populated only once Status is "prove-failed".
type ProveJobStatusResponse struct {
	Status      string `json:"status"`
	ChallengeID string `json:"challenge_id,omitempty"`
	Proof       []byte `json:"proof,omitempty"`
	Error       string `json:"error,omitempty"`
}
