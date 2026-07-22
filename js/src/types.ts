/**
 * Wire format types for the pinion-prover service.
 *
 * All byte fields (G1/G2 curve points, scalars, seeds) are transmitted as
 * standard base64 strings inside JSON objects.  The Go service uses encoding/json
 * which encodes []byte as base64 automatically.
 */

/**
 * The client_setup blob embedded in SetupResponse.
 * Matches wireClientSetup in storage-proofs/line/swpub/adapter.go.
 */
export interface WireClientSetup {
  protocol: string; // "swpub"
  suite_id: number; // 1 = SuiteV1 (HMAC-SHA256)
  s: number;        // sectors per block (determines μ vector length)
  name: string;     // base64 of 16-byte random file-name λ bound into every tag
  v: string;        // base64 of 128-byte G2 point V = α·G₂ (public key)
  u: string[];      // base64 of 64-byte G1 points u₁…uₛ (s elements)
}

/**
 * The challenge sent to POST /prove.
 * Matches wireChal in storage-proofs/line/swpub/adapter.go.
 * Transmitted as base64(JSON(wireChal)).
 */
export interface WireChallenge {
  suite_id: number; // 1 = SuiteV1
  seed: string;     // base64 of 32 random bytes; all indices/coeffs are derived from this
  c: number;        // number of blocks sampled in this round (≤ n)
  n: number;        // total blocks in the challenged store
}

/**
 * The proof returned by POST /prove as JSON.
 * Matches wireProof in storage-proofs/line/swpub/adapter.go.
 */
export interface WireProof {
  sigma: string;  // base64 of 64-byte G1 accumulator σ = Σ νₜ·σᵢₜ
  mu: string[];   // base64 of 32-byte Z_q scalars μⱼ = Σ νₜ·fᵢₜⱼ (s elements)
}

/**
 * JSON response from POST /prove.
 *
 * @deprecated Proving is now asynchronous. POST /prove returns a
 * ProveJobResponse immediately; poll GET /prove/:job_id for a
 * ProveJobStatusResponse, which carries these same fields once done.
 */
export interface ProveResponse {
  challenge_id: string; // echoed from ProveRequest.challenge_id
  proof: string;        // base64-encoded proof bytes (encoding/json encodes []byte as base64)
}

/** Returned by POST /prove: the proof job has been created and queued. */
export interface ProveJobResponse {
  job_id: string;
}

/**
 * Raw status response from GET /prove/:job_id. This endpoint is
 * unauthenticated, same as POST /prove — job_id is a fresh, unguessable
 * identifier (or, when the request carried a challenge_id, deterministic
 * from (key_id, challenge_id)), so possession of it is the only
 * authorization this route needs.
 *
 * `status` is one of "prove-queued" | "prove-running" | "prove-done" |
 * "prove-failed". `challenge_id` echoes the value from the original
 * request. `proof` is populated only once `status` is "prove-done" — the
 * same field ProveResponse used to return synchronously. `error` is
 * populated only once `status` is "prove-failed".
 */
export interface ProveJobStatusResponse {
  status: string;
  challenge_id?: string;
  proof?: string;
  error?: string;
}

/**
 * One root entry in the setup response. Exactly one of block_ids/block_count
 * is populated: block_ids for protocols addressed by real IPFS block CID
 * (Ateniese, Erway, BJO); block_count for protocols that virtualize each root
 * into uniform super-blocks (SW-Priv, SW-Pub). For the latter, no per-block
 * manifest is sent at all — challenge ids are `rootCID.Bytes() || BE64(localIndex)`
 * for localIndex in [0, block_count), constructible from `root` plus this one
 * integer. See superBlockId() in challenge.ts, an exact port of SuperBlockID()
 * in ipfs-storage-proofs/superblock.go.
 */
export interface RawTaggedRoot {
  root: string;          // CID string (e.g. "bafybeig...")
  block_ids?: string[];  // CID strings in TagList order — non-chunked protocols only
  block_count?: number;  // super-block count — chunked protocols only (SW-Priv, SW-Pub)
}

/** Raw JSON from GET /api/v1/setup?key_id=<id>. */
export interface RawSetupResponse {
  client_setup: string;    // base64 of WireClientSetup JSON
  roots: RawTaggedRoot[];
}

/** A root entry with block IDs already decoded to Uint8Arrays. */
export interface ParsedRoot {
  root: string;
  /**
   * Ids ready to feed directly to buildChallenge()/verifyProof(), in order.
   * For non-chunked protocols these are real per-block CID bytes; for chunked
   * protocols (see `chunked` below) these are synthesized super-block ids
   * (superBlockId(rootBytes, i) for i in [0, block_count)) — opaque either way
   * to buildChallenge()/verifyProof(), which only need byte-identity, not
   * meaning.
   */
  blockIds: Uint8Array[];
  /**
   * True if `blockIds` are synthesized super-block ids (chunked protocol:
   * SW-Priv, SW-Pub) rather than real per-block CIDs. Callers that need to
   * re-derive or re-export ids (e.g. writing an external client-state file)
   * must branch on this — synthesized ids are not valid CIDs and must be
   * reconstructed from `root` + a block count, never decoded as one.
   */
  chunked: boolean;
}

/** Fully decoded result of getSetup(). Ready to pass to audit(). */
export interface ParsedSetup {
  clientSetup: WireClientSetup;
  roots: ParsedRoot[];
  /** Sum of block counts across all roots. */
  totalBlocks: number;
}

export interface ChallengeKeyInfo {
  key_id: string;
  protocol: string;
  created_at: string; // RFC3339
  /** Human-readable name, if one was set. Empty for unnamed keys — a UUID
   * alone isn't usable in a UI once an account has more than one or two
   * keys, so callers should fall back to something derived from
   * created_at/key_id for display rather than assume this is always set. */
  label?: string;
  audit_count: number;
  blocks_audited: number;
  /** RFC3339; absent if the key has never been successfully audited. */
  last_audited_at?: string;
}

/** Raw wire response from POST /api/v1/challenge-key. */
export interface CreateKeyResponse {
  key_id: string;
  client_setup: string; // base64(JSON(WireClientSetup))
  label?: string; // echoes the label passed to createKey(), if any
}

/** Body for PATCH /api/v1/challenge-key/:id. */
export interface UpdateKeyLabelRequest {
  label: string;
}

/**
 * Result of createKey() — the key ID plus the decoded public key material.
 *
 * `publicKey` contains the G1/G2 points needed to verify proofs locally.
 * Unlike a symmetric secret, this is the *public* half of the key pair — the
 * private half (α) never leaves the server.  You can safely store publicKey
 * alongside keyId so that future audits can verify proofs without trusting the
 * server to return the same key material each time.
 */
export interface CreateKeyResult {
  keyId: string;
  publicKey: WireClientSetup;
  label?: string;
}

/**
 * Raw tag response from POST /api/v1/tag. Exactly one of block_ids/block_count
 * is populated — see RawTaggedRoot's doc comment for which protocols use which.
 *
 * For non-chunked protocols, `block_ids` is the ordered list of CID strings
 * for every block in the DAG; this same list is returned by getSetup() per
 * root and is what the client uses to select which blocks to challenge — the
 * server never picks them. For chunked protocols (SW-Priv, SW-Pub),
 * `block_count` is the super-block count instead — no manifest needed.
 */
export interface TagResponse {
  block_ids?: string[]; // CID strings in TagList order — non-chunked protocols only
  block_count?: number; // super-block count — chunked protocols only
}

/** Returned by POST /api/v1/tag: the tag job has been created and queued. */
export interface TagJobResponse {
  job_id: string;
}

/** How much of an in-flight tag job has completed. */
export interface TagJobProgress {
  total_blocks: number;
  completed_blocks: number;
}

/**
 * Raw status response from GET /api/v1/tag/:job_id.
 *
 * `status` is one of the tagstate.Lifecycle string values from pinion-prover:
 * "tag-queued" | "tag-planning" | "tag-running" | "tag-merging" | "tag-done" |
 * "tag-failed". `block_ids`/`block_count` are populated only once `status` is
 * "tag-done" — the same fields TagResponse used to return synchronously.
 * `error` is populated only once `status` is "tag-failed".
 */
export interface TagJobStatusResponse {
  status: string;
  progress?: TagJobProgress;
  block_ids?: string[];
  block_count?: number;
  error?: string;
}

/**
 * One entry from GET /api/v1/tag — a summary of a tag job for listing,
 * without the terminal block_ids/block_count/error payload
 * TagJobStatusResponse carries.
 */
export interface TagJobListEntry {
  job_id: string;
  root: string;
  key_id: string;
  status: string;
  progress?: TagJobProgress;
}

/**
 * Raw response from GET /api/v1/tag: every tag job for the caller's
 * account, most recently created first. Pass ?active=true (via
 * listTagJobs's `active` option) to list only non-terminal jobs.
 */
export interface TagJobListResponse {
  jobs: TagJobListEntry[];
}

/**
 * Result of verifyProofResult() (see verify.ts). Distinguishes a genuine
 * cryptographic failure from one that couldn't even be evaluated:
 *
 *   - { verified: false, reason: 'pairing-mismatch' } means the pairing
 *     equation was evaluated and did not hold — the server either does not
 *     hold the data or returned a deliberately bad proof. This is the only
 *     case that should ever be reported to a user as evidence of possible
 *     data loss.
 *   - { verified: false, reason: 'malformed-input', cause } means the
 *     equation was never evaluated at all — proofBytes wasn't valid
 *     WireProof JSON, a curve point failed to decode, etc. This is what an
 *     infra error looks like from here: a 5xx with an HTML body, a proxy
 *     timeout page, a truncated response — none of which say anything about
 *     whether the server actually holds the data.
 *
 * verifyProof() collapses both false cases into a plain `false`, which is
 * why it's the deprecated, lower-fidelity option.
 */
export type ProofVerificationResult =
  | { verified: true }
  | { verified: false; reason: 'pairing-mismatch' }
  | { verified: false; reason: 'malformed-input'; cause: unknown };

/** Result of a complete audit round (challenge → prove → cryptographic verify). */
export interface AuditResult {
  /** true only if the pairing check e(σ,G₂) == e(A,v) passed. */
  pass: boolean;
  /**
   * The richer verification outcome pass was derived from — check this to
   * distinguish a real cryptographic failure (reason: 'pairing-mismatch')
   * from one that couldn't be evaluated at all (reason: 'malformed-input').
   * Only the former should ever be reported to a user as evidence of
   * possible data loss.
   */
  verification: ProofVerificationResult;
  /** Number of blocks sampled in this challenge round. */
  blocksChecked: number;
  keyId: string;
  roots: string[];
  /** base64(JSON(WireChallenge)) used for this round — same bytes POST /prove sent. Decode with decodeChallenge(). */
  challenge: string;
}
