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
  l: number;        // challenge size: blocks sampled per audit round
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
  c: number;        // number of blocks sampled in this round (≤ l, ≤ n)
  n: number;        // total blocks in the challenged store
}

/**
 * The proof returned by POST /prove as application/octet-stream.
 * Despite the content-type, the body is JSON.
 * Matches wireProof in storage-proofs/line/swpub/adapter.go.
 */
export interface WireProof {
  sigma: string;  // base64 of 64-byte G1 accumulator σ = Σ νₜ·σᵢₜ
  mu: string[];   // base64 of 32-byte Z_q scalars μⱼ = Σ νₜ·fᵢₜⱼ (s elements)
}

/** One root entry in the setup response. */
export interface RawTaggedRoot {
  root: string;        // CID string
  block_ids: string[]; // base64-encoded CID.Bytes() in TagList order
}

/** Raw JSON from GET /api/v1/setup?key_id=<id>. */
export interface RawSetupResponse {
  client_setup: string;    // base64 of WireClientSetup JSON
  roots: RawTaggedRoot[];
}

/** A root entry with block IDs already decoded to Uint8Arrays. */
export interface ParsedRoot {
  root: string;
  blockIds: Uint8Array[]; // CID bytes in TagList order; feed directly to verifyProof
}

/** Fully decoded result of getSetup(). Ready to pass to audit(). */
export interface ParsedSetup {
  clientSetup: WireClientSetup;
  roots: ParsedRoot[];
  /** Sum of block counts across all roots. */
  totalBlocks: number;
  /** The l field from clientSetup: recommended blocks per challenge round. */
  challengeSize: number;
}

export interface ChallengeKeyInfo {
  key_id: string;
  protocol: string;
  created_at: string; // RFC3339
  audit_count: number;
  blocks_audited: number;
}

export interface CreateKeyResponse {
  key_id: string;
  client_setup: string; // base64 of WireClientSetup JSON (same shape as ParsedSetup.clientSetup)
}

export interface TagResponse {
  block_ids: string[]; // base64-encoded CID.Bytes() in TagList order
}

/** Result of a complete audit round (challenge → prove → cryptographic verify). */
export interface AuditResult {
  /** true only if the pairing check e(σ,G₂) == e(A,v) passed. */
  pass: boolean;
  blocksChecked: number;
  keyId: string;
  roots: string[];
}
