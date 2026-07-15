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
  l: number;        // challenge size (blocks per round) set at key creation
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

/** JSON response from POST /prove. */
export interface ProveResponse {
  challenge_id: string; // echoed from ProveRequest.challenge_id
  proof: string;        // base64-encoded proof bytes (encoding/json encodes []byte as base64)
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

/** Raw wire response from POST /api/v1/challenge-key. */
export interface CreateKeyResponse {
  key_id: string;
  client_setup: string; // base64(JSON(WireClientSetup))
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

/** Result of a complete audit round (challenge → prove → cryptographic verify). */
export interface AuditResult {
  /** true only if the pairing check e(σ,G₂) == e(A,v) passed. */
  pass: boolean;
  /** Number of blocks sampled in this challenge round. */
  blocksChecked: number;
  keyId: string;
  roots: string[];
}
