/**
 * SW-Pub proof verification.
 *
 * Implements the public-key verification equation from §3.3 of
 * Shacham & Waters, "Compact Proofs of Retrievability", ASIACRYPT 2008:
 *
 *   e(σ, G₂) == e(Σₜ νₜ·H(λ‖idᵢₜ) + Σⱼ μⱼ·uⱼ, v)
 *
 * where:
 *   σ       proof accumulator G1 point  (from server)
 *   G₂      generator of G2
 *   νₜ, iₜ  blinding coefficients and block indices (re-derived from seed)
 *   H(λ‖id) SHA-256(λ‖id) mod q · G₁    (ROM hash-to-G1)
 *   μⱼ      per-sector Z_q scalars       (from server)
 *   uⱼ      public key G1 elements       (from client_setup)
 *   v       V = α·G₂, public key G2 point (from client_setup)
 *
 * Correctness: any honest server response satisfies this equation because:
 *   σ = Σₜ νₜ·σᵢₜ  and  σᵢ = α·(H(λ‖idᵢ) + Σⱼ fᵢⱼ·uⱼ)
 * Substituting and using bilinearity of e gives the identity.
 *
 * Security: under the computational Diffie-Hellman assumption, a server
 * cannot forge a passing response without holding the tagged blocks.
 *
 * Ports verifyPubCore() in storage-proofs/por/sw/pub.go.
 */

import {
  atePairing,
  fp12Equal,
  g1Add,
  g1FromBytes,
  g1ScalarMult,
  g2FromBytes,
  bytesToBigInt,
  G2_BASE,
  type G1Point,
} from './bn254.js';
import { base64ToBytes, blockHashG1, deriveIndicesAndCoeffs } from './challenge.js';
import { verifyClientSetupSig, verifyBlockCountSig, verifyProofSig } from './trustkey.js';
import type { WireClientSetup, WireProof, ProofVerificationResult } from './types.js';

/** One root's authenticity inputs, checked before any pairing math runs. */
export interface VerifyRootEntry {
  root: string;
  /** Only present for chunked-protocol roots (SW-Priv, SW-Pub). */
  blockCount?: number;
  /** Only present for chunked-protocol roots; see ParsedRoot.blockCountSig. */
  blockCountSig?: Uint8Array;
}

export interface VerifyParams {
  /**
   * Ed25519 public key ClientSetup/BlockCount signatures are checked
   * against -- see PinionProverClientOptions.trustedKey for where this
   * should come from. There is no default: a caller must supply the real
   * key for whichever pinion-prover deployment these params came from.
   */
  trustedKey: Uint8Array;
  /** The key ID this proof was audited under -- both signatures below are bound to it. */
  keyId: string;
  /**
   * The parsed WireClientSetup from the client_setup blob.
   * Obtain via parseClientSetup() or directly from ParsedSetup.clientSetup.
   */
  clientSetup: WireClientSetup;
  /**
   * Raw base64-decoded client_setup bytes -- see ParsedSetup.clientSetupRaw
   * for why this must be kept alongside the parsed clientSetup.
   */
  clientSetupRaw: Uint8Array;
  /** Authenticates (keyId, clientSetupRaw); see ParsedSetup.clientSetupSig. */
  clientSetupSig?: Uint8Array;
  /**
   * Every root contributing to blockIds, in the same order, for the
   * per-root BlockCount authenticity check. Roots without blockCount/
   * blockCountSig (non-chunked protocols) are skipped, not failed -- see
   * ParsedRoot's doc comment.
   */
  rootEntries: VerifyRootEntry[];
  /**
   * Resolves a combined block position (in TagList order, concatenated
   * across all challenged roots in the same order as the roots array in
   * the ProveRequest -- see ParsedRoot.blockIds) to its identifier
   * (CID.Bytes()) on demand, rather than requiring every position's
   * identifier pre-materialized into one array: for a chunked-protocol
   * root with millions of super-blocks, that materialization alone is
   * what caused a real 2026-08-19 hydrogen incident on the equivalent
   * server-side code. Only ever called with positions in [0, n).
   */
  blockIds: (i: number) => Uint8Array;
  /**
   * Random seed, blocks-sampled count, and total-blocks count from the
   * self-contained ProveJobStatusResponse envelope (seed/c/n) -- everything
   * DeriveChallenge needs, alongside blockIds, to reconstruct the same
   * challenge indices/coefficients the server used. See VerifyParams'
   * top-level doc comment.
   */
  seed: Uint8Array;
  c: number;
  n: number;
  /**
   * The roots field from the same ProveJobStatusResponse envelope, in the
   * order the server returned them -- part of what proofSig authenticates.
   */
  proofRoots: string[];
  /**
   * Raw bytes from the ProveJobStatusResponse's proof field.
   */
  proofBytes: Uint8Array;
  /**
   * Authenticates (keyId, seed, c, n, proofRoots, proofBytes) against
   * trustedKey -- see verifyProofSig in trustkey.ts. Checked before any
   * pairing math runs, exactly like clientSetupSig/blockCountSig: a proof
   * envelope with a missing or invalid signature cannot be trusted to be
   * what pinion-prover actually computed, so evaluating the pairing
   * equation against it would prove nothing.
   */
  proofSig?: Uint8Array;
}

/**
 * Checks clientSetup and every chunked root's blockCount against
 * pinion-prover's signing key before any pairing math runs. Returns a
 * detail string describing the first failure, or null if everything
 * checked out. Deliberately fails on a missing signature exactly like a
 * wrong one: an attacker able to tamper with clientSetup/blockCount in
 * storage could just as easily blank out the accompanying signature field,
 * so "no signature" must not be treated as "skip the check."
 */
function checkSetupAuthenticity(params: VerifyParams): string | null {
  if (
    !verifyClientSetupSig(
      params.trustedKey,
      params.keyId,
      params.clientSetupRaw,
      params.clientSetupSig ?? new Uint8Array(0),
    )
  ) {
    return `ClientSetup failed authenticity check for key ${params.keyId}`;
  }
  for (const r of params.rootEntries) {
    if (r.blockCount === undefined) continue; // non-chunked: no BlockCount/BlockCountSig involved
    if (
      !verifyBlockCountSig(
        params.trustedKey,
        params.keyId,
        r.root,
        r.blockCount,
        r.blockCountSig ?? new Uint8Array(0),
      )
    ) {
      return `BlockCount failed authenticity check for key ${params.keyId} root ${r.root}`;
    }
  }
  return null;
}

/**
 * Checks the proof envelope (keyId, seed, c, n, proofRoots, proofBytes)
 * against pinion-prover's signing key. Returns a detail string on failure,
 * or null if it checked out. Same fail-closed rule as checkSetupAuthenticity.
 */
function checkProofAuthenticity(params: VerifyParams): string | null {
  if (
    !verifyProofSig(
      params.trustedKey,
      params.keyId,
      params.seed,
      params.c,
      params.n,
      params.proofRoots,
      params.proofBytes,
      params.proofSig ?? new Uint8Array(0),
    )
  ) {
    return `proof envelope failed authenticity check for key ${params.keyId}`;
  }
  return null;
}

/**
 * Cryptographically verify a storage proof returned by pinion-prover,
 * distinguishing a real pairing-equation failure from one that couldn't be
 * evaluated at all (malformed/truncated response, wrong shape, etc.) —
 * see ProofVerificationResult's doc comment for why that distinction
 * matters. This is what the website's StorageHealthContext should call
 * instead of checking resp.ok alone — HTTP 200 only proves the server
 * responded, not that it holds the data, and even a successful response
 * doesn't guarantee proofBytes is well-formed enough to evaluate.
 */
export function verifyProofResult(params: VerifyParams): ProofVerificationResult {
  const authFailure = checkSetupAuthenticity(params);
  if (authFailure !== null) {
    return { verified: false, reason: 'untrusted-setup', detail: authFailure };
  }
  const proofAuthFailure = checkProofAuthenticity(params);
  if (proofAuthFailure !== null) {
    return { verified: false, reason: 'untrusted-proof', detail: proofAuthFailure };
  }

  let result: boolean;
  try {
    result = _verifyProof(params);
  } catch (cause) {
    return { verified: false, reason: 'malformed-input', cause };
  }
  return result ? { verified: true } : { verified: false, reason: 'pairing-mismatch' };
}

/**
 * Cryptographically verify a storage proof returned by pinion-prover.
 *
 * Returns true if and only if the pairing equation holds.  A false result means
 * the server either does not hold the data, returned a deliberately bad proof,
 * OR the response couldn't even be parsed as a proof at all — those last two
 * cases are indistinguishable through this function.
 *
 * @deprecated Use verifyProofResult() instead — it distinguishes a genuine
 * cryptographic failure ({ reason: 'pairing-mismatch' }) from a
 * malformed/unevaluable response ({ reason: 'malformed-input' }, e.g. an
 * infra error masquerading as a proof). Reporting the latter to a user as
 * "proof failed" implies data loss that may not have happened at all.
 */
export function verifyProof(params: VerifyParams): boolean {
  return verifyProofResult(params).verified;
}

function _verifyProof(params: VerifyParams): boolean {
  const { clientSetup, blockIds, seed, c, n, proofBytes } = params;

  // 1. Re-derive indices and coefficients deterministically from the
  //    self-contained envelope's seed/c/n.
  //    Both sides (browser + server) run this on the same (seed, ids) to agree
  //    on which blocks were sampled without communicating the full index list.
  const { indices, coeffs } = deriveIndicesAndCoeffs(seed, n, blockIds, c);

  // 3. Decode the proof (JSON despite the octet-stream content-type).
  const wireProof = JSON.parse(new TextDecoder().decode(proofBytes)) as WireProof;
  const sigma = g1FromBytes(base64ToBytes(wireProof.sigma));
  const mu = wireProof.mu.map((m) => bytesToBigInt(base64ToBytes(m)));

  // 4. Decode the public key from client_setup.
  const name = base64ToBytes(clientSetup.name);
  const V = g2FromBytes(base64ToBytes(clientSetup.v));
  const U = clientSetup.u.map((u) => g1FromBytes(base64ToBytes(u)));

  // 5. Compute A = Σₜ νₜ·H(λ‖ids[iₜ]) + Σⱼ μⱼ·uⱼ  ∈ G₁
  let A: G1Point | null = null;

  for (let t = 0; t < indices.length; t++) {
    const idx = indices[t] ?? 0;
    const nu = coeffs[t] ?? 0n;
    const term = g1ScalarMult(blockHashG1(name, blockIds(idx)), nu);
    A = A === null ? term : g1Add(A, term);
  }

  for (let j = 0; j < U.length; j++) {
    const uj = U[j];
    const muj = mu[j];
    if (uj === undefined || muj === undefined) continue;
    const term = g1ScalarMult(uj, muj);
    A = A === null ? term : g1Add(A, term);
  }

  if (A === null) return false;

  // 6. Check e(σ, G₂) == e(A, v)
  const lhs = atePairing(sigma, G2_BASE);
  const rhs = atePairing(A, V);
  return fp12Equal(lhs, rhs);
}

/**
 * Decode a base64 client_setup blob into a WireClientSetup.
 * The blob is base64(JSON(WireClientSetup)) — there are two layers of encoding.
 */
export function parseClientSetup(clientSetupBase64: string): WireClientSetup {
  return JSON.parse(new TextDecoder().decode(base64ToBytes(clientSetupBase64))) as WireClientSetup;
}
