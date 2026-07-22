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
import type { WireClientSetup, WireChallenge, WireProof, ProofVerificationResult } from './types.js';

export interface VerifyParams {
  /**
   * The parsed WireClientSetup from the client_setup blob.
   * Obtain via parseClientSetup() or directly from ParsedSetup.clientSetup.
   */
  clientSetup: WireClientSetup;
  /**
   * Block IDs (CID.Bytes()) in TagList order, concatenated across all challenged
   * roots in the same order as the roots array in the ProveRequest.
   * These are the same byte slices stored in ParsedRoot.blockIds.
   */
  blockIds: Uint8Array[];
  /**
   * The challenge string that was sent to POST /prove.
   * This is buildChallenge()'s return value: base64(JSON(WireChallenge)).
   */
  challenge: string;
  /**
   * Raw bytes from the POST /prove response body.
   * Despite Content-Type: application/octet-stream, the body is JSON (WireProof).
   */
  proofBytes: Uint8Array;
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
  const { clientSetup, blockIds, challenge, proofBytes } = params;

  // 1. Decode the challenge to recover the seed used for derivation.
  const wireChal = JSON.parse(
    new TextDecoder().decode(base64ToBytes(challenge)),
  ) as WireChallenge;
  const seed = base64ToBytes(wireChal.seed);

  // 2. Re-derive indices and coefficients deterministically.
  //    Both sides (browser + server) run this on the same (seed, ids) to agree
  //    on which blocks were sampled without communicating the full index list.
  const { indices, coeffs } = deriveIndicesAndCoeffs(seed, blockIds, wireChal.c);

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
    const term = g1ScalarMult(blockHashG1(name, blockIds[idx] ?? new Uint8Array()), nu);
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
