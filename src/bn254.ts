/**
 * BN254 curve operations over the cloudflare/bn256 byte-encoding used by pinion-prover.
 *
 * The Go service serializes curve points via cloudflare/bn256's Marshal():
 *   G1: 64 bytes  = x_BE(32) || y_BE(32)          (no 0x04 prefix)
 *   G2: 128 bytes = im(X)_BE(32) || re(X)_BE(32) || im(Y)_BE(32) || re(Y)_BE(32)
 *
 * noble/curves bn254 uses Fp2 = { c0: real, c1: imaginary } (element = c0 + c1·u, u²=-1),
 * so the G2 coordinate mapping is:
 *   noble X = { c0: bytes[32:64], c1: bytes[0:32] }
 *   noble Y = { c0: bytes[96:128], c1: bytes[64:96] }
 *
 * This matches the EIP-197 (Ethereum bn254 precompile) encoding that noble targets,
 * which is identical to cloudflare's wire format.
 */

import { bn254 } from '@noble/curves/bn254';

const { G1, G2, pairing, fields } = bn254;
const { Fp12 } = fields;

export type G1Point = ReturnType<typeof G1.ProjectivePoint.fromAffine>;
export type G2Point = ReturnType<typeof G2.ProjectivePoint.fromAffine>;
export type Fp12Elem = ReturnType<typeof pairing>;

/** The G1 generator (same as Go's new(bn256.G1).ScalarBaseMult(big.NewInt(1))). */
export const G1_BASE: G1Point = G1.ProjectivePoint.BASE;

/** The G2 generator (same as Go's new(bn256.G2).ScalarBaseMult(big.NewInt(1))). */
export const G2_BASE: G2Point = G2.ProjectivePoint.BASE;

/**
 * Deserialize a cloudflare/bn256 G1 point from 64 bytes.
 * Format: x_big_endian(32) || y_big_endian(32) — no uncompressed prefix byte.
 */
export function g1FromBytes(bytes: Uint8Array): G1Point {
  if (bytes.length !== 64)
    throw new Error(`BN254 G1: expected 64 bytes, got ${bytes.length}`);
  const x = bytesToBigInt(bytes.subarray(0, 32));
  const y = bytesToBigInt(bytes.subarray(32, 64));
  return G1.ProjectivePoint.fromAffine({ x, y });
}

/**
 * Deserialize a cloudflare/bn256 G2 point from 128 bytes.
 *
 * cloudflare gfP2{x=imaginary, y=real}.Marshal() = [imaginary(32) | real(32)].
 * So the 128-byte layout is:
 *   [0:32]   = X_imaginary (noble X.c1)
 *   [32:64]  = X_real      (noble X.c0)
 *   [64:96]  = Y_imaginary (noble Y.c1)
 *   [96:128] = Y_real      (noble Y.c0)
 */
export function g2FromBytes(bytes: Uint8Array): G2Point {
  if (bytes.length !== 128)
    throw new Error(`BN254 G2: expected 128 bytes, got ${bytes.length}`);
  const xIm = bytesToBigInt(bytes.subarray(0, 32));
  const xRe = bytesToBigInt(bytes.subarray(32, 64));
  const yIm = bytesToBigInt(bytes.subarray(64, 96));
  const yRe = bytesToBigInt(bytes.subarray(96, 128));
  return G2.ProjectivePoint.fromAffine({
    x: { c0: xRe, c1: xIm },
    y: { c0: yRe, c1: yIm },
  });
}

/** Scalar-multiply a G1 point: returns k·P. */
export function g1ScalarMult(P: G1Point, k: bigint): G1Point {
  return P.multiply(k);
}

/** Add two G1 points. */
export function g1Add(A: G1Point, B: G1Point): G1Point {
  return A.add(B);
}

/**
 * Compute the Ate pairing e(P, Q) → Fp12.
 * Matches bn256.Pair() in Go (both implement the Optimal Ate pairing on BN254).
 */
export function atePairing(P: G1Point, Q: G2Point): Fp12Elem {
  return pairing(P, Q);
}

/** Check equality of two Fp12 (GT) elements. */
export function fp12Equal(a: Fp12Elem, b: Fp12Elem): boolean {
  return Fp12.eql(a, b);
}

/** Convert a big-endian byte array to a bigint. */
export function bytesToBigInt(bytes: Uint8Array): bigint {
  let result = 0n;
  for (let i = 0; i < bytes.length; i++) {
    result = (result << 8n) | BigInt(bytes[i] ?? 0);
  }
  return result;
}
