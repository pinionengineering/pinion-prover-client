/**
 * BN254 (alt_bn128 / Ethereum) curve operations using noble/curves.
 *
 * Curve parameters (Ethereum EIP-197 / gnark-crypto):
 *   p = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
 *   q = 21888242871839275222246405745257275088548364400416034343698204186575808495617
 *   y² = x³ + 3 over Fp
 *
 * Wire formats (gnark-crypto RawBytes / EIP-197):
 *   G1: 64 bytes  = X_BE(32) || Y_BE(32)
 *   G2: 128 bytes = X.A1(32) || X.A0(32) || Y.A1(32) || Y.A0(32)
 *                   (gnark-crypto A0=real, A1=imaginary; noble c0=real, c1=imaginary)
 *
 * hashToG1 implements RFC 9380 hash-to-curve using the SVDW map with DST
 * "sw-pub-v1-BN254G1_XMD:SHA-256_SVDW_RO_", matching gnark-crypto HashToG1
 * in storage-proofs/por/sw/pub.go.
 *
 * noble/curves v1.9.7 has SVDW for BN254 G1 marked notImplemented, so the
 * map is implemented here directly from RFC 9380 §6.6.2 using BigInt arithmetic.
 * Constants are from gnark-crypto ecc/bn254/hash_to_g1.go, converted from
 * Montgomery form.
 */

import { bn254 } from '@noble/curves/bn254';
import { hash_to_field } from '@noble/curves/abstract/hash-to-curve';
import { sha256 } from '@noble/hashes/sha256';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type G1Point = typeof bn254.G1.ProjectivePoint.BASE;
export type G2Point = typeof bn254.G2.ProjectivePoint.BASE;
export type Fp12Elem = ReturnType<typeof bn254.pairing>;

// ---------------------------------------------------------------------------
// Base points
// ---------------------------------------------------------------------------

export const G1_BASE: G1Point = bn254.G1.ProjectivePoint.BASE;
export const G2_BASE: G2Point = bn254.G2.ProjectivePoint.BASE;

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

/** Convert big-endian bytes to a bigint. */
export function bytesToBigInt(bytes: Uint8Array): bigint {
  let result = 0n;
  for (let i = 0; i < bytes.length; i++) result = (result << 8n) | BigInt(bytes[i] ?? 0);
  return result;
}

// ---------------------------------------------------------------------------
// Wire format parsing
// ---------------------------------------------------------------------------

/** Deserialize a G1 point from 64 bytes (gnark-crypto RawBytes / EIP-197 format). */
export function g1FromBytes(bytes: Uint8Array): G1Point {
  if (bytes.length !== 64)
    throw new Error(`BN254 G1: expected 64 bytes, got ${bytes.length}`);
  const x = bytesToBigInt(bytes.subarray(0, 32));
  const y = bytesToBigInt(bytes.subarray(32, 64));
  return bn254.G1.ProjectivePoint.fromAffine({ x, y });
}

/**
 * Deserialize a G2 point from 128 bytes (gnark-crypto RawBytes / EIP-197 format).
 *
 * gnark-crypto G2Affine.RawBytes() layout:
 *   bytes[ 0: 32] = X.A1 (imaginary)
 *   bytes[32: 64] = X.A0 (real)
 *   bytes[64: 96] = Y.A1 (imaginary)
 *   bytes[96:128] = Y.A0 (real)
 *
 * noble/curves Fp2 uses { c0: real, c1: imaginary }.
 */
export function g2FromBytes(bytes: Uint8Array): G2Point {
  if (bytes.length !== 128)
    throw new Error(`BN254 G2: expected 128 bytes, got ${bytes.length}`);
  const xIm = bytesToBigInt(bytes.subarray(0, 32));
  const xRe = bytesToBigInt(bytes.subarray(32, 64));
  const yIm = bytesToBigInt(bytes.subarray(64, 96));
  const yRe = bytesToBigInt(bytes.subarray(96, 128));
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const Fp2 = bn254.fields.Fp2 as any;
  return bn254.G2.ProjectivePoint.fromAffine({
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    x: Fp2.fromBigTuple([xRe, xIm]) as any,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    y: Fp2.fromBigTuple([yRe, yIm]) as any,
  });
}

// ---------------------------------------------------------------------------
// G1 arithmetic
// ---------------------------------------------------------------------------

/** Scalar-multiply a G1 point: returns k·P. */
export function g1ScalarMult(P: G1Point, k: bigint): G1Point {
  return P.multiply(k);
}

/** Add two G1 points. */
export function g1Add(A: G1Point, B: G1Point): G1Point {
  return A.add(B);
}

// ---------------------------------------------------------------------------
// Pairing
// ---------------------------------------------------------------------------

/** Compute the BN254 Ate pairing e(P, Q) → Fp12. */
export function atePairing(P: G1Point, Q: G2Point): Fp12Elem {
  return bn254.pairing(P, Q);
}

/** Check equality of two Fp12 elements. */
export function fp12Equal(a: Fp12Elem, b: Fp12Elem): boolean {
  return bn254.fields.Fp12.eql(a, b);
}

// ---------------------------------------------------------------------------
// RFC 9380 SVDW hash-to-G1 for BN254
// ---------------------------------------------------------------------------

const FP_P = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47n;
const FP_B = 3n; // BN254: y² = x³ + 3

// SVDW precomputed constants for Z = 1 (from gnark-crypto, converted from Montgomery form)
const C1 = 4n; // g(Z) = Z³ + B = 1 + 3 = 4
const C2 = 0x183227397098d014dc2822db40c0ac2ecbc0b548b438e5469e10460b6c3e7ea3n; // -Z/2 mod p
const C3 = 0x16789af3a83522eb353c98fc6b36d713d5d8d1cc5dffffffan;               // sqrt(-g(Z)·3Z²) mod p
const C4 = 0x10216f7ba065e00de81ac1e7808072c9dd2b2385cd7b438469602eb24829a9bdn; // -4g(Z)/(3Z²) mod p
const Z  = 1n;

const SQRT_EXP = (FP_P + 1n) >> 2n; // (p+1)/4, valid since p ≡ 3 mod 4
const LEG_EXP  = (FP_P - 1n) >> 1n; // (p-1)/2

function fpAdd(a: bigint, b: bigint): bigint { return (a + b) % FP_P; }
function fpSub(a: bigint, b: bigint): bigint { return ((a - b) % FP_P + FP_P) % FP_P; }
function fpMul(a: bigint, b: bigint): bigint { return (a * b) % FP_P; }
function fpSqr(a: bigint):            bigint { return (a * a) % FP_P; }
function fpNeg(a: bigint):            bigint { return a === 0n ? 0n : FP_P - a; }

function fpPow(base: bigint, exp: bigint): bigint {
  let r = 1n;
  let b = base % FP_P;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) r = (r * b) % FP_P;
    e >>= 1n;
    b = (b * b) % FP_P;
  }
  return r;
}

function fpSqrt(a: bigint): bigint    { return fpPow(a, SQRT_EXP); }
function fpInv0(a: bigint): bigint    { return a === 0n ? 0n : fpPow(a, FP_P - 2n); }
function isSquare(a: bigint): boolean { return fpPow(a, LEG_EXP) !== FP_P - 1n; }
function sgn0(a: bigint):    bigint   { return a & 1n; }
function cmov(a: bigint, b: bigint, cond: boolean): bigint { return cond ? b : a; }

/**
 * RFC 9380 §6.6.2 straightline SVDW map-to-curve for BN254 G1 (A=0, B=3, Z=1).
 * Matches gnark-crypto ecc/bn254/hash_to_g1.go MapToCurve1 exactly.
 *
 * Steps 22-26 compute x3 = (tv2² · tv3)² · c4 + Z, which is the RFC 9380
 * straightline form — NOT the non-straightline form tv4²+c4.
 */
function svdwMapToCurve(u: bigint): { x: bigint; y: bigint } {
  const tv1 = fpMul(fpSqr(u), C1);                               // 1-2:  u²·c1
  const tv2 = fpAdd(1n, tv1);                                     // 3:    1 + tv1
  const tv1b = fpSub(1n, tv1);                                    // 4:    1 - tv1
  const tv3 = fpInv0(fpMul(tv1b, tv2));                           // 5-6:  inv0(tv1b·tv2)
  const tv4 = fpMul(fpMul(fpMul(u, tv1b), tv3), C3);             // 7-9:  u·tv1b·tv3·c3
  const x1  = fpSub(C2, tv4);                                     // 10:   c2 - tv4
  const gx1 = fpAdd(fpMul(fpSqr(x1), x1), FP_B);                 // 11-14: x1³+B
  const e1  = isSquare(gx1);                                      // 15
  const x2  = fpAdd(C2, tv4);                                     // 16:   c2 + tv4
  const gx2 = fpAdd(fpMul(fpSqr(x2), x2), FP_B);                 // 17-20: x2³+B
  const e2  = isSquare(gx2) && !e1;                               // 21
  const x3  = fpAdd(fpMul(fpSqr(fpMul(fpSqr(tv2), tv3)), C4), Z); // 22-26: (tv2²·tv3)²·c4+Z
  const x   = cmov(cmov(x3, x2, e2), x1, e1);                    // 27-28
  const gx  = fpAdd(fpMul(fpSqr(x), x), FP_B);                   // 29-32: x³+B
  const y   = fpSqrt(gx);                                         // 33
  const e3  = sgn0(u) === sgn0(y);                                // 34
  return { x, y: cmov(fpNeg(y), y, e3) };                        // 35
}

/** RFC 9380 hash-to-G1 DST matching gnark-crypto storage-proofs/por/sw/pub.go. */
const SW_PUB_DST = 'sw-pub-v1-BN254G1_XMD:SHA-256_SVDW_RO_';

const HTF_OPTS = {
  DST: SW_PUB_DST,
  p: FP_P,
  m: 1,      // G1 lives in Fp (not an extension field)
  k: 128,    // 128 bits of security → L = 48 bytes per element
  expand: 'xmd' as const,
  hash: sha256,
};

/**
 * Hash bytes to a G1 point using RFC 9380 SVDW with the SW-Pub DST.
 *
 * Matches gnark-crypto HashToG1(msg, pubHashDST) in storage-proofs/por/sw/pub.go.
 */
export function hashToG1(msg: Uint8Array): G1Point {
  // hash_to_field returns [[u0], [u1]] for count=2, m=1
  const fields = hash_to_field(msg, 2, HTF_OPTS);
  const u0 = fields[0]![0]!;
  const u1 = fields[1]![0]!;
  const Q0 = bn254.G1.ProjectivePoint.fromAffine(svdwMapToCurve(u0));
  const Q1 = bn254.G1.ProjectivePoint.fromAffine(svdwMapToCurve(u1));
  return Q0.add(Q1);
}
