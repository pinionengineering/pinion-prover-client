/**
 * Challenge construction and deterministic derivation.
 *
 * Ports three Go functions exactly:
 *
 *   DeriveChallenge()   storage-proofs/line/chalderive.go
 *   blockHashG1()       storage-proofs/por/sw/pub.go
 *   SuperBlockID()      ipfs-storage-proofs/superblock.go
 *
 * Any deviation from these implementations will produce challenges or
 * verification paths that disagree with the server.
 */

import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToBigInt, hashToG1, type G1Point } from './bn254.js';

/**
 * BN254 (alt_bn128 / Ethereum) subgroup order q.
 * = 21888242871839275222246405745257275088548364400416034343698204186575808495617
 */
export const BN254_ORDER =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// ---------------------------------------------------------------------------
// Base64 helpers (browser + Node ≥ 18)
// ---------------------------------------------------------------------------

/** Encode bytes to base64. */
export function uint8ToBase64(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i] ?? 0);
  return btoa(s);
}

/** Decode a base64 string to bytes. */
export function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// ---------------------------------------------------------------------------
// Challenge construction
// ---------------------------------------------------------------------------

/**
 * Build a SW-Pub challenge for POST /prove.
 *
 * Returns a base64-encoded JSON string matching wireChal in
 * storage-proofs/line/swpub/adapter.go:
 *   { suite_id, seed, c, n }
 *
 * @param challengeSize  Number of blocks to sample (≤ totalBlocks).
 * @param totalBlocks    Total blocks in the challenged store.
 */
export function buildChallenge(challengeSize: number, totalBlocks: number): string {
  const seed = crypto.getRandomValues(new Uint8Array(32));
  const wireChal = {
    suite_id: 1, // SuiteV1 = HMAC-SHA256
    seed: uint8ToBase64(seed),
    c: Math.min(challengeSize, totalBlocks),
    n: totalBlocks,
  };
  return uint8ToBase64(new TextEncoder().encode(JSON.stringify(wireChal)));
}

// ---------------------------------------------------------------------------
// Deterministic index + coefficient derivation
// ---------------------------------------------------------------------------

/**
 * Re-derive the challenge indices and blinding coefficients from a seed.
 *
 * Exact port of DeriveChallenge() in storage-proofs/line/chalderive.go (SuiteV1):
 *
 *   idxKey   = HMAC-SHA256(seed, "indices")
 *   coeffKey = HMAC-SHA256(seed, "coeffs")
 *   rank[i]  = HMAC-SHA256(idxKey, ids[i])   → sort asc → first c positions
 *   coeff[t] = HMAC-SHA256(coeffKey, BE64(t)) mod BN254_ORDER
 *
 * Both challenger (browser) and prover (server) independently call this with
 * the same (seed, ids) to agree on which blocks to challenge without any
 * extra round-trip.
 */
export function deriveIndicesAndCoeffs(
  seed: Uint8Array,
  ids: Uint8Array[],
  c: number,
): { indices: number[]; coeffs: bigint[] } {
  const idxKey = hmac(sha256, seed, textBytes('indices'));
  const coeffKey = hmac(sha256, seed, textBytes('coeffs'));

  // Rank each block by HMAC(idxKey, id); sort ascending; take first c.
  const ranked = ids.map((id, pos) => ({ pos, rank: hmac(sha256, idxKey, id) }));
  ranked.sort((a, b) => compareBytes(a.rank, b.rank));
  const indices = ranked.slice(0, c).map((r) => r.pos);

  // Derive coefficients: HMAC(coeffKey, BigEndian(t)) mod order.
  // Go encodes t as a uint64 big-endian — 8 bytes.
  const tbuf = new Uint8Array(8);
  const tview = new DataView(tbuf.buffer);
  const coeffs: bigint[] = [];
  for (let t = 0; t < c; t++) {
    tview.setBigUint64(0, BigInt(t), false); // false = big-endian
    coeffs.push(bytesToBigInt(hmac(sha256, coeffKey, tbuf)) % BN254_ORDER);
  }

  return { indices, coeffs };
}

// ---------------------------------------------------------------------------
// Super-block id construction (chunked protocols: SW-Priv, SW-Pub)
// ---------------------------------------------------------------------------

/**
 * Build a challenge id for one super-block of a chunked protocol's root.
 *
 * Exact port of SuperBlockID() in ipfs-storage-proofs/superblock.go:
 *   id = rootCID.Bytes() || BigEndian(localIndex as uint64, 8 bytes)
 *
 * Only the root's own CID bytes are used — never a content-block CID or byte
 * offset — because the server maps (rootCID, localIndex) back to real bytes
 * purely through its own local manifest, never over the wire. Both sides only
 * need to agree on `rootBytes` (the client already knows the root it's
 * auditing) and `localIndex` (chosen independently from block_count), so no
 * per-block manifest is required for chunked protocols at all.
 *
 * @param rootBytes  CID.parse(root).bytes for the root being audited.
 * @param localIndex Index in [0, block_count) — must fit in a uint64 (Number
 *                    is safe here since block counts never approach 2^53).
 */
export function superBlockId(rootBytes: Uint8Array, localIndex: number): Uint8Array {
  const id = new Uint8Array(rootBytes.length + 8);
  id.set(rootBytes);
  const view = new DataView(id.buffer, id.byteOffset + rootBytes.length, 8);
  view.setBigUint64(0, BigInt(localIndex), false); // false = big-endian
  return id;
}

// ---------------------------------------------------------------------------
// Hash-to-G1
// ---------------------------------------------------------------------------

/**
 * H(λ‖id) = HashToG1(λ‖id) using RFC 9380 SVDW.
 *
 * Exact port of blockHashG1() in storage-proofs/por/sw/pub.go.
 * λ is the 16-byte file name from WireClientSetup.name; id is CID.Bytes().
 * Uses DST "sw-pub-v1-BN254G1_XMD:SHA-256_SVDW_RO_" internally.
 */
export function blockHashG1(name: Uint8Array, id: Uint8Array): G1Point {
  const buf = new Uint8Array(name.length + id.length);
  buf.set(name);
  buf.set(id, name.length);
  return hashToG1(buf);
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function textBytes(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    if ((a[i] ?? 0) !== (b[i] ?? 0)) return (a[i] ?? 0) < (b[i] ?? 0) ? -1 : 1;
  }
  return a.length - b.length;
}
