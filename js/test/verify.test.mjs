/**
 * JS cross-validation test for @pinion/prover-client's verifyProof().
 *
 * The test vectors in testdata/vectors.json were produced by the Go generator
 * in testdata/gen/main.go, which runs the full storage-proofs sw-pub pipeline
 * (TagBlocks → Challenge → Prove → Verify) and confirms the Go verifier passes
 * before writing the file.  If this test also passes, the JS pairing check
 * agrees with the Go pairing check — they interoperate correctly.
 *
 * Run with:
 *   node test/verify.test.mjs
 */

import { createRequire } from 'module';
import { fileURLToPath } from 'url';
import path from 'path';
import fs from 'fs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, '..');

// Import the built library (dist/ must be up-to-date).
const { verifyProof, verifyProofResult, parseClientSetup, base64ToBytes, buildChallenge, decodeChallenge } =
  await import(path.join(root, 'dist/index.js'));

// ---------------------------------------------------------------------------
// Load test vectors
// ---------------------------------------------------------------------------
const vecPath = path.resolve(root, '..', 'testdata/vectors.json');
const vec = JSON.parse(fs.readFileSync(vecPath, 'utf8'));

console.log(`\nTest vector: ${vec.description}`);
console.log(`  block_ids : ${vec.block_ids.length} blocks`);

// ---------------------------------------------------------------------------
// Decode fields from the test vector JSON
//
//   vec.client_setup  string  base64(JSON(wireClientSetup))
//   vec.block_ids     string[]  each element is base64(raw id bytes)
//   vec.challenge     string  base64(JSON(wireChal))
//   vec.proof         string  base64(wireProof JSON bytes)
// ---------------------------------------------------------------------------
const clientSetup = parseClientSetup(vec.client_setup);
const blockIds = vec.block_ids.map(base64ToBytes);
const challenge = vec.challenge;       // pass as-is to verifyProof
const proofBytes = base64ToBytes(vec.proof);

// ---------------------------------------------------------------------------
// Test 1: valid proof must pass
// ---------------------------------------------------------------------------
let passed = verifyProof({ clientSetup, blockIds, challenge, proofBytes });
assert(passed === true, 'Test 1 FAILED: verifyProof should return true for a valid proof');
console.log('  Test 1 PASS: valid proof accepted');

// ---------------------------------------------------------------------------
// Test 2: tampered sigma must fail
//
// Flip one byte in the sigma field.  The pairing equation will no longer hold.
// We reconstruct wireProof JSON with the tampered sigma to simulate a server
// that sends a bad proof.
// ---------------------------------------------------------------------------
const wireProof = JSON.parse(new TextDecoder().decode(proofBytes));
const sigmaBytes = base64ToBytes(wireProof.sigma);
sigmaBytes[0] ^= 0xFF;
const tamperedProofJson = JSON.stringify({
  sigma: toBase64(sigmaBytes),
  mu: wireProof.mu,
});
const tamperedProofBytes = new TextEncoder().encode(tamperedProofJson);
const tamperedPassed = verifyProof({
  clientSetup,
  blockIds,
  challenge,
  proofBytes: tamperedProofBytes,
});
assert(tamperedPassed === false, 'Test 2 FAILED: verifyProof should return false for tampered sigma');
console.log('  Test 2 PASS: tampered sigma rejected');

// ---------------------------------------------------------------------------
// Test 3: wrong block IDs must fail
//
// Replace the content of every block ID with all-zero bytes of the same length.
// The challenge indices (derived from HMAC ranking) will then refer to different
// IDs, producing a wrong H(λ‖id) and a failing pairing.
// ---------------------------------------------------------------------------
const wrongIds = blockIds.map((id) => new Uint8Array(id.length)); // all zeros
const wrongIdsPassed = verifyProof({
  clientSetup,
  blockIds: wrongIds,
  challenge,
  proofBytes,
});
assert(wrongIdsPassed === false, 'Test 3 FAILED: verifyProof should return false for wrong block IDs');
console.log('  Test 3 PASS: wrong block ID content rejected');

// ---------------------------------------------------------------------------
// Test 4: wrong public key (different V) must fail
//
// Replace V in the client_setup with a different G2 point.
// We craft a fake V by replacing the real V bytes with the G2 generator bytes
// (which we know from the cloudflare constants printed by gen/constants/main.go).
// The pairing will not balance.
//
// Simplest approach: flip a byte in the encoded V to produce a different-but-valid
// G2 point, or just build a fake setup where V is a scalar multiple of the real one.
// Here we just flip a high byte of the real/imaginary part of V's X coordinate.
// ---------------------------------------------------------------------------
const realVBytes = base64ToBytes(clientSetup.v);
// Flip byte at position 35 (inside X_real part) — this changes the G2 key.
const fakeVBytes = flipByte(realVBytes, 35);
const badKeySetup = { ...clientSetup, v: toBase64(fakeVBytes) };
let wrongKeyPassed;
try {
  wrongKeyPassed = verifyProof({ clientSetup: badKeySetup, blockIds, challenge, proofBytes });
} catch {
  wrongKeyPassed = false;
}
assert(wrongKeyPassed === false, 'Test 4 FAILED: verifyProof should return false for wrong public key');
console.log('  Test 4 PASS: wrong public key rejected');

// ---------------------------------------------------------------------------
// Test 5: verifyProofResult distinguishes malformed input from a real
// pairing-mismatch — regression test for the bug where both cases
// collapsed to an identical `false`, making an infra error (a proxy's
// HTML error page, a truncated body) indistinguishable from genuine
// evidence the server doesn't hold the data.
// ---------------------------------------------------------------------------
const garbageProofBytes = new TextEncoder().encode('<html>502 Bad Gateway</html>');
const malformedResult = verifyProofResult({
  clientSetup,
  blockIds,
  challenge,
  proofBytes: garbageProofBytes,
});
assert(
  malformedResult.verified === false && malformedResult.reason === 'malformed-input',
  'Test 5a FAILED: verifyProofResult should report malformed-input for an unparseable body',
);
assert(
  verifyProof({ clientSetup, blockIds, challenge, proofBytes: garbageProofBytes }) === false,
  'Test 5a FAILED: verifyProof should still return false for the same input (back-compat)',
);
console.log('  Test 5a PASS: malformed/unparseable proof body reported as malformed-input, not pairing-mismatch');

// tamperedProofBytes (Test 2) flips a byte inside the sigma G1 point, which
// can corrupt the encoding badly enough to fail curve-point/scalar decoding
// or range validation itself (a malformed-input case, not a
// pairing-mismatch) — not a reliable pairing-mismatch fixture. Swapping two
// (still individually valid) mu entries instead guarantees every value
// decodes cleanly — each is a real scalar from the original valid proof —
// while still applying the wrong coefficient to each u_j, so the pairing
// check legitimately fails rather than throwing.
assert(wireProof.mu.length >= 2, 'test vector needs at least 2 mu entries to swap');
const swappedMu = [wireProof.mu[1], wireProof.mu[0], ...wireProof.mu.slice(2)];
const scalarTamperedProofBytes = new TextEncoder().encode(
  JSON.stringify({ sigma: wireProof.sigma, mu: swappedMu }),
);
const mismatchResult = verifyProofResult({
  clientSetup,
  blockIds,
  challenge,
  proofBytes: scalarTamperedProofBytes,
});
assert(
  mismatchResult.verified === false && mismatchResult.reason === 'pairing-mismatch',
  `Test 5b FAILED: verifyProofResult should report pairing-mismatch for a well-formed but wrong proof, got ${JSON.stringify(mismatchResult)}`,
);
console.log('  Test 5b PASS: well-formed but cryptographically wrong proof reported as pairing-mismatch');

const validResult = verifyProofResult({ clientSetup, blockIds, challenge, proofBytes });
assert(validResult.verified === true, 'Test 5c FAILED: verifyProofResult should report verified:true for a valid proof');
console.log('  Test 5c PASS: valid proof reported as verified');

// ---------------------------------------------------------------------------
// Test 6: decodeChallenge is the exact inverse of buildChallenge
// ---------------------------------------------------------------------------
const builtChallenge = buildChallenge(5, 20);
const decoded = decodeChallenge(builtChallenge);
assert(decoded.suite_id === 1, 'Test 6 FAILED: suite_id should round-trip as 1');
assert(decoded.c === 5, 'Test 6 FAILED: c should round-trip as 5');
assert(decoded.n === 20, 'Test 6 FAILED: n should round-trip as 20');
assert(typeof decoded.seed === 'string' && decoded.seed.length > 0, 'Test 6 FAILED: seed should be a non-empty string');
console.log('  Test 6 PASS: decodeChallenge(buildChallenge(...)) round-trips suite_id/c/n/seed');

// ---------------------------------------------------------------------------
// Done
// ---------------------------------------------------------------------------
console.log('\nAll tests passed.\n');

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function assert(condition, message) {
  if (!condition) {
    console.error(`\n  FAIL: ${message}`);
    process.exit(1);
  }
}

function toBase64(bytes) {
  return Buffer.from(bytes).toString('base64');
}

function flipByte(bytes, index) {
  const copy = new Uint8Array(bytes);
  copy[index] ^= 0xFF;
  return copy;
}
