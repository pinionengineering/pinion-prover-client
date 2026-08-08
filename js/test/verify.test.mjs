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
const {
  verifyProof,
  verifyProofResult,
  parseClientSetup,
  base64ToBytes,
  buildChallenge,
  decodeChallenge,
  parseTrustedKeyHex,
} = await import(path.join(root, 'dist/index.js'));

// ---------------------------------------------------------------------------
// Auth fields every VerifyParams object below needs, now that
// verifyProofResult gates on ClientSetup/BlockCount authenticity (see
// trustkey.ts) before running any pairing math.
//
// TEST_TRUSTED_KEY_HEX is a throwaway Ed25519 keypair generated once for this
// test fixture only (not a real hydrogen/helium key). TEST_CLIENT_SETUP_SIG_B64
// is a genuine Ed25519 signature over frame("pinion-chalkey-v1", "test-key",
// <this vector's raw client_setup bytes>), computed once with the private
// half of that keypair and pasted here as a fixed value -- deliberately not
// re-derived in JS at test time, since transcribing key material by hand
// between languages is exactly the kind of thing that's easy to get subtly
// wrong (an off-by-one byte still "looks right" and fails silently as a
// verification mismatch). If the test vector or trusted key ever changes,
// this must be regenerated the same way: sign with the matching private key
// against the exact frame() bytes, not by editing this string directly.
// ---------------------------------------------------------------------------
const TEST_KEY_ID = 'test-key';
const TEST_TRUSTED_KEY_HEX = '4570328563453ac077277b233d99293d27b2057166f2bef397e4d60a84327ff8';
const TEST_TRUSTED_KEY = parseTrustedKeyHex(TEST_TRUSTED_KEY_HEX);
const TEST_CLIENT_SETUP_SIG_B64 =
  'nuQqBVQU9N6shvQ/qv/qplgYNERK4m0vczeC4wvp9hLWS/lbWAzFlOpIEu8J6unEUCF1YTRfX48mFAwvmuQ5AA==';
// This vector's roots use raw block_ids, not block_count, so there is no
// BlockCount to authenticate here -- see checkSetupAuthenticity's
// "non-chunked: skip" branch in verify.ts.
const rootEntries = [];

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
const clientSetupRaw = base64ToBytes(vec.client_setup);
const clientSetupSig = base64ToBytes(TEST_CLIENT_SETUP_SIG_B64);
const blockIds = vec.block_ids.map(base64ToBytes);
const challenge = vec.challenge;       // pass as-is to verifyProof
const proofBytes = base64ToBytes(vec.proof);

// Every VerifyParams object below needs these four fields; keeping them in
// one place means a future auth-scheme change only needs updating here, not
// at every call site.
const auth = { trustedKey: TEST_TRUSTED_KEY, keyId: TEST_KEY_ID, clientSetupRaw, clientSetupSig, rootEntries };

// ---------------------------------------------------------------------------
// Test 1: valid proof must pass
// ---------------------------------------------------------------------------
let passed = verifyProof({ ...auth, clientSetup, blockIds, challenge, proofBytes });
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
  ...auth,
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
  ...auth,
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
  wrongKeyPassed = verifyProof({ ...auth, clientSetup: badKeySetup, blockIds, challenge, proofBytes });
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
  ...auth,
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
  verifyProof({ ...auth, clientSetup, blockIds, challenge, proofBytes: garbageProofBytes }) === false,
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
  ...auth,
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

const validResult = verifyProofResult({ ...auth, clientSetup, blockIds, challenge, proofBytes });
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
// Test 7: setup authenticity gate. These are the actual security-relevant
// checks -- not just that a genuine signature passes (already exercised by
// every test above, all of which use `auth` with a real signature), but
// that a tampered or missing one is rejected with 'untrusted-setup' before
// the pairing math ever runs, and that the failure is reported distinctly
// from a genuine cryptographic mismatch.
// ---------------------------------------------------------------------------
const tamperedSig = new Uint8Array(clientSetupSig);
tamperedSig[0] ^= 0xFF;
const tamperedSigResult = verifyProofResult({
  ...auth,
  clientSetupSig: tamperedSig,
  clientSetup,
  blockIds,
  challenge,
  proofBytes,
});
assert(
  tamperedSigResult.verified === false && tamperedSigResult.reason === 'untrusted-setup',
  `Test 7a FAILED: tampered clientSetupSig should report untrusted-setup, got ${JSON.stringify(tamperedSigResult)}`,
);
console.log('  Test 7a PASS: tampered clientSetupSig rejected as untrusted-setup');

const missingSigResult = verifyProofResult({
  ...auth,
  clientSetupSig: undefined,
  clientSetup,
  blockIds,
  challenge,
  proofBytes,
});
assert(
  missingSigResult.verified === false && missingSigResult.reason === 'untrusted-setup',
  'Test 7b FAILED: a missing clientSetupSig must be treated the same as a wrong one, not skipped',
);
console.log('  Test 7b PASS: missing clientSetupSig rejected as untrusted-setup (fail closed, not skipped)');

const wrongKeyIdResult = verifyProofResult({
  ...auth,
  keyId: 'a-different-key',
  clientSetup,
  blockIds,
  challenge,
  proofBytes,
});
assert(
  wrongKeyIdResult.verified === false && wrongKeyIdResult.reason === 'untrusted-setup',
  'Test 7c FAILED: a genuine signature for one keyId must not verify under a different keyId',
);
console.log('  Test 7c PASS: signature does not verify under the wrong keyId');

const tamperedRawResult = verifyProofResult({
  ...auth,
  clientSetupRaw: new Uint8Array([...clientSetupRaw, 0]), // append a byte: still well-formed JSON prefix-wise for parseClientSetup, but different signed bytes
  clientSetup,
  blockIds,
  challenge,
  proofBytes,
});
assert(
  tamperedRawResult.verified === false && tamperedRawResult.reason === 'untrusted-setup',
  'Test 7d FAILED: a genuine signature must not verify against different raw client_setup bytes',
);
console.log('  Test 7d PASS: signature does not verify against tampered clientSetupRaw');

// A different (but still well-formed) trusted key must reject a genuinely
// signed setup: this is the regression test for the trustedKey redesign
// itself -- it fails if checkSetupAuthenticity ever stops threading the
// caller-supplied key through to verifyClientSetupSig/verifyBlockCountSig
// and silently falls back to accepting anything.
const wrongTrustedKeyHex = 'e2ca7910acbe769ad9da4078e2999e13d0aaa5db08cf720f9e21f2e3c86dc17a';
const wrongTrustedKeyResult = verifyProofResult({
  ...auth,
  trustedKey: parseTrustedKeyHex(wrongTrustedKeyHex),
  clientSetup,
  blockIds,
  challenge,
  proofBytes,
});
assert(
  wrongTrustedKeyResult.verified === false && wrongTrustedKeyResult.reason === 'untrusted-setup',
  'Test 7e FAILED: a genuine signature must not verify against a different trusted key',
);
console.log('  Test 7e PASS: signature does not verify against a different trusted key');

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
