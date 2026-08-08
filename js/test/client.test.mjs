/**
 * Tests for PinionProverClient's submit/wait polling model (client.ts).
 *
 * Regression coverage for the redesign: prove()/tag() must be submit-only
 * (never call the status endpoint themselves), and waitForProve()/
 * waitForTag() must have NO default deadline. The bug being fixed here is
 * a hardcoded 60s/10min ceiling that threw even when the job would have
 * succeeded given more time. A caller-supplied AbortSignal is the only way
 * to stop waiting early.
 *
 * Uses a hand-rolled global.fetch stub (no mocking library). This repo has
 * no test framework, following verify.test.mjs's existing convention of a
 * plain script with a custom assert() that exits(1) on failure.
 *
 * Run with:
 *   node test/client.test.mjs
 */

import { fileURLToPath } from 'url';
import path from 'path';
import fs from 'fs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, '..');

// Import the built library (dist/ must be up-to-date).
const {
  PinionProverClient,
  PinNotActiveError,
  ProveFailedError,
  ProveTimeoutError,
  TagFailedError,
  TagTimeoutError,
  MalformedResponseError,
} = await import(path.join(root, 'dist/index.js'));

const BASE_URL = 'https://test.invalid/prover';

// Genuine Ed25519 signature over frame("pinion-chalkey-v1", "test-key",
// <testdata/vectors.json's raw client_setup bytes>), computed once against
// trustkey.ts's hardcoded placeholder public key -- see verify.test.mjs's
// identical constant for how it was generated and why it's pasted here
// rather than re-signed in JS. Every test below that reaches
// verifyProofResult's authenticity gate uses this key ID and signature.
const TEST_KEY_ID = 'test-key';
const TEST_CLIENT_SETUP_SIG_B64 =
  'nuQqBVQU9N6shvQ/qv/qplgYNERK4m0vczeC4wvp9hLWS/lbWAzFlOpIEu8J6unEUCF1YTRfX48mFAwvmuQ5AA==';

// ---------------------------------------------------------------------------
// fetch stub
// ---------------------------------------------------------------------------

/**
 * Runs fn with global.fetch replaced by a handler that records every call
 * (url, method) into the returned `calls` array and lets `handler` decide
 * the Response. Restores the real fetch afterward, even on failure.
 */
async function withMockFetch(handler, fn) {
  const calls = [];
  const original = globalThis.fetch;
  globalThis.fetch = async (url, opts = {}) => {
    const entry = { url: String(url), method: opts.method ?? 'GET' };
    calls.push(entry);
    return handler(entry, calls.length - 1);
  };
  try {
    return await fn(calls);
  } finally {
    globalThis.fetch = original;
  }
}

function jsonResponse(status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

let testCount = 0;
function assert(condition, message) {
  testCount++;
  if (!condition) {
    console.error(`\n  FAIL: ${message}`);
    process.exit(1);
  }
}

// ---------------------------------------------------------------------------
// Test 1: prove() is submit-only, resolves right after POST /prove,
// without ever calling GET /prove/:job_id. Direct regression test for
// "submit and poll are no longer fused."
// ---------------------------------------------------------------------------
await withMockFetch(
  (call) => {
    assert(call.method === 'POST' && call.url.endsWith('/prove'), 'Test 1: unexpected call ' + JSON.stringify(call));
    return jsonResponse(202, { job_id: 'job-1' });
  },
  async (calls) => {
    const client = new PinionProverClient(BASE_URL);
    const submission = await client.prove('key-1', ['cidA'], 'chal-b64');
    assert(calls.length === 1, `Test 1 FAILED: expected exactly 1 fetch call, got ${calls.length}`);
    assert(submission.jobId === 'job-1', 'Test 1 FAILED: jobId not returned');
    assert(submission.challenge === 'chal-b64', 'Test 1 FAILED: challenge not echoed back');
    assert(submission.roots.length === 1 && submission.roots[0] === 'cidA', 'Test 1 FAILED: roots not echoed back');
  },
);
console.log('  Test 1 PASS: prove() submits once and returns immediately, no status poll');

// ---------------------------------------------------------------------------
// Test 2: prove() still throws PinNotActiveError synchronously on 409.
// ---------------------------------------------------------------------------
await withMockFetch(
  () => jsonResponse(409, { cid: 'bafyStale' }),
  async () => {
    const client = new PinionProverClient(BASE_URL);
    let threw;
    try {
      await client.prove('key-1', ['bafyStale'], 'chal-b64');
    } catch (e) {
      threw = e;
    }
    assert(threw instanceof PinNotActiveError, 'Test 2 FAILED: expected PinNotActiveError');
    assert(threw.cid === 'bafyStale', 'Test 2 FAILED: cid not carried through');
  },
);
console.log('  Test 2 PASS: prove() throws PinNotActiveError on 409');

// ---------------------------------------------------------------------------
// Test 3: waitForProve() polls queued -> running -> done, resolves with the
// decoded proof bytes, and actually waits pollIntervalMs between polls.
// ---------------------------------------------------------------------------
await withMockFetch(
  (call, i) => {
    assert(call.method === 'GET', 'Test 3: expected GET, got ' + call.method);
    const sequence = ['prove-queued', 'prove-running', 'prove-done'];
    const status = sequence[Math.min(i, sequence.length - 1)];
    if (status === 'prove-done') {
      const proofB64 = Buffer.from('hello-proof').toString('base64');
      return jsonResponse(200, { status, proof: proofB64 });
    }
    return jsonResponse(200, { status });
  },
  async (calls) => {
    const client = new PinionProverClient(BASE_URL);
    const pollIntervalMs = 20;
    const start = Date.now();
    const proofBytes = await client.waitForProve('job-3', { pollIntervalMs });
    const elapsed = Date.now() - start;
    assert(calls.length === 3, `Test 3 FAILED: expected 3 polls, got ${calls.length}`);
    assert(
      Buffer.from(proofBytes).toString() === 'hello-proof',
      'Test 3 FAILED: proof bytes not decoded correctly',
    );
    // 2 sleeps of pollIntervalMs between 3 polls.
    assert(
      elapsed >= pollIntervalMs * 2 - 5,
      `Test 3 FAILED: expected to wait at least ~${pollIntervalMs * 2}ms between polls, only ${elapsed}ms elapsed`,
    );
  },
);
console.log('  Test 3 PASS: waitForProve() polls to completion and honors pollIntervalMs');

// ---------------------------------------------------------------------------
// Test 4: waitForProve() throws ProveFailedError on "prove-failed", passing
// through the caller-supplied challenge/roots.
// ---------------------------------------------------------------------------
await withMockFetch(
  () => jsonResponse(200, { status: 'prove-failed', error: 'worker exploded' }),
  async () => {
    const client = new PinionProverClient(BASE_URL);
    let threw;
    try {
      await client.waitForProve('job-4', { challenge: 'chal-x', roots: ['cidX'] });
    } catch (e) {
      threw = e;
    }
    assert(threw instanceof ProveFailedError, 'Test 4 FAILED: expected ProveFailedError');
    assert(threw.reason === 'worker exploded', 'Test 4 FAILED: reason not carried through');
    assert(threw.challenge === 'chal-x', 'Test 4 FAILED: challenge not carried through');
    assert(threw.roots[0] === 'cidX', 'Test 4 FAILED: roots not carried through');
  },
);
console.log('  Test 4 PASS: waitForProve() throws ProveFailedError on prove-failed');

// ---------------------------------------------------------------------------
// Test 5 (the core regression test): with no signal, waitForProve() must
// NEVER give up, no matter how many non-terminal polls it sees. This is the
// direct test for the bug: the old code threw ProveTimeoutError after a
// hardcoded 60s even though the job might still succeed. 50 consecutive
// "still running" polls must not produce any error.
// ---------------------------------------------------------------------------
await withMockFetch(
  (call, i) => {
    if (i < 50) return jsonResponse(200, { status: 'prove-running' });
    const proofB64 = Buffer.from('finally-done').toString('base64');
    return jsonResponse(200, { status: 'prove-done', proof: proofB64 });
  },
  async (calls) => {
    const client = new PinionProverClient(BASE_URL);
    const proofBytes = await client.waitForProve('job-5', { pollIntervalMs: 1 });
    assert(calls.length === 51, `Test 5 FAILED: expected 51 polls, got ${calls.length}`);
    assert(
      Buffer.from(proofBytes).toString() === 'finally-done',
      'Test 5 FAILED: did not resolve with the eventual proof',
    );
  },
);
console.log('  Test 5 PASS: waitForProve() never times out on its own, no implicit deadline anywhere');

// ---------------------------------------------------------------------------
// Test 6: waitForProve() with an AbortSignal that fires mid-poll rejects
// promptly with ProveTimeoutError carrying the last-seen status. The only
// way to stop waiting early now that there's no built-in ceiling.
// ---------------------------------------------------------------------------
await withMockFetch(
  () => jsonResponse(200, { status: 'prove-running' }),
  async () => {
    const client = new PinionProverClient(BASE_URL);
    const controller = new AbortController();
    setTimeout(() => controller.abort(), 30);
    const start = Date.now();
    let threw;
    try {
      await client.waitForProve('job-6', { pollIntervalMs: 10_000, signal: controller.signal });
    } catch (e) {
      threw = e;
    }
    const elapsed = Date.now() - start;
    assert(threw instanceof ProveTimeoutError, 'Test 6 FAILED: expected ProveTimeoutError, got ' + threw);
    assert(threw.lastStatus === 'prove-running', 'Test 6 FAILED: lastStatus not carried through');
    // Must reject promptly on abort, not wait out the 10s pollIntervalMs.
    assert(
      elapsed < 1000,
      `Test 6 FAILED: expected prompt rejection near the 30ms abort, took ${elapsed}ms (did not respect the abort mid-sleep)`,
    );
  },
);
console.log('  Test 6 PASS: an AbortSignal cancels waitForProve() promptly, no default deadline needed');

// ---------------------------------------------------------------------------
// Test 7: tag() is submit-only, mirroring Test 1.
// ---------------------------------------------------------------------------
await withMockFetch(
  (call) => {
    assert(call.method === 'POST' && call.url.endsWith('/api/v1/tag'), 'Test 7: unexpected call ' + JSON.stringify(call));
    return jsonResponse(202, { job_id: 'tagjob-1' });
  },
  async (calls) => {
    const client = new PinionProverClient(BASE_URL);
    const submission = await client.tag('cidA', 'key-1');
    assert(calls.length === 1, `Test 7 FAILED: expected exactly 1 fetch call, got ${calls.length}`);
    assert(submission.jobId === 'tagjob-1', 'Test 7 FAILED: jobId not returned');
    assert(submission.root === 'cidA' && submission.keyId === 'key-1', 'Test 7 FAILED: root/keyId not echoed back');
  },
);
console.log('  Test 7 PASS: tag() submits once and returns immediately, no status poll');

// ---------------------------------------------------------------------------
// Test 8: waitForTag() polls to completion, decodes the terminal
// block_ids/block_count, and invokes onProgress with every poll's progress.
// ---------------------------------------------------------------------------
await withMockFetch(
  (call, i) => {
    const sequence = [
      { status: 'tag-queued', progress: { total_blocks: 0, completed_blocks: 0 } },
      { status: 'tag-running', progress: { total_blocks: 10, completed_blocks: 4 } },
      { status: 'tag-done', progress: { total_blocks: 10, completed_blocks: 10 }, block_count: 10 },
    ];
    return jsonResponse(200, sequence[Math.min(i, sequence.length - 1)]);
  },
  async (calls) => {
    const client = new PinionProverClient(BASE_URL);
    const progressLog = [];
    const result = await client.waitForTag('tagjob-8', {
      pollIntervalMs: 5,
      onProgress: (progress, status) => progressLog.push({ progress, status }),
    });
    assert(calls.length === 3, `Test 8 FAILED: expected 3 polls, got ${calls.length}`);
    assert(result.block_count === 10, 'Test 8 FAILED: block_count not returned');
    assert(progressLog.length === 3, `Test 8 FAILED: expected onProgress called 3 times, got ${progressLog.length}`);
    assert(progressLog[0].status === 'tag-queued', 'Test 8 FAILED: first progress status wrong');
    assert(progressLog[1].progress.completed_blocks === 4, 'Test 8 FAILED: mid-poll progress wrong');
    assert(progressLog[2].status === 'tag-done', 'Test 8 FAILED: final progress status wrong');
  },
);
console.log('  Test 8 PASS: waitForTag() polls to completion and reports progress every tick');

// ---------------------------------------------------------------------------
// Test 9: waitForTag() never gives up on its own (mirrors Test 5), and with
// an AbortSignal throws TagTimeoutError (mirrors Test 6).
// ---------------------------------------------------------------------------
await withMockFetch(
  (call, i) => (i < 30 ? jsonResponse(200, { status: 'tag-running' }) : jsonResponse(200, { status: 'tag-done', block_count: 3 })),
  async (calls) => {
    const client = new PinionProverClient(BASE_URL);
    const result = await client.waitForTag('tagjob-9a', { pollIntervalMs: 1 });
    assert(calls.length === 31, `Test 9a FAILED: expected 31 polls, got ${calls.length}`);
    assert(result.block_count === 3, 'Test 9a FAILED: did not resolve with the eventual result');
  },
);
console.log('  Test 9a PASS: waitForTag() never times out on its own');

await withMockFetch(
  () => jsonResponse(200, { status: 'tag-running' }),
  async () => {
    const client = new PinionProverClient(BASE_URL);
    const controller = new AbortController();
    setTimeout(() => controller.abort(), 30);
    let threw;
    try {
      await client.waitForTag('tagjob-9b', { pollIntervalMs: 10_000, signal: controller.signal });
    } catch (e) {
      threw = e;
    }
    assert(threw instanceof TagTimeoutError, 'Test 9b FAILED: expected TagTimeoutError, got ' + threw);
    assert(threw.lastStatus === 'tag-running', 'Test 9b FAILED: lastStatus not carried through');
  },
);
console.log('  Test 9b PASS: an AbortSignal cancels waitForTag() promptly');

// ---------------------------------------------------------------------------
// Test 10: waitForTag() throws TagFailedError on "tag-failed".
// ---------------------------------------------------------------------------
await withMockFetch(
  () => jsonResponse(200, { status: 'tag-failed', error: 'dag walk failed' }),
  async () => {
    const client = new PinionProverClient(BASE_URL);
    let threw;
    try {
      await client.waitForTag('tagjob-10');
    } catch (e) {
      threw = e;
    }
    assert(threw instanceof TagFailedError, 'Test 10 FAILED: expected TagFailedError');
    assert(threw.reason === 'dag walk failed', 'Test 10 FAILED: reason not carried through');
  },
);
console.log('  Test 10 PASS: waitForTag() throws TagFailedError on tag-failed');

// ---------------------------------------------------------------------------
// Test 11: prove()+waitForProve()+verifyProofResult() against the real
// cross-language test vector: genuine crypto coverage of the NEW submit/
// wait plumbing (not just mocked statuses). This deliberately bypasses
// audit(): audit() always builds a fresh, randomly-seeded challenge via
// buildChallenge(), which would never match a precomputed vector's fixed
// challenge/proof pair, even at 100% block coverage (the SW-Pub proof's
// coefficients are seed-derived, not just which blocks were picked), so a
// real "does this proof verify" test has to go through the raw calls with
// the vector's own vec.challenge, not through audit()'s wrapper.
// ---------------------------------------------------------------------------
const vecPath = path.resolve(root, '..', 'testdata/vectors.json');
const vec = JSON.parse(fs.readFileSync(vecPath, 'utf8'));
const { parseClientSetup, base64ToBytes, verifyProofResult } = await import(path.join(root, 'dist/index.js'));

await withMockFetch(
  (call, i) => {
    if (call.method === 'POST' && call.url.endsWith('/prove')) {
      return jsonResponse(202, { job_id: 'real-vector-job' });
    }
    // One non-terminal poll, then done with the real vector's proof.
    if (i === 1) return jsonResponse(200, { status: 'prove-running' });
    return jsonResponse(200, { status: 'prove-done', proof: vec.proof });
  },
  async (calls) => {
    const client = new PinionProverClient(BASE_URL);
    const blockIds = vec.block_ids.map(base64ToBytes);
    const submission = await client.prove('key-real', ['bafyTestRoot'], vec.challenge);
    const proofBytes = await client.waitForProve(submission.jobId, {
      pollIntervalMs: 5,
      challenge: submission.challenge,
      roots: submission.roots,
    });
    assert(calls.length === 3, `Test 11 FAILED: expected 1 submit + 2 polls = 3 calls, got ${calls.length}`);
    const verification = verifyProofResult({
      keyId: TEST_KEY_ID,
      clientSetup: parseClientSetup(vec.client_setup),
      clientSetupRaw: base64ToBytes(vec.client_setup),
      clientSetupSig: base64ToBytes(TEST_CLIENT_SETUP_SIG_B64),
      rootEntries: [],
      blockIds,
      challenge: vec.challenge,
      proofBytes,
    });
    assert(verification.verified === true, 'Test 11 FAILED: expected the real test-vector proof to verify');
  },
);
console.log('  Test 11 PASS: prove()+waitForProve() round-trip a real proof that verifies correctly');

// ---------------------------------------------------------------------------
// Test 12: audit() plumbing. Confirms onStatus/pollIntervalMs actually
// reach the underlying poll (the exact bug being fixed: audit() used to
// pass zero options through to prove()) and that a bad proof is reported
// as verification failure, not a crash. Uses a malformed proof rather than
// the real vector, since audit() always builds its own randomly-seeded
// challenge internally. Genuine crypto pass/fail coverage for the new
// plumbing lives in Test 11 instead.
// ---------------------------------------------------------------------------
await withMockFetch(
  (call, i) => {
    if (call.method === 'POST' && call.url.endsWith('/prove')) {
      return jsonResponse(202, { job_id: 'audit-job' });
    }
    const sequence = ['prove-queued', 'prove-running'];
    if (i - 1 < sequence.length) {
      return jsonResponse(200, { status: sequence[i - 1] });
    }
    // Garbage proof bytes: fails verification regardless of which challenge
    // audit() happened to generate.
    const garbageB64 = Buffer.from('<html>502 Bad Gateway</html>').toString('base64');
    return jsonResponse(200, { status: 'prove-done', proof: garbageB64 });
  },
  async (calls) => {
    const client = new PinionProverClient(BASE_URL);
    const clientSetup = parseClientSetup(vec.client_setup);
    const setup = {
      clientSetup,
      clientSetupRaw: base64ToBytes(vec.client_setup),
      clientSetupSig: base64ToBytes(TEST_CLIENT_SETUP_SIG_B64),
      roots: [{ root: 'bafyTestRoot', blockIds: vec.block_ids.map(base64ToBytes), chunked: false }],
      totalBlocks: vec.block_ids.length,
    };
    const statuses = [];
    const result = await client.audit(TEST_KEY_ID, setup, {
      challengePct: 100,
      pollIntervalMs: 5,
      onStatus: (s) => statuses.push(s),
    });
    assert(calls.length === 4, `Test 12 FAILED: expected 1 submit + 3 polls = 4 calls, got ${calls.length}`);
    assert(statuses.length === 3, `Test 12 FAILED: expected onStatus called 3 times, got ${statuses.length}`);
    assert(statuses[2] === 'prove-done', 'Test 12 FAILED: final onStatus should be prove-done');
    assert(result.pass === false, 'Test 12 FAILED: a garbage proof must not pass');
    assert(
      result.verification.reason === 'malformed-input',
      `Test 12 FAILED: expected malformed-input, got ${JSON.stringify(result.verification)}`,
    );
  },
);
console.log('  Test 12 PASS: audit() passes onStatus/pollIntervalMs through to the poll (the original bug, fixed)');

// ---------------------------------------------------------------------------
// Test 13: a non-JSON 2xx submit body still throws MalformedResponseError,
// unchanged by the redesign.
// ---------------------------------------------------------------------------
await withMockFetch(
  () => new Response('<html>not json</html>', { status: 200 }),
  async () => {
    const client = new PinionProverClient(BASE_URL);
    let threw;
    try {
      await client.prove('key-1', ['cidA'], 'chal-b64');
    } catch (e) {
      threw = e;
    }
    assert(threw instanceof MalformedResponseError, 'Test 13 FAILED: expected MalformedResponseError');
  },
);
console.log('  Test 13 PASS: a non-JSON 2xx submit body still throws MalformedResponseError');

console.log(`\nAll ${testCount} assertions passed across 13 tests.\n`);
