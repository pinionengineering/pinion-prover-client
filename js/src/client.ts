/**
 * HTTP client for the pinion-prover service.
 *
 * Route structure (urlPathPrefix = "/prover"):
 *   Authenticated (JWT Bearer):  /prover/api/v1/*
 *   Unauthenticated:             /prover/prove
 *
 * Pass the full base URL including the path prefix, e.g.:
 *   new PinionProverClient("https://hydrogen.pinion.build/prover", { getToken })
 */

import type {
  AuditResult,
  ChallengeKeyInfo,
  CreateKeyResponse,
  CreateKeyResult,
  ParsedSetup,
  ParsedRoot,
  ProveJobResponse,
  ProveJobStatusResponse,
  ProveSubmission,
  RawSetupResponse,
  TagJobListEntry,
  TagJobListResponse,
  TagJobProgress,
  TagJobResponse,
  TagJobStatusResponse,
  TagResponse,
  TagSubmission,
  WireClientSetup,
} from './types.js';
import { buildChallenge, base64ToBytes, superBlockId } from './challenge.js';
import { verifyProofResult, parseClientSetup } from './verify.js';
import { CID } from 'multiformats/cid';

export interface PinionProverClientOptions {
  /**
   * Returns a JWT Bearer token for authenticated endpoints, or null/undefined
   * if no token is available.  Called fresh before every authenticated request.
   */
  getToken?: () => Promise<string | null | undefined>;
}

/**
 * Options for the audit() convenience wrapper.
 *
 * For exact control over block count, use buildChallenge(n, total) +
 * prove() + waitForProve() + verifyProof() directly.
 */
export interface AuditOptions {
  /**
   * Subset of root CIDs to challenge.  Defaults to all roots in the setup.
   */
  roots?: string[];
  /**
   * Percentage of blocks to sample per round, 0–100.  Default 1.
   * Repeated 1% rounds accumulate statistical certainty over time. Each round
   * forces the server to prove possession of an independently random sample.
   * Use 100 for a one-shot full audit.
   *
   * For an exact block count use buildChallenge(n, total) + prove() + verifyProof().
   */
  challengePct?: number;
  /** Milliseconds between GET /prove/:job_id polls during audit()'s wait
   * phase. Default 500. */
  pollIntervalMs?: number;
  /**
   * Optional cancellation of audit()'s wait phase. There is no default
   * deadline. Omit to wait as long as the proof takes. Pass
   * `AbortSignal.timeout(ms)` to restore a fixed ceiling.
   */
  signal?: AbortSignal;
  /** Called after every status poll with the raw status string
   * ("prove-queued" | "prove-running"), for progress UI. There is no
   * per-block progress signal for proving, unlike tag()'s onProgress. */
  onStatus?: (status: string) => void;
}

/** Options for waitForTag()'s job-status polling. */
export interface WaitForTagOptions {
  /** Milliseconds between GET /tag/:job_id polls. Default 1000. */
  pollIntervalMs?: number;
  /**
   * Optional cancellation. There is no default deadline, omit to wait
   * indefinitely. Pass `AbortSignal.timeout(ms)` to restore the old fixed
   * ceiling (waitForTag() throws TagTimeoutError when the signal fires
   * before the job reaches a terminal state).
   */
  signal?: AbortSignal;
  /**
   * Called after every status poll with the latest progress and the raw
   * status string ("tag-queued" | "tag-planning" | "tag-running" |
   * "tag-merging" | "tag-done" | "tag-failed"). The server populates
   * progress on every poll regardless of status, including "tag-queued"
   * before any work has started (as {total_blocks: 0, completed_blocks: 0}).
   * Check `status` if you need to distinguish "not started yet" from
   * "actively running".
   */
  onProgress?: (progress: TagJobProgress, status: string) => void;
}

/** Options for waitForProve()'s job-status polling. */
export interface WaitForProveOptions {
  /** Milliseconds between GET /prove/:job_id polls. Default 500. */
  pollIntervalMs?: number;
  /**
   * Optional cancellation. There is no default deadline, omit to wait
   * indefinitely. Pass `AbortSignal.timeout(ms)` to restore the old fixed
   * ceiling (waitForProve() throws ProveTimeoutError when the signal fires
   * before the job reaches a terminal state).
   */
  signal?: AbortSignal;
  /**
   * The challenge/roots this job was submitted with. Optional, but passing
   * them lets a thrown ProveFailedError/ProveTimeoutError carry enough to
   * reconstruct a retry. Pass what prove() gave you back.
   */
  challenge?: string;
  roots?: string[];
  /** Called after every status poll with the raw status string
   * ("prove-queued" | "prove-running"). There is no per-block progress
   * signal for proving, unlike waitForTag()'s onProgress. */
  onStatus?: (status: string) => void;
}

export class PinionProverClient {
  private readonly baseUrl: string;
  private readonly getToken: () => Promise<string | null | undefined>;

  constructor(baseUrl: string, options: PinionProverClientOptions = {}) {
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.getToken = options.getToken ?? (() => Promise.resolve(null));
  }

  // ---------------------------------------------------------------------------
  // Challenge key lifecycle
  // ---------------------------------------------------------------------------

  async listKeys(): Promise<ChallengeKeyInfo[]> {
    return this.get<ChallengeKeyInfo[]>('/api/v1/challenge-keys');
  }

  /**
   * Create a challenge key and return the key ID along with the public key material.
   *
   * The server generates a key pair and keeps the private scalar α.  The returned
   * `publicKey` is the public half: G1 points U[0..s-1] and G2 point V = α·G₂.
   * Store these alongside `keyId`. They are all you need to verify proofs locally,
   * independent of the server returning the same material later.
   */
  async createKey(label?: string): Promise<CreateKeyResult> {
    const raw = await this.post<CreateKeyResponse>('/api/v1/challenge-key', {
      protocol: 'sw-pub',
      label: label ?? '',
    });
    return {
      keyId: raw.key_id,
      publicKey: parseClientSetup(raw.client_setup),
      label: raw.label,
    };
  }

  async deleteKey(keyId: string): Promise<void> {
    await this.authDelete(`/api/v1/challenge-key/${encodeURIComponent(keyId)}`);
  }

  /** Rename a key after creation. Pass an empty string to clear the label. */
  async updateKeyLabel(keyId: string, label: string): Promise<void> {
    await this.authPatch(`/api/v1/challenge-key/${encodeURIComponent(keyId)}`, { label });
  }

  // ---------------------------------------------------------------------------
  // Setup phase
  // ---------------------------------------------------------------------------

  /**
   * Fetch the setup document for a key: public key material and, per
   * registered root, either the block ID list (non-chunked protocols) or the
   * super-block count (chunked protocols: SW-Priv, SW-Pub). parseSetupResponse
   * turns either into a uniform ParsedRoot.blockIds array.
   *
   * Call this once after tagging to obtain the ParsedSetup needed for auditing.
   * Re-call whenever you add or remove roots.
   */
  async getSetup(keyId: string): Promise<ParsedSetup> {
    const raw = await this.get<RawSetupResponse>(
      `/api/v1/setup?key_id=${encodeURIComponent(keyId)}`,
    );
    return parseSetupResponse(raw);
  }

  /**
   * Ask the server to walk the IPFS DAG for root, compute per-block
   * authentication tags, and store them under keyId.
   *
   * The root must already be in the "pinned" lifecycle state for the
   * authenticated account. Tagging runs asynchronously on the server. This
   * submits the job and returns immediately with a job handle. Poll
   * tagStatus(jobId) yourself, or await waitForTag(jobId, options) to wait
   * for a terminal state (with no default deadline, pass `signal:
   * AbortSignal.timeout(ms)` if you want one). Call getSetup() after
   * tagging completes to get the updated block ID lists for the next audit
   * cycle.
   */
  async tag(root: string, keyId: string): Promise<TagSubmission> {
    const { job_id: jobId } = await this.post<TagJobResponse>('/api/v1/tag', {
      root,
      key_id: keyId,
    });
    return { jobId, root, keyId };
  }

  /** Poll the status of a tag job started by tag(). Exposed for callers that want progress UI without waiting on waitForTag()'s full promise. */
  async tagStatus(jobId: string): Promise<TagJobStatusResponse> {
    return this.get<TagJobStatusResponse>(`/api/v1/tag/${encodeURIComponent(jobId)}`);
  }

  /**
   * Wait for a tag job started by tag() to reach a terminal state, polling
   * tagStatus(jobId) on an interval.
   *
   * There is no default deadline. This waits as long as the job takes
   * unless options.signal is given and fires first, in which case it
   * throws TagTimeoutError with the last-seen status. Throws TagFailedError
   * if the job reaches "tag-failed".
   */
  async waitForTag(jobId: string, options: WaitForTagOptions = {}): Promise<TagResponse> {
    const pollIntervalMs = options.pollIntervalMs ?? 1000;
    const status = await pollUntilTerminal({
      fetchStatus: () => this.tagStatus(jobId),
      isTerminal: (s) => s.status === 'tag-done' || s.status === 'tag-failed',
      pollIntervalMs,
      signal: options.signal,
      onTick: (s) => {
        if (s.progress) options.onProgress?.(s.progress, s.status);
      },
    }).catch((e) => {
      if (e instanceof PollAbortedError) {
        const last = e.lastStatus as TagJobStatusResponse | undefined;
        throw new TagTimeoutError(jobId, last?.status ?? 'unknown');
      }
      throw e;
    });

    if (status.status === 'tag-failed') {
      throw new TagFailedError(jobId, status.error ?? 'unknown error');
    }
    return { block_ids: status.block_ids, block_count: status.block_count };
  }

  /**
   * List the caller's tag jobs, most recently created first.
   *
   * Unlike tagStatus(), this doesn't require already knowing a job_id. Use
   * it to discover in-flight tagging after a page reload or from a
   * different tab/device than the one that started it. Pass
   * `{ active: true }` to list only non-terminal jobs (queued/planning/
   * running/merging), which is what a "tagging in progress" indicator
   * should poll.
   */
  async listTagJobs(options: { active?: boolean } = {}): Promise<TagJobListEntry[]> {
    const query = options.active ? '?active=true' : '';
    const resp = await this.get<TagJobListResponse>(`/api/v1/tag${query}`);
    return resp.jobs;
  }

  async deregister(keyId: string, root: string): Promise<void> {
    await this.authDelete(
      `/api/v1/register/${encodeURIComponent(keyId)}/${encodeURIComponent(root)}`,
    );
  }

  // ---------------------------------------------------------------------------
  // Audit phase
  // ---------------------------------------------------------------------------

  /**
   * POST /prove: unauthenticated, the server resolves the account from key_id.
   *
   * Proving is asynchronous: this submits the challenge and returns
   * immediately with a job handle. Poll proveStatus(jobId) yourself, or
   * await waitForProve(jobId, options) to wait for a terminal state (with
   * no default deadline (pass `signal: AbortSignal.timeout(ms)` if you
   * want one). Most callers should use audit() instead, which submits,
   * waits, and cryptographically verifies the response in one call.
   *
   * @param keyId       Challenge key ID.
   * @param roots       CID strings to prove, in the same order as the challenge.
   * @param challenge   base64(JSON(WireChallenge)) from buildChallenge().
   * @param challengeId Optional idempotency key. If a caller's own retry
   *                    logic re-calls prove() for what is logically the
   *                    same request (e.g. after giving up waiting on an
   *                    earlier attempt with an unclear outcome), passing the
   *                    same challengeId across those attempts makes the
   *                    server return the original job instead of starting a
   *                    redundant one. Leave unset for normal audit rounds:
   *                    each is a fresh, independently random challenge,
   *                    which should never be deduped against a previous one.
   *
   * Throws PinNotActiveError (409, checked synchronously before any job is
   * created) or ProverError for any other non-2xx submit response.
   */
  async prove(
    keyId: string,
    roots: string[],
    challenge: string,
    challengeId?: string,
  ): Promise<ProveSubmission> {
    const resp = await fetch(`${this.baseUrl}/prove`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ key_id: keyId, roots, challenge, challenge_id: challengeId ?? '' }),
    });
    if (resp.status === 409) {
      const body = await resp.json().catch(() => ({})) as Record<string, unknown>;
      throw new PinNotActiveError(String(body['cid'] ?? 'unknown'));
    }
    if (!resp.ok) {
      throw new ProverError(resp.status, await resp.text().catch(() => ''));
    }
    const { job_id: jobId } = await parseJsonBody<ProveJobResponse>(resp);
    return { jobId, challenge, roots };
  }

  /** Poll the status of a proof job started by prove(). Exposed for callers that want to observe progress without waiting on waitForProve()'s full promise. */
  async proveStatus(jobId: string): Promise<ProveJobStatusResponse> {
    return this.get<ProveJobStatusResponse>(`/prove/${encodeURIComponent(jobId)}`);
  }

  /**
   * Wait for a proof job started by prove() to reach a terminal state,
   * polling proveStatus(jobId) on an interval. Returns the raw proof bytes.
   *
   * There is no default deadline. This waits as long as the proof takes
   * unless options.signal is given and fires first, in which case it
   * throws ProveTimeoutError with the last-seen status. Throws
   * ProveFailedError if the job reaches "prove-failed".
   */
  async waitForProve(jobId: string, options: WaitForProveOptions = {}): Promise<Uint8Array> {
    const pollIntervalMs = options.pollIntervalMs ?? 500;
    const status = await pollUntilTerminal({
      fetchStatus: () => this.proveStatus(jobId),
      isTerminal: (s) => s.status === 'prove-done' || s.status === 'prove-failed',
      pollIntervalMs,
      signal: options.signal,
      onTick: (s) => options.onStatus?.(s.status),
    }).catch((e) => {
      if (e instanceof PollAbortedError) {
        const last = e.lastStatus as ProveJobStatusResponse | undefined;
        throw new ProveTimeoutError(jobId, last?.status ?? 'unknown', options.challenge, options.roots);
      }
      throw e;
    });

    if (status.status === 'prove-failed') {
      throw new ProveFailedError(jobId, status.error ?? 'unknown error', options.challenge, options.roots);
    }
    return base64ToBytes(status.proof ?? '');
  }

  /**
   * Run one audit round against a pre-fetched setup.
   *
   * Builds a random challenge for the requested percentage of blocks, posts it
   * to POST /prove, and cryptographically verifies the response.  Pass the
   * ParsedSetup obtained from getSetup(). audit() does not fetch it for you,
   * keeping the setup and audit phases explicit.
   *
   * ```ts
   * // Setup phase (done once, or after adding/removing roots):
   * const { keyId } = await client.createKey();
   * await client.tag(cid, keyId);
   * const setup = await client.getSetup(keyId);
   *
   * // Audit phase (repeat on a schedule):
   * const result = await client.audit(keyId, setup);
   * const result = await client.audit(keyId, setup, { challengePct: 100 });
   * ```
   *
   * Waits for the proof with no default deadline. Pass `options.signal` if
   * you want to cancel or bound how long this waits (e.g.
   * `AbortSignal.timeout(60_000)` for the old fixed ceiling).
   *
   * Throws `PinNotActiveError` if any challenged root is no longer pinned.
   */
  async audit(keyId: string, setup: ParsedSetup, options: AuditOptions = {}): Promise<AuditResult> {
    const targetRoots = options.roots ?? setup.roots.map((r) => r.root);
    const challengePct = options.challengePct ?? 1;

    const rootEntries: ParsedRoot[] = targetRoots.map((root) => {
      const entry = setup.roots.find((r) => r.root === root);
      if (!entry) throw new Error(`root ${root} not found in setup`);
      return entry;
    });

    // Concatenate block IDs across roots in the same order the server does
    // in ipfs-storage-proofs/ipfsproof.go:NewChallengedList.
    const allBlockIds = rootEntries.flatMap((r) => r.blockIds);
    if (allBlockIds.length === 0) throw new Error('no blocks to audit');

    const challengeSize = Math.max(1, Math.round((challengePct / 100) * allBlockIds.length));
    const challenge = buildChallenge(challengeSize, allBlockIds.length);

    const submission = await this.prove(keyId, targetRoots, challenge);
    const proofBytes = await this.waitForProve(submission.jobId, {
      pollIntervalMs: options.pollIntervalMs,
      signal: options.signal,
      challenge,
      roots: targetRoots,
      onStatus: options.onStatus,
    });

    const verification = verifyProofResult({
      clientSetup: setup.clientSetup,
      blockIds: allBlockIds,
      challenge,
      proofBytes,
    });

    return {
      pass: verification.verified,
      verification,
      blocksChecked: challengeSize,
      keyId,
      roots: targetRoots,
      challenge,
    };
  }

  // ---------------------------------------------------------------------------
  // HTTP helpers
  // ---------------------------------------------------------------------------

  private async get<T>(path: string): Promise<T> {
    const resp = await fetch(`${this.baseUrl}${path}`, {
      headers: await this.authHeaders(),
    });
    if (!resp.ok) throw await this.httpError(resp);
    return parseJsonBody<T>(resp);
  }

  private async post<T>(path: string, body: unknown): Promise<T> {
    const resp = await fetch(`${this.baseUrl}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...(await this.authHeaders()) },
      body: JSON.stringify(body),
    });
    if (!resp.ok) throw await this.httpError(resp);
    if (resp.status === 204) return undefined as T;
    return parseJsonBody<T>(resp);
  }

  private async authDelete(path: string): Promise<void> {
    const resp = await fetch(`${this.baseUrl}${path}`, {
      method: 'DELETE',
      headers: await this.authHeaders(),
    });
    if (!resp.ok) throw await this.httpError(resp);
  }

  private async authPatch(path: string, body: unknown): Promise<void> {
    const resp = await fetch(`${this.baseUrl}${path}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json', ...(await this.authHeaders()) },
      body: JSON.stringify(body),
    });
    if (!resp.ok) throw await this.httpError(resp);
  }

  private async authHeaders(): Promise<Record<string, string>> {
    const token = await this.getToken();
    return token ? { Authorization: `Bearer ${token}` } : {};
  }

  private async httpError(resp: Response): Promise<ProverError> {
    const text = await resp.text().catch(() => '');
    return new ProverError(resp.status, text);
  }
}

// ---------------------------------------------------------------------------
// Shared response parsing
// ---------------------------------------------------------------------------

/**
 * Parses resp's body as JSON, throwing MalformedResponseError (rather than
 * a raw, untyped SyntaxError) if it isn't well-formed (e.g. a proxy or
 * load balancer returning an HTML error page with a 200 status, or a
 * response truncated mid-body. A non-2xx status is expected to have already
 * been handled by the caller before this is reached; this only guards
 * against a *successful* response whose body isn't what it claims to be.
 */
async function parseJsonBody<T>(resp: Response): Promise<T> {
  const text = await resp.text();
  try {
    return JSON.parse(text) as T;
  } catch (cause) {
    throw new MalformedResponseError(resp.status, text.slice(0, 200), cause);
  }
}

// ---------------------------------------------------------------------------
// Shared polling loop for waitForProve()/waitForTag()
// ---------------------------------------------------------------------------

/**
 * Internal signal that a poll loop was cancelled via its caller-supplied
 * AbortSignal before the job reached a terminal state. waitForProve()/
 * waitForTag() catch this and rethrow as ProveTimeoutError/TagTimeoutError
 * carrying lastStatus. Never thrown to the outside on its own.
 */
class PollAbortedError extends Error {
  constructor(public readonly lastStatus: unknown) {
    super('poll aborted');
    this.name = 'PollAbortedError';
  }
}

/**
 * Polls fetchStatus() every pollIntervalMs until isTerminal(status) is
 * true, calling onTick(status) after every poll (terminal or not) so
 * callers can drive progress callbacks. Has NO built-in deadline: the
 * caller's polling budget is unlimited unless `signal` is given, in which
 * case an abort rejects with PollAbortedError(lastStatus) instead of
 * resolving.
 */
async function pollUntilTerminal<TStatus>(opts: {
  fetchStatus: () => Promise<TStatus>;
  isTerminal: (status: TStatus) => boolean;
  pollIntervalMs: number;
  signal?: AbortSignal;
  onTick?: (status: TStatus) => void;
}): Promise<TStatus> {
  let last: TStatus | undefined;
  for (;;) {
    if (opts.signal?.aborted) throw new PollAbortedError(last);
    const status = await opts.fetchStatus();
    last = status;
    opts.onTick?.(status);
    if (opts.isTerminal(status)) return status;
    await sleepOrAbort(opts.pollIntervalMs, opts.signal, last);
  }
}

function sleepOrAbort<T>(ms: number, signal: AbortSignal | undefined, lastStatus: T): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(new PollAbortedError(lastStatus));
      return;
    }
    const timer = setTimeout(resolve, ms);
    signal?.addEventListener(
      'abort',
      () => {
        clearTimeout(timer);
        reject(new PollAbortedError(lastStatus));
      },
      { once: true },
    );
  });
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

export class ProverError extends Error {
  constructor(
    public readonly status: number,
    public readonly body: string,
  ) {
    super(`pinion-prover: HTTP ${status}: ${body}`);
    this.name = 'ProverError';
  }
}

/**
 * Thrown when a response has a successful HTTP status but a body that
 * isn't valid JSON. This is what an infra problem often looks like from
 * the client's perspective (a proxy's HTML error page returned with a 200,
 * a response cut off mid-stream), as opposed to a clean non-2xx status
 * (which surfaces as ProverError instead). bodyPreview is truncated to 200
 * characters so a large unexpected body doesn't bloat error logs/messages.
 */
export class MalformedResponseError extends Error {
  constructor(
    public readonly status: number,
    public readonly bodyPreview: string,
    public readonly cause?: unknown,
  ) {
    super(`pinion-prover: malformed response body (HTTP ${status}): ${bodyPreview}`);
    this.name = 'MalformedResponseError';
  }
}

/**
 * Thrown by prove() when the server returns 409 because a pin is no longer
 * in the "pinned" lifecycle state.  The caller should refresh the key's setup
 * and deregister or re-tag the stale root.
 */
export class PinNotActiveError extends Error {
  constructor(public readonly cid: string) {
    super(`pin ${cid} is not in pinned state`);
    this.name = 'PinNotActiveError';
  }
}

/** Thrown by waitForTag() when the async tag job reaches the "tag-failed" state. */
export class TagFailedError extends Error {
  constructor(
    public readonly jobId: string,
    public readonly reason: string,
  ) {
    super(`tag job ${jobId} failed: ${reason}`);
    this.name = 'TagFailedError';
  }
}

/**
 * Thrown by waitForTag() when its `options.signal` fires before the job
 * reaches a terminal state. There is no default deadline anymore. This
 * only happens if the caller opted into one (e.g. `signal:
 * AbortSignal.timeout(ms)`).
 */
export class TagTimeoutError extends Error {
  constructor(
    public readonly jobId: string,
    public readonly lastStatus: string,
  ) {
    super(`tag job ${jobId} timed out (last status: ${lastStatus})`);
    this.name = 'TagTimeoutError';
  }
}

/** Thrown by waitForProve() when the async proof job reaches the "prove-failed" state. */
export class ProveFailedError extends Error {
  constructor(
    public readonly jobId: string,
    public readonly reason: string,
    /** The challenge this job was for: base64(JSON(WireChallenge)), decode with decodeChallenge(). Undefined if the caller didn't pass one to waitForProve(). */
    public readonly challenge: string | undefined,
    public readonly roots: string[] | undefined,
  ) {
    super(`prove job ${jobId} failed: ${reason}`);
    this.name = 'ProveFailedError';
  }
}

/**
 * Thrown by waitForProve() when its `options.signal` fires before the job
 * reaches a terminal state. There is no default deadline anymore. This
 * only happens if the caller opted into one (e.g. `signal:
 * AbortSignal.timeout(ms)`).
 */
export class ProveTimeoutError extends Error {
  constructor(
    public readonly jobId: string,
    public readonly lastStatus: string,
    /** The challenge this job was for: base64(JSON(WireChallenge)), decode with decodeChallenge(). Undefined if the caller didn't pass one to waitForProve(). */
    public readonly challenge: string | undefined,
    public readonly roots: string[] | undefined,
  ) {
    super(`prove job ${jobId} timed out (last status: ${lastStatus})`);
    this.name = 'ProveTimeoutError';
  }
}

// ---------------------------------------------------------------------------
// Setup parsing (exported for use without the full client)
// ---------------------------------------------------------------------------

/**
 * Decode a raw /setup response into a ParsedSetup.
 *
 * The client_setup field is base64(JSON(WireClientSetup)). Each root is
 * either:
 *   - non-chunked (Ateniese/Erway/BJO): roots[].block_ids are CID strings,
 *     decoded to raw CID bytes (Uint8Array) via multiformats/cid.
 *   - chunked (SW-Priv/SW-Pub): roots[].block_count is a super-block count;
 *     ids are synthesized locally as superBlockId(rootBytes, i) for i in
 *     [0, block_count), see superBlockId()'s doc comment in challenge.ts for
 *     why no per-block manifest is needed for these protocols.
 */
export function parseSetupResponse(raw: RawSetupResponse): ParsedSetup {
  const clientSetup: WireClientSetup = parseClientSetup(raw.client_setup);

  const roots: ParsedRoot[] = raw.roots.map((r) => {
    if (r.block_count !== undefined) {
      const rootBytes = CID.parse(r.root).bytes;
      const blockIds = Array.from({ length: r.block_count }, (_, i) => superBlockId(rootBytes, i));
      return { root: r.root, blockIds, chunked: true };
    }
    return {
      root: r.root,
      blockIds: (r.block_ids ?? []).map((id) => CID.parse(id).bytes),
      chunked: false,
    };
  });

  const totalBlocks = roots.reduce((s, r) => s + r.blockIds.length, 0);

  return { clientSetup, roots, totalBlocks };
}
