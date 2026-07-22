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
  RawSetupResponse,
  TagJobListEntry,
  TagJobListResponse,
  TagJobProgress,
  TagJobResponse,
  TagJobStatusResponse,
  TagResponse,
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
 * prove() + verifyProof() directly.
 */
export interface AuditOptions {
  /**
   * Subset of root CIDs to challenge.  Defaults to all roots in the setup.
   */
  roots?: string[];
  /**
   * Percentage of blocks to sample per round, 0–100.  Default 1.
   * Repeated 1% rounds accumulate statistical certainty over time — each round
   * forces the server to prove possession of an independently random sample.
   * Use 100 for a one-shot full audit.
   *
   * For an exact block count use buildChallenge(n, total) + prove() + verifyProof().
   */
  challengePct?: number;
}

/** Options for tag()'s internal job-status polling. */
export interface TagOptions {
  /** Milliseconds between GET /tag/:job_id polls. Default 1000. */
  pollIntervalMs?: number;
  /** Give up and throw TagTimeoutError after this long. Default 10 minutes. */
  timeoutMs?: number;
  /**
   * Called after every status poll with the latest progress and the raw
   * status string ("tag-queued" | "tag-planning" | "tag-running" |
   * "tag-merging" | "tag-done" | "tag-failed"). The server populates
   * progress on every poll regardless of status, including "tag-queued"
   * before any work has started (as {total_blocks: 0, completed_blocks: 0})
   * — check `status` if you need to distinguish "not started yet" from
   * "actively running".
   */
  onProgress?: (progress: TagJobProgress, status: string) => void;
}

/** Options for prove()'s internal job-status polling. */
export interface ProveOptions {
  /** Milliseconds between GET /prove/:job_id polls. Default 500. */
  pollIntervalMs?: number;
  /**
   * Give up and throw ProveTimeoutError after this long. Default 60
   * seconds — much shorter than tag()'s default, since a proof round is one
   * bounded crypto operation over the sampled blocks, not a per-block loop
   * over an entire file.
   */
  timeoutMs?: number;
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
   * Store these alongside `keyId` — they are all you need to verify proofs locally,
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
   * super-block count (chunked protocols: SW-Priv, SW-Pub) — parseSetupResponse
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
   * authenticated account.  Tagging runs asynchronously on the server —
   * this enqueues the job and polls GET /api/v1/tag/:job_id until it
   * reaches a terminal state, so the returned promise resolves only once
   * tagging is actually done (matching the pre-async blocking behavior).
   * Call getSetup() after tagging to get the updated block ID lists for the
   * next audit cycle.
   *
   * Throws TagFailedError if the job reaches "tag-failed", or
   * TagTimeoutError if it doesn't reach a terminal state within
   * options.timeoutMs.
   */
  async tag(root: string, keyId: string, options: TagOptions = {}): Promise<TagResponse> {
    const pollIntervalMs = options.pollIntervalMs ?? 1000;
    const timeoutMs = options.timeoutMs ?? 10 * 60 * 1000;

    const { job_id: jobId } = await this.post<TagJobResponse>('/api/v1/tag', {
      root,
      key_id: keyId,
    });

    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const status = await this.tagStatus(jobId);
      if (status.progress) options.onProgress?.(status.progress, status.status);

      if (status.status === 'tag-done') {
        return { block_ids: status.block_ids, block_count: status.block_count };
      }
      if (status.status === 'tag-failed') {
        throw new TagFailedError(jobId, status.error ?? 'unknown error');
      }
      if (Date.now() >= deadline) {
        throw new TagTimeoutError(jobId, status.status);
      }
      await new Promise((resolve) => setTimeout(resolve, pollIntervalMs));
    }
  }

  /** Poll the status of a tag job started by tag(). Exposed for callers that want progress UI without waiting on tag()'s full promise. */
  async tagStatus(jobId: string): Promise<TagJobStatusResponse> {
    return this.get<TagJobStatusResponse>(`/api/v1/tag/${encodeURIComponent(jobId)}`);
  }

  /**
   * List the caller's tag jobs, most recently created first.
   *
   * Unlike tagStatus(), this doesn't require already knowing a job_id — use
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
   * POST /prove — unauthenticated, the server resolves the account from key_id.
   *
   * Proving is asynchronous: this posts the challenge, then polls GET
   * /prove/:job_id until the job reaches a terminal state, so the returned
   * promise resolves only once a proof is actually ready (matching the
   * pre-async blocking behavior). Returns the raw proof bytes. Most callers
   * should use audit() instead, which also cryptographically verifies the
   * response.
   *
   * @param keyId       Challenge key ID.
   * @param roots       CID strings to prove, in the same order as the challenge.
   * @param challenge   base64(JSON(WireChallenge)) from buildChallenge().
   * @param challengeId Optional idempotency key. If a caller's own retry
   *                    logic re-calls prove() for what is logically the
   *                    same request (e.g. after a timeout with an unclear
   *                    outcome), passing the same challengeId across those
   *                    attempts makes the server return the original job
   *                    instead of starting a redundant one. Leave unset for
   *                    normal audit rounds — each is a fresh, independently
   *                    random challenge, which should never be deduped
   *                    against a previous one.
   *
   * Throws PinNotActiveError (409, checked synchronously before any job is
   * created), ProveFailedError if the job reaches "prove-failed", or
   * ProveTimeoutError if it doesn't reach a terminal state within
   * options.timeoutMs.
   */
  async prove(
    keyId: string,
    roots: string[],
    challenge: string,
    challengeId?: string,
    options: ProveOptions = {},
  ): Promise<Uint8Array> {
    const pollIntervalMs = options.pollIntervalMs ?? 500;
    const timeoutMs = options.timeoutMs ?? 60 * 1000;

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

    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const status = await this.proveStatus(jobId);
      if (status.status === 'prove-done') {
        return base64ToBytes(status.proof ?? '');
      }
      if (status.status === 'prove-failed') {
        throw new ProveFailedError(jobId, status.error ?? 'unknown error', challenge, roots);
      }
      if (Date.now() >= deadline) {
        throw new ProveTimeoutError(jobId, status.status, challenge, roots);
      }
      await new Promise((resolve) => setTimeout(resolve, pollIntervalMs));
    }
  }

  /** Poll the status of a proof job started by prove(). Exposed for callers that want to observe progress without waiting on prove()'s full promise. */
  async proveStatus(jobId: string): Promise<ProveJobStatusResponse> {
    return this.get<ProveJobStatusResponse>(`/prove/${encodeURIComponent(jobId)}`);
  }

  /**
   * Run one audit round against a pre-fetched setup.
   *
   * Builds a random challenge for the requested percentage of blocks, posts it
   * to POST /prove, and cryptographically verifies the response.  Pass the
   * ParsedSetup obtained from getSetup() — audit() does not fetch it for you,
   * keeping the setup and audit phases explicit.
   *
   * ```ts
   * // Setup phase — done once (or after adding/removing roots):
   * const { keyId } = await client.createKey();
   * await client.tag(cid, keyId);
   * const setup = await client.getSetup(keyId);
   *
   * // Audit phase — repeat on a schedule:
   * const result = await client.audit(keyId, setup);
   * const result = await client.audit(keyId, setup, { challengePct: 100 });
   * ```
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

    const proofBytes = await this.prove(keyId, targetRoots, challenge);

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
 * a raw, untyped SyntaxError) if it isn't well-formed — e.g. a proxy or
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
 * isn't valid JSON — this is what an infra problem often looks like from
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

/** Thrown by tag() when the async tag job reaches the "tag-failed" state. */
export class TagFailedError extends Error {
  constructor(
    public readonly jobId: string,
    public readonly reason: string,
  ) {
    super(`tag job ${jobId} failed: ${reason}`);
    this.name = 'TagFailedError';
  }
}

/** Thrown by tag() when the job hasn't reached a terminal state within the configured timeout. */
export class TagTimeoutError extends Error {
  constructor(
    public readonly jobId: string,
    public readonly lastStatus: string,
  ) {
    super(`tag job ${jobId} timed out (last status: ${lastStatus})`);
    this.name = 'TagTimeoutError';
  }
}

/** Thrown by prove() when the async proof job reaches the "prove-failed" state. */
export class ProveFailedError extends Error {
  constructor(
    public readonly jobId: string,
    public readonly reason: string,
    /** The challenge this job was for — base64(JSON(WireChallenge)), decode with decodeChallenge(). */
    public readonly challenge: string,
    public readonly roots: string[],
  ) {
    super(`prove job ${jobId} failed: ${reason}`);
    this.name = 'ProveFailedError';
  }
}

/** Thrown by prove() when the job hasn't reached a terminal state within the configured timeout. */
export class ProveTimeoutError extends Error {
  constructor(
    public readonly jobId: string,
    public readonly lastStatus: string,
    /** The challenge this job was for — base64(JSON(WireChallenge)), decode with decodeChallenge(). */
    public readonly challenge: string,
    public readonly roots: string[],
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
 *     [0, block_count) — see superBlockId()'s doc comment in challenge.ts for
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
