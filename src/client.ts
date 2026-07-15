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
  ProveResponse,
  RawSetupResponse,
  TagResponse,
  WireClientSetup,
} from './types.js';
import { buildChallenge, base64ToBytes, superBlockId } from './challenge.js';
import { verifyProof, parseClientSetup } from './verify.js';
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
  async createKey(): Promise<CreateKeyResult> {
    const raw = await this.post<CreateKeyResponse>('/api/v1/challenge-key', {
      protocol: 'sw-pub',
    });
    return {
      keyId: raw.key_id,
      publicKey: parseClientSetup(raw.client_setup),
    };
  }

  async deleteKey(keyId: string): Promise<void> {
    await this.authDelete(`/api/v1/challenge-key/${encodeURIComponent(keyId)}`);
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
   * authenticated account.  Call getSetup() after tagging to get the updated
   * block ID lists for the next audit cycle.
   */
  async tag(root: string, keyId: string): Promise<TagResponse> {
    return this.post<TagResponse>('/api/v1/tag', { root, key_id: keyId });
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
   * Returns the raw proof bytes. Most callers should use audit() instead,
   * which also cryptographically verifies the response.
   *
   * @param keyId       Challenge key ID.
   * @param roots       CID strings to prove, in the same order as the challenge.
   * @param challenge   base64(JSON(WireChallenge)) from buildChallenge().
   * @param challengeId Optional idempotency key echoed back in the response.
   */
  async prove(keyId: string, roots: string[], challenge: string, challengeId?: string): Promise<Uint8Array> {
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
    const pr = await resp.json() as ProveResponse;
    return base64ToBytes(pr.proof);
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

    const pass = verifyProof({
      clientSetup: setup.clientSetup,
      blockIds: allBlockIds,
      challenge,
      proofBytes,
    });

    return { pass, blocksChecked: challengeSize, keyId, roots: targetRoots };
  }

  // ---------------------------------------------------------------------------
  // HTTP helpers
  // ---------------------------------------------------------------------------

  private async get<T>(path: string): Promise<T> {
    const resp = await fetch(`${this.baseUrl}${path}`, {
      headers: await this.authHeaders(),
    });
    if (!resp.ok) throw await this.httpError(resp);
    return resp.json() as Promise<T>;
  }

  private async post<T>(path: string, body: unknown): Promise<T> {
    const resp = await fetch(`${this.baseUrl}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...(await this.authHeaders()) },
      body: JSON.stringify(body),
    });
    if (!resp.ok) throw await this.httpError(resp);
    if (resp.status === 204) return undefined as T;
    return resp.json() as Promise<T>;
  }

  private async authDelete(path: string): Promise<void> {
    const resp = await fetch(`${this.baseUrl}${path}`, {
      method: 'DELETE',
      headers: await this.authHeaders(),
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

  return { clientSetup, roots, totalBlocks, challengeSize: clientSetup.l };
}
