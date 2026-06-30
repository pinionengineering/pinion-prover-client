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
  ParsedSetup,
  ParsedRoot,
  RawSetupResponse,
  TagResponse,
  WireClientSetup,
} from './types.js';
import { buildChallenge, base64ToBytes } from './challenge.js';
import { verifyProof, parseClientSetup } from './verify.js';

export interface PinionProverClientOptions {
  /**
   * Returns a JWT Bearer token for authenticated endpoints, or null/undefined
   * if no token is available.  Called fresh before every authenticated request.
   */
  getToken?: () => Promise<string | null | undefined>;
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
   * Create a server-managed challenge key for the given protocol.
   * Only "sw-pub" is supported for cryptographic verification from this client.
   * "sw-priv" can be created but the secret stays server-side; proofs are
   * verifiable only by the server.
   *
   * @param protocol      "sw-pub" (recommended) or "sw-priv"
   * @param challengeSize Blocks sampled per audit round (default 20).
   */
  async createKey(protocol: string, challengeSize = 20): Promise<CreateKeyResponse> {
    return this.post<CreateKeyResponse>('/api/v1/challenge-key', {
      protocol,
      challenge_size: challengeSize,
    });
  }

  async deleteKey(keyId: string): Promise<void> {
    await this.authDelete(`/api/v1/challenge-key/${encodeURIComponent(keyId)}`);
  }

  // ---------------------------------------------------------------------------
  // Setup & tagging
  // ---------------------------------------------------------------------------

  /**
   * Fetch the setup for a key and fully decode all base64 fields.
   * The returned ParsedSetup is ready to pass directly to audit().
   */
  async getSetup(keyId: string): Promise<ParsedSetup> {
    const raw = await this.get<RawSetupResponse>(
      `/api/v1/setup?key_id=${encodeURIComponent(keyId)}`,
    );
    return parseSetupResponse(raw);
  }

  /**
   * Ask the server to walk the IPFS DAG for root, compute per-block tags,
   * and store the prover-side material.  Returns the block IDs needed to
   * build a challenge for this root.
   *
   * The root must already be pinned (lifecycle state = "pinned") by the
   * authenticated account, or the server returns 500.
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
  // Proving
  // ---------------------------------------------------------------------------

  /**
   * POST /prove — unauthenticated, the server resolves the account from key_id.
   *
   * Returns the raw proof bytes (JSON despite Content-Type: application/octet-stream).
   * Most callers should use audit() instead, which also verifies the proof.
   *
   * @param keyId     Challenge key ID.
   * @param roots     CID strings to prove, in the same order used when building the challenge.
   * @param challenge base64(JSON(WireChallenge)) from buildChallenge().
   */
  async prove(keyId: string, roots: string[], challenge: string): Promise<Uint8Array> {
    const resp = await fetch(`${this.baseUrl}/prove`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ key_id: keyId, roots, challenge }),
    });
    if (resp.status === 409) {
      const body = await resp.json().catch(() => ({})) as Record<string, unknown>;
      throw new PinNotActiveError(String(body['cid'] ?? 'unknown'));
    }
    if (!resp.ok) {
      throw new ProverError(resp.status, await resp.text().catch(() => ''));
    }
    return new Uint8Array(await resp.arrayBuffer());
  }

  /**
   * Run a complete audit round: build challenge → POST /prove → verify proof.
   *
   * Unlike the website's current implementation, this calls verifyProof() to
   * perform the actual BN254 pairing check rather than trusting HTTP 200.
   *
   * @param keyId        Challenge key ID.
   * @param setup        Parsed setup from getSetup().
   * @param roots        CIDs to audit. Defaults to all roots in setup.
   * @param challengePct Fraction of total blocks to sample, 0–100 (default 100).
   */
  async audit(
    keyId: string,
    setup: ParsedSetup,
    roots?: string[],
    challengePct = 100,
  ): Promise<AuditResult> {
    const targetRoots = roots ?? setup.roots.map((r) => r.root);

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
 * The client_setup field is base64(JSON(WireClientSetup)); roots[].block_ids
 * are base64 CID bytes that get decoded to Uint8Arrays.
 */
export function parseSetupResponse(raw: RawSetupResponse): ParsedSetup {
  const clientSetup: WireClientSetup = parseClientSetup(raw.client_setup);

  const roots: ParsedRoot[] = raw.roots.map((r) => ({
    root: r.root,
    blockIds: r.block_ids.map((id) => base64ToBytes(id)),
  }));

  const totalBlocks = roots.reduce((s, r) => s + r.blockIds.length, 0);

  return { clientSetup, roots, totalBlocks, challengeSize: clientSetup.l };
}
