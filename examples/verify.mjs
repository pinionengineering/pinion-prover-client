#!/usr/bin/env node
/**
 * verify.mjs — end-to-end storage verification with @pinion/prover-client
 *
 * Proves that one or more pinned CIDs are cryptographically held by a Pinion
 * prover server.  "Pass" means the server solved a BN254 pairing challenge that
 * is only solvable by a party who actually has the block data — not just HTTP 200.
 *
 * Prerequisites:
 *   - A running pinion-prover server          → PROVER_URL
 *   - A JWT for the prover's authenticated API → PINION_TOKEN
 *   - At least one CID in the "pinned" state   → command-line arguments
 *
 * Usage:
 *   PROVER_URL=https://hydrogen.pinion.build/prover \
 *   PINION_TOKEN=eyJh...                            \
 *   node examples/verify.mjs <cid> [cid ...]
 *
 * Setup phase (first run or when new CIDs are supplied):
 *   - Creates a verification key if none exists
 *   - Tags any CIDs that have not been registered yet
 *   - Fetches the setup document (public key + block ID lists)
 *
 * Audit phase:
 *   - Runs one audit round (1% spot-check by default)
 *
 * Exit 0 = proof passed.  Exit 1 = proof failed or configuration error.
 */

import { PinionProverClient, PinNotActiveError, ProverError } from '@pinionengineering/prover-client';

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const PROVER_URL = process.env.PROVER_URL;
const TOKEN      = process.env.PINION_TOKEN;
const cids       = process.argv.slice(2).filter(a => !a.startsWith('-'));

if (!PROVER_URL) {
  console.error('Error: PROVER_URL is required');
  console.error('  PROVER_URL=https://... PINION_TOKEN=... node verify.mjs <cid>');
  process.exit(1);
}
if (cids.length === 0) {
  console.error('Usage: node verify.mjs <cid> [cid ...]');
  process.exit(1);
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

const client = new PinionProverClient(PROVER_URL, {
  getToken: async () => TOKEN ?? null,
});

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  // ── Setup phase ────────────────────────────────────────────────────────────

  // 1. Find an existing sw-pub key or create one.
  //    A single key can cover many CIDs — you don't need a new key per file.
  const keys  = await client.listKeys();
  const swPub = keys.find(k => k.protocol === 'sw-pub');

  let keyId;
  if (swPub) {
    keyId = swPub.key_id;
    console.log(`[key]   ${keyId}  (${swPub.audit_count} audits, ${swPub.blocks_audited} blocks audited so far)`);
  } else {
    const created = await client.createKey();
    keyId = created.keyId;
    console.log(`[key]   ${keyId}  (newly created)`);
  }

  // 2. Tag any CIDs that haven't been registered yet.
  //    Tagging walks the IPFS DAG server-side and builds per-block auth tags.
  //    This only needs to happen once per (CID, key) pair.
  const setup      = await client.getSetup(keyId);
  const registered = new Set(setup.roots.map(r => r.root));
  const toTag      = cids.filter(cid => !registered.has(cid));

  if (toTag.length > 0) {
    console.log(`[tag]   registering ${toTag.length} new CID(s)...`);
    await Promise.all(toTag.map(cid => client.tag(cid, keyId)));
    console.log('[tag]   done');
  }

  // 3. Fetch (or refresh) the setup document.
  //    We re-fetch after tagging so the setup includes any newly-tagged roots.
  //    The setup contains the public key and the block ID lists for all roots —
  //    both client and server use the same block IDs when processing a challenge.
  const freshSetup = toTag.length > 0 ? await client.getSetup(keyId) : setup;
  console.log(`[setup] ${freshSetup.totalBlocks} total block(s) across ${freshSetup.roots.length} root(s)`);

  // ── Audit phase ────────────────────────────────────────────────────────────

  // 4. Run the audit.
  //    The client:
  //      a. Generates a random seed and selects 1% of blocks (at least 1)
  //      b. Posts the challenge to POST /prove
  //      c. Verifies the response with e(σ, G₂) == e(Σ νₜ·H(λ‖id) + Σ μⱼ·uⱼ, V)
  console.log(`[audit] challenging ${cids.length} root(s), 1% of blocks...`);

  let result;
  try {
    result = await client.audit(keyId, freshSetup, { roots: cids });
  } catch (err) {
    if (err instanceof PinNotActiveError) {
      console.error(`\n[fail]  ${err.cid}`);
      console.error('        This CID is no longer in "pinned" state on the server.');
      console.error('        Re-pin it, then run this script again to re-tag.');
    } else if (err instanceof ProverError) {
      console.error(`\n[fail]  Server returned HTTP ${err.status}: ${err.body}`);
    } else {
      throw err;
    }
    process.exit(1);
  }

  // 5. Report result.
  if (result.pass) {
    console.log(`\n[pass]  ${result.blocksChecked} block(s) verified across ${result.roots.length} root(s)`);
    console.log('        Cryptographic proof: server holds the data.');
  } else {
    console.error('\n[fail]  Pairing check failed.');
    console.error('        The server\'s proof did not satisfy e(σ,G₂) == e(A,V).');
    console.error('        The server may not actually hold the block data.');
    process.exit(1);
  }
}

main().catch(err => {
  console.error('[error]', err instanceof Error ? err.message : String(err));
  process.exit(1);
});
