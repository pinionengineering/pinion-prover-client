/**
 * Authenticity check for ClientSetup/BlockCount against pinion-prover's own
 * signing key (see pinion-prover's authsig.go).
 *
 * Both values are looked up fresh from Firestore on every GET /setup and
 * every share-link resolve, so a Firestore-level compromise (an injection
 * bug, a bad migration, compromised DB credentials -- not necessarily a full
 * compromise of pinion-prover itself) could otherwise substitute fabricated
 * key material or shrink a BlockCount to make an unsatisfiable challenge
 * trivially satisfiable. This is exactly what feeds into verify.ts's real,
 * independent pairing check, so protecting the inputs matters as much as the
 * pairing math itself.
 */

import { ed25519 } from '@noble/curves/ed25519';

/** Number of raw bytes in an Ed25519 public key. */
export const TRUSTED_KEY_SIZE = 32;

/**
 * Decodes a hex-encoded Ed25519 public key (see PinionProverClientOptions.trustedKey),
 * throwing if it isn't well-formed. Mirrors pinion-cli's pinionconfig.decodeEd25519PublicKeyHex
 * and pinion-prover-client/go's testclient flag parsing, so the same key string works
 * unchanged across every Pinion prover client.
 */
export function parseTrustedKeyHex(hex: string): Uint8Array {
  if (!/^[0-9a-fA-F]*$/.test(hex) || hex.length % 2 !== 0) {
    throw new Error(`invalid trusted key: not valid hex: ${hex}`);
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  if (out.length !== TRUSTED_KEY_SIZE) {
    throw new Error(`invalid trusted key: must decode to ${TRUSTED_KEY_SIZE} bytes (an Ed25519 public key), got ${out.length}`);
  }
  return out;
}

// Domain tags and the frame() encoding below must match pinion-prover's
// authsig.go and pinion-prover-client's go/trustkey.go byte-for-byte, or a
// genuine signature will fail to verify.
const CLIENT_SETUP_SIG_DOMAIN = 'pinion-chalkey-v1';
const BLOCK_COUNT_SIG_DOMAIN = 'pinion-blockcount-v1';

/**
 * frame concatenates parts with a domain tag and explicit 4-byte
 * big-endian length prefixes, so distinct field boundaries can never
 * collide under concatenation (e.g. "ab"+"c" and "a"+"bc" always produce
 * different framed bytes), and a signature produced for one domain can
 * never be replayed as valid for another.
 */
function frame(domain: string, ...parts: Uint8Array[]): Uint8Array {
  const encoder = new TextEncoder();
  const pieces: Uint8Array[] = [lenPrefixed(encoder.encode(domain))];
  for (const p of parts) pieces.push(lenPrefixed(p));
  const total = pieces.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of pieces) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

function lenPrefixed(part: Uint8Array): Uint8Array {
  const out = new Uint8Array(4 + part.length);
  new DataView(out.buffer).setUint32(0, part.length, false); // big-endian
  out.set(part, 4);
  return out;
}

function beUint64(n: number): Uint8Array {
  const out = new Uint8Array(8);
  const view = new DataView(out.buffer);
  // BigInt avoids precision loss above 2^53; block counts realistically
  // never approach that, but matching Go's uint64 encoding exactly (rather
  // than assuming Number precision suffices) costs nothing here.
  view.setBigUint64(0, BigInt(n), false);
  return out;
}

/**
 * Checks that sig authenticates (keyId, clientSetup) against pubKey. false
 * means the bytes cannot be trusted to have come from pinion-prover's own
 * CreateKey call unmodified -- callers must not proceed to build a
 * Challenger or run any verification with them.
 *
 * pubKey is the caller's responsibility, deliberately not something this
 * package hardcodes or fetches on your behalf: it must come from something
 * published and reviewed out-of-band (see PinionProverClientOptions.trustedKey),
 * not from pinion-prover itself at request time -- fetching it from the same
 * server whose claims you're trying to verify would let whatever could
 * tamper with ClientSetup/BlockCount also tamper with the key used to check
 * them, defeating the entire point.
 */
export function verifyClientSetupSig(
  pubKey: Uint8Array,
  keyId: string,
  clientSetup: Uint8Array,
  sig: Uint8Array,
): boolean {
  if (!sig || sig.length === 0) return false;
  const encoder = new TextEncoder();
  const payload = frame(CLIENT_SETUP_SIG_DOMAIN, encoder.encode(keyId), clientSetup);
  try {
    return ed25519.verify(sig, payload, pubKey);
  } catch {
    return false;
  }
}

/**
 * Checks that sig authenticates (keyId, root, blockCount) against pubKey
 * (see verifyClientSetupSig on where pubKey should come from). false means
 * blockCount cannot be trusted -- in particular, an attacker could shrink it
 * to make a challenge trivially satisfiable, so callers must not proceed to
 * build challenge ids from it.
 */
export function verifyBlockCountSig(
  pubKey: Uint8Array,
  keyId: string,
  root: string,
  blockCount: number,
  sig: Uint8Array,
): boolean {
  if (!sig || sig.length === 0) return false;
  const encoder = new TextEncoder();
  const payload = frame(
    BLOCK_COUNT_SIG_DOMAIN,
    encoder.encode(keyId),
    encoder.encode(root),
    beUint64(blockCount),
  );
  try {
    return ed25519.verify(sig, payload, pubKey);
  } catch {
    return false;
  }
}
