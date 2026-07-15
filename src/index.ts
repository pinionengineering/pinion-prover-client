// High-level client
export {
  PinionProverClient,
  ProverError,
  PinNotActiveError,
  parseSetupResponse,
} from './client.js';
export type { PinionProverClientOptions, AuditOptions } from './client.js';

// Verification
export { verifyProof, parseClientSetup } from './verify.js';
export type { VerifyParams } from './verify.js';

// Challenge construction
export {
  buildChallenge,
  deriveIndicesAndCoeffs,
  blockHashG1,
  superBlockId,
  base64ToBytes,
  uint8ToBase64,
  BN254_ORDER,
} from './challenge.js';

// BN254 primitives (for advanced use / other protocols)
export {
  g1FromBytes,
  g2FromBytes,
  g1ScalarMult,
  g1Add,
  atePairing,
  fp12Equal,
  bytesToBigInt,
  G1_BASE,
  G2_BASE,
} from './bn254.js';
export type { G1Point, G2Point, Fp12Elem } from './bn254.js';

// Wire format types
export type {
  WireClientSetup,
  WireChallenge,
  WireProof,
  ProveResponse,
  RawTaggedRoot,
  RawSetupResponse,
  ParsedRoot,
  ParsedSetup,
  ChallengeKeyInfo,
  CreateKeyResponse,
  CreateKeyResult,
  TagResponse,
  AuditResult,
} from './types.js';
