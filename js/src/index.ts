// High-level client
export {
  PinionProverClient,
  ProverError,
  MalformedResponseError,
  PinNotActiveError,
  ChallengeTooLargeError,
  TagFailedError,
  TagTimeoutError,
  ProveFailedError,
  ProveTimeoutError,
  parseSetupResponse,
} from './client.js';
export type {
  PinionProverClientOptions,
  AuditOptions,
  WaitForTagOptions,
  WaitForProveOptions,
} from './client.js';

// Verification
export { verifyProof, verifyProofResult, parseClientSetup } from './verify.js';
export type { VerifyParams, VerifyRootEntry } from './verify.js';

// ClientSetup/BlockCount authenticity (see trustkey.ts's doc comment for
// the threat this protects against: Firestore-level tampering with data
// verifyProofResult's pairing check would otherwise trust unconditionally).
// parseTrustedKeyHex decodes the hex-encoded public key format published
// out-of-band for each pinion-prover deployment into the raw bytes
// PinionProverClientOptions.trustedKey / VerifyParams.trustedKey expect.
export { verifyClientSetupSig, verifyBlockCountSig, parseTrustedKeyHex, TRUSTED_KEY_SIZE } from './trustkey.js';

// Challenge construction
export {
  buildChallenge,
  decodeChallenge,
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
  ProveJobResponse,
  ProveJobStatusResponse,
  ProveSubmission,
  RawTaggedRoot,
  RawSetupResponse,
  ParsedRoot,
  ParsedSetup,
  ChallengeKeyInfo,
  CreateKeyResponse,
  CreateKeyResult,
  UpdateKeyLabelRequest,
  TagResponse,
  TagJobResponse,
  TagSubmission,
  TagJobProgress,
  TagJobStatusResponse,
  TagJobListEntry,
  TagJobListResponse,
  CreateShareRequest,
  CreateShareResponse,
  ShareResolveResponse,
  ProofVerificationResult,
  AuditResult,
} from './types.js';
