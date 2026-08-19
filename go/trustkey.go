package proverclient

import (
	"crypto/ed25519"
	"encoding/binary"
)

// frame and the domain constants below must match pinion-prover's
// authsig.go and pinion-prover-client's js/src/trustkey.ts byte-for-byte, or
// a genuine signature will fail to verify. See authsig.go's frame() doc
// comment for why length-prefixing and domain separation matter here.
func frame(domain string, parts ...[]byte) []byte {
	out := make([]byte, 0, len(domain)+4)
	out = appendLenPrefixed(out, []byte(domain))
	for _, p := range parts {
		out = appendLenPrefixed(out, p)
	}
	return out
}

func appendLenPrefixed(dst, part []byte) []byte {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(part)))
	dst = append(dst, lenBuf[:]...)
	dst = append(dst, part...)
	return dst
}

func beUint64(n int) []byte {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(n))
	return buf[:]
}

const (
	clientSetupSigDomain = "pinion-chalkey-v1"
	blockCountSigDomain  = "pinion-blockcount-v1"
	proofSigDomain       = "pinion-proof-v1"
)

// VerifyClientSetupSig checks that sig authenticates (keyID, clientSetup)
// against pubKey. A false result means the ClientSetup bytes cannot be
// trusted to have come from pinion-prover's own CreateKey call unmodified --
// callers must not proceed to build a Challenger or run any verification
// with them.
//
// pubKey is the caller's responsibility, deliberately not something this
// package hardcodes or fetches on your behalf: it must come from something
// published and reviewed out-of-band (see WithTrustedKey), not from
// pinion-prover itself at request time -- fetching it from the same server
// whose claims you're trying to verify would let whatever could tamper with
// ClientSetup/BlockCount also tamper with the key used to check them,
// defeating the entire point of a third party being able to independently
// verify a share link.
func VerifyClientSetupSig(pubKey ed25519.PublicKey, keyID string, clientSetup, sig []byte) bool {
	if len(sig) == 0 {
		return false
	}
	return ed25519.Verify(pubKey, frame(clientSetupSigDomain, []byte(keyID), clientSetup), sig)
}

// VerifyBlockCountSig checks that sig authenticates (keyID, root,
// blockCount) against pubKey (see VerifyClientSetupSig on where pubKey
// should come from). A false result means blockCount cannot be trusted --
// in particular, an attacker could shrink it to make a challenge trivially
// satisfiable, so callers must not proceed to build challenge ids from it.
func VerifyBlockCountSig(pubKey ed25519.PublicKey, keyID, root string, blockCount int, sig []byte) bool {
	if len(sig) == 0 {
		return false
	}
	return ed25519.Verify(pubKey, frame(blockCountSigDomain, []byte(keyID), []byte(root), beUint64(blockCount)), sig)
}

// VerifyProofSig checks that sig authenticates (keyID, seed, c, n, roots,
// proof) against pubKey (see VerifyClientSetupSig on where pubKey should
// come from). A false result means the proof envelope cannot be trusted to
// be what pinion-prover actually computed -- in particular, seed/c/n/roots
// could have been substituted for ones the proof bytes don't actually
// correspond to, silently defeating verification. roots must be passed in
// the same order the server framed them in (the order ProveJobStatusResponse
// returned them), since frame is order-sensitive.
func VerifyProofSig(pubKey ed25519.PublicKey, keyID string, seed []byte, c, n int, roots []string, proof, sig []byte) bool {
	if len(sig) == 0 {
		return false
	}
	parts := make([][]byte, 0, 4+len(roots)+1)
	parts = append(parts, []byte(keyID), seed, beUint64(c), beUint64(n))
	for _, r := range roots {
		parts = append(parts, []byte(r))
	}
	parts = append(parts, proof)
	return ed25519.Verify(pubKey, frame(proofSigDomain, parts...), sig)
}

// verifySetupAuthenticity gates Audit on both signature checks before it
// trusts anything in setup: ClientSetup once, and BlockCount for every
// chunked-protocol root actually being audited (targetRoots). Deliberately
// fails closed on a missing signature exactly the same as a wrong one --
// an attacker able to tamper with ClientSetup/BlockCount in storage could
// just as easily blank out the accompanying Sig field, so "no signature"
// must not be treated as "skip the check" or this protects nothing.
//
// Non-chunked-protocol roots (BlockIDs populated instead of BlockCount) have
// no BlockCountSig to check -- see registerProofMaterial's identical gate on
// the server side -- so they're skipped here, not failed.
func verifySetupAuthenticity(pubKey ed25519.PublicKey, keyID string, setup *SetupResponse, targetRoots []string) error {
	if !VerifyClientSetupSig(pubKey, keyID, setup.ClientSetup, setup.ClientSetupSig) {
		return &UntrustedSetupError{KeyID: keyID, Reason: "signature missing or invalid"}
	}

	byRoot := make(map[string]TaggedRoot, len(setup.Roots))
	for _, r := range setup.Roots {
		byRoot[r.Root] = r
	}
	for _, root := range targetRoots {
		r, ok := byRoot[root]
		if !ok {
			continue
		}
		if len(r.BlockIDs) > 0 {
			continue
		}
		if !VerifyBlockCountSig(pubKey, keyID, root, r.BlockCount, r.BlockCountSig) {
			return &UntrustedSetupError{KeyID: keyID, Root: root, Reason: "signature missing or invalid"}
		}
	}
	return nil
}
