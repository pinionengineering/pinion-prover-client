package proverclient

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func testChalKeySigningKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate test signing key: %v", err)
	}
	return pub, priv
}

func testSignClientSetup(t *testing.T, priv ed25519.PrivateKey, keyID string, clientSetup []byte) []byte {
	t.Helper()
	return ed25519.Sign(priv, frame(clientSetupSigDomain, []byte(keyID), clientSetup))
}

func testSignBlockCount(t *testing.T, priv ed25519.PrivateKey, keyID, root string, blockCount int) []byte {
	t.Helper()
	return ed25519.Sign(priv, frame(blockCountSigDomain, []byte(keyID), []byte(root), beUint64(blockCount)))
}

func testSignProof(t *testing.T, priv ed25519.PrivateKey, keyID string, seed []byte, c, n int, roots []string, proof []byte) []byte {
	t.Helper()
	parts := make([][]byte, 0, 4+len(roots)+1)
	parts = append(parts, []byte(keyID), seed, beUint64(c), beUint64(n))
	for _, r := range roots {
		parts = append(parts, []byte(r))
	}
	parts = append(parts, proof)
	return ed25519.Sign(priv, frame(proofSigDomain, parts...))
}

func TestVerifyClientSetupSig_RoundTrip(t *testing.T) {
	pub, priv := testChalKeySigningKeypair(t)
	sig := testSignClientSetup(t, priv, "key-1", []byte("setup-bytes"))
	if !VerifyClientSetupSig(pub, "key-1", []byte("setup-bytes"), sig) {
		t.Fatal("expected valid signature to verify")
	}
}

func TestVerifyClientSetupSig_TamperedRejected(t *testing.T) {
	pub, priv := testChalKeySigningKeypair(t)
	sig := testSignClientSetup(t, priv, "key-1", []byte("setup-bytes"))
	if VerifyClientSetupSig(pub, "key-1", []byte("different-bytes"), sig) {
		t.Fatal("expected tampered ClientSetup to fail verification")
	}
}

func TestVerifyClientSetupSig_WrongKeyRejected(t *testing.T) {
	_, priv := testChalKeySigningKeypair(t)
	otherPub, _ := testChalKeySigningKeypair(t)
	sig := testSignClientSetup(t, priv, "key-1", []byte("setup-bytes"))
	if VerifyClientSetupSig(otherPub, "key-1", []byte("setup-bytes"), sig) {
		t.Fatal("expected a signature from a different keypair to fail verification")
	}
}

func TestVerifyClientSetupSig_EmptyRejected(t *testing.T) {
	pub, _ := testChalKeySigningKeypair(t)
	if VerifyClientSetupSig(pub, "key-1", []byte("setup-bytes"), nil) {
		t.Fatal("expected empty signature to fail verification, not be treated as trusted")
	}
}

func TestVerifyBlockCountSig_RoundTrip(t *testing.T) {
	pub, priv := testChalKeySigningKeypair(t)
	sig := testSignBlockCount(t, priv, "key-1", "bafy-root", 42)
	if !VerifyBlockCountSig(pub, "key-1", "bafy-root", 42, sig) {
		t.Fatal("expected valid signature to verify")
	}
}

func TestVerifyBlockCountSig_TamperedCountRejected(t *testing.T) {
	pub, priv := testChalKeySigningKeypair(t)
	sig := testSignBlockCount(t, priv, "key-1", "bafy-root", 42)
	if VerifyBlockCountSig(pub, "key-1", "bafy-root", 1, sig) {
		t.Fatal("expected a shrunk BlockCount to fail verification")
	}
}

func TestVerifyProofSig_RoundTrip(t *testing.T) {
	pub, priv := testChalKeySigningKeypair(t)
	seed := []byte("seed-bytes")
	roots := []string{"bafy-root-a", "bafy-root-b"}
	proof := []byte("proof-bytes")
	sig := testSignProof(t, priv, "key-1", seed, 5, 10, roots, proof)
	if !VerifyProofSig(pub, "key-1", seed, 5, 10, roots, proof, sig) {
		t.Fatal("expected valid signature to verify")
	}
}

func TestVerifyProofSig_TamperedProofRejected(t *testing.T) {
	pub, priv := testChalKeySigningKeypair(t)
	seed := []byte("seed-bytes")
	roots := []string{"bafy-root-a"}
	sig := testSignProof(t, priv, "key-1", seed, 5, 10, roots, []byte("proof-bytes"))
	if VerifyProofSig(pub, "key-1", seed, 5, 10, roots, []byte("different-bytes"), sig) {
		t.Fatal("expected tampered proof bytes to fail verification")
	}
}

func TestVerifyProofSig_TamperedRootsRejected(t *testing.T) {
	pub, priv := testChalKeySigningKeypair(t)
	seed := []byte("seed-bytes")
	proof := []byte("proof-bytes")
	sig := testSignProof(t, priv, "key-1", seed, 5, 10, []string{"bafy-root-a"}, proof)
	if VerifyProofSig(pub, "key-1", seed, 5, 10, []string{"bafy-root-b"}, proof, sig) {
		t.Fatal("expected a substituted root list to fail verification")
	}
}

func TestVerifyProofSig_EmptyRejected(t *testing.T) {
	pub, _ := testChalKeySigningKeypair(t)
	if VerifyProofSig(pub, "key-1", []byte("seed"), 5, 10, []string{"bafy-root-a"}, []byte("proof"), nil) {
		t.Fatal("expected empty signature to fail verification, not be treated as trusted")
	}
}
