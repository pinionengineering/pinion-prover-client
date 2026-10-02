package proverclient

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/pinionengineering/storage-proofs/blocks"
	"github.com/pinionengineering/storage-proofs/capability"
)

// TestSetupProtocol_RealSetups builds a real ClientSetup for every scheme
// in capability.Schemes and checks that SetupProtocol maps its tag back to
// the name SchemeByProtocol uses, so setupTags can't drift from what
// storage-proofs actually writes.
func TestSetupProtocol_RealSetups(t *testing.T) {
	const blockSize = 64
	const blockCount = 4
	for _, spec := range capability.Schemes {
		name := strings.ToLower(strings.ReplaceAll(spec.Name, " ", "-"))
		t.Run(name, func(t *testing.T) {
			tagger, err := spec.NewTagger(512, 2, blockSize, 4)
			if err != nil {
				t.Fatalf("NewTagger: %v", err)
			}
			ids := make([][]byte, blockCount)
			contents := make([][]byte, blockCount)
			for i := range blockCount {
				ids[i] = blocks.IntID(i) // bjo and erway look blocks up by sequential index
				contents[i] = bytes.Repeat([]byte{byte(i + 1)}, blockSize)
			}
			if _, err := tagger.TagBlocks(newMapBlockStore(ids, contents)); err != nil {
				t.Fatalf("TagBlocks: %v", err)
			}
			cs, err := tagger.ClientSetup()
			if err != nil {
				t.Fatalf("ClientSetup: %v", err)
			}
			got, err := SetupProtocol(cs)
			if err != nil {
				t.Fatalf("SetupProtocol: %v", err)
			}
			if got != name {
				t.Fatalf("SetupProtocol = %q, want %q", got, name)
			}
			if err := CheckSetupProtocol(name, cs); err != nil {
				t.Fatalf("CheckSetupProtocol(%q): %v", name, err)
			}
		})
	}
}

func TestSetupProtocol_Invalid(t *testing.T) {
	for _, setup := range []string{`{}`, `{"protocol":""}`, `{"protocol":"sw-pub"}`, `{"protocol":"nope"}`, `not json`} {
		if got, err := SetupProtocol([]byte(setup)); err == nil {
			t.Errorf("SetupProtocol(%s) = %q, want an error", setup, got)
		}
	}
}

// TestAudit_ProtocolMismatchRejected: a validly signed SW-Pub setup audited
// as any other scheme must be refused before Audit contacts the server.
// Without the check, the other scheme's factory decodes the SW-Pub setup
// into a Challenger with empty key material.
func TestAudit_ProtocolMismatchRejected(t *testing.T) {
	fx := newSWPubFixture(t, "key-1", 4)
	for _, protocol := range []string{"sw-priv", "bjo", "erway", "ateniese"} {
		t.Run(protocol, func(t *testing.T) {
			c := newTestServerWithTrustedKey(t, fx.pub, func(w http.ResponseWriter, r *http.Request) {
				t.Errorf("unexpected request %s %s: Audit must reject before contacting the server", r.Method, r.URL.Path)
				w.WriteHeader(http.StatusInternalServerError)
			})
			_, err := c.Audit(context.Background(), "key-1", fx.setup, protocol, &AuditOptions{
				Roots: []string{fx.setup.Roots[0].Root},
			})
			var mismatch *SetupProtocolMismatchError
			if !errors.As(err, &mismatch) {
				t.Fatalf("expected *SetupProtocolMismatchError, got %v (%T)", err, err)
			}
			if mismatch.Protocol != protocol || mismatch.SetupProtocol != "sw-pub" {
				t.Fatalf("got %+v, want Protocol=%q SetupProtocol=\"sw-pub\"", mismatch, protocol)
			}
		})
	}
}
