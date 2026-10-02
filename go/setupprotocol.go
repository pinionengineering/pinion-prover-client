package proverclient

import (
	"encoding/json"
	"fmt"
)

// setupTags maps each protocol name SchemeByProtocol accepts to the
// "protocol" tag storage-proofs writes into that scheme's ClientSetup.
var setupTags = map[string]string{
	"ateniese": "ateniese",
	"erway":    "erway",
	"sw-priv":  "sw",
	"bjo":      "bjo",
	"sw-pub":   "swpub",
}

// SetupProtocol returns the protocol name (as SchemeByProtocol accepts it)
// that clientSetup was written for, read from the setup's own "protocol"
// tag. It returns an error if the tag is missing or names no known scheme.
//
// When clientSetup has passed VerifyClientSetupSig, the tag is
// authenticated along with the rest of the setup. A self-registered key's
// setup carries no signature, so for those the tag is only as trustworthy
// as wherever the setup came from.
func SetupProtocol(clientSetup []byte) (string, error) {
	var ws struct {
		Protocol string `json:"protocol"`
	}
	if err := json.Unmarshal(clientSetup, &ws); err != nil {
		return "", fmt.Errorf("proverclient: decode client setup: %w", err)
	}
	if ws.Protocol == "" {
		return "", fmt.Errorf("proverclient: client setup has no protocol tag")
	}
	for name, tag := range setupTags {
		if tag == ws.Protocol {
			return name, nil
		}
	}
	return "", fmt.Errorf("proverclient: client setup has unknown protocol tag %q", ws.Protocol)
}

// CheckSetupProtocol returns a *SetupProtocolMismatchError unless
// clientSetup was written for protocol. Run it before handing clientSetup
// to protocol's ChallengerFactory: a factory decodes whatever fields it
// recognizes, so a setup for another scheme yields a Challenger with
// missing key material instead of an error.
func CheckSetupProtocol(protocol string, clientSetup []byte) error {
	got, err := SetupProtocol(clientSetup)
	if err != nil {
		return err
	}
	if got != protocol {
		return &SetupProtocolMismatchError{Protocol: protocol, SetupProtocol: got}
	}
	return nil
}
