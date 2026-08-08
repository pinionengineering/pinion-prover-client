package proverclient

import "fmt"

// ProverError is returned for any non-2xx HTTP response.
type ProverError struct {
	Status int
	Body   string
}

func (e *ProverError) Error() string {
	return fmt.Sprintf("pinion-prover: HTTP %d: %s", e.Status, e.Body)
}

// MalformedResponseError is returned when a response has a successful HTTP
// status but a body that isn't valid JSON. Often what an infra problem
// looks like from here (a proxy's HTML error page returned with a 200, a
// response cut off mid-stream), as opposed to a clean non-2xx status (which
// surfaces as ProverError instead). BodyPreview is truncated to 200 bytes.
type MalformedResponseError struct {
	Status      int
	BodyPreview string
	Cause       error
}

func (e *MalformedResponseError) Error() string {
	return fmt.Sprintf("pinion-prover: malformed response body (HTTP %d): %s", e.Status, e.BodyPreview)
}

func (e *MalformedResponseError) Unwrap() error { return e.Cause }

// PinNotActiveError is returned by Prove when the server responds 409
// because a pin is no longer in the "pinned" lifecycle state -- most often
// because the pin was deleted after being tagged, since tag data isn't
// automatically cleaned up when its underlying pin goes away. Message is
// the server's own explanation, which already names the offending CID; the
// caller should refresh the key's setup and deregister or re-tag it.
type PinNotActiveError struct {
	Message string
}

func (e *PinNotActiveError) Error() string {
	return e.Message
}

// TagFailedError is returned by Tag when the async tag job reaches the
// "tag-failed" state.
type TagFailedError struct {
	JobID  string
	Reason string
}

func (e *TagFailedError) Error() string {
	return fmt.Sprintf("tag job %s failed: %s", e.JobID, e.Reason)
}

// ProveFailedError is returned by Prove when the async proof job reaches
// the "prove-failed" state.
type ProveFailedError struct {
	JobID     string
	Reason    string
	Challenge []byte // wire challenge bytes this job was for
	Roots     []string
}

func (e *ProveFailedError) Error() string {
	return fmt.Sprintf("prove job %s failed: %s", e.JobID, e.Reason)
}

// UntrustedSetupError is returned by Audit when a SetupResponse's
// ClientSetup or a root's BlockCount doesn't verify against the fixed
// pinion trust key (see trustkey.go). This means the data cannot be trusted
// to be what pinion-prover's CreateKey/Tag calls actually produced -- it may
// have been tampered with in storage, or the server was misconfigured
// without a signing key. Audit refuses to build a Challenger or run any
// verification against unverified data; callers must not retry with the
// same setup unchanged.
type UntrustedSetupError struct {
	KeyID  string
	Root   string // empty when the failure is on ClientSetup itself, not a specific root
	Reason string
}

func (e *UntrustedSetupError) Error() string {
	if e.Root == "" {
		return fmt.Sprintf("pinion-prover: key %s: ClientSetup failed authenticity check: %s", e.KeyID, e.Reason)
	}
	return fmt.Sprintf("pinion-prover: key %s root %s: BlockCount failed authenticity check: %s", e.KeyID, e.Root, e.Reason)
}
