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
// because a pin is no longer in the "pinned" lifecycle state. The caller
// should refresh the key's setup and deregister or re-tag the stale root.
type PinNotActiveError struct {
	CID string
}

func (e *PinNotActiveError) Error() string {
	return fmt.Sprintf("pin %s is not in pinned state", e.CID)
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

// TagTimeoutError is returned by Tag when the job hasn't reached a terminal
// state within the configured timeout.
type TagTimeoutError struct {
	JobID      string
	LastStatus string
}

func (e *TagTimeoutError) Error() string {
	return fmt.Sprintf("tag job %s timed out (last status: %s)", e.JobID, e.LastStatus)
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

// ProveTimeoutError is returned by Prove when the job hasn't reached a
// terminal state within the configured timeout.
type ProveTimeoutError struct {
	JobID      string
	LastStatus string
	Challenge  []byte
	Roots      []string
}

func (e *ProveTimeoutError) Error() string {
	return fmt.Sprintf("prove job %s timed out (last status: %s)", e.JobID, e.LastStatus)
}
