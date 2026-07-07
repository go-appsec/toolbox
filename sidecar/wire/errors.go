package wire

import "fmt"

// Sectool-specific JSON-RPC error codes occupy the reserved range
// -33000..-33999, partitioned by concern.

// Registration / lifecycle codes.
const (
	CodeRegistrationRejected  = -33000
	CodeVersionUnsupported    = -33001
	CodeDuplicateRegistration = -33002
	CodeCapabilityConflict    = -33003
	CodeToolNameConflict      = -33004
	CodeNotRegistered         = -33005
)

// Rule and flow codes; also cover flow emission and core_invoke validation.
const (
	CodeFlowRejected       = -33100
	CodeCoreInvokeRejected = -33101
	CodeRuleRejected       = -33102
)

// Transport codes.
const (
	CodeFramingViolation  = -33200
	CodeOversizedMessage  = -33201
	CodeUnknownStream     = -33202
	CodeClaimProbeFault   = -33203
	CodeTransportInternal = -33299
)

// dial_upstream codes.
const (
	CodeDialScopeRejected = -33300
	CodeDialFailed        = -33301
	CodeDialTLSFailed     = -33302
)

// invoke_adapter codes.
const (
	CodeUnknownDestAdapter = -33400
	CodeNoInjectionTarget  = -33401
	CodeInjectSendFailed   = -33402
)

// ErrorData carries the adapter name plus any relevant identifiers on a
// sectool-specific error.
type ErrorData struct {
	Adapter         string `json:"adapter,omitempty"`
	ConflictAdapter string `json:"conflict_adapter,omitempty"`
	FlowID          string `json:"flow_id,omitempty"`
	StreamID        string `json:"stream_id,omitempty"`
}

// Error is a JSON-RPC 2.0 error object; it implements the error interface.
type Error struct {
	Code    int        `json:"code"`
	Message string     `json:"message"`
	Data    *ErrorData `json:"data,omitempty"`
}

func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	} else if e.Data != nil && e.Data.Adapter != "" {
		return fmt.Sprintf("jsonrpc error %d (%s): %s", e.Code, e.Data.Adapter, e.Message)
	}
	return fmt.Sprintf("jsonrpc error %d: %s", e.Code, e.Message)
}

// NewError builds an Error with the given code and message.
func NewError(code int, msg string) *Error {
	return &Error{Code: code, Message: msg}
}

// WithData attaches structured data and returns the error for chaining.
func (e *Error) WithData(d *ErrorData) *Error {
	e.Data = d
	return e
}
