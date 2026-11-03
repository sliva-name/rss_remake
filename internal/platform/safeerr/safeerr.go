// Package safeerr carries failures across trust boundaries as codes. Database
// driver errors can quote row values (PostgreSQL DETAIL, duplicate-key
// messages), so their text must never reach a log or the wire.
package safeerr

import (
	"context"
	"errors"
)

// Code is a stable, value-free failure category.
type Code string

const (
	CodeUnknown      Code = "UNKNOWN"
	CodeTimeout      Code = "TIMEOUT"
	CodeCanceled     Code = "CANCELED"
	CodeUnavailable  Code = "UNAVAILABLE"
	CodeUnauthorized Code = "UNAUTHORIZED"
	CodeNotFound     Code = "NOT_FOUND"
	CodeInvalid      Code = "INVALID"
	CodeQuery        Code = "QUERY_FAILED"
	CodeInternal     Code = "INTERNAL"
)

// Error is a failure stripped of its original text. The cause is intentionally
// not retained: an Unwrap or %+v anywhere up the stack would print it.
type Error struct {
	Code Code
	// Op is a static description written by the caller, never derived from data.
	Op string
}

func (e *Error) Error() string { return e.Op + ": " + string(e.Code) }

// New drops the text of cause and keeps only its classification.
func New(op string, code Code, cause error) *Error {
	return &Error{Op: op, Code: classify(code, cause)}
}

func classify(fallback Code, cause error) Code {
	switch {
	case errors.Is(cause, context.DeadlineExceeded):
		return CodeTimeout
	case errors.Is(cause, context.Canceled):
		return CodeCanceled
	default:
		return fallback
	}
}

// CodeOf returns the code of err, or CodeUnknown if it is not a safe error.
func CodeOf(err error) Code {
	if safe, ok := errors.AsType[*Error](err); ok {
		return safe.Code
	}
	return CodeUnknown
}
