// Copyright (c) 2026, Janoš Guljaš <janos@resenje.org>
// All rights reserved.

package sajberpank

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

func isSensitiveField(field string) bool {
	switch strings.ToLower(strings.TrimSpace(field)) {
	case "api_key", "secret", "password", "private_key", "token", "authorization":
		return true
	default:
		return false
	}
}

// FieldError represents a structured, machine-readable validation error returned by the API.
type FieldError struct {
	Field   string
	Reason  string
	Message string
	Value   string
}

func (f FieldError) String() string {
	if f.Field != "" {
		if f.Value != "" {
			val := f.Value
			if isSensitiveField(f.Field) {
				val = "[REDACTED]"
			}
			return fmt.Sprintf("%s (%q): %s [%s]", f.Field, val, f.Message, f.Reason)
		}
		return fmt.Sprintf("%s: %s [%s]", f.Field, f.Message, f.Reason)
	}
	return fmt.Sprintf("%s [%s]", f.Message, f.Reason)
}

// Standard Reason constants.
const (
	ReasonMissing                  = "missing"
	ReasonEmpty                    = "empty"
	ReasonTooLong                  = "too_long"
	ReasonInvalidCharacter         = "invalid_character"
	ReasonInvalidFormat            = "invalid_format"
	ReasonUnsupported              = "unsupported"
	ReasonMaxKeysReached           = "max_keys_reached"
	ReasonInvalidExpiration        = "invalid_expiration"
	ReasonInvalidData              = "invalid_data"
	ReasonInvalidValue             = "invalid_value"
	ReasonCannotRevokeCurrentKey   = "cannot_revoke_current_key"
	ReasonCannotRevokeLastKey      = "cannot_revoke_last_key"
	ReasonReserved                 = "reserved"
	ReasonReservedPrefix           = "reserved_prefix"
	ReasonCategoryNotInSearchScope = "category_not_in_search_scope"
	ReasonMutuallyExclusive        = "mutually_exclusive"
	ReasonQuotaExceeded            = "quota_exceeded"
)

// BadRequestError holds structured validation errors from an HTTP 400 response.
type BadRequestError struct {
	message     string
	fieldErrors []FieldError
}

// NewBadRequestError constructs a new BadRequestError with provided field errors.
func NewBadRequestError(fieldErrors ...FieldError) *BadRequestError {
	return &BadRequestError{
		fieldErrors: fieldErrors,
	}
}

// Message returns the general error message from the bad request response, if any.
func (e *BadRequestError) Message() string {
	return e.message
}

func (e *BadRequestError) Error() string {
	if len(e.fieldErrors) == 0 {
		if e.message != "" {
			return fmt.Sprintf("bad request: %s", e.message)
		}
		return "bad request"
	}
	parts := make([]string, len(e.fieldErrors))
	for i, fe := range e.fieldErrors {
		parts[i] = fe.String()
	}
	if e.message != "" {
		return fmt.Sprintf("bad request: %s: %s", e.message, strings.Join(parts, "; "))
	}
	return fmt.Sprintf("bad request: %s", strings.Join(parts, "; "))
}

// FieldErrors returns all validation field errors.
func (e *BadRequestError) FieldErrors() []FieldError {
	return e.fieldErrors
}

// HasField returns true if any field error matches the field name.
func (e *BadRequestError) HasField(field string) bool {
	for _, fe := range e.fieldErrors {
		if fe.Field == field {
			return true
		}
	}
	return false
}

// HasReason returns true if any field error matches the reason.
func (e *BadRequestError) HasReason(reason string) bool {
	for _, fe := range e.fieldErrors {
		if fe.Reason == reason {
			return true
		}
	}
	return false
}

// HasFieldReason returns true if any field error matches both field name and reason.
func (e *BadRequestError) HasFieldReason(field, reason string) bool {
	for _, fe := range e.fieldErrors {
		if fe.Field == field && fe.Reason == reason {
			return true
		}
	}
	return false
}

// FindByField returns all errors for a specific field.
func (e *BadRequestError) FindByField(field string) []FieldError {
	var matches []FieldError
	for _, fe := range e.fieldErrors {
		if fe.Field == field {
			matches = append(matches, fe)
		}
	}
	return matches
}

// ForbiddenError holds structured error details from an HTTP 403 response.
type ForbiddenError struct {
	message     string
	fieldErrors []FieldError
}

// NewForbiddenError constructs a new ForbiddenError with provided field errors.
func NewForbiddenError(fieldErrors ...FieldError) *ForbiddenError {
	return &ForbiddenError{
		fieldErrors: fieldErrors,
	}
}

// Message returns the general error message from the forbidden response, if any.
func (e *ForbiddenError) Message() string {
	return e.message
}

func (e *ForbiddenError) Error() string {
	if len(e.fieldErrors) == 0 {
		if e.message != "" {
			return fmt.Sprintf("forbidden: %s", e.message)
		}
		return "forbidden"
	}
	parts := make([]string, len(e.fieldErrors))
	for i, fe := range e.fieldErrors {
		parts[i] = fe.String()
	}
	if e.message != "" {
		return fmt.Sprintf("forbidden: %s: %s", e.message, strings.Join(parts, "; "))
	}
	return fmt.Sprintf("forbidden: %s", strings.Join(parts, "; "))
}

// FieldErrors returns all error details.
func (e *ForbiddenError) FieldErrors() []FieldError {
	return e.fieldErrors
}

// HasReason returns true if any field error matches the reason.
func (e *ForbiddenError) HasReason(reason string) bool {
	for _, fe := range e.fieldErrors {
		if fe.Reason == reason {
			return true
		}
	}
	return false
}

// Is reports whether this error matches target. It returns true for ErrForbidden
// and, if any field error has ReasonQuotaExceeded, for ErrQuotaExceeded.
func (e *ForbiddenError) Is(target error) bool {
	if target == ErrForbidden {
		return true
	}
	if target == ErrQuotaExceeded && e.HasReason(ReasonQuotaExceeded) {
		return true
	}
	return false
}

// APIError represents an unexpected or non-2xx HTTP status response.
type APIError struct {
	StatusCode int
	Message    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("api error (%d): %s", e.StatusCode, e.Message)
}

// Sentinel error values.
var (
	ErrUnauthorized           = errors.New("unauthorized")
	ErrForbidden              = errors.New("forbidden")
	ErrQuotaExceeded          = errors.New("quota exceeded")
	ErrNotFound               = errors.New("not found")
	ErrConflict               = errors.New("conflict")
	ErrTooManyRequests        = errors.New("too many requests")
	ErrInternalServerError    = errors.New("internal server error")
	ErrInvalidKey             = errors.New("invalid key")
	ErrInvalidKeyName         = errors.New("invalid key name")
	ErrInvalidNamespace       = errors.New("invalid namespace")
	ErrInvalidCategory        = errors.New("invalid category")
	ErrInvalidDocumentID      = errors.New("invalid document id")
	ErrMissingDocumentContent = errors.New("missing document content")
	ErrInvalidDocumentContent = errors.New("invalid document content")
)

type fieldErrorBody struct {
	Field   string `json:"field,omitempty"`
	Reason  string `json:"reason"`
	Message string `json:"message"`
	Value   string `json:"value,omitempty"`
}

type apiErrorPayload struct {
	Code    int              `json:"code"`
	Message string           `json:"message"`
	Errors  []fieldErrorBody `json:"errors"`
}

func wrapSentinelError(sentinel error, message string) error {
	if message != "" {
		return fmt.Errorf("%w: %s", sentinel, message)
	}
	return sentinel
}

const maxErrorBodyBytes = 1 << 20 // 1 MB max error payload decode limit

func handleErrorResponse(resp *http.Response) error {
	var payload apiErrorPayload
	_ = json.NewDecoder(io.LimitReader(resp.Body, maxErrorBodyBytes)).Decode(&payload)

	switch resp.StatusCode {
	case http.StatusBadRequest:
		fieldErrors := make([]FieldError, len(payload.Errors))
		for i, fe := range payload.Errors {
			fieldErrors[i] = FieldError(fe)
		}
		return &BadRequestError{
			message:     payload.Message,
			fieldErrors: fieldErrors,
		}
	case http.StatusUnauthorized:
		return wrapSentinelError(ErrUnauthorized, payload.Message)
	case http.StatusForbidden:
		if len(payload.Errors) > 0 {
			fieldErrors := make([]FieldError, len(payload.Errors))
			for i, fe := range payload.Errors {
				fieldErrors[i] = FieldError(fe)
			}
			return &ForbiddenError{
				message:     payload.Message,
				fieldErrors: fieldErrors,
			}
		}
		return wrapSentinelError(ErrForbidden, payload.Message)
	case http.StatusNotFound:
		return wrapSentinelError(ErrNotFound, payload.Message)
	case http.StatusConflict:
		return wrapSentinelError(ErrConflict, payload.Message)
	case http.StatusTooManyRequests:
		return wrapSentinelError(ErrTooManyRequests, payload.Message)
	case http.StatusInternalServerError:
		return wrapSentinelError(ErrInternalServerError, payload.Message)
	default:
		if payload.Message != "" {
			return &APIError{StatusCode: resp.StatusCode, Message: payload.Message}
		}
		return &APIError{StatusCode: resp.StatusCode, Message: http.StatusText(resp.StatusCode)}
	}
}
