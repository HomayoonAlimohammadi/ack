package validation

import (
	"fmt"
	"strings"
)

// ErrorType represents different types of validation errors
type ErrorType string

const (
	ErrorTypeInvalidFormat      ErrorType = "invalid_format"
	ErrorTypeInvalidSignature   ErrorType = "invalid_signature"
	ErrorTypeExpired           ErrorType = "expired"
	ErrorTypeNotYetValid       ErrorType = "not_yet_valid"
	ErrorTypeMissingField      ErrorType = "missing_field"
	ErrorTypeInvalidValue      ErrorType = "invalid_value"
	ErrorTypeUnsupportedType   ErrorType = "unsupported_type"
	ErrorTypeVerificationFailed ErrorType = "verification_failed"
	ErrorTypeKeyNotFound       ErrorType = "key_not_found"
	ErrorTypeNetworkError      ErrorType = "network_error"
	ErrorTypeInternalError     ErrorType = "internal_error"
)

// ValidationError represents a structured validation error
type ValidationError struct {
	Type        ErrorType `json:"type"`
	Message     string    `json:"message"`
	Field       string    `json:"field,omitempty"`
	Value       string    `json:"value,omitempty"`
	Context     string    `json:"context,omitempty"`
	InnerError  error     `json:"-"`
	Suggestions []string  `json:"suggestions,omitempty"`
}

// Error implements the error interface
func (e *ValidationError) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("%s: %s (field: %s)", e.Type, e.Message, e.Field)
	}
	return fmt.Sprintf("%s: %s", e.Type, e.Message)
}

// Unwrap returns the inner error for error unwrapping
func (e *ValidationError) Unwrap() error {
	return e.InnerError
}

// Is implements error matching for errors.Is
func (e *ValidationError) Is(target error) bool {
	if ve, ok := target.(*ValidationError); ok {
		return e.Type == ve.Type
	}
	return false
}

// ValidationErrors represents multiple validation errors
type ValidationErrors struct {
	Errors []ValidationError `json:"errors"`
}

// Error implements the error interface
func (ve *ValidationErrors) Error() string {
	if len(ve.Errors) == 0 {
		return "no validation errors"
	}
	
	if len(ve.Errors) == 1 {
		return ve.Errors[0].Error()
	}
	
	var messages []string
	for _, err := range ve.Errors {
		messages = append(messages, err.Error())
	}
	
	return fmt.Sprintf("validation failed with %d errors: %s", 
		len(ve.Errors), strings.Join(messages, "; "))
}

// Add adds a validation error
func (ve *ValidationErrors) Add(err ValidationError) {
	ve.Errors = append(ve.Errors, err)
}

// AddError adds an error as a validation error
func (ve *ValidationErrors) AddError(errType ErrorType, message string, field ...string) {
	err := ValidationError{
		Type:    errType,
		Message: message,
	}
	if len(field) > 0 {
		err.Field = field[0]
	}
	ve.Add(err)
}

// HasErrors returns true if there are validation errors
func (ve *ValidationErrors) HasErrors() bool {
	return len(ve.Errors) > 0
}

// HasErrorType returns true if there are errors of the specified type
func (ve *ValidationErrors) HasErrorType(errType ErrorType) bool {
	for _, err := range ve.Errors {
		if err.Type == errType {
			return true
		}
	}
	return false
}

// GetByType returns all errors of the specified type
func (ve *ValidationErrors) GetByType(errType ErrorType) []ValidationError {
	var result []ValidationError
	for _, err := range ve.Errors {
		if err.Type == errType {
			result = append(result, err)
		}
	}
	return result
}

// NewValidationError creates a new validation error
func NewValidationError(errType ErrorType, message string) *ValidationError {
	return &ValidationError{
		Type:    errType,
		Message: message,
	}
}

// NewValidationErrorWithField creates a validation error with a field
func NewValidationErrorWithField(errType ErrorType, message, field string) *ValidationError {
	return &ValidationError{
		Type:    errType,
		Message: message,
		Field:   field,
	}
}

// NewValidationErrorWithSuggestions creates a validation error with suggestions
func NewValidationErrorWithSuggestions(errType ErrorType, message string, suggestions []string) *ValidationError {
	return &ValidationError{
		Type:        errType,
		Message:     message,
		Suggestions: suggestions,
	}
}

// WrapError wraps an existing error as a validation error
func WrapError(errType ErrorType, message string, innerErr error) *ValidationError {
	return &ValidationError{
		Type:       errType,
		Message:    message,
		InnerError: innerErr,
	}
}

// WrapErrorWithField wraps an error with field information
func WrapErrorWithField(errType ErrorType, message, field string, innerErr error) *ValidationError {
	return &ValidationError{
		Type:       errType,
		Message:    message,
		Field:      field,
		InnerError: innerErr,
	}
}

// Common validation error constructors

// InvalidFormatError creates an invalid format error
func InvalidFormatError(field, expected string) *ValidationError {
	return NewValidationErrorWithField(ErrorTypeInvalidFormat, 
		fmt.Sprintf("invalid format, expected %s", expected), field)
}

// MissingFieldError creates a missing field error
func MissingFieldError(field string) *ValidationError {
	return NewValidationErrorWithField(ErrorTypeMissingField, 
		fmt.Sprintf("required field is missing"), field)
}

// InvalidValueError creates an invalid value error
func InvalidValueError(field, value, reason string) *ValidationError {
	return &ValidationError{
		Type:    ErrorTypeInvalidValue,
		Message: fmt.Sprintf("invalid value: %s", reason),
		Field:   field,
		Value:   value,
	}
}

// ExpiredError creates an expired error
func ExpiredError(context string) *ValidationError {
	return &ValidationError{
		Type:    ErrorTypeExpired,
		Message: fmt.Sprintf("%s has expired", context),
		Context: context,
	}
}

// SignatureVerificationError creates a signature verification error
func SignatureVerificationError(details string) *ValidationError {
	return NewValidationError(ErrorTypeInvalidSignature, 
		fmt.Sprintf("signature verification failed: %s", details))
}

// UnsupportedTypeError creates an unsupported type error
func UnsupportedTypeError(typeName, context string) *ValidationError {
	return &ValidationError{
		Type:    ErrorTypeUnsupportedType,
		Message: fmt.Sprintf("unsupported type '%s' in %s", typeName, context),
		Context: context,
	}
}