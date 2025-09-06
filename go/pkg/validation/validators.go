package validation

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Common validation patterns
var (
	// DID format: did:method:method-specific-id
	didPattern = regexp.MustCompile(`^did:[a-z0-9]+:.+$`)
	
	// JWT format: header.payload.signature (base64url encoded)
	jwtPattern = regexp.MustCompile(`^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$`)
	
	// Multibase format: starts with 'z' (base58btc) or 'u' (base64url)  
	multibasePattern = regexp.MustCompile(`^[zmuUkKzZ][A-Za-z0-9+/=_-]+$`)
	
	// Ethereum address format: 0x followed by 40 hex characters
	ethereumAddressPattern = regexp.MustCompile(`^0x[a-fA-F0-9]{40}$`)
	
	// Transaction hash format: 0x followed by 64 hex characters
	txHashPattern = regexp.MustCompile(`^0x[a-fA-F0-9]{64}$`)
)

// ValidateDID validates a DID string format
func ValidateDID(didString string) *ValidationError {
	if didString == "" {
		return MissingFieldError("did")
	}
	
	if !didPattern.MatchString(didString) {
		return InvalidFormatError("did", "did:method:method-specific-id")
	}
	
	// Additional validation for specific DID methods
	parts := strings.Split(didString, ":")
	if len(parts) < 3 {
		return InvalidFormatError("did", "did:method:method-specific-id")
	}
	
	method := parts[1]
	switch method {
	case "key":
		return validateDidKey(didString, parts[2])
	case "web":
		return validateDidWeb(didString, parts[2:])
	}
	
	return nil
}

// validateDidKey validates a did:key format
func validateDidKey(didString, methodSpecific string) *ValidationError {
	if !multibasePattern.MatchString(methodSpecific) {
		return InvalidValueError("did", didString, "did:key requires multibase encoded public key")
	}
	
	// Ensure it starts with 'z' (base58btc) for standard did:key
	if !strings.HasPrefix(methodSpecific, "z") && !strings.HasPrefix(methodSpecific, "u") {
		return InvalidValueError("did", didString, "did:key should use base58btc (z) or base64url (u) encoding")
	}
	
	return nil
}

// validateDidWeb validates a did:web format
func validateDidWeb(didString string, parts []string) *ValidationError {
	if len(parts) == 0 {
		return InvalidValueError("did", didString, "did:web requires domain")
	}
	
	domain := parts[0]
	
	// Basic domain validation
	if domain == "" {
		return InvalidValueError("did", didString, "did:web domain cannot be empty")
	}
	
	// Check for invalid characters
	if strings.Contains(domain, "/") || strings.Contains(domain, "?") || strings.Contains(domain, "#") {
		return InvalidValueError("did", didString, "did:web domain contains invalid characters")
	}
	
	return nil
}

// ValidateJWT validates a JWT format
func ValidateJWT(token string) *ValidationError {
	if token == "" {
		return MissingFieldError("jwt")
	}
	
	if !jwtPattern.MatchString(token) {
		return InvalidFormatError("jwt", "header.payload.signature")
	}
	
	return nil
}

// ValidateMultibase validates a multibase encoded string
func ValidateMultibase(encoded string) *ValidationError {
	if encoded == "" {
		return MissingFieldError("multibase")
	}
	
	if !multibasePattern.MatchString(encoded) {
		return InvalidFormatError("multibase", "multibase encoded string (e.g., z..., u...)")
	}
	
	return nil
}

// ValidateURL validates a URL format
func ValidateURL(urlString string) *ValidationError {
	if urlString == "" {
		return MissingFieldError("url")
	}
	
	parsed, err := url.Parse(urlString)
	if err != nil {
		return WrapErrorWithField(ErrorTypeInvalidFormat, "invalid URL format", "url", err)
	}
	
	if parsed.Scheme == "" {
		return InvalidValueError("url", urlString, "missing URL scheme")
	}
	
	if parsed.Host == "" {
		return InvalidValueError("url", urlString, "missing URL host")
	}
	
	return nil
}

// ValidateHTTPSURL validates that a URL uses HTTPS
func ValidateHTTPSURL(urlString string) *ValidationError {
	if err := ValidateURL(urlString); err != nil {
		return err
	}
	
	parsed, _ := url.Parse(urlString) // Already validated above
	if parsed.Scheme != "https" {
		return InvalidValueError("url", urlString, "must use HTTPS scheme")
	}
	
	return nil
}

// ValidateEthereumAddress validates an Ethereum address format
func ValidateEthereumAddress(address string) *ValidationError {
	if address == "" {
		return MissingFieldError("ethereum_address")
	}
	
	if !ethereumAddressPattern.MatchString(address) {
		return InvalidFormatError("ethereum_address", "0x followed by 40 hex characters")
	}
	
	return nil
}

// ValidateTransactionHash validates a transaction hash format
func ValidateTransactionHash(hash string) *ValidationError {
	if hash == "" {
		return MissingFieldError("transaction_hash")
	}
	
	if !txHashPattern.MatchString(hash) {
		return InvalidFormatError("transaction_hash", "0x followed by 64 hex characters")
	}
	
	return nil
}

// ValidateTimeRange validates that a time is within an acceptable range
func ValidateTimeRange(t time.Time, minTime, maxTime time.Time, fieldName string) *ValidationError {
	if t.Before(minTime) {
		return InvalidValueError(fieldName, t.Format(time.RFC3339), 
			fmt.Sprintf("time is before minimum allowed time %s", minTime.Format(time.RFC3339)))
	}
	
	if t.After(maxTime) {
		return InvalidValueError(fieldName, t.Format(time.RFC3339), 
			fmt.Sprintf("time is after maximum allowed time %s", maxTime.Format(time.RFC3339)))
	}
	
	return nil
}

// ValidateNotExpired validates that a time is not expired
func ValidateNotExpired(expiresAt time.Time, fieldName string) *ValidationError {
	if time.Now().After(expiresAt) {
		return &ValidationError{
			Type:    ErrorTypeExpired,
			Message: fmt.Sprintf("%s has expired at %s", fieldName, expiresAt.Format(time.RFC3339)),
			Field:   fieldName,
		}
	}
	
	return nil
}

// ValidateNotBefore validates that a time is not before current time
func ValidateNotBefore(notBefore time.Time, fieldName string) *ValidationError {
	if time.Now().Before(notBefore) {
		return &ValidationError{
			Type:    ErrorTypeNotYetValid,
			Message: fmt.Sprintf("%s is not yet valid until %s", fieldName, notBefore.Format(time.RFC3339)),
			Field:   fieldName,
		}
	}
	
	return nil
}

// ValidateNonEmpty validates that a string is not empty
func ValidateNonEmpty(value, fieldName string) *ValidationError {
	if strings.TrimSpace(value) == "" {
		return MissingFieldError(fieldName)
	}
	return nil
}

// ValidateStringLength validates string length constraints
func ValidateStringLength(value, fieldName string, minLen, maxLen int) *ValidationError {
	length := len(value)
	
	if length < minLen {
		return InvalidValueError(fieldName, value, 
			fmt.Sprintf("length %d is less than minimum %d", length, minLen))
	}
	
	if length > maxLen {
		return InvalidValueError(fieldName, value, 
			fmt.Sprintf("length %d exceeds maximum %d", length, maxLen))
	}
	
	return nil
}

// ValidateOneOf validates that a value is one of the allowed values
func ValidateOneOf(value, fieldName string, allowedValues []string) *ValidationError {
	for _, allowed := range allowedValues {
		if value == allowed {
			return nil
		}
	}
	
	return InvalidValueError(fieldName, value, 
		fmt.Sprintf("must be one of: %s", strings.Join(allowedValues, ", ")))
}

// ValidateRegex validates that a string matches a regular expression
func ValidateRegex(value, fieldName string, pattern *regexp.Regexp, description string) *ValidationError {
	if !pattern.MatchString(value) {
		return InvalidValueError(fieldName, value, 
			fmt.Sprintf("does not match required pattern: %s", description))
	}
	
	return nil
}

// Composite validators

// ValidateCredentialBasics validates basic credential structure
func ValidateCredentialBasics(id, issuer string, types []string, issuanceDate time.Time) *ValidationErrors {
	var errors ValidationErrors
	
	if id != "" {
		if err := ValidateURL(id); err != nil {
			err.Field = "id"
			errors.Add(*err)
		}
	}
	
	if err := ValidateDID(issuer); err != nil {
		err.Field = "issuer"
		errors.Add(*err)
	}
	
	if len(types) == 0 {
		errors.AddError(ErrorTypeMissingField, "credential must have at least one type", "type")
	} else {
		hasVerifiableCredential := false
		for _, t := range types {
			if t == "VerifiableCredential" {
				hasVerifiableCredential = true
				break
			}
		}
		if !hasVerifiableCredential {
			errors.AddError(ErrorTypeInvalidValue, 
				"credential type must include 'VerifiableCredential'", "type")
		}
	}
	
	// Validate issuance date is reasonable (not too far in past or future)
	oneYearAgo := time.Now().AddDate(-1, 0, 0)
	oneHourFromNow := time.Now().Add(time.Hour)
	if err := ValidateTimeRange(issuanceDate, oneYearAgo, oneHourFromNow, "issuanceDate"); err != nil {
		errors.Add(*err)
	}
	
	return &errors
}

// ValidatePaymentMethod validates a payment method
func ValidatePaymentMethod(methodType, currency, network, address string) *ValidationErrors {
	var errors ValidationErrors
	
	// Validate method type
	allowedTypes := []string{"crypto", "credit_card", "bank_transfer", "paypal", "stripe", "wire"}
	if err := ValidateOneOf(methodType, "type", allowedTypes); err != nil {
		errors.Add(*err)
	}
	
	// Validate currency
	if err := ValidateNonEmpty(currency, "currency"); err != nil {
		errors.Add(*err)
	} else if err := ValidateStringLength(currency, "currency", 3, 10); err != nil {
		errors.Add(*err)
	}
	
	// Method-specific validation
	if methodType == "crypto" {
		if err := ValidateNonEmpty(network, "network"); err != nil {
			errors.Add(*err)
		}
		
		if address != "" {
			// Validate address format based on currency/network
			if strings.ToLower(currency) == "eth" || 
			   strings.ToLower(currency) == "usdc" || 
			   strings.ToLower(currency) == "usdt" {
				if err := ValidateEthereumAddress(address); err != nil {
					err.Field = "address"
					errors.Add(*err)
				}
			}
		}
	}
	
	return &errors
}