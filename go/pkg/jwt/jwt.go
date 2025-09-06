package jwt

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/agentcommercekit/ack/go/pkg/keys"
)

// Header represents JWT header
type Header struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
	KeyID     string `json:"kid,omitempty"`
}

// Claims represents JWT claims
type Claims struct {
	Issuer         string                 `json:"iss,omitempty"`
	Subject        string                 `json:"sub,omitempty"`
	Audience       interface{}            `json:"aud,omitempty"` // string or []string
	ExpirationTime *NumericDate           `json:"exp,omitempty"`
	NotBefore      *NumericDate           `json:"nbf,omitempty"`
	IssuedAt       *NumericDate           `json:"iat,omitempty"`
	JWTID          string                 `json:"jti,omitempty"`
	Extra          map[string]interface{} `json:"-"`
}

// NumericDate represents JWT numeric date
type NumericDate struct {
	time.Time
}

// MarshalJSON implements json.Marshaler
func (n NumericDate) MarshalJSON() ([]byte, error) {
	return json.Marshal(n.Unix())
}

// UnmarshalJSON implements json.Unmarshaler
func (n *NumericDate) UnmarshalJSON(data []byte) error {
	var timestamp int64
	if err := json.Unmarshal(data, &timestamp); err != nil {
		return err
	}
	n.Time = time.Unix(timestamp, 0)
	return nil
}

// NewNumericDate creates a NumericDate from time.Time
func NewNumericDate(t time.Time) *NumericDate {
	return &NumericDate{Time: t}
}

// Token represents a JWT token
type Token struct {
	Header    Header
	Claims    Claims
	Signature []byte
	Raw       string
}

// Sign creates and signs a JWT token
func Sign(header Header, claims Claims, keyPair *keys.KeyPair) (string, error) {
	if keyPair.PrivateKey == nil {
		return "", fmt.Errorf("private key is required for signing")
	}

	// Ensure algorithm matches key curve
	expectedAlg := keyPair.Algorithm()
	if header.Algorithm != expectedAlg {
		return "", fmt.Errorf("algorithm mismatch: header has %s, key requires %s", 
			header.Algorithm, expectedAlg)
	}

	// Set default type
	if header.Type == "" {
		header.Type = "JWT"
	}

	// Encode header
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("failed to marshal header: %w", err)
	}
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	// Prepare claims map including extra claims
	claimsMap := make(map[string]interface{})
	
	// Add standard claims
	if claims.Issuer != "" {
		claimsMap["iss"] = claims.Issuer
	}
	if claims.Subject != "" {
		claimsMap["sub"] = claims.Subject
	}
	if claims.Audience != nil {
		claimsMap["aud"] = claims.Audience
	}
	if claims.ExpirationTime != nil {
		claimsMap["exp"] = claims.ExpirationTime.Unix()
	}
	if claims.NotBefore != nil {
		claimsMap["nbf"] = claims.NotBefore.Unix()
	}
	if claims.IssuedAt != nil {
		claimsMap["iat"] = claims.IssuedAt.Unix()
	}
	if claims.JWTID != "" {
		claimsMap["jti"] = claims.JWTID
	}
	
	// Add extra claims
	for k, v := range claims.Extra {
		claimsMap[k] = v
	}

	// Encode claims
	claimsJSON, err := json.Marshal(claimsMap)
	if err != nil {
		return "", fmt.Errorf("failed to marshal claims: %w", err)
	}
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	// Create signing input
	signingInput := headerB64 + "." + claimsB64

	// Sign
	signature, err := keyPair.Sign([]byte(signingInput))
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %w", err)
	}

	// Encode signature
	signatureB64 := base64.RawURLEncoding.EncodeToString(signature)

	// Return complete JWT
	return signingInput + "." + signatureB64, nil
}

// Parse parses a JWT token string
func Parse(tokenString string) (*Token, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	// Decode header
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode header: %w", err)
	}
	
	var header Header
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("failed to unmarshal header: %w", err)
	}

	// Decode claims
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode claims: %w", err)
	}

	// Parse into raw map first to handle extra claims
	var rawClaims map[string]interface{}
	if err := json.Unmarshal(claimsJSON, &rawClaims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal claims: %w", err)
	}

	// Build claims struct
	claims := Claims{
		Extra: make(map[string]interface{}),
	}

	// Extract standard claims
	for k, v := range rawClaims {
		switch k {
		case "iss":
			if str, ok := v.(string); ok {
				claims.Issuer = str
			}
		case "sub":
			if str, ok := v.(string); ok {
				claims.Subject = str
			}
		case "aud":
			claims.Audience = v
		case "exp":
			if num, ok := v.(float64); ok {
				claims.ExpirationTime = NewNumericDate(time.Unix(int64(num), 0))
			}
		case "nbf":
			if num, ok := v.(float64); ok {
				claims.NotBefore = NewNumericDate(time.Unix(int64(num), 0))
			}
		case "iat":
			if num, ok := v.(float64); ok {
				claims.IssuedAt = NewNumericDate(time.Unix(int64(num), 0))
			}
		case "jti":
			if str, ok := v.(string); ok {
				claims.JWTID = str
			}
		default:
			claims.Extra[k] = v
		}
	}

	// Decode signature
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature: %w", err)
	}

	return &Token{
		Header:    header,
		Claims:    claims,
		Signature: signature,
		Raw:       tokenString,
	}, nil
}

// Verify verifies a JWT token signature
func (t *Token) Verify(keyPair *keys.KeyPair) error {
	if keyPair.PublicKey == nil {
		return fmt.Errorf("public key is required for verification")
	}

	// Check algorithm matches
	expectedAlg := keyPair.Algorithm()
	if t.Header.Algorithm != expectedAlg {
		return fmt.Errorf("algorithm mismatch: token has %s, key requires %s", 
			t.Header.Algorithm, expectedAlg)
	}

	// Recreate signing input
	parts := strings.Split(t.Raw, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid token format")
	}
	
	signingInput := parts[0] + "." + parts[1]

	// Verify signature
	return keyPair.Verify([]byte(signingInput), t.Signature)
}

// IsExpired checks if the token is expired
func (t *Token) IsExpired() bool {
	if t.Claims.ExpirationTime == nil {
		return false // No expiration set
	}
	return time.Now().After(t.Claims.ExpirationTime.Time)
}

// IsNotYetValid checks if the token is not yet valid
func (t *Token) IsNotYetValid() bool {
	if t.Claims.NotBefore == nil {
		return false // No nbf set
	}
	return time.Now().Before(t.Claims.NotBefore.Time)
}

// ValidateTime validates token time claims
func (t *Token) ValidateTime() error {
	if t.IsExpired() {
		return fmt.Errorf("token is expired")
	}
	if t.IsNotYetValid() {
		return fmt.Errorf("token is not yet valid")
	}
	return nil
}

// GetClaim retrieves a custom claim value
func (t *Token) GetClaim(key string) (interface{}, bool) {
	value, exists := t.Claims.Extra[key]
	return value, exists
}

// GetStringClaim retrieves a custom claim as a string
func (t *Token) GetStringClaim(key string) (string, bool) {
	value, exists := t.GetClaim(key)
	if !exists {
		return "", false
	}
	str, ok := value.(string)
	return str, ok
}

// VerifyAudience checks if the token audience matches expected value
func (t *Token) VerifyAudience(expected string) error {
	if t.Claims.Audience == nil {
		return fmt.Errorf("token has no audience claim")
	}

	switch aud := t.Claims.Audience.(type) {
	case string:
		if subtle.ConstantTimeCompare([]byte(aud), []byte(expected)) != 1 {
			return fmt.Errorf("audience mismatch")
		}
	case []string:
		for _, a := range aud {
			if subtle.ConstantTimeCompare([]byte(a), []byte(expected)) == 1 {
				return nil
			}
		}
		return fmt.Errorf("audience not found in array")
	case []interface{}:
		for _, a := range aud {
			if str, ok := a.(string); ok {
				if subtle.ConstantTimeCompare([]byte(str), []byte(expected)) == 1 {
					return nil
				}
			}
		}
		return fmt.Errorf("audience not found in array")
	default:
		return fmt.Errorf("invalid audience type")
	}

	return nil
}