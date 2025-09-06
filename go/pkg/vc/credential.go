package vc

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/HomayoonAlimohammadi/ack/go/pkg/jwt"
	"github.com/HomayoonAlimohammadi/ack/go/pkg/keys"
)

// Credential represents a W3C Verifiable Credential
type Credential struct {
	Context           []string    `json:"@context"`
	ID                string      `json:"id,omitempty"`
	Type              []string    `json:"type"`
	Issuer            interface{} `json:"issuer"` // string or IssuerObject
	IssuanceDate      time.Time   `json:"issuanceDate"`
	ExpirationDate    *time.Time  `json:"expirationDate,omitempty"`
	CredentialSubject interface{} `json:"credentialSubject"`
	CredentialStatus  interface{} `json:"credentialStatus,omitempty"`
	Proof             []Proof     `json:"proof,omitempty"`
	RefreshService    interface{} `json:"refreshService,omitempty"`
	TermsOfUse        interface{} `json:"termsOfUse,omitempty"`
	Evidence          interface{} `json:"evidence,omitempty"`
}

// IssuerObject represents an issuer with additional properties
type IssuerObject struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
}

// Proof represents a cryptographic proof for a credential
type Proof struct {
	Type               string     `json:"type"`
	Created            *time.Time `json:"created,omitempty"`
	VerificationMethod string     `json:"verificationMethod,omitempty"`
	ProofPurpose       string     `json:"proofPurpose,omitempty"`
	ProofValue         string     `json:"proofValue,omitempty"`
	JWS                string     `json:"jws,omitempty"`
	Challenge          string     `json:"challenge,omitempty"`
	Domain             string     `json:"domain,omitempty"`
}

// Presentation represents a W3C Verifiable Presentation
type Presentation struct {
	Context              []string    `json:"@context"`
	ID                   string      `json:"id,omitempty"`
	Type                 []string    `json:"type"`
	Holder               string      `json:"holder,omitempty"`
	VerifiableCredential interface{} `json:"verifiableCredential,omitempty"` // Can be array or single credential
	Proof                []Proof     `json:"proof,omitempty"`
}

// NewCredential creates a new verifiable credential
func NewCredential() *Credential {
	return &Credential{
		Context: []string{
			"https://www.w3.org/2018/credentials/v1",
		},
		Type: []string{
			"VerifiableCredential",
		},
		IssuanceDate: time.Now(),
		Proof:        make([]Proof, 0),
	}
}

// NewPresentation creates a new verifiable presentation
func NewPresentation() *Presentation {
	return &Presentation{
		Context: []string{
			"https://www.w3.org/2018/credentials/v1",
		},
		Type: []string{
			"VerifiablePresentation",
		},
		Proof: make([]Proof, 0),
	}
}

// AddType adds a type to the credential
func (c *Credential) AddType(credType string) {
	c.Type = append(c.Type, credType)
}

// AddContext adds a context to the credential
func (c *Credential) AddContext(context string) {
	c.Context = append(c.Context, context)
}

// SetIssuer sets the issuer of the credential
func (c *Credential) SetIssuer(issuer string) {
	c.Issuer = issuer
}

// SetIssuerObject sets the issuer as an object with additional properties
func (c *Credential) SetIssuerObject(id, name string) {
	c.Issuer = IssuerObject{
		ID:   id,
		Name: name,
	}
}

// GetIssuerID returns the issuer ID regardless of format
func (c *Credential) GetIssuerID() string {
	switch issuer := c.Issuer.(type) {
	case string:
		return issuer
	case IssuerObject:
		return issuer.ID
	case map[string]interface{}:
		if id, ok := issuer["id"].(string); ok {
			return id
		}
	}
	return ""
}

// AddProof adds a proof to the credential
func (c *Credential) AddProof(proof Proof) {
	c.Proof = append(c.Proof, proof)
}

// ToJSON converts the credential to JSON
func (c *Credential) ToJSON() ([]byte, error) {
	return json.MarshalIndent(c, "", "  ")
}

// FromJSON parses a credential from JSON
func CredentialFromJSON(data []byte) (*Credential, error) {
	var cred Credential
	if err := json.Unmarshal(data, &cred); err != nil {
		return nil, fmt.Errorf("failed to parse credential: %w", err)
	}
	return &cred, nil
}

// Validate performs basic validation of the credential
func (c *Credential) Validate() error {
	if len(c.Context) == 0 {
		return fmt.Errorf("credential must have @context")
	}

	// Check required context
	hasRequiredContext := false
	for _, ctx := range c.Context {
		if ctx == "https://www.w3.org/2018/credentials/v1" {
			hasRequiredContext = true
			break
		}
	}
	if !hasRequiredContext {
		return fmt.Errorf("credential must include https://www.w3.org/2018/credentials/v1 in @context")
	}

	if len(c.Type) == 0 {
		return fmt.Errorf("credential must have type")
	}

	// Check required type
	hasRequiredType := false
	for _, t := range c.Type {
		if t == "VerifiableCredential" {
			hasRequiredType = true
			break
		}
	}
	if !hasRequiredType {
		return fmt.Errorf("credential must include VerifiableCredential in type")
	}

	if c.Issuer == nil {
		return fmt.Errorf("credential must have issuer")
	}

	if c.GetIssuerID() == "" {
		return fmt.Errorf("credential issuer must have id")
	}

	if c.CredentialSubject == nil {
		return fmt.Errorf("credential must have credentialSubject")
	}

	// Validate expiration
	if c.ExpirationDate != nil && time.Now().After(*c.ExpirationDate) {
		return fmt.Errorf("credential is expired")
	}

	return nil
}

// IsExpired checks if the credential is expired
func (c *Credential) IsExpired() bool {
	if c.ExpirationDate == nil {
		return false
	}
	return time.Now().After(*c.ExpirationDate)
}

// ToJWT converts the credential to a JWT format
func (c *Credential) ToJWT(keyPair *keys.KeyPair, kid string) (string, error) {
	if err := c.Validate(); err != nil {
		return "", fmt.Errorf("credential validation failed: %w", err)
	}

	// Create JWT claims
	claims := jwt.Claims{
		Issuer:   c.GetIssuerID(),
		IssuedAt: jwt.NewNumericDate(c.IssuanceDate),
		Extra:    make(map[string]interface{}),
	}

	if c.ExpirationDate != nil {
		claims.ExpirationTime = jwt.NewNumericDate(*c.ExpirationDate)
	}

	// Add VC-specific claims
	claims.Extra["vc"] = c

	// Create JWT header
	header := jwt.Header{
		Algorithm: keyPair.Algorithm(),
		Type:      "JWT",
		KeyID:     kid,
	}

	// Sign and return JWT
	return jwt.Sign(header, claims, keyPair)
}

// CredentialFromJWT parses a credential from JWT format
func CredentialFromJWT(tokenString string) (*Credential, *jwt.Token, error) {
	// Parse JWT
	token, err := jwt.Parse(tokenString)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse JWT: %w", err)
	}

	// Extract VC claim
	vcClaim, exists := token.GetClaim("vc")
	if !exists {
		return nil, nil, fmt.Errorf("JWT does not contain vc claim")
	}

	// Convert to JSON and back to parse as credential
	vcJSON, err := json.Marshal(vcClaim)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal vc claim: %w", err)
	}

	credential, err := CredentialFromJSON(vcJSON)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse credential from vc claim: %w", err)
	}

	return credential, token, nil
}

// VerifyJWT verifies a JWT credential signature
func VerifyJWT(tokenString string, keyPair *keys.KeyPair) (*Credential, error) {
	credential, token, err := CredentialFromJWT(tokenString)
	if err != nil {
		return nil, err
	}

	// Verify signature
	if err := token.Verify(keyPair); err != nil {
		return nil, fmt.Errorf("JWT signature verification failed: %w", err)
	}

	// Validate time claims
	if err := token.ValidateTime(); err != nil {
		return nil, fmt.Errorf("JWT time validation failed: %w", err)
	}

	// Validate credential
	if err := credential.Validate(); err != nil {
		return nil, fmt.Errorf("credential validation failed: %w", err)
	}

	return credential, nil
}

// AddType adds a type to the presentation
func (p *Presentation) AddType(presType string) {
	p.Type = append(p.Type, presType)
}

// AddContext adds a context to the presentation
func (p *Presentation) AddContext(context string) {
	p.Context = append(p.Context, context)
}

// AddCredential adds a credential to the presentation
func (p *Presentation) AddCredential(credential interface{}) {
	switch existing := p.VerifiableCredential.(type) {
	case nil:
		p.VerifiableCredential = credential
	case []interface{}:
		p.VerifiableCredential = append(existing, credential)
	default:
		// Convert single credential to array and add new one
		p.VerifiableCredential = []interface{}{existing, credential}
	}
}

// ToJSON converts the presentation to JSON
func (p *Presentation) ToJSON() ([]byte, error) {
	return json.MarshalIndent(p, "", "  ")
}

// FromJSON parses a presentation from JSON
func PresentationFromJSON(data []byte) (*Presentation, error) {
	var pres Presentation
	if err := json.Unmarshal(data, &pres); err != nil {
		return nil, fmt.Errorf("failed to parse presentation: %w", err)
	}
	return &pres, nil
}
