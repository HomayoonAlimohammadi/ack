package ackid

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/agentcommercekit/ack/go/pkg/did"
	"github.com/agentcommercekit/ack/go/pkg/jwt"
	"github.com/agentcommercekit/ack/go/pkg/keys"
	"github.com/agentcommercekit/ack/go/pkg/vc"
)

// Agent represents an ACK-ID agent with cryptographic identity
type Agent struct {
	DID                *did.DID
	Document           *did.Document
	KeyPair            *keys.KeyPair
	Name               string
	ControllerKeyPair  *keys.KeyPair // Optional: for agents controlled by another entity
	ControllerDID      *did.DID      // Optional: DID of the controlling entity
	CredentialIssuerURL string       // URL of credential issuer
	VerifierURL        string        // URL of credential verifier
	Resolver           *did.Resolver // DID resolver for verification
}

// IdentityChallenge represents a cryptographic challenge for identity verification
type IdentityChallenge struct {
	Challenge   string    `json:"challenge"`
	DID         string    `json:"did"`
	Timestamp   time.Time `json:"timestamp"`
	ExpiresAt   time.Time `json:"expires_at"`
	Nonce       string    `json:"nonce"`
	Purpose     string    `json:"purpose,omitempty"`
	RequiredVCs []string  `json:"required_vcs,omitempty"`
}

// IdentityResponse represents the response to an identity challenge
type IdentityResponse struct {
	Challenge           string                 `json:"challenge"`
	SignedChallenge     string                 `json:"signed_challenge"`   // JWT
	DIDDocument         *did.Document          `json:"did_document"`
	VerifiableCredential interface{}           `json:"verifiable_credential,omitempty"` // Can be single VC or array
	AdditionalProofs    []string               `json:"additional_proofs,omitempty"`
	Metadata            map[string]interface{} `json:"metadata,omitempty"`
}

// VerificationResult represents the result of identity verification
type VerificationResult struct {
	Valid           bool                   `json:"valid"`
	DID             string                 `json:"did"`
	VerifiedClaims  map[string]interface{} `json:"verified_claims"`
	TrustLevel      TrustLevel             `json:"trust_level"`
	Errors          []string               `json:"errors,omitempty"`
	Warnings        []string               `json:"warnings,omitempty"`
	VerifiedAt      time.Time              `json:"verified_at"`
	CredentialChain []string               `json:"credential_chain,omitempty"`
}

// TrustLevel represents the level of trust established
type TrustLevel string

const (
	TrustNone         TrustLevel = "none"
	TrustDIDOnly      TrustLevel = "did_only"      // Only DID verified
	TrustBasic        TrustLevel = "basic"         // DID + signature verified
	TrustCredential   TrustLevel = "credential"    // Has valid credential
	TrustController   TrustLevel = "controller"    // Has valid controller credential
	TrustFull         TrustLevel = "full"          // Complete verification chain
)

// NewAgent creates a new ACK-ID agent
func NewAgent(curve keys.CurveType, name string) (*Agent, error) {
	// Generate key pair
	keyPair, err := keys.Generate(curve)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	// Create DID from public key
	pubKeyMulticodec, err := keyPair.EncodePublicKeyMulticodec()
	if err != nil {
		return nil, fmt.Errorf("failed to encode public key: %w", err)
	}

	agentDID, err := did.CreateKey(pubKeyMulticodec)
	if err != nil {
		return nil, fmt.Errorf("failed to create DID: %w", err)
	}

	// Create DID document
	document := did.NewDocument(agentDID.String())
	
	// Add verification method
	vmID := agentDID.String() + "#key-1"
	vm := did.VerificationMethod{
		ID:                 vmID,
		Type:               getVerificationMethodType(curve),
		Controller:         agentDID.String(),
		PublicKeyMultibase: pubKeyMulticodec,
	}
	
	document.AddVerificationMethod(vm)
	document.AddAuthentication(vmID)
	document.AddAssertionMethod(vmID)

	return &Agent{
		DID:      agentDID,
		Document: document,
		KeyPair:  keyPair,
		Name:     name,
		Resolver: did.NewResolver(),
	}, nil
}

// NewWebAgent creates a new ACK-ID agent with did:web
func NewWebAgent(curve keys.CurveType, domain, name string, path ...string) (*Agent, error) {
	// Generate key pair
	keyPair, err := keys.Generate(curve)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	// Create did:web DID
	agentDID, err := did.CreateWeb(domain, path...)
	if err != nil {
		return nil, fmt.Errorf("failed to create did:web: %w", err)
	}

	// Create DID document
	document := did.NewDocument(agentDID.String())
	
	// Add verification method
	pubKeyMulticodec, err := keyPair.EncodePublicKeyMulticodec()
	if err != nil {
		return nil, fmt.Errorf("failed to encode public key: %w", err)
	}

	vmID := agentDID.String() + "#key-1"
	vm := did.VerificationMethod{
		ID:                 vmID,
		Type:               getVerificationMethodType(curve),
		Controller:         agentDID.String(),
		PublicKeyMultibase: pubKeyMulticodec,
	}
	
	document.AddVerificationMethod(vm)
	document.AddAuthentication(vmID)
	document.AddAssertionMethod(vmID)

	return &Agent{
		DID:      agentDID,
		Document: document,
		KeyPair:  keyPair,
		Name:     name,
		Resolver: did.NewResolver(),
	}, nil
}

// SetController sets a controller for this agent
func (a *Agent) SetController(controllerDID *did.DID, controllerKeyPair *keys.KeyPair) {
	a.ControllerDID = controllerDID
	a.ControllerKeyPair = controllerKeyPair
	a.Document.AddController(controllerDID.String())
}

// AddService adds a service endpoint to the agent's DID document
func (a *Agent) AddService(serviceID, serviceType string, endpoint interface{}) {
	service := did.Service{
		ID:              a.DID.String() + "#" + serviceID,
		Type:            serviceType,
		ServiceEndpoint: endpoint,
	}
	a.Document.AddService(service)
}

// CreateChallenge creates a cryptographic challenge for identity verification
func (a *Agent) CreateChallenge(targetDID string, purpose string, requiredVCs ...string) (*IdentityChallenge, error) {
	// Generate random challenge
	challengeBytes := make([]byte, 32)
	if _, err := rand.Read(challengeBytes); err != nil {
		return nil, fmt.Errorf("failed to generate challenge: %w", err)
	}
	
	// Generate nonce
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	now := time.Now()
	return &IdentityChallenge{
		Challenge:   hex.EncodeToString(challengeBytes),
		DID:         targetDID,
		Timestamp:   now,
		ExpiresAt:   now.Add(5 * time.Minute),
		Nonce:       hex.EncodeToString(nonceBytes),
		Purpose:     purpose,
		RequiredVCs: requiredVCs,
	}, nil
}

// RespondToChallenge creates a response to an identity challenge
func (a *Agent) RespondToChallenge(ctx context.Context, challenge *IdentityChallenge) (*IdentityResponse, error) {
	// Validate challenge expiration
	if time.Now().After(challenge.ExpiresAt) {
		return nil, fmt.Errorf("challenge has expired")
	}

	// Create signed challenge JWT
	signedChallenge, err := a.signChallenge(challenge)
	if err != nil {
		return nil, fmt.Errorf("failed to sign challenge: %w", err)
	}

	// Prepare response
	response := &IdentityResponse{
		Challenge:       challenge.Challenge,
		SignedChallenge: signedChallenge,
		DIDDocument:     a.Document,
		Metadata: map[string]interface{}{
			"agent_name": a.Name,
			"timestamp":  time.Now(),
		},
	}

	// Add credentials if available and required
	if len(challenge.RequiredVCs) > 0 {
		credentials, err := a.retrieveRequiredCredentials(ctx, challenge.RequiredVCs)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve required credentials: %w", err)
		}
		if len(credentials) > 0 {
			response.VerifiableCredential = credentials
		}
	}

	return response, nil
}

// VerifyIdentityResponse verifies an identity response
func (a *Agent) VerifyIdentityResponse(ctx context.Context, response *IdentityResponse, originalChallenge *IdentityChallenge) (*VerificationResult, error) {
	result := &VerificationResult{
		Valid:          false,
		DID:            "",
		VerifiedClaims: make(map[string]interface{}),
		TrustLevel:     TrustNone,
		Errors:         make([]string, 0),
		Warnings:       make([]string, 0),
		VerifiedAt:     time.Now(),
	}

	// Verify challenge matches
	if response.Challenge != originalChallenge.Challenge {
		result.Errors = append(result.Errors, "challenge mismatch")
		return result, nil
	}

	// Verify DID document
	if response.DIDDocument == nil {
		result.Errors = append(result.Errors, "missing DID document")
		return result, nil
	}

	result.DID = response.DIDDocument.ID

	// Validate DID document
	if err := response.DIDDocument.Validate(); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("invalid DID document: %v", err))
		return result, nil
	}

	result.TrustLevel = TrustDIDOnly

	// Verify signed challenge
	err := a.verifySignedChallenge(response.SignedChallenge, originalChallenge, response.DIDDocument)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("challenge signature verification failed: %v", err))
		return result, nil
	}

	result.TrustLevel = TrustBasic

	// Verify credentials if present
	if response.VerifiableCredential != nil {
		trustLevel, err := a.verifyCredentials(ctx, response.VerifiableCredential, response.DIDDocument.ID)
		if err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("credential verification warning: %v", err))
		} else if trustLevel > result.TrustLevel {
			result.TrustLevel = trustLevel
		}
	}

	// Mark as valid if basic verification passed
	if len(result.Errors) == 0 {
		result.Valid = true
		result.VerifiedClaims["did"] = result.DID
		result.VerifiedClaims["verified_at"] = result.VerifiedAt
	}

	return result, nil
}

// signChallenge signs a challenge and returns a JWT
func (a *Agent) signChallenge(challenge *IdentityChallenge) (string, error) {
	header := jwt.Header{
		Algorithm: a.KeyPair.Algorithm(),
		Type:      "JWT",
		KeyID:     a.DID.String() + "#key-1",
	}

	claims := jwt.Claims{
		Issuer:         a.DID.String(),
		Subject:        challenge.DID,
		Audience:       challenge.DID,
		IssuedAt:       jwt.NewNumericDate(time.Now()),
		ExpirationTime: jwt.NewNumericDate(challenge.ExpiresAt),
		Extra: map[string]interface{}{
			"challenge": challenge.Challenge,
			"nonce":     challenge.Nonce,
			"purpose":   challenge.Purpose,
		},
	}

	return jwt.Sign(header, claims, a.KeyPair)
}

// verifySignedChallenge verifies a signed challenge JWT
func (a *Agent) verifySignedChallenge(signedChallenge string, originalChallenge *IdentityChallenge, document *did.Document) error {
	// Parse JWT
	token, err := jwt.Parse(signedChallenge)
	if err != nil {
		return fmt.Errorf("failed to parse signed challenge: %w", err)
	}

	// Get verification method from DID document
	vm, err := document.GetVerificationMethod(document.ID + "#key-1")
	if err != nil {
		return fmt.Errorf("verification method not found: %w", err)
	}

	// Reconstruct key pair from public key
	keyPair, err := keys.DecodePublicKeyMulticodec(vm.PublicKeyMultibase)
	if err != nil {
		return fmt.Errorf("failed to decode public key: %w", err)
	}

	// Verify JWT signature
	if err := token.Verify(keyPair); err != nil {
		return fmt.Errorf("JWT signature verification failed: %w", err)
	}

	// Verify JWT time claims
	if err := token.ValidateTime(); err != nil {
		return fmt.Errorf("JWT time validation failed: %w", err)
	}

	// Verify challenge matches
	challengeClaim, ok := token.GetStringClaim("challenge")
	if !ok || challengeClaim != originalChallenge.Challenge {
		return fmt.Errorf("challenge mismatch in JWT")
	}

	// Verify issuer matches DID
	if token.Claims.Issuer != document.ID {
		return fmt.Errorf("JWT issuer does not match DID document")
	}

	return nil
}

// verifyCredentials verifies presented credentials
func (a *Agent) verifyCredentials(ctx context.Context, credentials interface{}, holderDID string) (TrustLevel, error) {
	switch creds := credentials.(type) {
	case string:
		// Single JWT credential
		return a.verifySingleCredential(ctx, creds, holderDID)
	case []string:
		// Array of JWT credentials
		maxTrust := TrustNone
		for _, credJWT := range creds {
			trust, err := a.verifySingleCredential(ctx, credJWT, holderDID)
			if err != nil {
				// Log warning but continue with other credentials
				continue
			}
			if trust > maxTrust {
				maxTrust = trust
			}
		}
		return maxTrust, nil
	case []interface{}:
		// Mixed array of credentials
		maxTrust := TrustNone
		for _, cred := range creds {
			if credStr, ok := cred.(string); ok {
				trust, err := a.verifySingleCredential(ctx, credStr, holderDID)
				if err != nil {
					continue
				}
				if trust > maxTrust {
					maxTrust = trust
				}
			}
		}
		return maxTrust, nil
	default:
		return TrustNone, fmt.Errorf("unsupported credential format")
	}
}

// verifySingleCredential verifies a single JWT credential
func (a *Agent) verifySingleCredential(ctx context.Context, credentialJWT, holderDID string) (TrustLevel, error) {
	// Parse the credential JWT
	credential, token, err := vc.CredentialFromJWT(credentialJWT)
	if err != nil {
		return TrustNone, fmt.Errorf("failed to parse credential JWT: %w", err)
	}

	// Verify basic credential structure
	if err := credential.Validate(); err != nil {
		return TrustNone, fmt.Errorf("credential validation failed: %w", err)
	}

	// Verify time claims
	if err := token.ValidateTime(); err != nil {
		return TrustNone, fmt.Errorf("credential time validation failed: %w", err)
	}

	// Get issuer DID
	issuerDID := credential.GetIssuerID()
	if issuerDID == "" {
		return TrustNone, fmt.Errorf("credential missing issuer")
	}

	// Resolve issuer's DID document to get verification key
	issuerKeyPair, err := a.resolveIssuerKey(ctx, token.Header.KeyID, issuerDID)
	if err != nil {
		return TrustNone, fmt.Errorf("failed to resolve issuer key: %w", err)
	}

	// Verify JWT signature
	if err := token.Verify(issuerKeyPair); err != nil {
		return TrustNone, fmt.Errorf("credential signature verification failed: %w", err)
	}

	// Determine trust level based on credential type and content
	return a.assessCredentialTrust(credential, holderDID)
}

// resolveIssuerKey resolves the issuer's verification key
func (a *Agent) resolveIssuerKey(ctx context.Context, keyID, issuerDID string) (*keys.KeyPair, error) {
	if keyID != "" {
		// Use specific key ID if provided
		return a.Resolver.GetPublicKey(ctx, keyID)
	}

	// Fall back to resolving the issuer DID and using the first authentication key
	parsedDID, err := did.Parse(issuerDID)
	if err != nil {
		return nil, fmt.Errorf("invalid issuer DID: %w", err)
	}

	document, err := a.Resolver.Resolve(ctx, parsedDID)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve issuer DID: %w", err)
	}

	// Find an authentication method
	if len(document.Authentication) == 0 {
		return nil, fmt.Errorf("issuer has no authentication methods")
	}

	// Get the first authentication method
	var authMethodID string
	switch auth := document.Authentication[0].(type) {
	case string:
		authMethodID = auth
	case map[string]interface{}:
		if id, ok := auth["id"].(string); ok {
			authMethodID = id
		} else {
			return nil, fmt.Errorf("invalid authentication method format")
		}
	default:
		return nil, fmt.Errorf("unsupported authentication method type")
	}

	// Get the verification method
	vm, err := document.GetVerificationMethod(authMethodID)
	if err != nil {
		return nil, fmt.Errorf("authentication method not found: %w", err)
	}

	// Extract public key
	if vm.PublicKeyMultibase != "" {
		return keys.DecodePublicKeyMulticodec(vm.PublicKeyMultibase)
	}

	return nil, fmt.Errorf("verification method does not contain supported key format")
}

// assessCredentialTrust determines the trust level based on credential content
func (a *Agent) assessCredentialTrust(credential *vc.Credential, holderDID string) (TrustLevel, error) {
	// Check credential types for specific trust levels
	hasControllerCredential := false
	hasPaymentCredential := false
	
	for _, credType := range credential.Type {
		switch credType {
		case "ControllerCredential":
			hasControllerCredential = true
		case "PaymentReceiptCredential":
			hasPaymentCredential = true
		}
	}

	// Verify credential subject matches holder
	if err := a.verifyCredentialSubject(credential, holderDID); err != nil {
		return TrustNone, fmt.Errorf("credential subject verification failed: %w", err)
	}

	// Determine trust level
	if hasControllerCredential {
		// Verify controller relationship
		if a.verifyControllerRelationship(credential, holderDID) {
			return TrustController, nil
		}
		return TrustCredential, nil
	}

	if hasPaymentCredential {
		return TrustCredential, nil
	}

	// Basic verifiable credential
	return TrustCredential, nil
}

// verifyCredentialSubject verifies the credential subject matches the holder
func (a *Agent) verifyCredentialSubject(credential *vc.Credential, holderDID string) error {
	switch subject := credential.CredentialSubject.(type) {
	case string:
		if subject != holderDID {
			return fmt.Errorf("credential subject mismatch: expected %s, got %s", holderDID, subject)
		}
	case map[string]interface{}:
		if id, ok := subject["id"].(string); ok {
			if id != holderDID {
				return fmt.Errorf("credential subject ID mismatch: expected %s, got %s", holderDID, id)
			}
		} else {
			return fmt.Errorf("credential subject missing ID field")
		}
	default:
		return fmt.Errorf("unsupported credential subject format")
	}
	return nil
}

// verifyControllerRelationship verifies a controller credential establishes proper control
func (a *Agent) verifyControllerRelationship(credential *vc.Credential, holderDID string) bool {
	// Check if the credential establishes a controller relationship
	subject, ok := credential.CredentialSubject.(map[string]interface{})
	if !ok {
		return false
	}

	// Look for controller field in subject
	if controller, exists := subject["controller"]; exists {
		if controllerStr, ok := controller.(string); ok {
			// Verify the controller relationship makes sense
			return a.isValidControllerRelationship(controllerStr, holderDID)
		}
	}

	return false
}

// isValidControllerRelationship checks if a controller relationship is valid
func (a *Agent) isValidControllerRelationship(controllerDID, agentDID string) bool {
	// Basic validation - in a full implementation, this could involve:
	// 1. Checking if the controller DID is in a trusted list
	// 2. Verifying the controller's own credentials
	// 3. Checking delegation chains
	// 4. Validating against organizational policies
	
	// For now, accept any controller relationship that is properly formed
	return controllerDID != "" && agentDID != "" && controllerDID != agentDID
}

// retrieveRequiredCredentials retrieves the required credentials for a challenge
func (a *Agent) retrieveRequiredCredentials(ctx context.Context, requiredVCs []string) ([]string, error) {
	var credentials []string
	
	for _, requiredType := range requiredVCs {
		switch requiredType {
		case "ControllerCredential":
			if a.ControllerDID != nil && a.ControllerKeyPair != nil {
				// Generate a controller credential if we have controller info
				cred, err := a.generateControllerCredential(ctx)
				if err != nil {
					return nil, fmt.Errorf("failed to generate controller credential: %w", err)
				}
				credentials = append(credentials, cred)
			}
		default:
			// For other credential types, we would typically:
			// 1. Check local credential store
			// 2. Contact credential issuer if configured
			// 3. Present stored credentials
			// For now, skip unknown credential types
			continue
		}
	}
	
	return credentials, nil
}

// generateControllerCredential generates a controller credential if agent has controller info
func (a *Agent) generateControllerCredential(ctx context.Context) (string, error) {
	if a.ControllerDID == nil || a.ControllerKeyPair == nil {
		return "", fmt.Errorf("no controller information available")
	}

	// Create controller credential
	credential := vc.NewCredential()
	credential.AddType("ControllerCredential")
	credential.SetIssuer(a.ControllerDID.String())
	
	// Set subject as this agent with controller information
	credential.CredentialSubject = map[string]interface{}{
		"id":         a.DID.String(),
		"controller": a.ControllerDID.String(),
		"type":       "Agent",
		"name":       a.Name,
	}

	// Convert to JWT and sign with controller's key
	keyID := a.ControllerDID.String() + "#key-1"
	credentialJWT, err := credential.ToJWT(a.ControllerKeyPair, keyID)
	if err != nil {
		return "", fmt.Errorf("failed to create controller credential JWT: %w", err)
	}

	return credentialJWT, nil
}

// getVerificationMethodType returns the appropriate verification method type for a curve
func getVerificationMethodType(curve keys.CurveType) string {
	switch curve {
	case keys.CurveEd25519:
		return "Ed25519VerificationKey2020"
	case keys.CurveSecp256k1:
		return "EcdsaSecp256k1VerificationKey2019"
	case keys.CurveSecp256r1:
		return "EcdsaSecp256r1VerificationKey2019"
	default:
		return "JsonWebKey2020"
	}
}