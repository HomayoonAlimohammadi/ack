package did

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/agentcommercekit/ack/go/pkg/keys"
)

// Resolver resolves DIDs to their DID Documents
type Resolver struct {
	HTTPClient *http.Client
	Cache      map[string]*CacheEntry
	CacheTTL   time.Duration
}

// CacheEntry represents a cached DID document
type CacheEntry struct {
	Document  *Document
	CachedAt  time.Time
	ExpiresAt time.Time
}

// NewResolver creates a new DID resolver
func NewResolver() *Resolver {
	return &Resolver{
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		Cache:    make(map[string]*CacheEntry),
		CacheTTL: 5 * time.Minute,
	}
}

// Resolve resolves a DID to its DID Document
func (r *Resolver) Resolve(ctx context.Context, did *DID) (*Document, error) {
	// Check cache first
	if entry, exists := r.Cache[did.String()]; exists && time.Now().Before(entry.ExpiresAt) {
		return entry.Document, nil
	}

	var document *Document
	var err error

	switch did.Method {
	case "key":
		document, err = r.resolveKeyDID(ctx, did)
	case "web":
		document, err = r.resolveWebDID(ctx, did)
	default:
		return nil, fmt.Errorf("unsupported DID method: %s", did.Method)
	}

	if err != nil {
		return nil, err
	}

	// Cache the resolved document
	r.Cache[did.String()] = &CacheEntry{
		Document:  document,
		CachedAt:  time.Now(),
		ExpiresAt: time.Now().Add(r.CacheTTL),
	}

	return document, nil
}

// resolveKeyDID resolves a did:key DID by reconstructing the document from the key
func (r *Resolver) resolveKeyDID(ctx context.Context, did *DID) (*Document, error) {
	// For did:key, the method-specific identifier is the multicodec encoded public key
	multicodecKey := did.MethodSpecific

	// Decode the public key
	keyPair, err := keys.DecodePublicKeyMulticodec(multicodecKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key from did:key: %w", err)
	}

	// Create DID document
	document := NewDocument(did.String())

	// Add verification method
	vmID := did.String() + "#" + multicodecKey
	vm := VerificationMethod{
		ID:                 vmID,
		Type:               getVerificationMethodTypeFromCurve(keyPair.Curve),
		Controller:         did.String(),
		PublicKeyMultibase: multicodecKey,
	}

	document.AddVerificationMethod(vm)
	document.AddAuthentication(vmID)
	document.AddAssertionMethod(vmID)
	document.AddKeyAgreement(vmID)

	return document, nil
}

// resolveWebDID resolves a did:web DID by fetching from the web
func (r *Resolver) resolveWebDID(ctx context.Context, did *DID) (*Document, error) {
	// Extract domain and path from did:web
	domain, err := did.GetWebDomain()
	if err != nil {
		return nil, fmt.Errorf("failed to extract domain from did:web: %w", err)
	}

	path, err := did.GetWebPath()
	if err != nil {
		return nil, fmt.Errorf("failed to extract path from did:web: %w", err)
	}

	// Construct the URL for the DID document
	didDocURL := r.constructWebDIDURL(domain, path)

	// Fetch the DID document
	req, err := http.NewRequestWithContext(ctx, "GET", didDocURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	req.Header.Set("Accept", "application/did+json, application/json")

	resp, err := r.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch DID document from %s: %w", didDocURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch DID document: HTTP %d from %s", resp.StatusCode, didDocURL)
	}

	// Read and parse the DID document
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read DID document response: %w", err)
	}

	document, err := FromJSON(body)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DID document JSON: %w", err)
	}

	// Validate that the document ID matches the DID
	if document.ID != did.String() {
		return nil, fmt.Errorf("DID document ID mismatch: expected %s, got %s", did.String(), document.ID)
	}

	return document, nil
}

// constructWebDIDURL constructs the URL for fetching a did:web document
func (r *Resolver) constructWebDIDURL(domain string, path []string) string {
	// Start with HTTPS (did:web always uses HTTPS)
	didDocURL := "https://" + domain

	if len(path) == 0 {
		// No path specified, use /.well-known/did.json
		didDocURL += "/.well-known/did.json"
	} else {
		// Path specified, append it and add /did.json
		for _, segment := range path {
			didDocURL += "/" + url.PathEscape(segment)
		}
		didDocURL += "/did.json"
	}

	return didDocURL
}

// ResolveString resolves a DID string to its DID Document
func (r *Resolver) ResolveString(ctx context.Context, didString string) (*Document, error) {
	did, err := Parse(didString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DID: %w", err)
	}
	return r.Resolve(ctx, did)
}

// GetVerificationMethod retrieves a verification method by ID from a resolved DID
func (r *Resolver) GetVerificationMethod(ctx context.Context, did *DID, vmID string) (*VerificationMethod, error) {
	document, err := r.Resolve(ctx, did)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve DID: %w", err)
	}

	vm, err := document.GetVerificationMethod(vmID)
	if err != nil {
		return nil, fmt.Errorf("verification method not found: %w", err)
	}

	return vm, nil
}

// GetPublicKey retrieves the public key for a verification method
func (r *Resolver) GetPublicKey(ctx context.Context, vmID string) (*keys.KeyPair, error) {
	// Parse the verification method ID to extract DID
	// VM IDs typically follow the format: did:method:identifier#key-id
	parts := strings.Split(vmID, "#")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid verification method ID format: %s", vmID)
	}

	didString := parts[0]
	did, err := Parse(didString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DID from VM ID: %w", err)
	}

	vm, err := r.GetVerificationMethod(ctx, did, vmID)
	if err != nil {
		return nil, err
	}

	// Extract public key from verification method
	if vm.PublicKeyMultibase != "" {
		return keys.DecodePublicKeyMulticodec(vm.PublicKeyMultibase)
	}

	if vm.PublicKeyJwk != nil {
		return r.parseJWKToKeyPair(vm.PublicKeyJwk)
	}

	return nil, fmt.Errorf("verification method does not contain a supported public key format")
}

// parseJWKToKeyPair converts a JWK to a KeyPair
func (r *Resolver) parseJWKToKeyPair(jwk *JWK) (*keys.KeyPair, error) {
	switch jwk.Kty {
	case "OKP":
		if jwk.Crv == "Ed25519" {
			// Parse Ed25519 key from JWK
			return r.parseEd25519JWK(jwk)
		}
		return nil, fmt.Errorf("unsupported OKP curve: %s", jwk.Crv)
	case "EC":
		if jwk.Crv == "secp256k1" {
			return r.parseECDSAJWK(jwk, keys.CurveSecp256k1)
		}
		if jwk.Crv == "P-256" {
			return r.parseECDSAJWK(jwk, keys.CurveSecp256r1)
		}
		return nil, fmt.Errorf("unsupported EC curve: %s", jwk.Crv)
	default:
		return nil, fmt.Errorf("unsupported JWK key type: %s", jwk.Kty)
	}
}

// parseEd25519JWK parses an Ed25519 key from JWK format
func (r *Resolver) parseEd25519JWK(jwk *JWK) (*keys.KeyPair, error) {
	if jwk.X == "" {
		return nil, fmt.Errorf("Ed25519 JWK missing X coordinate")
	}

	// Decode base64url X coordinate
	xBytes, err := decodeBase64URL(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("failed to decode Ed25519 X coordinate: %w", err)
	}

	if len(xBytes) != 32 {
		return nil, fmt.Errorf("invalid Ed25519 public key length: %d", len(xBytes))
	}

	return &keys.KeyPair{
		Curve:     keys.CurveEd25519,
		PublicKey: xBytes,
	}, nil
}

// parseECDSAJWK parses an ECDSA key from JWK format
func (r *Resolver) parseECDSAJWK(jwk *JWK, curve keys.CurveType) (*keys.KeyPair, error) {
	if jwk.X == "" || jwk.Y == "" {
		return nil, fmt.Errorf("ECDSA JWK missing X or Y coordinate")
	}

	// Decode base64url coordinates
	xBytes, err := decodeBase64URL(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ECDSA X coordinate: %w", err)
	}

	yBytes, err := decodeBase64URL(jwk.Y)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ECDSA Y coordinate: %w", err)
	}

	// Create uncompressed public key format (0x04 + X + Y)
	pubKeyBytes := make([]byte, 1+len(xBytes)+len(yBytes))
	pubKeyBytes[0] = 0x04
	copy(pubKeyBytes[1:], xBytes)
	copy(pubKeyBytes[1+len(xBytes):], yBytes)

	// Use existing ECDSA reconstruction
	return keys.ReconstructECDSAPublicKey(curve, pubKeyBytes)
}

// ClearCache clears the DID document cache
func (r *Resolver) ClearCache() {
	r.Cache = make(map[string]*CacheEntry)
}

// getVerificationMethodTypeFromCurve returns the verification method type for a curve
func getVerificationMethodTypeFromCurve(curve keys.CurveType) string {
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

// decodeBase64URL decodes a base64url string
func decodeBase64URL(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}