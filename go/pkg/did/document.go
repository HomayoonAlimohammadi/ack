package did

import (
	"encoding/json"
	"fmt"
	"time"
)

// Document represents a DID Document according to W3C DID specification
type Document struct {
	Context            []string                   `json:"@context"`
	ID                 string                     `json:"id"`
	Controller         []string                   `json:"controller,omitempty"`
	VerificationMethod []VerificationMethod       `json:"verificationMethod,omitempty"`
	Authentication     []interface{}              `json:"authentication,omitempty"`
	AssertionMethod    []interface{}              `json:"assertionMethod,omitempty"`
	KeyAgreement       []interface{}              `json:"keyAgreement,omitempty"`
	Service            []Service                  `json:"service,omitempty"`
	Created            *time.Time                 `json:"created,omitempty"`
	Updated            *time.Time                 `json:"updated,omitempty"`
	Deactivated        bool                       `json:"deactivated,omitempty"`
	VersionID          string                     `json:"versionId,omitempty"`
	NextUpdate         *time.Time                 `json:"nextUpdate,omitempty"`
	NextVersionID      string                     `json:"nextVersionId,omitempty"`
	Proof              []Proof                    `json:"proof,omitempty"`
}

// VerificationMethod represents a verification method in a DID document
type VerificationMethod struct {
	ID                 string `json:"id"`
	Type               string `json:"type"`
	Controller         string `json:"controller"`
	PublicKeyMultibase string `json:"publicKeyMultibase,omitempty"`
	PublicKeyJwk       *JWK   `json:"publicKeyJwk,omitempty"`
}

// JWK represents a JSON Web Key
type JWK struct {
	Kty   string `json:"kty"`
	Crv   string `json:"crv,omitempty"`
	X     string `json:"x,omitempty"`
	Y     string `json:"y,omitempty"`
	D     string `json:"d,omitempty"`
	Use   string `json:"use,omitempty"`
	KeyID string `json:"kid,omitempty"`
	Alg   string `json:"alg,omitempty"`
}

// Service represents a service endpoint in a DID document
type Service struct {
	ID              string      `json:"id"`
	Type            interface{} `json:"type"` // Can be string or array of strings
	ServiceEndpoint interface{} `json:"serviceEndpoint"` // Can be string, object, or array
}

// Proof represents a cryptographic proof for a DID document
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

// NewDocument creates a new DID document with default context
func NewDocument(didID string) *Document {
	return &Document{
		Context: []string{
			"https://www.w3.org/ns/did/v1",
		},
		ID:                 didID,
		VerificationMethod: make([]VerificationMethod, 0),
		Authentication:     make([]interface{}, 0),
		AssertionMethod:    make([]interface{}, 0),
		KeyAgreement:       make([]interface{}, 0),
		Service:            make([]Service, 0),
		Controller:         make([]string, 0),
	}
}

// AddVerificationMethod adds a verification method to the document
func (doc *Document) AddVerificationMethod(vm VerificationMethod) {
	doc.VerificationMethod = append(doc.VerificationMethod, vm)
}

// AddAuthentication adds an authentication method reference
func (doc *Document) AddAuthentication(ref interface{}) {
	doc.Authentication = append(doc.Authentication, ref)
}

// AddAssertionMethod adds an assertion method reference
func (doc *Document) AddAssertionMethod(ref interface{}) {
	doc.AssertionMethod = append(doc.AssertionMethod, ref)
}

// AddKeyAgreement adds a key agreement method reference
func (doc *Document) AddKeyAgreement(ref interface{}) {
	doc.KeyAgreement = append(doc.KeyAgreement, ref)
}

// AddService adds a service endpoint to the document
func (doc *Document) AddService(service Service) {
	doc.Service = append(doc.Service, service)
}

// AddController adds a controller DID to the document
func (doc *Document) AddController(controller string) {
	doc.Controller = append(doc.Controller, controller)
}

// GetVerificationMethod retrieves a verification method by ID
func (doc *Document) GetVerificationMethod(id string) (*VerificationMethod, error) {
	for _, vm := range doc.VerificationMethod {
		if vm.ID == id {
			return &vm, nil
		}
	}
	return nil, fmt.Errorf("verification method not found: %s", id)
}

// GetService retrieves a service by ID
func (doc *Document) GetService(id string) (*Service, error) {
	for _, service := range doc.Service {
		if service.ID == id {
			return &service, nil
		}
	}
	return nil, fmt.Errorf("service not found: %s", id)
}

// GetServicesByType retrieves services by type
func (doc *Document) GetServicesByType(serviceType string) []Service {
	var services []Service
	
	for _, service := range doc.Service {
		// Handle both string and array type formats
		switch t := service.Type.(type) {
		case string:
			if t == serviceType {
				services = append(services, service)
			}
		case []string:
			for _, st := range t {
				if st == serviceType {
					services = append(services, service)
					break
				}
			}
		case []interface{}:
			for _, st := range t {
				if str, ok := st.(string); ok && str == serviceType {
					services = append(services, service)
					break
				}
			}
		}
	}
	
	return services
}

// ToJSON converts the document to JSON
func (doc *Document) ToJSON() ([]byte, error) {
	return json.MarshalIndent(doc, "", "  ")
}

// FromJSON parses a DID document from JSON
func FromJSON(data []byte) (*Document, error) {
	var doc Document
	err := json.Unmarshal(data, &doc)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DID document: %w", err)
	}
	
	// Validate required fields
	if doc.ID == "" {
		return nil, fmt.Errorf("DID document must have an id field")
	}
	
	if len(doc.Context) == 0 {
		return nil, fmt.Errorf("DID document must have @context field")
	}
	
	return &doc, nil
}

// Validate performs basic validation of the DID document
func (doc *Document) Validate() error {
	if doc.ID == "" {
		return fmt.Errorf("DID document must have an id field")
	}
	
	// Validate that ID is a valid DID
	_, err := Parse(doc.ID)
	if err != nil {
		return fmt.Errorf("invalid DID in id field: %w", err)
	}
	
	if len(doc.Context) == 0 {
		return fmt.Errorf("DID document must have @context field")
	}
	
	// Check that required DID context is present
	hasRequiredContext := false
	for _, ctx := range doc.Context {
		if ctx == "https://www.w3.org/ns/did/v1" {
			hasRequiredContext = true
			break
		}
	}
	if !hasRequiredContext {
		return fmt.Errorf("DID document must include https://www.w3.org/ns/did/v1 in @context")
	}
	
	// Validate verification methods
	for _, vm := range doc.VerificationMethod {
		if vm.ID == "" {
			return fmt.Errorf("verification method must have id")
		}
		if vm.Type == "" {
			return fmt.Errorf("verification method must have type")
		}
		if vm.Controller == "" {
			return fmt.Errorf("verification method must have controller")
		}
	}
	
	// Validate services
	for _, service := range doc.Service {
		if service.ID == "" {
			return fmt.Errorf("service must have id")
		}
		if service.Type == nil {
			return fmt.Errorf("service must have type")
		}
		if service.ServiceEndpoint == nil {
			return fmt.Errorf("service must have serviceEndpoint")
		}
	}
	
	return nil
}