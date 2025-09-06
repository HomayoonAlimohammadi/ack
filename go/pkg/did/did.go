package did

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// DID represents a Decentralized Identifier
type DID struct {
	Method         string
	MethodSpecific string
	Fragment       string
	Params         map[string]string
}

// String returns the DID as a string representation
func (d *DID) String() string {
	result := fmt.Sprintf("did:%s:%s", d.Method, d.MethodSpecific)
	
	// Add parameters
	if len(d.Params) > 0 {
		params := make([]string, 0, len(d.Params))
		for k, v := range d.Params {
			params = append(params, fmt.Sprintf("%s=%s", k, v))
		}
		result += ";" + strings.Join(params, ";")
	}
	
	// Add fragment
	if d.Fragment != "" {
		result += "#" + d.Fragment
	}
	
	return result
}

// URL returns the DID as a URL for web resolution
func (d *DID) URL() string {
	return d.String()
}

// Parse parses a DID string into a DID struct
func Parse(didString string) (*DID, error) {
	// Basic DID format validation
	if !strings.HasPrefix(didString, "did:") {
		return nil, fmt.Errorf("DID must start with 'did:'")
	}
	
	// Remove did: prefix
	remainder := didString[4:]
	
	// Split by '#' to separate fragment
	parts := strings.SplitN(remainder, "#", 2)
	didPart := parts[0]
	var fragment string
	if len(parts) > 1 {
		fragment = parts[1]
	}
	
	// Split by ';' to separate parameters
	paramParts := strings.Split(didPart, ";")
	mainPart := paramParts[0]
	
	// Parse parameters
	params := make(map[string]string)
	for _, param := range paramParts[1:] {
		if param == "" {
			continue
		}
		kv := strings.SplitN(param, "=", 2)
		if len(kv) != 2 {
			return nil, fmt.Errorf("invalid parameter format: %s", param)
		}
		params[kv[0]] = kv[1]
	}
	
	// Split main part by ':' to get method and method-specific
	methodParts := strings.SplitN(mainPart, ":", 2)
	if len(methodParts) != 2 {
		return nil, fmt.Errorf("invalid DID format: missing method or method-specific identifier")
	}
	
	method := methodParts[0]
	methodSpecific := methodParts[1]
	
	// Validate method
	if !isValidMethod(method) {
		return nil, fmt.Errorf("invalid DID method: %s", method)
	}
	
	return &DID{
		Method:         method,
		MethodSpecific: methodSpecific,
		Fragment:       fragment,
		Params:         params,
	}, nil
}

// CreateKey creates a did:key DID from a multicodec encoded public key
func CreateKey(multicodecKey string) (*DID, error) {
	if !strings.HasPrefix(multicodecKey, "u") && !strings.HasPrefix(multicodecKey, "z") {
		return nil, fmt.Errorf("multicodec key must start with 'u' or 'z'")
	}
	
	return &DID{
		Method:         "key",
		MethodSpecific: multicodecKey,
		Fragment:       "",
		Params:         make(map[string]string),
	}, nil
}

// CreateWeb creates a did:web DID from a domain and optional path
func CreateWeb(domain string, path ...string) (*DID, error) {
	if domain == "" {
		return nil, fmt.Errorf("domain cannot be empty")
	}
	
	// Validate domain format
	if !isValidDomain(domain) {
		return nil, fmt.Errorf("invalid domain format: %s", domain)
	}
	
	methodSpecific := domain
	if len(path) > 0 && path[0] != "" {
		// URL encode the path components
		encodedPath := make([]string, len(path))
		for i, p := range path {
			encodedPath[i] = url.PathEscape(p)
		}
		methodSpecific += ":" + strings.Join(encodedPath, ":")
	}
	
	return &DID{
		Method:         "web",
		MethodSpecific: methodSpecific,
		Fragment:       "",
		Params:         make(map[string]string),
	}, nil
}

// IsKey returns true if this is a did:key DID
func (d *DID) IsKey() bool {
	return d.Method == "key"
}

// IsWeb returns true if this is a did:web DID
func (d *DID) IsWeb() bool {
	return d.Method == "web"
}

// GetWebDomain extracts the domain from a did:web DID
func (d *DID) GetWebDomain() (string, error) {
	if !d.IsWeb() {
		return "", fmt.Errorf("not a did:web DID")
	}
	
	parts := strings.Split(d.MethodSpecific, ":")
	return parts[0], nil
}

// GetWebPath extracts the path components from a did:web DID
func (d *DID) GetWebPath() ([]string, error) {
	if !d.IsWeb() {
		return nil, fmt.Errorf("not a did:web DID")
	}
	
	parts := strings.Split(d.MethodSpecific, ":")
	if len(parts) <= 1 {
		return nil, nil // No path
	}
	
	// URL decode path components
	path := make([]string, len(parts)-1)
	for i, p := range parts[1:] {
		decoded, err := url.PathUnescape(p)
		if err != nil {
			return nil, fmt.Errorf("failed to decode path component: %w", err)
		}
		path[i] = decoded
	}
	
	return path, nil
}

// isValidMethod validates DID method name format
func isValidMethod(method string) bool {
	// Method names must match: [a-z0-9]+
	matched, _ := regexp.MatchString(`^[a-z0-9]+$`, method)
	return matched && len(method) > 0
}

// isValidDomain performs basic domain validation
func isValidDomain(domain string) bool {
	// Basic domain validation - allows domains with ports
	// More comprehensive validation could be added
	return len(domain) > 0 && !strings.Contains(domain, "/") && !strings.Contains(domain, "?")
}