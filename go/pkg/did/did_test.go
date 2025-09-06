package did

import (
	"testing"
)

func TestParseDID(t *testing.T) {
	tests := []struct {
		input    string
		expected *DID
		hasError bool
	}{
		{
			input: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
			expected: &DID{
				Method:         "key",
				MethodSpecific: "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
				Fragment:       "",
				Params:         map[string]string{},
			},
			hasError: false,
		},
		{
			input: "did:web:example.com",
			expected: &DID{
				Method:         "web",
				MethodSpecific: "example.com",
				Fragment:       "",
				Params:         map[string]string{},
			},
			hasError: false,
		},
		{
			input: "did:web:example.com:path:to:resource",
			expected: &DID{
				Method:         "web",
				MethodSpecific: "example.com:path:to:resource",
				Fragment:       "",
				Params:         map[string]string{},
			},
			hasError: false,
		},
		{
			input: "did:example:123456789abcdefghi#keys-1",
			expected: &DID{
				Method:         "example",
				MethodSpecific: "123456789abcdefghi",
				Fragment:       "keys-1",
				Params:         map[string]string{},
			},
			hasError: false,
		},
		{
			input: "did:example:123456;service=agent;version=1.0#keys-1",
			expected: &DID{
				Method:         "example",
				MethodSpecific: "123456",
				Fragment:       "keys-1",
				Params: map[string]string{
					"service": "agent",
					"version": "1.0",
				},
			},
			hasError: false,
		},
		{
			input:    "not-a-did",
			hasError: true,
		},
		{
			input:    "did:invalid-method-123:something",
			hasError: true,
		},
		{
			input:    "did:method",
			hasError: true,
		},
	}

	for _, test := range tests {
		result, err := Parse(test.input)
		
		if test.hasError {
			if err == nil {
				t.Errorf("Expected error for input %s, but got none", test.input)
			}
			continue
		}

		if err != nil {
			t.Errorf("Unexpected error for input %s: %v", test.input, err)
			continue
		}

		if result.Method != test.expected.Method {
			t.Errorf("Method mismatch for %s: expected %s, got %s", 
				test.input, test.expected.Method, result.Method)
		}

		if result.MethodSpecific != test.expected.MethodSpecific {
			t.Errorf("MethodSpecific mismatch for %s: expected %s, got %s", 
				test.input, test.expected.MethodSpecific, result.MethodSpecific)
		}

		if result.Fragment != test.expected.Fragment {
			t.Errorf("Fragment mismatch for %s: expected %s, got %s", 
				test.input, test.expected.Fragment, result.Fragment)
		}

		if len(result.Params) != len(test.expected.Params) {
			t.Errorf("Params length mismatch for %s: expected %d, got %d", 
				test.input, len(test.expected.Params), len(result.Params))
		}

		for k, v := range test.expected.Params {
			if result.Params[k] != v {
				t.Errorf("Param %s mismatch for %s: expected %s, got %s", 
					k, test.input, v, result.Params[k])
			}
		}
	}
}

func TestDIDString(t *testing.T) {
	did := &DID{
		Method:         "example",
		MethodSpecific: "123456",
		Fragment:       "keys-1",
		Params: map[string]string{
			"service": "agent",
			"version": "1.0",
		},
	}

	result := did.String()
	
	// Should contain all components
	if !contains(result, "did:example:123456") {
		t.Error("Result should contain basic DID structure")
	}
	if !contains(result, "#keys-1") {
		t.Error("Result should contain fragment")
	}
	if !contains(result, "service=agent") {
		t.Error("Result should contain service parameter")
	}
	if !contains(result, "version=1.0") {
		t.Error("Result should contain version parameter")
	}
}

func TestCreateKeyDID(t *testing.T) {
	multicodecKey := "u5wEET7jbSPSRP0mHiUrA-7dtTBn6QLKzs6q7WTGL4Ip2h4o5Tai3UISAA2t6V7EoNZAf8Zf7l_ta5jvHm_YA77vaAw"
	
	did, err := CreateKey(multicodecKey)
	if err != nil {
		t.Fatalf("Failed to create did:key: %v", err)
	}

	if did.Method != "key" {
		t.Errorf("Expected method 'key', got %s", did.Method)
	}

	if did.MethodSpecific != multicodecKey {
		t.Errorf("Expected method-specific %s, got %s", multicodecKey, did.MethodSpecific)
	}

	expectedString := "did:key:" + multicodecKey
	if did.String() != expectedString {
		t.Errorf("Expected string %s, got %s", expectedString, did.String())
	}
}

func TestCreateWebDID(t *testing.T) {
	// Test simple domain
	did1, err := CreateWeb("example.com")
	if err != nil {
		t.Fatalf("Failed to create did:web: %v", err)
	}

	expected1 := "did:web:example.com"
	if did1.String() != expected1 {
		t.Errorf("Expected %s, got %s", expected1, did1.String())
	}

	// Test domain with path
	did2, err := CreateWeb("example.com", "path", "to", "resource")
	if err != nil {
		t.Fatalf("Failed to create did:web with path: %v", err)
	}

	expected2 := "did:web:example.com:path:to:resource"
	if did2.String() != expected2 {
		t.Errorf("Expected %s, got %s", expected2, did2.String())
	}

	// Test domain extraction
	domain, err := did2.GetWebDomain()
	if err != nil {
		t.Fatalf("Failed to get web domain: %v", err)
	}
	if domain != "example.com" {
		t.Errorf("Expected domain 'example.com', got %s", domain)
	}

	// Test path extraction
	path, err := did2.GetWebPath()
	if err != nil {
		t.Fatalf("Failed to get web path: %v", err)
	}
	expectedPath := []string{"path", "to", "resource"}
	if len(path) != len(expectedPath) {
		t.Errorf("Path length mismatch: expected %d, got %d", len(expectedPath), len(path))
	}
	for i, p := range expectedPath {
		if path[i] != p {
			t.Errorf("Path component %d mismatch: expected %s, got %s", i, p, path[i])
		}
	}
}

func TestDIDHelpers(t *testing.T) {
	keyDID, _ := Parse("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")
	webDID, _ := Parse("did:web:example.com")

	if !keyDID.IsKey() {
		t.Error("did:key should return true for IsKey()")
	}
	if keyDID.IsWeb() {
		t.Error("did:key should return false for IsWeb()")
	}

	if !webDID.IsWeb() {
		t.Error("did:web should return true for IsWeb()")
	}
	if webDID.IsKey() {
		t.Error("did:web should return false for IsKey()")
	}
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && 
		   (s == substr || 
		    s[:len(substr)] == substr || 
		    s[len(s)-len(substr):] == substr || 
		    findSubstring(s, substr))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}