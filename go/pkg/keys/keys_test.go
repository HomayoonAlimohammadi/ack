package keys

import (
	"testing"
)

func TestGenerateEd25519(t *testing.T) {
	kp, err := Generate(CurveEd25519)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key pair: %v", err)
	}

	if kp.Curve != CurveEd25519 {
		t.Errorf("Expected curve %s, got %s", CurveEd25519, kp.Curve)
	}

	if kp.Algorithm() != "EdDSA" {
		t.Errorf("Expected algorithm EdDSA, got %s", kp.Algorithm())
	}

	// Test signing and verification
	message := []byte("test message")
	signature, err := kp.Sign(message)
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	err = kp.Verify(message, signature)
	if err != nil {
		t.Fatalf("Failed to verify signature: %v", err)
	}

	// Test with wrong message
	wrongMessage := []byte("wrong message")
	err = kp.Verify(wrongMessage, signature)
	if err == nil {
		t.Error("Expected verification to fail with wrong message")
	}
}

func TestGenerateSecp256k1(t *testing.T) {
	kp, err := Generate(CurveSecp256k1)
	if err != nil {
		t.Fatalf("Failed to generate secp256k1 key pair: %v", err)
	}

	if kp.Curve != CurveSecp256k1 {
		t.Errorf("Expected curve %s, got %s", CurveSecp256k1, kp.Curve)
	}

	if kp.Algorithm() != "ES256K" {
		t.Errorf("Expected algorithm ES256K, got %s", kp.Algorithm())
	}

	// Test signing and verification
	message := []byte("test message")
	signature, err := kp.Sign(message)
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	err = kp.Verify(message, signature)
	if err != nil {
		t.Fatalf("Failed to verify signature: %v", err)
	}
}

func TestGenerateSecp256r1(t *testing.T) {
	kp, err := Generate(CurveSecp256r1)
	if err != nil {
		t.Fatalf("Failed to generate secp256r1 key pair: %v", err)
	}

	if kp.Curve != CurveSecp256r1 {
		t.Errorf("Expected curve %s, got %s", CurveSecp256r1, kp.Curve)
	}

	if kp.Algorithm() != "ES256" {
		t.Errorf("Expected algorithm ES256, got %s", kp.Algorithm())
	}

	// Test signing and verification
	message := []byte("test message")
	signature, err := kp.Sign(message)
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	err = kp.Verify(message, signature)
	if err != nil {
		t.Fatalf("Failed to verify signature: %v", err)
	}
}

func TestMulticodecEncoding(t *testing.T) {
	kp, err := Generate(CurveEd25519)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Test public key encoding
	encoded, err := kp.EncodePublicKeyMulticodec()
	if err != nil {
		t.Fatalf("Failed to encode public key: %v", err)
	}

	if len(encoded) == 0 {
		t.Error("Encoded public key should not be empty")
	}

	if encoded[0] != 'u' {
		t.Errorf("Expected multibase prefix 'u', got '%c'", encoded[0])
	}

	// Test private key encoding
	privEncoded, err := kp.EncodePrivateKeyMulticodec()
	if err != nil {
		t.Fatalf("Failed to encode private key: %v", err)
	}

	if len(privEncoded) == 0 {
		t.Error("Encoded private key should not be empty")
	}

	if privEncoded[0] != 'u' {
		t.Errorf("Expected multibase prefix 'u', got '%c'", privEncoded[0])
	}
}

func TestFromPrivateKeyBytes(t *testing.T) {
	// Test Ed25519
	originalKP, err := Generate(CurveEd25519)
	if err != nil {
		t.Fatalf("Failed to generate original key pair: %v", err)
	}

	privKeyBytes, err := originalKP.PrivateKeyBytes()
	if err != nil {
		t.Fatalf("Failed to get private key bytes: %v", err)
	}

	reconstructedKP, err := FromPrivateKeyBytes(CurveEd25519, privKeyBytes)
	if err != nil {
		t.Fatalf("Failed to reconstruct key pair: %v", err)
	}

	// Test that both key pairs can sign/verify the same message
	message := []byte("test message")
	
	signature1, err := originalKP.Sign(message)
	if err != nil {
		t.Fatalf("Failed to sign with original key: %v", err)
	}

	signature2, err := reconstructedKP.Sign(message)
	if err != nil {
		t.Fatalf("Failed to sign with reconstructed key: %v", err)
	}

	// Both should be able to verify each other's signatures
	err = originalKP.Verify(message, signature2)
	if err != nil {
		t.Error("Original key should verify reconstructed key's signature")
	}

	err = reconstructedKP.Verify(message, signature1)
	if err != nil {
		t.Error("Reconstructed key should verify original key's signature")
	}

	// Compare public keys
	origPubBytes, err := originalKP.PublicKeyBytes()
	if err != nil {
		t.Fatalf("Failed to get original public key bytes: %v", err)
	}

	reconPubBytes, err := reconstructedKP.PublicKeyBytes()
	if err != nil {
		t.Fatalf("Failed to get reconstructed public key bytes: %v", err)
	}

	if len(origPubBytes) != len(reconPubBytes) {
		t.Error("Public key bytes length mismatch")
	}

	for i := range origPubBytes {
		if origPubBytes[i] != reconPubBytes[i] {
			t.Error("Public key bytes mismatch")
			break
		}
	}
}