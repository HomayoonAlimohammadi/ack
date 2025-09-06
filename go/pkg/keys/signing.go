package keys

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
)

// Sign signs data using the private key
func (kp *KeyPair) Sign(data []byte) ([]byte, error) {
	if kp.PrivateKey == nil {
		return nil, fmt.Errorf("private key is required for signing")
	}

	switch kp.Curve {
	case CurveEd25519:
		return kp.signEd25519(data)
	case CurveSecp256k1:
		return kp.signSecp256k1(data)
	case CurveSecp256r1:
		return kp.signSecp256r1(data)
	default:
		return nil, fmt.Errorf("unsupported curve for signing: %s", kp.Curve)
	}
}

// Verify verifies a signature against data using the public key
func (kp *KeyPair) Verify(data, signature []byte) error {
	if kp.PublicKey == nil {
		return fmt.Errorf("public key is required for verification")
	}

	switch kp.Curve {
	case CurveEd25519:
		return kp.verifyEd25519(data, signature)
	case CurveSecp256k1:
		return kp.verifySecp256k1(data, signature)
	case CurveSecp256r1:
		return kp.verifySecp256r1(data, signature)
	default:
		return fmt.Errorf("unsupported curve for verification: %s", kp.Curve)
	}
}

// signEd25519 signs data using Ed25519
func (kp *KeyPair) signEd25519(data []byte) ([]byte, error) {
	privKey, ok := kp.PrivateKey.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("invalid Ed25519 private key type")
	}

	signature := ed25519.Sign(privKey, data)
	return signature, nil
}

// verifyEd25519 verifies Ed25519 signature
func (kp *KeyPair) verifyEd25519(data, signature []byte) error {
	pubKey, ok := kp.PublicKey.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("invalid Ed25519 public key type")
	}

	if !ed25519.Verify(pubKey, data, signature) {
		return fmt.Errorf("Ed25519 signature verification failed")
	}

	return nil
}

// signSecp256k1 signs data using secp256k1
func (kp *KeyPair) signSecp256k1(data []byte) ([]byte, error) {
	privKey, ok := kp.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("invalid secp256k1 private key type")
	}

	// Hash the data
	hash := sha256.Sum256(data)

	// Sign the hash
	r, s, err := ecdsa.Sign(rand.Reader, privKey, hash[:])
	if err != nil {
		return nil, fmt.Errorf("secp256k1 signing failed: %w", err)
	}

	// Encode signature as concatenated r || s (each 32 bytes)
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])

	return signature, nil
}

// verifySecp256k1 verifies secp256k1 signature
func (kp *KeyPair) verifySecp256k1(data, signature []byte) error {
	pubKey, ok := kp.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("invalid secp256k1 public key type")
	}

	if len(signature) != 64 {
		return fmt.Errorf("secp256k1 signature must be 64 bytes, got %d", len(signature))
	}

	// Hash the data
	hash := sha256.Sum256(data)

	// Decode signature components
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])

	// Verify signature
	if !ecdsa.Verify(pubKey, hash[:], r, s) {
		return fmt.Errorf("secp256k1 signature verification failed")
	}

	return nil
}

// signSecp256r1 signs data using secp256r1 (P-256)
func (kp *KeyPair) signSecp256r1(data []byte) ([]byte, error) {
	privKey, ok := kp.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("invalid secp256r1 private key type")
	}

	// Hash the data
	hash := sha256.Sum256(data)

	// Sign the hash
	r, s, err := ecdsa.Sign(rand.Reader, privKey, hash[:])
	if err != nil {
		return nil, fmt.Errorf("secp256r1 signing failed: %w", err)
	}

	// Encode signature as concatenated r || s (each 32 bytes)
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])

	return signature, nil
}

// verifySecp256r1 verifies secp256r1 signature
func (kp *KeyPair) verifySecp256r1(data, signature []byte) error {
	pubKey, ok := kp.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("invalid secp256r1 public key type")
	}

	if len(signature) != 64 {
		return fmt.Errorf("secp256r1 signature must be 64 bytes, got %d", len(signature))
	}

	// Hash the data
	hash := sha256.Sum256(data)

	// Decode signature components
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])

	// Verify signature
	if !ecdsa.Verify(pubKey, hash[:], r, s) {
		return fmt.Errorf("secp256r1 signature verification failed")
	}

	return nil
}