package keys

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/btcsuite/btcd/btcec/v2"
)

// Generate creates a new key pair for the specified curve
func Generate(curve CurveType) (*KeyPair, error) {
	switch curve {
	case CurveEd25519:
		return generateEd25519()
	case CurveSecp256k1:
		return generateSecp256k1()
	case CurveSecp256r1:
		return generateSecp256r1()
	default:
		return nil, fmt.Errorf("unsupported curve: %s", curve)
	}
}

// generateEd25519 creates a new Ed25519 key pair
func generateEd25519() (*KeyPair, error) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Ed25519 key pair: %w", err)
	}

	return &KeyPair{
		Curve:      CurveEd25519,
		PrivateKey: privKey,
		PublicKey:  pubKey,
	}, nil
}

// generateSecp256k1 creates a new secp256k1 key pair
func generateSecp256k1() (*KeyPair, error) {
	privKey, err := btcec.NewPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate secp256k1 key pair: %w", err)
	}

	// Convert to standard ecdsa types
	ecdsaPrivKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: btcec.S256(),
			X:     privKey.PubKey().X(),
			Y:     privKey.PubKey().Y(),
		},
		D: func() *big.Int {
			keyBytes := privKey.Key.Bytes()
			return new(big.Int).SetBytes(keyBytes[:])
		}(),
	}

	return &KeyPair{
		Curve:      CurveSecp256k1,
		PrivateKey: ecdsaPrivKey,
		PublicKey:  &ecdsaPrivKey.PublicKey,
	}, nil
}

// generateSecp256r1 creates a new secp256r1 (P-256) key pair
func generateSecp256r1() (*KeyPair, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate secp256r1 key pair: %w", err)
	}

	return &KeyPair{
		Curve:      CurveSecp256r1,
		PrivateKey: privKey,
		PublicKey:  &privKey.PublicKey,
	}, nil
}

// FromPrivateKeyBytes reconstructs a key pair from private key bytes
func FromPrivateKeyBytes(curve CurveType, privKeyBytes []byte) (*KeyPair, error) {
	switch curve {
	case CurveEd25519:
		return fromEd25519PrivateKey(privKeyBytes)
	case CurveSecp256k1:
		return fromSecp256k1PrivateKey(privKeyBytes)
	case CurveSecp256r1:
		return fromSecp256r1PrivateKey(privKeyBytes)
	default:
		return nil, fmt.Errorf("unsupported curve: %s", curve)
	}
}

// fromEd25519PrivateKey reconstructs Ed25519 key pair from private key bytes
func fromEd25519PrivateKey(privKeyBytes []byte) (*KeyPair, error) {
	if len(privKeyBytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("Ed25519 private key must be %d bytes, got %d", ed25519.PrivateKeySize, len(privKeyBytes))
	}

	// Ed25519 private key is 64 bytes: 32-byte seed + 32-byte public key
	privKey := make(ed25519.PrivateKey, ed25519.PrivateKeySize)
	copy(privKey, privKeyBytes)
	
	// Extract public key from private key (last 32 bytes)
	pubKey := make(ed25519.PublicKey, ed25519.PublicKeySize)
	copy(pubKey, privKey[32:])

	return &KeyPair{
		Curve:      CurveEd25519,
		PrivateKey: privKey,
		PublicKey:  pubKey,
	}, nil
}

// fromSecp256k1PrivateKey reconstructs secp256k1 key pair from private key bytes
func fromSecp256k1PrivateKey(privKeyBytes []byte) (*KeyPair, error) {
	privKey, _ := btcec.PrivKeyFromBytes(privKeyBytes)
	
	// Convert to standard ecdsa types
	ecdsaPrivKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: btcec.S256(),
			X:     privKey.PubKey().X(),
			Y:     privKey.PubKey().Y(),
		},
		D: func() *big.Int {
			keyBytes := privKey.Key.Bytes()
			return new(big.Int).SetBytes(keyBytes[:])
		}(),
	}

	return &KeyPair{
		Curve:      CurveSecp256k1,
		PrivateKey: ecdsaPrivKey,
		PublicKey:  &ecdsaPrivKey.PublicKey,
	}, nil
}

// fromSecp256r1PrivateKey reconstructs secp256r1 key pair from private key bytes
func fromSecp256r1PrivateKey(privKeyBytes []byte) (*KeyPair, error) {
	privKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
		},
		D: nil,
	}
	
	privKey.D = new(big.Int).SetBytes(privKeyBytes)
	privKey.PublicKey.X, privKey.PublicKey.Y = privKey.PublicKey.Curve.ScalarBaseMult(privKeyBytes)

	return &KeyPair{
		Curve:      CurveSecp256r1,
		PrivateKey: privKey,
		PublicKey:  &privKey.PublicKey,
	}, nil
}