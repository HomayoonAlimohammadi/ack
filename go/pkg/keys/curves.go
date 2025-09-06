package keys

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"fmt"
)

// CurveType represents supported cryptographic curves
type CurveType string

const (
	CurveEd25519   CurveType = "Ed25519"
	CurveSecp256k1 CurveType = "secp256k1" 
	CurveSecp256r1 CurveType = "secp256r1"
)

// Algorithm returns the JWT algorithm for this curve
func (c CurveType) Algorithm() string {
	switch c {
	case CurveEd25519:
		return "EdDSA"
	case CurveSecp256k1:
		return "ES256K"
	case CurveSecp256r1:
		return "ES256"
	default:
		return ""
	}
}

// KeyPrefix returns the multicodec prefix for public keys
func (c CurveType) KeyPrefix() []byte {
	switch c {
	case CurveEd25519:
		return []byte{0xed, 0x01} // ed25519-pub
	case CurveSecp256k1:
		return []byte{0xe7, 0x01} // secp256k1-pub  
	case CurveSecp256r1:
		return []byte{0x80, 0x24} // p256-pub
	default:
		return nil
	}
}

// PrivateKeyPrefix returns the multicodec prefix for private keys
func (c CurveType) PrivateKeyPrefix() []byte {
	switch c {
	case CurveEd25519:
		return []byte{0x80, 0x26} // ed25519-priv
	case CurveSecp256k1:
		return []byte{0x80, 0x27} // secp256k1-priv
	case CurveSecp256r1:
		return []byte{0x80, 0x21} // p256-priv  
	default:
		return nil
	}
}

// KeyPair represents a cryptographic key pair
type KeyPair struct {
	Curve      CurveType
	PrivateKey interface{} // ed25519.PrivateKey or *ecdsa.PrivateKey
	PublicKey  interface{} // ed25519.PublicKey or *ecdsa.PublicKey
}

// Algorithm returns the JWT algorithm for this key pair
func (kp *KeyPair) Algorithm() string {
	return kp.Curve.Algorithm()
}

// PublicKeyBytes returns the raw public key bytes
func (kp *KeyPair) PublicKeyBytes() ([]byte, error) {
	switch kp.Curve {
	case CurveEd25519:
		if pubKey, ok := kp.PublicKey.(ed25519.PublicKey); ok {
			return []byte(pubKey), nil
		}
	case CurveSecp256k1, CurveSecp256r1:
		if pubKey, ok := kp.PublicKey.(*ecdsa.PublicKey); ok {
			return ellipticPublicKeyBytes(pubKey), nil
		}
	}
	return nil, fmt.Errorf("invalid key type for curve %s", kp.Curve)
}

// PrivateKeyBytes returns the raw private key bytes
func (kp *KeyPair) PrivateKeyBytes() ([]byte, error) {
	switch kp.Curve {
	case CurveEd25519:
		if privKey, ok := kp.PrivateKey.(ed25519.PrivateKey); ok {
			return []byte(privKey), nil // Return full private key (64 bytes)
		}
	case CurveSecp256k1, CurveSecp256r1:
		if privKey, ok := kp.PrivateKey.(*ecdsa.PrivateKey); ok {
			return privKey.D.Bytes(), nil
		}
	}
	return nil, fmt.Errorf("invalid key type for curve %s", kp.Curve)
}

// ellipticPublicKeyBytes returns uncompressed public key bytes for ECDSA
func ellipticPublicKeyBytes(pubKey *ecdsa.PublicKey) []byte {
	// Uncompressed format: 0x04 || X || Y
	keySize := (pubKey.Curve.Params().BitSize + 7) / 8
	pubKeyBytes := make([]byte, 1+2*keySize)
	pubKeyBytes[0] = 0x04
	
	xBytes := pubKey.X.Bytes()
	yBytes := pubKey.Y.Bytes()
	
	// Pad with zeros if necessary
	copy(pubKeyBytes[1+keySize-len(xBytes):1+keySize], xBytes)
	copy(pubKeyBytes[1+2*keySize-len(yBytes):], yBytes)
	
	return pubKeyBytes
}