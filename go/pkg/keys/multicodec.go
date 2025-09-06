package keys

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/base64"
	"fmt"
	"math/big"

	"github.com/btcsuite/btcd/btcec/v2"
)

// EncodePublicKeyMulticodec encodes a public key with multicodec prefix
func (kp *KeyPair) EncodePublicKeyMulticodec() (string, error) {
	pubKeyBytes, err := kp.PublicKeyBytes()
	if err != nil {
		return "", err
	}

	prefix := kp.Curve.KeyPrefix()
	if prefix == nil {
		return "", fmt.Errorf("no multicodec prefix for curve %s", kp.Curve)
	}

	// Concatenate prefix and key bytes
	encoded := append(prefix, pubKeyBytes...)
	
	// Base64URL encode with leading 'u' for multibase (temporary - should be base58 'z')
	return "u" + base64.RawURLEncoding.EncodeToString(encoded), nil
}

// EncodePrivateKeyMulticodec encodes a private key with multicodec prefix
func (kp *KeyPair) EncodePrivateKeyMulticodec() (string, error) {
	privKeyBytes, err := kp.PrivateKeyBytes()
	if err != nil {
		return "", err
	}

	prefix := kp.Curve.PrivateKeyPrefix()
	if prefix == nil {
		return "", fmt.Errorf("no multicodec prefix for curve %s", kp.Curve)
	}

	// Concatenate prefix and key bytes
	encoded := append(prefix, privKeyBytes...)
	
	// Base64URL encode with leading 'u' for multibase (temporary - should be base58 'z')
	return "u" + base64.RawURLEncoding.EncodeToString(encoded), nil
}

// DecodePublicKeyMulticodec decodes a multicodec encoded public key
func DecodePublicKeyMulticodec(encoded string) (*KeyPair, error) {
	if len(encoded) == 0 || encoded[0] != 'u' {
		return nil, fmt.Errorf("invalid multibase encoding, must start with 'u'")
	}

	// Remove multibase prefix and decode base64url
	decoded, err := base64.RawURLEncoding.DecodeString(encoded[1:])
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64url: %w", err)
	}

	if len(decoded) < 2 {
		return nil, fmt.Errorf("decoded data too short")
	}

	// Identify curve from prefix
	curve, prefixLen, err := identifyCurveFromPublicPrefix(decoded[:2])
	if err != nil {
		return nil, err
	}

	// Extract key bytes (skip prefix)
	keyBytes := decoded[prefixLen:]
	
	// Reconstruct key pair from public key bytes
	return fromPublicKeyBytes(curve, keyBytes)
}

// DecodePrivateKeyMulticodec decodes a multicodec encoded private key
func DecodePrivateKeyMulticodec(encoded string) (*KeyPair, error) {
	if len(encoded) == 0 || encoded[0] != 'u' {
		return nil, fmt.Errorf("invalid multibase encoding, must start with 'u'")
	}

	// Remove multibase prefix and decode base64url
	decoded, err := base64.RawURLEncoding.DecodeString(encoded[1:])
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64url: %w", err)
	}

	if len(decoded) < 2 {
		return nil, fmt.Errorf("decoded data too short")
	}

	// Identify curve from prefix
	curve, prefixLen, err := identifyCurveFromPrivatePrefix(decoded[:2])
	if err != nil {
		return nil, err
	}

	// Extract key bytes (skip prefix)
	keyBytes := decoded[prefixLen:]
	
	// Reconstruct key pair from private key bytes
	return FromPrivateKeyBytes(curve, keyBytes)
}

// identifyCurveFromPublicPrefix identifies curve type from public key prefix
func identifyCurveFromPublicPrefix(prefix []byte) (CurveType, int, error) {
	switch {
	case len(prefix) >= 2 && prefix[0] == 0xed && prefix[1] == 0x01:
		return CurveEd25519, 2, nil
	case len(prefix) >= 2 && prefix[0] == 0xe7 && prefix[1] == 0x01:
		return CurveSecp256k1, 2, nil
	case len(prefix) >= 2 && prefix[0] == 0x80 && prefix[1] == 0x24:
		return CurveSecp256r1, 2, nil
	default:
		return "", 0, fmt.Errorf("unknown public key multicodec prefix: %x", prefix)
	}
}

// identifyCurveFromPrivatePrefix identifies curve type from private key prefix
func identifyCurveFromPrivatePrefix(prefix []byte) (CurveType, int, error) {
	switch {
	case len(prefix) >= 2 && prefix[0] == 0x80 && prefix[1] == 0x26:
		return CurveEd25519, 2, nil
	case len(prefix) >= 2 && prefix[0] == 0x80 && prefix[1] == 0x27:
		return CurveSecp256k1, 2, nil
	case len(prefix) >= 2 && prefix[0] == 0x80 && prefix[1] == 0x21:
		return CurveSecp256r1, 2, nil
	default:
		return "", 0, fmt.Errorf("unknown private key multicodec prefix: %x", prefix)
	}
}

// fromPublicKeyBytes reconstructs key pair from public key bytes
func fromPublicKeyBytes(curve CurveType, pubKeyBytes []byte) (*KeyPair, error) {
	switch curve {
	case CurveEd25519:
		if len(pubKeyBytes) != 32 {
			return nil, fmt.Errorf("Ed25519 public key must be 32 bytes, got %d", len(pubKeyBytes))
		}
		pubKey := make(ed25519.PublicKey, 32)
		copy(pubKey, pubKeyBytes)
		
		return &KeyPair{
			Curve:     CurveEd25519,
			PublicKey: pubKey,
			// Private key is nil - this is a public key only pair
		}, nil
		
	case CurveSecp256k1, CurveSecp256r1:
		return ReconstructECDSAPublicKey(curve, pubKeyBytes)
		
	default:
		return nil, fmt.Errorf("unsupported curve: %s", curve)
	}
}

// ReconstructECDSAPublicKey reconstructs an ECDSA public key from bytes
func ReconstructECDSAPublicKey(curve CurveType, pubKeyBytes []byte) (*KeyPair, error) {
	// For ECDSA curves, we expect uncompressed format (0x04 + X + Y)
	if len(pubKeyBytes) == 0 {
		return nil, fmt.Errorf("empty public key bytes")
	}

	var ecdsaCurve elliptic.Curve
	var expectedSize int
	
	switch curve {
	case CurveSecp256k1:
		ecdsaCurve = btcec.S256()
		expectedSize = 65 // 1 byte prefix + 32 bytes X + 32 bytes Y
	case CurveSecp256r1:
		ecdsaCurve = elliptic.P256()
		expectedSize = 65 // 1 byte prefix + 32 bytes X + 32 bytes Y
	default:
		return nil, fmt.Errorf("unsupported ECDSA curve: %s", curve)
	}

	// Handle both compressed and uncompressed formats
	if len(pubKeyBytes) == expectedSize {
		// Uncompressed format: 0x04 + X + Y
		if pubKeyBytes[0] != 0x04 {
			return nil, fmt.Errorf("invalid uncompressed public key prefix, expected 0x04, got 0x%02x", pubKeyBytes[0])
		}
		return parseUncompressedECDSAKey(curve, ecdsaCurve, pubKeyBytes)
	} else if len(pubKeyBytes) == expectedSize-32 {
		// Compressed format: 0x02/0x03 + X
		if pubKeyBytes[0] != 0x02 && pubKeyBytes[0] != 0x03 {
			return nil, fmt.Errorf("invalid compressed public key prefix, expected 0x02 or 0x03, got 0x%02x", pubKeyBytes[0])
		}
		return parseCompressedECDSAKey(curve, ecdsaCurve, pubKeyBytes)
	} else {
		return nil, fmt.Errorf("invalid ECDSA public key length: expected %d or %d bytes, got %d", expectedSize, expectedSize-32, len(pubKeyBytes))
	}
}

// parseUncompressedECDSAKey parses uncompressed ECDSA public key (0x04 + X + Y)
func parseUncompressedECDSAKey(curve CurveType, ecdsaCurve elliptic.Curve, pubKeyBytes []byte) (*KeyPair, error) {
	keySize := (len(pubKeyBytes) - 1) / 2
	
	// Extract X and Y coordinates
	xBytes := pubKeyBytes[1:1+keySize]
	yBytes := pubKeyBytes[1+keySize:]
	
	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)
	
	// Verify the point is on the curve
	if !ecdsaCurve.IsOnCurve(x, y) {
		return nil, fmt.Errorf("public key point is not on the curve")
	}
	
	pubKey := &ecdsa.PublicKey{
		Curve: ecdsaCurve,
		X:     x,
		Y:     y,
	}
	
	return &KeyPair{
		Curve:     curve,
		PublicKey: pubKey,
		// Private key is nil - this is a public key only pair
	}, nil
}

// parseCompressedECDSAKey parses compressed ECDSA public key (0x02/0x03 + X)
func parseCompressedECDSAKey(curve CurveType, ecdsaCurve elliptic.Curve, pubKeyBytes []byte) (*KeyPair, error) {
	isEven := pubKeyBytes[0] == 0x02
	x := new(big.Int).SetBytes(pubKeyBytes[1:])
	
	// Calculate Y coordinate from X using the curve equation
	// For secp curves: y² = x³ + ax + b, where a=0 and b=7 for secp256k1, a=-3 and b varies for secp256r1
	xCubed := new(big.Int).Mul(x, x)
	xCubed.Mul(xCubed, x)
	
	var ySquared *big.Int
	switch curve {
	case CurveSecp256k1:
		// secp256k1: y² = x³ + 7
		ySquared = new(big.Int).Add(xCubed, big.NewInt(7))
	case CurveSecp256r1:
		// secp256r1 (P-256): y² = x³ - 3x + b
		params := ecdsaCurve.Params()
		ax := new(big.Int).Mul(x, big.NewInt(-3))
		ySquared = new(big.Int).Add(xCubed, ax)
		ySquared.Add(ySquared, params.B)
	default:
		return nil, fmt.Errorf("unsupported curve for compressed key: %s", curve)
	}
	
	// Calculate square root modulo p
	y := new(big.Int).ModSqrt(ySquared, ecdsaCurve.Params().P)
	if y == nil {
		return nil, fmt.Errorf("invalid compressed public key: no square root exists")
	}
	
	// Choose the correct Y coordinate based on parity
	if y.Bit(0) != 0 && isEven {
		// Y is odd but we want even
		y.Sub(ecdsaCurve.Params().P, y)
	} else if y.Bit(0) == 0 && !isEven {
		// Y is even but we want odd
		y.Sub(ecdsaCurve.Params().P, y)
	}
	
	// Verify the point is on the curve
	if !ecdsaCurve.IsOnCurve(x, y) {
		return nil, fmt.Errorf("reconstructed public key point is not on the curve")
	}
	
	pubKey := &ecdsa.PublicKey{
		Curve: ecdsaCurve,
		X:     x,
		Y:     y,
	}
	
	return &KeyPair{
		Curve:     curve,
		PublicKey: pubKey,
		// Private key is nil - this is a public key only pair
	}, nil
}