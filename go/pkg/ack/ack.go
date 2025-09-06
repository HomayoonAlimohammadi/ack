// Package ack provides the main Agent Commerce Kit (ACK) SDK for Go.
// This package re-exports all the core ACK functionality for easy access.
package ack

import (
	"github.com/agentcommercekit/ack/go/pkg/ackid"
	"github.com/agentcommercekit/ack/go/pkg/ackpay"
	"github.com/agentcommercekit/ack/go/pkg/did"
	"github.com/agentcommercekit/ack/go/pkg/jwt"
	"github.com/agentcommercekit/ack/go/pkg/keys"
	"github.com/agentcommercekit/ack/go/pkg/vc"
)

// Re-export key types from sub-packages for convenience

// Keys
type (
	CurveType = keys.CurveType
	KeyPair   = keys.KeyPair
)

// DID
type (
	DID      = did.DID
	Document = did.Document
	Service  = did.Service
)

// JWT
type (
	Header      = jwt.Header
	Claims      = jwt.Claims
	Token       = jwt.Token
	NumericDate = jwt.NumericDate
)

// Verifiable Credentials
type (
	Credential   = vc.Credential
	Presentation = vc.Presentation
	Proof        = vc.Proof
)

// ACK-ID
type (
	Agent              = ackid.Agent
	IdentityChallenge  = ackid.IdentityChallenge
	IdentityResponse   = ackid.IdentityResponse
	VerificationResult = ackid.VerificationResult
)

// ACK-Pay
type (
	PaymentRequest     = ackpay.PaymentRequest
	PaymentMethod      = ackpay.PaymentMethod
	PaymentMethodType  = ackpay.PaymentMethodType
	PaymentReceipt     = ackpay.PaymentReceipt
	PaymentResponse    = ackpay.PaymentResponse
	PaymentService     = ackpay.PaymentService
)

// Constants
const (
	// Curves
	CurveEd25519   = keys.CurveEd25519
	CurveSecp256k1 = keys.CurveSecp256k1
	CurveSecp256r1 = keys.CurveSecp256r1
	
	// Payment Methods
	PaymentMethodCrypto      = ackpay.PaymentMethodCrypto
	PaymentMethodCreditCard  = ackpay.PaymentMethodCreditCard
	PaymentMethodBankTransfer = ackpay.PaymentMethodBankTransfer
	PaymentMethodPayPal      = ackpay.PaymentMethodPayPal
	PaymentMethodStripe      = ackpay.PaymentMethodStripe
	PaymentMethodWire        = ackpay.PaymentMethodWire
)

// Key generation functions
var (
	GenerateKeyPair         = keys.Generate
	KeyPairFromPrivateBytes = keys.FromPrivateKeyBytes
)

// DID functions
var (
	ParseDID      = did.Parse
	CreateKeyDID  = did.CreateKey
	CreateWebDID  = did.CreateWeb
	NewDocument   = did.NewDocument
	DocumentFromJSON = did.FromJSON
)

// JWT functions
var (
	SignJWT        = jwt.Sign
	ParseJWT       = jwt.Parse
	NewNumericDate = jwt.NewNumericDate
)

// VC functions
var (
	NewCredential         = vc.NewCredential
	NewPresentation       = vc.NewPresentation
	CredentialFromJSON    = vc.CredentialFromJSON
	PresentationFromJSON  = vc.PresentationFromJSON
	CredentialFromJWT     = vc.CredentialFromJWT
	VerifyCredentialJWT   = vc.VerifyJWT
)

// ACK-ID functions
var (
	NewAgent              = ackid.NewAgent
	NewWebAgent           = ackid.NewWebAgent
)

// ACK-Pay functions
var (
	NewPaymentService     = ackpay.NewPaymentService
)

// Version information
const (
	Version = "1.0.0"
	Name    = "Agent Commerce Kit - Go"
)