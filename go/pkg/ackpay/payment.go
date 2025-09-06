package ackpay

import (
	"context"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/HomayoonAlimohammadi/ack/go/pkg/did"
	"github.com/HomayoonAlimohammadi/ack/go/pkg/jwt"
	"github.com/HomayoonAlimohammadi/ack/go/pkg/keys"
	"github.com/HomayoonAlimohammadi/ack/go/pkg/vc"
)

// PaymentRequest represents a request for payment (HTTP 402 Payment Required)
type PaymentRequest struct {
	ID              string                 `json:"id"`
	Payee           string                 `json:"payee"`    // DID of payee
	Amount          *big.Int               `json:"amount"`   // Amount in smallest unit
	Currency        string                 `json:"currency"` // Currency code (USD, ETH, USDC, etc.)
	Description     string                 `json:"description"`
	PaymentMethods  []PaymentMethod        `json:"payment_methods"`
	ExpiresAt       *time.Time             `json:"expires_at,omitempty"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
	ReceiptRequired bool                   `json:"receipt_required"`
	ReceiptService  string                 `json:"receipt_service,omitempty"` // URL of receipt service
	Signature       string                 `json:"signature,omitempty"`       // JWT signature of the request
}

// PaymentMethod represents a supported payment method
type PaymentMethod struct {
	Type          PaymentMethodType      `json:"type"`
	Currency      string                 `json:"currency"`
	Network       string                 `json:"network,omitempty"`        // For crypto payments
	Address       string                 `json:"address,omitempty"`        // For crypto payments
	PaymentURL    string                 `json:"payment_url,omitempty"`    // For traditional payments
	ProcessorInfo map[string]interface{} `json:"processor_info,omitempty"` // Payment processor specific data
	MinAmount     *big.Int               `json:"min_amount,omitempty"`
	MaxAmount     *big.Int               `json:"max_amount,omitempty"`
	Fee           *big.Int               `json:"fee,omitempty"`
	EstimatedTime time.Duration          `json:"estimated_time,omitempty"`
}

// PaymentMethodType represents different types of payment methods
type PaymentMethodType string

const (
	PaymentMethodCrypto       PaymentMethodType = "crypto"
	PaymentMethodCreditCard   PaymentMethodType = "credit_card"
	PaymentMethodBankTransfer PaymentMethodType = "bank_transfer"
	PaymentMethodPayPal       PaymentMethodType = "paypal"
	PaymentMethodStripe       PaymentMethodType = "stripe"
	PaymentMethodWire         PaymentMethodType = "wire"
)

// PaymentResponse represents a payment response
type PaymentResponse struct {
	PaymentRequestID string                 `json:"payment_request_id"`
	PaymentMethod    PaymentMethod          `json:"payment_method"`
	TransactionID    string                 `json:"transaction_id"`
	Amount           *big.Int               `json:"amount"`
	Currency         string                 `json:"currency"`
	Status           PaymentStatus          `json:"status"`
	Payer            string                 `json:"payer"` // DID of payer
	Payee            string                 `json:"payee"` // DID of payee
	Timestamp        time.Time              `json:"timestamp"`
	BlockchainTxHash string                 `json:"blockchain_tx_hash,omitempty"`
	ConfirmationURL  string                 `json:"confirmation_url,omitempty"`
	Metadata         map[string]interface{} `json:"metadata,omitempty"`
	Receipt          *PaymentReceipt        `json:"receipt,omitempty"`
}

// PaymentStatus represents the status of a payment
type PaymentStatus string

const (
	PaymentStatusPending   PaymentStatus = "pending"
	PaymentStatusCompleted PaymentStatus = "completed"
	PaymentStatusFailed    PaymentStatus = "failed"
	PaymentStatusCancelled PaymentStatus = "cancelled"
	PaymentStatusRefunded  PaymentStatus = "refunded"
)

// PaymentReceipt represents a verifiable payment receipt
type PaymentReceipt struct {
	ID                string                 `json:"id"`
	PaymentRequestID  string                 `json:"payment_request_id"`
	TransactionID     string                 `json:"transaction_id"`
	Amount            *big.Int               `json:"amount"`
	Currency          string                 `json:"currency"`
	Payer             string                 `json:"payer"` // DID of payer
	Payee             string                 `json:"payee"` // DID of payee
	Timestamp         time.Time              `json:"timestamp"`
	PaymentMethod     PaymentMethod          `json:"payment_method"`
	BlockchainTxHash  string                 `json:"blockchain_tx_hash,omitempty"`
	VerifiableReceipt *vc.Credential         `json:"verifiable_receipt,omitempty"`
	Metadata          map[string]interface{} `json:"metadata,omitempty"`
}

// PaymentService represents a payment processing service
type PaymentService struct {
	DID              *did.DID
	KeyPair          *keys.KeyPair
	Name             string
	SupportedMethods []PaymentMethodType
	ReceiptIssuer    string            // URL of receipt issuer service
	BlockchainClient *BlockchainClient // For crypto payment verification
	StripeKey        string            // Stripe API key
}

// NewPaymentService creates a new payment service
func NewPaymentService(curve keys.CurveType, domain, name string) (*PaymentService, error) {
	// Generate key pair
	keyPair, err := keys.Generate(curve)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	// Create did:web DID
	serviceDID, err := did.CreateWeb(domain, "payment-service")
	if err != nil {
		return nil, fmt.Errorf("failed to create did:web: %w", err)
	}

	return &PaymentService{
		DID:     serviceDID,
		KeyPair: keyPair,
		Name:    name,
		SupportedMethods: []PaymentMethodType{
			PaymentMethodCrypto,
			PaymentMethodStripe,
		},
		BlockchainClient: NewBlockchainClient("ethereum", "https://eth-mainnet.g.alchemy.com/v2/demo"),
	}, nil
}

// CreatePaymentRequest creates a new payment request
func (ps *PaymentService) CreatePaymentRequest(
	payeeDID string,
	amount *big.Int,
	currency, description string,
	methods []PaymentMethod,
	expiresAt *time.Time,
) (*PaymentRequest, error) {

	request := &PaymentRequest{
		ID:              generatePaymentRequestID(),
		Payee:           payeeDID,
		Amount:          amount,
		Currency:        currency,
		Description:     description,
		PaymentMethods:  methods,
		ExpiresAt:       expiresAt,
		ReceiptRequired: true,
		ReceiptService:  ps.ReceiptIssuer,
		Metadata: map[string]interface{}{
			"service": ps.Name,
			"created": time.Now(),
		},
	}

	// Sign the payment request
	signature, err := ps.signPaymentRequest(request)
	if err != nil {
		return nil, fmt.Errorf("failed to sign payment request: %w", err)
	}

	request.Signature = signature
	return request, nil
}

// ProcessPayment processes a payment and returns a payment response
func (ps *PaymentService) ProcessPayment(ctx context.Context, request *PaymentRequest, selectedMethod PaymentMethod, payerDID string) (*PaymentResponse, error) {
	// Verify payment request signature
	if err := ps.verifyPaymentRequest(request); err != nil {
		return nil, fmt.Errorf("payment request verification failed: %w", err)
	}

	// Check expiration
	if request.ExpiresAt != nil && time.Now().After(*request.ExpiresAt) {
		return nil, fmt.Errorf("payment request has expired")
	}

	// Generate transaction ID
	transactionID := generateTransactionID()

	// Process payment based on method type
	var txHash string
	var err error

	switch selectedMethod.Type {
	case PaymentMethodCrypto:
		txHash, err = ps.processCryptoPayment(ctx, request, selectedMethod)
	case PaymentMethodStripe:
		txHash, err = ps.processStripePayment(ctx, request, selectedMethod)
	default:
		return nil, fmt.Errorf("unsupported payment method: %s", selectedMethod.Type)
	}

	if err != nil {
		return &PaymentResponse{
			PaymentRequestID: request.ID,
			PaymentMethod:    selectedMethod,
			TransactionID:    transactionID,
			Amount:           request.Amount,
			Currency:         request.Currency,
			Status:           PaymentStatusFailed,
			Payer:            payerDID,
			Payee:            request.Payee,
			Timestamp:        time.Now(),
			Metadata: map[string]interface{}{
				"error": err.Error(),
			},
		}, err
	}

	// Create payment response
	response := &PaymentResponse{
		PaymentRequestID: request.ID,
		PaymentMethod:    selectedMethod,
		TransactionID:    transactionID,
		Amount:           request.Amount,
		Currency:         request.Currency,
		Status:           PaymentStatusCompleted,
		Payer:            payerDID,
		Payee:            request.Payee,
		Timestamp:        time.Now(),
		BlockchainTxHash: txHash,
	}

	// Generate receipt if required
	if request.ReceiptRequired {
		receipt, err := ps.generateReceipt(ctx, request, response)
		if err != nil {
			// Don't fail the payment if receipt generation fails
			response.Metadata = map[string]interface{}{
				"receipt_error": err.Error(),
			}
		} else {
			response.Receipt = receipt
		}
	}

	return response, nil
}

// VerifyPaymentReceipt verifies a payment receipt credential
func (ps *PaymentService) VerifyPaymentReceipt(ctx context.Context, receiptJWT string) (*PaymentReceipt, error) {
	// Parse JWT credential
	credential, token, err := vc.CredentialFromJWT(receiptJWT)
	if err != nil {
		return nil, fmt.Errorf("failed to parse receipt credential: %w", err)
	}

	// Verify credential signature with proper key resolution
	issuerDID := credential.GetIssuerID()
	if issuerDID == "" {
		return nil, fmt.Errorf("credential missing issuer")
	}

	// Resolve issuer's verification key
	resolver := did.NewResolver()
	var issuerKeyPair *keys.KeyPair

	if token.Header.KeyID != "" {
		var err error
		issuerKeyPair, err = resolver.GetPublicKey(ctx, token.Header.KeyID)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve issuer key: %w", err)
		}
	} else {
		// Fall back to DID resolution
		parsedDID, err := did.Parse(issuerDID)
		if err != nil {
			return nil, fmt.Errorf("invalid issuer DID: %w", err)
		}

		document, err := resolver.Resolve(ctx, parsedDID)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve issuer DID: %w", err)
		}

		// Find assertion method
		if len(document.AssertionMethod) == 0 {
			return nil, fmt.Errorf("issuer has no assertion methods")
		}

		var keyID string
		switch assertionMethod := document.AssertionMethod[0].(type) {
		case string:
			keyID = assertionMethod
		default:
			return nil, fmt.Errorf("unsupported assertion method format")
		}

		vm, err := document.GetVerificationMethod(keyID)
		if err != nil {
			return nil, fmt.Errorf("assertion method not found: %w", err)
		}

		if vm.PublicKeyMultibase != "" {
			issuerKeyPair, err = keys.DecodePublicKeyMulticodec(vm.PublicKeyMultibase)
			if err != nil {
				return nil, fmt.Errorf("failed to decode issuer public key: %w", err)
			}
		} else {
			return nil, fmt.Errorf("verification method missing public key")
		}
	}

	// Verify JWT signature
	if err := token.Verify(issuerKeyPair); err != nil {
		return nil, fmt.Errorf("receipt signature verification failed: %w", err)
	}

	// Extract receipt data from credential subject
	subjectData, ok := credential.CredentialSubject.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid credential subject format")
	}

	receipt := &PaymentReceipt{
		VerifiableReceipt: credential,
		Metadata: map[string]interface{}{
			"verified_at": time.Now(),
		},
	}

	// Extract receipt fields
	if id, ok := subjectData["receipt_id"].(string); ok {
		receipt.ID = id
	}
	if txID, ok := subjectData["transaction_id"].(string); ok {
		receipt.TransactionID = txID
	}
	if payerDID, ok := subjectData["payer"].(string); ok {
		receipt.Payer = payerDID
	}
	if payeeDID, ok := subjectData["payee"].(string); ok {
		receipt.Payee = payeeDID
	}

	return receipt, nil
}

// signPaymentRequest signs a payment request and returns a JWT
func (ps *PaymentService) signPaymentRequest(request *PaymentRequest) (string, error) {
	header := jwt.Header{
		Algorithm: ps.KeyPair.Algorithm(),
		Type:      "JWT",
		KeyID:     ps.DID.String() + "#key-1",
	}

	claims := jwt.Claims{
		Issuer:   ps.DID.String(),
		Subject:  request.Payee,
		IssuedAt: jwt.NewNumericDate(time.Now()),
		Extra: map[string]interface{}{
			"payment_request": request,
		},
	}

	if request.ExpiresAt != nil {
		claims.ExpirationTime = jwt.NewNumericDate(*request.ExpiresAt)
	}

	return jwt.Sign(header, claims, ps.KeyPair)
}

// verifyPaymentRequest verifies a signed payment request
func (ps *PaymentService) verifyPaymentRequest(request *PaymentRequest) error {
	if request.Signature == "" {
		return fmt.Errorf("payment request is not signed")
	}

	// Parse JWT
	token, err := jwt.Parse(request.Signature)
	if err != nil {
		return fmt.Errorf("failed to parse payment request signature: %w", err)
	}

	// Verify time claims
	if err := token.ValidateTime(); err != nil {
		return fmt.Errorf("payment request time validation failed: %w", err)
	}

	// Resolve issuer's public key for signature verification
	if token.Claims.Issuer == "" {
		return fmt.Errorf("payment request missing issuer")
	}

	// Create resolver if not exists
	resolver := did.NewResolver()

	// Resolve issuer key
	var issuerKeyPair *keys.KeyPair
	if token.Header.KeyID != "" {
		// Use specific key ID if provided
		var err error
		issuerKeyPair, err = resolver.GetPublicKey(context.Background(), token.Header.KeyID)
		if err != nil {
			return fmt.Errorf("failed to resolve issuer key: %w", err)
		}
	} else {
		// Fall back to resolving issuer DID
		issuerDID, err := did.Parse(token.Claims.Issuer)
		if err != nil {
			return fmt.Errorf("invalid issuer DID: %w", err)
		}

		document, err := resolver.Resolve(context.Background(), issuerDID)
		if err != nil {
			return fmt.Errorf("failed to resolve issuer DID: %w", err)
		}

		// Use first assertion method
		if len(document.AssertionMethod) == 0 {
			return fmt.Errorf("issuer has no assertion methods")
		}

		var keyID string
		switch assertionMethod := document.AssertionMethod[0].(type) {
		case string:
			keyID = assertionMethod
		case map[string]interface{}:
			if id, ok := assertionMethod["id"].(string); ok {
				keyID = id
			} else {
				return fmt.Errorf("invalid assertion method format")
			}
		default:
			return fmt.Errorf("unsupported assertion method type")
		}

		vm, err := document.GetVerificationMethod(keyID)
		if err != nil {
			return fmt.Errorf("assertion method not found: %w", err)
		}

		// Extract public key
		if vm.PublicKeyMultibase != "" {
			issuerKeyPair, err = keys.DecodePublicKeyMulticodec(vm.PublicKeyMultibase)
			if err != nil {
				return fmt.Errorf("failed to decode issuer public key: %w", err)
			}
		} else {
			return fmt.Errorf("verification method does not contain supported key format")
		}
	}

	// Verify JWT signature
	if err := token.Verify(issuerKeyPair); err != nil {
		return fmt.Errorf("payment request signature verification failed: %w", err)
	}

	return nil
}

// processCryptoPayment processes a cryptocurrency payment
func (ps *PaymentService) processCryptoPayment(ctx context.Context, request *PaymentRequest, method PaymentMethod) (string, error) {
	if ps.BlockchainClient == nil {
		return "", fmt.Errorf("blockchain client not configured")
	}

	// Set up blockchain client for the specific network
	if method.Network != "" {
		ps.BlockchainClient.Network = method.Network

		// Configure RPC endpoint based on network
		switch method.Network {
		case "ethereum", "mainnet":
			ps.BlockchainClient.RPCEndpoint = "https://eth-mainnet.g.alchemy.com/v2/demo"
		case "sepolia":
			ps.BlockchainClient.RPCEndpoint = "https://eth-sepolia.g.alchemy.com/v2/demo"
		case "base":
			ps.BlockchainClient.RPCEndpoint = "https://mainnet.base.org"
		case "base-sepolia":
			ps.BlockchainClient.RPCEndpoint = "https://sepolia.base.org"
		default:
			return "", fmt.Errorf("unsupported network: %s", method.Network)
		}
	}

	// Verify the payment on the blockchain
	txHash, err := ps.BlockchainClient.VerifyPayment(ctx, request, method)
	if err != nil {
		return "", fmt.Errorf("payment verification failed: %w", err)
	}

	if txHash == "" {
		return "", fmt.Errorf("no payment transaction found")
	}

	return txHash, nil
}

// processStripePayment processes a Stripe payment
func (ps *PaymentService) processStripePayment(ctx context.Context, request *PaymentRequest, method PaymentMethod) (string, error) {
	if ps.StripeKey == "" {
		// In demo mode, return a mock charge ID
		return "ch_demo_" + generateTransactionID(), nil
	}

	// In a real implementation, this would:
	// 1. Create a Stripe Payment Intent
	// 2. Process the payment with provided payment method
	// 3. Handle webhooks for payment confirmation
	// 4. Return the actual charge/payment intent ID

	return ps.createStripePaymentIntent(ctx, request, method)
}

// createStripePaymentIntent creates a Stripe payment intent (simplified implementation)
func (ps *PaymentService) createStripePaymentIntent(ctx context.Context, request *PaymentRequest, method PaymentMethod) (string, error) {
	// This is a simplified mock implementation
	// In production, you would use the Stripe Go SDK:
	// https://github.com/stripe/stripe-go

	// Example payload for Stripe API:
	paymentData := map[string]interface{}{
		"amount":   request.Amount.Int64(), // Amount in cents
		"currency": strings.ToLower(request.Currency),
		"metadata": map[string]string{
			"payment_request_id": request.ID,
			"description":        request.Description,
		},
		"automatic_payment_methods": map[string]bool{
			"enabled": true,
		},
	}

	// Mock successful payment intent creation
	_ = paymentData // Use the data in real implementation

	// Return a mock payment intent ID
	return "pi_demo_" + generateTransactionID(), nil
}

// generateReceipt generates a verifiable credential receipt
func (ps *PaymentService) generateReceipt(ctx context.Context, request *PaymentRequest, response *PaymentResponse) (*PaymentReceipt, error) {
	// Create verifiable credential for the receipt
	credential := vc.NewCredential()
	credential.AddType("PaymentReceiptCredential")
	credential.SetIssuer(ps.DID.String())

	// Set credential subject
	receiptData := map[string]interface{}{
		"receipt_id":         generateReceiptID(),
		"payment_request_id": request.ID,
		"transaction_id":     response.TransactionID,
		"amount":             response.Amount.String(),
		"currency":           response.Currency,
		"payer":              response.Payer,
		"payee":              response.Payee,
		"payment_method":     response.PaymentMethod,
		"blockchain_tx_hash": response.BlockchainTxHash,
		"timestamp":          response.Timestamp,
	}

	credential.CredentialSubject = receiptData

	// Create receipt
	receipt := &PaymentReceipt{
		ID:                generateReceiptID(),
		PaymentRequestID:  request.ID,
		TransactionID:     response.TransactionID,
		Amount:            response.Amount,
		Currency:          response.Currency,
		Payer:             response.Payer,
		Payee:             response.Payee,
		Timestamp:         response.Timestamp,
		PaymentMethod:     response.PaymentMethod,
		BlockchainTxHash:  response.BlockchainTxHash,
		VerifiableReceipt: credential,
	}

	return receipt, nil
}

// Helper functions for ID generation
func generatePaymentRequestID() string {
	return fmt.Sprintf("pr_%d", time.Now().UnixNano())
}

func generateTransactionID() string {
	return fmt.Sprintf("tx_%d", time.Now().UnixNano())
}

func generateReceiptID() string {
	return fmt.Sprintf("rec_%d", time.Now().UnixNano())
}
