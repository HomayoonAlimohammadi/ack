package main

import (
	"context"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"

	"github.com/HomayoonAlimohammadi/ack/go/pkg/ack"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("Usage: %s <demo>\n", os.Args[0])
		fmt.Println("Available demos:")
		fmt.Println("  identity    - ACK-ID identity verification demo")
		fmt.Println("  payments    - ACK-Pay payment processing demo")
		fmt.Println("  e2e         - End-to-end demo (ACK-ID + ACK-Pay)")
		fmt.Println("  identity-a2a - ACK-ID with A2A protocol demo")
		os.Exit(1)
	}

	demo := os.Args[1]
	ctx := context.Background()

	switch demo {
	case "identity":
		runIdentityDemo(ctx)
	case "payments":
		runPaymentsDemo(ctx)
	case "e2e":
		runE2EDemo(ctx)
	case "identity-a2a":
		runIdentityA2ADemo(ctx)
	default:
		fmt.Printf("Unknown demo: %s\n", demo)
		os.Exit(1)
	}
}

// runIdentityDemo demonstrates ACK-ID identity verification
func runIdentityDemo(ctx context.Context) {
	fmt.Println("🔐 ACK-ID Identity Verification Demo")
	fmt.Println("=====================================")

	// Create Owner (human with DID and keys)
	fmt.Println("1. Creating Owner identity...")
	owner, err := ack.NewAgent(ack.CurveSecp256k1, "Alice (Owner)")
	if err != nil {
		log.Fatalf("Failed to create owner: %v", err)
	}
	fmt.Printf("   Owner DID: %s\n", owner.DID.String())

	// Create Agent (AI agent controlled by owner)
	fmt.Println("2. Creating Agent identity...")
	agent, err := ack.NewWebAgent(ack.CurveEd25519, "agent.example.com", "AI Assistant Agent", "agent-1")
	if err != nil {
		log.Fatalf("Failed to create agent: %v", err)
	}
	fmt.Printf("   Agent DID: %s\n", agent.DID.String())

	// Set controller relationship
	fmt.Println("3. Establishing controller relationship...")
	agent.SetController(owner.DID, owner.KeyPair)
	fmt.Printf("   Agent is now controlled by: %s\n", owner.DID.String())

	// Add service endpoints to agent
	agent.AddService("chat", "ChatService", map[string]interface{}{
		"serviceEndpoint": "https://agent.example.com/chat",
		"protocols":       []string{"https", "wss"},
	})

	agent.AddService("identity", "IdentityService", map[string]interface{}{
		"serviceEndpoint": "https://agent.example.com/identity",
		"methods":         []string{"challenge", "verify"},
	})

	// Create Verifier (service that needs to verify agent identity)
	fmt.Println("4. Creating Verifier service...")
	verifier, err := ack.NewWebAgent(ack.CurveSecp256r1, "verifier.example.com", "Identity Verifier Service")
	if err != nil {
		log.Fatalf("Failed to create verifier: %v", err)
	}
	fmt.Printf("   Verifier DID: %s\n", verifier.DID.String())

	// Challenge-Response Flow
	fmt.Println("5. Starting identity verification flow...")

	// Verifier creates challenge for agent
	fmt.Println("   → Verifier creates challenge for Agent")
	challenge, err := verifier.CreateChallenge(
		agent.DID.String(),
		"identity_verification",
		"ControllerCredential", // Require proof of controller relationship
	)
	if err != nil {
		log.Fatalf("Failed to create challenge: %v", err)
	}
	fmt.Printf("   Challenge: %s\n", challenge.Challenge[:16]+"...")

	// Agent responds to challenge
	fmt.Println("   → Agent responds to challenge")
	response, err := agent.RespondToChallenge(ctx, challenge)
	if err != nil {
		log.Fatalf("Failed to respond to challenge: %v", err)
	}
	fmt.Printf("   Response includes DID document and signed challenge\n")

	// Verifier verifies the response
	fmt.Println("   → Verifier verifies response")
	result, err := verifier.VerifyIdentityResponse(ctx, response, challenge)
	if err != nil {
		log.Fatalf("Failed to verify response: %v", err)
	}

	// Display results
	fmt.Println("6. Verification Results:")
	fmt.Printf("   ✓ Valid: %t\n", result.Valid)
	fmt.Printf("   ✓ DID: %s\n", result.DID)
	fmt.Printf("   ✓ Trust Level: %s\n", result.TrustLevel)
	fmt.Printf("   ✓ Verified at: %s\n", result.VerifiedAt.Format(time.RFC3339))

	if len(result.Errors) > 0 {
		fmt.Println("   ⚠ Errors:")
		for _, err := range result.Errors {
			fmt.Printf("     - %s\n", err)
		}
	}

	if len(result.Warnings) > 0 {
		fmt.Println("   ⚠ Warnings:")
		for _, warning := range result.Warnings {
			fmt.Printf("     - %s\n", warning)
		}
	}

	fmt.Println("✅ Identity verification demo completed!")
}

// runPaymentsDemo demonstrates ACK-Pay payment processing
func runPaymentsDemo(ctx context.Context) {
	fmt.Println("💳 ACK-Pay Payment Processing Demo")
	fmt.Println("==================================")

	// Create Client (payer)
	fmt.Println("1. Creating Client agent...")
	client, err := ack.NewWebAgent(ack.CurveEd25519, "client.example.com", "Client Agent")
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	fmt.Printf("   Client DID: %s\n", client.DID.String())

	// Create Server (payee)
	fmt.Println("2. Creating Server...")
	server, err := ack.NewWebAgent(ack.CurveSecp256k1, "server.example.com", "Content Server")
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}
	fmt.Printf("   Server DID: %s\n", server.DID.String())

	// Create Payment Service
	fmt.Println("3. Creating Payment Service...")
	paymentService, err := ack.NewPaymentService(ack.CurveSecp256r1, "payments.example.com", "Universal Payment Service")
	if err != nil {
		log.Fatalf("Failed to create payment service: %v", err)
	}
	fmt.Printf("   Payment Service DID: %s\n", paymentService.DID.String())

	// Server creates payment request
	fmt.Println("4. Server creates payment request...")
	amount := big.NewInt(1000000) // 1 USDC (6 decimals)
	expiresAt := time.Now().Add(1 * time.Hour)

	paymentMethods := []ack.PaymentMethod{
		{
			Type:      ack.PaymentMethodCrypto,
			Currency:  "USDC",
			Network:   "base-sepolia",
			Address:   "0x1234567890123456789012345678901234567890",
			MinAmount: big.NewInt(100000),     // 0.1 USDC minimum
			MaxAmount: big.NewInt(1000000000), // 1000 USDC maximum
		},
		{
			Type:       ack.PaymentMethodStripe,
			Currency:   "USD",
			PaymentURL: "https://payments.example.com/stripe/pay",
			MinAmount:  big.NewInt(100), // $1.00 minimum (cents)
		},
	}

	paymentRequest, err := paymentService.CreatePaymentRequest(
		server.DID.String(),
		amount,
		"USDC",
		"Access to premium content",
		paymentMethods,
		&expiresAt,
	)
	if err != nil {
		log.Fatalf("Failed to create payment request: %v", err)
	}
	fmt.Printf("   Payment Request ID: %s\n", paymentRequest.ID)
	fmt.Printf("   Amount: %s USDC\n", amount.String())
	fmt.Printf("   Available methods: %d\n", len(paymentRequest.PaymentMethods))

	// Client selects payment method and pays
	fmt.Println("5. Client processes payment...")
	selectedMethod := paymentRequest.PaymentMethods[0] // Select crypto payment
	fmt.Printf("   Selected method: %s (%s)\n", selectedMethod.Type, selectedMethod.Currency)

	paymentResponse, err := paymentService.ProcessPayment(
		ctx,
		paymentRequest,
		selectedMethod,
		client.DID.String(),
	)
	if err != nil {
		log.Fatalf("Failed to process payment: %v", err)
	}

	fmt.Printf("   Transaction ID: %s\n", paymentResponse.TransactionID)
	fmt.Printf("   Status: %s\n", paymentResponse.Status)
	fmt.Printf("   Blockchain TX: %s\n", paymentResponse.BlockchainTxHash)

	// Display payment receipt
	if paymentResponse.Receipt != nil {
		fmt.Println("6. Payment Receipt Generated:")
		fmt.Printf("   Receipt ID: %s\n", paymentResponse.Receipt.ID)
		fmt.Printf("   Verifiable Receipt: %t\n", paymentResponse.Receipt.VerifiableReceipt != nil)

		if paymentResponse.Receipt.VerifiableReceipt != nil {
			fmt.Printf("   Credential Type: %v\n", paymentResponse.Receipt.VerifiableReceipt.Type)
			fmt.Printf("   Issuer: %s\n", paymentResponse.Receipt.VerifiableReceipt.GetIssuerID())
		}
	}

	// Demonstrate receipt verification
	if paymentResponse.Receipt != nil && paymentResponse.Receipt.VerifiableReceipt != nil {
		fmt.Println("7. Verifying payment receipt...")

		// Convert receipt to JWT for verification demo
		receiptJWT, err := paymentResponse.Receipt.VerifiableReceipt.ToJWT(
			paymentService.KeyPair,
			paymentService.DID.String()+"#key-1",
		)
		if err != nil {
			fmt.Printf("   ⚠ Failed to create receipt JWT: %v\n", err)
		} else {
			// Verify the receipt
			verifiedReceipt, err := paymentService.VerifyPaymentReceipt(ctx, receiptJWT)
			if err != nil {
				fmt.Printf("   ⚠ Receipt verification failed: %v\n", err)
			} else {
				fmt.Printf("   ✓ Receipt verified successfully\n")
				fmt.Printf("   ✓ Verified payer: %s\n", verifiedReceipt.Payer)
				fmt.Printf("   ✓ Verified payee: %s\n", verifiedReceipt.Payee)
			}
		}
	}

	fmt.Println("✅ Payment processing demo completed!")
}

// runE2EDemo demonstrates end-to-end ACK-ID + ACK-Pay integration
func runE2EDemo(ctx context.Context) {
	fmt.Println("🚀 End-to-End ACK Demo (ACK-ID + ACK-Pay)")
	fmt.Println("=========================================")

	// This would combine identity verification with payment processing
	fmt.Println("1. Running identity verification...")
	runIdentityDemo(ctx)

	fmt.Println("\n2. Running payment processing...")
	runPaymentsDemo(ctx)

	fmt.Println("✅ End-to-end demo completed!")
	fmt.Println("💡 In a real implementation, the identity verification would")
	fmt.Println("   establish trust before allowing payment processing.")
}

// runIdentityA2ADemo demonstrates ACK-ID with Google A2A protocol
func runIdentityA2ADemo(ctx context.Context) {
	fmt.Println("🤝 ACK-ID with A2A Protocol Demo")
	fmt.Println("=================================")

	// Create Bank Client Agent (customer)
	fmt.Println("1. Creating Bank Client Agent (Ed25519)...")
	clientAgent, err := ack.NewAgent(ack.CurveEd25519, "Bank Client Agent")
	if err != nil {
		log.Fatalf("Failed to create client agent: %v", err)
	}
	fmt.Printf("   Client Agent DID: %s\n", clientAgent.DID.String())

	// Create Bank Teller Agent (service provider)
	fmt.Println("2. Creating Bank Teller Agent (secp256k1)...")
	tellerAgent, err := ack.NewWebAgent(ack.CurveSecp256k1, "bank.example.com", "Bank Teller Agent", "teller")
	if err != nil {
		log.Fatalf("Failed to create teller agent: %v", err)
	}
	fmt.Printf("   Teller Agent DID: %s\n", tellerAgent.DID.String())

	// Add A2A-compatible services
	tellerAgent.AddService("a2a", "AgentCard", map[string]interface{}{
		"serviceEndpoint": "https://bank.example.com/a2a",
		"protocols":       []string{"agent2agent"},
		"capabilities":    []string{"account_balance", "transaction_history"},
	})

	// Demonstrate service discovery
	fmt.Println("3. Service Discovery...")
	fmt.Printf("   Client discovers Teller services via DID: %s\n", tellerAgent.DID.String())

	services := tellerAgent.Document.GetServicesByType("AgentCard")
	if len(services) > 0 {
		fmt.Printf("   Found AgentCard service: %v\n", services[0].ServiceEndpoint)
	}

	// Demonstrate mutual authentication
	fmt.Println("4. Mutual Authentication Flow...")

	// Client creates challenge for Teller
	clientChallenge, err := clientAgent.CreateChallenge(
		tellerAgent.DID.String(),
		"service_access",
	)
	if err != nil {
		log.Fatalf("Failed to create client challenge: %v", err)
	}
	fmt.Printf("   Client → Teller challenge: %s\n", clientChallenge.Challenge[:16]+"...")

	// Teller responds to client challenge
	tellerResponse, err := tellerAgent.RespondToChallenge(ctx, clientChallenge)
	if err != nil {
		log.Fatalf("Failed to create teller response: %v", err)
	}
	fmt.Println("   Teller responds with signed challenge and DID document")

	// Teller creates challenge for Client
	tellerChallenge, err := tellerAgent.CreateChallenge(
		clientAgent.DID.String(),
		"client_verification",
	)
	if err != nil {
		log.Fatalf("Failed to create teller challenge: %v", err)
	}
	fmt.Printf("   Teller → Client challenge: %s\n", tellerChallenge.Challenge[:16]+"...")

	// Client responds to teller challenge
	clientResponse, err := clientAgent.RespondToChallenge(ctx, tellerChallenge)
	if err != nil {
		log.Fatalf("Failed to create client response: %v", err)
	}
	fmt.Println("   Client responds with signed challenge and DID document")

	// Both parties verify each other
	fmt.Println("5. Mutual Verification...")

	// Client verifies Teller
	tellerResult, err := clientAgent.VerifyIdentityResponse(ctx, tellerResponse, clientChallenge)
	if err != nil {
		log.Fatalf("Failed to verify teller: %v", err)
	}
	fmt.Printf("   Client verifies Teller: %t (Trust: %s)\n", tellerResult.Valid, tellerResult.TrustLevel)

	// Teller verifies Client
	clientResult, err := tellerAgent.VerifyIdentityResponse(ctx, clientResponse, tellerChallenge)
	if err != nil {
		log.Fatalf("Failed to verify client: %v", err)
	}
	fmt.Printf("   Teller verifies Client: %t (Trust: %s)\n", clientResult.Valid, clientResult.TrustLevel)

	// Demonstrate authenticated communication
	fmt.Println("6. Authenticated Communication:")
	if tellerResult.Valid && clientResult.Valid {
		fmt.Println("   ✓ Mutual authentication successful")
		fmt.Println("   ✓ Secure communication channel established")
		fmt.Println("   ✓ Both parties can now exchange signed messages")
		fmt.Println("   → Client: 'Please show my account balance'")
		fmt.Println("   ← Teller: 'Your balance is $1,234.56' (cryptographically signed)")
	} else {
		fmt.Println("   ⚠ Authentication failed - secure communication not established")
	}

	fmt.Println("✅ A2A protocol demo completed!")
	fmt.Println("💡 This demonstrates interoperability between different")
	fmt.Println("   cryptographic curves (Ed25519 ↔ secp256k1) and standards")
	fmt.Println("   compliance with both ACK-ID and Google A2A protocols.")
}
