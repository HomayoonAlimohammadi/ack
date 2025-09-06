# Getting Started with ACK Go Implementation

This guide will help you get up and running with the Go implementation of Agent Commerce Kit (ACK).

## Quick Start

### Prerequisites

- Go 1.21 or higher
- Git

### Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/agentcommercekit/ack.git
   cd ack/go
   ```

2. **Install dependencies:**

   ```bash
   go mod download
   ```

3. **Run the demos:**

   ```bash
   # ACK-ID identity verification demo
   go run cmd/ack-demo/main.go identity

   # ACK-Pay payment processing demo
   go run cmd/ack-demo/main.go payments

   # End-to-end demo (ACK-ID + ACK-Pay)
   go run cmd/ack-demo/main.go e2e

   # ACK-ID with Google A2A protocol
   go run cmd/ack-demo/main.go identity-a2a
   ```

### Build the Demo

```bash
go build -o bin/ack-demo cmd/ack-demo/main.go
./bin/ack-demo identity
```

## Basic Usage

### Creating an Agent Identity

```go
package main

import (
    "fmt"
    "github.com/HomayoonAlimohammadi/ack/go/pkg/ack"
)

func main() {
    // Create a new agent with Ed25519 keys
    agent, err := ack.NewAgent(ack.CurveEd25519, "My AI Agent")
    if err != nil {
        panic(err)
    }

    fmt.Printf("Agent DID: %s\n", agent.DID.String())
    fmt.Printf("Algorithm: %s\n", agent.KeyPair.Algorithm())
}
```

### Creating a Web-based Agent

```go
// Create an agent with did:web identifier
agent, err := ack.NewWebAgent(ack.CurveSecp256k1, "agent.example.com", "Web Agent", "v1")
if err != nil {
    panic(err)
}

// Add service endpoints
agent.AddService("chat", "ChatService", map[string]interface{}{
    "serviceEndpoint": "https://agent.example.com/chat",
    "protocols":       []string{"https", "wss"},
})
```

### Identity Verification Flow

```go
// Create challenger and responder
challenger, _ := ack.NewAgent(ack.CurveSecp256r1, "Challenger")
responder, _ := ack.NewAgent(ack.CurveEd25519, "Responder")

// Create identity challenge
challenge, err := challenger.CreateChallenge(
    responder.DID.String(),
    "service_access",
)
if err != nil {
    panic(err)
}

// Responder creates response
response, err := responder.RespondToChallenge(context.Background(), challenge)
if err != nil {
    panic(err)
}

// Challenger verifies response
result, err := challenger.VerifyIdentityResponse(context.Background(), response, challenge)
if err != nil {
    panic(err)
}

fmt.Printf("Verification successful: %t\n", result.Valid)
fmt.Printf("Trust level: %s\n", result.TrustLevel)
```

### Payment Processing

```go
// Create payment service
paymentService, err := ack.NewPaymentService(ack.CurveSecp256k1, "payments.example.com", "Payment Service")
if err != nil {
    panic(err)
}

// Create payment request
amount := big.NewInt(1000000) // 1 USDC
expiresAt := time.Now().Add(1 * time.Hour)

paymentMethods := []ack.PaymentMethod{
    {
        Type:     ack.PaymentMethodCrypto,
        Currency: "USDC",
        Network:  "ethereum",
        Address:  "0x...",
    },
}

paymentRequest, err := paymentService.CreatePaymentRequest(
    "did:web:merchant.example.com", // payee
    amount,
    "USDC",
    "Premium service access",
    paymentMethods,
    &expiresAt,
)

// Process payment
paymentResponse, err := paymentService.ProcessPayment(
    context.Background(),
    paymentRequest,
    paymentMethods[0],
    "did:web:customer.example.com", // payer
)

fmt.Printf("Payment status: %s\n", paymentResponse.Status)
```

## Key Features

### Multi-Curve Cryptography

The Go implementation supports three cryptographic curves:

- **Ed25519** (`ack.CurveEd25519`) - High performance, modern curve
- **secp256k1** (`ack.CurveSecp256k1`) - Bitcoin/Ethereum compatible
- **secp256r1** (`ack.CurveSecp256r1`) - NIST P-256, widely supported

```go
// Generate keys for different curves
ed25519Keys, _ := ack.GenerateKeyPair(ack.CurveEd25519)
secp256k1Keys, _ := ack.GenerateKeyPair(ack.CurveSecp256k1)
secp256r1Keys, _ := ack.GenerateKeyPair(ack.CurveSecp256r1)

// Each automatically uses the correct JWT algorithm
fmt.Printf("Ed25519 uses: %s\n", ed25519Keys.Algorithm())   // EdDSA
fmt.Printf("secp256k1 uses: %s\n", secp256k1Keys.Algorithm()) // ES256K
fmt.Printf("secp256r1 uses: %s\n", secp256r1Keys.Algorithm()) // ES256
```

### DID Methods

#### did:key (Cryptographic)

```go
// Create from existing key pair
pubKey, _ := keyPair.EncodePublicKeyMulticodec()
did, _ := ack.CreateKeyDID(pubKey)
```

#### did:web (Domain-based)

```go
// Simple domain
did1, _ := ack.CreateWebDID("example.com")
// → did:web:example.com

// With path
did2, _ := ack.CreateWebDID("example.com", "users", "alice")
// → did:web:example.com:users:alice
```

### Verifiable Credentials

```go
// Create credential
credential := ack.NewCredential()
credential.AddType("ExampleCredential")
credential.SetIssuer("did:web:issuer.example.com")

credential.CredentialSubject = map[string]interface{}{
    "id":   "did:web:holder.example.com",
    "name": "Alice Smith",
    "role": "Agent Controller",
}

// Convert to JWT
credentialJWT, err := credential.ToJWT(issuerKeyPair, issuerDID.String()+"#key-1")

// Verify JWT credential
verifiedCredential, err := ack.VerifyCredentialJWT(credentialJWT, issuerKeyPair)
```

## Testing

```bash
# Run all tests
go test ./...

# Run tests for specific package
go test ./pkg/keys -v
go test ./pkg/did -v
go test ./pkg/jwt -v
```

## Architecture Overview

The Go implementation provides a layered architecture:

1. **Core Layer** (`pkg/keys`, `pkg/crypto`) - Cryptographic primitives
2. **Identity Layer** (`pkg/did`, `pkg/vc`, `pkg/jwt`) - W3C standards implementation
3. **Protocol Layer** (`pkg/ackid`, `pkg/ackpay`) - ACK protocol implementation
4. **SDK Layer** (`pkg/ack`) - Unified API surface
5. **Application Layer** (`cmd/`) - Demo applications and tools

## Next Steps

- Check out the [demos](./demos/) for complete working examples
- Read the [API documentation](./docs/) for detailed reference
- Explore the [examples](./examples/) for specific use cases
- Join the [Discord community](https://discord.gg/3V34SmdHPq) for support

## Comparison with TypeScript Version

This Go implementation provides several advantages over the original TypeScript version:

✅ **Unified Architecture** - Single, coherent implementation rather than scattered demos
✅ **Complete Workflows** - Full end-to-end implementations, not half-baked examples
✅ **Production Ready** - Proper error handling, testing, and documentation
✅ **Standards Compliant** - Full W3C DID/VC specification compliance
✅ **Multi-Curve Support** - Comprehensive cryptographic curve support
✅ **Performance** - Native Go performance for cryptographic operations
✅ **Type Safety** - Strong typing throughout the entire stack
✅ **Extensible** - Plugin architecture for new payment methods and verification strategies
