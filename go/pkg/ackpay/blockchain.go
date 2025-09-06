package ackpay

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// BlockchainClient handles blockchain operations for crypto payments
type BlockchainClient struct {
	HTTPClient  *http.Client
	RPCEndpoint string
	Network     string
}

// EthereumTransaction represents an Ethereum transaction
type EthereumTransaction struct {
	Hash             string `json:"hash"`
	BlockNumber      string `json:"blockNumber"`
	From             string `json:"from"`
	To               string `json:"to"`
	Value            string `json:"value"`
	GasUsed          string `json:"gasUsed"`
	Status           string `json:"status"`
	Confirmations    int    `json:"-"`
	TransactionIndex string `json:"transactionIndex"`
	Logs             []Log  `json:"logs"`
}

// Log represents a transaction log (for ERC-20 transfers)
type Log struct {
	Address string   `json:"address"`
	Topics  []string `json:"topics"`
	Data    string   `json:"data"`
}

// ERC20Transfer represents an ERC-20 token transfer event
type ERC20Transfer struct {
	From       string
	To         string
	Value      *big.Int
	TokenAddr  string
	TxHash     string
	BlockNum   *big.Int
}

// RPCRequest represents a JSON-RPC request
type RPCRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params"`
	ID      int         `json:"id"`
}

// RPCResponse represents a JSON-RPC response
type RPCResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	Result  interface{} `json:"result"`
	Error   *RPCError   `json:"error"`
	ID      int         `json:"id"`
}

// RPCError represents a JSON-RPC error
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// NewBlockchainClient creates a new blockchain client
func NewBlockchainClient(network, rpcEndpoint string) *BlockchainClient {
	return &BlockchainClient{
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		Network:     network,
		RPCEndpoint: rpcEndpoint,
	}
}

// VerifyPayment verifies a cryptocurrency payment on the blockchain
func (bc *BlockchainClient) VerifyPayment(ctx context.Context, request *PaymentRequest, method PaymentMethod) (string, error) {
	switch strings.ToLower(method.Currency) {
	case "eth", "ethereum":
		return bc.verifyEthereumPayment(ctx, request, method)
	case "usdc", "usdt", "dai":
		return bc.verifyERC20Payment(ctx, request, method)
	case "btc", "bitcoin":
		return bc.verifyBitcoinPayment(ctx, request, method)
	default:
		return "", fmt.Errorf("unsupported cryptocurrency: %s", method.Currency)
	}
}

// verifyEthereumPayment verifies an Ethereum payment
func (bc *BlockchainClient) verifyEthereumPayment(ctx context.Context, request *PaymentRequest, method PaymentMethod) (string, error) {
	// Get latest transactions to the payment address
	txs, err := bc.getLatestTransactions(ctx, method.Address, 10)
	if err != nil {
		return "", fmt.Errorf("failed to get transactions: %w", err)
	}

	// Look for a transaction matching the payment amount
	expectedAmount := request.Amount
	tolerance := new(big.Int).Div(expectedAmount, big.NewInt(1000)) // 0.1% tolerance

	for _, tx := range txs {
		// Parse transaction value
		value, success := new(big.Int).SetString(tx.Value[2:], 16) // Remove "0x" prefix
		if !success {
			continue
		}

		// Check if value is within tolerance of expected amount
		diff := new(big.Int).Sub(value, expectedAmount)
		diff.Abs(diff)
		
		if diff.Cmp(tolerance) <= 0 && tx.Status == "0x1" {
			// Verify confirmations
			confirmations, err := bc.getConfirmations(ctx, tx.Hash)
			if err != nil {
				continue
			}

			if confirmations >= 3 { // Require at least 3 confirmations
				return tx.Hash, nil
			}
		}
	}

	return "", fmt.Errorf("no matching payment found")
}

// verifyERC20Payment verifies an ERC-20 token payment
func (bc *BlockchainClient) verifyERC20Payment(ctx context.Context, request *PaymentRequest, method PaymentMethod) (string, error) {
	// Get ERC-20 token contract address for the currency
	tokenAddress, err := bc.getTokenAddress(method.Currency, method.Network)
	if err != nil {
		return "", fmt.Errorf("failed to get token address: %w", err)
	}

	// Get recent transactions for the payment address
	txs, err := bc.getLatestTransactions(ctx, method.Address, 50)
	if err != nil {
		return "", fmt.Errorf("failed to get transactions: %w", err)
	}

	expectedAmount := request.Amount
	tolerance := new(big.Int).Div(expectedAmount, big.NewInt(1000)) // 0.1% tolerance

	// Look for ERC-20 transfer events
	for _, tx := range txs {
		if tx.Status != "0x1" {
			continue // Skip failed transactions
		}

		// Check transaction logs for Transfer events
		for _, log := range tx.Logs {
			if strings.EqualFold(log.Address, tokenAddress) {
				transfer, err := bc.parseERC20Transfer(log, tx.Hash)
				if err != nil {
					continue
				}

				// Check if transfer is to the payment address and amount matches
				if strings.EqualFold(transfer.To, method.Address) {
					diff := new(big.Int).Sub(transfer.Value, expectedAmount)
					diff.Abs(diff)
					
					if diff.Cmp(tolerance) <= 0 {
						// Verify confirmations
						confirmations, err := bc.getConfirmations(ctx, tx.Hash)
						if err != nil {
							continue
						}

						if confirmations >= 3 {
							return tx.Hash, nil
						}
					}
				}
			}
		}
	}

	return "", fmt.Errorf("no matching ERC-20 payment found")
}

// verifyBitcoinPayment verifies a Bitcoin payment (basic implementation)
func (bc *BlockchainClient) verifyBitcoinPayment(ctx context.Context, request *PaymentRequest, method PaymentMethod) (string, error) {
	// Bitcoin verification would require different API calls
	// This is a simplified implementation
	return "", fmt.Errorf("Bitcoin payment verification not yet fully implemented")
}

// getLatestTransactions gets the latest transactions for an address
func (bc *BlockchainClient) getLatestTransactions(ctx context.Context, address string, limit int) ([]*EthereumTransaction, error) {
	// Get latest block number
	latestBlock, err := bc.getLatestBlockNumber(ctx)
	if err != nil {
		return nil, err
	}

	var transactions []*EthereumTransaction
	
	// Search recent blocks for transactions to this address
	for i := 0; i < 100 && len(transactions) < limit; i++ {
		blockNum := latestBlock - int64(i)
		if blockNum < 0 {
			break
		}

		blockTxs, err := bc.getTransactionsInBlock(ctx, blockNum, address)
		if err != nil {
			continue // Skip blocks with errors
		}

		transactions = append(transactions, blockTxs...)
	}

	return transactions, nil
}

// getLatestBlockNumber gets the latest block number
func (bc *BlockchainClient) getLatestBlockNumber(ctx context.Context) (int64, error) {
	result, err := bc.makeRPCCall(ctx, "eth_blockNumber", []interface{}{})
	if err != nil {
		return 0, err
	}

	if result == nil {
		return 0, fmt.Errorf("no result from eth_blockNumber")
	}

	blockHex, ok := result.(string)
	if !ok {
		return 0, fmt.Errorf("invalid block number format")
	}

	blockNum, err := strconv.ParseInt(blockHex[2:], 16, 64)
	if err != nil {
		return 0, fmt.Errorf("failed to parse block number: %w", err)
	}

	return blockNum, nil
}

// getTransactionsInBlock gets transactions in a specific block that involve the target address
func (bc *BlockchainClient) getTransactionsInBlock(ctx context.Context, blockNum int64, targetAddress string) ([]*EthereumTransaction, error) {
	blockHex := fmt.Sprintf("0x%x", blockNum)
	
	result, err := bc.makeRPCCall(ctx, "eth_getBlockByNumber", []interface{}{blockHex, true})
	if err != nil {
		return nil, err
	}

	blockData, ok := result.(map[string]interface{})
	if !ok || blockData == nil {
		return nil, nil // No block data
	}

	txsInterface, exists := blockData["transactions"]
	if !exists {
		return nil, nil
	}

	txsList, ok := txsInterface.([]interface{})
	if !ok {
		return nil, nil
	}

	var matchingTxs []*EthereumTransaction
	
	for _, txInterface := range txsList {
		txMap, ok := txInterface.(map[string]interface{})
		if !ok {
			continue
		}

		// Check if transaction involves target address
		to, hasTo := txMap["to"].(string)
		from, hasFrom := txMap["from"].(string)
		
		if (hasTo && strings.EqualFold(to, targetAddress)) || 
		   (hasFrom && strings.EqualFold(from, targetAddress)) {
			
			tx := &EthereumTransaction{
				Hash:        getStringField(txMap, "hash"),
				BlockNumber: getStringField(txMap, "blockNumber"),
				From:        getStringField(txMap, "from"),
				To:          getStringField(txMap, "to"),
				Value:       getStringField(txMap, "value"),
			}

			// Get transaction receipt for status and logs
			receipt, err := bc.getTransactionReceipt(ctx, tx.Hash)
			if err == nil && receipt != nil {
				tx.Status = getStringField(receipt, "status")
				tx.GasUsed = getStringField(receipt, "gasUsed")
				
				// Parse logs
				if logsInterface, exists := receipt["logs"]; exists {
					if logsList, ok := logsInterface.([]interface{}); ok {
						for _, logInterface := range logsList {
							if logMap, ok := logInterface.(map[string]interface{}); ok {
								log := Log{
									Address: getStringField(logMap, "address"),
									Data:    getStringField(logMap, "data"),
								}
								
								if topicsInterface, exists := logMap["topics"]; exists {
									if topicsList, ok := topicsInterface.([]interface{}); ok {
										for _, topic := range topicsList {
											if topicStr, ok := topic.(string); ok {
												log.Topics = append(log.Topics, topicStr)
											}
										}
									}
								}
								
								tx.Logs = append(tx.Logs, log)
							}
						}
					}
				}
			}

			matchingTxs = append(matchingTxs, tx)
		}
	}

	return matchingTxs, nil
}

// getTransactionReceipt gets the receipt for a transaction
func (bc *BlockchainClient) getTransactionReceipt(ctx context.Context, txHash string) (map[string]interface{}, error) {
	result, err := bc.makeRPCCall(ctx, "eth_getTransactionReceipt", []interface{}{txHash})
	if err != nil {
		return nil, err
	}

	receipt, ok := result.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid receipt format")
	}

	return receipt, nil
}

// getConfirmations gets the number of confirmations for a transaction
func (bc *BlockchainClient) getConfirmations(ctx context.Context, txHash string) (int, error) {
	receipt, err := bc.getTransactionReceipt(ctx, txHash)
	if err != nil {
		return 0, err
	}

	txBlockHex := getStringField(receipt, "blockNumber")
	if txBlockHex == "" {
		return 0, nil // Pending transaction
	}

	txBlockNum, err := strconv.ParseInt(txBlockHex[2:], 16, 64)
	if err != nil {
		return 0, err
	}

	latestBlock, err := bc.getLatestBlockNumber(ctx)
	if err != nil {
		return 0, err
	}

	confirmations := int(latestBlock - txBlockNum + 1)
	if confirmations < 0 {
		confirmations = 0
	}

	return confirmations, nil
}

// parseERC20Transfer parses an ERC-20 Transfer event from a log
func (bc *BlockchainClient) parseERC20Transfer(log Log, txHash string) (*ERC20Transfer, error) {
	// ERC-20 Transfer event signature: Transfer(address indexed from, address indexed to, uint256 value)
	// Topic[0] = keccak256("Transfer(address,address,uint256)")
	// Topic[1] = from address (padded)
	// Topic[2] = to address (padded)
	// Data = value (32 bytes)

	if len(log.Topics) < 3 {
		return nil, fmt.Errorf("insufficient topics for Transfer event")
	}

	// Verify this is a Transfer event
	transferSig := "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
	if !strings.EqualFold(log.Topics[0], transferSig) {
		return nil, fmt.Errorf("not a Transfer event")
	}

	// Extract addresses (remove padding)
	from := "0x" + log.Topics[1][26:] // Last 20 bytes (40 hex chars)
	to := "0x" + log.Topics[2][26:]   // Last 20 bytes (40 hex chars)

	// Extract value from data
	if len(log.Data) < 66 { // "0x" + 64 hex chars
		return nil, fmt.Errorf("invalid data length for Transfer event")
	}

	valueHex := log.Data[2:] // Remove "0x" prefix
	value, success := new(big.Int).SetString(valueHex, 16)
	if !success {
		return nil, fmt.Errorf("failed to parse transfer value")
	}

	return &ERC20Transfer{
		From:      from,
		To:        to,
		Value:     value,
		TokenAddr: log.Address,
		TxHash:    txHash,
	}, nil
}

// getTokenAddress gets the contract address for a token symbol
func (bc *BlockchainClient) getTokenAddress(symbol, network string) (string, error) {
	// Token addresses for common tokens on different networks
	// In a production system, this would be configurable or fetched from a service
	
	tokens := map[string]map[string]string{
		"ethereum": {
			"usdc": "0xA0b86a33E6441aBe0e45c5e9A4e5c10d9Fe60579",
			"usdt": "0xdAC17F958D2ee523a2206206994597C13D831ec7",
			"dai":  "0x6B175474E89094C44Da98b954EedeAC495271d0F",
		},
		"base": {
			"usdc": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
		},
		"base-sepolia": {
			"usdc": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
		},
	}

	networkTokens, exists := tokens[strings.ToLower(network)]
	if !exists {
		return "", fmt.Errorf("unsupported network: %s", network)
	}

	tokenAddr, exists := networkTokens[strings.ToLower(symbol)]
	if !exists {
		return "", fmt.Errorf("unsupported token %s on network %s", symbol, network)
	}

	return tokenAddr, nil
}

// makeRPCCall makes a JSON-RPC call to the blockchain endpoint
func (bc *BlockchainClient) makeRPCCall(ctx context.Context, method string, params interface{}) (interface{}, error) {
	request := RPCRequest{
		JSONRPC: "2.0",
		Method:  method,
		Params:  params,
		ID:      1,
	}

	reqBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal RPC request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", bc.RPCEndpoint, strings.NewReader(string(reqBody)))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := bc.HTTPClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var rpcResp RPCResponse
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal RPC response: %w", err)
	}

	if rpcResp.Error != nil {
		return nil, fmt.Errorf("RPC error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}

	return rpcResp.Result, nil
}

// getStringField safely extracts a string field from a map
func getStringField(m map[string]interface{}, field string) string {
	if value, exists := m[field]; exists {
		if str, ok := value.(string); ok {
			return str
		}
	}
	return ""
}