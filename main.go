package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)
// Estrutura para os dados da requisição
type DeployTransactionRequest struct {
	WalletID       string   `json:"walletID"`
	Owner          string   `json:"owner"`
	BaseURI        string   `json:"baseURI"`
	Name           string   `json:"name"`
	Symbol         string   `json:"symbol"`
	Backend        string   `json:"backend"`
	AddressWithdraw string   `json:"addressWithdraw"`
	MaxSupplyEach  []uint64 `json:"maxSupplyEach"`
	ReqSignature   bool     `json:"reqSignature"`
	Salt           string   `json:"salt"`
}

type MintTransactionRequest struct {
	WalletID string   `json:"walletID"`
	Owner    string   `json:"owner"`
	Quantity uint64   `json:"quantity"`
	IDs      []uint64 `json:"ids"`
	Salt     string   `json:"salt"`
}


// InitiateDeployTransaction inicia uma transação para deploy de contrato
func InitiateDeployTransaction(walletID, owner, baseURI, name, symbol, backend, addressWithdraw string, maxSupplyEach []uint64, reqSignature bool, salt, signature string) (string, error) {
	authToken := os.Getenv("LUMX_AUTH_TOKEN")
	client := &http.Client{}

	transactionPayload := map[string]interface{}{
		"walletId":        walletID,
		"contractAddress": "0xB7A020dDf59DBFfC2FE172C78C109E2025B1f387",
		"operations": []map[string]interface{}{
			{
				"functionSignature": "deployERC721AOld(address,string,string,string,address,address,uint256[],bool,string,bytes)",
				"argumentsValues": []interface{}{
					owner, baseURI, name, symbol, backend, addressWithdraw, maxSupplyEach, reqSignature, salt, signature,
				},
			},
		},
	}

	payloadBytes, err := json.Marshal(transactionPayload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal payload: %v", err)
	}
	req, err := http.NewRequest("POST", "https://protocol-staging.int.lumx.io/v2/transactions/custom", bytes.NewReader(payloadBytes))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+authToken)
	req.Header.Set("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to execute request: %v", err)
	}
	defer res.Body.Close()

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		bodyBytes, _ := io.ReadAll(res.Body)
		return "", fmt.Errorf("API request failed with status %d: %s", res.StatusCode, string(bodyBytes))
	}

	var transactionResponse map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&transactionResponse); err != nil {
		return "", fmt.Errorf("failed to parse response: %v", err)
	}

	transactionID, ok := transactionResponse["id"].(string)
	if !ok {
		return "", fmt.Errorf("failed to parse transaction ID from response: %+v", transactionResponse)
	}

	return transactionID, nil
}

// InitiateMintTransaction inicia uma transação de mint
func InitiateMintTransaction(walletID string, quantity uint64, ids []uint64, salt, signature string) (string, error) {
	authToken := os.Getenv("LUMX_AUTH_TOKEN")
	client := &http.Client{}

	transactionPayload := map[string]interface{}{
		"walletId":        walletID,
		"contractAddress": "0x841e6D1dcf65ca10e2f04D3c04c837B6dba5a673",
		"operations": []map[string]interface{}{
			{
				"functionSignature": "mint(uint256,uint256[],string,bytes)",
				"argumentsValues": []interface{}{
					quantity, ids, salt, signature,
				},
			},
		},
	}

	payloadBytes, err := json.Marshal(transactionPayload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal payload: %v", err)
	}
	req, err := http.NewRequest("POST", "https://protocol-staging.int.lumx.io/v2/transactions/custom", bytes.NewReader(payloadBytes))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+authToken)
	req.Header.Set("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to execute request: %v", err)
	}
	defer res.Body.Close()

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		bodyBytes, _ := io.ReadAll(res.Body)
		return "", fmt.Errorf("API request failed with status %d: %s", res.StatusCode, string(bodyBytes))
	}

	var transactionResponse map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&transactionResponse); err != nil {
		return "", fmt.Errorf("failed to parse response: %v", err)
	}

	transactionID, ok := transactionResponse["id"].(string)
	if !ok {
		return "", fmt.Errorf("failed to parse transaction ID from response: %+v", transactionResponse)
	}

	return transactionID, nil
}

// generateSignature gera o hash e assina os dados
func generateSignature(contractAddress, msgSender, salt string, blockchainID uint64) (string, error) {
	contractAddressBytes := common.HexToAddress(contractAddress).Bytes()
	msgSenderBytes := common.HexToAddress(msgSender).Bytes()

	blockchainIDBigInt := new(big.Int).SetUint64(blockchainID)
	blockchainIDBytes := blockchainIDBigInt.FillBytes(make([]byte, 32))

	saltBytes := []byte(salt)

	dataToHash := append(contractAddressBytes, msgSenderBytes...)
	dataToHash = append(dataToHash, blockchainIDBytes...)
	dataToHash = append(dataToHash, saltBytes...)

	innerHash := crypto.Keccak256Hash(dataToHash)

	prefix := []byte("\x19Ethereum Signed Message:\n32")
	prefixedMessage := append(prefix, innerHash.Bytes()...)
	finalHash := crypto.Keccak256Hash(prefixedMessage)

	privateKeyHex := os.Getenv("PRIVATE_KEY_HEX")
	privateKey, err := crypto.HexToECDSA(privateKeyHex)
	if err != nil {
		return "", fmt.Errorf("failed to load private key: %v", err)
	}

	signatureBytes, err := crypto.Sign(finalHash.Bytes(), privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign data: %v", err)
	}

	return "0x" + hex.EncodeToString(signatureBytes), nil
}

// Handler para testar InitiateDeployTransaction
func handleDeployTransaction(c *gin.Context) {
	var req DeployTransactionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request data", "details": err.Error()})
		return
	}

	contractAddress := "0xB7A020dDf59DBFfC2FE172C78C109E2025B1f387"
	blockchainID := uint64(80002)

	// Gerar a assinatura
	signature, err := generateSignature(contractAddress, req.Owner, req.Salt, blockchainID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate signature", "details": err.Error()})
		return
	}

	// Iniciar a transação de deploy
	transactionID, err := InitiateDeployTransaction(
		req.WalletID,
		req.Owner,
		req.BaseURI,
		req.Name,
		req.Symbol,
		req.Backend,
		req.AddressWithdraw,
		req.MaxSupplyEach,
		req.ReqSignature,
		req.Salt,
		signature,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to initiate deploy transaction", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"transactionID": transactionID})
}

// Handler para testar InitiateMintTransaction
func handleMintTransaction(c *gin.Context) {
	var req MintTransactionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request data", "details": err.Error()})
		return
	}

	contractAddress := "0x841e6D1dcf65ca10e2f04D3c04c837B6dba5a673"
	blockchainID := uint64(80002)

	// Gerar a assinatura
	signature, err := generateSignature(contractAddress, req.Owner, req.Salt, blockchainID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate signature", "details": err.Error()})
		return
	}

	// Iniciar a transação de mint
	transactionID, err := InitiateMintTransaction(
		req.WalletID,
		req.Quantity,
		req.IDs,
		req.Salt,
		signature,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to initiate mint transaction", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"transactionID": transactionID})
}


//usando diretamente a smartwalletFunction:

// Estrutura da requisição para a assinatura
type SignRequest struct {
	Message string `json:"message"`
}

// Estrutura da resposta da assinatura
type SignerRequest struct {
	Messages []string `json:"messages"`
	Hashed   bool     `json:"hashed"`
	Format   string   `json:"format"`
	Signer   struct {
		VersionID string `json:"versionId"`
		ClientID  string `json:"clientId"`
	} `json:"signer"`
}

type SignerResponse struct {
	Signatures []string `json:"signatures"`
	Address    string   `json:"address"`
}

// SignMessageWithLocalSigner assina uma mensagem localmente
func SignMessageWithLocalSigner(message string) ([]byte, string, error) {
	requestBody := SignerRequest{
		Messages: []string{message},
		Hashed:   true,
		Format:   "hex",
		Signer: struct {
			VersionID string `json:"versionId"`
			ClientID  string `json:"clientId"`
		}{
			VersionID: "1",
			ClientID:  "e94aecb1-5daf-47f3-948f-2a639a56baa6",
		},
	}

	payloadBytes, err := json.Marshal(requestBody)
	if err != nil {
		return nil, "", fmt.Errorf("failed to marshal payload: %v", err)
	}

	req, err := http.NewRequest("POST", "http://localhost:8000/sign", bytes.NewBuffer(payloadBytes))
	if err != nil {
		return nil, "", fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("failed to execute request: %v", err)
	}
	defer res.Body.Close()

	var response SignerResponse
	if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
		return nil, "", fmt.Errorf("failed to parse response: %v", err)
	}

	if len(response.Signatures) == 0 {
		return nil, "", fmt.Errorf("no signature returned from local signer")
	}

	signatureBytes, err := hex.DecodeString(strings.TrimPrefix(response.Signatures[0], "0x"))
	if err != nil {
		return nil, "", fmt.Errorf("failed to decode signature: %v", err)
	}

	return signatureBytes, response.Address, nil
}

// Handler para `InitiateDeployTransaction`
func handleDeployTransactionSmartWallet(c *gin.Context) {
	var req DeployTransactionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request data", "details": err.Error()})
		return
	}

	// Definições
	contractAddress := "0xB7A020dDf59DBFfC2FE172C78C109E2025B1f387"
	blockchainID := uint64(80002)

	// Gerar hash para assinatura
	dataToSign, err := generateDataToSign(contractAddress, req.Owner, req.Salt, blockchainID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate data to sign", "details": err.Error()})
		return
	}

	// Gerar assinatura
	signatureBytes, hsmAddress, err := SignMessageWithLocalSigner(hex.EncodeToString(dataToSign))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to sign message", "details": err.Error()})
		return
	}
	log.Printf("HSM Address: %s", hsmAddress)

	// Converter assinatura para string hexadecimal
	signatureHex := "0x" + hex.EncodeToString(signatureBytes)

	// Iniciar a transação
	transactionID, err := InitiateDeployTransaction(
		req.WalletID,
		req.Owner,
		req.BaseURI,
		req.Name,
		req.Symbol,
		req.Backend,
		req.AddressWithdraw,
		req.MaxSupplyEach,
		req.ReqSignature,
		req.Salt,
		signatureHex,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to initiate deploy transaction", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"transactionID": transactionID})
}

// Handler para `InitiateMintTransaction`
func handleMintTransactionSmartWallet(c *gin.Context) {
	var req MintTransactionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request data", "details": err.Error()})
		return
	}

	// Definições
	contractAddress := "0x841e6D1dcf65ca10e2f04D3c04c837B6dba5a673"
	blockchainID := uint64(80002)

	// Gerar hash para assinatura
	dataToSign, err := generateDataToSign(contractAddress, req.Owner, req.Salt, blockchainID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate data to sign", "details": err.Error()})
		return
	}

	// Gerar assinatura
	signatureBytes, hsmAddress, err := SignMessageWithLocalSigner(hex.EncodeToString(dataToSign))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to sign message", "details": err.Error()})
		return
	}
	log.Printf("HSM Address: %s", hsmAddress)

	// Converter assinatura para string hexadecimal
	signatureHex := "0x" + hex.EncodeToString(signatureBytes)

	// Iniciar a transação
	transactionID, err := InitiateMintTransaction(
		req.WalletID,
		req.Quantity,
		req.IDs,
		req.Salt,
		signatureHex,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to initiate mint transaction", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"transactionID": transactionID})
}

// Função auxiliar para gerar os dados a serem assinados
func generateDataToSign(contractAddress, msgSender, salt string, blockchainID uint64) ([]byte, error) {
	contractAddressBytes := common.HexToAddress(contractAddress).Bytes()
	msgSenderBytes := common.HexToAddress(msgSender).Bytes()

	blockchainIDBigInt := new(big.Int).SetUint64(blockchainID)
	blockchainIDBytes := blockchainIDBigInt.FillBytes(make([]byte, 32))

	saltBytes := []byte(salt)

	dataToHash := append(contractAddressBytes, msgSenderBytes...)
	dataToHash = append(dataToHash, blockchainIDBytes...)
	dataToHash = append(dataToHash, saltBytes...)

	innerHash := crypto.Keccak256Hash(dataToHash)

	prefix := []byte("\x19Ethereum Signed Message:\n32")
	prefixedMessage := append(prefix, innerHash.Bytes()...)
	finalHash := crypto.Keccak256Hash(prefixedMessage)

	return finalHash.Bytes(), nil
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	r := gin.Default()
	r.Use(cors.Default())

	// Rotas POST
	r.POST("/deploy", handleDeployTransaction)
	r.POST("/mint", handleMintTransaction)

	r.POST("/deploy-smart-wallet", handleDeployTransactionSmartWallet)
	r.POST("/mint-smart-wallet", handleMintTransactionSmartWallet)


	log.Println("Server running on port 8080")
	r.Run(":8080")
}
