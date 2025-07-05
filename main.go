package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"time"
)

// Transaction represents a Bitcoin transaction
type Transaction struct {
	ID      string
	Inputs  []TxInput
	Outputs []TxOutput
}

// TxInput represents a transaction input
type TxInput struct {
	TxID      string
	OutIdx    int
	Signature string
	PubKey    string
}

// TxOutput represents a transaction output
type TxOutput struct {
	Value  int
	PubKey string
}

// Block represents a block in the blockchain
type Block struct {
	Timestamp    int64
	Transactions []*Transaction
	PrevHash     []byte
	Hash         []byte
	Nonce        int
}

// Blockchain represents the blockchain
type Blockchain struct {
	Blocks []*Block
}

// NewBlock creates a new block
func NewBlock(transactions []*Transaction, prevHash []byte) *Block {
	block := &Block{
		Timestamp:    time.Now().Unix(),
		Transactions: transactions,
		PrevHash:     prevHash,
		Hash:         []byte{},
		Nonce:        0,
	}
	block.Hash = block.CalculateHash()
	return block
}

// CalculateHash calculates the block hash
func (b *Block) CalculateHash() []byte {
	record := string(b.Timestamp) + hex.EncodeToString(b.PrevHash)
	for _, tx := range b.Transactions {
		record += tx.ID
	}
	h := sha256.New()
	h.Write([]byte(record))
	hashed := h.Sum(nil)
	return hashed
}

// NewGenesisBlock creates the genesis block
func NewGenesisBlock() *Block {
	return NewBlock([]*Transaction{}, []byte{})
}

// NewBlockchain creates a new blockchain
func NewBlockchain() *Blockchain {
	return &Blockchain{[]*Block{NewGenesisBlock()}}
}

// SetID calculates the transaction hash ID
func (tx *Transaction) SetID() error {
	var buf bytes.Buffer
	for _, input := range tx.Inputs {
		buf.WriteString(input.TxID)
		buf.WriteString(strconv.Itoa(input.OutIdx))
		buf.WriteString(input.Signature)
		buf.WriteString(input.PubKey)
	}
	for _, output := range tx.Outputs {
		buf.WriteString(strconv.Itoa(output.Value))
		buf.WriteString(output.PubKey)
	}
	hash := sha256.Sum256(buf.Bytes())
	tx.ID = hex.EncodeToString(hash[:])
	return nil
}

// CreateSampleTransaction creates a sample transaction (using real keys)
func CreateSampleTransaction(senderPrivKey *ecdsa.PrivateKey, senderPubKey, receiverPubKey string) *Transaction {

	// Create transaction structure
	tx := &Transaction{
		Inputs: []TxInput{
			{
				TxID:   "0000000000000000000000000000000000000000000000000000000000000000", // Genesis transaction ID
				OutIdx: 0,
				PubKey: senderPubKey,
			},
		},
		Outputs: []TxOutput{
			{
				Value:  10,
				PubKey: receiverPubKey,
			},
		},
	}

	// Calculate transaction ID
	tx.SetID()

	// Sign the transaction ID
	txHash, _ := hex.DecodeString(tx.ID)
	signature, err := SignData(senderPrivKey, txHash)
	if err != nil {
		panic(err)
	}

	// Set the signature
	tx.Inputs[0].Signature = signature

	return tx
}

// SerializeTransaction serializes transaction in Bitcoin style
func (tx *Transaction) Serialize() ([]byte, error) {
	var buf bytes.Buffer

	if err := binary.Write(&buf, binary.LittleEndian, uint32(1)); err != nil {
		return nil, err
	}

	if err := binary.Write(&buf, binary.LittleEndian, uint32(len(tx.Inputs))); err != nil {
		return nil, err
	}

	for _, input := range tx.Inputs {
		txid, err := hex.DecodeString(input.TxID)
		if err != nil {
			return nil, err
		}
		if _, err := buf.Write(txid); err != nil {
			return nil, err
		}

		if err := binary.Write(&buf, binary.LittleEndian, uint32(input.OutIdx)); err != nil {
			return nil, err
		}

		if err := writeVarStr(&buf, input.Signature); err != nil {
			return nil, err
		}
		if err := writeVarStr(&buf, input.PubKey); err != nil {
			return nil, err
		}
	}

	if err := binary.Write(&buf, binary.LittleEndian, uint32(len(tx.Outputs))); err != nil {
		return nil, err
	}

	for _, output := range tx.Outputs {
		if err := binary.Write(&buf, binary.LittleEndian, uint64(output.Value)); err != nil {
			return nil, err
		}

		if err := writeVarStr(&buf, output.PubKey); err != nil {
			return nil, err
		}
	}

	if err := binary.Write(&buf, binary.LittleEndian, uint32(0)); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// writeVarStr writes variable length string (Bitcoin format)
func writeVarStr(buf *bytes.Buffer, s string) error {
	if err := binary.Write(buf, binary.LittleEndian, uint32(len(s))); err != nil {
		return err
	}
	if _, err := buf.WriteString(s); err != nil {
		return err
	}
	return nil
}

// SaveTransactionToFile saves transaction as binary file in Bitcoin format
func SaveTransactionToFile(tx *Transaction, baseDir string) error {
	// Ensure directory exists
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return err
	}

	// Find latest file number
	files, err := os.ReadDir(baseDir)
	if err != nil {
		return err
	}

	fileNum := 1
	if len(files) > 0 {
		// Get the highest file number
		for _, file := range files {
			var n int
			_, err := fmt.Sscanf(file.Name(), "%d.dat", &n)
			if err == nil && n >= fileNum {
				fileNum = n + 1
			}
		}
	}

	// Check latest file size
	currentFile := fmt.Sprintf("%s/%d.dat", baseDir, fileNum)
	if fileNum > 1 {
		prevFile := fmt.Sprintf("%s/%d.dat", baseDir, fileNum-1)
		if fi, err := os.Stat(prevFile); err == nil {
			if fi.Size() < 160*1024*1024 {
				currentFile = prevFile
				fileNum--
			}
		}
	}

	// Serialize transaction data
	data, err := tx.Serialize()
	if err != nil {
		return err
	}

	// Write to file
	return os.WriteFile(currentFile, data, 0644)
}

// GenerateKeyPair generates ECDSA key pair
func GenerateKeyPair() (*ecdsa.PrivateKey, string, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", err
	}

	pubKey := append(
		privateKey.PublicKey.X.Bytes(),
		privateKey.PublicKey.Y.Bytes()...,
	)

	return privateKey, hex.EncodeToString(pubKey), nil
}

// SignData signs data using private key
func SignData(privateKey *ecdsa.PrivateKey, data []byte) (string, error) {
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, data)
	if err != nil {
		return "", err
	}
	signature := append(r.Bytes(), s.Bytes()...)
	return hex.EncodeToString(signature), nil
}

func main() {
	bc := NewBlockchain()
	_ = bc

	// Generate sender key pair
	senderPrivKey, senderPubKey, err := GenerateKeyPair()
	if err != nil {
		panic(err)
	}

	// Generate receiver public key
	_, receiverPubKey, err := GenerateKeyPair()
	if err != nil {
		panic(err)
	}

	// Create and save sample transaction to transactions directory
	tx := CreateSampleTransaction(senderPrivKey, senderPubKey, receiverPubKey)
	err = SaveTransactionToFile(tx, "transactions")
	if err != nil {
		panic(err)
	}
}
