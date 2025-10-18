/*
 * ChaCha20 CLI Wrapper for Go Implementation
 * Accepts hex-encoded key, nonce, counter, and plaintext as arguments
 * Outputs hex-encoded ciphertext
 */

package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"strconv"

	"golang.org/x/crypto/chacha20"
)

func main() {
	if len(os.Args) != 5 {
		fmt.Fprintf(os.Stderr, "Usage: %s <key_hex> <nonce_hex> <counter> <plaintext_hex>\n", os.Args[0])
		os.Exit(1)
	}

	keyHex := os.Args[1]
	nonceHex := os.Args[2]
	counterStr := os.Args[3]
	plaintextHex := os.Args[4]

	// Decode key
	key, err := hex.DecodeString(keyHex)
	if err != nil || len(key) != 32 {
		fmt.Fprintf(os.Stderr, "Error: Key must be 64 hex characters (32 bytes)\n")
		os.Exit(1)
	}

	// Decode nonce
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil || len(nonce) != 12 {
		fmt.Fprintf(os.Stderr, "Error: Nonce must be 24 hex characters (12 bytes)\n")
		os.Exit(1)
	}

	// Parse counter
	counter, err := strconv.ParseUint(counterStr, 10, 32)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Invalid counter: %v\n", err)
		os.Exit(1)
	}

	// Decode plaintext
	plaintext, err := hex.DecodeString(plaintextHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Invalid plaintext hex: %v\n", err)
		os.Exit(1)
	}

	// Create cipher
	cipher, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating cipher: %v\n", err)
		os.Exit(1)
	}

	// Set counter
	cipher.SetCounter(uint32(counter))

	// Encrypt
	ciphertext := make([]byte, len(plaintext))
	cipher.XORKeyStream(ciphertext, plaintext)

	// Output as hex
	fmt.Printf("%s\n", hex.EncodeToString(ciphertext))
}
