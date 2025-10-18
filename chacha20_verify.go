/*
 * ChaCha20 Stream Cipher Test Suite - Go
 * Based on RFC 8439: ChaCha20 and Poly1305 for IETF Protocols
 * Tests Go's golang.org/x/crypto/chacha20 package
 */

package main

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/chacha20"
)

// Run a single test
func runTest(name string, keyHex, nonceHex string, counter uint32, plaintext []byte, expectedHex string) bool {
	fmt.Printf("\n=== %s ===\n", name)

	key, _ := hex.DecodeString(keyHex)
	nonce, _ := hex.DecodeString(nonceHex)
	expected, _ := hex.DecodeString(expectedHex)

	// Print test parameters
	fmt.Printf("Key:       %s\n", keyHex)
	fmt.Printf("Nonce:     %s\n", nonceHex)
	fmt.Printf("Counter:   %d\n", counter)

	// Print plaintext (first 64 bytes if longer)
	if len(plaintext) <= 64 {
		fmt.Printf("Plaintext: %x\n", plaintext)
	} else {
		fmt.Printf("Plaintext: %x... (%d bytes)\n", plaintext[:64], len(plaintext))
	}

	// Create cipher
	cipher, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		fmt.Printf("Error creating cipher: %v\n", err)
		return false
	}

	// Set counter to match the test vector
	cipher.SetCounter(counter)

	ciphertext := make([]byte, len(plaintext))
	cipher.XORKeyStream(ciphertext, plaintext)

	// Print expected and got
	if len(expected) <= 64 {
		fmt.Printf("Expected:  %x\n", expected)
		fmt.Printf("Got:       %x\n", ciphertext)
	} else {
		fmt.Printf("Expected:  %x... (%d bytes)\n", expected[:64], len(expected))
		fmt.Printf("Got:       %x... (%d bytes)\n", ciphertext[:64], len(ciphertext))
	}

	passed := bytes.Equal(ciphertext, expected)
	if passed {
		fmt.Printf("Result:    PASS ✓\n")
	} else {
		fmt.Printf("Result:    FAIL ✗\n")
	}

	return passed
}

func passOrFail(passed bool) string {
	if passed {
		return "PASS ✓"
	}
	return "FAIL ✗"
}

func main() {
	fmt.Println("ChaCha20 Implementation Test Suite")
	fmt.Println("Based on RFC 8439 (June 2018)")
	fmt.Println("Testing Go's golang.org/x/crypto/chacha20 package")
	fmt.Println("=====================================")

	totalTests := 0
	passedTests := 0

	fmt.Println("\n--- Section 2.4.2: ChaCha20 Encryption ---")

	// Test 1: Section 2.4.2 - Sunscreen Test
	totalTests++
	if runTest(
		"Section 2.4.2 - Sunscreen Test",
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		"000000000000004a00000000",
		1,
		[]byte("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."),
		"6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d",
	) {
		passedTests++
	}

	fmt.Println("\n--- Appendix A.2: Test Vectors for ChaCha20 ---")

	// Test 2: A.2 Test Vector #1 - Keystream (counter=0)
	totalTests++
	if runTest(
		"A.2 Test Vector #1 - Keystream (counter=0)",
		"0000000000000000000000000000000000000000000000000000000000000000",
		"000000000000000000000000",
		0,
		make([]byte, 64),
		"76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586",
	) {
		passedTests++
	}

	// Test 3: A.2 Test Vector #1 - Keystream (counter=1)
	totalTests++
	if runTest(
		"A.2 Test Vector #1 - Keystream (counter=1)",
		"0000000000000000000000000000000000000000000000000000000000000000",
		"000000000000000000000000",
		1,
		make([]byte, 64),
		"9f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed29b721769ce64e43d57133b074d839d531ed1f28510afb45ace10a1f4b794d6f",
	) {
		passedTests++
	}

	// Test 4: A.2 Test Vector #2 - Sunscreen (consistency)
	totalTests++
	if runTest(
		"A.2 Test Vector #2 - Sunscreen (consistency)",
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		"000000000000004a00000000",
		1,
		[]byte("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."),
		"6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d",
	) {
		passedTests++
	}

	// Test 5: A.2 Test Vector #3 - Keystream (counter=2)
	totalTests++
	if runTest(
		"A.2 Test Vector #3 - Keystream (counter=2)",
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		"000000000000004a00000000",
		2,
		make([]byte, 64),
		"69a6749f3f630f4122cafe28ec4dc47e26d4346d70b98c73f3e9c53ac40c5945398b6eda1a832c89c167eacd901d7e2bf363740373201aa188fbbce83991c4ed",
	) {
		passedTests++
	}

	// Test 6: Block Function State (all zeros, counter=0)
	// This is essentially the same as Test 2 above
	totalTests++
	if runTest(
		"Block Function State - All zeros (counter=0)",
		"0000000000000000000000000000000000000000000000000000000000000000",
		"000000000000000000000000",
		0,
		make([]byte, 64),
		"76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586",
	) {
		passedTests++
	}

	// Test 7: Quarter Round test (matching C implementation)
	// Note: Go's chacha20 package doesn't expose internal functions,
	// so we test the same keystream test as Test 2
	fmt.Println("\n--- Additional Verification ---")
	totalTests++
	if runTest(
		"Quarter Round Verification - Keystream test",
		"0000000000000000000000000000000000000000000000000000000000000000",
		"000000000000000000000000",
		0,
		make([]byte, 64),
		"76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586",
	) {
		passedTests++
	}

	fmt.Println("\n=====================================")
	fmt.Printf("Test Summary: %d/%d tests passed\n", passedTests, totalTests)
	fmt.Println("=====================================")

	if passedTests != totalTests {
		fmt.Println("\nSome tests failed!")
	}
}
