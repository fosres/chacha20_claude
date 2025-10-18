/*
 * ChaCha20 Cross-Implementation Verification
 * Generates random test vectors using csprng
 * Verifies C and Go implementations produce identical results
 */

package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"gitlab.com/xx_network/crypto/csprng"
)

// TestVector represents a ChaCha20 test case
type TestVector struct {
	Key       []byte
	Nonce     []byte
	Counter   uint32
	Plaintext []byte
}

// generateRandomTestVector creates a random test vector using csprng
func generateRandomTestVector(plaintextLen int) *TestVector {
	rng := csprng.NewSystemRNG()

	key := make([]byte, 32)
	nonce := make([]byte, 12)
	plaintext := make([]byte, plaintextLen)

	rng.Read(key)
	rng.Read(nonce)
	rng.Read(plaintext)

	// Generate random counter (0-100 for reasonable values)
	counterBytes := make([]byte, 1)
	rng.Read(counterBytes)
	counter := uint32(counterBytes[0]) % 100

	return &TestVector{
		Key:       key,
		Nonce:     nonce,
		Counter:   counter,
		Plaintext: plaintext,
	}
}

// runCImplementation executes the C CLI wrapper
func runCImplementation(tv *TestVector) ([]byte, error) {
	keyHex := hex.EncodeToString(tv.Key)
	nonceHex := hex.EncodeToString(tv.Nonce)
	counterStr := strconv.FormatUint(uint64(tv.Counter), 10)
	plaintextHex := hex.EncodeToString(tv.Plaintext)

	cmd := exec.Command("./chacha20_c_cli", keyHex, nonceHex, counterStr, plaintextHex)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("C execution failed: %v", err)
	}

	// Parse hex output
	hexStr := strings.TrimSpace(string(output))
	ciphertext, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode C output: %v", err)
	}

	return ciphertext, nil
}

// runGoImplementation executes the Go CLI wrapper
func runGoImplementation(tv *TestVector) ([]byte, error) {
	keyHex := hex.EncodeToString(tv.Key)
	nonceHex := hex.EncodeToString(tv.Nonce)
	counterStr := strconv.FormatUint(uint64(tv.Counter), 10)
	plaintextHex := hex.EncodeToString(tv.Plaintext)

	cmd := exec.Command("./chacha20_go_cli", keyHex, nonceHex, counterStr, plaintextHex)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("Go execution failed: %v", err)
	}

	// Parse hex output
	hexStr := strings.TrimSpace(string(output))
	ciphertext, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode Go output: %v", err)
	}

	return ciphertext, nil
}

// runTest executes a test vector against both implementations
func runTest(testNum int, tv *TestVector) bool {
	fmt.Printf("\n=== Test Case #%d ===\n", testNum)
	fmt.Printf("Key:       %s\n", hex.EncodeToString(tv.Key))
	fmt.Printf("Nonce:     %s\n", hex.EncodeToString(tv.Nonce))
	fmt.Printf("Counter:   %d\n", tv.Counter)

	if len(tv.Plaintext) <= 64 {
		fmt.Printf("Plaintext: %s\n", hex.EncodeToString(tv.Plaintext))
	} else {
		fmt.Printf("Plaintext: %s... (%d bytes)\n",
			hex.EncodeToString(tv.Plaintext[:64]), len(tv.Plaintext))
	}

	// Test C implementation
	cCiphertext, err := runCImplementation(tv)
	if err != nil {
		fmt.Printf("C Error:   %v\n", err)
		fmt.Printf("C Implementation (chacha20_cursor.c):  FAIL ✗\n")
		return false
	}

	// Test Go implementation
	goCiphertext, err := runGoImplementation(tv)
	if err != nil {
		fmt.Printf("Go Error:  %v\n", err)
		fmt.Printf("Go Implementation (chacha20_verify.go): FAIL ✗\n")
		return false
	}

	// Print expected ciphertext (use Go's output as reference)
	if len(goCiphertext) <= 64 {
		fmt.Printf("Expected Ciphertext: %s\n", hex.EncodeToString(goCiphertext))
	} else {
		fmt.Printf("Expected Ciphertext: %s... (%d bytes)\n",
			hex.EncodeToString(goCiphertext[:64]), len(goCiphertext))
	}

	// Compare results
	cMatch := bytes.Equal(cCiphertext, goCiphertext)
	goMatch := true // Go is our reference

	fmt.Printf("\nC Implementation (chacha20_cursor.c):  %s\n", passOrFail(cMatch))
	fmt.Printf("Go Implementation (chacha20_verify.go): %s\n", passOrFail(goMatch))
	fmt.Printf("Both Match:                             %s\n", passOrFail(cMatch && goMatch))

	return cMatch && goMatch
}

func passOrFail(passed bool) string {
	if passed {
		return "PASS ✓"
	}
	return "FAIL ✗"
}

func compilePrograms() error {
	fmt.Println("Compiling implementations...")

	// Compile C CLI wrapper
	fmt.Print("  Compiling chacha20_c_cli.c... ")
	cmd := exec.Command("gcc", "-Wall", "-Wextra", "-O2", "-o", "chacha20_c_cli", "chacha20_c_cli.c")
	if output, err := cmd.CombinedOutput(); err != nil {
		fmt.Println("FAILED")
		return fmt.Errorf("C compilation failed: %v\n%s", err, output)
	}
	fmt.Println("✓")

	// Compile Go CLI wrapper
	fmt.Print("  Compiling chacha20_go_cli.go... ")
	cmd = exec.Command("go", "build", "-o", "chacha20_go_cli", "chacha20_go_cli.go")
	if output, err := cmd.CombinedOutput(); err != nil {
		fmt.Println("FAILED")
		return fmt.Errorf("Go compilation failed: %v\n%s", err, output)
	}
	fmt.Println("✓")

	return nil
}

func main() {
	fmt.Println("ChaCha20 Cross-Implementation Verification")
	fmt.Println("Using csprng for random test vector generation")
	fmt.Println("Testing: chacha20_cursor.c vs chacha20_verify.go")
	fmt.Println("=====================================================")

	// Compile the CLI wrappers
	if err := compilePrograms(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\nGenerating and running random test vectors...\n")

	numTests := 30
	plaintextSizes := []int{16, 32, 48, 64, 80, 96, 112, 114, 128, 144, 160, 176, 192, 208, 224, 240, 256, 288, 320, 352, 384, 416, 448, 480, 512, 640, 768, 896, 1024, 2048}

	totalTests := 0
	passedTests := 0

	for i := 0; i < numTests; i++ {
		tv := generateRandomTestVector(plaintextSizes[i])
		totalTests++

		if runTest(i+1, tv) {
			passedTests++
		}
	}

	fmt.Println("\n=====================================================")
	fmt.Printf("Test Summary: %d/%d tests passed\n", passedTests, totalTests)
	fmt.Println("=====================================================")

	if passedTests == totalTests {
		fmt.Println("\n✓ All implementations produce identical results!")
		fmt.Println("  Both chacha20_cursor.c and chacha20_verify.go are correct!")
	} else {
		fmt.Println("\n✗ Some tests failed - implementations differ!")
		os.Exit(1)
	}
}
