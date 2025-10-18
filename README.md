# ChaCha20 Stream Cipher Implementation

A complete, compilable, and testable implementation of the ChaCha20 stream cipher based on RFC 8439.

## Features

- Full ChaCha20 implementation according to RFC 8439
- Multiple test vectors from the official specification
- Automatic test execution with pass/fail reporting
- Clean, readable C code with comprehensive comments

## Compilation

### Using Make
```bash
cd /home/fosres/Personal/fosres/claude
make
```

### Using GCC directly
```bash
gcc -Wall -Wextra -std=c99 -O2 -o chacha20_test chacha20_cursor.c
```

### Using simple GCC
```bash
gcc chacha20_cursor.c -o chacha20_test
```

## Running

After compilation, run the tests:
```bash
./chacha20_test
```

## Test Vectors

The program includes 4 official test vectors from RFC 8439:

1. **Section 2.4.2 - "Sunscreen" Test**: The classic example from the RFC with the famous quote
2. **Appendix A.2 - All Zeros**: Tests with all-zero key, nonce, and plaintext
3. **Block Function Test**: Validates the core ChaCha20 block function
4. **Multi-block Counter Test**: Verifies proper counter increment across multiple blocks

## Expected Output

When you run the program, it will:
- Display each test vector's parameters (key, nonce, counter)
- Show the plaintext, expected ciphertext, and actual output
- Print "PASS ✓" or "FAIL ✗" for each test
- Provide a summary of test results

All tests should pass with the message:
```
Test Summary: 4/4 tests passed
```

## Implementation Details

The implementation includes:
- `chacha20_init_state()`: Initializes the ChaCha20 state matrix
- `chacha20_block()`: Performs the 20-round ChaCha20 block function
- `chacha20_encrypt()`: Main encryption/decryption function
- Quarter Round (QR) macro: Core ChaCha20 operation
- Little-endian conversion helpers

## RFC 8439 Reference

This implementation follows RFC 8439:
https://www.rfc-editor.org/rfc/rfc8439.html

ChaCha20 is a stream cipher developed by Daniel J. Bernstein, offering high security and excellent performance on modern CPUs.
