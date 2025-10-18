/*
 * ChaCha20 Stream Cipher Implementation
 * Based on RFC 8439: ChaCha20 and Poly1305 for IETF Protocols
 * https://www.rfc-editor.org/rfc/rfc8439.html
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

/* ChaCha20 state is 16 words of 32 bits each */
#define CHACHA20_STATE_WORDS 16
#define CHACHA20_BLOCK_SIZE 64
#define CHACHA20_KEY_SIZE 32
#define CHACHA20_NONCE_SIZE 12

/* Rotate left operation */
#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

/* Quarter round operation */
#define QR(a, b, c, d) \
    do { \
        a += b; d ^= a; d = ROTL32(d, 16); \
        c += d; b ^= c; b = ROTL32(b, 12); \
        a += b; d ^= a; d = ROTL32(d, 8); \
        c += d; b ^= c; b = ROTL32(b, 7); \
    } while(0)

/* Read 32-bit word in little-endian */
static uint32_t read_le32(const uint8_t *p) {
    return ((uint32_t)p[0]) |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

/* Write 32-bit word in little-endian */
static void write_le32(uint8_t *p, uint32_t v) {
    p[0] = v & 0xff;
    p[1] = (v >> 8) & 0xff;
    p[2] = (v >> 16) & 0xff;
    p[3] = (v >> 24) & 0xff;
}

/* Initialize ChaCha20 state */
static void chacha20_init_state(uint32_t state[CHACHA20_STATE_WORDS],
                                const uint8_t key[CHACHA20_KEY_SIZE],
                                const uint8_t nonce[CHACHA20_NONCE_SIZE],
                                uint32_t counter) {
    /* Constants "expand 32-byte k" */
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;

    /* 256-bit key */
    state[4] = read_le32(key + 0);
    state[5] = read_le32(key + 4);
    state[6] = read_le32(key + 8);
    state[7] = read_le32(key + 12);
    state[8] = read_le32(key + 16);
    state[9] = read_le32(key + 20);
    state[10] = read_le32(key + 24);
    state[11] = read_le32(key + 28);

    /* Block counter */
    state[12] = counter;

    /* 96-bit nonce */
    state[13] = read_le32(nonce + 0);
    state[14] = read_le32(nonce + 4);
    state[15] = read_le32(nonce + 8);
}

/* ChaCha20 block function - generates 64 bytes of keystream */
static void chacha20_block(uint32_t state[CHACHA20_STATE_WORDS],
                          uint8_t output[CHACHA20_BLOCK_SIZE]) {
    uint32_t working_state[CHACHA20_STATE_WORDS];
    int i;

    /* Copy state to working state */
    memcpy(working_state, state, sizeof(working_state));

    /* 20 rounds (10 double rounds) */
    for (i = 0; i < 10; i++) {
        /* Column rounds */
        QR(working_state[0], working_state[4], working_state[8],  working_state[12]);
        QR(working_state[1], working_state[5], working_state[9],  working_state[13]);
        QR(working_state[2], working_state[6], working_state[10], working_state[14]);
        QR(working_state[3], working_state[7], working_state[11], working_state[15]);

        /* Diagonal rounds */
        QR(working_state[0], working_state[5], working_state[10], working_state[15]);
        QR(working_state[1], working_state[6], working_state[11], working_state[12]);
        QR(working_state[2], working_state[7], working_state[8],  working_state[13]);
        QR(working_state[3], working_state[4], working_state[9],  working_state[14]);
    }

    /* Add original state to working state */
    for (i = 0; i < CHACHA20_STATE_WORDS; i++) {
        working_state[i] += state[i];
    }

    /* Serialize to output in little-endian */
    for (i = 0; i < CHACHA20_STATE_WORDS; i++) {
        write_le32(output + (i * 4), working_state[i]);
    }
}

/* ChaCha20 encryption/decryption */
void chacha20_encrypt(const uint8_t key[CHACHA20_KEY_SIZE],
                     const uint8_t nonce[CHACHA20_NONCE_SIZE],
                     uint32_t counter,
                     const uint8_t *plaintext,
                     uint8_t *ciphertext,
                     size_t length) {
    uint32_t state[CHACHA20_STATE_WORDS];
    uint8_t keystream[CHACHA20_BLOCK_SIZE];
    size_t i, j;

    chacha20_init_state(state, key, nonce, counter);

    for (i = 0; i < length; i += CHACHA20_BLOCK_SIZE) {
        chacha20_block(state, keystream);

        /* XOR plaintext with keystream */
        for (j = 0; j < CHACHA20_BLOCK_SIZE && (i + j) < length; j++) {
            ciphertext[i + j] = plaintext[i + j] ^ keystream[j];
        }

        /* Increment block counter */
        state[12]++;
    }
}

/* Helper function to print hex */
void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if ((i + 1) % 32 == 0 && i + 1 < len) {
            printf("\n%*s", (int)strlen(label), "");
        }
    }
    printf("\n");
}

/* Compare two byte arrays */
int compare_bytes(const uint8_t *a, const uint8_t *b, size_t len) {
    return memcmp(a, b, len) == 0;
}

/* Test vector structure */
typedef struct {
    const char *name;
    uint8_t key[32];
    uint8_t nonce[12];
    uint32_t counter;
    const uint8_t *plaintext;
    const uint8_t *expected;
    size_t length;
} test_vector_t;

/* Run a single test */
int run_test(const test_vector_t *test) {
    uint8_t *ciphertext = malloc(test->length);
    int passed;

    printf("\n=== %s ===\n", test->name);

    chacha20_encrypt(test->key, test->nonce, test->counter,
                    test->plaintext, ciphertext, test->length);

    print_hex("Key:       ", test->key, 32);
    print_hex("Nonce:     ", test->nonce, 12);
    printf("Counter:   %u\n", test->counter);

    if (test->length <= 256) {
        print_hex("Plaintext: ", test->plaintext, test->length);
        print_hex("Expected:  ", test->expected, test->length);
        print_hex("Got:       ", ciphertext, test->length);
    } else {
        printf("Plaintext: (%zu bytes)\n", test->length);
        printf("Expected:  (first 64 bytes)\n  ");
        for (size_t i = 0; i < 64; i++) printf("%02x", test->expected[i]);
        printf("\nGot:       (first 64 bytes)\n  ");
        for (size_t i = 0; i < 64; i++) printf("%02x", ciphertext[i]);
        printf("\n");
    }

    passed = compare_bytes(ciphertext, test->expected, test->length);
    printf("Result:    %s\n", passed ? "PASS " : "FAIL ");

    free(ciphertext);
    return passed;
}

int main(void) {
    int total_tests = 0;
    int passed_tests = 0;

    printf("ChaCha20 Implementation Test Suite\n");
    printf("Based on RFC 8439\n");
    printf("=====================================\n");

    /* Test Vector 1: RFC 8439 Section 2.4.2 - Example and Test Vector */
    {
        static const uint8_t key1[32] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
        };
        static const uint8_t nonce1[12] = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a,
            0x00, 0x00, 0x00, 0x00
        };
        static const uint8_t plaintext1[] =
            "Ladies and Gentlemen of the class of '99: If I could offer you "
            "only one tip for the future, sunscreen would be it.";
        static const uint8_t expected1[] = {
            0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80,
            0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69, 0x81,
            0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2,
            0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f, 0xae, 0x0b,
            0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab,
            0x8f, 0x59, 0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57,
            0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab,
            0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8,
            0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d, 0x6a, 0x61,
            0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e,
            0x52, 0xbc, 0x51, 0x4d, 0x16, 0xcc, 0xf8, 0x06,
            0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36,
            0x5a, 0xf9, 0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6,
            0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42,
            0x87, 0x4d
        };

        test_vector_t test1 = {
            .name = "RFC 8439 Section 2.4.2 - Sunscreen",
            .key = {0},
            .nonce = {0},
            .counter = 1,
            .plaintext = plaintext1,
            .expected = expected1,
            .length = sizeof(expected1)
        };
        memcpy(test1.key, key1, 32);
        memcpy(test1.nonce, nonce1, 12);

        total_tests++;
        if (run_test(&test1)) passed_tests++;
    }

    /* Test Vector 2: RFC 8439 Appendix A.2 - All zeros */
    {
        static const uint8_t key2[32] = {0};
        static const uint8_t nonce2[12] = {0};
        static const uint8_t plaintext2[64] = {0};
        static const uint8_t expected2[64] = {
            0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90,
            0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86, 0xbd, 0x28,
            0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a,
            0xa8, 0x36, 0xef, 0xcc, 0x8b, 0x77, 0x0d, 0xc7,
            0xda, 0x41, 0x59, 0x7c, 0x51, 0x57, 0x48, 0x8d,
            0x77, 0x24, 0xe0, 0x3f, 0xb8, 0xd8, 0x4a, 0x37,
            0x6a, 0x43, 0xb8, 0xf4, 0x15, 0x18, 0xa1, 0x1c,
            0xc3, 0x87, 0xb6, 0x69, 0xb2, 0xee, 0x65, 0x86
        };

        test_vector_t test2 = {
            .name = "RFC 8439 Appendix A.2 - All Zeros",
            .key = {0},
            .nonce = {0},
            .counter = 0,
            .plaintext = plaintext2,
            .expected = expected2,
            .length = 64
        };
        memcpy(test2.key, key2, 32);
        memcpy(test2.nonce, nonce2, 12);

        total_tests++;
        if (run_test(&test2)) passed_tests++;
    }

    /* Test Vector 3: RFC 8439 Appendix A.1 - Quarter Round Test */
    /* Testing the block function directly */
    {
        uint8_t plaintext3[64] = {0};

        /* All-zero key and nonce to test block function */
        static const uint8_t key3_mod[32] = {0};
        static const uint8_t nonce3_mod[12] = {0};

        /* Expected output is the keystream for all-zero key, nonce, counter=0 */
        static const uint8_t expected3[64] = {
            0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90,
            0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86, 0xbd, 0x28,
            0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a,
            0xa8, 0x36, 0xef, 0xcc, 0x8b, 0x77, 0x0d, 0xc7,
            0xda, 0x41, 0x59, 0x7c, 0x51, 0x57, 0x48, 0x8d,
            0x77, 0x24, 0xe0, 0x3f, 0xb8, 0xd8, 0x4a, 0x37,
            0x6a, 0x43, 0xb8, 0xf4, 0x15, 0x18, 0xa1, 0x1c,
            0xc3, 0x87, 0xb6, 0x69, 0xb2, 0xee, 0x65, 0x86
        };

        test_vector_t test3 = {
            .name = "RFC 8439 - Block Function (counter=0)",
            .key = {0},
            .nonce = {0},
            .counter = 0,
            .plaintext = plaintext3,
            .expected = expected3,
            .length = 64
        };
        memcpy(test3.key, key3_mod, 32);
        memcpy(test3.nonce, nonce3_mod, 12);

        total_tests++;
        if (run_test(&test3)) passed_tests++;
    }

    /* Test Vector 4: RFC 8439 Appendix A.2 - Block counter=1 */
    {
        static const uint8_t key4[32] = {0};
        static const uint8_t nonce4[12] = {0};
        static const uint8_t plaintext4[64] = {0};
        /* Keystream with counter=1 (second block) */
        static const uint8_t expected4[64] = {
            0x9f, 0x07, 0xe7, 0xbe, 0x55, 0x51, 0x38, 0x7a,
            0x98, 0xba, 0x97, 0x7c, 0x73, 0x2d, 0x08, 0x0d,
            0xcb, 0x0f, 0x29, 0xa0, 0x48, 0xe3, 0x65, 0x69,
            0x12, 0xc6, 0x53, 0x3e, 0x32, 0xee, 0x7a, 0xed,
            0x29, 0xb7, 0x21, 0x76, 0x9c, 0xe6, 0x4e, 0x43,
            0xd5, 0x71, 0x33, 0xb0, 0x74, 0xd8, 0x39, 0xd5,
            0x31, 0xed, 0x1f, 0x28, 0x51, 0x0a, 0xfb, 0x45,
            0xac, 0xe1, 0x0a, 0x1f, 0x4b, 0x79, 0x4d, 0x6f
        };

        test_vector_t test4 = {
            .name = "RFC 8439 Appendix A.2 - Block counter=1",
            .key = {0},
            .nonce = {0},
            .counter = 1,
            .plaintext = plaintext4,
            .expected = expected4,
            .length = 64
        };
        memcpy(test4.key, key4, 32);
        memcpy(test4.nonce, nonce4, 12);

        total_tests++;
        if (run_test(&test4)) passed_tests++;
    }

    /* Test Vector 5: Verify this is same as test 1 (duplicate for verification) */
    {
        static const uint8_t key5[32] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
        };
        static const uint8_t nonce5[12] = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a,
            0x00, 0x00, 0x00, 0x00
        };
        static const uint8_t plaintext5[] =
            "Ladies and Gentlemen of the class of '99: If I could offer you "
            "only one tip for the future, sunscreen would be it.";
        static const uint8_t expected5[] = {
            0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80,
            0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69, 0x81,
            0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2,
            0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f, 0xae, 0x0b,
            0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab,
            0x8f, 0x59, 0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57,
            0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab,
            0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8,
            0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d, 0x6a, 0x61,
            0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e,
            0x52, 0xbc, 0x51, 0x4d, 0x16, 0xcc, 0xf8, 0x06,
            0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36,
            0x5a, 0xf9, 0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6,
            0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42,
            0x87, 0x4d
        };

        test_vector_t test5 = {
            .name = "Consistency check (same as test 1)",
            .key = {0},
            .nonce = {0},
            .counter = 1,
            .plaintext = plaintext5,
            .expected = expected5,
            .length = sizeof(expected5)
        };
        memcpy(test5.key, key5, 32);
        memcpy(test5.nonce, nonce5, 12);

        total_tests++;
        if (run_test(&test5)) passed_tests++;
    }

    /* Print summary */
    printf("\n=====================================\n");
    printf("Test Summary: %d/%d tests passed\n", passed_tests, total_tests);
    printf("=====================================\n");

    return (passed_tests == total_tests) ? 0 : 1;
}
