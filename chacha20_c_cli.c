/*
 * ChaCha20 CLI Wrapper for C Implementation
 * Accepts hex-encoded key, nonce, counter, and plaintext as arguments
 * Outputs hex-encoded ciphertext
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define CHACHA20_STATE_WORDS 16
#define CHACHA20_BLOCK_SIZE 64
#define CHACHA20_KEY_SIZE 32
#define CHACHA20_NONCE_SIZE 12

#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

#define QR(a, b, c, d) \
    do { \
        a += b; d ^= a; d = ROTL32(d, 16); \
        c += d; b ^= c; b = ROTL32(b, 12); \
        a += b; d ^= a; d = ROTL32(d, 8); \
        c += d; b ^= c; b = ROTL32(b, 7); \
    } while(0)

static uint32_t read_le32(const uint8_t *p) {
    return ((uint32_t)p[0]) |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static void write_le32(uint8_t *p, uint32_t v) {
    p[0] = v & 0xff;
    p[1] = (v >> 8) & 0xff;
    p[2] = (v >> 16) & 0xff;
    p[3] = (v >> 24) & 0xff;
}

static void secure_zero_memory(void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) {
        *p++ = 0;
    }
}

static void chacha20_init_state(uint32_t state[CHACHA20_STATE_WORDS],
                                const uint8_t key[CHACHA20_KEY_SIZE],
                                const uint8_t nonce[CHACHA20_NONCE_SIZE],
                                uint32_t counter) {
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;

    state[4] = read_le32(key + 0);
    state[5] = read_le32(key + 4);
    state[6] = read_le32(key + 8);
    state[7] = read_le32(key + 12);
    state[8] = read_le32(key + 16);
    state[9] = read_le32(key + 20);
    state[10] = read_le32(key + 24);
    state[11] = read_le32(key + 28);

    state[12] = counter;

    state[13] = read_le32(nonce + 0);
    state[14] = read_le32(nonce + 4);
    state[15] = read_le32(nonce + 8);
}

static void chacha20_block(uint32_t state[CHACHA20_STATE_WORDS],
                          uint8_t output[CHACHA20_BLOCK_SIZE]) {
    uint32_t working_state[CHACHA20_STATE_WORDS];
    int i;

    memcpy(working_state, state, sizeof(working_state));

    for (i = 0; i < 10; i++) {
        QR(working_state[0], working_state[4], working_state[8],  working_state[12]);
        QR(working_state[1], working_state[5], working_state[9],  working_state[13]);
        QR(working_state[2], working_state[6], working_state[10], working_state[14]);
        QR(working_state[3], working_state[7], working_state[11], working_state[15]);

        QR(working_state[0], working_state[5], working_state[10], working_state[15]);
        QR(working_state[1], working_state[6], working_state[11], working_state[12]);
        QR(working_state[2], working_state[7], working_state[8],  working_state[13]);
        QR(working_state[3], working_state[4], working_state[9],  working_state[14]);
    }

    for (i = 0; i < CHACHA20_STATE_WORDS; i++) {
        working_state[i] += state[i];
    }

    for (i = 0; i < CHACHA20_STATE_WORDS; i++) {
        write_le32(output + (i * 4), working_state[i]);
    }

    secure_zero_memory(working_state, sizeof(working_state));
}

void chacha20_encrypt(const uint8_t key[CHACHA20_KEY_SIZE],
                     const uint8_t nonce[CHACHA20_NONCE_SIZE],
                     uint32_t counter,
                     const uint8_t *plaintext,
                     uint8_t *ciphertext,
                     size_t length) {
    uint32_t state[CHACHA20_STATE_WORDS];
    uint8_t keystream[CHACHA20_BLOCK_SIZE];
    size_t i, j;

    if (!key || !nonce || !plaintext || !ciphertext) {
        return;
    }

    chacha20_init_state(state, key, nonce, counter);

    for (i = 0; i < length; i += CHACHA20_BLOCK_SIZE) {
        chacha20_block(state, keystream);

        for (j = 0; j < CHACHA20_BLOCK_SIZE && (i + j) < length; j++) {
            ciphertext[i + j] = plaintext[i + j] ^ keystream[j];
        }

        secure_zero_memory(keystream, CHACHA20_BLOCK_SIZE);

        state[12]++;
    }

    secure_zero_memory(state, sizeof(state));
    secure_zero_memory(keystream, sizeof(keystream));
}

int hex_to_bytes(const char *hex, uint8_t *bytes, size_t max_len) {
    size_t len = strlen(hex);
    if (len % 2 != 0 || len / 2 > max_len) {
        return -1;
    }

    for (size_t i = 0; i < len / 2; i++) {
        sscanf(hex + 2 * i, "%2hhx", &bytes[i]);
    }

    return len / 2;
}

int main(int argc, char *argv[]) {
    if (argc != 5) {
        fprintf(stderr, "Usage: %s <key_hex> <nonce_hex> <counter> <plaintext_hex>\n", argv[0]);
        return 1;
    }

    uint8_t key[32];
    uint8_t nonce[12];
    uint32_t counter;
    uint8_t *plaintext = NULL;
    uint8_t *ciphertext = NULL;
    int plaintext_len;

    if (hex_to_bytes(argv[1], key, 32) != 32) {
        fprintf(stderr, "Error: Key must be 64 hex characters (32 bytes)\n");
        return 1;
    }

    if (hex_to_bytes(argv[2], nonce, 12) != 12) {
        fprintf(stderr, "Error: Nonce must be 24 hex characters (12 bytes)\n");
        return 1;
    }

    counter = (uint32_t)atoi(argv[3]);

    plaintext_len = strlen(argv[4]) / 2;
    plaintext = malloc(plaintext_len);
    ciphertext = malloc(plaintext_len);

    if (!plaintext || !ciphertext) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        free(plaintext);
        free(ciphertext);
        return 1;
    }

    if (hex_to_bytes(argv[4], plaintext, plaintext_len) != plaintext_len) {
        fprintf(stderr, "Error: Invalid plaintext hex\n");
        free(plaintext);
        free(ciphertext);
        return 1;
    }

    chacha20_encrypt(key, nonce, counter, plaintext, ciphertext, plaintext_len);

    for (int i = 0; i < plaintext_len; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    secure_zero_memory(plaintext, plaintext_len);
    secure_zero_memory(ciphertext, plaintext_len);
    free(plaintext);
    free(ciphertext);

    return 0;
}
