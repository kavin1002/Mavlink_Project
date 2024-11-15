// generate_key_aes.c
#include <stdio.h>
#include <openssl/rand.h>

#define AES_GCM_KEY_SIZE 32  // 256 bits
#define KEY_FILE "session_key.bin"  // Path to save the AES key

int main() {
    unsigned char key[AES_GCM_KEY_SIZE];

    // Generate a random AES key
    if (!RAND_bytes(key, AES_GCM_KEY_SIZE)) {
        fprintf(stderr, "Key generation failed\n");
        return 1;
    }

    // Save the key to a file
    FILE *file = fopen(KEY_FILE, "wb");
    if (!file) {
        perror("Failed to open key file");
        return 1;
    }
    fwrite(key, 1, AES_GCM_KEY_SIZE, file);
    fclose(file);

    printf("AES-GCM key generated and saved to %s\n", KEY_FILE);
    return 0;
}
