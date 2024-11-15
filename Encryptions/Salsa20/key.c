#include <sodium.h>
#include <stdio.h>

#define KEY_FILE "session_key.bin"
#define KEY_SIZE crypto_stream_salsa20_KEYBYTES

int main() {
    unsigned char key[KEY_SIZE];

    // Initialize libsodium
    if (sodium_init() < 0) {
        printf("Libsodium initialization failed.\n");
        return 1;
    }

    // Generate a random key
    randombytes_buf(key, KEY_SIZE);

    // Save the key to a file
    FILE *file = fopen(KEY_FILE, "wb");
    if (!file) {
        perror("Failed to open key file");
        return 1;
    }
    fwrite(key, 1, KEY_SIZE, file);
    fclose(file);

    printf("Session key generated and saved to %s\n", KEY_FILE);
    return 0;
}
