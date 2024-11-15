// Server 1 (uav_udp) using Salsa20 with circular buffer nonce storage
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sodium.h>
#include <stdint.h>
#include <stdbool.h>

#define PORT1 14660           // Port to receive data from PX4
#define PORT2 14662           // Port to receive encrypted data from Server 2
#define SERVER2_PORT 14661    // Port to send encrypted data to Server 2
#define PX4_PORT 14556        // PX4 listening port

#define MESSAGE_LEN 2048
#define NONCE_LEN crypto_stream_salsa20_NONCEBYTES
#define CIPHERTEXT_LEN (MESSAGE_LEN + crypto_stream_salsa20_KEYBYTES)
#define MAX_NONCES 100000     // Maximum number of nonces to track for verification

#define KEY_FILE "session_key.bin" // Path to the Salsa20 session key file
#define KEY_SIZE crypto_stream_salsa20_KEYBYTES

// Global variables
uint64_t nonce_counter = 1;  // Start with 1 for odd nonces
unsigned char used_nonces[MAX_NONCES][NONCE_LEN]; // Circular buffer for nonces
int nonce_head = 0; // Points to the position to overwrite (oldest nonce)
int nonce_count = 0; // Tracks the total number of stored nonces (up to MAX_NONCES)
unsigned char key[KEY_SIZE]; // Session key

// Function to load the session key from file
int load_session_key() {
    FILE *file = fopen(KEY_FILE, "rb");
    if (!file) {
        perror("Failed to open key file");
        return -1;
    }
    fread(key, 1, KEY_SIZE, file);
    fclose(file);
    return 0;
}

// Function to check if a nonce has already been used
bool is_nonce_used(unsigned char *nonce) {
    for (int i = 0; i < nonce_count; i++) {
        if (memcmp(used_nonces[i], nonce, NONCE_LEN) == 0) {
            return true; // Nonce found, indicating it's been used
        }
    }
    return false;
}

// Function to store a new nonce in the circular buffer
void store_nonce(unsigned char *nonce) {
    // Store the new nonce in the circular buffer
    memcpy(used_nonces[nonce_head], nonce, NONCE_LEN);

    // Move the head pointer to the next position, wrapping around if necessary
    nonce_head = (nonce_head + 1) % MAX_NONCES;

    // Increment the nonce count, ensuring it doesn't exceed MAX_NONCES
    if (nonce_count < MAX_NONCES) {
        nonce_count++;
    }
}

// Function to generate a unique odd nonce using the counter
void generate_nonce(unsigned char *nonce) {
    memset(nonce, 0, NONCE_LEN);                         // Clear the nonce buffer
    memcpy(nonce, &nonce_counter, sizeof(nonce_counter)); // Copy the counter into the nonce
    nonce_counter += 2;                                   // Increment by 2 to keep it odd
}

int main() {
    int sockfd1, sockfd2;
    struct sockaddr_in servaddr1, servaddr2, cliaddr, server2_addr, px4_addr;
    int len, n;
    unsigned char buffer[MESSAGE_LEN];
    unsigned char nonce[NONCE_LEN];
    unsigned char ciphertext[CIPHERTEXT_LEN + NONCE_LEN];
    unsigned char decrypted[MESSAGE_LEN];

    // Initialize libsodium
    if (sodium_init() < 0) {
        printf("Libsodium initialization failed.\n");
        return 1;
    }

    // Load session key
    if (load_session_key() != 0) {
        printf("Failed to load session key. Exiting.\n");
        return 1;
    }

    // Create socket file descriptors
    if ((sockfd1 = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Socket 1 creation failed");
        exit(EXIT_FAILURE);
    }
    if ((sockfd2 = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Socket 2 creation failed");
        exit(EXIT_FAILURE);
    }

    // Bind the first socket to PORT1 (receive from PX4 on port 14660)
    memset(&servaddr1, 0, sizeof(servaddr1));
    servaddr1.sin_family = AF_INET;
    servaddr1.sin_addr.s_addr = INADDR_ANY;
    servaddr1.sin_port = htons(PORT1);

    if (bind(sockfd1, (const struct sockaddr *)&servaddr1, sizeof(servaddr1)) < 0) {
        perror("Bind failed on PORT1");
        exit(EXIT_FAILURE);
    }

    // Bind the second socket to PORT2 (receive encrypted commands from Server 2 on port 14662)
    memset(&servaddr2, 0, sizeof(servaddr2));
    servaddr2.sin_family = AF_INET;
    servaddr2.sin_addr.s_addr = INADDR_ANY;
    servaddr2.sin_port = htons(PORT2);

    if (bind(sockfd2, (const struct sockaddr *)&servaddr2, sizeof(servaddr2)) < 0) {
        perror("Bind failed on PORT2");
        exit(EXIT_FAILURE);
    }

    // Setup destination address for Server 2 (send encrypted to port 14661)
    memset(&server2_addr, 0, sizeof(server2_addr));
    server2_addr.sin_family = AF_INET;
    server2_addr.sin_port = htons(SERVER2_PORT);
    inet_pton(AF_INET, "127.0.0.1", &server2_addr.sin_addr);

    // Setup destination address for PX4 (send decrypted back to PX4 on port 14556)
    memset(&px4_addr, 0, sizeof(px4_addr));
    px4_addr.sin_family = AF_INET;
    px4_addr.sin_port = htons(PX4_PORT);
    inet_pton(AF_INET, "127.0.0.1", &px4_addr.sin_addr);

    printf("Server 1 listening on ports %d (for PX4) and %d (for Server 2)\n", PORT1, PORT2);

    while (1) {
        // Receive from both sockets in a non-blocking manner
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(sockfd1, &readfds);
        FD_SET(sockfd2, &readfds);

        int max_sd = sockfd1 > sockfd2 ? sockfd1 : sockfd2;
        int activity = select(max_sd + 1, &readfds, NULL, NULL, NULL);

        if (FD_ISSET(sockfd1, &readfds)) {
            // Received from PX4
            n = recvfrom(sockfd1, buffer, MESSAGE_LEN, MSG_WAITALL, (struct sockaddr *)&cliaddr, &len);

            // Generate a unique odd nonce
            generate_nonce(nonce);

            // Encrypt the message with Salsa20
            crypto_stream_salsa20_xor(ciphertext + NONCE_LEN, buffer, n, nonce, key);

            // Prepend nonce to the ciphertext
            memcpy(ciphertext, nonce, NONCE_LEN);
            int ciphertext_len = n + NONCE_LEN;

            // Store the nonce for future verification
            store_nonce(nonce);

            // Send encrypted message (including nonce) to Server 2 on port 14661
            sendto(sockfd1, ciphertext, ciphertext_len, MSG_CONFIRM, (const struct sockaddr *)&server2_addr, sizeof(server2_addr));
            // printf("Encrypted and forwarded to Server 2 on port %d\n", SERVER2_PORT);
        }

        if (FD_ISSET(sockfd2, &readfds)) {
            // Received encrypted data from Server 2 on port 14662
            n = recvfrom(sockfd2, ciphertext, sizeof(ciphertext), MSG_WAITALL, (struct sockaddr *)&cliaddr, &len);

            // Extract the nonce from the message
            memcpy(nonce, ciphertext, NONCE_LEN);

            // Verify the nonce to prevent replay attacks
            if (is_nonce_used(nonce)) {
                printf("Replay attack detected! Nonce has already been used.\n");
                continue;
            } else {
                // Store the nonce to prevent future reuse
                store_nonce(nonce);
            }

            // Decrypt the message with Salsa20
            crypto_stream_salsa20_xor(decrypted, ciphertext + NONCE_LEN, n - NONCE_LEN, nonce, key);

            // Send decrypted message to PX4 on port 14556
            sendto(sockfd1, decrypted, n - NONCE_LEN, MSG_CONFIRM, (const struct sockaddr *)&px4_addr, sizeof(px4_addr));
            // printf("Decrypted and forwarded to PX4 on port %d\n", PX4_PORT);
        }
    }

    close(sockfd1);
    close(sockfd2);
    return 0;
}
