// Server 2 (gcs_udp) using Salsa20
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

#define PORT1 14661           // Port to receive encrypted data from Server 1
#define PORT2 14550           // Port to send data to QGroundControl
#define PORT3 14551           // Port to receive data from QGroundControl
#define SERVER1_PORT 14662    // Port to send encrypted data back to Server 1

#define MESSAGE_LEN 2048
#define NONCE_LEN crypto_stream_salsa20_NONCEBYTES
#define CIPHERTEXT_LEN (MESSAGE_LEN)
#define MAX_NONCES 100000     // Maximum number of nonces to track for verification

#define KEY_FILE "session_key.bin" // Path to the Salsa20 session key file
#define KEY_SIZE crypto_stream_salsa20_KEYBYTES

// Global counter for generating unique even nonces
uint64_t nonce_counter = 2;  // Start with 2 for even nonces
unsigned char used_nonces[MAX_NONCES][NONCE_LEN];  // Array to store used nonces
int nonce_count = 0;
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

// Function to store a new nonce in the used_nonces array
void store_nonce(unsigned char *nonce) {
    if (nonce_count < MAX_NONCES) {
        memcpy(used_nonces[nonce_count++], nonce, NONCE_LEN);
    } else {
        printf("Nonce storage full. Increase MAX_NONCES or clear nonces periodically.\n");
        exit(1); // Stop the server when nonce storage is full
    }
}

// Function to generate a unique even nonce using the counter
void generate_nonce(unsigned char *nonce) {
    memset(nonce, 0, NONCE_LEN);                         // Clear the nonce buffer
    memcpy(nonce, &nonce_counter, sizeof(nonce_counter)); // Copy the counter into the nonce
    nonce_counter += 2;                                   // Increment by 2 to keep it even
}

int main() {
    int sockfd1, sockfd3;
    struct sockaddr_in servaddr1, servaddr3, qground_addr, server1_send_addr;
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
    if ((sockfd3 = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Socket 3 creation failed");
        exit(EXIT_FAILURE);
    }

    // Bind sockfd1 to PORT1 (receive from Server 1 on port 14661)
    memset(&servaddr1, 0, sizeof(servaddr1));
    servaddr1.sin_family = AF_INET;
    servaddr1.sin_addr.s_addr = INADDR_ANY;
    servaddr1.sin_port = htons(PORT1);

    if (bind(sockfd1, (const struct sockaddr *)&servaddr1, sizeof(servaddr1)) < 0) {
        perror("Bind failed on PORT1");
        exit(EXIT_FAILURE);
    }

    // Bind sockfd3 to PORT3 (receive from QGroundControl on port 14551)
    memset(&servaddr3, 0, sizeof(servaddr3));
    servaddr3.sin_family = AF_INET;
    servaddr3.sin_addr.s_addr = INADDR_ANY;
    servaddr3.sin_port = htons(PORT3);

    if (bind(sockfd3, (const struct sockaddr *)&servaddr3, sizeof(servaddr3)) < 0) {
        perror("Bind failed on PORT3");
        exit(EXIT_FAILURE);
    }

    // Setup destination address for QGroundControl (send to port 14550)
    memset(&qground_addr, 0, sizeof(qground_addr));
    qground_addr.sin_family = AF_INET;
    qground_addr.sin_port = htons(PORT2);  // QGroundControl's listening port 14550
    inet_pton(AF_INET, "127.0.0.1", &qground_addr.sin_addr);  // Assuming localhost

    // Setup destination address for Server 1 (send back to port 14662)
    memset(&server1_send_addr, 0, sizeof(server1_send_addr));
    server1_send_addr.sin_family = AF_INET;
    server1_send_addr.sin_port = htons(SERVER1_PORT);  // Port 14662
    inet_pton(AF_INET, "127.0.0.1", &server1_send_addr.sin_addr);  // Assuming localhost

    printf("Server 2 listening on ports %d (from Server 1), %d (to QGroundControl), and %d (from QGroundControl)\n", PORT1, PORT2, PORT3);

    while (1) {
        // Receive from both sockets in a non-blocking manner
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(sockfd1, &readfds);
        FD_SET(sockfd3, &readfds);

        int max_sd = sockfd1 > sockfd3 ? sockfd1 : sockfd3;
        int activity = select(max_sd + 1, &readfds, NULL, NULL, NULL);

        if (FD_ISSET(sockfd1, &readfds)) {
            // Received encrypted data from Server 1
            n = recvfrom(sockfd1, ciphertext, sizeof(ciphertext), MSG_WAITALL, (struct sockaddr *)&servaddr1, &len);

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

            // Send decrypted message to QGroundControl
            sendto(sockfd3, decrypted, n - NONCE_LEN, MSG_CONFIRM, (const struct sockaddr *)&qground_addr, sizeof(qground_addr));
            printf("Decrypted and forwarded to QGroundControl on port %d\n", PORT2);
        }

        if (FD_ISSET(sockfd3, &readfds)) {
            // Received data from QGroundControl
            n = recvfrom(sockfd3, buffer, MESSAGE_LEN, MSG_WAITALL, (struct sockaddr *)&qground_addr, &len);

            // Generate a unique even nonce
            generate_nonce(nonce);

            // Re-encrypt the message with Salsa20 before sending back to Server 1
            crypto_stream_salsa20_xor(ciphertext + NONCE_LEN, buffer, n, nonce, key);

            // Prepend nonce to the ciphertext
            memcpy(ciphertext, nonce, NONCE_LEN);
            int ciphertext_len = n + NONCE_LEN;

            // Store the nonce for future verification
            store_nonce(nonce);

            // Send re-encrypted message (including nonce) back to Server 1 on port 14662
            sendto(sockfd1, ciphertext, ciphertext_len, MSG_CONFIRM, (const struct sockaddr *)&server1_send_addr, sizeof(server1_send_addr));
            printf("Re-encrypted and forwarded to Server 1 on port %d\n", SERVER1_PORT);
        }
    }

    close(sockfd1);
    close(sockfd3);
    return 0;
}