#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdint.h>
#include <stdbool.h>

#define PORT1 14661           // Port to receive encrypted data from Server 1
#define PORT2 14550           // Port to send data to QGroundControl
#define PORT3 14551           // Port to receive data from QGroundControl
#define SERVER1_PORT 14662    // Port to send encrypted data back to Server 1

#define MESSAGE_LEN 2048
#define AES_GCM_KEY_SIZE 32    // 256 bits
#define AES_GCM_TAG_SIZE 16    // 128 bits
#define AES_GCM_IV_SIZE 12     // 96 bits
#define MAX_NONCES 100000      // Maximum number of nonces to track for verification

#define KEY_FILE "session_key.bin" // Path to the AES-GCM key file

// Global variables
uint64_t nonce_counter = 2; // Start with 2 for even nonces
unsigned char used_nonces[MAX_NONCES][AES_GCM_IV_SIZE]; // Ring buffer for nonces
int nonce_head = 0; // Points to the position to overwrite (oldest nonce)
int nonce_count = 0; // Tracks the total number of stored nonces (up to MAX_NONCES)
unsigned char key[AES_GCM_KEY_SIZE]; // Session key

// Function to load the AES-GCM session key from file
int load_session_key() {
    FILE *file = fopen(KEY_FILE, "rb");
    if (!file) {
        perror("Failed to open key file");
        return -1;
    }
    fread(key, 1, AES_GCM_KEY_SIZE, file);
    fclose(file);
    return 0;
}

// Function to check if a nonce has already been used
bool is_nonce_used(unsigned char *nonce) {
    for (int i = 0; i < nonce_count; i++) {
        if (memcmp(used_nonces[i], nonce, AES_GCM_IV_SIZE) == 0) {
            return true; // Nonce found, indicating it's been used
        }
    }
    return false;
}

// Function to store a new nonce in the rotating ring buffer
void store_nonce(unsigned char *nonce) {
    // Store the new nonce in the ring buffer
    memcpy(used_nonces[nonce_head], nonce, AES_GCM_IV_SIZE);

    // Move the head pointer to the next position, wrapping around if necessary
    nonce_head = (nonce_head + 1) % MAX_NONCES;

    // Increment the nonce count, ensuring it doesn't exceed MAX_NONCES
    if (nonce_count < MAX_NONCES) {
        nonce_count++;
    }
}

// Function to generate a unique even nonce using the counter
void generate_nonce(unsigned char *nonce) {
    memset(nonce, 0, AES_GCM_IV_SIZE);
    memcpy(nonce, &nonce_counter, sizeof(nonce_counter));
    nonce_counter += 2;
}

int main() {
    int sockfd1, sockfd3;
    struct sockaddr_in servaddr1, servaddr3, qground_addr, server1_send_addr;
    int len, n;
    unsigned char buffer[MESSAGE_LEN];
    unsigned char nonce[AES_GCM_IV_SIZE];
    unsigned char tag[AES_GCM_TAG_SIZE];
    unsigned char ciphertext[MESSAGE_LEN + AES_GCM_TAG_SIZE];
    int ciphertext_len;
    unsigned char decrypted[MESSAGE_LEN];
    int decrypted_len;

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
    inet_pton(AF_INET, "127.0.0.1", &qground_addr.sin_addr);

    // Setup destination address for Server 1 (send back to port 14662)
    memset(&server1_send_addr, 0, sizeof(server1_send_addr));
    server1_send_addr.sin_family = AF_INET;
    server1_send_addr.sin_port = htons(SERVER1_PORT);
    inet_pton(AF_INET, "127.0.0.1", &server1_send_addr.sin_addr);

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
            // Handle data from Server 1
            unsigned char receive_buffer[MESSAGE_LEN + AES_GCM_TAG_SIZE + AES_GCM_IV_SIZE];
            n = recvfrom(sockfd1, receive_buffer, sizeof(receive_buffer), MSG_WAITALL, (struct sockaddr *)&servaddr1, &len);

            if (n < (AES_GCM_IV_SIZE + AES_GCM_TAG_SIZE)) {
                printf("Received packet too short for decryption.\n");
                continue;
            }

            // Extract nonce, ciphertext, and tag
            memcpy(nonce, receive_buffer, AES_GCM_IV_SIZE);
            memcpy(tag, receive_buffer + n - AES_GCM_TAG_SIZE, AES_GCM_TAG_SIZE);
            int ciphertext_length = n - AES_GCM_IV_SIZE - AES_GCM_TAG_SIZE;
            memcpy(ciphertext, receive_buffer + AES_GCM_IV_SIZE, ciphertext_length);

            // Verify nonce to prevent replay attacks
            if (is_nonce_used(nonce)) {
                printf("Replay attack detected! Nonce has already been used: ");
                for (int i = 0; i < AES_GCM_IV_SIZE; i++) {
                    printf("%02x", nonce[i]);
                }
                printf("\n");
                continue;
            }
            store_nonce(nonce);

            // Decrypt the message
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, nonce);
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_SIZE, tag);
            EVP_DecryptUpdate(ctx, decrypted, &decrypted_len, ciphertext, ciphertext_length);

            if (EVP_DecryptFinal_ex(ctx, decrypted + decrypted_len, &len) > 0) {
                decrypted_len += len;
                sendto(sockfd3, decrypted, decrypted_len, MSG_CONFIRM, (const struct sockaddr *)&qground_addr, sizeof(qground_addr));
            } else {
                printf("Decryption failed.\n");
            }
            EVP_CIPHER_CTX_free(ctx);
        }

        if (FD_ISSET(sockfd3, &readfds)) {
            // Handle data from QGroundControl
            n = recvfrom(sockfd3, buffer, MESSAGE_LEN, MSG_WAITALL, (struct sockaddr *)&qground_addr, &len);

            // Generate a unique even nonce
            generate_nonce(nonce);

            // Re-encrypt the message before sending back to Server 1
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, nonce);
            EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len, buffer, n);
            EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &len);
            ciphertext_len += len;

            // Get the authentication tag
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_SIZE, tag);
            EVP_CIPHER_CTX_free(ctx);

            // Prepend nonce and tag to the ciphertext
            unsigned char send_buffer[AES_GCM_IV_SIZE + ciphertext_len + AES_GCM_TAG_SIZE];
            memcpy(send_buffer, nonce, AES_GCM_IV_SIZE);
            memcpy(send_buffer + AES_GCM_IV_SIZE, ciphertext, ciphertext_len);
            memcpy(send_buffer + AES_GCM_IV_SIZE + ciphertext_len, tag, AES_GCM_TAG_SIZE);
            store_nonce(nonce);

            // Send nonce, ciphertext, and tag back to Server 1
            sendto(sockfd1, send_buffer, sizeof(send_buffer), MSG_CONFIRM, (const struct sockaddr *)&server1_send_addr, sizeof(server1_send_addr));
        }
    }

    close(sockfd1);
    close(sockfd3);
    return 0;
}
