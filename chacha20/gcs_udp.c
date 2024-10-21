// Server 2
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sodium.h>

#define PORT1 14661   // Port to receive encrypted data from Server 1
#define PORT2 14550   // Port to send data to QGroundControl
#define PORT3 14551   // Port to receive data from QGroundControl
#define SERVER1_PORT 14662  // Port to send encrypted data back to Server 1

#define MESSAGE_LEN 2048
#define NONCE_LEN crypto_aead_chacha20poly1305_IETF_NPUBBYTES
#define CIPHERTEXT_LEN (MESSAGE_LEN + crypto_aead_chacha20poly1305_IETF_ABYTES)

int main() {
    int sockfd1, sockfd2, sockfd3;
    struct sockaddr_in servaddr1, servaddr3, qground_addr, server1_send_addr;
    int len, n;
    unsigned char buffer[MESSAGE_LEN];
    unsigned char nonce[NONCE_LEN];  // Nonce for encryption
    unsigned char ciphertext[CIPHERTEXT_LEN + NONCE_LEN];
    unsigned long long ciphertext_len;
    unsigned char decrypted[MESSAGE_LEN];
    unsigned long long decrypted_len;

    // Initialize libsodium
    if (sodium_init() < 0) {
        printf("Libsodium initialization failed.\n");
        return 1;
    }

    // Hardcoded encryption key (32 bytes)
    unsigned char key[crypto_aead_chacha20poly1305_IETF_KEYBYTES] = "12345678901234567890123456789012";

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
        FD_SET(sockfd1, &readfds);  // Add socket for PORT1 (Server 1)
        FD_SET(sockfd3, &readfds);  // Add socket for PORT3 (QGroundControl)

        int max_sd = sockfd1 > sockfd3 ? sockfd1 : sockfd3;
        int activity = select(max_sd + 1, &readfds, NULL, NULL, NULL);  // Monitor sockets

        if (FD_ISSET(sockfd1, &readfds)) {
            // Received encrypted data from Server 1
            n = recvfrom(sockfd1, ciphertext, sizeof(ciphertext), MSG_WAITALL, (struct sockaddr *)&servaddr1, &len);

            // Extract the nonce from the message
            memcpy(nonce, ciphertext, NONCE_LEN);

            // Decrypt the message
            if (crypto_aead_chacha20poly1305_ietf_decrypt(
                decrypted, &decrypted_len,
                NULL, ciphertext + NONCE_LEN, n - NONCE_LEN,
                NULL, 0, nonce, key) != 0) {
                printf("Decryption failed.\n");
                continue;
            }

            // Send decrypted message to QGroundControl
            sendto(sockfd3, decrypted, decrypted_len, MSG_CONFIRM, (const struct sockaddr *)&qground_addr, sizeof(qground_addr));
            printf("Decrypted and forwarded to QGroundControl on port %d\n", PORT2);
        }

        if (FD_ISSET(sockfd3, &readfds)) {
            // Received data from QGroundControl
            n = recvfrom(sockfd3, buffer, MESSAGE_LEN, MSG_WAITALL, (struct sockaddr *)&qground_addr, &len);

            // Generate a random nonce
            randombytes_buf(nonce, NONCE_LEN);

            // Re-encrypt the message before sending back to Server 1
            if (crypto_aead_chacha20poly1305_ietf_encrypt(
                ciphertext + NONCE_LEN, &ciphertext_len,
                buffer, n,
                NULL, 0, NULL, nonce, key) != 0) {
                printf("Encryption failed.\n");
                continue;
            }

            // Prepend nonce to the ciphertext
            memcpy(ciphertext, nonce, NONCE_LEN);
            ciphertext_len += NONCE_LEN;

            // Send re-encrypted message (including nonce) back to Server 1 on port 14662
            sendto(sockfd1, ciphertext, ciphertext_len, MSG_CONFIRM, (const struct sockaddr *)&server1_send_addr, sizeof(server1_send_addr));
            printf("Re-encrypted and forwarded to Server 1 on port %d\n", SERVER1_PORT);
        }
    }

    close(sockfd1);
    close(sockfd3);
    return 0;
}
