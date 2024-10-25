// Server 2 Code with AES-GCM
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/rand.h>  // For RAND_bytes

#define PORT1 14661   // Port to receive encrypted data from Server 1
#define PORT2 14550   // Port to send data to QGroundControl
#define PORT3 14551   // Port to receive data from QGroundControl
#define SERVER1_PORT 14662  // Port to send encrypted data back to Server 1

#define MESSAGE_LEN 2048
#define AES_GCM_KEY_SIZE 32  // 256 bits
#define AES_GCM_TAG_SIZE 16  // 128 bits
#define AES_GCM_IV_SIZE 12   // 96 bits

int main() {
    int sockfd1, sockfd2, sockfd3;
    struct sockaddr_in servaddr1, servaddr3, qground_addr, server1_send_addr;
    int len, n;
    unsigned char buffer[MESSAGE_LEN];
    unsigned char tag[AES_GCM_TAG_SIZE];
    unsigned char iv[AES_GCM_IV_SIZE];
    unsigned char ciphertext[MESSAGE_LEN + AES_GCM_TAG_SIZE];
    unsigned char decrypted[MESSAGE_LEN];

    unsigned char key[AES_GCM_KEY_SIZE] = "12345678901234567890123456789012";  // Hardcoded key

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
            n = recvfrom(sockfd1, iv, AES_GCM_IV_SIZE, MSG_WAITALL, (struct sockaddr *)&servaddr1, &len);  // Receive IV
            recvfrom(sockfd1, tag, AES_GCM_TAG_SIZE, MSG_WAITALL, (struct sockaddr *)&servaddr1, &len);  // Receive tag
            n = recvfrom(sockfd1, ciphertext, sizeof(ciphertext), MSG_WAITALL, (struct sockaddr *)&servaddr1, &len);  // Receive ciphertext

            // Decrypt the message using AES-GCM
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
            int len;
            int plaintext_len;
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_SIZE, tag);
            EVP_DecryptUpdate(ctx, decrypted, &len, ciphertext, n);
            plaintext_len = len;

            if (EVP_DecryptFinal_ex(ctx, decrypted + len, &len) > 0) {
                plaintext_len += len;
                sendto(sockfd3, decrypted, plaintext_len, MSG_CONFIRM, (const struct sockaddr *)&qground_addr, sizeof(qground_addr));
                printf("Decrypted and forwarded to QGroundControl on port %d\n", PORT2);
            } else {
                printf("Decryption failed.\n");
            }
            EVP_CIPHER_CTX_free(ctx);
        }

        if (FD_ISSET(sockfd3, &readfds)) {
            // Received data from QGroundControl
            n = recvfrom(sockfd3, buffer, MESSAGE_LEN, MSG_WAITALL, (struct sockaddr *)&qground_addr, &len);

            // Generate a random IV
            RAND_bytes(iv, AES_GCM_IV_SIZE);

            // Re-encrypt the message before sending back to Server 1
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
            int len;
            int ciphertext_len;
            EVP_EncryptUpdate(ctx, ciphertext, &len, buffer, n);
            ciphertext_len = len;
            EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
            ciphertext_len += len;
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_SIZE, tag);
            EVP_CIPHER_CTX_free(ctx);

            // Send IV, tag, and re-encrypted message back to Server 1
            sendto(sockfd1, iv, AES_GCM_IV_SIZE, MSG_CONFIRM, (const struct sockaddr *)&server1_send_addr, sizeof(server1_send_addr));  // Send IV
            sendto(sockfd1, tag, AES_GCM_TAG_SIZE, MSG_CONFIRM, (const struct sockaddr *)&server1_send_addr, sizeof(server1_send_addr));  // Send tag
            sendto(sockfd1, ciphertext, ciphertext_len, MSG_CONFIRM, (const struct sockaddr *)&server1_send_addr, sizeof(server1_send_addr));  // Send ciphertext
            printf("Re-encrypted and forwarded to Server 1 on port %d\n", SERVER1_PORT);
        }
    }

    close(sockfd1);
    close(sockfd3);
    return 0;
}
