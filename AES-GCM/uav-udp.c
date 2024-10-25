// Server 1 Code with AES-GCM
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/rand.h>  // For RAND_bytes

#define PORT1 14660   // Port to receive data from PX4
#define PORT2 14662   // Port to receive encrypted data from Server 2
#define SERVER2_PORT 14661  // Port to send encrypted data to Server 2
#define PX4_PORT 14556  // PX4 listening port

#define MESSAGE_LEN 2048
#define AES_GCM_KEY_SIZE 32  // 256 bits
#define AES_GCM_TAG_SIZE 16  // 128 bits
#define AES_GCM_IV_SIZE 12   // 96 bits

int main() {
    int sockfd1, sockfd2;
    struct sockaddr_in servaddr1, servaddr2, cliaddr, server2_addr, px4_addr;
    int len, n;
    unsigned char buffer[MESSAGE_LEN];
    unsigned char tag[AES_GCM_TAG_SIZE];
    unsigned char iv[AES_GCM_IV_SIZE];
    unsigned char ciphertext[MESSAGE_LEN + AES_GCM_TAG_SIZE];

    unsigned char key[AES_GCM_KEY_SIZE] = "12345678901234567890123456789012";  // Hardcoded key

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
    server2_addr.sin_port = htons(SERVER2_PORT);  // Port to send to Server 2 (14661)
    inet_pton(AF_INET, "127.0.0.1", &server2_addr.sin_addr);

    // Setup destination address for PX4 (send decrypted back to PX4 on port 14556)
    memset(&px4_addr, 0, sizeof(px4_addr));
    px4_addr.sin_family = AF_INET;
    px4_addr.sin_port = htons(PX4_PORT);  // PX4 listening on port 14556
    inet_pton(AF_INET, "127.0.0.1", &px4_addr.sin_addr);

    while (1) {
        // Receive from both sockets in a non-blocking manner
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(sockfd1, &readfds);  // Add socket for PORT1 (PX4)
        FD_SET(sockfd2, &readfds);  // Add socket for PORT2 (Server 2)

        int max_sd = sockfd1 > sockfd2 ? sockfd1 : sockfd2;
        int activity = select(max_sd + 1, &readfds, NULL, NULL, NULL);  // Monitor sockets

        if (FD_ISSET(sockfd1, &readfds)) {
            // Received from PX4
            n = recvfrom(sockfd1, buffer, MESSAGE_LEN, MSG_WAITALL, (struct sockaddr *)&cliaddr, &len);

            // Generate a random IV
            RAND_bytes(iv, AES_GCM_IV_SIZE);

            // Encrypt the message using AES-GCM
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

            // Prepend IV and tag to the ciphertext
            sendto(sockfd1, iv, AES_GCM_IV_SIZE, MSG_CONFIRM, (const struct sockaddr *)&server2_addr, sizeof(server2_addr));  // Send IV
            sendto(sockfd1, tag, AES_GCM_TAG_SIZE, MSG_CONFIRM, (const struct sockaddr *)&server2_addr, sizeof(server2_addr));  // Send tag
            sendto(sockfd1, ciphertext, ciphertext_len, MSG_CONFIRM, (const struct sockaddr *)&server2_addr, sizeof(server2_addr));  // Send ciphertext
            printf("Encrypted and forwarded to Server 2 on port %d\n", SERVER2_PORT);
        }

        if (FD_ISSET(sockfd2, &readfds)) {
            // Received encrypted data from Server 2 on port 14662
            n = recvfrom(sockfd2, iv, AES_GCM_IV_SIZE, MSG_WAITALL, (struct sockaddr *)&cliaddr, &len);  // Receive IV
            recvfrom(sockfd2, tag, AES_GCM_TAG_SIZE, MSG_WAITALL, (struct sockaddr *)&cliaddr, &len);  // Receive tag
            n = recvfrom(sockfd2, ciphertext, sizeof(ciphertext), MSG_WAITALL, (struct sockaddr *)&cliaddr, &len);  // Receive ciphertext

            // Decrypt the message using AES-GCM
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);

            int len;
            int plaintext_len;

            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_SIZE, tag);

            EVP_DecryptUpdate(ctx, buffer, &len, ciphertext, n);
            plaintext_len = len;

            int ret = EVP_DecryptFinal_ex(ctx, buffer + len, &len);
            if (ret > 0) {
                plaintext_len += len;
                sendto(sockfd1, buffer, plaintext_len, MSG_CONFIRM, (const struct sockaddr *)&px4_addr, sizeof(px4_addr));  // Send decrypted message to PX4
                printf("Decrypted and forwarded to PX4 on port %d\n", PX4_PORT);
            } else {
                printf("Decryption failed.\n");
            }

            EVP_CIPHER_CTX_free(ctx);
        }
    }

    close(sockfd1);
    close(sockfd2);
    return 0;
}
