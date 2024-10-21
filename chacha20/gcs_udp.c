#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sodium.h>

#define PORT1 14661   // Port to receive data from Server 1
#define PORT2 14550   // Port to send data to QGroundControl
#define PORT3 14551   // Port to receive data from QGroundControl
#define SERVER1_PORT 14662  // Port to send data back to Server 1

#define MESSAGE_LEN 1024
#define CIPHERTEXT_LEN (MESSAGE_LEN + crypto_aead_chacha20poly1305_IETF_ABYTES)

int main() {
    int sockfd1, sockfd2, sockfd3;
    struct sockaddr_in servaddr1, servaddr2, servaddr3, qground_addr, server1_recv_addr;
    int len, n;
    unsigned char buffer[CIPHERTEXT_LEN];
    unsigned char decrypted[MESSAGE_LEN];
    unsigned long long decrypted_len;

    // Initialize libsodium
    if (sodium_init() < 0) {
        printf("Libsodium initialization failed.\n");
        return 1;
    }

    // Hardcoded encryption key and nonce (32 bytes key, 12 bytes nonce)
    unsigned char key[crypto_aead_chacha20poly1305_IETF_KEYBYTES] = "12345678901234567890123456789012";
    unsigned char nonce[crypto_aead_chacha20poly1305_IETF_NPUBBYTES] = "123456789012";

    // Create three socket file descriptors
    if ((sockfd1 = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Socket 1 creation failed");
        exit(EXIT_FAILURE);
    }
    if ((sockfd2 = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Socket 2 creation failed");
        exit(EXIT_FAILURE);
    }
    if ((sockfd3 = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Socket 3 creation failed");
        exit(EXIT_FAILURE);
    }

    // Bind sockfd1 to PORT1 (receive from Server 1)
    memset(&servaddr1, 0, sizeof(servaddr1));
    servaddr1.sin_family = AF_INET;
    servaddr1.sin_addr.s_addr = INADDR_ANY;
    servaddr1.sin_port = htons(PORT1);

    if (bind(sockfd1, (const struct sockaddr *)&servaddr1, sizeof(servaddr1)) < 0) {
        perror("Bind failed on PORT1");
        exit(EXIT_FAILURE);
    }

    // Bind sockfd3 to PORT3 (receive from QGroundControl)
    memset(&servaddr3, 0, sizeof(servaddr3));
    servaddr3.sin_family = AF_INET;
    servaddr3.sin_addr.s_addr = INADDR_ANY;
    servaddr3.sin_port = htons(PORT3);

    if (bind(sockfd3, (const struct sockaddr *)&servaddr3, sizeof(servaddr3)) < 0) {
        perror("Bind failed on PORT3");
        exit(EXIT_FAILURE);
    }

    // Setup destination address for QGroundControl (sending to port 14550)
    memset(&qground_addr, 0, sizeof(qground_addr));
    qground_addr.sin_family = AF_INET;
    qground_addr.sin_port = htons(PORT2);
    inet_pton(AF_INET, "127.0.0.1", &qground_addr.sin_addr);

    // Setup destination address for Server 1 (sending back)
    struct sockaddr_in server1_addr;
    memset(&server1_addr, 0, sizeof(server1_addr));
    server1_addr.sin_family = AF_INET;
    server1_addr.sin_port = htons(SERVER1_PORT);
    inet_pton(AF_INET, "127.0.0.1", &server1_addr.sin_addr);

    len = sizeof(server1_recv_addr);

    printf("Server 2 listening on ports %d (Server 1), %d (QGroundControl), and %d (QGroundControl responses)\n", PORT1, PORT2, PORT3);

    while (1) {
        // Receive from both sockets in a non-blocking manner
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(sockfd1, &readfds);  // Add socket for PORT1 (Server 1)
        FD_SET(sockfd3, &readfds);  // Add socket for PORT3 (QGroundControl responses)

        int max_sd = sockfd1 > sockfd3 ? sockfd1 : sockfd3;
        int activity = select(max_sd + 1, &readfds, NULL, NULL, NULL);  // Monitor sockets

        if (FD_ISSET(sockfd1, &readfds)) {
            // Received from Server 1
            n = recvfrom(sockfd1, buffer, sizeof(buffer), MSG_WAITALL, (struct sockaddr *)&server1_recv_addr, &len);
            if (n < 0) {
                perror("Error in recvfrom Server 1");
            } else {
                // Decrypt the message
                if (crypto_aead_chacha20poly1305_ietf_decrypt(
                    decrypted, &decrypted_len,
                    NULL, buffer, n,
                    NULL, 0, // no additional data
                    nonce, key) != 0) {
                    // decryption failed
                    printf("Decryption failed.\n");
                    continue;
                }
                decrypted[decrypted_len] = '\0';
                printf("Decrypted message: %s\n", decrypted);

                // Forward the decrypted message to QGroundControl
                sendto(sockfd2, decrypted, decrypted_len, MSG_CONFIRM, (const struct sockaddr *)&qground_addr, sizeof(qground_addr));
                printf("Decrypted and forwarded to QGroundControl on port %d\n", PORT2);
            }
        }

        if (FD_ISSET(sockfd3, &readfds)) {
            // Received from QGroundControl
            n = recvfrom(sockfd3, decrypted, sizeof(decrypted), MSG_WAITALL, (struct sockaddr *)&qground_addr, &len);
            if (n < 0) {
                perror("Error in recvfrom QGroundControl");
            } else {
                // Re-encrypt the message before sending back to Server 1
                unsigned char re_encrypted[CIPHERTEXT_LEN];
                unsigned long long re_encrypted_len;
                if (crypto_aead_chacha20poly1305_ietf_encrypt(
                    re_encrypted, &re_encrypted_len,
                    decrypted, n,
                    NULL, 0, // no additional data
                    NULL, nonce, key) != 0) {
                    // re-encryption failed
                    printf("Re-encryption failed.\n");
                    continue;
                }
                // Forward the re-encrypted message back to Server 1
                sendto(sockfd1, re_encrypted, re_encrypted_len, MSG_CONFIRM, (const struct sockaddr *)&server1_addr, sizeof(server1_addr));
                printf("Re-encrypted and forwarded to Server 1 on port %d\n", SERVER1_PORT);
            }
        }
    }

    close(sockfd1);
    close(sockfd2);
    close(sockfd3);
    return 0;
}
