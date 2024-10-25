#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sodium.h>

#define PORT1 14660   // Port to receive data from PX4
#define PORT2 14662   // Port to receive encrypted data from Server 2
#define SERVER2_PORT 14661  // Port to send encrypted data to Server 2
#define PX4_PORT 14556  // PX4 listening port

#define MESSAGE_LEN 2048
#define NONCE_LEN crypto_secretbox_NONCEBYTES
#define CIPHERTEXT_LEN (MESSAGE_LEN + crypto_secretbox_MACBYTES)

int main() {
    int sockfd1, sockfd2;
    struct sockaddr_in servaddr1, servaddr2, cliaddr, server2_addr, px4_addr;
    int len, n;
    unsigned char buffer[MESSAGE_LEN];
    unsigned char nonce[NONCE_LEN];  // Nonce for encryption
    unsigned char ciphertext[CIPHERTEXT_LEN + NONCE_LEN]; // Buffer for ciphertext + nonce
    unsigned long long ciphertext_len;
    unsigned char decrypted[MESSAGE_LEN];
    unsigned long long decrypted_len;

    // Initialize libsodium
    if (sodium_init() < 0) {
        printf("Libsodium initialization failed.\n");
        return 1;
    }

    // Hardcoded encryption key (32 bytes)
    unsigned char key[crypto_secretbox_KEYBYTES] = "12345678901234567890123456789012";

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

            // Generate a random nonce
            randombytes_buf(nonce, NONCE_LEN);

            // Encrypt the message
            if (crypto_secretbox_easy(
                ciphertext + NONCE_LEN, buffer, n,
                nonce, key) != 0) {
                printf("Encryption failed.\n");
                continue;
            }

            // Prepend nonce to the ciphertext
            memcpy(ciphertext, nonce, NONCE_LEN);
            ciphertext_len = n + NONCE_LEN + crypto_secretbox_MACBYTES;

            // Send encrypted message (including nonce) to Server 2 on port 14661
            sendto(sockfd1, ciphertext, ciphertext_len, MSG_CONFIRM, (const struct sockaddr *)&server2_addr, sizeof(server2_addr));
            printf("Encrypted and forwarded to Server 2 on port %d\n", SERVER2_PORT);
        }

        if (FD_ISSET(sockfd2, &readfds)) {
            // Received encrypted data from Server 2 on port 14662
            n = recvfrom(sockfd2, ciphertext, sizeof(ciphertext), MSG_WAITALL, (struct sockaddr *)&cliaddr, &len);

            // Extract the nonce from the message
            memcpy(nonce, ciphertext, NONCE_LEN);

            // Decrypt the message
            if (crypto_secretbox_open_easy(
                decrypted, ciphertext + NONCE_LEN, n - NONCE_LEN,
                nonce, key) != 0) {
                printf("Decryption failed.\n");
                continue;
            }

            decrypted_len = n - NONCE_LEN - crypto_secretbox_MACBYTES;

            // Send decrypted message to PX4 on port 14556
            sendto(sockfd1, decrypted, decrypted_len, MSG_CONFIRM, (const struct sockaddr *)&px4_addr, sizeof(px4_addr));
            printf("Decrypted and forwarded to PX4 on port %d\n", PX4_PORT);
        }
    }

    close(sockfd1);
    close(sockfd2);
    return 0;
}
