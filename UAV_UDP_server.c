#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "chacha.h"  // Include ChaCha20 encryption header

#define PORT1 14660   // Port to receive data from PX4
#define PORT2 14662   // Port to receive data from Server 2
#define SERVER2_PORT 14661  // Port to send data to Server 2
#define PX4_PORT 14556  // PX4 listening port
#define KEY_SIZE 32     // 256-bit key for ChaCha20
#define NONCE_SIZE 12   // 96-bit nonce for ChaCha20
#define MSG_SIZE 1024   // Buffer size

// Function to print data in hexadecimal format (for debugging purposes)
void print_hex(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x ", data[i]);
    }
    printf("\n");
}

int main() {
    int sockfd1, sockfd2;
    struct sockaddr_in servaddr1, servaddr2, cliaddr;
    int len, n;
    char buffer[MSG_SIZE];

    // Define the ChaCha20 key and nonce
    uint8_t key[KEY_SIZE] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    uint8_t nonce[NONCE_SIZE] = {
        0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a,
        0x00, 0x00, 0x00, 0x00
    };
    uint32_t counter = 1;  // Initial block counter for ChaCha20

    // Create two socket file descriptors
    if ((sockfd1 = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Socket 1 creation failed");
        exit(EXIT_FAILURE);
    }
    if ((sockfd2 = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Socket 2 creation failed");
        exit(EXIT_FAILURE);
    }

    // Bind the first socket to PORT1 (receive from PX4)
    memset(&servaddr1, 0, sizeof(servaddr1));
    servaddr1.sin_family = AF_INET;
    servaddr1.sin_addr.s_addr = INADDR_ANY;
    servaddr1.sin_port = htons(PORT1);

    if (bind(sockfd1, (const struct sockaddr *)&servaddr1, sizeof(servaddr1)) < 0) {
        perror("Bind failed on PORT1");
        exit(EXIT_FAILURE);
    }

    // Bind the second socket to PORT2 (receive from Server 2)
    memset(&servaddr2, 0, sizeof(servaddr2));
    servaddr2.sin_family = AF_INET;
    servaddr2.sin_addr.s_addr = INADDR_ANY;
    servaddr2.sin_port = htons(PORT2);

    if (bind(sockfd2, (const struct sockaddr *)&servaddr2, sizeof(servaddr2)) < 0) {
        perror("Bind failed on PORT2");
        exit(EXIT_FAILURE);
    }

    len = sizeof(cliaddr);
    printf("Server 1 listening on ports %d (PX4) and %d (Server 2)\n", PORT1, PORT2);

    // Setup destination address for Server 2
    struct sockaddr_in server2_addr;
    memset(&server2_addr, 0, sizeof(server2_addr));
    server2_addr.sin_family = AF_INET;
    server2_addr.sin_port = htons(SERVER2_PORT);  // Port to send to Server 2
    inet_pton(AF_INET, "127.0.0.1", &server2_addr.sin_addr);  // Assuming Server 2 is localhost

    // Setup destination address for PX4 (send back to PX4 on port 14556)
    struct sockaddr_in px4_addr;
    memset(&px4_addr, 0, sizeof(px4_addr));
    px4_addr.sin_family = AF_INET;
    px4_addr.sin_port = htons(PX4_PORT);  // PX4 listening on port 14556
    inet_pton(AF_INET, "127.0.0.1", &px4_addr.sin_addr);  // Assuming PX4 is localhost

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
            n = recvfrom(sockfd1, buffer, MSG_SIZE, MSG_WAITALL, (struct sockaddr *)&cliaddr, &len);
            buffer[n] = '\0';
            printf("Received from PX4: %s\n", buffer);

            // Encrypt the message using ChaCha20
            uint8_t encrypted[MSG_SIZE];
            ChaCha20XOR(key, counter++, nonce, (uint8_t *)buffer, (uint8_t *)encrypted, n);

            printf("Encrypted message to be forwarded to Server 2: ");
            print_hex(encrypted, n);

            // Forward the encrypted message to Server 2
            sendto(sockfd1, encrypted, n, MSG_CONFIRM, (const struct sockaddr *)&server2_addr, sizeof(server2_addr));
            printf("Forwarded to Server 2 on port %d\n", SERVER2_PORT);
        }

        if (FD_ISSET(sockfd2, &readfds)) {
            // Received from Server 2 (encrypted)
            n = recvfrom(sockfd2, buffer, MSG_SIZE, MSG_WAITALL, (struct sockaddr *)&cliaddr, &len);
            if (n < 0) {
                perror("Error in recvfrom Server 2");
            } else {
                // Decrypt the message using ChaCha20
                uint8_t decrypted[MSG_SIZE];
                ChaCha20XOR(key, counter++, nonce, (uint8_t *)buffer, (uint8_t *)decrypted, n);

                printf("Decrypted message from Server 2: ");
                print_hex(decrypted, n);

                // Forward the decrypted message back to PX4 on port 14556
                sendto(sockfd1, decrypted, n, MSG_CONFIRM, (const struct sockaddr *)&px4_addr, sizeof(px4_addr));
                printf("Forwarded to PX4 on port %d\n", PX4_PORT);
            }
        }
    }

    close(sockfd1);
    close(sockfd2);
    return 0;
}
