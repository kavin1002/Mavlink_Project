#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "chacha.h"  // Include your ChaCha20 header

#define BUFSIZE 1024

// Function to print received data in hexadecimal format
void print_hex(const uint8_t *data, size_t len) {
    printf("Received Data (Hex): ");
    for (size_t i = 0; i < len; i++) {
        printf("%02x ", data[i]);
    }
    printf("\n");
}

int main() {
    int sockfd_network, sockfd_qgc;
    struct sockaddr_in serveraddr_qgc, clientaddr_qgc, serveraddr_network, clientaddr_network, serveraddr_uav;
    char buffer[BUFSIZE];
    socklen_t len;
    ssize_t n;

    // Define the key and nonce for ChaCha20 encryption/decryption
    uint8_t key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    uint8_t nonce[12] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a,
        0x00, 0x00, 0x00, 0x00
    };

    // Create socket for receiving data from UAVudpserver
    sockfd_network = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd_network < 0) {
        perror("Socket creation failed for network");
        exit(EXIT_FAILURE);
    }

    // Configure UDP server to listen for encrypted data from UAVudpserver (port 14570)
    memset(&serveraddr_network, 0, sizeof(serveraddr_network));
    serveraddr_network.sin_family = AF_INET;
    serveraddr_network.sin_addr.s_addr = INADDR_ANY;
    serveraddr_network.sin_port = htons(14570);  // UAVudpserver sends to port 14570

    if (bind(sockfd_network, (const struct sockaddr *)&serveraddr_network, sizeof(serveraddr_network)) < 0) {
        perror("Bind failed on port 14570 (network to GCSudpserver)");
        close(sockfd_network);
        exit(EXIT_FAILURE);
    }

    // Create a separate socket for QGroundControl communication
    sockfd_qgc = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd_qgc < 0) {
        perror("Socket creation failed for QGC");
        close(sockfd_network);
        exit(EXIT_FAILURE);
    }

    // Configure QGroundControl address to send decrypted messages to QGC (port 14550)
    memset(&serveraddr_qgc, 0, sizeof(serveraddr_qgc));
    serveraddr_qgc.sin_family = AF_INET;
    serveraddr_qgc.sin_port = htons(14550);  // QGroundControl listens on port 14550
    inet_pton(AF_INET, "127.0.0.1", &serveraddr_qgc.sin_addr);  // Assuming QGC is on the same machine

    // Configure server to listen for QGroundControl messages on port 14550
    memset(&serveraddr_uav, 0, sizeof(serveraddr_uav));
    serveraddr_uav.sin_family = AF_INET;
    serveraddr_uav.sin_port = htons(14580);  // UAVudpserver listens on port 14580

    // Listen for and forward messages in both directions
    len = sizeof(clientaddr_network);
    while (1) {
        // ------------------------------
        // UAV -> GCSudpserver -> QGC
        // ------------------------------
        // Receive encrypted message from UAVudpserver
        n = recvfrom(sockfd_network, buffer, BUFSIZE, 0, (struct sockaddr *)&clientaddr_network, &len);
        if (n < 0) {
            perror("Receive failed from network");
            continue;
        }

        // Print the encrypted message received from UAV
        printf("\nReceived from network (Encrypted):\n");
        print_hex((uint8_t *)buffer, n);

        // Decrypt the message before sending it to QGroundControl
        uint8_t decrypted[n];
        ChaCha20XOR(key, 1, nonce, (uint8_t *)buffer, decrypted, n);

        // Print the decrypted message
        printf("Decrypted message to QGroundControl:\n");
        print_hex(decrypted, n);

        // Send decrypted message to QGroundControl
        ssize_t sent_len = sendto(sockfd_qgc, decrypted, n, 0, (struct sockaddr *)&serveraddr_qgc, sizeof(serveraddr_qgc));
        if (sent_len < 0) {
            perror("Sending to QGroundControl failed");
        } else {
            printf("Decrypted message sent to QGroundControl\n");
        }

        // ------------------------------
        // QGC -> GCSudpserver -> UAV
        // ------------------------------
        // Receive data from QGroundControl
        n = recvfrom(sockfd_qgc, buffer, BUFSIZE, 0, (struct sockaddr *)&clientaddr_qgc, &len);
        if (n < 0) {
            perror("Receive failed from QGroundControl");
            continue;
        }

        // Print the received data (from QGroundControl)
        printf("\nReceived from QGroundControl (Original Packet):\n");
        print_hex((uint8_t *)buffer, n);

        // Encrypt the message before sending it over the network to UAVudpserver
        uint8_t encrypted[n];
        ChaCha20XOR(key, 1, nonce, (uint8_t *)buffer, encrypted, n);

        // Print the encrypted message
        printf("Encrypted message to UAVudpserver:\n");
        print_hex(encrypted, n);

        // Send encrypted message to UAVudpserver
        sent_len = sendto(sockfd_network, encrypted, n, 0, (struct sockaddr *)&serveraddr_uav, sizeof(serveraddr_uav));
        if (sent_len < 0) {
            perror("Sending to UAVudpserver failed");
        } else {
            printf("Encrypted message sent to UAVudpserver\n");
        }
    }

    // Close the sockets
    close(sockfd_network);
    close(sockfd_qgc);
    return 0;
}
