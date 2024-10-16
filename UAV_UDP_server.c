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
    int sockfd_px4, sockfd_gcs;
    struct sockaddr_in serveraddr_px4, clientaddr_px4, serveraddr_network, clientaddr_network, serveraddr_gcs, clientaddr_gcs;
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

    // Create socket for PX4 communication
    sockfd_px4 = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd_px4 < 0) {
        perror("Socket creation failed for PX4");
        exit(EXIT_FAILURE);
    }

    // Configure UDP server to listen for PX4 messages on port 14660
    memset(&serveraddr_px4, 0, sizeof(serveraddr_px4));
    serveraddr_px4.sin_family = AF_INET;
    serveraddr_px4.sin_addr.s_addr = INADDR_ANY;
    serveraddr_px4.sin_port = htons(14660);  // PX4 sends data to this server

    // Bind the socket to port 14660
    if (bind(sockfd_px4, (const struct sockaddr *)&serveraddr_px4, sizeof(serveraddr_px4)) < 0) {
        perror("Bind failed on port 14660 (PX4 to UAVudpserver)");
        close(sockfd_px4);
        exit(EXIT_FAILURE);
    }

    // Create socket for GCS communication
    sockfd_gcs = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd_gcs < 0) {
        perror("Socket creation failed for GCS");
        exit(EXIT_FAILURE);
    }

    // Configure server to listen for encrypted data from GCSudpserver on port 14580
    memset(&serveraddr_gcs, 0, sizeof(serveraddr_gcs));
    serveraddr_gcs.sin_family = AF_INET;
    serveraddr_gcs.sin_addr.s_addr = INADDR_ANY;
    serveraddr_gcs.sin_port = htons(14580);  // GCSudpserver sends to port 14580

    if (bind(sockfd_gcs, (const struct sockaddr *)&serveraddr_gcs, sizeof(serveraddr_gcs)) < 0) {
        perror("Bind failed on port 14580 (GCS to UAVudpserver)");
        close(sockfd_gcs);
        exit(EXIT_FAILURE);
    }

    // Configure network address to send encrypted data to GCSudpserver (port 14570)
    memset(&serveraddr_network, 0, sizeof(serveraddr_network));
    serveraddr_network.sin_family = AF_INET;
    serveraddr_network.sin_port = htons(14570);  // GCSudpserver listens on port 14570
    inet_pton(AF_INET, "127.0.0.1", &serveraddr_network.sin_addr);  // Localhost for testing

    // Listen for and forward messages in both directions
    len = sizeof(clientaddr_px4);
    while (1) {
        // ------------------------------
        // PX4 -> UAVudpserver -> GCSudpserver
        // ------------------------------
        // Receive data from PX4
        n = recvfrom(sockfd_px4, buffer, BUFSIZE, 0, (struct sockaddr *)&clientaddr_px4, &len);
        if (n < 0) {
            perror("Receive failed from PX4");
            continue;
        }

        // Print the received data (from PX4)
        printf("\nReceived from PX4 (Original Packet):\n");
        print_hex((uint8_t *)buffer, n);

        // Encrypt the message before sending it over the network to GCSudpserver
        uint8_t encrypted[n];
        ChaCha20XOR(key, 1, nonce, (uint8_t *)buffer, encrypted, n);

        // Print the encrypted message
        printf("Encrypted message to network:\n");
        print_hex(encrypted, n);

        ssize_t sent_len = sendto(sockfd_gcs, encrypted, n, 0, (struct sockaddr *)&serveraddr_network, sizeof(serveraddr_network));
        if (sent_len < 0) {
            perror("Sending to network failed");
        } else {
            printf("Encrypted message sent to network\n");
        }

        // ------------------------------
        // GCS -> UAVudpserver -> PX4
        // ------------------------------
        // Listen for encrypted data from GCSudpserver
        n = recvfrom(sockfd_gcs, buffer, BUFSIZE, 0, (struct sockaddr *)&clientaddr_gcs, &len);
        if (n < 0) {
            perror("Receive failed from GCS");
            continue;
        }

        // Print the encrypted message received from GCS
        printf("\nReceived from GCS (Encrypted):\n");
        print_hex((uint8_t *)buffer, n);

        // Decrypt the message before forwarding to PX4
        uint8_t decrypted[n];
        ChaCha20XOR(key, 1, nonce, (uint8_t *)buffer, decrypted, n);

        // Print the decrypted message
        printf("Decrypted message to PX4:\n");
        print_hex(decrypted, n);

        // Forward the decrypted message to PX4
        sent_len = sendto(sockfd_px4, decrypted, n, 0, (struct sockaddr *)&clientaddr_px4, sizeof(clientaddr_px4));
        if (sent_len < 0) {
            perror("Forwarding to PX4 failed");
        } else {
            printf("Decrypted message forwarded to PX4\n");
        }
    }

    // Close the sockets
    close(sockfd_px4);
    close(sockfd_gcs);
    return 0;
}
