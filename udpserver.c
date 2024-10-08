#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <unistd.h>

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
    int sockfd;
    struct sockaddr_in serveraddr_px4, serveraddr_qgc, clientaddr_px4, clientaddr_qgc;
    char buffer[BUFSIZE];
    socklen_t len;
    ssize_t n;

    // Create socket
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Configure UDP server to listen on port 14560 (from PX4 to QGC)
    memset(&serveraddr_px4, 0, sizeof(serveraddr_px4));
    serveraddr_px4.sin_family = AF_INET;
    serveraddr_px4.sin_addr.s_addr = INADDR_ANY;
    serveraddr_px4.sin_port = htons(14560);  // PX4 to QGC

    // Bind the socket to port 14560
    if (bind(sockfd, (const struct sockaddr *)&serveraddr_px4, sizeof(serveraddr_px4)) < 0) {
        perror("Bind failed on port 14560 (PX4 to QGC)");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // Configure QGroundControl address (forward messages to port 14550)
    memset(&serveraddr_qgc, 0, sizeof(serveraddr_qgc));
    serveraddr_qgc.sin_family = AF_INET;
    serveraddr_qgc.sin_port = htons(14550);  // QGroundControl listens on port 14550
    inet_pton(AF_INET, "127.0.0.1", &serveraddr_qgc.sin_addr);  // Assuming QGC is on the same machine

    // Listen for and forward messages in both directions
    len = sizeof(clientaddr_px4);
    while (1) {
        // Forward from PX4 to QGroundControl (port 14560 -> port 14550)
        n = recvfrom(sockfd, buffer, BUFSIZE, 0, (struct sockaddr *)&clientaddr_px4, &len);
        if (n < 0) {
            perror("Receive failed from PX4");
            continue;
        }
        // Print received data from PX4
        printf("Received from PX4:\n");
        print_hex((uint8_t *)buffer, n);

        // Forward to QGroundControl
        ssize_t sent_len = sendto(sockfd, buffer, n, 0, (struct sockaddr *)&serveraddr_qgc, sizeof(serveraddr_qgc));
        if (sent_len < 0) {
            perror("Forwarding to QGroundControl failed");
        } else {
            printf("Message forwarded to QGroundControl\n");
        }

        // Forward from QGroundControl to PX4 (port 14550 -> port 14560)
        n = recvfrom(sockfd, buffer, BUFSIZE, 0, (struct sockaddr *)&clientaddr_qgc, &len);
        if (n < 0) {
            perror("Receive failed from QGroundControl");
            continue;
        }
        // Print received data from QGroundControl
        printf("Received from QGroundControl:\n");
        print_hex((uint8_t *)buffer, n);

        // Forward to PX4
        sent_len = sendto(sockfd, buffer, n, 0, (struct sockaddr *)&serveraddr_px4, sizeof(serveraddr_px4));
        if (sent_len < 0) {
            perror("Forwarding to PX4 failed");
        } else {
            printf("Message forwarded to PX4\n");
        }
    }

    // Close the socket (this will never be reached in the current loop)
    close(sockfd);
    return 0;
}
