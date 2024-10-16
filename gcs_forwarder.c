#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORT1 14661   // Port to receive data from Server 1
#define PORT2 14550   // Port to send data to QGroundControl
#define PORT3 14551   // Port to receive data from QGroundControl
#define SERVER1_PORT 14662  // Port to send data back to Server 1

int main() {
    int sockfd1, sockfd2, sockfd3;
    struct sockaddr_in servaddr1, servaddr2, servaddr3, qground_addr, server1_recv_addr;
    int len, n;
    char buffer[1024];

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

    // Increase socket buffer sizes for better performance
    int buf_size = 1048576;  // 1MB buffer size
    setsockopt(sockfd1, SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(buf_size));
    setsockopt(sockfd1, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size));
    setsockopt(sockfd2, SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(buf_size));
    setsockopt(sockfd2, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size));
    setsockopt(sockfd3, SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(buf_size));

    // Bind sockfd1 to PORT1 (receive from Server 1)
    memset(&servaddr1, 0, sizeof(servaddr1));
    servaddr1.sin_family = AF_INET;
    servaddr1.sin_addr.s_addr = INADDR_ANY;
    servaddr1.sin_port = htons(PORT1);  // Bind to 14661 for receiving

    if (bind(sockfd1, (const struct sockaddr *)&servaddr1, sizeof(servaddr1)) < 0) {
        perror("Bind failed on PORT1");
        exit(EXIT_FAILURE);
    }

    // Bind sockfd3 to PORT3 (receive from QGroundControl on 14551)
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
    qground_addr.sin_port = htons(PORT2);  // QGroundControl's listening port
    inet_pton(AF_INET, "127.0.0.1", &qground_addr.sin_addr);  // Localhost IP address

    // Setup destination address for Server 1 (sending back)
    struct sockaddr_in server1_addr;
    memset(&server1_addr, 0, sizeof(server1_addr));
    server1_addr.sin_family = AF_INET;
    server1_addr.sin_port = htons(SERVER1_PORT);  // Port to send to Server 1
    inet_pton(AF_INET, "127.0.0.1", &server1_addr.sin_addr);  // Assuming Server 1 is localhost

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
            n = recvfrom(sockfd1, buffer, 1024, MSG_WAITALL, (struct sockaddr *)&server1_recv_addr, &len);
            if (n < 0) {
                perror("Error in recvfrom Server 1");
            } else {
                buffer[n] = '\0';
                printf("Received from Server 1: %s\n", buffer);

                // Forward the message to QGroundControl on PORT2 (14550) using sockfd2
                n = sendto(sockfd2, buffer, n, MSG_CONFIRM, (const struct sockaddr *)&qground_addr, sizeof(qground_addr));
                if (n < 0) {
                    perror("Error in sendto QGroundControl");
                } else {
                    printf("Forwarded to QGroundControl on port %d\n", PORT2);
                }
            }
        }

        if (FD_ISSET(sockfd3, &readfds)) {
            // Received from QGroundControl (responses on PORT3)
            n = recvfrom(sockfd3, buffer, 1024, MSG_WAITALL, (struct sockaddr *)&qground_addr, &len);
            if (n < 0) {
                perror("Error in recvfrom QGroundControl");
            } else {
                buffer[n] = '\0';
                printf("Received from QGroundControl: %s\n", buffer);

                // Forward the message back to Server 1 on PORT1 (14662)
                n = sendto(sockfd1, buffer, n, MSG_CONFIRM, (const struct sockaddr *)&server1_addr, sizeof(server1_addr));
                if (n < 0) {
                    perror("Error in sendto Server 1");
                } else {
                    printf("Forwarded to Server 1 on port %d\n", SERVER1_PORT);
                }
            }
        }
    }

    close(sockfd1);
    close(sockfd2);
    close(sockfd3);
    return 0;
}
