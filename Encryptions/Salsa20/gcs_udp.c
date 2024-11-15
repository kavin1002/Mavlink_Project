// Server 2 (gcs_udp) using Salsa20 with circular buffer nonce storage
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sodium.h>
#include <stdint.h>
#include <stdbool.h>

#define PORT1 14661           // Port to receive encrypted data from Server 1
#define PORT2 14550           // Port to send data to QGroundControl
#define PORT3 14551           // Port to receive data from QGroundControl
#define SERVER1_PORT 14662    // Port to send encrypted data back to Server 1

#define MESSAGE_LEN 2048
#define NONCE_LEN crypto_stream_salsa20_NONCEBYTES
#define CIPHERTEXT_LEN (MESSAGE_LEN + crypto_stream_salsa20_NONCEBYTES)
#define MAX_NONCES 100000     // Maximum number of nonces to track

#define KEY_FILE "session_key.bin" // Path to the Salsa20 session key file
#define KEY_SIZE crypto_stream_salsa20_KEYBYTES

unsigned char key[KEY_SIZE]; // Session key
uint64_t nonce_counter = 2;  // Start with 2 for even nonces
unsigned char used_nonces[MAX_NONCES][NONCE_LEN]; // Circular buffer for nonces
int nonce_head = 0; // Points to the position to overwrite (oldest nonce)
int nonce_count = 0; // Tracks the total number of stored nonces

int load_session_key() {
    FILE *file = fopen(KEY_FILE, "rb");
    if (!file) {
        perror("Failed to open key file");
        return -1;
    }
    if (fread(key, 1, KEY_SIZE, file) != KEY_SIZE) {
        perror("Failed to read key file");
        fclose(file);
        return -1;
    }
    fclose(file);
    return 0;
}

bool is_nonce_used(unsigned char *nonce) {
    for (int i = 0; i < nonce_count; i++) {
        if (memcmp(used_nonces[i], nonce, NONCE_LEN) == 0) {
            return true; // Nonce found, indicating it's been used
        }
    }
    return false;
}

void store_nonce(unsigned char *nonce) {
    memcpy(used_nonces[nonce_head], nonce, NONCE_LEN);
    nonce_head = (nonce_head + 1) % MAX_NONCES;
    if (nonce_count < MAX_NONCES) {
        nonce_count++;
    }
}

void generate_nonce(unsigned char *nonce) {
    memset(nonce, 0, NONCE_LEN);
    memcpy(nonce, &nonce_counter, sizeof(nonce_counter));
    nonce_counter += 2; // Increment by 2 to keep it even
}

int main() {
    int sockfd1, sockfd3;
    struct sockaddr_in servaddr1, servaddr3, qground_addr, server1_send_addr;
    socklen_t len;
    ssize_t n;
    unsigned char buffer[MESSAGE_LEN];
    unsigned char nonce[NONCE_LEN];
    unsigned char ciphertext[CIPHERTEXT_LEN];
    unsigned char decrypted[MESSAGE_LEN];

    if (sodium_init() < 0) {
        fprintf(stderr, "Libsodium initialization failed.\n");
        return 1;
    }

    if (load_session_key() != 0) {
        fprintf(stderr, "Failed to load session key.\n");
        return 1;
    }

    sockfd1 = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd1 < 0) {
        perror("Socket 1 creation failed");
        return 1;
    }

    sockfd3 = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd3 < 0) {
        perror("Socket 3 creation failed");
        close(sockfd1);
        return 1;
    }

    memset(&servaddr1, 0, sizeof(servaddr1));
    servaddr1.sin_family = AF_INET;
    servaddr1.sin_addr.s_addr = INADDR_ANY;
    servaddr1.sin_port = htons(PORT1);

    if (bind(sockfd1, (struct sockaddr *)&servaddr1, sizeof(servaddr1)) < 0) {
        perror("Bind failed on PORT1");
        close(sockfd1);
        close(sockfd3);
        return 1;
    }

    memset(&servaddr3, 0, sizeof(servaddr3));
    servaddr3.sin_family = AF_INET;
    servaddr3.sin_addr.s_addr = INADDR_ANY;
    servaddr3.sin_port = htons(PORT3);

    if (bind(sockfd3, (struct sockaddr *)&servaddr3, sizeof(servaddr3)) < 0) {
        perror("Bind failed on PORT3");
        close(sockfd1);
        close(sockfd3);
        return 1;
    }

    memset(&qground_addr, 0, sizeof(qground_addr));
    qground_addr.sin_family = AF_INET;
    qground_addr.sin_port = htons(PORT2);
    inet_pton(AF_INET, "127.0.0.1", &qground_addr.sin_addr);

    memset(&server1_send_addr, 0, sizeof(server1_send_addr));
    server1_send_addr.sin_family = AF_INET;
    server1_send_addr.sin_port = htons(SERVER1_PORT);
    inet_pton(AF_INET, "127.0.0.1", &server1_send_addr.sin_addr);

    printf("Server 2 listening on ports %d (from Server 1), %d (to QGroundControl), and %d (from QGroundControl)\n", PORT1, PORT2, PORT3);

    while (1) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(sockfd1, &readfds);
        FD_SET(sockfd3, &readfds);

        int max_sd = sockfd1 > sockfd3 ? sockfd1 : sockfd3;
        int activity = select(max_sd + 1, &readfds, NULL, NULL, NULL);

        if (FD_ISSET(sockfd1, &readfds)) {
            n = recvfrom(sockfd1, ciphertext, sizeof(ciphertext), MSG_WAITALL, (struct sockaddr *)&servaddr1, &len);
            if (n > NONCE_LEN) {
                memcpy(nonce, ciphertext, NONCE_LEN);
                if (!is_nonce_used(nonce)) {
                    store_nonce(nonce);
                    crypto_stream_salsa20_xor(decrypted, ciphertext + NONCE_LEN, n - NONCE_LEN, nonce, key);
                    sendto(sockfd3, decrypted, n - NONCE_LEN, MSG_CONFIRM, (struct sockaddr *)&qground_addr, sizeof(qground_addr));
                } else {
                    printf("Replay attack detected! Nonce has already been used.\n");
                }
            }
        }

        if (FD_ISSET(sockfd3, &readfds)) {
            n = recvfrom(sockfd3, buffer, MESSAGE_LEN, MSG_WAITALL, (struct sockaddr *)&qground_addr, &len);
            if (n > 0) {
                generate_nonce(nonce);
                crypto_stream_salsa20_xor(ciphertext + NONCE_LEN, buffer, n, nonce, key);
                memcpy(ciphertext, nonce, NONCE_LEN);
                store_nonce(nonce);
                sendto(sockfd1, ciphertext, n + NONCE_LEN, MSG_CONFIRM, (struct sockaddr *)&server1_send_addr, sizeof(server1_send_addr));
            }
        }
    }

    close(sockfd1);
    close(sockfd3);
    return 0;
}
