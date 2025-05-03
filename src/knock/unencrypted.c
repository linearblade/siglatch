/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 50000
#define TARGET "127.0.0.1"

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <message>\n", argv[0]);
        return 1;
    }

    int sock;
    struct sockaddr_in server;
    const char *message = argv[1];

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(PORT);

    if (inet_pton(AF_INET, TARGET, &server.sin_addr) <= 0) {
        perror("inet_pton");
        close(sock);
        return 1;
    }

    ssize_t sent = sendto(sock, message, strlen(message), 0,
                          (struct sockaddr *)&server, sizeof(server));
    if (sent < 0) {
        perror("sendto");
        close(sock);
        return 1;
    }

    printf("Sent: '%s' to %s:%d\n", message, TARGET, PORT);
    close(sock);
    return 0;
}
