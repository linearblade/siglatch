#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "config.h"
#include "udp_listener.h"
#include "lib.h"

#define BUF_SIZE 4096
#define TIMEOUT_SEC 5
int start_udp_listener(const siglatch_config *cfg) {
    int sock;
    struct sockaddr_in server;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
      LOGPERR("❌ Socket creation failed");
        return -1;
    }

    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(cfg->current_server->port);  // Use dynamic port from config

    if (bind(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        LOGPERR("❌ Bind failed");
        close(sock);
        return -1;
    }
    
    struct timeval tv = {TIMEOUT_SEC, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    LOGW("📡 Daemon started on UDP port %d\n", cfg->current_server->port);
    return sock;
}
