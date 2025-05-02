#include "udp.h"
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

// Static internal context
static UdpContext g_udp_ctx = {0};
static void printHEX(const unsigned char *input, size_t input_len) ;
// Lifecycle functions
static void udp_set_context(const UdpContext *ctx) {
    if (!ctx || !ctx->log) {
        return;
    }
    g_udp_ctx = *ctx; // Shallow copy
}

static void udp_init(const UdpContext *ctx) {
    udp_set_context(ctx);
}

static void udp_shutdown(void) {
    g_udp_ctx = (UdpContext){0};
}

static int udp_send(const char *target_ip, uint16_t port,
                    const unsigned char *data, size_t data_len) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        if (g_udp_ctx.log) {
            g_udp_ctx.log->perror("socket");
        }
        return 0;
    }

    struct sockaddr_in server;
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(port);

    if (inet_pton(AF_INET, target_ip, &server.sin_addr) <= 0) {
        if (g_udp_ctx.log) {
            g_udp_ctx.log->perror("inet_pton");
        }
        close(sock);
        return 0;
    }

    printHEX(data,data_len);
    
    ssize_t sent = sendto(sock, data, data_len, 0,
                          (struct sockaddr *)&server, sizeof(server));
    if (sent < 0) {
        if (g_udp_ctx.log) {
            g_udp_ctx.log->perror("sendto");
        }
        close(sock);
        return 0;
    }

    if (g_udp_ctx.log) {
        g_udp_ctx.log->emit(LOG_INFO, 1, "📤 Sent UDP payload to %s:%u (%zu bytes)\n",
                            target_ip, port, data_len);
    }

    close(sock);
    return 1;
}

static void printHEX(const unsigned char *input, size_t input_len) {
    if (!input || input_len == 0) {
        printf("⚠️  printHEX called with null or empty input");
        return;
    }

    printf("🔎 Binary (non-ASCII) payload:");

    char line[256] = {0};
    size_t pos = 0;
    size_t limit = (input_len > 512) ? 512 : input_len;

    for (size_t i = 0; i < limit; ++i) {
        if (pos >= sizeof(line) - 4) break;  // Leave space for null and safety
        int written = snprintf(line + pos, sizeof(line) - pos, "%02X ", input[i]);
        if (written <= 0 || (size_t)written >= sizeof(line) - pos) break;
        pos += (size_t)written;
    }

    if (input_len > 512 && pos + 18 < sizeof(line)) {
        strncat(line, "... (truncated)", sizeof(line) - strlen(line) - 1);
    }

    printf("%s\n", line);
}

// Singleton instance
static const UdpLib udp_instance = {
    .init         = udp_init,
    .set_context  = udp_set_context,
    .shutdown     = udp_shutdown,
    .send         = udp_send
};

const UdpLib *get_udp_lib(void) {
    return &udp_instance;
}
