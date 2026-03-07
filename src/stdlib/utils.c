/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include "utils.h"
//set to 1, so you can lazy button store the time and not have to pass around a global etc.
//printf("[%s] new packet\n", timestamp_now(0));
//printf("[%s]  %zd bytes from %s\n", timestr, n, ip);

static UtilsContext g_utils_ctx = {0};

static void utils_set_context(const UtilsContext *ctx) {
    if (ctx) {
        g_utils_ctx = *ctx;
    } else {
        g_utils_ctx = (UtilsContext){0};
    }
}

static void utils_init(const UtilsContext *ctx) {
    utils_set_context(ctx);
}

static void utils_shutdown(void) {
    g_utils_ctx = (UtilsContext){0};
}

static void utils_print(const char *marker, const char *fmt, ...) {
    va_list args;

    va_start(args, fmt);
    if (g_utils_ctx.print && g_utils_ctx.print->uc_vfprintf) {
        (void)g_utils_ctx.print->uc_vfprintf(stdout, marker, fmt, args);
    } else {
        (void)vprintf(fmt, args);
    }
    va_end(args);
}

const char *timestamp_now(int cache) {
  
    static char buffer[32];   // persistent cache
    static time_t last = 0;   // cached timestamp

    time_t now = time(NULL);

    // Refresh if requested or unset
    if (!cache || last == 0 || now != last) {
        const char *raw = ctime(&now);
        if (!raw) return "unknown time";

        strncpy(buffer, raw, sizeof(buffer) - 1);
        buffer[sizeof(buffer) - 1] = '\0';
        buffer[strcspn(buffer, "\n")] = '\0';

        last = now;
    }

    return buffer;
}

void dumpDigest(const char *label, const uint8_t *digest, size_t len) {
    utils_print(NULL, "%s: ", label);
    for (size_t i = 0; i < len; ++i) {
        utils_print(NULL, "%02x", digest[i]);
    }
    utils_print(NULL, "\n");
}

void dumpPacketFields(const char *label, const KnockPacket *pkt) {
    if (!pkt) {
        utils_print(NULL, "%s: NULL packet\n", label);
        return;
    }

    utils_print(NULL, "---- %s ----\n", label);
    utils_print(NULL, "Version: %u\n", pkt->version);
    utils_print(NULL, "Timestamp: %u\n", pkt->timestamp);
    utils_print(NULL, "User ID: %u\n", pkt->user_id);
    utils_print(NULL, "Action ID: %u\n", pkt->action_id);
    utils_print(NULL, "Challenge: %u\n", pkt->challenge);
    utils_print(NULL, "Payload Length: %u\n", pkt->payload_len);

    utils_print(NULL, "Payload (first 32 bytes or up to payload_len): ");
    size_t to_dump = pkt->payload_len;
    if (to_dump > 32) to_dump = 32;
    for (size_t i = 0; i < to_dump; ++i) {
        utils_print(NULL, "%02x", pkt->payload[i]);
    }
    utils_print(NULL, "\n");

    utils_print(NULL, "--------------------\n");
}

static const UtilsLib utils_lib = {
    .init = utils_init,
    .set_context = utils_set_context,
    .shutdown = utils_shutdown,
    .timestamp_now = timestamp_now,
    .dump_digest = dumpDigest,
    .dump_packet_fields = dumpPacketFields
};

const UtilsLib *get_lib_utils(void) {
    return &utils_lib;
}
