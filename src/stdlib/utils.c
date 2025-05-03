/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdint.h>
#include "payload.h"
//set to 1, so you can lazy button store the time and not have to pass around a global etc.
//printf("[%s] new packet\n", timestamp_now(0));
//printf("[%s] 📩 %zd bytes from %s\n", timestr, n, ip);
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
    printf("%s: ", label);
    for (size_t i = 0; i < len; ++i) {
        printf("%02x", digest[i]);
    }
    printf("\n");
}

void dumpPacketFields(const char *label, const KnockPacket *pkt) {
    if (!pkt) {
        printf("%s: NULL packet\n", label);
        return;
    }

    printf("---- %s ----\n", label);
    printf("Version: %u\n", pkt->version);
    printf("Timestamp: %u\n", pkt->timestamp);
    printf("User ID: %u\n", pkt->user_id);
    printf("Action ID: %u\n", pkt->action_id);
    printf("Challenge: %u\n", pkt->challenge);
    printf("Payload Length: %u\n", pkt->payload_len);

    printf("Payload (first 32 bytes or up to payload_len): ");
    size_t to_dump = pkt->payload_len;
    if (to_dump > 32) to_dump = 32;
    for (size_t i = 0; i < to_dump; ++i) {
        printf("%02x", pkt->payload[i]);
    }
    printf("\n");

    printf("--------------------\n");
}
