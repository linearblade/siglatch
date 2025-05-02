#ifndef SIGLATCH_UTILS_H
#define SIGLATCH_UTILS_H
#include <stdio.h>
#include <stdint.h>
#include "payload.h"

const char *timestamp_now(int cache);
void dumpDigest(const char *label, const uint8_t *digest, size_t len) ;
void dumpPacketFields(const char *label, const KnockPacket *pkt);
#endif // SIGLATCH_UTILS_H
