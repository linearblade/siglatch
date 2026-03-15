/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "debug.h"

#include <stdarg.h>
#include <stdio.h>

static SharedKnockDebugContext g_shared_knock_debug_ctx = {0};

static void shared_knock_debug_print(const char *fmt, ...) {
  va_list args;

  va_start(args, fmt);
  if (g_shared_knock_debug_ctx.print && g_shared_knock_debug_ctx.print->uc_vfprintf) {
    (void)g_shared_knock_debug_ctx.print->uc_vfprintf(stdout, NULL, fmt, args);
  } else {
    (void)vprintf(fmt, args);
  }
  va_end(args);
}

int shared_knock_debug_init(const SharedKnockDebugContext *ctx) {
  if (ctx) {
    g_shared_knock_debug_ctx = *ctx;
  } else {
    g_shared_knock_debug_ctx = (SharedKnockDebugContext){0};
  }

  return 1;
}

void shared_knock_debug_shutdown(void) {
  g_shared_knock_debug_ctx = (SharedKnockDebugContext){0};
}

void shared_knock_dump_packet_fields(const char *label, const KnockPacket *pkt) {
  size_t to_dump = 0;

  if (!pkt) {
    shared_knock_debug_print("%s: NULL packet\n", label ? label : "KnockPacket");
    return;
  }

  shared_knock_debug_print("---- %s ----\n", label ? label : "KnockPacket");
  shared_knock_debug_print("Version: %u\n", pkt->version);
  shared_knock_debug_print("Timestamp: %u\n", pkt->timestamp);
  shared_knock_debug_print("User ID: %u\n", pkt->user_id);
  shared_knock_debug_print("Action ID: %u\n", pkt->action_id);
  shared_knock_debug_print("Challenge: %u\n", pkt->challenge);
  shared_knock_debug_print("Payload Length: %u\n", pkt->payload_len);

  shared_knock_debug_print("Payload (first 32 bytes or up to payload_len): ");
  to_dump = pkt->payload_len;
  if (to_dump > 32) {
    to_dump = 32;
  }
  for (size_t i = 0; i < to_dump; ++i) {
    shared_knock_debug_print("%02x", pkt->payload[i]);
  }
  shared_knock_debug_print("\n");
  shared_knock_debug_print("--------------------\n");
}

static const SharedKnockDebugLib shared_knock_debug = {
  .init = shared_knock_debug_init,
  .shutdown = shared_knock_debug_shutdown,
  .dump_packet_fields = shared_knock_dump_packet_fields
};

const SharedKnockDebugLib *get_shared_knock_debug_lib(void) {
  return &shared_knock_debug;
}
