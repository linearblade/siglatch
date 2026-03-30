/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SHARED_KNOCK_DETECT_H
#define SIGLATCH_SHARED_KNOCK_DETECT_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
  SHARED_KNOCK_ROUTE_UNKNOWN = 0,
  SHARED_KNOCK_ROUTE_V1_LEGACY = 1,
  SHARED_KNOCK_ROUTE_V2_FORM1 = 2,
  SHARED_KNOCK_ROUTE_V3_FORM1 = 3
} SharedKnockRouteKind;

typedef struct {
  SharedKnockRouteKind kind;
  uint32_t version;
  uint8_t form;
  size_t expected_packet_size;
  int exact_size_required;
  int identified_by_prefix;
} SharedKnockRoutingInfo;

typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
  SharedKnockRouteKind (*detect_kind)(const uint8_t *buf, size_t buflen);
  int (*detect)(const uint8_t *buf, size_t buflen, SharedKnockRoutingInfo *out);
  const char *(*kind_name)(SharedKnockRouteKind kind);
} SharedKnockDetectLib;

int shared_knock_detect_init(void);
void shared_knock_detect_shutdown(void);
SharedKnockRouteKind shared_knock_detect_kind(const uint8_t *buf, size_t buflen);
int shared_knock_detect(const uint8_t *buf, size_t buflen, SharedKnockRoutingInfo *out);
const char *shared_knock_detect_kind_name(SharedKnockRouteKind kind);
const SharedKnockDetectLib *get_shared_knock_detect_lib(void);

#endif /* SIGLATCH_SHARED_KNOCK_DETECT_H */
