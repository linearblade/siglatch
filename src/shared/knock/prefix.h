/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SHARED_KNOCK_PREFIX_H
#define SIGLATCH_SHARED_KNOCK_PREFIX_H

#include <stdint.h>

/*
 * Post-v1 packet-family routing prefix.
 *
 * This is intentionally shared by v2 and later packet families.
 * It is router metadata only: family magic, wire version, and outer form.
 */
#define SHARED_KNOCK_PREFIX_MAGIC 0x534C504Bu /* "SLPK" */
#define SHARED_KNOCK_PREFIX_SIZE   9u

typedef struct {
  uint32_t magic;
  uint32_t version;
  uint8_t form;
} SharedKnockPrefix;

#endif /* SIGLATCH_SHARED_KNOCK_PREFIX_H */
