/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef LIB_SIGLATCH_OPENSSL_DIGEST_H
#define LIB_SIGLATCH_OPENSSL_DIGEST_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
  const void *data;
  size_t size;
} DigestItem;

int siglatch_openssl_digest_array(const DigestItem *items, size_t item_count, uint8_t *out_digest);

#endif // LIB_SIGLATCH_OPENSSL_DIGEST_H
