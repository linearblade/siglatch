/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */


#ifndef SIGLATCH_NONCE_CACHE_H
#define SIGLATCH_NONCE_CACHE_H

#include <time.h>

#define NONCE_MAX 128
#define NONCE_STRLEN 32
#define NONCE_TTL 60  // seconds

void nonce_cache_init();
int nonce_seen(const char *nonce, time_t now);
void nonce_cache_add(const char *nonce, time_t now);

#endif // SIGLATCH_NONCE_CACHE_H
