/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "nonce.h"

#include <stdlib.h>
#include <string.h>

int lib_nonce_init(void) {
  return 1;
}

void lib_nonce_shutdown(void) {
}

int lib_nonce_cache_init(NonceCache *cache, const NonceConfig *cfg) {
  size_t capacity = NONCE_DEFAULT_CAPACITY;
  size_t nonce_strlen = NONCE_DEFAULT_STRLEN;
  time_t ttl_seconds = NONCE_DEFAULT_TTL_SECONDS;
  size_t i = 0;

  if (!cache) {
    return 0;
  }

  lib_nonce_cache_shutdown(cache);

  if (cfg) {
    if (cfg->capacity > 0) {
      capacity = cfg->capacity;
    }
    if (cfg->nonce_strlen > 1) {
      nonce_strlen = cfg->nonce_strlen;
    }
    if (cfg->ttl_seconds >= 0) {
      ttl_seconds = cfg->ttl_seconds;
    }
  }

  cache->entries = calloc(capacity, sizeof(NonceEntry));
  cache->storage = calloc(capacity, nonce_strlen);
  if (!cache->entries || !cache->storage) {
    lib_nonce_cache_shutdown(cache);
    return 0;
  }

  for (i = 0; i < capacity; ++i) {
    cache->entries[i].nonce = cache->storage + (i * nonce_strlen);
  }

  cache->capacity = capacity;
  cache->nonce_strlen = nonce_strlen;
  cache->ttl_seconds = ttl_seconds;
  cache->next_index = 0;
  return 1;
}

void lib_nonce_cache_shutdown(NonceCache *cache) {
  if (!cache) {
    return;
  }

  free(cache->storage);
  free(cache->entries);
  *cache = (NonceCache){0};
}

void lib_nonce_clear(NonceCache *cache) {
  if (!cache || !cache->entries || !cache->storage) {
    return;
  }

  memset(cache->storage, 0, cache->capacity * cache->nonce_strlen);
  memset(cache->entries, 0, cache->capacity * sizeof(NonceEntry));
  for (size_t i = 0; i < cache->capacity; ++i) {
    cache->entries[i].nonce = cache->storage + (i * cache->nonce_strlen);
  }
  cache->next_index = 0;
}

int lib_nonce_check(NonceCache *cache, const char *nonce, time_t now) {
  size_t i = 0;

  if (!cache || !cache->entries || !nonce) {
    return 0;
  }

  for (i = 0; i < cache->capacity; ++i) {
    NonceEntry *entry = &cache->entries[i];

    if (!entry->nonce || entry->nonce[0] == '\0') {
      continue;
    }

    if ((now - entry->timestamp) > cache->ttl_seconds) {
      entry->nonce[0] = '\0';
      entry->timestamp = 0;
      continue;
    }

    if (strncmp(entry->nonce, nonce, cache->nonce_strlen) == 0) {
      return 1;
    }
  }

  return 0;
}

void lib_nonce_add(NonceCache *cache, const char *nonce, time_t now) {
  NonceEntry *entry = NULL;

  if (!cache || !cache->entries || !nonce || cache->capacity == 0 || cache->nonce_strlen == 0) {
    return;
  }

  entry = &cache->entries[cache->next_index];
  strncpy(entry->nonce, nonce, cache->nonce_strlen - 1);
  entry->nonce[cache->nonce_strlen - 1] = '\0';
  entry->timestamp = now;
  cache->next_index = (cache->next_index + 1) % cache->capacity;
}

static const NonceLib nonce_lib = {
  .init = lib_nonce_init,
  .shutdown = lib_nonce_shutdown,
  .cache_init = lib_nonce_cache_init,
  .cache_shutdown = lib_nonce_cache_shutdown,
  .clear = lib_nonce_clear,
  .check = lib_nonce_check,
  .add = lib_nonce_add
};

const NonceLib *get_lib_nonce(void) {
  return &nonce_lib;
}
