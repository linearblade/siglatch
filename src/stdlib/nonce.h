/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_NONCE_H
#define SIGLATCH_NONCE_H

#include <stddef.h>
#include <time.h>

#define NONCE_DEFAULT_CAPACITY 128
#define NONCE_DEFAULT_STRLEN 32
#define NONCE_DEFAULT_TTL_SECONDS 60

typedef struct {
  char *nonce;
  time_t timestamp;
} NonceEntry;

typedef struct {
  NonceEntry *entries;
  char *storage;
  size_t capacity;
  size_t nonce_strlen;
  time_t ttl_seconds;
  size_t next_index;
} NonceCache;

typedef struct {
  size_t capacity;
  size_t nonce_strlen;
  time_t ttl_seconds;
} NonceConfig;

typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
  int (*cache_init)(NonceCache *cache, const NonceConfig *cfg);
  void (*cache_shutdown)(NonceCache *cache);
  void (*clear)(NonceCache *cache);
  int (*check)(NonceCache *cache, const char *nonce, time_t now);
  void (*add)(NonceCache *cache, const char *nonce, time_t now);
} NonceLib;

int lib_nonce_init(void);
void lib_nonce_shutdown(void);
int lib_nonce_cache_init(NonceCache *cache, const NonceConfig *cfg);
void lib_nonce_cache_shutdown(NonceCache *cache);
void lib_nonce_clear(NonceCache *cache);
int lib_nonce_check(NonceCache *cache, const char *nonce, time_t now);
void lib_nonce_add(NonceCache *cache, const char *nonce, time_t now);
const NonceLib *get_lib_nonce(void);

#endif
