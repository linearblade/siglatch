/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include <string.h>
#include <stdio.h>
#include "nonce_cache.h"

typedef struct {
  char nonce[NONCE_STRLEN];
  time_t timestamp;
} NonceEntry;


static void nonce_clear(void);


static NonceEntry nonce_cache[NONCE_MAX];
static int nonce_index = 0;



static void nonce_init(void) {
  memset(nonce_cache, 0, sizeof(nonce_cache));
  nonce_index = 0;
}

static void nonce_shutdown(void) {
  nonce_clear();  // for now, just clear the cache
}

static void nonce_clear(void) {
  memset(nonce_cache, 0, sizeof(nonce_cache));
  nonce_index = 0;
}

static int nonce_check(const char *nonce, time_t now) {
  for (int i = 0; i < NONCE_MAX; ++i) {
    if (nonce_cache[i].nonce[0] == '\0') continue;
    if ((now - nonce_cache[i].timestamp) > NONCE_TTL) {
      nonce_cache[i].nonce[0] = '\0';  // expire old entry
      continue;
    }
    if (strncmp(nonce_cache[i].nonce, nonce, NONCE_STRLEN) == 0) {
      return 1;  // replay detected
    }
  }
  return 0;
}

static void nonce_add(const char *nonce, time_t now) {
  strncpy(nonce_cache[nonce_index].nonce, nonce, NONCE_STRLEN - 1);
  nonce_cache[nonce_index].nonce[NONCE_STRLEN - 1] = '\0';
  nonce_cache[nonce_index].timestamp = now;
  nonce_index = (nonce_index + 1) % NONCE_MAX;
}

static const NonceCache instance = {
  .init = nonce_init,
  .shutdown = nonce_shutdown,
  .check = nonce_check,
  .add = nonce_add,
  .clear = nonce_clear
};

const NonceCache *get_nonce_cache(void) {
  return &instance;
}
