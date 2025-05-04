
/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "str.h"
#include <string.h>

static void lib_str_init(void) {
  // no-op for now
}

static void lib_str_shutdown(void) {
  // no-op for now
}

static size_t lib_str_lcpy(char *dst, const char *src, size_t dstsize) {
  const char *s = src;
  size_t n = dstsize;

  if (n != 0) {
    while (--n != 0) {
      if ((*dst++ = *s++) == '\0')
        break;
    }
  }

  if (n == 0) {
    if (dstsize != 0)
      *dst = '\0';
    while (*s++) ;
  }

  return (size_t)(s - src - 1);
}

static size_t lib_str_lcat(char *dst, const char *src, size_t dstsize) {
  size_t dlen = 0;
  const char *s = src;
  char *d = dst;
  size_t n = dstsize;

  while (n-- != 0 && *d != '\0') {
    d++;
    dlen++;
  }

  n = dstsize - dlen;
  if (n == 0)
    return dlen + strlen(src);

  while (*s != '\0') {
    if (n != 1) {
      *d++ = *s;
      n--;
    }
    s++;
  }

  *d = '\0';
  return dlen + (s - src);
}

static size_t lib_str_len(const char *str) {
  return strlen(str);
}

static int lib_str_eq(const char *a, const char *b) {
  return strcmp(a, b) == 0;
}

static const StrLib instance = {
  .init = lib_str_init,
  .shutdown = lib_str_shutdown,
  .lcpy = lib_str_lcpy,
  .lcat = lib_str_lcat,
  .len  = lib_str_len,
  .eq   = lib_str_eq

};

const StrLib *get_lib_str(void) {
  return &instance;
}
