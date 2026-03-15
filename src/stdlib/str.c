
/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "str.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

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

static char *lib_str_dup(const char *str) {
  size_t len = 0;
  char *copy = NULL;

  if (!str) {
    return NULL;
  }

  len = strlen(str) + 1;
  copy = (char *)malloc(len);
  if (!copy) {
    return NULL;
  }

  memcpy(copy, str, len);
  return copy;
}

static size_t lib_str_len(const char *str) {
  return strlen(str);
}

static int lib_str_eq(const char *a, const char *b) {
  return strcmp(a, b) == 0;
}

static int lib_str_is_blank(const char *str) {
  if (!str) {
    return 0;
  }

  while (*str) {
    if (!isspace((unsigned char)*str)) {
      return 0;
    }
    str++;
  }

  return 1;
}

static char *lib_str_trim(char *str) {
  char *end = NULL;

  if (!str) {
    return NULL;
  }

  while (*str && isspace((unsigned char)*str)) {
    str++;
  }

  if (*str == '\0') {
    return str;
  }

  end = str + strlen(str) - 1;
  while (end > str && isspace((unsigned char)*end)) {
    end--;
  }

  end[1] = '\0';
  return str;
}

static int lib_str_to_bool(const char *text, int *out) {
  int value = 0;

  if (!text || !out) {
    return 0;
  }

  if (strcasecmp(text, "1") == 0 ||
      strcasecmp(text, "yes") == 0) {
    value = 1;
  } else if (strcasecmp(text, "0") == 0 ||
             strcasecmp(text, "no") == 0) {
    value = 0;
  } else {
    return 0;
  }

  *out = value;
  return 1;
}

static int lib_str_split_kv(char *text, char **key_out, char **value_out) {
  char *eq = NULL;
  char *key = NULL;
  char *value = NULL;

  if (!text || !key_out || !value_out) {
    return 0;
  }

  eq = strchr(text, '=');
  if (!eq) {
    return 0;
  }

  *eq = '\0';
  key = lib_str_trim(text);
  value = lib_str_trim(eq + 1);

  *key_out = key;
  *value_out = value;
  return 1;
}

static void lib_str_parse_csv_fixed(char *items,
                                    int *count,
                                    int max_items,
                                    size_t item_size,
                                    const char *value) {
  char *copy = NULL;
  char *tok = NULL;

  if (!items || !count || max_items <= 0 || item_size == 0 || !value) {
    return;
  }

  copy = lib_str_dup(value);
  if (!copy) {
    return;
  }

  tok = strtok(copy, ",");
  while (tok && *count < max_items) {
    lib_str_lcpy(items + ((*count) * item_size), lib_str_trim(tok), item_size);
    (*count)++;
    tok = strtok(NULL, ",");
  }

  free(copy);
}

static const StrLib instance = {
  .init = lib_str_init,
  .shutdown = lib_str_shutdown,
  .lcpy = lib_str_lcpy,
  .lcat = lib_str_lcat,
  .dup = lib_str_dup,
  .len  = lib_str_len,
  .eq   = lib_str_eq,
  .is_blank = lib_str_is_blank,
  .trim = lib_str_trim,
  .to_bool = lib_str_to_bool,
  .split_kv = lib_str_split_kv,
  .parse_csv_fixed = lib_str_parse_csv_fixed

};

const StrLib *get_lib_str(void) {
  return &instance;
}
