/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_STR_H
#define SIGLATCH_STR_H

#include <stddef.h>

/**
 * @file str.h
 * @brief Singleton string utility library for safe, portable operations
 *
 * Provides safe wrappers for common C string operations such as copying,
 * concatenation, and length calculation. Uses function pointers in a
 * singleton StringLib struct for runtime use.
 *
 * To install:
 *   1. Place string.c and string.h in your stdlib directory
 *   2. Include str.h where needed
 *   3. Call `get_lib_string()` once to access the `StringLib` object
 */

typedef struct {
  void (*init)(void);                           ///< Optional setup (noop for now)
  void (*shutdown)(void);                           ///< Optional setup (noop for now)
  size_t (*lcpy)(char *dst, const char *src, size_t dstsize);   ///< Safe strlcpy
  size_t (*lcat)(char *dst, const char *src, size_t dstsize);    ///< Safe strlcat
  char *(*dup)(const char *str);               ///< Duplicate string with malloc ownership
  size_t (*len)(const char *str);              ///< strlen wrapper
  int (*eq)(const char *a, const char *b);     ///< strcmp == 0
  int (*is_blank)(const char *str);            ///< Return 1 when string is empty or ASCII whitespace only
  char *(*trim)(char *str);                    ///< Trim leading/trailing ASCII whitespace in place
  int (*to_bool)(const char *text, int *out);  ///< Parse yes/no style boolean text into out
  int (*split_kv)(char *text, char **key_out, char **value_out); ///< Split first key=value pair in place
  void (*parse_csv_fixed)(char *items, int *count, int max_items, size_t item_size, const char *value); ///< Split CSV text into fixed-width caller-provided slots
} StrLib;

const StrLib *get_lib_str(void);

#endif /* SIGLATCH_STR_H */
