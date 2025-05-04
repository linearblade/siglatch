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
  size_t (*len)(const char *str);              ///< strlen wrapper
  int (*eq)(const char *a, const char *b);     ///< strcmp == 0
} StrLib;

const StrLib *get_lib_str(void);

#endif /* SIGLATCH_STR_H */
