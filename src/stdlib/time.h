#ifndef SIGLATCH_TIME_H
#define SIGLATCH_TIME_H

#include <stddef.h>
#include <time.h>

/**
 * @file time.h
 * @brief Singleton time library for formatted and numeric timestamps
 *
 * This module provides unified timestamp access for the siglatch runtime.
 * It supports raw Unix timestamps, formatted strings for logs, and basic
 * human-readable formats. All access is through function pointers in a
 * singleton TimeLib struct.
 *
 * To install:
 *   1. Place time.c and time.h in your stdlib directory
 *   2. Include time.h where needed
 *   3. Call `get_lib_time()` once to access the `TimeLib` object
 */

typedef struct {
  void (*init)(void);                         ///< Optional lifecycle setup
  void (*shutdown)(void);                     ///< Optional teardown logic
  time_t (*now)(void);                        ///< time_t
  long (*unix)(void);                         ///< Unix timestamp as integer
  const char *(*human)(int cache);            ///< ctime-style human string
  const char *(*log)(void);                   ///< ISO 8601 formatted time
  const char *(*unix_string)(void);           ///< Unix timestamp as string
} TimeLib;

const TimeLib *get_lib_time(void);

#endif // SIGLATCH_TIME_H
