
#ifndef SIGLATCH_TIME_H
#define SIGLATCH_TIME_H

#include <stddef.h>  // for size_t

typedef struct {
  void (*init)(void);
  void (*shutdown)(void);

  long (*unix)(void);               // Unix timestamp (seconds since epoch)
  const char *(*human)(int);        // Human-readable string (ctime-style, cached)
  const char *(*log)(void);         // ISO 8601 log format
  const char *(*unix_string)(void); // Unix timestamp as a string.
} TimeLib;

const TimeLib *get_lib_time(void);

#endif // SIGLATCH_TIME_H
