/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_LOG_H
#define SIGLATCH_LOG_H

#include <stdio.h>
#include <stdarg.h>  // for va_list if needed
#include <stddef.h>  // for size_t if used in function signatures
#include "log_context.h"
// ─────────────────────────────────────────────
// Log Level Definition
// ─────────────────────────────────────────────

typedef enum {
    LOG_NONE   = 0,
    LOG_ERROR  = 1,
    LOG_WARN   = 2,
    LOG_INFO   = 3,
    LOG_DEBUG  = 4,
    LOG_TRACE  = 5
} LogLevel;

// ─────────────────────────────────────────────
// Logger Interface
// ─────────────────────────────────────────────

typedef struct {
  // Lifecycle
  void (*init)(LogContext ctx);                       // Logger constructor
  void (*shutdown)(void);                   // Logger destructor

  // File Configuration
  void (*set_handle)(FILE *fp);
  int  (*open)(const char *path);
  void (*close)(void);
  
  void (*set_enabled)(int);
  void (*set_debug)(int);
  void (*set_level)(int);

  // Output

  void (*write)(const char *fmt, ...);          // File only
  void (*console)(const char *fmt, ...);        // Screen only
  void (*console_write)(const char *fmt, ...);  // File + screen
  void (*perror)(const char *prefix);           // File + screen
  // Unified routing
  void (*emit)(LogLevel level, int to_console, const char *fmt, ...); 
} Logger;

//Logger get_logger(void);  // Returns struct by value
const Logger *get_logger(void);


/*
  void log_set_file(FILE *fp);
  void log_set_enabled(int enable);
  void log_set_level(int level);
  void log_set_debug(int enable);

  void log_info(const char *fmt, ...);
  void log_debug(const char *fmt, ...);
  void log_info_and_screen(const char *fmt, ...);
*/
#endif // SIGLATCH_LOG_H
