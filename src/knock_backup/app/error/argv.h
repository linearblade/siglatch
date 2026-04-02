/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_KNOCK_APP_ERROR_ARGV_H
#define SIGLATCH_KNOCK_APP_ERROR_ARGV_H

#include <stddef.h>
#include "../../../stdlib/argv.h"

typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
  int (*shape)(const ArgvParsed *parsed, char *out, size_t out_size);
  int (*shape_typed)(const ArgvParsedOption *opt, const ArgvError *err, char *out, size_t out_size);
} AppErrorArgvLib;

const AppErrorArgvLib *get_app_error_argv_lib(void);

#endif
