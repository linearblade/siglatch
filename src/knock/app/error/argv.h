/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_KNOCK_APP_ERROR_ARGV_H
#define SIGLATCH_KNOCK_APP_ERROR_ARGV_H

#include "../../../stdlib/argv.h"

typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
  int (*parse)(const ArgvParsed *parsed);
  int (*typed)(const ArgvParsedOption *opt, const ArgvError *err);
} AppErrorArgvLib;

const AppErrorArgvLib *get_app_error_argv_lib(void);

#endif
