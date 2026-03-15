/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SERVER_APP_OPTS_H
#define SIGLATCH_SERVER_APP_OPTS_H

#include "contract.h"

typedef struct {
  int reserved;
} AppOptsContext;

typedef struct {
  int ok;
  int exit_code;
  char error[256];
  AppOpts values;
} AppParsedOpts;

typedef struct {
  int (*init)(const AppOptsContext *ctx);
  void (*shutdown)(void);
  int (*parse)(int argc, char *argv[], AppParsedOpts *out);
  void (*dump)(const AppParsedOpts *parsed);
} AppOptsLib;

const AppOptsLib *get_app_opts_lib(void);

#endif
