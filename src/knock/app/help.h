/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_KNOCK_APP_HELP_H
#define SIGLATCH_KNOCK_APP_HELP_H

#include "../parse_opts.h"

typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
  int (*isHelp)(int argc, char *argv[]);
  void (*printHelp)(void);
  void (*errorMessage)(void);
  void (*handleParseResult)(int argc, char *argv[], const Opts *opts);
} AppHelpLib;

const AppHelpLib *get_app_help_lib(void);

#endif
