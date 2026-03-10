/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_KNOCK_APP_OUTPUT_MODE_H
#define SIGLATCH_KNOCK_APP_OUTPUT_MODE_H

#include "../parse_opts.h"

typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
  void (*set_from_config)(void);
  void (*set_from_env)(void);
  void (*set_from_opts)(const Opts *opts);
} AppOutputModeLib;

const AppOutputModeLib *get_app_output_mode_lib(void);

#endif
