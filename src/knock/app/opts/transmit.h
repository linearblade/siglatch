/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_KNOCK_APP_OPTS_TRANSMIT_H
#define SIGLATCH_KNOCK_APP_OPTS_TRANSMIT_H

#include "../../../stdlib/argv.h"
#include "../command.h"
#include "contract.h"

typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
  const ArgvOptionSpec *(*spec)(void);
  int (*parse)(const char *mode_selector, const ArgvParsed *parsed, AppCommand *out);
  void (*dump)(const Opts *opts);
} AppOptsTransmitLib;

const AppOptsTransmitLib *get_app_opts_transmit_lib(void);

#endif
