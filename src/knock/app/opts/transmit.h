/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_KNOCK_APP_OPTS_TRANSMIT_H
#define SIGLATCH_KNOCK_APP_OPTS_TRANSMIT_H

#include "contract.h"

typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
  int (*parse)(int argc, char *argv[], Opts *opts_out, int *dump_requested);
  void (*dump)(const Opts *opts);
} AppOptsTransmitLib;

const AppOptsTransmitLib *get_app_opts_transmit_lib(void);

#endif
