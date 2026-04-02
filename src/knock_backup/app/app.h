/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_KNOCK_APP_H
#define SIGLATCH_KNOCK_APP_H

#include "opts/opts.h"
#include "env/env.h"
#include "alias/alias.h"
#include "output_mode/output_mode.h"
#include "help/help.h"
#include "transmit/transmit.h"
#include "error/argv.h"

typedef struct {
  AppOptsLib opts;
  AppEnvLib env;
  AppAliasLib alias;
  AppOutputModeLib output_mode;
  AppHelpLib help;
  AppErrorArgvLib error_argv;
  AppTransmitLib transmit;
} App;

extern App app;

int init_app(void);
void shutdown_app(void);

#endif
