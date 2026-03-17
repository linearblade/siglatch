/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SERVER_APP_OPTS_CONTRACT_H
#define SIGLATCH_SERVER_APP_OPTS_CONTRACT_H

#include "../config/config.h"

typedef struct {
  int help_requested;
  int dump_config_requested;
  int output_mode;
  char config_path[PATH_MAX];
  char server_name[MAX_SERVER_NAME];
} AppOpts;

#endif
