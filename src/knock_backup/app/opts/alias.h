/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_KNOCK_APP_OPTS_ALIAS_H
#define SIGLATCH_KNOCK_APP_OPTS_ALIAS_H

#include "../../../stdlib/argv.h"
#include "../command.h"

typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
  const ArgvOptionSpec *(*spec)(void);
  int (*parse)(const char *mode_selector, const ArgvParsed *parsed, AppCommand *out);
  void (*dump)(const AppAliasCommand *cmd);
} AppOptsAliasLib;

const AppOptsAliasLib *get_app_opts_alias_lib(void);

#endif
