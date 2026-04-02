/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_KNOCK_APP_ALIAS_COMMAND_H
#define SIGLATCH_KNOCK_APP_ALIAS_COMMAND_H

#include "../command.h"

typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
  int (*execute)(const AppAliasCommand *cmd);
} AppAliasCommandLib;

const AppAliasCommandLib *get_app_alias_command_lib(void);

#endif // SIGLATCH_KNOCK_APP_ALIAS_COMMAND_H
