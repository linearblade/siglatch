/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_KNOCK_APP_HELP_H
#define SIGLATCH_KNOCK_APP_HELP_H

typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
  void (*printHelp)(void);
  void (*errorMessage)(void);
} AppHelpLib;

const AppHelpLib *get_app_help_lib(void);

#endif
