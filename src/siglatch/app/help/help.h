/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SERVER_APP_HELP_H
#define SIGLATCH_SERVER_APP_HELP_H

typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
  void (*version)(void);
  void (*show)(int argc, char *argv[]);
} AppHelpLib;

const AppHelpLib *get_app_help_lib(void);

#endif
