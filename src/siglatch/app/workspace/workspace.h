/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SERVER_APP_WORKSPACE_H
#define SIGLATCH_SERVER_APP_WORKSPACE_H

#include "../../../shared/knock/codec3/context.h"

typedef struct {
  SharedKnockCodec3Context *codec_context;
} AppWorkspace;

typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
  AppWorkspace *(*get)(void);
} AppWorkspaceLib;

const AppWorkspaceLib *get_app_workspace_lib(void);

#endif
