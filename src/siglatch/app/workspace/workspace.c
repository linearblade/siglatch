/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "workspace.h"

#include <string.h>

static AppWorkspace workspace = {0};

static int workspace_init(void) {
  workspace = (AppWorkspace){0};
  return 1;
}

static void workspace_shutdown(void) {
  if (workspace.codec_context) {
    shared_knock_codec_context_destroy(workspace.codec_context);
    workspace.codec_context = NULL;
  }
  memset(&workspace, 0, sizeof(workspace));
}

static AppWorkspace *workspace_get(void) {
  return &workspace;
}

static const AppWorkspaceLib workspace_instance = {
  .init = workspace_init,
  .shutdown = workspace_shutdown,
  .get = workspace_get
};

const AppWorkspaceLib *get_app_workspace_lib(void) {
  return &workspace_instance;
}
