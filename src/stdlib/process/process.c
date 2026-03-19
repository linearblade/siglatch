/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "process.h"

#include <stdio.h>
#include <string.h>

static int process_wire_children(void);
static int process_init(void);
static void process_shutdown(void);

static ProcessLib g_process = {
  .init = process_init,
  .shutdown = process_shutdown,
  .user = {0}
};

static int g_process_initialized = 0;
static int g_process_wired = 0;

static int process_wire_children(void) {
  const ProcessUserLib *user = NULL;

  if (g_process_wired) {
    return 1;
  }

  user = get_lib_process_user();
  if (!user) {
    fprintf(stderr, "Failed to wire stdlib.process barrel: user provider unavailable\n");
    return 0;
  }

  g_process.user = *user;
  if (!g_process.user.init || !g_process.user.shutdown ||
      !g_process.user.lookup_by_name || !g_process.user.drop_to_name ||
      !g_process.user.drop_to_identity) {
    fprintf(stderr, "Failed to wire stdlib.process barrel: incomplete child wiring\n");
    memset(&g_process.user, 0, sizeof(g_process.user));
    return 0;
  }

  g_process_wired = 1;
  return 1;
}

static int process_init(void) {
  if (g_process_initialized) {
    return 1;
  }

  if (!process_wire_children()) {
    return 0;
  }

  g_process.user.init();
  g_process_initialized = 1;
  return 1;
}

static void process_shutdown(void) {
  if (!g_process_initialized) {
    return;
  }

  g_process.user.shutdown();
  g_process_initialized = 0;
}

const ProcessLib *get_lib_process(void) {
  if (!process_wire_children()) {
    return NULL;
  }

  return &g_process;
}
