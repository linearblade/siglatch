/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_KNOCK_APP_OPTS_H
#define SIGLATCH_KNOCK_APP_OPTS_H

typedef struct {
  int reserved;
} AppOptsContext;

typedef struct {
  int (*init)(const AppOptsContext *ctx);
  void (*shutdown)(void);
} AppOptsLib;

const AppOptsLib *get_app_opts_lib(void);

#endif
