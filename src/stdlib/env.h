/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_ENV_H
#define SIGLATCH_ENV_H

#include <stddef.h>
#include <sys/types.h>

typedef struct {
  const char *(*get)(const char *key);
  int (*get_required)(const char *key, const char **out);
} EnvCoreLib;

typedef struct {
  int (*home)(const char **out);
  int (*build_home_path)(char *out, size_t out_size, const char *relative_path);
  int (*ensure_dir)(const char *path, mode_t mode);
} EnvUserLib;

typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
  EnvCoreLib core;
  EnvUserLib user;
} EnvLib;

const EnvLib *get_lib_env(void);

#endif
