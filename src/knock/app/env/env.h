/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_KNOCK_APP_ENV_H
#define SIGLATCH_KNOCK_APP_ENV_H

#include <stddef.h>

typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
  int (*build_host_config_path)(char *out, size_t out_size, const char *host, const char *filename);
  int (*ensure_host_config_dir)(const char *host);
  int (*load_output_mode_default)(void);
  int (*save_output_mode_default)(const char *mode_value);
} AppEnvLib;

const AppEnvLib *get_app_env_lib(void);

#endif
