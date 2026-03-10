/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_STDIN_H
#define SIGLATCH_STDIN_H

#include <stddef.h>
#include <stdint.h>
#include "print.h"

typedef struct {
  const PrintLib *print;
} StdinContext;

typedef struct {
  void (*init)(const StdinContext *ctx);
  void (*set_context)(const StdinContext *ctx);
  void (*shutdown)(void);
  int (*is_terminal)(void);
  int (*has_piped_input)(void);
  int (*attach_if_piped)(uint8_t *dst, size_t dst_size, size_t *out_len);
  int (*read_once)(uint8_t *dst, size_t dst_size, size_t *out_len);
  int (*read_multiline)(uint8_t *dst, size_t dst_size, size_t *out_len);
} StdinLib;

const StdinLib *get_lib_stdin(void);

#endif
