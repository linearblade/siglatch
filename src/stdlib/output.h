/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_OUTPUT_H
#define SIGLATCH_OUTPUT_H

#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>

#define SL_OUTPUT_MODE_UNICODE 1
#define SL_OUTPUT_MODE_ASCII 2

#ifndef SL_OUTPUT_MODE_DEFAULT
#define SL_OUTPUT_MODE_DEFAULT SL_OUTPUT_MODE_UNICODE
#endif

int sl_output_parse_mode(const char *value);
const char *sl_output_mode_name(int mode);
void sl_output_set_mode(int mode);
int sl_output_get_mode(void);
int sl_output_get_env_mode(const char *env_name);

void sl_output_sanitize(const char *input, char *output, size_t output_size);

int sl_vfprintf(FILE *stream, const char *fmt, va_list args);
int sl_fprintf(FILE *stream, const char *fmt, ...);
int sl_printf(const char *fmt, ...);

#endif
