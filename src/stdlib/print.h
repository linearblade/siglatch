/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_PRINT_H
#define SIGLATCH_PRINT_H

#include <stdarg.h>
#include <stdio.h>
#include "unicode.h"

#define SL_OUTPUT_MODE_UNICODE 1
#define SL_OUTPUT_MODE_ASCII 2

#ifndef SL_OUTPUT_MODE_DEFAULT
#define SL_OUTPUT_MODE_DEFAULT SL_OUTPUT_MODE_UNICODE
#endif

typedef struct {
    const UnicodeLib *unicode;
} PrintContext;

typedef struct {
    void (*init)(const PrintContext *ctx);
    void (*shutdown)(void);
    int (*output_parse_mode)(const char *value);
    const char *(*output_mode_name)(int mode);
    void (*output_set_mode)(int mode);
    int (*output_get_mode)(void);
    int (*output_get_env_mode)(const char *env_name);
    void (*sl_output_sanitize)(const char *input, char *output, size_t output_size);
    int (*sl_vfprintf)(FILE *stream, const char *fmt, va_list args);
    int (*sl_fprintf)(FILE *stream, const char *fmt, ...);
    int (*sl_printf)(const char *fmt, ...);
    int (*uc_vfprintf)(FILE *stream, const char *marker, const char *fmt, va_list args);
    int (*uc_fprintf)(FILE *stream, const char *marker, const char *fmt, ...);
    int (*uc_printf)(const char *marker, const char *fmt, ...);
    int (*uc_vsprintf)(char *dst, size_t dst_size, const char *marker, const char *fmt, va_list args);
    int (*uc_sprintf)(char *dst, size_t dst_size, const char *marker, const char *fmt, ...);
} PrintLib;

const PrintLib *get_lib_print(void);

#endif
