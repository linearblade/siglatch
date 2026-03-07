/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_UNICODE_H
#define SIGLATCH_UNICODE_H

#include <stddef.h>

typedef struct {
    const char *utf8;
    size_t utf8_len;
    const char *ascii;
    size_t ascii_len;
} UnicodeReplacement;

typedef struct {
    void (*init)(void);
    void (*shutdown)(void);
    const char *(*get)(const char *key);
    const char *(*get_unicode)(const char *key);
    const char *(*get_ascii)(const char *key);
    size_t (*replacement_count)(void);
    const UnicodeReplacement *(*replacement_at)(size_t index);
} UnicodeLib;

const UnicodeLib *get_lib_unicode(void);

#endif
