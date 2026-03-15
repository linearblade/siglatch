/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_UTILS_H
#define SIGLATCH_UTILS_H
#include <stdio.h>
#include <stdint.h>
#include "print.h"

typedef struct {
    const PrintLib *print;
} UtilsContext;

typedef struct {
    void (*init)(const UtilsContext *ctx);
    void (*set_context)(const UtilsContext *ctx);
    void (*shutdown)(void);
    const char *(*timestamp_now)(int cache);
    void (*dump_digest)(const char *label, const uint8_t *digest, size_t len);
} UtilsLib;

const UtilsLib *get_lib_utils(void);

const char *timestamp_now(int cache);
void dumpDigest(const char *label, const uint8_t *digest, size_t len) ;
#endif // SIGLATCH_UTILS_H
