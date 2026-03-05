/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "output.h"

#include <stdlib.h>
#include <string.h>
#include <strings.h>

#define SL_OUTPUT_FMT_BUF 2048
#define SL_OUTPUT_SAN_BUF 4096

typedef struct {
    const char *utf8;
    size_t utf8_len;
    const char *ascii;
    size_t ascii_len;
} OutputReplacement;

/* Keep replacements static: no runtime heap allocations. */
static const OutputReplacement replacements[] = {
    {"\xE2\x9A\xA0\xEF\xB8\x8F", 6, "[WARN]", 6},    /* ⚠️ */
    {"\xE2\x98\xA2\xEF\xB8\x8F", 6, "[FATAL]", 7},   /* ☢️ */
    {"\xF0\x9F\x97\x91\xEF\xB8\x8F", 7, "[DEL]", 5},/* 🗑️ */

    {"\xE2\x9D\x8C", 3, "[ERR]", 5},                  /* ❌ */
    {"\xE2\x9C\x85", 3, "[OK]", 4},                   /* ✅ */
    {"\xE2\x9A\xA0", 3, "[WARN]", 6},                 /* ⚠ */
    {"\xE2\x98\xA2", 3, "[FATAL]", 7},                /* ☢ */
    {"\xE2\x80\xA2", 3, "-", 1},                      /* • */
    {"\xE2\x94\x9C", 3, "|", 1},                      /* ├ */
    {"\xE2\x94\x94", 3, "`", 1},                      /* └ */
    {"\xE2\x94\x80", 3, "-", 1},                      /* ─ */

    {"\xF0\x9F\x9B\x91", 4, "[STOP]", 6},            /* 🛑 */
    {"\xF0\x9F\x93\xA9", 4, "[RX]", 4},              /* 📩 */
    {"\xF0\x9F\x93\xA4", 4, "[TX]", 4},              /* 📤 */
    {"\xF0\x9F\x9A\x80", 4, "[BOOT]", 6},            /* 🚀 */
    {"\xF0\x9F\x94\x90", 4, "[SEC]", 5},             /* 🔐 */
    {"\xF0\x9F\x94\x8E", 4, "[DBG]", 5},             /* 🔎 */
    {"\xF0\x9F\xA7\xB5", 4, "[THREAD]", 8},          /* 🧵 */
    {"\xF0\x9F\x93\x9D", 4, "[NOTE]", 6},            /* 📝 */
    {"\xF0\x9F\x94\x84", 4, "[UPDATE]", 8},          /* 🔄 */
    {"\xF0\x9F\x8E\xAF", 4, "[TARGET]", 8},          /* 🎯 */
    {"\xF0\x9F\x93\x82", 4, "[DIR]", 5},             /* 📂 */
    {"\xF0\x9F\x93\xA6", 4, "[BOX]", 5},             /* 📦 */
    {"\xF0\x9F\x93\xA5", 4, "[IN]", 4},              /* 📥 */
    {"\xF0\x9F\x91\xA5", 4, "[USERS]", 7},           /* 👥 */
    {"\xF0\x9F\x97\x91", 4, "[DEL]", 5},             /* 🗑 */
};

static int g_output_mode = SL_OUTPUT_MODE_DEFAULT;

/* Strict-C99 compatible atomic access via compiler builtins. */
static void output_mode_store(int mode) {
#if defined(__GNUC__) || defined(__clang__)
    __atomic_store_n(&g_output_mode, mode, __ATOMIC_RELAXED);
#else
    g_output_mode = mode;
#endif
}

static int output_mode_load(void) {
#if defined(__GNUC__) || defined(__clang__)
    return __atomic_load_n(&g_output_mode, __ATOMIC_RELAXED);
#else
    return g_output_mode;
#endif
}

static int output_mode_valid(int mode) {
    return mode == SL_OUTPUT_MODE_UNICODE || mode == SL_OUTPUT_MODE_ASCII;
}

static size_t append_bytes(char *dst, size_t dst_size, size_t offset,
                           const char *src, size_t src_len) {
    if (!dst || dst_size == 0 || !src || src_len == 0) {
        return offset;
    }

    while (src_len > 0 && offset + 1 < dst_size) {
        dst[offset++] = *src++;
        src_len--;
    }

    dst[offset] = '\0';
    return offset;
}

static const OutputReplacement *match_replacement(const unsigned char *in, size_t remaining) {
    size_t count = sizeof(replacements) / sizeof(replacements[0]);
    for (size_t i = 0; i < count; ++i) {
        const OutputReplacement *r = &replacements[i];
        if (r->utf8_len <= remaining && memcmp(in, r->utf8, r->utf8_len) == 0) {
            return r;
        }
    }
    return NULL;
}

int sl_output_parse_mode(const char *value) {
    if (!value || *value == '\0') {
        return 0;
    }

    if (strcasecmp(value, "unicode") == 0) {
        return SL_OUTPUT_MODE_UNICODE;
    }

    if (strcasecmp(value, "ascii") == 0) {
        return SL_OUTPUT_MODE_ASCII;
    }

    return 0;
}

const char *sl_output_mode_name(int mode) {
    switch (mode) {
        case SL_OUTPUT_MODE_UNICODE:
            return "unicode";
        case SL_OUTPUT_MODE_ASCII:
            return "ascii";
        default:
            return "unknown";
    }
}

void sl_output_set_mode(int mode) {
    if (!output_mode_valid(mode)) {
        return;
    }
    output_mode_store(mode);
}

int sl_output_get_mode(void) {
    return output_mode_load();
}

int sl_output_get_env_mode(const char *env_name) {
    const char *name = env_name && env_name[0] ? env_name : "SIGLATCH_OUTPUT_MODE";
    const char *value = getenv(name);
    return sl_output_parse_mode(value);
}

void sl_output_sanitize(const char *input, char *output, size_t output_size) {
    if (!output || output_size == 0) {
        return;
    }

    output[0] = '\0';
    if (!input) {
        return;
    }

    if (output_mode_load() != SL_OUTPUT_MODE_ASCII) {
        strncpy(output, input, output_size - 1);
        output[output_size - 1] = '\0';
        return;
    }

    const unsigned char *start = (const unsigned char *)input;
    const unsigned char *p = start;
    size_t input_len = strlen(input);
    size_t out = 0;

    while (*p != '\0' && out + 1 < output_size) {
        /* Strip ANSI escape sequences in ASCII mode. */
        if (*p == 0x1B) {
            p++;
            if (*p == '[') {
                p++;
                while (*p && ((*p >= '0' && *p <= '9') || *p == ';' || *p == '?')) {
                    p++;
                }
                if (*p) {
                    p++;
                }
            }
            continue;
        }

        size_t consumed = (size_t)(p - start);
        size_t remaining = (consumed <= input_len) ? (input_len - consumed) : 0;

        const OutputReplacement *r = match_replacement(p, remaining);
        if (r) {
            out = append_bytes(output, output_size, out, r->ascii, r->ascii_len);
            p += r->utf8_len;
            continue;
        }

        if (*p == '\n' || *p == '\r' || *p == '\t' || (*p >= 0x20 && *p <= 0x7E)) {
            output[out++] = (char)*p;
            output[out] = '\0';
            p++;
            continue;
        }

        output[out++] = '?';
        output[out] = '\0';

        p++;
        while ((*p & 0xC0) == 0x80) {
            p++;
        }
    }

    output[out] = '\0';
}

int sl_vfprintf(FILE *stream, const char *fmt, va_list args) {
    if (!stream || !fmt) {
        return -1;
    }

    char fmt_buf[SL_OUTPUT_FMT_BUF];
    char sanitized[SL_OUTPUT_SAN_BUF];

    int n = vsnprintf(fmt_buf, sizeof(fmt_buf), fmt, args);
    if (n < 0) {
        return -1;
    }

    sl_output_sanitize(fmt_buf, sanitized, sizeof(sanitized));

    if (fputs(sanitized, stream) == EOF) {
        return -1;
    }

    return (int)strlen(sanitized);
}

int sl_fprintf(FILE *stream, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    int rc = sl_vfprintf(stream, fmt, args);
    va_end(args);
    return rc;
}

int sl_printf(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    int rc = sl_vfprintf(stdout, fmt, args);
    va_end(args);
    return rc;
}
