/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "print.h"

#include <string.h>
#include <stdlib.h>
#include <strings.h>

#define SL_PRINT_FMT_BUF 2048
#define SL_PRINT_SAN_BUF 4096

static PrintContext print_ctx = {0};
static int print_initialized = 0;
static int print_output_mode_state = SL_OUTPUT_MODE_DEFAULT;

static void print_panic(const char *msg) {
    if (msg) {
        fputs(msg, stderr);
        fputc('\n', stderr);
    }
    abort();
}

static void print_require_ready(void) {
    if (!print_initialized) {
        print_panic("PrintLib used before init");
    }
    if (!print_ctx.unicode ||
        !print_ctx.unicode->get_unicode ||
        !print_ctx.unicode->get_ascii ||
        !print_ctx.unicode->replacement_count ||
        !print_ctx.unicode->replacement_at) {
        print_panic("PrintLib missing UnicodeLib context");
    }
}

/* Strict-C99 compatible atomic access via compiler builtins. */
static void print_output_mode_store(int mode) {
#if defined(__GNUC__) || defined(__clang__)
    __atomic_store_n(&print_output_mode_state, mode, __ATOMIC_RELAXED);
#else
    print_output_mode_state = mode;
#endif
}

static int print_output_mode_load(void) {
#if defined(__GNUC__) || defined(__clang__)
    return __atomic_load_n(&print_output_mode_state, __ATOMIC_RELAXED);
#else
    return print_output_mode_state;
#endif
}

static int print_output_mode_valid(int mode) {
    return mode == SL_OUTPUT_MODE_UNICODE || mode == SL_OUTPUT_MODE_ASCII;
}

static int print_output_parse_mode(const char *value) {
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

static const char *print_output_mode_name(int mode) {
    switch (mode) {
        case SL_OUTPUT_MODE_UNICODE:
            return "unicode";
        case SL_OUTPUT_MODE_ASCII:
            return "ascii";
        default:
            return "unknown";
    }
}

static void print_output_set_mode(int mode) {
    if (!print_output_mode_valid(mode)) {
        return;
    }
    print_output_mode_store(mode);
}

static int print_output_get_mode(void) {
    return print_output_mode_load();
}

static int print_output_get_env_mode(const char *env_name) {
    const char *name = env_name && env_name[0] ? env_name : "SIGLATCH_OUTPUT_MODE";
    const char *value = getenv(name);
    return print_output_parse_mode(value);
}

static int print_current_output_mode(void) {
    print_require_ready();
    return print_output_get_mode();
}

static size_t print_append_bytes(char *dst, size_t dst_size, size_t offset,
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

static const UnicodeReplacement *print_match_replacement(const unsigned char *in, size_t remaining) {
    size_t count = print_ctx.unicode->replacement_count();

    for (size_t i = 0; i < count; ++i) {
        const UnicodeReplacement *r = print_ctx.unicode->replacement_at(i);
        if (!r || !r->utf8 || !r->ascii || r->utf8_len == 0) {
            continue;
        }
        if (r->utf8_len <= remaining && memcmp(in, r->utf8, r->utf8_len) == 0) {
            return r;
        }
    }

    return NULL;
}

static const char *print_marker_text(const char *marker_input) {
    int mode;

    print_require_ready();
    mode = print_current_output_mode();

    if (mode == SL_OUTPUT_MODE_ASCII) {
        return print_ctx.unicode->get_ascii(marker_input);
    }

    return print_ctx.unicode->get_unicode(marker_input);
}

static void print_sl_output_sanitize(const char *input, char *output, size_t output_size) {
    if (!output || output_size == 0) {
        return;
    }

    output[0] = '\0';
    if (!input) {
        return;
    }

    if (print_current_output_mode() != SL_OUTPUT_MODE_ASCII) {
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

        {
            size_t consumed = (size_t)(p - start);
            size_t remaining = (consumed <= input_len) ? (input_len - consumed) : 0;
            const UnicodeReplacement *r = print_match_replacement(p, remaining);
            if (r) {
                out = print_append_bytes(output, output_size, out, r->ascii, r->ascii_len);
                p += r->utf8_len;
                continue;
            }
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

static int print_sl_vfprintf(FILE *stream, const char *fmt, va_list args) {
    char fmt_buf[SL_PRINT_FMT_BUF];
    char sanitized[SL_PRINT_SAN_BUF];

    print_require_ready();

    if (!stream || !fmt) {
        return -1;
    }

    if (vsnprintf(fmt_buf, sizeof(fmt_buf), fmt, args) < 0) {
        return -1;
    }

    print_sl_output_sanitize(fmt_buf, sanitized, sizeof(sanitized));

    if (fputs(sanitized, stream) == EOF) {
        return -1;
    }

    return (int)strlen(sanitized);
}

static int print_sl_fprintf(FILE *stream, const char *fmt, ...) {
    va_list args;
    int rc;

    va_start(args, fmt);
    rc = print_sl_vfprintf(stream, fmt, args);
    va_end(args);

    return rc;
}

static int print_sl_printf(const char *fmt, ...) {
    va_list args;
    int rc;

    va_start(args, fmt);
    rc = print_sl_vfprintf(stdout, fmt, args);
    va_end(args);

    return rc;
}

static int print_uc_vsprintf(char *dst, size_t dst_size, const char *marker, const char *fmt, va_list args) {
    char fmt_buf[SL_PRINT_FMT_BUF];
    const char *prefix = print_marker_text(marker);

    if (!dst || dst_size == 0 || !fmt) {
        return -1;
    }

    dst[0] = '\0';

    if (vsnprintf(fmt_buf, sizeof(fmt_buf), fmt, args) < 0) {
        return -1;
    }

    if (prefix) {
        return snprintf(dst, dst_size, "%s %s", prefix, fmt_buf);
    }
    return snprintf(dst, dst_size, "%s", fmt_buf);
}

static int print_uc_sprintf(char *dst, size_t dst_size, const char *marker, const char *fmt, ...) {
    va_list args;
    int rc;

    va_start(args, fmt);
    rc = print_uc_vsprintf(dst, dst_size, marker, fmt, args);
    va_end(args);
    return rc;
}

static int print_uc_vfprintf(FILE *stream, const char *marker, const char *fmt, va_list args) {
    char line_buf[SL_PRINT_FMT_BUF];
    int rc;

    if (!stream || !fmt) {
        return -1;
    }

    rc = print_uc_vsprintf(line_buf, sizeof(line_buf), marker, fmt, args);
    if (rc < 0) {
        return -1;
    }

    if (fputs(line_buf, stream) == EOF) {
        return -1;
    }

    return (int)strlen(line_buf);
}

static int print_uc_fprintf(FILE *stream, const char *marker, const char *fmt, ...) {
    va_list args;
    int rc;

    va_start(args, fmt);
    rc = print_uc_vfprintf(stream, marker, fmt, args);
    va_end(args);
    return rc;
}

static int print_uc_printf(const char *marker, const char *fmt, ...) {
    va_list args;
    int rc;

    va_start(args, fmt);
    rc = print_uc_vfprintf(stdout, marker, fmt, args);
    va_end(args);
    return rc;
}

static void print_init(const PrintContext *ctx) {
    if (!ctx) {
        print_panic("PrintLib init requires non-NULL context");
    }

    if (!ctx->unicode || !ctx->unicode->get_unicode || !ctx->unicode->get_ascii) {
        print_panic("PrintLib init requires valid UnicodeLib in context");
    }

    print_ctx = *ctx;
    print_initialized = 1;
}

static void print_shutdown(void) {
    print_ctx = (PrintContext){0};
    print_initialized = 0;
}

static const PrintLib print_instance = {
    .init = print_init,
    .shutdown = print_shutdown,
    .output_parse_mode = print_output_parse_mode,
    .output_mode_name = print_output_mode_name,
    .output_set_mode = print_output_set_mode,
    .output_get_mode = print_output_get_mode,
    .output_get_env_mode = print_output_get_env_mode,
    .sl_output_sanitize = print_sl_output_sanitize,
    .sl_vfprintf = print_sl_vfprintf,
    .sl_fprintf = print_sl_fprintf,
    .sl_printf = print_sl_printf,
    .uc_vfprintf = print_uc_vfprintf,
    .uc_fprintf = print_uc_fprintf,
    .uc_printf = print_uc_printf,
    .uc_vsprintf = print_uc_vsprintf,
    .uc_sprintf = print_uc_sprintf
};

const PrintLib *get_lib_print(void) {
    return &print_instance;
}
