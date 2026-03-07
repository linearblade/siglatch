/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "unicode.h"

#include <ctype.h>
#include <string.h>

#include "print.h"

#define UNICODE_MARKER_LIST(X) \
    X("ok", "✅", "[OK]") \
    X("err", "❌", "[ERR]") \
    X("error", "❌", "[ERR]") \
    X("warn", "⚠️", "[WARN]") \
    X("warning", "⚠️", "[WARN]") \
    X("fatal", "☢️", "[FATAL]") \
    X("info", "ℹ️", "[INFO]") \
    X("debug", "🔎", "[DBG]") \
    X("dbg", "🔎", "[DBG]") \
    X("trace", "🧵", "[THREAD]") \
    X("thread", "🧵", "[THREAD]") \
    X("note", "📝", "[NOTE]") \
    X("tx", "📤", "[TX]") \
    X("rx", "📩", "[RX]") \
    X("boot", "🚀", "[BOOT]") \
    X("stop", "🛑", "[STOP]") \
    X("sec", "🔐", "[SEC]") \
    X("del", "🗑️", "[DEL]") \
    X("users", "👥", "[USERS]") \
    X("target", "🎯", "[TARGET]") \
    X("update", "🔄", "[UPDATE]") \
    X("in", "📥", "[IN]") \
    X("box", "📦", "[BOX]") \
    X("dir", "📂", "[DIR]")

#define UNICODE_REPLACEMENT_MARKER_LIST(X) \
    X("✅", "[OK]") \
    X("❌", "[ERR]") \
    X("⚠️", "[WARN]") \
    X("☢️", "[FATAL]") \
    X("ℹ️", "[INFO]") \
    X("🔎", "[DBG]") \
    X("🧵", "[THREAD]") \
    X("📝", "[NOTE]") \
    X("📤", "[TX]") \
    X("📩", "[RX]") \
    X("🚀", "[BOOT]") \
    X("🛑", "[STOP]") \
    X("🔐", "[SEC]") \
    X("🗑️", "[DEL]") \
    X("👥", "[USERS]") \
    X("🎯", "[TARGET]") \
    X("🔄", "[UPDATE]") \
    X("📥", "[IN]") \
    X("📦", "[BOX]") \
    X("📂", "[DIR]")

typedef struct {
    const char *name;
    const char *utf8;
    const char *ascii;
} UnicodeMarker;

/* Central marker registry for print/log paths. */
static const UnicodeMarker unicode_markers[] = {
#define UNICODE_MARKER_ENTRY(name_, utf8_, ascii_) {name_, utf8_, ascii_},
    UNICODE_MARKER_LIST(UNICODE_MARKER_ENTRY)
#undef UNICODE_MARKER_ENTRY
};

/* Shared sanitize replacement table used by PrintLib ASCII mode. */
static const UnicodeReplacement unicode_replacements[] = {
#define UNICODE_REPLACEMENT_MARKER_ENTRY(utf8_, ascii_) \
    {utf8_, sizeof(utf8_) - 1, ascii_, sizeof(ascii_) - 1},
    UNICODE_REPLACEMENT_MARKER_LIST(UNICODE_REPLACEMENT_MARKER_ENTRY)
#undef UNICODE_REPLACEMENT_MARKER_ENTRY
    {"⚠", sizeof("⚠") - 1, "[WARN]", sizeof("[WARN]") - 1},
    {"☢", sizeof("☢") - 1, "[FATAL]", sizeof("[FATAL]") - 1},
    {"🗑", sizeof("🗑") - 1, "[DEL]", sizeof("[DEL]") - 1},
    {"•", sizeof("•") - 1, "-", sizeof("-") - 1},
    {"├", sizeof("├") - 1, "|", sizeof("|") - 1},
    {"└", sizeof("└") - 1, "`", sizeof("`") - 1},
    {"─", sizeof("─") - 1, "-", sizeof("-") - 1},
};

static int unicode_key_from_input(const char *input, char *out, size_t out_size) {
    size_t i = 0;
    const char *p = input;

    if (!out || out_size == 0) {
        return 0;
    }
    out[0] = '\0';

    if (!p) {
        return 0;
    }

    while (*p != '\0' && isspace((unsigned char)*p)) {
        p++;
    }

    if (*p == '[') {
        p++;
    }

    while (*p != '\0' && *p != ']' && !isspace((unsigned char)*p) && i + 1 < out_size) {
        out[i++] = (char)tolower((unsigned char)*p);
        p++;
    }
    out[i] = '\0';

    return (i > 0);
}

static const UnicodeMarker *unicode_lookup(const char *key_input) {
    char key[32];
    size_t count = sizeof(unicode_markers) / sizeof(unicode_markers[0]);

    if (!unicode_key_from_input(key_input, key, sizeof(key))) {
        return NULL;
    }

    for (size_t i = 0; i < count; ++i) {
        if (strcmp(key, unicode_markers[i].name) == 0) {
            return &unicode_markers[i];
        }
    }

    return NULL;
}

static const char *unicode_get_unicode(const char *key) {
    const UnicodeMarker *m = unicode_lookup(key);
    if (!m) {
        return NULL;
    }
    return m->utf8;
}

static const char *unicode_get_ascii(const char *key) {
    const UnicodeMarker *m = unicode_lookup(key);
    if (!m) {
        return NULL;
    }
    return m->ascii;
}

static const char *unicode_get(const char *key) {
    const UnicodeMarker *m = unicode_lookup(key);
    const PrintLib *print = get_lib_print();
    int mode = SL_OUTPUT_MODE_DEFAULT;

    if (!m) {
        return NULL;
    }

    if (print && print->output_get_mode) {
        mode = print->output_get_mode();
    }

    return (mode == SL_OUTPUT_MODE_ASCII) ? m->ascii : m->utf8;
}

static size_t unicode_replacement_count(void) {
    return sizeof(unicode_replacements) / sizeof(unicode_replacements[0]);
}

static const UnicodeReplacement *unicode_replacement_at(size_t index) {
    if (index >= unicode_replacement_count()) {
        return NULL;
    }
    return &unicode_replacements[index];
}

static void unicode_init(void) {
    /* no-op */
}

static void unicode_shutdown(void) {
    /* no-op */
}

static const UnicodeLib unicode_instance = {
    .init = unicode_init,
    .shutdown = unicode_shutdown,
    .get = unicode_get,
    .get_unicode = unicode_get_unicode,
    .get_ascii = unicode_get_ascii,
    .replacement_count = unicode_replacement_count,
    .replacement_at = unicode_replacement_at
};

const UnicodeLib *get_lib_unicode(void) {
    return &unicode_instance;
}
