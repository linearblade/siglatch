/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "stdin.h"

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>

static StdinContext stdin_ctx = {0};

static int stdin_vmsg(FILE *stream, const char *marker, const char *fmt, va_list args) {
  if (!stream || !fmt) {
    return -1;
  }

  if (stdin_ctx.print && stdin_ctx.print->uc_vfprintf) {
    return stdin_ctx.print->uc_vfprintf(stream, marker, fmt, args);
  }

  return vfprintf(stream, fmt, args);
}

static int stdin_msg(FILE *stream, const char *marker, const char *fmt, ...) {
  va_list args;
  int rc = -1;

  va_start(args, fmt);
  rc = stdin_vmsg(stream, marker, fmt, args);
  va_end(args);
  return rc;
}

static int stdin_is_terminal(void) {
  return isatty(STDIN_FILENO) ? 1 : 0;
}

static int stdin_has_piped_input(void) {
  if (stdin_is_terminal()) {
    stdin_msg(stdout, "debug", "STDIN is a terminal\n");
    return 0;
  }

  stdin_msg(stdout, "box", "STDIN is piped or redirected\n");
  return 1;
}

static int stdin_attach_if_piped(uint8_t *dst, size_t dst_size, size_t *out_len) {
  ssize_t n = 0;

  if (!dst || dst_size == 0) {
    stdin_msg(stderr, "err", "stdin destination buffer is invalid\n");
    return 0;
  }

  if (stdin_is_terminal()) {
    return 0;
  }

  n = read(STDIN_FILENO, dst, dst_size);
  if (n <= 0) {
    stdin_msg(stderr, "err", "stdin read failed or was empty\n");
    return 0;
  }

  if (out_len) {
    *out_len = (size_t)n;
  }
  return 1;
}

static int stdin_read_once(uint8_t *dst, size_t dst_size, size_t *out_len) {
  ssize_t n = 0;

  if (out_len) {
    *out_len = 0;
  }

  if (!dst || dst_size == 0) {
    stdin_msg(stderr, "err", "stdin destination buffer is invalid\n");
    return 0;
  }

  stdin_msg(stderr, "in", "Reading payload from stdin (--stdin)...\n");
  n = read(STDIN_FILENO, dst, dst_size);
  if (n <= 0) {
    stdin_msg(stderr, "err", "Failed to read from stdin or input was empty\n");
    return 0;
  }

  if (out_len) {
    *out_len = (size_t)n;
  }
  stdin_msg(stderr, "ok", "Read %zu bytes from stdin\n", (size_t)n);
  return 1;
}

static int stdin_read_multiline(uint8_t *dst, size_t dst_size, size_t *out_len) {
  char buffer[256];
  size_t total = 0;

  if (out_len) {
    *out_len = 0;
  }

  if (!dst || dst_size == 0) {
    stdin_msg(stderr, "err", "stdin destination buffer is invalid\n");
    return 0;
  }

  stdin_msg(stderr, "in", "Reading multi-line payload from stdin (end with Ctrl+D):\n");

  while (fgets(buffer, sizeof(buffer), stdin)) {
    size_t len = strlen(buffer);

    if (total + len >= dst_size) {
      stdin_msg(stderr, "err", "Payload too large (max %zu bytes)\n", dst_size);
      return 0;
    }

    memcpy(dst + total, buffer, len);
    total += len;
  }

  if (total == 0) {
    stdin_msg(stderr, "err", "No input received from stdin\n");
    return 0;
  }

  if (out_len) {
    *out_len = total;
  }
  stdin_msg(stderr, "ok", "Read %zu bytes from stdin\n", total);
  return 1;
}

static void stdin_set_context(const StdinContext *ctx) {
  if (!ctx || !ctx->print) {
    return;
  }

  stdin_ctx = *ctx;
}

static void stdin_init(const StdinContext *ctx) {
  stdin_set_context(ctx);
}

static void stdin_shutdown(void) {
  stdin_ctx = (StdinContext){0};
}

static const StdinLib stdin_instance = {
  .init = stdin_init,
  .set_context = stdin_set_context,
  .shutdown = stdin_shutdown,
  .is_terminal = stdin_is_terminal,
  .has_piped_input = stdin_has_piped_input,
  .attach_if_piped = stdin_attach_if_piped,
  .read_once = stdin_read_once,
  .read_multiline = stdin_read_multiline
};

const StdinLib *get_lib_stdin(void) {
  return &stdin_instance;
}
