/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "parse.h"

static ParseLib parse_instance = {0};
static int parse_wired = 0;
static ParseContext parse_ctx = {0};

static void wire_parse_instance(void) {
  if (parse_wired) {
    return;
  }

  parse_instance.ini = *get_lib_parse_ini();
  parse_wired = 1;
}

static int parse_set_context(const ParseContext *ctx) {
  IniContext ini_ctx = {0};

  wire_parse_instance();

  if (!ctx || !ctx->str) {
    return 0;
  }

  parse_ctx = *ctx;

  if (!parse_instance.ini.init ||
      !parse_instance.ini.shutdown ||
      !parse_instance.ini.set_context ||
      !parse_instance.ini.read_file ||
      !parse_instance.ini.destroy ||
      !parse_instance.ini.find_section ||
      !parse_instance.ini.find_entry ||
      !parse_instance.ini.get) {
    return 0;
  }

  ini_ctx.str = parse_ctx.str;
  return parse_instance.ini.set_context(&ini_ctx);
}

static int parse_init(const ParseContext *ctx) {
  IniContext ini_ctx = {0};

  wire_parse_instance();

  if (!ctx || !ctx->str) {
    return 0;
  }

  parse_ctx = *ctx;
  ini_ctx.str = parse_ctx.str;
  return parse_instance.ini.init(&ini_ctx);
}

static void parse_shutdown(void) {
  wire_parse_instance();

  if (parse_instance.ini.shutdown) {
    parse_instance.ini.shutdown();
  }

  parse_ctx = (ParseContext){0};
}

const ParseLib *get_lib_parse(void) {
  wire_parse_instance();
  parse_instance.init = parse_init;
  parse_instance.shutdown = parse_shutdown;
  parse_instance.set_context = parse_set_context;
  return &parse_instance;
}
