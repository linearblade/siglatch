/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_PARSE_ARGV_H
#define SIGLATCH_PARSE_ARGV_H

#include <stddef.h>
#include "log.h"
/**
 * @file parse_argv.h
 * @brief Simple argument parsing utility for CLI flags and positionals
 *
 * This module supports flag/argument parsing for CLI programs.
 * It provides a lightweight parser with static option specification
 * and positional argument capture. Useful for building consistent
 * command-line interfaces across Siglatch tools.
 *
 * Typical usage:
 *   1. Define an array of OptionSpec objects
 *   2. Call get_lib_parse_argv() to access the singleton interface
 *   3. Use .parse() to fill ParsedArgv based on argc/argv
 *   4. Use .has() or .dump() for analysis/debug
 */

typedef enum {
  OPT_FLAG,     ///< Option has no arguments (e.g., --debug)
  OPT_KEYED,    ///< Option expects 1 or more arguments (e.g., --port 1234)
  OPT_UNKNOWN   ///< Used for invalid or unknown options
} OptionType;

typedef struct {
  const char *name;     ///< Full option name (e.g., "--log")
  int id;               ///< Unique identifier or enum for lookup
  int num_args;         ///< How many args it expects (0 for flags)
  OptionType type;      ///< Option classification
} OptionSpec;

typedef struct {
  const OptionSpec *spec;     ///< Backref to the matched OptionSpec
  const char *args[10];       ///< Arguments parsed for this option
  int num_args;               ///< How many args were parsed
} ParsedOption;

typedef struct {
  ParsedOption options[32];     ///< List of parsed options
  int num_options;

  const char *positionals[8];   ///< Remaining args (non-option)
  int num_positionals;

  const OptionSpec *spec;       ///< The spec table used for parsing
} ParsedArgv;

/**
 * Optional context for parse_argv library
 * Reserved for logging or global overrides in future
 */
typedef struct {
  int strict;  ///< If true, reject unknown options
  const  Logger *log;
} ParseArgvContext;

typedef struct {
  void (*init)(const ParseArgvContext *ctx);                     ///< Optional lifecycle init
  void (*shutdown)(void);                                       ///< shutdown 
  void (*set_context)(const ParseArgvContext *ctx);             ///< Override parsing context
  int (*parse)(int argc, char *argv[], ParsedArgv *out, const OptionSpec *spec);
  int (*has)(const ParsedArgv *parsed, const char *flag);       ///< Lookup by flag name
  void (*dump)(const ParsedArgv *parsed);                       ///< Debug dump
} ParseArgvLib;

const ParseArgvLib *get_lib_parse_argv(void);

#endif // SIGLATCH_PARSE_ARGV_H
