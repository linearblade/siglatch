/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_ARGV_H
#define SIGLATCH_ARGV_H

#include <stddef.h>
#include <stdint.h>

#define ARGV_MAX_OPTIONS 32
#define ARGV_MAX_OPTION_ARGS 10
#define ARGV_MAX_POSITIONALS 8

typedef enum {
  ARGV_OPT_FLAG = 0,
  ARGV_OPT_KEYED = 1
} ArgvOptionType;

typedef enum {
  ARGV_ERR_NONE = 0,
  ARGV_ERR_INVALID_INPUT,
  ARGV_ERR_UNKNOWN_OPTION,
  ARGV_ERR_NOT_ENOUGH_OPTION_ARGS,
  ARGV_ERR_TOO_MANY_OPTIONS,
  ARGV_ERR_TOO_MANY_POSITIONALS,
  ARGV_ERR_TOO_MANY_OPTION_ARGS,
  ARGV_ERR_EQUALS_FORM_NOT_ALLOWED,
  ARGV_ERR_DUPLICATE_OPTION,
  ARGV_ERR_REQUIRED_OPTION_MISSING,
  ARGV_ERR_BAD_INTEGER,
  ARGV_ERR_INTEGER_OUT_OF_RANGE,
  ARGV_ERR_BAD_ENUM
} ArgvErrorCode;

typedef struct {
  ArgvErrorCode code;
  int arg_index;
  const char *arg_value;
  int option_id;
  const char *option_name;
} ArgvError;

typedef struct {
  const char *name;
  int id;
  int num_args;
  ArgvOptionType type;
  int required;
  int allow_repeat;
  int last_wins;
} ArgvOptionSpec;

typedef struct {
  const ArgvOptionSpec *spec;
  const char *args[ARGV_MAX_OPTION_ARGS];
  int num_args;
  int source_index;
} ArgvParsedOption;

typedef struct {
  ArgvParsedOption options[ARGV_MAX_OPTIONS];
  int num_options;

  const char *positionals[ARGV_MAX_POSITIONALS];
  int positional_indices[ARGV_MAX_POSITIONALS];
  int num_positionals;

  const ArgvOptionSpec *spec;
  ArgvError error;
} ArgvParsed;

typedef struct {
  int strict;
} ArgvContext;

typedef struct {
  const char *name;
  int value;
} ArgvEnumMap;

typedef struct {
  void (*init)(const ArgvContext *ctx);
  void (*shutdown)(void);
  void (*set_context)(const ArgvContext *ctx);
  int (*parse)(int argc, char *argv[], ArgvParsed *out, const ArgvOptionSpec *spec);
  int (*has)(const ArgvParsed *parsed, const char *option_name);
  void (*dump)(const ArgvParsed *parsed);
  const ArgvParsedOption *(*find_first_by_id)(const ArgvParsed *parsed, int option_id);
  const ArgvParsedOption *(*find_last_by_id)(const ArgvParsed *parsed, int option_id);
  const ArgvParsedOption *(*find_first_by_name)(const ArgvParsed *parsed, const char *option_name);
  const char *(*option_value)(const ArgvParsedOption *option, int value_index);
  int (*get_i32)(const ArgvParsedOption *option, int value_index, int min_value, int max_value, int *out, ArgvError *err);
  int (*get_u16)(const ArgvParsedOption *option, int value_index, uint16_t *out, ArgvError *err);
  int (*get_enum)(const ArgvParsedOption *option, int value_index, const ArgvEnumMap *map, size_t map_count, int *out, ArgvError *err);
  const char *(*error_code_name)(ArgvErrorCode code);
  int (*format_error)(const ArgvError *err, char *out, size_t out_size);
} ArgvLib;

const ArgvLib *get_lib_argv(void);

#endif
