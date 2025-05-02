#ifndef PARSE_ARGV_H
#define PARSE_ARGV_H

#include <stddef.h>

typedef enum {
    OPT_FLAG,
    OPT_KEYED,
    OPT_UNKNOWN
} OptionType;

typedef struct {
  const char *name;
  int id;
  int num_args;
  OptionType type;
} OptionSpec;

typedef struct {
    const OptionSpec *spec;
    const char *args[10];
    int num_args;
} ParsedOption;

typedef struct {
    ParsedOption options[32];
    int num_options;
    const char *positionals[8];
    int num_positionals;
    const OptionSpec *spec; // Reference spec table
} ParsedArgv;

int parse_argv(int argc, char *argv[], ParsedArgv *parsed_out, const OptionSpec *spec_table);
void parse_argv_dump(const ParsedArgv * parsed);
int parse_argv_has(const ParsedArgv *parsed, const char *flag); 
#endif // PARSE_ARGV_H
