/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include <stdio.h>
#include <string.h>
//#include <stdlib.h>
//#include <sys/stat.h>
//#include <errno.h>
#include "parse_argv.h"

int parse_argv_has(const ParsedArgv *parsed, const char *flag) {
    for (int i = 0; i < parsed->num_options; i++) {
        if (strcmp(parsed->options[i].args[0], flag) == 0) {
            return 1;
        }
    }
    return 0;
}
void parse_argv_dump(const ParsedArgv *parsed) {
  printf("🔍 Parsed Options (%d):\n", parsed->num_options);
  for (int i = 0; i < parsed->num_options; i++) {
    const ParsedOption *po = &parsed->options[i];
    printf("  • %s", po->args[0]); // option name
    for (int j = 1; j < po->num_args; j++) {
      printf(" %s", po->args[j]);
    }
    printf("\n");
  }

  printf("\n📦 Positional Arguments (%d):\n", parsed->num_positionals);
  for (int i = 0; i < parsed->num_positionals; i++) {
    printf("  [%d] %s\n", i, parsed->positionals[i]);
  }
}
static const OptionSpec* find_option_spec(const char *arg, const OptionSpec *spec_table) {
    for (const OptionSpec *spec = spec_table; spec->name != NULL; spec++) {
        if (strcmp(arg, spec->name) == 0) {
            return spec;
        }
    }
    return NULL; // Unknown
}

int parse_argv(int argc, char *argv[], ParsedArgv *parsed_out, const OptionSpec *spec_table) {
    int i = 1;
    parsed_out->num_options = 0;
    parsed_out->num_positionals = 0;
    parsed_out->spec = spec_table; // Save whole spec table for reference

    while (i < argc) {
        if (strncmp(argv[i], "--", 2) != 0) {
            break; // Done with options
        }

        const OptionSpec *opt = find_option_spec(argv[i], spec_table);
        if (!opt) {
            fprintf(stderr, "❌ Unknown option: %s\n", argv[i]);
            return 0;
        }

        if (i + opt->num_args >= argc) {
            fprintf(stderr, "❌ Not enough arguments for option: %s\n", argv[i]);
            return 0;
        }

        ParsedOption *po = &parsed_out->options[parsed_out->num_options++];
        po->spec = opt;           // ← attach pointer to specific matched spec
        po->num_args = 1 + opt->num_args;

        for (int j = 0; j < po->num_args; j++) {
            po->args[j] = argv[i + j];
        }

        i += 1 + opt->num_args;
    }

    while (i < argc) {
        parsed_out->positionals[parsed_out->num_positionals++] = argv[i++];
    }

    return 1;
}
