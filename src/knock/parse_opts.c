/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdint.h>
#include <limits.h>
#include "lib.h"
#include "app/app.h"
#include "parse_opts.h"
#include "parse_opts_alias.h"
#include "print_help.h"
#include "../stdlib/argv.h"

enum {
  OPT_ID_NONE = 0, //no op. for passing flags to be picked up in parse handler, not set in opts object
  OPT_ID_HMAC_KEY ,
  OPT_ID_PORT,
  OPT_ID_SERVER_KEY,
  OPT_ID_CLIENT_KEY,
  OPT_ID_NO_HMAC,
  OPT_ID_DUMMY_HMAC,
  OPT_ID_NO_ENCRYPT,
  OPT_ID_DEAD_DROP,
  OPT_ID_VERBOSE,
  OPT_ID_LOG,
  OPT_ID_STDIN,
  OPT_ID_OUTPUT_MODE,
};

static const ArgvOptionSpec option_specs[] = {
  { "--port",        OPT_ID_PORT,        1, ARGV_OPT_KEYED, 0, 0, 1 },
  { "--hmac-key",    OPT_ID_HMAC_KEY,    1, ARGV_OPT_KEYED, 0, 0, 1 },
  { "--server-key",  OPT_ID_SERVER_KEY,  1, ARGV_OPT_KEYED, 0, 0, 1 },
  { "--client-key",  OPT_ID_CLIENT_KEY,  1, ARGV_OPT_KEYED, 0, 0, 1 },
  { "--no-hmac",     OPT_ID_NO_HMAC,     0, ARGV_OPT_FLAG,  0, 0, 1 },
  { "--stdin",       OPT_ID_STDIN,       0, ARGV_OPT_FLAG,  0, 0, 1 },
  { "--opts-dump",   OPT_ID_NONE,        0, ARGV_OPT_FLAG,  0, 0, 1 },
  { "--dummy-hmac",  OPT_ID_DUMMY_HMAC,  0, ARGV_OPT_FLAG,  0, 0, 1 },
  { "--no-encrypt",  OPT_ID_NO_ENCRYPT,  0, ARGV_OPT_FLAG,  0, 0, 1 },
  { "--dead-drop",   OPT_ID_DEAD_DROP,   0, ARGV_OPT_FLAG,  0, 0, 1 },
  { "--verbose",     OPT_ID_VERBOSE,     1, ARGV_OPT_KEYED, 0, 0, 1 },
  { "--log",         OPT_ID_LOG,         1, ARGV_OPT_KEYED, 0, 0, 1 },
  { "--output-mode", OPT_ID_OUTPUT_MODE, 1, ARGV_OPT_KEYED, 0, 0, 1 },
  { NULL, 0, 0, ARGV_OPT_FLAG, 0, 0, 0 }
};

static const char *const opts_response_type_names[] = {
  [OPTS_RESPONSE_HELP] = "help",
  [OPTS_RESPONSE_ERROR] = "error",
  [OPTS_RESPONSE_ALIAS] = "alias",
  [OPTS_RESPONSE_TRANSMIT] = "transmit"
};

typedef enum {
  OPTS_PARSE_MODE_HELP = 0,
  OPTS_PARSE_MODE_OUTPUT_MODE_DEFAULT,
  OPTS_PARSE_MODE_ALIAS,
  OPTS_PARSE_MODE_TRANSMIT
} OptsParseMode;

int parseOpts(int argc, char *argv[], Opts *opts_out);
int apply_parsed_opts(const ArgvParsed *parsed, Opts *out);
int opts_validate(Opts *opts) ;
static OptsParseMode get_parse_mode(int argc, char *argv[]);
static int parse_transmit_mode(int argc, char *argv[], Opts *opts_out);

static const char *opts_response_type_name(OptsResponseType value);
static const char *opts_response_type_name(OptsResponseType value) {
  int idx = (int)value;
  int limit = (int)(sizeof(opts_response_type_names) / sizeof(opts_response_type_names[0]));

  if (idx >= 0 && idx < limit && opts_response_type_names[idx]) {
    return opts_response_type_names[idx];
  }
  return "unknown";
}

static OptsParseMode get_parse_mode(int argc, char *argv[]) {
  if (argc < 2 || !argv || !argv[1]) {
    return OPTS_PARSE_MODE_HELP;
  }

  if (strcmp(argv[1], "--output-mode-default") == 0) {
    return OPTS_PARSE_MODE_OUTPUT_MODE_DEFAULT;
  }

  if (strncmp(argv[1], "--help", 6) == 0) {
    return OPTS_PARSE_MODE_HELP;
  }

  if (strncmp(argv[1], "--alias", 7) == 0) {
    return OPTS_PARSE_MODE_ALIAS;
  }

  return OPTS_PARSE_MODE_TRANSMIT;
}

static int parse_transmit_mode(int argc, char *argv[], Opts *opts_out) {
  ArgvParsed parsed = {0};

  opts_out->hmac_mode = HMAC_MODE_NORMAL;
  opts_out->encrypt = 1;
  opts_out->verbose = 3;
  opts_out->output_mode = 0;

  if (!lib.argv.parse(argc, argv, &parsed, option_specs)) {
    return app.error_argv.parse(&parsed);
  }

  if (!apply_parsed_opts(&parsed, opts_out)) {
    return 0;
  }

  if (!lib.argv.has(&parsed, "--stdin") &&
      lib.stdin.has_piped_input &&
      lib.stdin.attach_if_piped) {
    if (lib.stdin.has_piped_input()) {
      lib.stdin.attach_if_piped(opts_out->payload, sizeof(opts_out->payload), &opts_out->payload_len);
    }
  }

  if (!opts_validate(opts_out)) {
    return 0;
  }

  opts_out->response_type = OPTS_RESPONSE_TRANSMIT;

  if (lib.argv.has(&parsed, "--opts-dump")) {
    if (lib.argv.dump) {
      lib.argv.dump(&parsed);
    }
    opts_dump(opts_out);
    exit(0);
  }

  return 1;
}

int parseOpts(int argc, char *argv[], Opts *opts_out) {
  OptsParseMode parse_mode = OPTS_PARSE_MODE_TRANSMIT;

  if (!opts_out) {
    return 0;
  }

  opts_out->response_type = OPTS_RESPONSE_ERROR;
  parse_mode = get_parse_mode(argc, argv);

  switch (parse_mode) {
    case OPTS_PARSE_MODE_HELP:
      opts_out->response_type = OPTS_RESPONSE_HELP;
      return 0;
    case OPTS_PARSE_MODE_OUTPUT_MODE_DEFAULT:
      return app.env.handle_output_mode_default_command(argc, argv);
    case OPTS_PARSE_MODE_ALIAS:
      opts_out->response_type = OPTS_RESPONSE_ALIAS;
      return handle_alias(argc, argv);
    case OPTS_PARSE_MODE_TRANSMIT:
      return parse_transmit_mode(argc, argv, opts_out);
    default:
      return 0;
  }
}

int opts_validate(Opts *opts) {
    int valid = 1;

    // Host must be provided
    if (opts->host[0] == '\0') {
        lib.print.uc_fprintf(stderr, "err", "Host not specified!\n");
        valid = 0;
    }

    // User ID must be nonzero
    if (opts->user_id == 0) {
        lib.print.uc_fprintf(stderr, "err", "Invalid or missing user ID\n");
        valid = 0;
    }

    // Action ID must be nonzero
    if (opts->action_id == 0) {
        lib.print.uc_fprintf(stderr, "err", "Invalid or missing action ID\n");
        valid = 0;
    }
    // Derive default key paths if missing
    if (opts->host[0] != '\0' && opts->hmac_key_path[0] == '\0') {
      if (!app.env.build_host_config_path(opts->hmac_key_path, PATH_MAX, opts->host, "hmac.key")) {
        valid = 0;
      }
    }

    if (opts->host[0] != '\0' && opts->server_pubkey_path[0] == '\0') {
      if (!app.env.build_host_config_path(opts->server_pubkey_path, PATH_MAX, opts->host, "server.pub.pem")) {
        valid = 0;
      }
    }
    
    // Port default
    if (opts->port == 0) {
        opts->port = 50000;
    }

    // Verbose level default
    if (opts->verbose < 0 || opts->verbose > 5) {
        opts->verbose = 3;
    }

    // Encrypt should default ON
    if (opts->encrypt < 0) {
        opts->encrypt = 1;
    }

    // Handle dead-drop specific rules
    if (opts->dead_drop) {
        opts->hmac_mode = HMAC_MODE_NONE;
        //opts->encrypt   = 1; // Dead-drop still encrypts
        if (opts->payload_len == 0) {
            lib.print.uc_fprintf(stderr, "err", "Dead drop payload is required \n");
	    
            valid = 0;
        }
    } else {
      // Structured knock
      // rely on default value , or override from command line.
      //opts->encrypt = 1; // Structured always encrypts
      // Payload is optional here
    }

    return valid;
}

int apply_parsed_opts(const ArgvParsed *parsed, Opts *out) {
  ArgvError parse_err = {0};

  for (int i = 0; i < parsed->num_options; i++) {
    const ArgvParsedOption *opt = &parsed->options[i];

    switch (opt->spec->id) {
    case OPT_ID_NONE:
      break; //no op for handling non assignable or non actionable opts
    case OPT_ID_PORT: {
      uint16_t parsed_port = 0;
      if (!lib.argv.get_u16(opt, 0, &parsed_port, &parse_err)) {
        return app.error_argv.typed(opt, &parse_err);
      }
      out->port = parsed_port;
      break;
    }
    case OPT_ID_HMAC_KEY:
      strncpy(out->hmac_key_path, opt->args[1], PATH_MAX - 1);
      break;

    case OPT_ID_SERVER_KEY:
      strncpy(out->server_pubkey_path, opt->args[1], PATH_MAX - 1);
      break;

    case OPT_ID_CLIENT_KEY:
      strncpy(out->client_privkey_path, opt->args[1], PATH_MAX - 1);
      break;

    case OPT_ID_NO_HMAC:
      out->hmac_mode = HMAC_MODE_NONE;
      break;

    case OPT_ID_DUMMY_HMAC:
      out->hmac_mode = HMAC_MODE_DUMMY;
      break;

    case OPT_ID_NO_ENCRYPT:
      out->encrypt = 0;
      break;

    case OPT_ID_DEAD_DROP:
      out->dead_drop = 1;
      break;

    case OPT_ID_VERBOSE: {
      int parsed_verbose = 0;
      if (!lib.argv.get_i32(opt, 0, 0, 5, &parsed_verbose, &parse_err)) {
        return app.error_argv.typed(opt, &parse_err);
      }
      out->verbose = parsed_verbose;
      break;
    }

    case OPT_ID_LOG:
      strncpy(out->log_file, opt->args[1], PATH_MAX - 1);
      break;
    case OPT_ID_STDIN:
      if (lib.stdin.read_multiline) {
        lib.stdin.read_multiline(out->payload, sizeof(out->payload), &out->payload_len);
      }
      break;
    case OPT_ID_OUTPUT_MODE: {
      static const ArgvEnumMap output_mode_map[] = {
        { "unicode", SL_OUTPUT_MODE_UNICODE },
        { "ascii", SL_OUTPUT_MODE_ASCII }
      };
      int mode = 0;

      if (!lib.argv.get_enum(opt, 0, output_mode_map,
                             sizeof(output_mode_map) / sizeof(output_mode_map[0]),
                             &mode, &parse_err)) {
        lib.print.uc_fprintf(stderr, "err",
                             "Invalid output mode: %s (expected 'unicode' or 'ascii')\n",
                             lib.argv.option_value(opt, 0) ? lib.argv.option_value(opt, 0) : "(null)");
        return 0;
      }
      out->output_mode = mode;
      break;
    }
    default:
      lib.print.uc_fprintf(stderr, "warn", "Unhandled option id %d: %s\n", opt->spec->id, opt->args[0]);
      break;
    }
  }

  // --- Positional args: host, user, action, payload ---
  if (parsed->num_positionals < 3) {
    lib.print.uc_fprintf(stderr, "err", "Missing required positional arguments: host, user, action\n");
    return 0;
  }

  const char *host_str   = parsed->positionals[0];
  const char *user_str   = parsed->positionals[1];
  const char *action_str = parsed->positionals[2];


  // Copy host
  strncpy(out->host, host_str, sizeof(out->host) - 1);
  //out->port = 50000; // Default port for now (TODO: make configurable)

  //  User alias resolution
  if (isdigit(user_str[0])) {
    out->user_id = (uint32_t)strtoul(user_str, NULL, 10);
  } else {
    out->user_id = app.alias.resolve_user(host_str, user_str);
    if (out->user_id == 0) {
      lib.print.uc_fprintf(stderr, "err", "Unknown user alias: %s\n", user_str);
      return 0;
    }
  }

  //  Action alias resolution
  if (isdigit(action_str[0])) {
    out->action_id = (uint32_t)strtoul(action_str, NULL, 10);
  } else {
    out->action_id = app.alias.resolve_action(host_str, action_str);
    if (out->action_id == 0) {
      lib.print.uc_fprintf(stderr, "err", "Unknown action alias: %s\n", action_str);
      return 0;
    }
  }

  //  Payload (optional)
  if (out->payload_len <= 0) {
    const char *payload    = (parsed->num_positionals >= 4) ? parsed->positionals[3] : NULL;
    if (payload) {
      size_t len = strlen(payload);
      if (len >= MAX_PAYLOAD_SIZE) len = MAX_PAYLOAD_SIZE - 1;

      memcpy(out->payload, payload, len);
      out->payload_len = len;
    } else {
      out->payload_len = 0;
    }
  }
  return 1;
}

void opts_dump(const Opts *opts) {
    lib.print.uc_printf("debug", "Dumping Resolved Opts:\n");

    lib.print.uc_printf(NULL, "Paths:\n");
    lib.print.uc_printf(NULL, "  HMAC Key Path    : %s\n", opts->hmac_key_path);
    lib.print.uc_printf(NULL, "  Server PubKey    : %s\n", opts->server_pubkey_path);
    lib.print.uc_printf(NULL, "  Client PrivKey   : %s\n", opts->client_privkey_path);
    lib.print.uc_printf(NULL, "  Log File         : %s\n", opts->log_file);

    lib.print.uc_printf(NULL, "\nTarget:\n");
    lib.print.uc_printf(NULL, "  Host             : %s\n", opts->host);
    lib.print.uc_printf(NULL, "  Port             : %u\n", opts->port);

    lib.print.uc_printf(NULL, "\nModes:\n");
    lib.print.uc_printf(NULL, "  HMAC Mode        : %d\n", opts->hmac_mode);
    lib.print.uc_printf(NULL, "  Encrypt Payload  : %s\n", opts->encrypt ? "Yes" : "No");
    lib.print.uc_printf(NULL, "  Dead Drop        : %s\n", opts->dead_drop ? "Yes" : "No");
    lib.print.uc_printf(NULL, "  Output Mode      : %s\n",
                        opts->output_mode ? lib.print.output_mode_name(opts->output_mode)
                                          : lib.print.output_mode_name(lib.print.output_get_mode()));

    lib.print.uc_printf(NULL, "\nUser and Action:\n");
    lib.print.uc_printf(NULL, "  User ID          : %u\n", opts->user_id);
    lib.print.uc_printf(NULL, "  Action ID        : %u\n", opts->action_id);

    lib.print.uc_printf(NULL, "\nPayload (%zu bytes):\n", opts->payload_len);
    if (opts->payload_len > 0) {
        lib.print.uc_printf(NULL, "  ");
        for (size_t i = 0; i < opts->payload_len; i++) {
            lib.print.uc_printf(NULL, "%02X ", opts->payload[i]);
        }
        lib.print.uc_printf(NULL, "\n");
    } else {
        lib.print.uc_printf(NULL, "  (No Payload)\n");
    }

    lib.print.uc_printf(NULL, "\nMisc:\n");
    lib.print.uc_printf(NULL, "  Verbose Level    : %d\n", opts->verbose);
    lib.print.uc_printf(NULL, "  Response Type    : %s\n", opts_response_type_name(opts->response_type));
}
