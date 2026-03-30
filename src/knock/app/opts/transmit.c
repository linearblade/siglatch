/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "transmit.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../lib.h"
#include "../app.h"

enum {
  OPT_ID_NONE = 0,
  OPT_ID_HMAC_KEY,
  OPT_ID_PROTOCOL,
  OPT_ID_PORT,
  OPT_ID_SERVER_KEY,
  OPT_ID_CLIENT_KEY,
  OPT_ID_NO_HMAC,
  OPT_ID_DUMMY_HMAC,
  OPT_ID_NO_ENCRYPT,
  OPT_ID_DEAD_DROP,
  OPT_ID_SEND_FROM,
  OPT_ID_VERBOSE,
  OPT_ID_LOG,
  OPT_ID_STDIN,
  OPT_ID_OUTPUT_MODE
};

static const ArgvOptionSpec option_specs[] = {
  { "--port",        OPT_ID_PORT,        1, ARGV_OPT_KEYED, 0, 0, 1 },
  { "--hmac-key",    OPT_ID_HMAC_KEY,    1, ARGV_OPT_KEYED, 0, 0, 1 },
  { "--protocol",    OPT_ID_PROTOCOL,    1, ARGV_OPT_KEYED, 0, 0, 1 },
  { "--server-key",  OPT_ID_SERVER_KEY,  1, ARGV_OPT_KEYED, 0, 0, 1 },
  { "--client-key",  OPT_ID_CLIENT_KEY,  1, ARGV_OPT_KEYED, 0, 0, 1 },
  { "--no-hmac",     OPT_ID_NO_HMAC,     0, ARGV_OPT_FLAG,  0, 0, 1 },
  { "--stdin",       OPT_ID_STDIN,       0, ARGV_OPT_FLAG,  0, 0, 1 },
  { "--opts-dump",   OPT_ID_NONE,        0, ARGV_OPT_FLAG,  0, 0, 1 },
  { "--dummy-hmac",  OPT_ID_DUMMY_HMAC,  0, ARGV_OPT_FLAG,  0, 0, 1 },
  { "--no-encrypt",  OPT_ID_NO_ENCRYPT,  0, ARGV_OPT_FLAG,  0, 0, 1 },
  { "--dead-drop",   OPT_ID_DEAD_DROP,   0, ARGV_OPT_FLAG,  0, 0, 1 },
  { "--send-from",   OPT_ID_SEND_FROM,   1, ARGV_OPT_KEYED, 0, 0, 1 },
  { "--verbose",     OPT_ID_VERBOSE,     1, ARGV_OPT_KEYED, 0, 0, 1 },
  { "--log",         OPT_ID_LOG,         1, ARGV_OPT_KEYED, 0, 0, 1 },
  { "--output-mode", OPT_ID_OUTPUT_MODE, 1, ARGV_OPT_KEYED, 0, 0, 1 },
  { NULL, 0, 0, ARGV_OPT_FLAG, 0, 0, 0 }
};

static const ArgvOptionSpec *app_opts_transmit_spec(void) {
  return option_specs;
}

static const char *const opts_response_type_names[] = {
  [OPTS_RESPONSE_HELP] = "help",
  [OPTS_RESPONSE_ERROR] = "error",
  [OPTS_RESPONSE_ALIAS] = "alias",
  [OPTS_RESPONSE_TRANSMIT] = "transmit"
};

static int app_opts_transmit_init(void) {
  return 1;
}

static void app_opts_transmit_shutdown(void) {
}

static int app_opts_transmit_set_error(AppCommand *out, int exit_code, const char *message) {
  if (!out) {
    return 0;
  }

  out->type = APP_CMD_ERROR;
  out->ok = 0;
  out->exit_code = exit_code;

  if (message && *message) {
    snprintf(out->error, sizeof(out->error), "%s", message);
  } else {
    out->error[0] = '\0';
  }

  return 0;
}

static int app_opts_transmit_set_typed_error(AppCommand *out, const ArgvParsedOption *opt,
                                             const ArgvError *err) {
  char message[256];

  if (app.error_argv.shape_typed &&
      app.error_argv.shape_typed(opt, err, message, sizeof(message))) {
    return app_opts_transmit_set_error(out, 2, message);
  }

  return app_opts_transmit_set_error(out, 2, "Invalid option value");
}

static int app_opts_transmit_parse_numeric_id(const char *value,
                                              uint32_t min_value,
                                              uint32_t max_value,
                                              uint32_t *out_id) {
  unsigned long parsed = 0;
  char *end = NULL;

  if (!value || !*value || !out_id || min_value > max_value) {
    return 0;
  }

  errno = 0;
  parsed = strtoul(value, &end, 10);
  if (errno != 0 || !end || *end != '\0') {
    return 0;
  }

  if (parsed < (unsigned long)min_value || parsed > (unsigned long)max_value) {
    return 0;
  }

  *out_id = (uint32_t)parsed;
  return 1;
}

static const char *app_opts_response_type_name(OptsResponseType value) {
  int idx = (int)value;
  int limit = (int)(sizeof(opts_response_type_names) / sizeof(opts_response_type_names[0]));

  if (idx >= 0 && idx < limit && opts_response_type_names[idx]) {
    return opts_response_type_names[idx];
  }

  return "unknown";
}

static const char *app_opts_protocol_name(KnockProtocol protocol) {
  switch (protocol) {
    case KNOCK_PROTOCOL_V1:
      return "v1";
    case KNOCK_PROTOCOL_V2:
      return "v2";
    case KNOCK_PROTOCOL_V3:
      return "v3";
    default:
      return "unknown";
  }
}

static int app_opts_transmit_validate(Opts *opts, AppCommand *cmd) {
  int valid = 1;
  char message[256];

  if (opts->host[0] == '\0') {
    app_opts_transmit_set_error(cmd, 2, "Host not specified!");
    valid = 0;
  }

  if (opts->user_id == 0) {
    app_opts_transmit_set_error(cmd, 2, "Invalid or missing user ID");
    valid = 0;
  }

  if (opts->user_id > UINT16_MAX) {
    app_opts_transmit_set_error(cmd, 2, "Resolved user ID exceeds packet range (max 65535)");
    valid = 0;
  }

  if (opts->action_id == 0) {
    app_opts_transmit_set_error(cmd, 2, "Invalid or missing action ID");
    valid = 0;
  }

  if (opts->action_id > UINT8_MAX) {
    app_opts_transmit_set_error(cmd, 2, "Resolved action ID exceeds packet range (max 255)");
    valid = 0;
  }

  if (opts->host[0] != '\0' && opts->hmac_key_path[0] == '\0') {
    if (!app.env.build_host_config_path(opts->hmac_key_path, PATH_MAX, opts->host, "hmac.key")) {
      snprintf(message, sizeof(message), "Failed to resolve hmac key path for host: %s", opts->host);
      app_opts_transmit_set_error(cmd, 2, message);
      valid = 0;
    }
  }

  if (opts->host[0] != '\0' && opts->server_pubkey_path[0] == '\0') {
    if (!app.env.build_host_config_path(opts->server_pubkey_path, PATH_MAX, opts->host, "server.pub.pem")) {
      snprintf(message, sizeof(message), "Failed to resolve server key path for host: %s", opts->host);
      app_opts_transmit_set_error(cmd, 2, message);
      valid = 0;
    }
  }

  if (opts->host[0] != '\0' && opts->client_privkey_path[0] == '\0') {
    if (!app.env.build_host_config_path(opts->client_privkey_path, PATH_MAX, opts->host, "user.pri.pem")) {
      snprintf(message, sizeof(message), "Failed to resolve client key path for host: %s", opts->host);
      app_opts_transmit_set_error(cmd, 2, message);
      valid = 0;
    }
  }

  if (opts->host[0] != '\0' &&
      opts->user_selector[0] != '\0' &&
      opts->send_from_ip[0] == '\0') {
    int send_from_rv = app.env.load_host_user_send_from_ip(opts->host,
                                                           opts->user_selector,
                                                           opts->send_from_ip,
                                                           sizeof(opts->send_from_ip));
    if (send_from_rv < 0) {
      snprintf(message, sizeof(message),
               "Invalid host user send_from_ip config for %s/%s",
               opts->host, opts->user_selector);
      app_opts_transmit_set_error(cmd, 2, message);
      valid = 0;
    }
  }

  if (opts->send_from_ip[0] != '\0' &&
      !lib.net.ip.range.is_single_ipv4(opts->send_from_ip)) {
    app_opts_transmit_set_error(cmd, 2, "Invalid --send-from IPv4 address");
    valid = 0;
  }

  if (opts->port == 0) {
    opts->port = 50000;
  }

  if (opts->verbose < 0 || opts->verbose > 5) {
    opts->verbose = 3;
  }

  if (opts->encrypt < 0) {
    opts->encrypt = 1;
  }

  if (opts->protocol == 0) {
    opts->protocol = KNOCK_PROTOCOL_V1;
  }

  if (opts->dead_drop) {
    opts->hmac_mode = HMAC_MODE_NONE;
  }

  if (opts->protocol == KNOCK_PROTOCOL_V3) {
    if (!opts->encrypt) {
      app_opts_transmit_set_error(cmd, 2, "Protocol v3 requires encryption");
      valid = 0;
    }

    if (opts->hmac_mode != HMAC_MODE_NORMAL) {
      app_opts_transmit_set_error(cmd, 2, "Protocol v3 requires normal HMAC signing");
      valid = 0;
    }

    if (opts->dead_drop) {
      app_opts_transmit_set_error(cmd, 2, "Protocol v3 does not support dead-drop mode");
      valid = 0;
    }
  }

  return valid;
}

static int app_opts_transmit_apply_parsed(const ArgvParsed *parsed, Opts *out, AppCommand *cmd) {
  ArgvError parse_err = {0};
  char message[256];

  for (int i = 0; i < parsed->num_options; i++) {
    const ArgvParsedOption *opt = &parsed->options[i];

    switch (opt->spec->id) {
    case OPT_ID_NONE:
      break;
    case OPT_ID_PORT: {
      uint16_t parsed_port = 0;
      if (!lib.argv.get_u16(opt, 0, &parsed_port, &parse_err)) {
        return app_opts_transmit_set_typed_error(cmd, opt, &parse_err);
      }
      out->port = parsed_port;
      break;
    }
    case OPT_ID_HMAC_KEY:
      strncpy(out->hmac_key_path, opt->args[1], PATH_MAX - 1);
      break;
    case OPT_ID_PROTOCOL: {
      static const ArgvEnumMap protocol_map[] = {
        { "v1", KNOCK_PROTOCOL_V1 },
        { "v2", KNOCK_PROTOCOL_V2 },
        { "v3", KNOCK_PROTOCOL_V3 }
      };
      int protocol = 0;

      if (!lib.argv.get_enum(opt, 0, protocol_map,
                             sizeof(protocol_map) / sizeof(protocol_map[0]),
                             &protocol, &parse_err)) {
        snprintf(message, sizeof(message),
                 "Invalid protocol: %s (expected 'v1', 'v2', or 'v3')",
                 lib.argv.option_value(opt, 0) ? lib.argv.option_value(opt, 0) : "(null)");
        return app_opts_transmit_set_error(cmd, 2, message);
      }
      out->protocol = (KnockProtocol)protocol;
      break;
    }
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
    case OPT_ID_SEND_FROM:
      strncpy(out->send_from_ip, opt->args[1], sizeof(out->send_from_ip) - 1);
      break;
    case OPT_ID_VERBOSE: {
      int parsed_verbose = 0;
      if (!lib.argv.get_i32(opt, 0, 0, 5, &parsed_verbose, &parse_err)) {
        return app_opts_transmit_set_typed_error(cmd, opt, &parse_err);
      }
      out->verbose = parsed_verbose;
      break;
    }
    case OPT_ID_LOG:
      strncpy(out->log_file, opt->args[1], PATH_MAX - 1);
      break;
    case OPT_ID_STDIN:
      out->stdin_requested = 1;
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
        snprintf(message, sizeof(message),
                 "Invalid output mode: %s (expected 'unicode' or 'ascii')",
                 lib.argv.option_value(opt, 0) ? lib.argv.option_value(opt, 0) : "(null)");
        return app_opts_transmit_set_error(cmd, 2, message);
      }
      out->output_mode = mode;
      break;
    }
    default:
      lib.print.uc_fprintf(stderr, "warn", "Unhandled option id %d: %s\n", opt->spec->id, opt->args[0]);
      break;
    }
  }

  if (parsed->num_positionals < 3) {
    return app_opts_transmit_set_error(cmd, 2,
                                       "Missing required positional arguments: host, user, action");
  }

  {
    const char *host_str = parsed->positionals[0];
    const char *user_str = parsed->positionals[1];
    const char *action_str = parsed->positionals[2];

    strncpy(out->host, host_str, sizeof(out->host) - 1);
    strncpy(out->user_selector, user_str, sizeof(out->user_selector) - 1);

    out->user_id = app.alias.resolve_user(host_str, user_str);
    if (out->user_id == 0) {
      if (!app_opts_transmit_parse_numeric_id(user_str, 1, UINT16_MAX, &out->user_id)) {
        snprintf(message, sizeof(message),
                 "Unknown user alias or invalid user ID: %s (expected alias or numeric range 1-%u)",
                 user_str, (unsigned)UINT16_MAX);
        return app_opts_transmit_set_error(cmd, 2, message);
      }
    }

    out->action_id = app.alias.resolve_action(host_str, action_str);
    if (out->action_id == 0) {
      if (!app_opts_transmit_parse_numeric_id(action_str, 1, UINT8_MAX, &out->action_id)) {
        snprintf(message, sizeof(message),
                 "Unknown action alias or invalid action ID: %s (expected alias or numeric range 1-%u)",
                 action_str, (unsigned)UINT8_MAX);
        return app_opts_transmit_set_error(cmd, 2, message);
      }
    }

    if (out->payload_len <= 0) {
      const char *payload = (parsed->num_positionals >= 4) ? parsed->positionals[3] : NULL;
      if (payload) {
        size_t len = strlen(payload);
        if (len >= MAX_PAYLOAD_SIZE) {
          len = MAX_PAYLOAD_SIZE - 1;
        }

        memcpy(out->payload, payload, len);
        out->payload_len = len;
      } else {
        out->payload_len = 0;
      }
    }
  }

  return 1;
}

static void app_opts_transmit_dump(const Opts *opts) {
  lib.print.uc_printf("debug", "Dumping Resolved Opts:\n");

  lib.print.uc_printf(NULL, "Paths:\n");
  lib.print.uc_printf(NULL, "  HMAC Key Path    : %s\n", opts->hmac_key_path);
  lib.print.uc_printf(NULL, "  Server PubKey    : %s\n", opts->server_pubkey_path);
  lib.print.uc_printf(NULL, "  Client PrivKey   : %s\n", opts->client_privkey_path);
  lib.print.uc_printf(NULL, "  Log File         : %s\n", opts->log_file);

  lib.print.uc_printf(NULL, "\nTarget:\n");
  lib.print.uc_printf(NULL, "  Host             : %s\n", opts->host);
  lib.print.uc_printf(NULL, "  User Selector    : %s\n",
                      opts->user_selector[0] ? opts->user_selector : "(unset)");
  lib.print.uc_printf(NULL, "  Send From IP     : %s\n",
                      opts->send_from_ip[0] ? opts->send_from_ip : "(unset)");
  lib.print.uc_printf(NULL, "  Port             : %u\n", opts->port);

  lib.print.uc_printf(NULL, "\nModes:\n");
  lib.print.uc_printf(NULL, "  HMAC Mode        : %d\n", opts->hmac_mode);
  lib.print.uc_printf(NULL, "  Protocol         : %s\n", app_opts_protocol_name(opts->protocol));
  lib.print.uc_printf(NULL, "  Encrypt Payload  : %s\n", opts->encrypt ? "Yes" : "No");
  lib.print.uc_printf(NULL, "  Dead Drop        : %s\n", opts->dead_drop ? "Yes" : "No");
  lib.print.uc_printf(NULL, "  Stdin Requested  : %s\n", opts->stdin_requested ? "Yes" : "No");
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
  lib.print.uc_printf(NULL, "  Response Type    : %s\n", app_opts_response_type_name(opts->response_type));
}

static int app_opts_transmit_parse(const char *mode_selector, const ArgvParsed *parsed, AppCommand *out) {
  Opts *opts_out = NULL;

  (void)mode_selector;

  if (!parsed || !out) {
    return 0;
  }

  out->type = APP_CMD_TRANSMIT;
  out->ok = 0;
  out->exit_code = 2;
  out->dump_requested = 0;
  memset(&out->as.transmit, 0, sizeof(out->as.transmit));
  opts_out = &out->as.transmit;

  opts_out->hmac_mode = HMAC_MODE_NORMAL;
  opts_out->protocol = KNOCK_PROTOCOL_V1;
  opts_out->encrypt = 1;
  opts_out->verbose = 3;
  opts_out->output_mode = 0;

  out->dump_requested = lib.argv.has(parsed, "--opts-dump") ? 1 : 0;

  if (!app_opts_transmit_apply_parsed(parsed, opts_out, out)) {
    return 0;
  }

  if (!app_opts_transmit_validate(opts_out, out)) {
    return 0;
  }

  opts_out->response_type = OPTS_RESPONSE_TRANSMIT;
  out->ok = 1;
  out->exit_code = 0;
  return 1;
}

static const AppOptsTransmitLib app_opts_transmit_instance = {
  .init = app_opts_transmit_init,
  .shutdown = app_opts_transmit_shutdown,
  .spec = app_opts_transmit_spec,
  .parse = app_opts_transmit_parse,
  .dump = app_opts_transmit_dump
};

const AppOptsTransmitLib *get_app_opts_transmit_lib(void) {
  return &app_opts_transmit_instance;
}
