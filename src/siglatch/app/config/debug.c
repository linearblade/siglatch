/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include <stddef.h>

#include "debug.h"
#include "../app.h"
#include "../../lib.h"

static const char *payload_overflow_policy_name(siglatch_payload_overflow_policy policy) {
  switch (policy) {
  case SL_PAYLOAD_OVERFLOW_REJECT:
    return "reject";
  case SL_PAYLOAD_OVERFLOW_CLAMP:
    return "clamp";
  case SL_PAYLOAD_OVERFLOW_INHERIT:
    return "inherit";
  default:
    return "unknown";
  }
}

static const char *action_handler_name(siglatch_action_handler handler) {
  switch (handler) {
  case SL_ACTION_HANDLER_SHELL:
    return "shell";
  case SL_ACTION_HANDLER_BUILTIN:
    return "builtin";
  case SL_ACTION_HANDLER_STATIC:
    return "static";
  case SL_ACTION_HANDLER_DYNAMIC:
    return "dynamic";
  case SL_ACTION_HANDLER_INVALID:
  default:
    return "invalid";
  }
}

void config_debug_dump(void) {
  const siglatch_config *cfg = NULL;

  cfg = app.config.get();
  config_debug_dump_ptr(cfg);
}

void config_debug_dump_ptr(const siglatch_config *cfg) {
  if (!cfg) {
    lib.log.console("No config to dump.\n");
    return;
  }

  lib.log.console("siglatch config dump:\n\n");

  lib.log.console("  Master log file: %s\n", cfg->log_file);
  lib.log.console("  Private key path: %s\n", cfg->priv_key_path);
  lib.log.console("  Default server: %s\n",
                  cfg->default_server[0] ? cfg->default_server : "(unset)");
  lib.log.console("  Output mode: %s\n",
                  cfg->output_mode ? lib.print.output_mode_name(cfg->output_mode) : "(unset)");
  lib.log.console("  Payload overflow policy: %s\n",
                  payload_overflow_policy_name(cfg->payload_overflow));
  if (cfg->master_privkey) {
    lib.log.console("  Master private key loaded from %s\n", cfg->priv_key_path);
  } else {
    lib.log.console("  Master private key not loaded\n");
  }

  lib.log.console("\n  Actions (%d):\n", cfg->action_count);
  for (int i = 0; i < cfg->action_count; ++i) {
    const siglatch_action *a = &cfg->actions[i];
    lib.log.console("    - [%s]\n", a->name);
    lib.log.console("      ID         : %u\n", a->id);
    lib.log.console("      Label      : %s\n", a->label[0] ? a->label : "(unset)");
    lib.log.console("      Handler    : %s\n", action_handler_name(a->handler));
    lib.log.console("      Builtin    : %s\n", a->builtin[0] ? a->builtin : "(none)");
    lib.log.console("      Object     : %s\n", a->object[0] ? a->object : "(none)");
    lib.log.console("      Object Path: %s\n", a->object_path[0] ? a->object_path : "(none)");
    lib.log.console("      Run As     : %s\n", a->run_as[0] ? a->run_as : "(daemon)");
    lib.log.console("      Constructor: %s\n", a->constructor[0] ? a->constructor : "(none)");
    lib.log.console("      Destructor : %s\n", a->destructor[0] ? a->destructor : "(none)");
    lib.log.console("      Keepalive  : %d\n", a->keepalive_interval);
    lib.log.console("      Enabled  : %s\n", a->enabled ? "yes" : "no");
    lib.log.console("      Require Ascii Message  : %s\n", a->require_ascii ? "yes" : "no");
    lib.log.console("      exec_split  : %s\n", a->exec_split ? "yes" : "no");
    lib.log.console("      Enforce Wire Auth  : %s\n",
                    a->enforce_wire_auth ? "yes" : "no");
    lib.log.console("      Payload overflow policy : %s\n",
                    payload_overflow_policy_name(a->payload_overflow));
    lib.log.console("      Allowed IPs:\n");
    if (a->allowed_ip_count == 0) {
      lib.log.console("        - (any)\n");
    } else {
      for (int j = 0; j < a->allowed_ip_count; ++j) {
        lib.log.console("        - %s\n", a->allowed_ips[j]);
      }
    }
  }

  lib.log.console("\n  Users (%d):\n", cfg->user_count);
  for (int i = 0; i < cfg->user_count; ++i) {
    const siglatch_user *u = &cfg->users[i];
    int all_zero = 1;

    lib.log.console("    - [%s]\n", u->name);
    lib.log.console("      ID      : %u\n", u->id);
    lib.log.console("      Enabled : %s\n", u->enabled ? "yes" : "no");
    lib.log.console("      Key file: %s\n", u->key_file);
    if (u->pubkey) {
      lib.log.console("      User public key loaded from %s\n", u->key_file);
    } else {
      lib.log.console("      User public key not loaded\n");
    }

    lib.log.console("      HMAC file: %s\n", u->hmac_file);
    for (int j = 0; j < (int)sizeof(u->hmac_key); ++j) {
      if (u->hmac_key[j] != 0) {
        all_zero = 0;
        break;
      }
    }
    if (!all_zero) {
      lib.log.console("      HMAC key loaded from %s\n", u->hmac_file);
    } else {
      lib.log.console("      HMAC key not loaded\n");
    }

    lib.log.console("      Actions :\n");
    if (u->action_count == 0) {
      lib.log.console("        - (none)\n");
    } else {
      for (int j = 0; j < u->action_count; ++j) {
        lib.log.console("        - %s\n", u->actions[j]);
      }
    }
    lib.log.console("      Allowed IPs:\n");
    if (u->allowed_ip_count == 0) {
      lib.log.console("        - (any)\n");
    } else {
      for (int j = 0; j < u->allowed_ip_count; ++j) {
        lib.log.console("        - %s\n", u->allowed_ips[j]);
      }
    }
    lib.log.console("\n");
  }

  lib.log.console("\n  Servers (%d):\n", cfg->server_count);
  for (int i = 0; i < cfg->server_count; ++i) {
    const siglatch_server *s = &cfg->servers[i];
    lib.log.console("    - [%s]\n", s->name);
    lib.log.console("      ID       : %u\n", s->id);
    lib.log.console("      Label    : %s\n", s->label[0] ? s->label : "(unset)");
    lib.log.console("      Enabled  : %s\n", s->enabled ? "yes" : "no");
    lib.log.console("      Logging  : %s\n", s->logging ? "yes" : "no");
    lib.log.console("      Secure   : %s\n", s->secure ? "yes" : "no");
    lib.log.console("      Enforce Wire Decode : %s\n",
                    s->enforce_wire_decode ? "yes" : "no");
    lib.log.console("      Enforce Wire Auth   : %s\n",
                    s->enforce_wire_auth ? "yes" : "no");
    lib.log.console("      Bind IP  : %s\n", s->bind_ip[0] ? s->bind_ip : "(any)");
    lib.log.console("      Port     : %d\n", s->port);
    lib.log.console("      Log file : %s\n", s->log_file[0] ? s->log_file : "(none)");
    lib.log.console("      Output Mode : %s\n",
                    s->output_mode ? lib.print.output_mode_name(s->output_mode) : "(unset)");
    lib.log.console("      Payload overflow policy : %s\n",
                    payload_overflow_policy_name(s->payload_overflow));

    lib.log.console("      Private key: %s\n",
                    s->priv_key_path[0] ? s->priv_key_path : "(inherited)");
    if (s->priv_key) {
      lib.log.console("      Private key loaded (owned: %s)\n", s->key_owned ? "yes" : "no");
    } else {
      lib.log.console("      Private key not loaded\n");
    }

    lib.log.console("      Actions:\n");
    if (s->action_count == 0) {
      lib.log.console("        - (none)\n");
    } else {
      for (int j = 0; j < s->action_count; ++j) {
        lib.log.console("        - %s\n", s->actions[j]);
      }
    }

    lib.log.console("      Allowed IPs:\n");
    if (s->allowed_ip_count == 0) {
      lib.log.console("        - (any)\n");
    } else {
      for (int j = 0; j < s->allowed_ip_count; ++j) {
        lib.log.console("        - %s\n", s->allowed_ips[j]);
      }
    }

    lib.log.console("      Deaddrops:\n");
    if (s->deaddrop_count == 0) {
      lib.log.console("        - (none)\n");
    } else {
      for (int j = 0; j < s->deaddrop_count; ++j) {
        lib.log.console("        - %s\n", s->deaddrops[j]);
      }
    }

    lib.log.console("\n");
  }

  lib.log.console("  Deaddrops (%d):\n", cfg->deaddrop_count);
  for (int i = 0; i < cfg->deaddrop_count; ++i) {
    const siglatch_deaddrop *d = &cfg->deaddrops[i];
    lib.log.console("    - [%s]\n", d->name);
    lib.log.console("      ID       : %u\n", d->id);
    lib.log.console("      Label    : %s\n", d->label[0] ? d->label : d->name);
    lib.log.console("      Enabled  : %s\n", d->enabled ? "yes" : "no");
    lib.log.console("      Require Ascii Message  : %s\n", d->require_ascii ? "yes" : "no");
    lib.log.console("      exec_split  : %s\n", d->exec_split ? "yes" : "no");
    lib.log.console("      Run As     : %s\n", d->run_as[0] ? d->run_as : "(daemon)");
    lib.log.console("      Constructor: %s\n", d->constructor);
    lib.log.console("      Filters:\n");
    if (d->filter_count == 0) {
      lib.log.console("        - (none)\n");
    } else {
      for (int j = 0; j < d->filter_count; ++j) {
        lib.log.console("        - %s\n", d->filters[j]);
      }
    }
    lib.log.console("      Starts With:\n");
    if (d->starts_with_count == 0) {
      lib.log.console("        - (none)\n");
    } else {
      for (int j = 0; j < d->starts_with_count; ++j) {
        lib.log.console("        - %s\n", d->starts_with[j]);
      }
    }
  }

  lib.log.console("\n");
}
