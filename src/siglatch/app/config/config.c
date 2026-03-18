/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <openssl/evp.h>
#include "config.h"
#include "debug.h"
#include "../app.h"
#include "../../lib.h"

#define TIMEOUT_SEC 5

static void config_free(siglatch_config *config);
static siglatch_config *config_consume_document_ptr(const IniDocument *document);
static siglatch_config *config_build_from_path(const char *path);
static int parse_output_mode_key(const char *value, const char *scope_label);
static siglatch_action_handler parse_action_handler_key(
    const char *value,
    const char *scope_label);
static siglatch_payload_overflow_policy parse_payload_overflow_key(
    const char *value,
    const char *scope_label,
    int allow_inherit,
    siglatch_payload_overflow_policy fallback);
static int validate_unique_server_names(const siglatch_config *cfg);
static int validate_action_handlers(const siglatch_config *cfg);
static int validate_ip_constraints(const siglatch_config *cfg);

static void apply_server_runtime_defaults(siglatch_config *cfg);
static void config_apply_defaults(siglatch_config *config);
static siglatch_user *config_append_user(siglatch_config *config, const char *name);
static siglatch_action *config_append_action(siglatch_config *config, const char *name);
static siglatch_server *config_append_server(siglatch_config *config, const char *name);
static siglatch_deaddrop *config_append_deaddrop(siglatch_config *config, const char *name);
static void config_consume_global_entry(siglatch_config *config, const IniEntry *entry);
static void config_consume_action_entry(siglatch_action *action, const IniEntry *entry);
static void config_consume_user_entry(siglatch_user *user, const IniEntry *entry);
static void config_consume_server_entry(siglatch_server *server, const IniEntry *entry);
static void config_consume_deaddrop_entry(siglatch_deaddrop *deaddrop, const IniEntry *entry);
static const siglatch_user *config_user_by_id_from_ptr(const siglatch_config *cfg, uint32_t user_id);
static const siglatch_action *config_action_by_id_from_ptr(const siglatch_config *cfg, uint32_t action_id);
static const siglatch_server *config_server_by_name_from_ptr(const siglatch_config *cfg, const char *name);
static const siglatch_deaddrop *config_deaddrop_by_name_from_ptr(const siglatch_config *cfg, const char *name);
static int config_server_set_port(const char *name, int port);
static int config_server_set_binding(const char *name, const char *bind_ip, int port);
static int validate_ip_spec_list(const char specs[][MAX_IP_RANGE_LEN],
                                 int count,
                                 const char *scope_label);

static  siglatch_config *_config = NULL;
static  int _owned = 0;
static siglatch_config_context _ctx = {0};

static int config_init(const siglatch_config_context *ctx) {
    if (!ctx) {
        return 0; // NULL context passed
    }
    _ctx = *ctx;
    return 1; // Success
}

static void config_shutdown(void) {
  _ctx = (siglatch_config_context){0};
  if (_owned) 
    config_free(_config);
  _owned = 0;
  _config = NULL;
}

static int config_set_context(const siglatch_config_context *ctx) {
    if (!ctx) {
        return 0; // Ignore null override
    }
    // Copy new context into static global
    _ctx = *ctx;
    return 1;
}

static const siglatch_config *config_get(void) {
    return _config;
}
static siglatch_config *config_detach(void) {
    siglatch_config *detached = _config;
    _config = NULL;
    _owned = 0;
    return detached;
}

static void config_attach(siglatch_config *config) {
  if (!config)
    return;

  if (_owned && _config)
    config_free(_config);

  _config = config;
  _owned = 1;
}

static int config_load(const char *path) {
  siglatch_config *cfg = NULL;
  cfg = config_build_from_path(path);
  if (!cfg) {
    return 0;
  }

  config_attach(cfg);
  return 1;
}

static int config_load_detached(const char *path, siglatch_config **out_config) {
  siglatch_config *cfg = NULL;

  if (!out_config) {
    return 0;
  }

  *out_config = NULL;
  cfg = config_build_from_path(path);
  if (!cfg) {
    return 0;
  }

  *out_config = cfg;
  return 1;
}

static int config_consume(const IniDocument *document) {
  siglatch_config *cfg = config_consume_document_ptr(document);
  if (cfg) {
    config_attach(cfg);  // takes ownership, frees any prior
    return 1;
  }
  return 0;
}

static int parse_output_mode_key(const char *value, const char *scope_label) {
  int mode = lib.print.output_parse_mode(value);
  if (mode) {
    return mode;
  }

  LOGW("Invalid output_mode '%s' in %s (expected 'unicode' or 'ascii')\n",
       value ? value : "(null)",
       scope_label ? scope_label : "config");
  return 0;
}

static siglatch_action_handler parse_action_handler_key(
    const char *value,
    const char *scope_label) {
  if (value && strcasecmp(value, "shell") == 0) {
    return SL_ACTION_HANDLER_SHELL;
  }

  if (value && strcasecmp(value, "builtin") == 0) {
    return SL_ACTION_HANDLER_BUILTIN;
  }

  LOGW("Invalid action handler '%s' in %s (expected 'shell' or 'builtin')\n",
       value ? value : "(null)",
       scope_label ? scope_label : "action");
  return SL_ACTION_HANDLER_INVALID;
}

static siglatch_payload_overflow_policy parse_payload_overflow_key(
    const char *value,
    const char *scope_label,
    int allow_inherit,
    siglatch_payload_overflow_policy fallback) {
  if (value && strcasecmp(value, "reject") == 0) {
    return SL_PAYLOAD_OVERFLOW_REJECT;
  }

  if (value && strcasecmp(value, "clamp") == 0) {
    return SL_PAYLOAD_OVERFLOW_CLAMP;
  }

  if (allow_inherit && value && strcasecmp(value, "inherit") == 0) {
    return SL_PAYLOAD_OVERFLOW_INHERIT;
  }

  LOGW("Invalid payload_overflow '%s' in %s (expected '%s')\n",
       value ? value : "(null)",
       scope_label ? scope_label : "config",
       allow_inherit ? "reject|clamp|inherit" : "reject|clamp");
  return fallback;
}

static siglatch_config *config_build_from_path(const char *path) {
  IniDocument *document = NULL;
  IniError error = {0};
  siglatch_config *cfg = NULL;

  if (!path || path[0] == '\0') {
    LOGE("Invalid config path\n");
    return NULL;
  }

  document = lib.parse.ini.read_file(path, &error);
  if (!document) {
    if (error.message[0] != '\0') {
      if (error.line) {
        LOGE("Config parse error on line %zu: %s\n", error.line, error.message);
      } else {
        LOGE("Config parse error: %s\n", error.message);
      }
    }
    return NULL;
  }

  cfg = config_consume_document_ptr(document);
  lib.parse.ini.destroy(document);
  document = NULL;

  if (!cfg) {
    return NULL;
  }

  if (!app.keys.load(cfg)) {
    config_free(cfg);
    return NULL;
  }

  return cfg;
}

static const siglatch_user *config_user_by_id_from_ptr(
    const siglatch_config *cfg,
    uint32_t user_id) {
    if (!cfg) return NULL;

    for (int i = 0; i < cfg->user_count; ++i) {
        const siglatch_user *u = &cfg->users[i];
        if (u->enabled && u->id == user_id) {
            return u;
        }
    }

    return NULL;  // Not found
}

const siglatch_user *config_user_by_id(uint32_t user_id) {
    return config_user_by_id_from_ptr(_config, user_id);
}

static const siglatch_user *config_user_by_id_from(
    const siglatch_config *cfg,
    uint32_t user_id) {
  return config_user_by_id_from_ptr(cfg, user_id);
}

static int config_action_available_by_user(uint32_t user_id, const char *action) {
    if (!_config || !action) return 0;

    const siglatch_user *user = config_user_by_id(user_id);
    if (!user ) return 0;

    for (int i = 0; i < user->action_count; ++i) {
        const char *a = user->actions[i];
        if (lib.str.eq(a, action)) {
            return 1;
        }
    }

    return 0;  // Not found
}

const char * config_username_by_id(uint32_t user_id){
  const siglatch_user * u = config_user_by_id(user_id);
  return u && u->name[0] != '\0'?
    u->name:
    NULL;
}

static const siglatch_action *config_action_by_id_from_ptr(
    const siglatch_config *cfg,
    uint32_t action_id) {
  if (!cfg) return NULL;
  
  for (int i = 0; i < cfg->action_count; ++i) {
    if (cfg->actions[i].id == action_id) {
      return &cfg->actions[i];
    }
  }
  return NULL;
}

const siglatch_action *config_action_by_id(uint32_t action_id){
  return config_action_by_id_from_ptr(_config, action_id);
}

static const siglatch_action *config_action_by_id_from(
    const siglatch_config *cfg,
    uint32_t action_id) {
  return config_action_by_id_from_ptr(cfg, action_id);
}

static void apply_server_runtime_defaults(siglatch_config *cfg) {
  if (!cfg) {
    return;
  }

  for (int i = 0; i < cfg->server_count; ++i) {
    siglatch_server *s = &cfg->servers[i];

    if (!s->port) {
      s->port = 50000;
    }

    if (s->log_file[0] == '\0' && cfg->log_file[0] != '\0') {
      lib.str.lcpy(s->log_file, cfg->log_file, PATH_MAX);
      LOGW("Using fallback log file for server [%s]: %s\n", s->name, s->log_file);
    }
  }
}

static int validate_unique_server_names(const siglatch_config *cfg) {
  if (!cfg) {
    return 0;
  }

  for (int i = 0; i < cfg->server_count; ++i) {
    const siglatch_server *a = &cfg->servers[i];

    if (a->name[0] == '\0') {
      LOGE("Invalid server config: server entry #%d has empty effective name\n", i + 1);
      return 0;
    }

    for (int j = i + 1; j < cfg->server_count; ++j) {
      const siglatch_server *b = &cfg->servers[j];

      if (strcmp(a->name, b->name) == 0) {
        LOGE("Invalid server config: duplicate effective server name '%s' (entries #%d and #%d)\n",
             a->name, i + 1, j + 1);
        return 0;
      }
    }
  }

  return 1;
}

static int validate_action_handlers(const siglatch_config *cfg) {
  if (!cfg) {
    return 0;
  }

  for (int i = 0; i < cfg->action_count; ++i) {
    const siglatch_action *action = &cfg->actions[i];

    switch (action->handler) {
    case SL_ACTION_HANDLER_SHELL:
      if (action->constructor[0] == '\0') {
        LOGE("Invalid action [%s]: shell handler requires constructor\n",
             action->name);
        return 0;
      }
      break;

    case SL_ACTION_HANDLER_BUILTIN:
      if (action->builtin[0] == '\0') {
        LOGE("Invalid action [%s]: builtin handler requires builtin name\n",
             action->name);
        return 0;
      }

      if (action->constructor[0] != '\0') {
        LOGE("Invalid action [%s]: builtin handler cannot define constructor\n",
             action->name);
        return 0;
      }

      if (!app.builtin.supports(action->builtin)) {
        LOGE("Invalid action [%s]: unsupported builtin '%s'\n",
             action->name,
             action->builtin);
        return 0;
      }
      break;

    case SL_ACTION_HANDLER_INVALID:
    default:
      LOGE("Invalid action [%s]: unknown handler type\n", action->name);
      return 0;
    }
  }

  return 1;
}

static int validate_ip_spec_list(const char specs[][MAX_IP_RANGE_LEN],
                                 int count,
                                 const char *scope_label) {
  int i = 0;

  for (i = 0; i < count; ++i) {
    const char *spec = specs[i];

    if (!spec || spec[0] == '\0') {
      continue;
    }

    if (lib.net.ip.range.is_single_ipv4(spec) ||
        lib.net.ip.range.is_cidr_ipv4(spec)) {
      continue;
    }

    LOGE("Invalid IP restriction '%s' in %s\n",
         spec,
         scope_label ? scope_label : "config");
    return 0;
  }

  return 1;
}

static int validate_ip_constraints(const siglatch_config *cfg) {
  int i = 0;
  char scope_label[128] = {0};

  if (!cfg) {
    return 0;
  }

  for (i = 0; i < cfg->user_count; ++i) {
    const siglatch_user *user = &cfg->users[i];
    snprintf(scope_label, sizeof(scope_label), "[user:%s]", user->name);
    if (!validate_ip_spec_list(user->allowed_ips, user->allowed_ip_count, scope_label)) {
      return 0;
    }
  }

  for (i = 0; i < cfg->action_count; ++i) {
    const siglatch_action *action = &cfg->actions[i];
    snprintf(scope_label, sizeof(scope_label), "[action:%s]", action->name);
    if (!validate_ip_spec_list(action->allowed_ips, action->allowed_ip_count, scope_label)) {
      return 0;
    }
  }

  for (i = 0; i < cfg->server_count; ++i) {
    const siglatch_server *server = &cfg->servers[i];

    snprintf(scope_label, sizeof(scope_label), "[server:%s]", server->name);
    if (!validate_ip_spec_list(server->allowed_ips, server->allowed_ip_count, scope_label)) {
      return 0;
    }

    if (server->bind_ip[0] == '\0') {
      continue;
    }

    if (!lib.net.ip.range.is_single_ipv4(server->bind_ip)) {
      LOGE("Invalid bind_ip '%s' in [server:%s]\n",
           server->bind_ip,
           server->name);
      return 0;
    }
  }

  return 1;
}


static const siglatch_deaddrop *config_deaddrop_by_name_from_ptr(
    const siglatch_config *cfg,
    const char *name) {
  if (!cfg || !name) return NULL;

  for (int i = 0; i < cfg->deaddrop_count; ++i) {
    if (strcmp(cfg->deaddrops[i].name, name) == 0) {
      return &cfg->deaddrops[i];
    }
  }
  return NULL;
}

const siglatch_deaddrop *config_deaddrop_by_name(const char *name) {
  return config_deaddrop_by_name_from_ptr(_config, name);
}

static const siglatch_deaddrop *config_deaddrop_by_name_from(
    const siglatch_config *cfg,
    const char *name) {
  return config_deaddrop_by_name_from_ptr(cfg, name);
}

static const siglatch_server *config_server_by_name_from_ptr(
    const siglatch_config *cfg,
    const char *name) {
  if (!cfg || !name) return NULL;

  for (int i = 0; i < cfg->server_count; ++i) {
    if (strcmp(cfg->servers[i].name, name) == 0) {
      return &cfg->servers[i];
    }
  }
  return NULL;
}

const siglatch_server *config_server_by_name(const char *name) {
  return config_server_by_name_from_ptr(_config, name);
}

static const siglatch_server *config_server_by_name_from(
    const siglatch_config *cfg,
    const char *name) {
  return config_server_by_name_from_ptr(cfg, name);
}

static int config_server_set_port(const char *name, int port) {
  siglatch_server *server = NULL;

  if (!_config || !name || name[0] == '\0') {
    return 0;
  }

  if (port <= 0 || port > 65535) {
    return 0;
  }

  server = (siglatch_server *)config_server_by_name_from_ptr(_config, name);
  if (!server) {
    return 0;
  }

  server->port = port;
  return 1;
}

static int config_server_set_binding(const char *name,
                                     const char *bind_ip,
                                     int port) {
  siglatch_server *server = NULL;

  if (!_config || !name || name[0] == '\0') {
    return 0;
  }

  if (port <= 0 || port > 65535) {
    return 0;
  }

  server = (siglatch_server *)config_server_by_name_from_ptr(_config, name);
  if (!server) {
    return 0;
  }

  if (bind_ip && bind_ip[0] != '\0' &&
      !lib.net.ip.range.is_single_ipv4(bind_ip)) {
    return 0;
  }

  server->port = port;
  if (bind_ip && bind_ip[0] != '\0') {
    lib.str.lcpy(server->bind_ip, bind_ip, sizeof(server->bind_ip));
  } else {
    server->bind_ip[0] = '\0';
  }

  return 1;
}


static const siglatch_deaddrop *config_deaddrop_starts_with_buffer(const uint8_t *payload, size_t payload_len) {
  if (!_config || !payload || payload_len == 0)
    return NULL;

  for (int i = 0; i < _config->deaddrop_count; ++i) {
    const siglatch_deaddrop *d = &_config->deaddrops[i];
    for (int j = 0; j < d->starts_with_count; ++j) {
      const char *prefix = d->starts_with[j];
      size_t prefix_len = strlen(prefix);

      if (prefix_len <= payload_len && memcmp(payload, prefix, prefix_len) == 0) {
        return d;
      }
    }
  }

  return NULL;
}
static void config_apply_defaults(siglatch_config *config) {
  if (!config) {
    return;
  }

  config->master_privkey = NULL;
  lib.str.lcpy(config->priv_key_path, "/etc/siglatch/server_priv.pem", PATH_MAX);
  config->payload_overflow = SL_PAYLOAD_OVERFLOW_REJECT;
}

static siglatch_user *config_append_user(siglatch_config *config, const char *name) {
  siglatch_user *user = NULL;

  if (!config || !name) {
    return NULL;
  }

  if (config->user_count >= MAX_USERS) {
    LOGW("Too many [user:*] sections; ignoring '%s'\n", name);
    return NULL;
  }

  user = &config->users[config->user_count++];
  lib.str.lcpy(user->name, name, sizeof(user->name));
  user->pubkey = NULL;
  return user;
}

static siglatch_action *config_append_action(siglatch_config *config, const char *name) {
  siglatch_action *action = NULL;

  if (!config || !name) {
    return NULL;
  }

  if (config->action_count >= MAX_ACTIONS) {
    LOGW("Too many [action:*] sections; ignoring '%s'\n", name);
    return NULL;
  }

  action = &config->actions[config->action_count++];
  lib.str.lcpy(action->name, name, sizeof(action->name));
  action->handler = SL_ACTION_HANDLER_SHELL;
  action->exec_split = 1;
  action->enabled = 1;
  action->require_ascii = 0;
  action->payload_overflow = SL_PAYLOAD_OVERFLOW_INHERIT;
  return action;
}

static siglatch_server *config_append_server(siglatch_config *config, const char *name) {
  siglatch_server *server = NULL;

  if (!config || !name) {
    return NULL;
  }

  if (config->server_count >= MAX_SERVERS) {
    LOGW("Too many [server:*] sections; ignoring '%s'\n", name);
    return NULL;
  }

  server = &config->servers[config->server_count++];
  lib.str.lcpy(server->name, name, sizeof(server->name));
  lib.str.lcpy(server->label, server->name, sizeof(server->label));
  server->payload_overflow = SL_PAYLOAD_OVERFLOW_INHERIT;
  return server;
}

static siglatch_deaddrop *config_append_deaddrop(siglatch_config *config, const char *name) {
  siglatch_deaddrop *deaddrop = NULL;

  if (!config || !name) {
    return NULL;
  }

  if (config->deaddrop_count >= MAX_DEADDROPS) {
    LOGW("Too many [deaddrop:*] sections; ignoring '%s'\n", name);
    return NULL;
  }

  deaddrop = &config->deaddrops[config->deaddrop_count++];
  lib.str.lcpy(deaddrop->name, name, sizeof(deaddrop->name));
  lib.str.lcpy(deaddrop->label, deaddrop->name, sizeof(deaddrop->label));
  deaddrop->enabled = 1;
  deaddrop->require_ascii = 0;
  deaddrop->exec_split = 1;
  return deaddrop;
}

static void config_consume_global_entry(siglatch_config *config, const IniEntry *entry) {
  const char *key = entry ? entry->key : NULL;
  const char *val = entry ? entry->value : NULL;

  if (!config || !key || !val) {
    return;
  }

  if (strcmp(key, "priv_key_path") == 0) {
    lib.str.lcpy(config->priv_key_path, val, PATH_MAX);
  } else if (strcmp(key, "port") == 0) {
    /* reserved */
  } else if (strcmp(key, "default_server") == 0) {
    lib.str.lcpy(config->default_server, val, MAX_SERVER_NAME);
  } else if (strcmp(key, "log_file") == 0) {
    lib.str.lcpy(config->log_file, val, PATH_MAX);
  } else if (strcmp(key, "output_mode") == 0) {
    config->output_mode = parse_output_mode_key(val, "[global]");
  } else if (strcmp(key, "payload_overflow") == 0) {
    config->payload_overflow = parse_payload_overflow_key(
        val, "[global]", 0, config->payload_overflow);
  }
}

static void config_consume_action_entry(siglatch_action *action, const IniEntry *entry) {
  const char *key = entry ? entry->key : NULL;
  const char *val = entry ? entry->value : NULL;

  if (!action || !key || !val) {
    return;
  }

  if (strcmp(key, "constructor") == 0) {
    lib.str.lcpy(action->constructor, val, PATH_MAX);
  } else if (strcmp(key, "handler") == 0) {
    action->handler = parse_action_handler_key(val, action->name);
  } else if (strcmp(key, "builtin") == 0) {
    lib.str.lcpy(action->builtin, val, sizeof(action->builtin));
  } else if (strcmp(key, "destructor") == 0) {
    lib.str.lcpy(action->destructor, val, PATH_MAX);
  } else if (strcmp(key, "keepalive_interval") == 0) {
    action->keepalive_interval = atoi(val);
  } else if (strcmp(key, "id") == 0) {
    action->id = atoi(val);
  } else if (strcmp(key, "enabled") == 0) {
    action->enabled = 0;
    lib.str.to_bool(val, &action->enabled);
  } else if (strcmp(key, "require_ascii") == 0) {
    action->require_ascii = 0;
    lib.str.to_bool(val, &action->require_ascii);
  } else if (strcmp(key, "exec_split") == 0) {
    action->exec_split = 0;
    lib.str.to_bool(val, &action->exec_split);
  } else if (strcmp(key, "payload_overflow") == 0) {
    action->payload_overflow = parse_payload_overflow_key(
        val, action->name, 1, action->payload_overflow);
  } else if (strcmp(key, "allowed_ips") == 0) {
    lib.str.parse_csv_fixed(
        (char *)action->allowed_ips,
        &action->allowed_ip_count,
        MAX_IP_RANGES,
        MAX_IP_RANGE_LEN,
        val);
  }
}

static void config_consume_user_entry(siglatch_user *user, const IniEntry *entry) {
  const char *key = entry ? entry->key : NULL;
  const char *val = entry ? entry->value : NULL;

  if (!user || !key || !val) {
    return;
  }

  if (strcmp(key, "enabled") == 0) {
    user->enabled = 0;
    lib.str.to_bool(val, &user->enabled);
  } else if (strcmp(key, "key_file") == 0) {
    lib.str.lcpy(user->key_file, val, PATH_MAX);
  } else if (strcmp(key, "hmac_file") == 0) {
    lib.str.lcpy(user->hmac_file, val, PATH_MAX);
  } else if (strcmp(key, "id") == 0) {
    user->id = atoi(val);
  } else if (strcmp(key, "actions") == 0) {
    lib.str.parse_csv_fixed(
        (char *)user->actions,
        &user->action_count,
        MAX_ACTIONS,
        MAX_ACTION_NAME,
        val);
  } else if (strcmp(key, "allowed_ips") == 0) {
    lib.str.parse_csv_fixed(
        (char *)user->allowed_ips,
        &user->allowed_ip_count,
        MAX_IP_RANGES,
        MAX_IP_RANGE_LEN,
        val);
  }
}

static void config_consume_server_entry(siglatch_server *server, const IniEntry *entry) {
  const char *key = entry ? entry->key : NULL;
  const char *val = entry ? entry->value : NULL;

  if (!server || !key || !val) {
    return;
  }

  if (strcmp(key, "id") == 0) {
    server->id = atoi(val);
  } else if (strcmp(key, "enabled") == 0) {
    server->enabled = 0;
    lib.str.to_bool(val, &server->enabled);
  } else if (strcmp(key, "label") == 0) {
    lib.str.lcpy(server->label, val, MAX_SERVER_NAME);
  } else if (strcmp(key, "name") == 0) {
    lib.str.lcpy(server->label, val, MAX_SERVER_NAME);
    LOGW("Deprecated key 'name' in [server:%s]; use 'label' instead (server identity remains section label)\n",
         server->name);
  } else if (strcmp(key, "priv_key_path") == 0) {
    lib.str.lcpy(server->priv_key_path, val, PATH_MAX);
  } else if (strcmp(key, "log_file") == 0) {
    lib.str.lcpy(server->log_file, val, PATH_MAX);
  } else if (strcmp(key, "bind_ip") == 0) {
    lib.str.lcpy(server->bind_ip, val, sizeof(server->bind_ip));
  } else if (strcmp(key, "allowed_ips") == 0) {
    lib.str.parse_csv_fixed(
        (char *)server->allowed_ips,
        &server->allowed_ip_count,
        MAX_IP_RANGES,
        MAX_IP_RANGE_LEN,
        val);
  } else if (strcmp(key, "port") == 0) {
    server->port = atoi(val);
  } else if (strcmp(key, "secure") == 0) {
    server->secure = 0;
    lib.str.to_bool(val, &server->secure);
  } else if (strcmp(key, "logging") == 0) {
    server->logging = 0;
    lib.str.to_bool(val, &server->logging);
  } else if (strcmp(key, "output_mode") == 0) {
    server->output_mode = parse_output_mode_key(val, server->name);
  } else if (strcmp(key, "payload_overflow") == 0) {
    server->payload_overflow = parse_payload_overflow_key(
        val, server->name, 1, server->payload_overflow);
  } else if (strcmp(key, "actions") == 0) {
    lib.str.parse_csv_fixed(
        (char *)server->actions,
        &server->action_count,
        MAX_ACTIONS,
        MAX_ACTION_NAME,
        val);
  } else if (strcmp(key, "deaddrops") == 0) {
    lib.str.parse_csv_fixed(
        (char *)server->deaddrops,
        &server->deaddrop_count,
        MAX_ACTIONS,
        MAX_ACTION_NAME,
        val);
  } else {
    LOGW("Unknown key in [server:%s]: %s\n", server->name, key);
  }
}

static void config_consume_deaddrop_entry(siglatch_deaddrop *deaddrop, const IniEntry *entry) {
  const char *key = entry ? entry->key : NULL;
  const char *val = entry ? entry->value : NULL;

  if (!deaddrop || !key || !val) {
    return;
  }

  if (strcmp(key, "id") == 0) {
    deaddrop->id = atoi(val);
  } else if (strcmp(key, "label") == 0) {
    lib.str.lcpy(deaddrop->label, val, MAX_DEADDROP_NAME);
  } else if (strcmp(key, "name") == 0) {
    lib.str.lcpy(deaddrop->label, val, MAX_DEADDROP_NAME);
    LOGW("Deprecated key 'name' in [deaddrop:%s]; use 'label' instead (deaddrop identity remains section label)\n",
         deaddrop->name);
  } else if (strcmp(key, "constructor") == 0) {
    lib.str.lcpy(deaddrop->constructor, val, MAX_PATH_LEN);
  } else if (strcmp(key, "filter") == 0 || strcmp(key, "filters") == 0) {
    lib.str.parse_csv_fixed(
        (char *)deaddrop->filters,
        &deaddrop->filter_count,
        MAX_FILTERS,
        MAX_FILTER_LEN,
        val);
  } else if (strcmp(key, "starts_with") == 0) {
    lib.str.parse_csv_fixed(
        (char *)deaddrop->starts_with,
        &deaddrop->starts_with_count,
        MAX_FILTERS,
        MAX_FILTER_LEN,
        val);
  } else if (strcmp(key, "enabled") == 0) {
    deaddrop->enabled = 0;
    lib.str.to_bool(val, &deaddrop->enabled);
  } else if (strcmp(key, "require_ascii") == 0) {
    deaddrop->require_ascii = 0;
    lib.str.to_bool(val, &deaddrop->require_ascii);
  } else if (strcmp(key, "exec_split") == 0) {
    deaddrop->exec_split = 0;
    lib.str.to_bool(val, &deaddrop->exec_split);
  }
}

static siglatch_config *config_consume_document_ptr(const IniDocument *document) {
  siglatch_config *config = NULL;
  size_t i = 0;

  if (!document) {
    return NULL;
  }

  config = calloc(1, sizeof(*config));
  if (!config) {
    return NULL;
  }

  config_apply_defaults(config);

  for (i = 0; i < document->global.entry_count; ++i) {
    config_consume_global_entry(config, &document->global.entries[i]);
  }

  for (i = 0; i < document->section_count; ++i) {
    const IniSection *section = &document->sections[i];
    size_t j = 0;

    if (!section->name) {
      continue;
    }

    if (strncmp(section->name, "user:", 5) == 0) {
      siglatch_user *user = config_append_user(config, section->name + 5);
      if (!user) {
        continue;
      }

      for (j = 0; j < section->entry_count; ++j) {
        config_consume_user_entry(user, &section->entries[j]);
      }
      continue;
    }

    if (strncmp(section->name, "action:", 7) == 0) {
      siglatch_action *action = config_append_action(config, section->name + 7);
      if (!action) {
        continue;
      }

      for (j = 0; j < section->entry_count; ++j) {
        config_consume_action_entry(action, &section->entries[j]);
      }
      continue;
    }

    if (strncmp(section->name, "server:", 7) == 0) {
      siglatch_server *server = config_append_server(config, section->name + 7);
      if (!server) {
        continue;
      }

      for (j = 0; j < section->entry_count; ++j) {
        config_consume_server_entry(server, &section->entries[j]);
      }
      continue;
    }

    if (strncmp(section->name, "deaddrop:", 9) == 0) {
      siglatch_deaddrop *deaddrop = config_append_deaddrop(config, section->name + 9);
      if (!deaddrop) {
        continue;
      }

      for (j = 0; j < section->entry_count; ++j) {
        config_consume_deaddrop_entry(deaddrop, &section->entries[j]);
      }
      continue;
    }

    LOGW("Unknown config section [%s]\n", section->name);
  }

  if (!validate_unique_server_names(config)) {
    config_free(config);
    return NULL;
  }

  if (!validate_action_handlers(config)) {
    config_free(config);
    return NULL;
  }

  if (!validate_ip_constraints(config)) {
    config_free(config);
    return NULL;
  }

  apply_server_runtime_defaults(config);

  return config;
}

static void config_unload(void){
  siglatch_config *config = config_detach();
  config_free(config);
  
}

static void config_destroy(siglatch_config *config) {
  config_free(config);
}

static void config_free(siglatch_config *config) {
    if (!config) return;
    if (config->master_privkey) {
      EVP_PKEY_free(config->master_privkey);
      config->master_privkey = NULL;
    }
    // Free each user's loaded EVP_PKEY (if used)
    for (int i = 0; i < config->user_count; ++i) {
        siglatch_user *u = &config->users[i];
        if (u->pubkey) {
            EVP_PKEY_free(u->pubkey);
            u->pubkey = NULL;
        }
    }

    // Free the server keys
    for (int i = 0; i < config->server_count; ++i) {
      siglatch_server *s = &config->servers[i];
      if (!s->key_owned) continue;
      if (s->priv_key) {
        EVP_PKEY_free(s->priv_key);
        s->priv_key = NULL;
      }
    }
    free(config);
}



static const ConfigLib config_instance = {
  .init = config_init,
  .shutdown = config_shutdown,

  .load = config_load,
  .load_detached = config_load_detached,
  .consume = config_consume,
  .unload = config_unload,
  .detach = config_detach,
  .attach = config_attach,
  .destroy = config_destroy,
  .get = config_get,

  .set_context = config_set_context,

  .dump = config_debug_dump,
  .dump_ptr = config_debug_dump_ptr,
  .deaddrop_starts_with_buffer = config_deaddrop_starts_with_buffer,
  .user_by_id = config_user_by_id,
  .user_by_id_from = config_user_by_id_from,
  .action_by_id = config_action_by_id,
  .action_by_id_from = config_action_by_id_from,
  .action_available_by_user = config_action_available_by_user, 
  .server_by_name = config_server_by_name,
  .server_by_name_from = config_server_by_name_from,
  .server_set_port = config_server_set_port,
  .server_set_binding = config_server_set_binding,
  .deaddrop_by_name = config_deaddrop_by_name,
  .deaddrop_by_name_from = config_deaddrop_by_name_from,
  .username_by_id = config_username_by_id,
};

const ConfigLib *get_app_config_lib(void) {
  return &config_instance;
}
