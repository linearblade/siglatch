#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include "config.h"
#include "lib.h"

#define TIMEOUT_SEC 5

static void config_free(siglatch_config *config);
static void config_dump_ptr(const siglatch_config *cfg) ;
static siglatch_config *_load_config(const char *path) ;

static int load_user_hmac_keys(siglatch_config *cfg) ;
static int load_server_keys(siglatch_config *cfg) ;
static int load_user_keys(siglatch_config *cfg) ;
static int load_master_key(siglatch_config *cfg);

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

// Trim leading and trailing whitespace
static char *trim(char *str) {
  char *end;

  // Trim leading space
  while (isspace((unsigned char)*str)) str++;

  if (*str == 0) return str; // all spaces

  // Trim trailing space
  end = str + strlen(str) - 1;
  while (end > str && isspace((unsigned char)*end)) end--;

  // Write new null terminator
  *(end + 1) = 0;
  return str;
}

static int config_load(const char *path) {
  siglatch_config *cfg = _load_config(path);  // assumes malloc + fully parsed
  if (cfg) {
    config_attach(cfg);  // takes ownership, frees any prior
    return 1;
  }
  return 0;
}

const siglatch_user *config_user_by_id( uint32_t user_id) {
    if (!_config) return NULL;

    for (int i = 0; i < _config->user_count; ++i) {
        const siglatch_user *u = &_config->users[i];
        if (u->enabled && u->id == user_id) {
            return u;
        }
    }

    return NULL;  // Not found
}

const char * config_username_by_id(uint32_t user_id){
  const siglatch_user * u = config_user_by_id(user_id);
  return u && u->name[0] != '\0'?
    u->name:
    NULL;
}

const siglatch_action * config_action_by_id(uint32_t action_id){
  if (!_config) return NULL;
  
  for (int i = 0; i < _config->action_count; ++i) {
    if (_config->actions[i].id == action_id) {
      return &_config->actions[i];
    }
  }
  return NULL;
}


const siglatch_deaddrop *config_deaddrop_by_name(const char *name) {
  if (!_config || !name) return NULL;

  for (int i = 0; i < _config->deaddrop_count; ++i) {
    if (strcmp(_config->deaddrops[i].name, name) == 0) {
      return &_config->deaddrops[i];
    }
  }
  return NULL;
}

const siglatch_server *config_server_by_name(const char *name) {
  if (!_config || !name) return NULL;

  for (int i = 0; i < _config->server_count; ++i) {
    if (strcmp(_config->servers[i].name, name) == 0) {
      return &_config->servers[i];
    }
  }
  return NULL;
}



const siglatch_server * config_set_current_server(const char * name){
  if (!_config || !name)
    return NULL;

  const siglatch_server * current = config_server_by_name(name);
  if(!current)
    return NULL;
  _config->current_server = (siglatch_server *)current;
  return _config->current_server;
}
const siglatch_server * config_get_current_server(void){
  if (!_config)
    return NULL;
  if (!_config->current_server)
    return NULL;
  return _config->current_server;
}


static int config_current_server_action_available(const char *action_name) {
  if (!_config || !_config->current_server || !action_name)
    return 0;

  const siglatch_server *s = _config->current_server;
  for (int i = 0; i < s->action_count; ++i) {
    if (strcmp(s->actions[i], action_name) == 0)
      return 1;
  }
  return 0;
}

static int config_current_server_deaddrop_available(const char *deaddrop_name) {
  if (!_config || !_config->current_server || !deaddrop_name)
    return 0;

  const siglatch_server *s = _config->current_server;
  for (int i = 0; i < s->deaddrop_count; ++i) {
    if (strcmp(s->deaddrops[i], deaddrop_name) == 0)
      return 1;
  }
  return 0;
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



static const siglatch_deaddrop *config_current_server_deaddrop_starts_with_buffer(
    const uint8_t *payload, size_t payload_len,
    char *match, int match_buf_size,
    size_t *matched_prefix_len)
{
  if (!_config || !_config->current_server || !payload || payload_len == 0)
    return NULL;

  const siglatch_server *s = _config->current_server;

  for (int i = 0; i < s->deaddrop_count; ++i) {
    const char *allowed = s->deaddrops[i];
    const siglatch_deaddrop *d = config_deaddrop_by_name(allowed);
    if (!d || !d->enabled)
      continue;

    for (int j = 0; j < d->starts_with_count; ++j) {
      const char *prefix = d->starts_with[j];
      size_t prefix_len = strlen(prefix);

      if (prefix_len <= payload_len && memcmp(payload, prefix, prefix_len) == 0) {
        // Optional: copy matched prefix
        if (match && match_buf_size > 0) {
          snprintf(match, match_buf_size, "%s", prefix);
        }
        if (matched_prefix_len) {
          *matched_prefix_len = prefix_len;
        }
        return d;
      }
    }
  }

  return NULL;
}
/*
static const siglatch_deaddrop *config_current_server_deaddrop_starts_with_buffer(const uint8_t *payload, size_t payload_len,char * match, int match_len) {
  if (!_config || !_config->current_server || !payload || payload_len == 0)
    return NULL;

  const siglatch_server *s = _config->current_server;

  for (int i = 0; i < s->deaddrop_count; ++i) {
    const char *allowed = s->deaddrops[i];
    const siglatch_deaddrop *d = config_deaddrop_by_name(allowed);
    if (!d || !d->enabled)
      continue;

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
*/
typedef enum {
  CFG_BLOCK_NONE,
  CFG_BLOCK_USER,
  CFG_BLOCK_ACTION,
  CFG_BLOCK_SERVER,
  CFG_BLOCK_DEADDROP
} config_block_type;

static siglatch_config *_load_config(const char *path) {
  FILE *fp = fopen(path, "r");
  if (!fp) {
    LOGPERR("fopen");
    return NULL;
  }

  siglatch_config *config = calloc(1, sizeof(siglatch_config));
  config->master_privkey = NULL;
  if (!config) {
    fclose(fp);
    return NULL;
  }

  // Set defaults
  strncpy(config->priv_key_path, "/etc/siglatch/server_priv.pem", PATH_MAX);
  //config->port = 50000;

  char line[512];
  config_block_type current_block = CFG_BLOCK_NONE;
  siglatch_user *current_user = NULL;
  siglatch_action *current_action = NULL;
  siglatch_server *current_server = NULL;
  siglatch_deaddrop *current_deaddrop = NULL;

  while (fgets(line, sizeof(line), fp)) {
    char *trimmed = trim(line);
    if (trimmed[0] == '#' || trimmed[0] == '\0') continue;

    if (strncmp(trimmed, "[user:", 6) == 0) {
      if (config->user_count >= MAX_USERS) continue;
      current_block = CFG_BLOCK_USER;
      current_user = &config->users[config->user_count++];
      sscanf(trimmed, "[user:%63[^]]", current_user->name);
      current_user->pubkey = NULL;
      continue;
    }

    if (strncmp(trimmed, "[action:", 8) == 0) {
      if (config->action_count >= MAX_ACTIONS) continue;
      current_block = CFG_BLOCK_ACTION;
      current_action = &config->actions[config->action_count++];
      sscanf(trimmed, "[action:%31[^]]", current_action->name);
      current_action->exec_split = 1;
      current_action->enabled = 1;
      current_action->require_ascii = 0;
      current_action->exec_split = 1;

      continue;
    }

    if (strncmp(trimmed, "[server:", 8) == 0) {
      if (config->server_count >= MAX_SERVERS) continue;
      current_block = CFG_BLOCK_SERVER;
      current_server = &config->servers[config->server_count++];
      sscanf(trimmed, "[server:%63[^]]", current_server->name);
      continue;
    }

    if (strncmp(trimmed, "[deaddrop:", 10) == 0) {
      if (config->deaddrop_count >= MAX_DEADDROPS) continue;
      current_block = CFG_BLOCK_DEADDROP;
      current_deaddrop = &config->deaddrops[config->deaddrop_count++];
      sscanf(trimmed, "[deaddrop:%63[^]]", current_deaddrop->name);
      current_deaddrop->enabled = 1;
      current_deaddrop->require_ascii = 0;
      current_deaddrop->exec_split = 1;
      continue;
    }
    
    char *eq = strchr(trimmed, '=');
    if (!eq) continue;
    *eq = '\0';
    char *key = trim(trimmed);
    char *val = trim(eq + 1);

    switch (current_block) {
    case CFG_BLOCK_NONE:
      if (strcmp(key, "priv_key_path") == 0) {
	strncpy(config->priv_key_path, val, PATH_MAX);
      } else if (strcmp(key, "port") == 0) {
	//config->port = atoi(val);
      } else if (strcmp(key, "log_file") == 0) {
	strncpy(config->log_file, val, PATH_MAX);
      }
      break;
    case CFG_BLOCK_ACTION:
      if (strcmp(key, "constructor") == 0) {
	strncpy(current_action->constructor, val, PATH_MAX);
      } else if (strcmp(key, "destructor") == 0) {
	strncpy(current_action->destructor, val, PATH_MAX);
      } else if (strcmp(key, "keepalive_interval") == 0) {
	current_action->keepalive_interval = atoi(val);
      } else if (strcmp(key, "id") == 0) {
	current_action->id = atoi(val);
      }else if (strcmp(key, "enabled") == 0) {
	current_action->enabled = (strcmp(val, "yes") == 0 || strcmp(val, "1") == 0);
      }else if (strcmp(key, "require_ascii") == 0) {
	current_action->require_ascii = (strcmp(val, "yes") == 0 || strcmp(val, "1") == 0);
      }else if (strcmp(key, "exec_split") == 0) {
	current_action->exec_split = (strcmp(val, "yes") == 0 || strcmp(val, "1") == 0);
      }
      break;
    case CFG_BLOCK_USER:

      if (strcmp(key, "enabled") == 0) {
	current_user->enabled = (strcmp(val, "yes") == 0 || strcmp(val, "1") == 0);
      } else if (strcmp(key, "key_file") == 0) {
	strncpy(current_user->key_file, val, PATH_MAX);
      } else if (strcmp(key, "hmac_file") == 0) {
	strncpy(current_user->hmac_file, val, PATH_MAX);
      } else if (strcmp(key, "id") == 0) {
	current_user->id = atoi(val);
      } else if (strcmp(key, "actions") == 0) {
	char *tok = strtok(val, ",");
	while (tok && current_user->action_count < MAX_ACTIONS) {
	  strncpy(current_user->actions[current_user->action_count++],
		  trim(tok), MAX_ACTION_NAME);
	  tok = strtok(NULL, ",");
	}
      }
      break;
    case CFG_BLOCK_SERVER:
      if (!current_server) break;

      if (strcmp(key, "id") == 0) {
	current_server->id = atoi(val);
      }else if (strcmp(key, "enabled") == 0) {
	current_server->enabled = (strcmp(val, "yes") == 0 || strcmp(val, "1") == 0);
      } else if (strcmp(key, "name") == 0) {
	strncpy(current_server->name, val, MAX_SERVER_NAME);
      } else if (strcmp(key, "priv_key_path") == 0) {
	strncpy(current_server->priv_key_path, val, PATH_MAX);
      } else if (strcmp(key, "log_file") == 0) {
	strncpy(current_server->log_file, val, PATH_MAX);
      } else if (strcmp(key, "port") == 0) {
	current_server->port = atoi(val);
      } else if (strcmp(key, "secure") == 0) {
	current_server->secure = (strcmp(val, "yes") == 0 || strcmp(val, "1") == 0);
      } else if (strcmp(key, "logging") == 0) {
	current_server->logging = (strcmp(val, "yes") == 0 || strcmp(val, "1") == 0);
      } else if (strcmp(key, "actions") == 0) {
	char *tok = strtok(val, ",");
	while (tok && current_server->action_count < MAX_ACTIONS) {
	  strncpy(current_server->actions[current_server->action_count++],
		  trim(tok), MAX_ACTION_NAME);
	  tok = strtok(NULL, ",");
	}
      } else if (strcmp(key, "deaddrops") == 0) {
	char *tok = strtok(val, ",");
	while (tok && current_server->deaddrop_count < MAX_ACTIONS) {
	  strncpy(current_server->deaddrops[current_server->deaddrop_count++],
		  trim(tok), MAX_ACTION_NAME);
	  tok = strtok(NULL, ",");
	}
      }else {
	LOGW("⚠️  Unknown key in [server:%s]: %s\n", current_server->name, key);
      }
      break;
      
    case CFG_BLOCK_DEADDROP:
      if (!current_deaddrop) break;

      if (strcmp(key, "id") == 0) {
	current_deaddrop->id = atoi(val);
      } else if (strcmp(key, "name") == 0) {
	strncpy(current_deaddrop->name, val, MAX_DEADDROP_NAME);
      } else if (strcmp(key, "constructor") == 0) {
	strncpy(current_deaddrop->constructor, val, MAX_PATH_LEN);
      } else if (strcmp(key, "filter") == 0 || strcmp(key, "filters") == 0) {
	char *tok = strtok(val, ",");
	while (tok && current_deaddrop->filter_count < MAX_FILTERS) {
	  strncpy(current_deaddrop->filters[current_deaddrop->filter_count++],
		  trim(tok), MAX_FILTER_LEN);
	  tok = strtok(NULL, ",");
	}
      } else if (strcmp(key, "starts_with") == 0 || strcmp(key, "starts_with") == 0) {
	char *tok = strtok(val, ",");
	while (tok && current_deaddrop->starts_with_count < MAX_FILTERS) {
	  strncpy(current_deaddrop->starts_with[current_deaddrop->starts_with_count++],
		  trim(tok), MAX_FILTER_LEN);
	  tok = strtok(NULL, ",");
	}
      }else if (strcmp(key, "enabled") == 0) {
	current_deaddrop->enabled = (strcmp(val, "yes") == 0 || strcmp(val, "1") == 0);
      }else if (strcmp(key, "require_ascii") == 0) {
	current_deaddrop->require_ascii = (strcmp(val, "yes") == 0 || strcmp(val, "1") == 0);
      }else if (strcmp(key, "exec_split") == 0) {
	current_deaddrop->exec_split = (strcmp(val, "yes") == 0 || strcmp(val, "1") == 0);
      }


      break;
    }
  }

  fclose(fp);
  if (!load_master_key(config)) {
    config_free(config);
    return NULL;
  }

  if (!load_user_keys(config)) {
    LOGE("❌ Failed to load user keys\n" );
    config_free(config);
    return NULL;
  }
  if (!load_server_keys(config)) {
    LOGE("❌ Failed to server  keys\n" );
    config_free(config);
    return NULL;
  }

  if (!load_user_hmac_keys(config)) {
    LOGE("❌ Failed to load user HMAC keys\n" );
    config_free(config);
    return NULL;
  }
  
  return config;
}

/**
 * Load fallback master private key from the top-level config.
 * Only used if per-server keys are omitted or for legacy deployments.
 */

static int load_master_key(siglatch_config *cfg){
  if (cfg->priv_key_path[0] == '\0' ){
    LOGD("✅ default master private key (EVP) skipped in mater config\n");
  }else {
    FILE *fp = fopen(cfg->priv_key_path, "r");
    if (!fp) {
      LOGE( "❌ Could not open master private key: %s\n", cfg->priv_key_path);
      return 0;
    }

    cfg->master_privkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    if (!cfg->master_privkey) {
      LOGE( "❌ Invalid private key format in: %s\n", cfg->priv_key_path);
      return 0;
    }
  }
  return 1;
}


static int load_user_keys(siglatch_config *cfg) {
    for (int i = 0; i < cfg->user_count; ++i) {
        siglatch_user *u = &cfg->users[i];
        if (!u->enabled) continue;

        FILE *fp = fopen(u->key_file, "r");
        if (!fp) {
            LOGE( "❌ Failed to open key file for user '%s': %s\n", u->name, u->key_file);
            return 0;
        }

        EVP_PKEY *pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
        fclose(fp);

        if (!pkey) {
            LOGE( "❌ Invalid public key for user '%s' (%s)\n", u->name, u->key_file);
            return 0;
        }

        if (EVP_PKEY_base_id(pkey) != EVP_PKEY_RSA) {
            LOGE( "❌ Public key for user '%s' is not RSA\n", u->name);
            EVP_PKEY_free(pkey);
            return 0;
        }


	u->pubkey = pkey;  // don't free it yet
	//if your just fucking around and testing, uncomment.
        //EVP_PKEY_free(pkey);

        LOGD("✅ Loaded and validated RSA public key for user '%s' (EVP)\n", u->name);
    }
    return 1;
}

static int load_server_keys(siglatch_config *cfg) {
    for (int i = 0; i < cfg->server_count; ++i) {
        siglatch_server *s = &cfg->servers[i];
        if (!s->secure) continue;
        if (!s->enabled) continue;
	if (!s->port) s->port = 50000;
	// Log file fallback
        if (s->log_file[0] == '\0' && cfg->log_file[0] != '\0') {
            strncpy(s->log_file, cfg->log_file, PATH_MAX);
            LOGW("⚠️  Using fallback log file for server [%s]: %s\n", s->name, s->log_file);
        }

	// Optional: Emit this info even for insecure/disabled if needed:
        if (s->logging) {
	  LOGD("📝 Logging enabled for server [%s] to: %s\n", s->name,
	       s->log_file[0] ? s->log_file : "(none)");
        }
	
        if (s->priv_key_path[0] == '\0') {
            s->key_owned = 0;
            s->priv_key = cfg->master_privkey;
	    LOGW("⚠️  Using fallback master key for server [%s]\n", s->name);
        } else {
            FILE *fp = fopen(s->priv_key_path, "r");
            if (!fp) {
                LOGE("❌ Could not open private key for server [%s]: %s\n", s->name, s->priv_key_path);
                return 0;
            }

            s->priv_key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
            fclose(fp);
	    
            if (!s->priv_key) {
                LOGE("❌ Invalid private key format for server [%s]: %s\n", s->name, s->priv_key_path);
                return 0;
            }

            s->key_owned = 1;  // we now own this key and must free it
        }

        LOGD("✅ Loaded RSA private key for server [%s] (EVP)\n", s->name);
    }
    return 1;
}

static int load_user_hmac_keys(siglatch_config *cfg) {
    for (int i = 0; i < cfg->user_count; ++i) {
        siglatch_user *u = &cfg->users[i];
        if (!u->enabled) continue;

        FILE *fp = fopen(u->hmac_file, "rb");
        if (!fp) {
            LOGE("❌ Failed to open HMAC key file for user '%s': %s\n", u->name, u->hmac_file);
            return 0;
        }

        // Temporary buffer to read raw file contents
        uint8_t file_buf[128] = {0};  // more than enough room for hex or binary
        size_t bytes_read = fread(file_buf, 1, sizeof(file_buf), fp);
        fclose(fp);

        if (bytes_read != 32 && bytes_read != 64) {
            LOGE("❌ Invalid HMAC key file size for user '%s' (%s): read %zu bytes\n", u->name, u->hmac_file, bytes_read);
            return 0;
        }

        // Normalize the key (binary or hex) into user struct
        if (!lib.hmac.normalize(file_buf, bytes_read, u->hmac_key)) {
            LOGE("❌ Failed to normalize HMAC key for user '%s'\n", u->name);
            return 0;
        }

        LOGD("✅ Loaded and normalized HMAC key for user '%s'\n", u->name);
    }
    return 1;
}





static void config_unload(void){
  siglatch_config *config = config_detach();
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

    config->current_server = NULL;
    free(config);
}



static void config_dump(){
  if (!_config){
    lib.log.console("❌ No config to dump.\n");
    return;
  }
  config_dump_ptr(_config);
}

static void config_dump_ptr(const siglatch_config *cfg) { 
  if (!cfg){
    lib.log.console("❌ No config to dump.\n");
    return;
  }

    lib.log.console("🔐 siglatch config dump:\n\n");

    lib.log.console("  Master log file: %s\n", cfg->log_file);
    lib.log.console("  Private key path: %s\n", cfg->priv_key_path);
    if (cfg->master_privkey) {
        lib.log.console("  ✅ Master private key loaded from %s\n", cfg->priv_key_path);
    } else {
        lib.log.console("  ❌ Master private key not loaded\n");
    }

    lib.log.console("\n  Actions (%d):\n", cfg->action_count);
    for (int i = 0; i < cfg->action_count; ++i) {
        const siglatch_action *a = &cfg->actions[i];
        lib.log.console("    - [%s]\n", a->name);
        lib.log.console("      Constructor: %s\n", a->constructor);
        lib.log.console("      Destructor : %s\n", a->destructor);
        lib.log.console("      Keepalive  : %d\n", a->keepalive_interval);
	lib.log.console("      Enabled  : %s\n", a->enabled ? "yes" : "no");
	lib.log.console("      Require Ascii Message  : %s\n", a->require_ascii ? "yes" : "no");
	lib.log.console("      exec_split  : %s\n", a->exec_split ? "yes" : "no");

    }

    lib.log.console("\n  Users (%d):\n", cfg->user_count);
    for (int i = 0; i < cfg->user_count; ++i) {
        const siglatch_user *u = &cfg->users[i];
        lib.log.console("    - [%s]\n", u->name);
        lib.log.console("      Enabled : %s\n", u->enabled ? "yes" : "no");
        lib.log.console("      Key file: %s\n", u->key_file);
        if (u->pubkey) {
            lib.log.console("      ✅ User public key loaded from %s\n", u->key_file);
        } else {
            lib.log.console("      ❌ User public key not loaded\n");
        }

        lib.log.console("      HMAC file: %s\n", u->hmac_file);
        int all_zero = 1;
        for (int j = 0; j < sizeof(u->hmac_key); ++j) {
            if (u->hmac_key[j] != 0) {
                all_zero = 0;
                break;
            }
        }
        if (!all_zero) {
            lib.log.console("      ✅ HMAC key loaded from %s\n", u->hmac_file);
        } else {
            lib.log.console("      ❌ HMAC key not loaded\n");
        }

        lib.log.console("      Actions :\n");
        for (int j = 0; j < u->action_count; ++j) {
            lib.log.console("        - %s\n", u->actions[j]);
        }
        lib.log.console("\n");
    }

    lib.log.console("\n  Servers (%d):\n", cfg->server_count);
    for (int i = 0; i < cfg->server_count; ++i) {
        const siglatch_server *s = &cfg->servers[i];
        lib.log.console("    - [%s]\n", s->name);
        lib.log.console("      Enabled  : %s\n", s->enabled ? "yes" : "no");
        lib.log.console("      Secure   : %s\n", s->secure ? "yes" : "no");
        lib.log.console("      Port     : %d\n", s->port);
        lib.log.console("      Log file : %s\n", s->log_file[0] ? s->log_file : "(none)");

        lib.log.console("      Private key: %s\n", s->priv_key_path[0] ? s->priv_key_path : "(inherited)");
        if (s->priv_key) {
            lib.log.console("      ✅ Private key loaded (owned: %s)\n", s->key_owned ? "yes" : "no");
        } else {
            lib.log.console("      ❌ Private key not loaded\n");
        }

        lib.log.console("      Actions:\n");
        for (int j = 0; j < s->action_count; ++j) {
            lib.log.console("        - %s\n", s->actions[j]);
        }

        lib.log.console("      Deaddrops:\n");
        for (int j = 0; j < s->deaddrop_count; ++j) {
            lib.log.console("        - %s\n", s->deaddrops[j]);
        }

        lib.log.console("\n");
    }

    lib.log.console("  Deaddrops (%d):\n", cfg->deaddrop_count);
    for (int i = 0; i < cfg->deaddrop_count; ++i) {
        const siglatch_deaddrop *d = &cfg->deaddrops[i];
        lib.log.console("    - [%s]\n", d->name);
	lib.log.console("      Enabled  : %s\n", d->enabled ? "yes" : "no");
	lib.log.console("      Require Ascii Message  : %s\n", d->require_ascii ? "yes" : "no");
	lib.log.console("      exec_split  : %s\n", d->exec_split ? "yes" : "no");
        lib.log.console("      Constructor: %s\n", d->constructor);
        lib.log.console("      Filters:\n");
        for (int j = 0; j < d->filter_count; ++j) {
            lib.log.console("        - %s\n", d->filters[j]);
        }
        lib.log.console("      Starts With:\n");
        for (int j = 0; j < d->starts_with_count; ++j) {
            lib.log.console("        - %s\n", d->starts_with[j]);
        }
    }

    lib.log.console("\n");
}












static const ConfigLib config_instance = {
  .init = config_init,
  .shutdown = config_shutdown,

  .load = config_load,
  .unload = config_unload,
  .detach = config_detach,
  .attach = config_attach,
  .get = config_get,

  .set_context = config_set_context,

  .dump = config_dump,
  .dump_ptr = config_dump_ptr,
  .set_current_server = config_set_current_server,
  .get_current_server = config_get_current_server,
  .current_server_action_available = config_current_server_action_available,
  .current_server_deaddrop_available = config_current_server_deaddrop_available,
  .deaddrop_starts_with_buffer = config_deaddrop_starts_with_buffer,
  .current_server_deaddrop_starts_with_buffer = config_current_server_deaddrop_starts_with_buffer,
  .user_by_id = config_user_by_id,
  .action_by_id = config_action_by_id,
  .server_by_name = config_server_by_name,
  .deaddrop_by_name = config_deaddrop_by_name,
  .username_by_id = config_username_by_id,
};

const ConfigLib *get_lib_config(void) {
  return &config_instance;
}

