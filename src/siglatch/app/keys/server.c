/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include <stdio.h>
#include <openssl/pem.h>

#include "server.h"
#include "../../lib.h"

int app_keys_server_init(void) {
  return 1;
}

void app_keys_server_shutdown(void) {
}

int app_keys_server_load_all(siglatch_config *cfg) {
  int i = 0;

  if (!cfg) {
    return 0;
  }

  for (i = 0; i < cfg->server_count; ++i) {
    FILE *fp = NULL;
    siglatch_server *s = &cfg->servers[i];

    if (!s->secure) {
      continue;
    }

    if (!s->enabled) {
      continue;
    }

    if (s->logging) {
      LOGD("Logging enabled for server [%s] to: %s\n",
           s->name,
           s->log_file[0] ? s->log_file : "(none)");
    }

    if (s->priv_key_path[0] == '\0') {
      s->key_owned = 0;
      s->priv_key = cfg->master_privkey;
      LOGW("Using fallback master key for server [%s]\n", s->name);
      LOGD("Loaded RSA private key for server [%s] (EVP)\n", s->name);
      continue;
    }

    fp = fopen(s->priv_key_path, "r");
    if (!fp) {
      LOGE("Could not open private key for server [%s]: %s\n", s->name, s->priv_key_path);
      return 0;
    }

    s->priv_key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    if (!s->priv_key) {
      LOGE("Invalid private key format for server [%s]: %s\n", s->name, s->priv_key_path);
      return 0;
    }

    s->key_owned = 1;
    LOGD("Loaded RSA private key for server [%s] (EVP)\n", s->name);
  }

  return 1;
}
