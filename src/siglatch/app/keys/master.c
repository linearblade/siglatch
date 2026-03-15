/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include <stdio.h>
#include <openssl/pem.h>

#include "master.h"
#include "../../lib.h"

int app_keys_master_init(void) {
  return 1;
}

void app_keys_master_shutdown(void) {
}

int app_keys_master_load(siglatch_config *cfg) {
  FILE *fp = NULL;

  if (!cfg) {
    return 0;
  }

  if (cfg->priv_key_path[0] == '\0') {
    LOGD("Default master private key (EVP) skipped in master config\n");
    return 1;
  }

  fp = fopen(cfg->priv_key_path, "r");
  if (!fp) {
    LOGE("Could not open master private key: %s\n", cfg->priv_key_path);
    return 0;
  }

  cfg->master_privkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
  fclose(fp);

  if (!cfg->master_privkey) {
    LOGE("Invalid private key format in: %s\n", cfg->priv_key_path);
    return 0;
  }

  return 1;
}
