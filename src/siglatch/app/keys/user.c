/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include <stdio.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

#include "user.h"
#include "../../lib.h"

int app_keys_user_init(void) {
  return 1;
}

void app_keys_user_shutdown(void) {
}

int app_keys_user_load_all(siglatch_config *cfg) {
  int i = 0;

  if (!cfg) {
    return 0;
  }

  for (i = 0; i < cfg->user_count; ++i) {
    FILE *fp = NULL;
    EVP_PKEY *pkey = NULL;
    siglatch_user *u = &cfg->users[i];

    if (!u->enabled) {
      continue;
    }

    fp = fopen(u->key_file, "r");
    if (!fp) {
      LOGE("Failed to open key file for user '%s': %s\n", u->name, u->key_file);
      return 0;
    }

    pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);

    if (!pkey) {
      LOGE("Invalid public key for user '%s' (%s)\n", u->name, u->key_file);
      return 0;
    }

    if (EVP_PKEY_base_id(pkey) != EVP_PKEY_RSA) {
      LOGE("Public key for user '%s' is not RSA\n", u->name);
      EVP_PKEY_free(pkey);
      return 0;
    }

    u->pubkey = pkey;
    LOGD("Loaded and validated RSA public key for user '%s' (EVP)\n", u->name);
  }

  return 1;
}
