/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include "config.h"
#include "lib.h"
int load_user_keys(siglatch_config *cfg) {
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

        // Optional: store pkey or fingerprint
        EVP_PKEY_free(pkey);

        LOGD("✅ Loaded and validated RSA public key for user '%s' (EVP)\n", u->name);
    }
    return 1;
}
