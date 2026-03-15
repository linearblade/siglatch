/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include <stdio.h>

#include "hmac.h"
#include "../../lib.h"

int app_keys_hmac_init(void) {
  return 1;
}

void app_keys_hmac_shutdown(void) {
}

int app_keys_hmac_load_all(siglatch_config *cfg) {
  int i = 0;

  if (!cfg) {
    return 0;
  }

  for (i = 0; i < cfg->user_count; ++i) {
    FILE *fp = NULL;
    uint8_t file_buf[128] = {0};
    size_t bytes_read = 0;
    siglatch_user *u = &cfg->users[i];

    if (!u->enabled) {
      continue;
    }

    fp = fopen(u->hmac_file, "rb");
    if (!fp) {
      LOGE("Failed to open HMAC key file for user '%s': %s\n", u->name, u->hmac_file);
      return 0;
    }

    bytes_read = fread(file_buf, 1, sizeof(file_buf), fp);
    fclose(fp);

    if (bytes_read != 32 && bytes_read == sizeof(file_buf)) {
      LOGE("Invalid HMAC key file size for user '%s' (%s): read %zu bytes\n",
           u->name,
           u->hmac_file,
           bytes_read);
      return 0;
    }

    if (!lib.hmac.normalize(file_buf, bytes_read, u->hmac_key)) {
      LOGE("Failed to normalize HMAC key for user '%s'\n", u->name);
      return 0;
    }

    LOGD("Loaded and normalized HMAC key for user '%s'\n", u->name);
  }

  return 1;
}
