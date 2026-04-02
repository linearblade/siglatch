/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SERVER_APP_INBOUND_CRYPTO_H
#define SIGLATCH_SERVER_APP_INBOUND_CRYPTO_H

#include "../../config/config.h"
#include "../../daemon/connection.h"
#include "../../../../stdlib/openssl/session/session.h"

typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
  int (*init_session_for_server)(
      const siglatch_server *server,
      SiglatchOpenSSLSession *session);
  int (*assign_session_to_user)(
      SiglatchOpenSSLSession *session,
      const siglatch_user *user);
  int (*validate_signature)(
      const SiglatchOpenSSLSession *session,
      const AppConnectionJob *job);
} AppInboundCryptoLib;

int app_inbound_crypto_init(void);
void app_inbound_crypto_shutdown(void);
int app_inbound_crypto_init_session_for_server(
    const siglatch_server *server,
    SiglatchOpenSSLSession *session);
int app_inbound_crypto_assign_session_to_user(
    SiglatchOpenSSLSession *session,
    const siglatch_user *user);
int app_inbound_crypto_validate_signature(
    const SiglatchOpenSSLSession *session,
    const AppConnectionJob *job);

#endif
