/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SHARED_KNOCK_CODEC2_CONTEXT_H
#define SIGLATCH_SHARED_KNOCK_CODEC2_CONTEXT_H

#include <stddef.h>
#include <stdint.h>

#include <openssl/evp.h>

typedef struct SiglatchOpenSSLSession SiglatchOpenSSLSession;

/*
 * Read-only codec configuration snapshot.
 *
 * Siglatch owns the storage for this object and may refresh it on config
 * reloads. Codecs borrow the pointer and use it for key selection, nonce
 * policy, and decrypt/verify setup.
 *
 * This snapshot carries codec-facing policy and borrowed runtime handles that
 * the codec layer needs to serialize and decrypt packets. The borrowed
 * SiglatchOpenSSLSession pointer is not owned here; it is installed by the
 * host when a runner has an active session.
 */
typedef struct SharedKnockCodecKeyEntry {
  uint32_t user_id;
  const char *name;
  EVP_PKEY *public_key;
  EVP_PKEY *private_key;
  const uint8_t *hmac_key;
  size_t hmac_key_len;
  uint32_t flags;
} SharedKnockCodecKeyEntry;

typedef struct SharedKnockCodecServerKey {
  const char *name;
  EVP_PKEY *public_key;
  EVP_PKEY *private_key;
  const uint8_t *hmac_key;
  size_t hmac_key_len;
  uint32_t flags;
} SharedKnockCodecServerKey;

typedef struct SharedKnockCodecContext {
  SharedKnockCodecServerKey server_key;
  int has_server_key;
  int server_secure;
  SiglatchOpenSSLSession *openssl_session;

  SharedKnockCodecKeyEntry *keychain;
  size_t keychain_len;
  size_t keychain_cap;
  const char *active_key_name;
  uint64_t nonce_window_ms;
  uint32_t flags;
} SharedKnockCodecContext;

typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
  int (*create)(SharedKnockCodecContext **out_context);
  void (*destroy)(SharedKnockCodecContext *context);
  int (*set_server_key)(SharedKnockCodecContext *context, const SharedKnockCodecServerKey *server_key);
  void (*clear_server_key)(SharedKnockCodecContext *context);
  int (*set_openssl_session)(SharedKnockCodecContext *context,
                             SiglatchOpenSSLSession *session);
  void (*clear_openssl_session)(SharedKnockCodecContext *context);
  int (*add_keychain)(SharedKnockCodecContext *context, const SharedKnockCodecKeyEntry *entry);
  int (*remove_keychain)(SharedKnockCodecContext *context, const char *name);
} SharedKnockCodecContextLib;

int shared_knock_codec_context_init(void);
void shared_knock_codec_context_shutdown(void);
int shared_knock_codec_context_create(SharedKnockCodecContext **out_context);
void shared_knock_codec_context_destroy(SharedKnockCodecContext *context);
int shared_knock_codec_context_set_server_key(SharedKnockCodecContext *context,
                                              const SharedKnockCodecServerKey *server_key);
void shared_knock_codec_context_clear_server_key(SharedKnockCodecContext *context);
int shared_knock_codec_context_set_openssl_session(SharedKnockCodecContext *context,
                                                   SiglatchOpenSSLSession *session);
void shared_knock_codec_context_clear_openssl_session(SharedKnockCodecContext *context);
int shared_knock_codec_context_add_keychain(SharedKnockCodecContext *context,
                                            const SharedKnockCodecKeyEntry *entry);
int shared_knock_codec_context_remove_keychain(SharedKnockCodecContext *context,
                                               const char *name);
const SharedKnockCodecContextLib *get_shared_knock_codec_context_lib(void);

#endif /* SIGLATCH_SHARED_KNOCK_CODEC2_CONTEXT_H */
