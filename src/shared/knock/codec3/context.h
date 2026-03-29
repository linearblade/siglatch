/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SHARED_KNOCK_CODEC3_CONTEXT_H
#define SIGLATCH_SHARED_KNOCK_CODEC3_CONTEXT_H

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
typedef struct SharedKnockCodec3KeyEntry {
  uint32_t user_id;
  const char *name;
  EVP_PKEY *public_key;
  EVP_PKEY *private_key;
  const uint8_t *hmac_key;
  size_t hmac_key_len;
  uint32_t flags;
} SharedKnockCodec3KeyEntry;

typedef struct SharedKnockCodec3ServerKey {
  const char *name;
  EVP_PKEY *public_key;
  EVP_PKEY *private_key;
  const uint8_t *hmac_key;
  size_t hmac_key_len;
  uint32_t flags;
} SharedKnockCodec3ServerKey;

typedef struct SharedKnockCodec3Context {
  SharedKnockCodec3ServerKey server_key;
  int has_server_key;
  int server_secure;
  SiglatchOpenSSLSession *openssl_session;

  SharedKnockCodec3KeyEntry *keychain;
  size_t keychain_len;
  size_t keychain_cap;
  const char *active_key_name;
  uint64_t nonce_window_ms;
  uint32_t flags;
} SharedKnockCodec3Context;

typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
  int (*create)(SharedKnockCodec3Context **out_context);
  void (*destroy)(SharedKnockCodec3Context *context);
  int (*set_server_key)(SharedKnockCodec3Context *context, const SharedKnockCodec3ServerKey *server_key);
  void (*clear_server_key)(SharedKnockCodec3Context *context);
  int (*set_openssl_session)(SharedKnockCodec3Context *context,
                             SiglatchOpenSSLSession *session);
  void (*clear_openssl_session)(SharedKnockCodec3Context *context);
  int (*add_keychain)(SharedKnockCodec3Context *context, const SharedKnockCodec3KeyEntry *entry);
  int (*remove_keychain)(SharedKnockCodec3Context *context, const char *name);
} SharedKnockCodec3ContextLib;

int shared_knock_codec3_context_init(void);
void shared_knock_codec3_context_shutdown(void);
int shared_knock_codec3_context_create(SharedKnockCodec3Context **out_context);
void shared_knock_codec3_context_destroy(SharedKnockCodec3Context *context);
int shared_knock_codec3_context_set_server_key(SharedKnockCodec3Context *context,
                                              const SharedKnockCodec3ServerKey *server_key);
void shared_knock_codec3_context_clear_server_key(SharedKnockCodec3Context *context);
int shared_knock_codec3_context_set_openssl_session(SharedKnockCodec3Context *context,
                                                   SiglatchOpenSSLSession *session);
void shared_knock_codec3_context_clear_openssl_session(SharedKnockCodec3Context *context);
int shared_knock_codec3_context_add_keychain(SharedKnockCodec3Context *context,
                                            const SharedKnockCodec3KeyEntry *entry);
int shared_knock_codec3_context_remove_keychain(SharedKnockCodec3Context *context,
                                               const char *name);
const SharedKnockCodec3ContextLib *get_shared_knock_codec3_context_lib(void);

#endif /* SIGLATCH_SHARED_KNOCK_CODEC3_CONTEXT_H */
