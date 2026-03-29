/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "context.h"

#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>

static int g_initialized = 0;

static void shared_knock_codec3_context_free_server_key(SharedKnockCodec3ServerKey *entry);
static void shared_knock_codec3_context_free_entry(SharedKnockCodec3KeyEntry *entry);
static int shared_knock_codec3_context_copy_server_key(const SharedKnockCodec3ServerKey *src,
                                                      SharedKnockCodec3ServerKey *dst);
static int shared_knock_codec3_context_copy_entry(const SharedKnockCodec3KeyEntry *src,
                                                 SharedKnockCodec3KeyEntry *dst);
static int shared_knock_codec3_context_ensure_capacity(SharedKnockCodec3Context *context,
                                                      size_t needed);
static int shared_knock_codec3_context_name_exists(const SharedKnockCodec3Context *context,
                                                  const char *name);

int shared_knock_codec3_context_init(void) {
  g_initialized = 1;
  return 1;
}

void shared_knock_codec3_context_shutdown(void) {
  g_initialized = 0;
}

int shared_knock_codec3_context_create(SharedKnockCodec3Context **out_context) {
  SharedKnockCodec3Context *context = NULL;

  if (!g_initialized || !out_context) {
    return 0;
  }

  context = (SharedKnockCodec3Context *)calloc(1u, sizeof(*context));
  if (!context) {
    return 0;
  }

  *out_context = context;
  return 1;
}

void shared_knock_codec3_context_destroy(SharedKnockCodec3Context *context) {
  size_t i = 0;

  if (!context) {
    return;
  }

  shared_knock_codec3_context_free_server_key(&context->server_key);
  context->openssl_session = NULL;

  for (i = 0; i < context->keychain_len; ++i) {
    shared_knock_codec3_context_free_entry(&context->keychain[i]);
  }

  free(context->keychain);
  context->keychain = NULL;
  context->keychain_len = 0u;
  context->keychain_cap = 0u;
  free(context);
}

int shared_knock_codec3_context_set_server_key(SharedKnockCodec3Context *context,
                                              const SharedKnockCodec3ServerKey *server_key) {
  SharedKnockCodec3ServerKey copy = {0};

  if (!g_initialized || !context || !server_key || !server_key->name || server_key->name[0] == '\0') {
    return 0;
  }

  if (!shared_knock_codec3_context_copy_server_key(server_key, &copy)) {
    return 0;
  }

  shared_knock_codec3_context_free_server_key(&context->server_key);
  context->server_key = copy;
  context->has_server_key = 1;
  return 1;
}

void shared_knock_codec3_context_clear_server_key(SharedKnockCodec3Context *context) {
  if (!context) {
    return;
  }

  shared_knock_codec3_context_free_server_key(&context->server_key);
  context->has_server_key = 0;
  context->server_secure = 0;
}

int shared_knock_codec3_context_set_openssl_session(SharedKnockCodec3Context *context,
                                                   SiglatchOpenSSLSession *session) {
  if (!g_initialized || !context) {
    return 0;
  }

  context->openssl_session = session;
  return 1;
}

void shared_knock_codec3_context_clear_openssl_session(SharedKnockCodec3Context *context) {
  if (!context) {
    return;
  }

  context->openssl_session = NULL;
}

int shared_knock_codec3_context_add_keychain(SharedKnockCodec3Context *context,
                                            const SharedKnockCodec3KeyEntry *entry) {
  SharedKnockCodec3KeyEntry *slot = NULL;
  size_t index = 0;

  if (!g_initialized || !context || !entry || !entry->name || entry->name[0] == '\0') {
    return 0;
  }

  if (shared_knock_codec3_context_name_exists(context, entry->name)) {
    return 0;
  }

  if (!shared_knock_codec3_context_ensure_capacity(context, context->keychain_len + 1u)) {
    return 0;
  }

  index = context->keychain_len;
  slot = &context->keychain[index];
  if (!shared_knock_codec3_context_copy_entry(entry, slot)) {
    shared_knock_codec3_context_free_entry(slot);
    return 0;
  }

  context->keychain_len = index + 1u;
  return 1;
}

int shared_knock_codec3_context_remove_keychain(SharedKnockCodec3Context *context,
                                               const char *name) {
  size_t i = 0;
  size_t j = 0;

  if (!g_initialized || !context || !name || name[0] == '\0') {
    return 0;
  }

  for (i = 0; i < context->keychain_len; ++i) {
    SharedKnockCodec3KeyEntry *entry = &context->keychain[i];
    int active_matches = 0;

    if (!entry->name || strcmp(entry->name, name) != 0) {
      continue;
    }

    if (context->active_key_name && strcmp(context->active_key_name, name) == 0) {
      active_matches = 1;
    }

    shared_knock_codec3_context_free_entry(entry);
    for (j = i; j + 1u < context->keychain_len; ++j) {
      context->keychain[j] = context->keychain[j + 1u];
    }

    memset(&context->keychain[context->keychain_len - 1u], 0, sizeof(context->keychain[0]));
    context->keychain_len--;

    if (active_matches) {
      context->active_key_name = NULL;
    }

    return 1;
  }

  return 0;
}

static void shared_knock_codec3_context_free_server_key(SharedKnockCodec3ServerKey *entry) {
  if (!entry) {
    return;
  }

  free((void *)entry->name);
  entry->name = NULL;

  if (entry->public_key) {
    EVP_PKEY_free(entry->public_key);
    entry->public_key = NULL;
  }

  if (entry->private_key) {
    EVP_PKEY_free(entry->private_key);
    entry->private_key = NULL;
  }

  free((void *)entry->hmac_key);
  entry->hmac_key = NULL;
  entry->hmac_key_len = 0u;
  entry->flags = 0u;
}

static void shared_knock_codec3_context_free_entry(SharedKnockCodec3KeyEntry *entry) {
  if (!entry) {
    return;
  }

  free((void *)entry->name);
  entry->name = NULL;

  if (entry->public_key) {
    EVP_PKEY_free(entry->public_key);
    entry->public_key = NULL;
  }

  if (entry->private_key) {
    EVP_PKEY_free(entry->private_key);
    entry->private_key = NULL;
  }

  free((void *)entry->hmac_key);
  entry->hmac_key = NULL;
  entry->hmac_key_len = 0u;
  entry->user_id = 0u;
  entry->flags = 0u;
}

static int shared_knock_codec3_context_copy_server_key(const SharedKnockCodec3ServerKey *src,
                                                      SharedKnockCodec3ServerKey *dst) {
  char *name_copy = NULL;
  uint8_t *hmac_copy = NULL;

  if (!src || !dst || !src->name) {
    return 0;
  }

  memset(dst, 0, sizeof(*dst));

  name_copy = (char *)malloc(strlen(src->name) + 1u);
  if (!name_copy) {
    return 0;
  }
  strcpy(name_copy, src->name);
  dst->name = name_copy;

  if (src->public_key) {
    if (EVP_PKEY_up_ref((EVP_PKEY *)src->public_key) != 1) {
      shared_knock_codec3_context_free_server_key(dst);
      return 0;
    }
    dst->public_key = src->public_key;
  }

  if (src->private_key) {
    if (EVP_PKEY_up_ref((EVP_PKEY *)src->private_key) != 1) {
      shared_knock_codec3_context_free_server_key(dst);
      return 0;
    }
    dst->private_key = src->private_key;
  }

  if (src->hmac_key_len > 0u) {
    if (!src->hmac_key) {
      shared_knock_codec3_context_free_server_key(dst);
      return 0;
    }

    hmac_copy = (uint8_t *)malloc(src->hmac_key_len);
    if (!hmac_copy) {
      shared_knock_codec3_context_free_server_key(dst);
      return 0;
    }
    memcpy(hmac_copy, src->hmac_key, src->hmac_key_len);
    dst->hmac_key = hmac_copy;
  }

  dst->hmac_key_len = src->hmac_key_len;
  dst->flags = src->flags;
  return 1;
}

static int shared_knock_codec3_context_copy_entry(const SharedKnockCodec3KeyEntry *src,
                                                 SharedKnockCodec3KeyEntry *dst) {
  char *name_copy = NULL;
  uint8_t *hmac_copy = NULL;

  if (!src || !dst || !src->name) {
    return 0;
  }

  memset(dst, 0, sizeof(*dst));

  name_copy = (char *)malloc(strlen(src->name) + 1u);
  if (!name_copy) {
    return 0;
  }
  strcpy(name_copy, src->name);
  dst->name = name_copy;

  if (src->public_key) {
    if (EVP_PKEY_up_ref((EVP_PKEY *)src->public_key) != 1) {
      shared_knock_codec3_context_free_entry(dst);
      return 0;
    }
    dst->public_key = src->public_key;
  }

  if (src->private_key) {
    if (EVP_PKEY_up_ref((EVP_PKEY *)src->private_key) != 1) {
      shared_knock_codec3_context_free_entry(dst);
      return 0;
    }
    dst->private_key = src->private_key;
  }

  if (src->hmac_key_len > 0u) {
    if (!src->hmac_key) {
      shared_knock_codec3_context_free_entry(dst);
      return 0;
    }

    hmac_copy = (uint8_t *)malloc(src->hmac_key_len);
    if (!hmac_copy) {
      shared_knock_codec3_context_free_entry(dst);
      return 0;
    }
    memcpy(hmac_copy, src->hmac_key, src->hmac_key_len);
    dst->hmac_key = hmac_copy;
  }

  dst->hmac_key_len = src->hmac_key_len;
  dst->user_id = src->user_id;
  dst->flags = src->flags;
  return 1;
}

static int shared_knock_codec3_context_ensure_capacity(SharedKnockCodec3Context *context,
                                                      size_t needed) {
  SharedKnockCodec3KeyEntry *entries = NULL;
  size_t old_cap = 0u;
  size_t new_cap = 0u;
  size_t bytes = 0u;

  if (!context || needed == 0u) {
    return 0;
  }

  if (context->keychain_cap >= needed) {
    return 1;
  }

  old_cap = context->keychain_cap;
  new_cap = old_cap ? old_cap : 4u;
  while (new_cap < needed) {
    new_cap *= 2u;
  }

  bytes = new_cap * sizeof(*entries);
  entries = (SharedKnockCodec3KeyEntry *)realloc(context->keychain, bytes);
  if (!entries) {
    return 0;
  }

  memset(entries + old_cap, 0, (new_cap - old_cap) * sizeof(*entries));
  context->keychain = entries;
  context->keychain_cap = new_cap;
  return 1;
}

static int shared_knock_codec3_context_name_exists(const SharedKnockCodec3Context *context,
                                                  const char *name) {
  size_t i = 0;

  if (!context || !name) {
    return 0;
  }

  for (i = 0; i < context->keychain_len; ++i) {
    if (context->keychain[i].name && strcmp(context->keychain[i].name, name) == 0) {
      return 1;
    }
  }

  return 0;
}

static const SharedKnockCodec3ContextLib _instance = {
  .init = shared_knock_codec3_context_init,
  .shutdown = shared_knock_codec3_context_shutdown,
  .create = shared_knock_codec3_context_create,
  .destroy = shared_knock_codec3_context_destroy,
  .set_server_key = shared_knock_codec3_context_set_server_key,
  .clear_server_key = shared_knock_codec3_context_clear_server_key,
  .set_openssl_session = shared_knock_codec3_context_set_openssl_session,
  .clear_openssl_session = shared_knock_codec3_context_clear_openssl_session,
  .add_keychain = shared_knock_codec3_context_add_keychain,
  .remove_keychain = shared_knock_codec3_context_remove_keychain
};

const SharedKnockCodec3ContextLib *get_shared_knock_codec3_context_lib(void) {
  return &_instance;
}
