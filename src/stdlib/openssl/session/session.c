/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "session.h"

#include <openssl/pem.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>

static void _session_free_evp_key(EVP_PKEY **key_ptr);
static void _session_free_evp_ctx(EVP_PKEY_CTX **ctx);
static void openssl_print_err(const char *marker, const char *fmt, ...);
static void openssl_log_key_fingerprint(const SiglatchOpenSSLSession *session,
                                        const char *label,
                                        const EVP_PKEY *key);

int siglatch_openssl_session_init(SiglatchOpenSSLSession *session) {
  if (!session) {
    SiglatchOpenSSLContext *ctx = siglatch_openssl_context_current();
    if (ctx && ctx->log && ctx->log->emit) {
      ctx->log->emit(LOG_ERROR, 1, "Failed to initialize session: session NULL");
    }
    return 0;
  }
  if (!siglatch_openssl_context_current() ||
      !siglatch_openssl_context_current()->file ||
      !siglatch_openssl_context_current()->file->read_fn_bytes) {
    openssl_print_err("fatal", "YOU DONE FUCKED UP JIMBO. HOW DID YOU LOSE THE GLOBAL SESSION!?\n");
    return 0;
  }
  session->owns_ctx = 0;
  session->parent_ctx = siglatch_openssl_context_current();
  return 1;
}

int siglatch_openssl_key_fingerprint(const EVP_PKEY *key, char *out_hex, size_t out_hex_len) {
  unsigned char *der = NULL;
  unsigned char *cursor = NULL;
  unsigned char digest[SHA256_DIGEST_LENGTH] = {0};
  int der_len = 0;
  size_t i = 0u;

  if (!key || !out_hex || out_hex_len < ((size_t)SHA256_DIGEST_LENGTH * 2u) + 1u) {
    return 0;
  }

  der_len = i2d_PUBKEY((EVP_PKEY *)key, NULL);
  if (der_len <= 0) {
    return 0;
  }

  der = (unsigned char *)malloc((size_t)der_len);
  if (!der) {
    return 0;
  }

  cursor = der;
  if (i2d_PUBKEY((EVP_PKEY *)key, &cursor) != der_len) {
    free(der);
    return 0;
  }

  if (!SHA256(der, (size_t)der_len, digest)) {
    free(der);
    return 0;
  }

  free(der);

  for (i = 0u; i < SHA256_DIGEST_LENGTH; ++i) {
    snprintf(out_hex + (i * 2u), out_hex_len - (i * 2u), "%02x", digest[i]);
  }
  out_hex[SHA256_DIGEST_LENGTH * 2u] = '\0';
  return 1;
}

int siglatch_openssl_session_free(SiglatchOpenSSLSession *session) {
  if (!session) {
    return 0;
  }

  _session_free_evp_ctx(&session->public_key_ctx);
  _session_free_evp_ctx(&session->private_key_ctx);
  _session_free_evp_key(&session->public_key);
  _session_free_evp_key(&session->private_key);

  if (session->owns_ctx && session->parent_ctx) {
    openssl_print_err("fatal",
      "CRITICAL: siglatch OpenSSL session context marked as owned, but heap context logic is not implemented.\n"
      "-> AUDIT your session allocation path.\n"
      "-> This WILL break log/file/hmac behavior if not handled correctly.\n\n");
    free(session->parent_ctx);
    session->parent_ctx = NULL;
  }

  *session = (SiglatchOpenSSLSession){0};
  if (!session->owns_ctx) {
    session->parent_ctx = siglatch_openssl_context_current();
  }
  return 1;
}

static void openssl_print_err(const char *marker, const char *fmt, ...) {
  va_list args;
  SiglatchOpenSSLContext *ctx = siglatch_openssl_context_current();

  va_start(args, fmt);
  if (ctx && ctx->print && ctx->print->uc_vfprintf) {
    (void)ctx->print->uc_vfprintf(stderr, marker, fmt, args);
  } else {
    (void)vfprintf(stderr, fmt, args);
  }
  va_end(args);
}

static void openssl_log_key_fingerprint(const SiglatchOpenSSLSession *session,
                                        const char *label,
                                        const EVP_PKEY *key) {
  char fingerprint[(SHA256_DIGEST_LENGTH * 2u) + 1u] = {0};

  if (!session || !session->parent_ctx || !session->parent_ctx->log || !label || !key) {
    return;
  }

  if (!siglatch_openssl_key_fingerprint(key, fingerprint, sizeof(fingerprint))) {
    return;
  }

  session->parent_ctx->log->emit(LOG_DEBUG, 1, "%s fingerprint: %s\n", label, fingerprint);
}

int siglatch_openssl_session_readHMAC(SiglatchOpenSSLSession *session, const char *filename) {
  if (!session || !filename || !session->parent_ctx || !session->parent_ctx->file || !session->parent_ctx->hmac) {
    return 0;
  }

  uint8_t file_buf[128] = {0};
  size_t bytes_read = session->parent_ctx->file->read_fn_bytes(filename, file_buf, sizeof(file_buf));
  if (bytes_read == 0) {
    return 0;
  }
  if (!session->parent_ctx->hmac->normalize(file_buf, bytes_read, session->hmac_key)) {
    if (session->parent_ctx->log) {
      session->parent_ctx->log->emit(LOG_ERROR, 1, "Failed to normalize HMAC key");
    }
    return 0;
  }

  session->hmac_key_len = 32;
  return 1;
}

static void _session_free_evp_key(EVP_PKEY **key_ptr) {
  if (key_ptr && *key_ptr) {
    EVP_PKEY_free(*key_ptr);
    *key_ptr = NULL;
  }
}

static void _session_free_evp_ctx(EVP_PKEY_CTX **ctx) {
  if (*ctx) {
    EVP_PKEY_CTX_free(*ctx);
    *ctx = NULL;
  }
}

int siglatch_openssl_session_readPrivateKey(SiglatchOpenSSLSession *session, const char *filename) {
  FILE *fp = NULL;
  EVP_PKEY *privkey = NULL;

  if (!session || !filename || !session->parent_ctx || !session->parent_ctx->file) {
    return 0;
  }

  fp = session->parent_ctx->file->open(filename, "rb");
  if (!fp) {
    if (session->parent_ctx->log) {
      session->parent_ctx->log->console("Failed to open private key file: %s\n", filename);
    }
    return 0;
  }

  privkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
  fclose(fp);

  if (!privkey) {
    if (session->parent_ctx->log) {
      session->parent_ctx->log->console("Failed to read private key from file: %s\n", filename);
    }
    return 0;
  }

  _session_free_evp_key(&session->private_key);
  session->private_key = privkey;

  if (session->parent_ctx->log) {
    session->parent_ctx->log->console("Loaded private key from: %s\n", filename);
  }
  openssl_log_key_fingerprint(session, "Private key", session->private_key);

  return 1;
}

int siglatch_openssl_session_readPublicKey(SiglatchOpenSSLSession *session, const char *filename) {
  if (!session || !filename || !session->parent_ctx || !session->parent_ctx->file) {
    return 0;
  }

  FILE *fp = session->parent_ctx->file->open(filename, "rb");
  if (!fp) {
    if (session->parent_ctx->log) {
      session->parent_ctx->log->console("Failed to open public key file: %s\n", filename);
    }
    return 0;
  }

  EVP_PKEY *pubkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
  fclose(fp);

  if (!pubkey) {
    if (session->parent_ctx->log) {
      session->parent_ctx->log->console("Failed to read public key from file: %s\n", filename);
    }
    return 0;
  }
  _session_free_evp_key(&session->public_key);
  session->public_key = pubkey;

  if (session->parent_ctx->log) {
    session->parent_ctx->log->console("Loaded public key from: %s\n", filename);
  }
  openssl_log_key_fingerprint(session, "Public key", session->public_key);

  return 1;
}
