/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "rsa.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

int siglatch_openssl_session_encrypt(SiglatchOpenSSLSession *session,
                                     const unsigned char *msg, size_t msg_len,
                                     unsigned char *out_buf, size_t *out_len) {
  if (!session || !session->public_key || !msg || !out_buf || !out_len) {
    return 0;
  }

  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(session->public_key, NULL);
  if (!ctx) {
    if (session->parent_ctx && session->parent_ctx->log) {
      session->parent_ctx->log->console("Failed to create EVP_PKEY_CTX for encryption\n");
    }
    return 0;
  }

  if (EVP_PKEY_encrypt_init(ctx) <= 0 ||
      EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    if (session->parent_ctx && session->parent_ctx->log) {
      session->parent_ctx->log->console("Failed to initialize encryption context or set padding\n");
    }
    return 0;
  }

  size_t out_len_tmp = 0;
  if (EVP_PKEY_encrypt(ctx, NULL, &out_len_tmp, msg, msg_len) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    if (session->parent_ctx && session->parent_ctx->log) {
      session->parent_ctx->log->console("Failed to estimate encrypted size\n");
    }
    return 0;
  }

  if (EVP_PKEY_encrypt(ctx, out_buf, &out_len_tmp, msg, msg_len) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    if (session->parent_ctx && session->parent_ctx->log) {
      session->parent_ctx->log->console("Encryption failed\n");
    }
    return 0;
  }

  *out_len = out_len_tmp;

  EVP_PKEY_CTX_free(ctx);
  return 1;
}

int siglatch_openssl_session_decrypt(
    SiglatchOpenSSLSession *session,
    const unsigned char *input, size_t input_len,
    unsigned char *output, size_t *output_len
) {
  if (!session || !session->private_key || !input || !output || !output_len) {
    return SL_SSL_DECRYPT_ERR_ARGS;
  }

  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(session->private_key, NULL);
  if (!ctx) return SL_SSL_DECRYPT_ERR_CTX_ALLOC;

  int rc = SL_SSL_DECRYPT_ERR_INIT;

  do {
    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
	  rc = SL_SSL_DECRYPT_ERR_INIT;
      break;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
      rc = SL_SSL_DECRYPT_ERR_PADDING;
      break;
    }

    size_t len = 0;
    if (EVP_PKEY_decrypt(ctx, NULL, &len, input, input_len) <= 0) {
      rc = SL_SSL_DECRYPT_ERR_LEN_QUERY;
      break;
    }

    if (EVP_PKEY_decrypt(ctx, output, &len, input, input_len) <= 0) {
      rc = SL_SSL_DECRYPT_ERR_DECRYPT;
      break;
    }

    *output_len = len;
    rc = SL_SSL_DECRYPT_OK;
  } while (0);

  EVP_PKEY_CTX_free(ctx);
  return rc;
}

const char *siglatch_openssl_decrypt_strerror(int code) {
  switch (code) {
    case SL_SSL_DECRYPT_OK:
      return "Success";
    case SL_SSL_DECRYPT_ERR_ARGS:
      return "Invalid arguments (null pointers or missing key)";
    case SL_SSL_DECRYPT_ERR_CTX_ALLOC:
      return "Failed to allocate EVP_PKEY_CTX";
    case SL_SSL_DECRYPT_ERR_INIT:
      return "EVP_PKEY_decrypt_init failed";
    case SL_SSL_DECRYPT_ERR_PADDING:
      return "Failed to set RSA padding";
    case SL_SSL_DECRYPT_ERR_LEN_QUERY:
      return "Failed to determine decrypted length";
    case SL_SSL_DECRYPT_ERR_DECRYPT:
      return "EVP_PKEY_decrypt failed (bad data or wrong key)";
    default:
      return "Unknown decryption error";
  }
}
