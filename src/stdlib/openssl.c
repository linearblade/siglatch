/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include "openssl.h"
#include "openssl_context.h"

// Static global pointer to the active library context
//static SiglatchOpenSSLContext *g_openssl_ctx = NULL;
static SiglatchOpenSSLContext g_openssl_ctx = {0};

static void _session_free_evp_key(EVP_PKEY **key_ptr) ;
static void _session_free_evp_ctx(EVP_PKEY_CTX **ctx) ;

// Internal implementations

static int siglatch_openssl_init(SiglatchOpenSSLContext *ctx) {
    if (!ctx) {
        return -1; // NULL context passed
    }
    g_openssl_ctx = *ctx;
    return 0; // Success
}

static void siglatch_openssl_shutdown(void) {
  g_openssl_ctx = (SiglatchOpenSSLContext){0};
}

static void siglatch_openssl_set_context(SiglatchOpenSSLContext *ctx) {
    if (!ctx) {
        return; // Ignore null override
    }
    // Copy new context into static global
    g_openssl_ctx = *ctx;
}

static int siglatch_openssl_session_init(SiglatchOpenSSLSession *session) {

    if (!session) {
        if (g_openssl_ctx.log && g_openssl_ctx.log->emit) {
            g_openssl_ctx.log->emit(LOG_ERROR, 1, "Failed to initialize session: session NULL");
        }
        return 0;
    }
    if ( !g_openssl_ctx.file->read_fn_bytes) { //just check some random ptr to make sure context proper... if you convert this to ptr then  !g_openssl_ctx 
        fprintf(stderr, "YOU DONE FUCKED UP JIMBO. HOW DID YOU LOSE THE GLOBAL SESSION!?\n");
        return 0;
    }
    session->owns_ctx = 0;
    session->parent_ctx = &g_openssl_ctx;
    return 1;
}



static int siglatch_openssl_session_free(SiglatchOpenSSLSession *session) {
    if (!session) {
        return 0;
    }

    _session_free_evp_ctx(&session->public_key_ctx);
    _session_free_evp_ctx(&session->private_key_ctx);
    _session_free_evp_key(&session->public_key);
    _session_free_evp_key(&session->private_key);

    if (session->owns_ctx && session->parent_ctx) {
        fprintf(stderr,
            "☢️☢️☢️  CRITICAL: siglatch OpenSSL session context marked as owned, but you haven't implemented heap context logic! ☢️☢️☢️ \n"
            "-> AUDIT your session allocation path.\n"
            "-> This WILL break log/file/hmac behavior if not handled correctly.\n\n"
        );
        free(session->parent_ctx);  // Placeholder for future heap-based context
        session->parent_ctx = NULL;
    }

    // Clear the structure but preserve known globals
    *session = (SiglatchOpenSSLSession){0};

    // Reattach global context if nothing was freed
    if (!session->owns_ctx) {
        session->parent_ctx = &g_openssl_ctx;
    }

    return 1;
}

static int siglatch_openssl_session_readHMAC(SiglatchOpenSSLSession *session, const char *filename) {
  if (!session || !filename || !session->parent_ctx || !session->parent_ctx->file || !session->parent_ctx->hmac) {
    return 0;
  }

  
  uint8_t file_buf[128] = {0};
  size_t bytes_read = session->parent_ctx->file->read_fn_bytes(filename, file_buf, sizeof(file_buf));
  //size_t bytes_read = g_openssl_ctx.file.read_fn_bytes(filename, file_buf, sizeof(file_buf));
  if (bytes_read == 0) {
    return 0;
  }
  if (!session->parent_ctx->hmac->normalize(file_buf, bytes_read, session->hmac_key)) {
    if (session->parent_ctx->log) {
      session->parent_ctx->log->emit(LOG_ERROR, 1, "Failed to normalize HMAC key");
    }
    return 0;
  }
  

  session->hmac_key_len = 32; // Assuming normalized HMAC key is 32 bytes after normalization

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

static int siglatch_openssl_session_readPrivateKey(SiglatchOpenSSLSession *session, const char *filename) {
    (void)session;
    (void)filename;
    // TODO: Implement private key loading
    return 0; // Stub returns failure by default
}


static int siglatch_openssl_session_readPublicKey(SiglatchOpenSSLSession *session, const char *filename) {
    if (!session || !filename || !session->parent_ctx || !session->parent_ctx->file) {
        return 0;
    }

    FILE *fp = session->parent_ctx->file->open(filename, "rb");
    if (!fp) {
        if (session->parent_ctx->log) {
            session->parent_ctx->log->console("❌ Failed to open public key file: %s\n", filename);
        }
        return 0;
    }

    EVP_PKEY *pubkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);

    if (!pubkey) {
        if (session->parent_ctx->log) {
            session->parent_ctx->log->console("❌ Failed to read public key from file: %s\n", filename);
        }
        return 0;
    }
    _session_free_evp_key(&session->public_key);
    session->public_key = pubkey; // Set inside the session

    if (session->parent_ctx->log) {
        session->parent_ctx->log->console("✅ Loaded public key from: %s\n", filename);
    }

    return 1;
}
/**
 * payload_sign - Sign a precomputed SHA-256 digest using a 32-byte HMAC key.
 *
 * Parameters:
 *   hmac_key      - Pointer to 32-byte HMAC key.
 *   digest        - Pointer to 32-byte digest to sign.
 *   out_signature - Pointer to buffer (must be at least 32 bytes) to store the HMAC output.
 *
 * Returns:
 *   1 on success,
 *   0 on failure.
 */

static int siglatch_openssl_sign(SiglatchOpenSSLSession *session, const uint8_t *digest, uint8_t *out_signature) {
    if (!session || !digest || !out_signature) {
        return 0;
    }

    // Reuse your old sign logic, but use session->hmac_key
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *ctx = NULL;
    size_t out_len = 0;
    int result = 0;

    mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (!mac) {
        return 0;
    }

    ctx = EVP_MAC_CTX_new(mac);
    if (!ctx) {
        EVP_MAC_free(mac);
        return 0;
    }

    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string("digest", "SHA256", 0),
        OSSL_PARAM_END
    };

    if (EVP_MAC_init(ctx, session->hmac_key, session->hmac_key_len, params) != 1) {
        goto cleanup;
    }

    if (EVP_MAC_update(ctx, digest, 32) != 1) {
        goto cleanup;
    }

    if (EVP_MAC_final(ctx, out_signature, &out_len, 32) != 1) {
        goto cleanup;
    }

    if (out_len != 32) {
        goto cleanup;
    }

    result = 1;

cleanup:
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return result;
}

static int siglatch_openssl_digest_array(const DigestItem *items, size_t item_count, uint8_t *out_digest) {
    if (!items || !out_digest || item_count == 0) {
        return 0;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return 0;
    }

    int result = 0; // Assume failure

    do {
        if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
            break;
        }

        for (size_t i = 0; i < item_count; ++i) {
            if (!items[i].data || items[i].size == 0) {
                continue; // Skip empty entries for safety
            }
            if (EVP_DigestUpdate(ctx, items[i].data, items[i].size) != 1) {
                break;
            }
        }

        unsigned int digest_len = 0;
        if (EVP_DigestFinal_ex(ctx, out_digest, &digest_len) != 1) {
            break;
        }
        if (digest_len != 32) {
            break;
        }

        result = 1; // Success
    } while (0);

    EVP_MD_CTX_free(ctx);
    return result;
}

static int siglatch_openssl_session_encrypt(SiglatchOpenSSLSession *session,
                                            const unsigned char *msg, size_t msg_len,
                                            unsigned char *out_buf, size_t *out_len) {
  if (!session || !session->public_key || !msg || !out_buf || !out_len) {
    return 0;
  }

  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(session->public_key, NULL);
  if (!ctx) {
    if (session->parent_ctx && session->parent_ctx->log) {
      session->parent_ctx->log->console("❌ Failed to create EVP_PKEY_CTX for encryption\n");
    }
    return 0;
  }

  if (EVP_PKEY_encrypt_init(ctx) <= 0 ||
      EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    if (session->parent_ctx && session->parent_ctx->log) {
      session->parent_ctx->log->console("❌ Failed to initialize encryption context or set padding\n");
    }
    return 0;
  }

  size_t out_len_tmp = 0;
  if (EVP_PKEY_encrypt(ctx, NULL, &out_len_tmp, msg, msg_len) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    if (session->parent_ctx && session->parent_ctx->log) {
      session->parent_ctx->log->console("❌ Failed to estimate encrypted size\n");
    }
    return 0;
  }

  if (EVP_PKEY_encrypt(ctx, out_buf, &out_len_tmp, msg, msg_len) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    if (session->parent_ctx && session->parent_ctx->log) {
      session->parent_ctx->log->console("❌ Encryption failed\n");
    }
    return 0;
  }

  *out_len = out_len_tmp;

  EVP_PKEY_CTX_free(ctx);
  return 1;
}


/**
 * Decrypts a ciphertext using the private key stored in the session.
 * 
 * @param session        The SiglatchOpenSSLSession with valid private_key.
 * @param input          The encrypted payload (RSA-encrypted blob).
 * @param input_len      Length of the encrypted payload.
 * @param output         Output buffer for decrypted data.
 * @param output_len     Pointer to size of output buffer; set to result size.
 * @return 1 on success, 0 on failure.
 */
//
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

/*
// Stub for session_decrypt - decrypts encrypted input using session private key
static int siglatch_openssl_session_decrypt(SiglatchOpenSSLSession *session,
                                            const unsigned char *input, size_t input_len,
                                            unsigned char *output, size_t *output_len) {
    (void)session;
    (void)input;
    (void)input_len;
    (void)output;
    (void)output_len;

    fprintf(stderr, "🛑 session_decrypt() is not yet implemented.\n");
    return 0;
}
*/

// Singleton library instance
static const SiglatchOpenSSL_Lib siglatch_openssl_instance = {
    .init                   = siglatch_openssl_init,
    .shutdown               = siglatch_openssl_shutdown,
    .set_context            = siglatch_openssl_set_context,

    .session_init           = siglatch_openssl_session_init,
    .session_free           = siglatch_openssl_session_free,
    .session_readPrivateKey = siglatch_openssl_session_readPrivateKey,
    .session_readPublicKey  = siglatch_openssl_session_readPublicKey,
    .session_readHMAC       = siglatch_openssl_session_readHMAC,
    .session_encrypt        = siglatch_openssl_session_encrypt,
    .session_decrypt        = siglatch_openssl_session_decrypt,
    .session_decrypt_strerror = siglatch_openssl_decrypt_strerror,
    .sign                   = siglatch_openssl_sign,
    .digest_array           = siglatch_openssl_digest_array
};


// Public getter for singleton instance
const SiglatchOpenSSL_Lib *get_siglatch_openssl(void) {
    return &siglatch_openssl_instance;
}
