#ifndef LIB_SIGLATCH_OPENSSL_H
#define LIB_SIGLATCH_OPENSSL_H

#include "file.h"
#include "log.h"
#include "openssl_session.h"
#include "openssl_context.h"
#include "hmac_key.h"

typedef struct {
    const void *data;
    size_t size;
} DigestItem;

// Struct holding all lib.openssl function pointers
typedef struct {
    int (*init)(SiglatchOpenSSLContext *ctx);          ///< Initialize OpenSSL library
    void (*shutdown)(void);                            ///< Shutdown OpenSSL library
    void (*set_context)(SiglatchOpenSSLContext *ctx);   ///< Set/override library context

    // Session helpers
  int (*session_init)(SiglatchOpenSSLSession *session);
  int (*session_free)(SiglatchOpenSSLSession *session);
  int (*session_readPrivateKey)(SiglatchOpenSSLSession *session, const char *filename); ///< Load a private key into session
  int (*session_readPublicKey)(SiglatchOpenSSLSession *session, const char *filename);  ///< Load a public key into session
  int (*session_readHMAC)(SiglatchOpenSSLSession *session, const char *filename);       ///< Load an HMAC key into session
  int (*session_encrypt)(SiglatchOpenSSLSession *session, const unsigned char *msg, size_t msg_len, unsigned char *out_buf, size_t *out_len);
  int (*session_decrypt)(SiglatchOpenSSLSession *session, const unsigned char *input, size_t input_len, unsigned char *output, size_t *output_len);
  const char *(*session_decrypt_strerror)(int code);
  // Signing helper
  int (*sign)(SiglatchOpenSSLSession *session, const uint8_t *digest, uint8_t *out_signature); ///< Sign a digest using session key
  int (*digest_array)(const DigestItem *items, size_t item_count, uint8_t *out_digest);

} SiglatchOpenSSL_Lib;

// Getter for the OpenSSL library singleton
const SiglatchOpenSSL_Lib *get_siglatch_openssl(void);

#define SL_SSL_DECRYPT_OK               0
#define SL_SSL_DECRYPT_ERR_ARGS       -1
#define SL_SSL_DECRYPT_ERR_CTX_ALLOC  -2
#define SL_SSL_DECRYPT_ERR_INIT       -3
#define SL_SSL_DECRYPT_ERR_PADDING    -4
#define SL_SSL_DECRYPT_ERR_LEN_QUERY  -5
#define SL_SSL_DECRYPT_ERR_DECRYPT    -6

#endif // LIB_SIGLATCH_OPENSSL_H
