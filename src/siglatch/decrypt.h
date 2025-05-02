#ifndef SIGLATCH_DECRYPT
#define SIGLATCH_DECRYPT

#include "config.h"
#include "../stdlib/payload.h"
#include "../stdlib/openssl_session.h"

//int decrypt_knock(const siglatch_config *cfg, const unsigned char *input, size_t input_len);

int decrypt_knock(
    SiglatchOpenSSLSession *session,
    const unsigned char *input, size_t input_len,
    unsigned char *output, size_t *output_len,
    char *error_msg_buf, size_t bufsize
);

int validateSignature(const SiglatchOpenSSLSession *session, const KnockPacket *pkt);

const siglatch_user *find_user_by_id(const siglatch_config *cfg, uint32_t user_id);
int session_init_for_server(const siglatch_config *cfg, SiglatchOpenSSLSession *session);
int session_assign_to_user(SiglatchOpenSSLSession *session, const siglatch_user *user);
#endif // SIGLATCH_DECRYPT
