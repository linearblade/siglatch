/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <time.h>
#include "daemon.h"
#include "config.h"
#include "decrypt.h"
#include "signal.h"
#include "../stdlib/utils.h"
#include "lib.h"
#include "../stdlib/net_helpers.h"
#include "handle_packet.h"
#include "handle_unstructured.h"
#include "../stdlib/openssl_session.h"

#define BUF_SIZE 1024
static int unrecoverable_decrypt_error(int rc);
ssize_t receiveValidData(int sock, char *buffer, size_t bufsize, struct sockaddr_in *client, char *ip_out);
int normalizeInboundPayload(
    SiglatchOpenSSLSession *session,
    const uint8_t *input,
    size_t input_len,
    uint8_t *normalized_out,
    size_t *normalized_len
			    );

void siglatch_daemon(siglatch_config * cfg, int sock){
  char buffer[BUF_SIZE];
  char ip[INET_ADDRSTRLEN];

  struct sockaddr_in client;

  SiglatchOpenSSLSession session = {0};
  if (!session_init_for_server(cfg, &session)) {
    LOGE("❌ Failed to initialize OpenSSL session for server\n");
    return;
  }

  const siglatch_server * server_conf = lib.config.get_current_server();
  int is_encrypted = server_conf->secure;

  while (!should_exit) {
    ssize_t n = receiveValidData(sock, buffer, BUF_SIZE, &client, ip);
    if (n <= 0) continue;
    lib.log.console("RECEIVED SOMETHING\n");

    // Debugging aid (optional toggle later)
    LOGT("📩 %zd bytes from %s\n", n, ip);

    uint8_t normalized_buffer[512] = {0};
    size_t  normalized_len = 0;
    if (is_encrypted) {
      if (!normalizeInboundPayload(&session,
				   (const uint8_t *)buffer,
				   n,
				   normalized_buffer,
				   &normalized_len
				   )) {
	// Fatal decryption error — skip packet
	continue;
      }
    }else {
      // Treat as raw unencrypted packet
      size_t copy_len = (n < sizeof(normalized_buffer)) ? n : sizeof(normalized_buffer);
      memcpy(normalized_buffer, buffer, copy_len);
      normalized_len = copy_len;
    }
    

    KnockPacket pkt = {0};  // Initialize cleanly

    int payloadRC = lib.payload.deserialize(normalized_buffer, normalized_len, &pkt);
    ////

    if (payloadRC == SL_PAYLOAD_OK) {
      LOGT("[deserialize] ✅ Valid %s KnockPacket — User ID: %u, Action ID: %u\n",
	   is_encrypted? "encrypted" : "unencrypted", pkt.user_id, pkt.action_id);
      handle_structured_payload( &pkt, &session, ip);
      continue;
    } else {
      LOGW("[deserialize] ❌ Error: encrypted=%d; %s\n", is_encrypted, lib.payload.deserialize_strerror(payloadRC));
      handle_unstructured_payload( normalized_buffer, normalized_len,   ip );
    }
  } 
}
/*

    int payloadRC = lib.payload.deserialize(normalized_buffer, normalized_len, &pkt);
    ////
    if (payloadRC == SL_PAYLOAD_OK) {
      LOGT("[deserialize] ✅ Valid %s KnockPacket — User ID: %u, Action ID: %u\n",
	   is_encrypted ? "encrypted" : "unencrypted", pkt.user_id, pkt.action_id);
      handle_structured_payload(cfg, &pkt, &session, ip, is_encrypted);
      continue;
    } else {
      LOGW("[deserialize] ❌ Error: encrypted=%d; %s\n",
	   is_encrypted, lib.payload.deserialize_strerror(payloadRC));

      if (is_encrypted == 1) {
        LOGW("[deserialize] ⚠️ Retrying deserialization using unencrypted fallback path...\n");

        pkt = (KnockPacket){0};  // Reset packet
        payloadRC = lib.payload.deserialize((const uint8_t *)buffer, n, &pkt);
        if (payloadRC == SL_PAYLOAD_OK) {
	  LOGT("[deserialize] ✅ Valid unencrypted KnockPacket — User ID: %u, Action ID: %u\n",
	       pkt.user_id, pkt.action_id);
	  handle_structured_payload(cfg, &pkt, &session, ip, 0);  // Force plaintext
	  continue;
        }
      }
      handle_unstructured_payload(
				  (const uint8_t *)buffer, n,          // raw buffer and length
				  normalized_buffer, normalized_len,   // normalized (possibly decrypted) buffer and length
				  ip, is_encrypted                     // source IP and encryption flag
				  );
    }

 */

/**
 * @brief Receives a single UDP packet and performs basic validation.
 *
 * This function performs a blocking `recvfrom()` call on the specified socket,
 * checks for timeouts, oversized packets, and extracts the sender's IP address
 * into a string. It logs appropriate diagnostics on errors or every 100 packets.
 *
 * @param sock      The UDP socket descriptor to receive from.
 * @param buffer    Destination buffer for packet data.
 * @param bufsize   Size of the buffer (typically BUF_SIZE).
 * @param client    Populated with sender's address info.
 * @param ip_out    Caller-supplied buffer (INET_ADDRSTRLEN) for string IP.
 *                  Must not be NULL.
 *
 * @return Number of bytes received, or -1 on error.
 *         Fatal errors (e.g., ip_out is NULL) will call exit().
 */
ssize_t receiveValidData(int sock, char *buffer, size_t bufsize, struct sockaddr_in *client, char *ip_out) {
  static unsigned long packet_count = 0;
  socklen_t len = sizeof(*client);
  ssize_t n = recvfrom(sock, buffer, bufsize - 1, 0,
                       (struct sockaddr *)client, &len);
  const char *timestr = lib.time.human(0);

  if (n < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return -1;  // Timed out
    }
    LOGPERR("❌ recvfrom failed");
    LOGE("[%s] recvfrom error (client maybe unreachable)\n", timestr);
    return -1;
  }

  if (!ip_out) {
    LOGE("☢️ FATAL: ip_out was NULL in receiveValidData() — cannot record client address");
    exit(SL_EXIT_ERR_NETWORK_FATAL);  // Or #define 3
  }
  

  ip_out[0] = '\0';  // Ensure safe default
  if (!inet_ntop(AF_INET, &client->sin_addr, ip_out, INET_ADDRSTRLEN)) {
    LOGPERR("inet_ntop");
    return -1;
  }

  if (n >= bufsize) {
    LOGE("⚠️  Dropping oversized packet (%zd bytes)\n", n);
    return -1;
  }

  if (++packet_count % 100 == 0) {
    LOGD("[%s] ✅ Processed %lu candidate packets so far\n", timestr, packet_count);
  }

  return n;
}


/**
 * @brief Normalize incoming UDP payload by attempting decryption.
 *
 * This function attempts to decrypt the given buffer using the session.
 * If decryption fails due to a recoverable error (e.g., plaintext fallback),
 * it copies the raw input into the output buffer instead. If an unrecoverable
 * OpenSSL failure occurs, it returns failure.
 *
 * @param session          Pointer to a valid OpenSSL session
 * @param input            Raw UDP packet buffer
 * @param input_len        Length of input buffer
 * @param normalized_out   Output buffer to store decrypted or fallback data
 * @param normalized_len   Output: actual length of normalized buffer
 * @param is_encrypted_out Output: 1 if decrypted, 0 if plaintext fallback
 *
 * @return int 1 on success, 0 on fatal failure
 */
int normalizeInboundPayload(
    SiglatchOpenSSLSession *session,
    const uint8_t *input,
    size_t input_len,
    uint8_t *normalized_out,
    size_t *normalized_len
) {
    if (!session || !input || !normalized_out || !normalized_len ) {
        return 0;
    }

    LOGT("🔐 Attempting to decrypt incoming packet...\n");

    int rc = lib.openssl.session_decrypt(
        session,
        input,
        input_len,
        normalized_out,
        normalized_len
    );

    if (rc == SL_SSL_DECRYPT_OK) {
      //*is_encrypted_out = 1;
        return 1;
    }

    const char *msg = lib.openssl.session_decrypt_strerror
        ? lib.openssl.session_decrypt_strerror(rc)
        : "Unknown decrypt error";

    LOGE("[decrypt] ❌ Decryption failed (rc=%d): %s\n", rc, msg);

    //works fine but no longer try to auto nego encryption status. server determines encrypted or not
    /*
    if (unrecoverable_decrypt_error(rc)) {
      LOGW("[decrypt] ❌ Fatal OpenSSL error. Dropping packet.\n");
      return 0;
    }
    */
    return 0;
    /*
      //we no longer assume encrypted or not. encryption is determined by server config.
    *is_encrypted_out = 0;

    // Fallback: treat original buffer as plaintext
    memset(normalized_out, 0, 512);  // Safe default
    memcpy(normalized_out, input, input_len);
    *normalized_len = input_len;

    LOGW("[decrypt] ⚠️ Assuming plaintext fallback (%zu bytes)\n", *normalized_len);
    */
    return 1;
}

/**
 * @brief Determines if a given decryption error code is fatal.
 *
 * Fatal errors indicate a failure in OpenSSL setup, argument errors,
 * or broken context state — not recoverable or fallback-friendly.
 *
 * @param rc The return code from session_decrypt().
 * @return 1 if fatal (should drop packet); 0 if recoverable (e.g. unencrypted input).
 */
UNUSED_FN
static int unrecoverable_decrypt_error(int rc) {
    switch (rc) {
        case SL_SSL_DECRYPT_ERR_ARGS:
        case SL_SSL_DECRYPT_ERR_CTX_ALLOC:
        case SL_SSL_DECRYPT_ERR_INIT:
        case SL_SSL_DECRYPT_ERR_PADDING:
            return 1;  // Fatal: misconfiguration, internal errors
        case SL_SSL_DECRYPT_ERR_LEN_QUERY:
        case SL_SSL_DECRYPT_ERR_DECRYPT:
            return 0;  // Might be benign (e.g. unencrypted input)
        case SL_SSL_DECRYPT_OK:
        default:
            return 0;  // Not fatal
    }
}
