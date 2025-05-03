/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include <string.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

//#include "config.h" //dont need at moment
#include "../stdlib/base64.h"
#include "lib.h"
#include "handle_unstructured.h"
#include "handle_packet.h"
/*
static  float compute_ascii_ratio(const uint8_t *buf, size_t len);
static const uint8_t *choose_best_dead_drop(    const uint8_t *raw, size_t raw_len,    const uint8_t *decrypted, size_t dec_len);
*/

static int is_ascii(const unsigned char *buf, size_t len) ;
static void printASCII(const unsigned char *input, size_t input_len);
static void printHEX(const unsigned char *input, size_t input_len);
static void handle_invalid_payload(const unsigned char *buf, size_t buflen);


/**
 * @brief Handles packets that failed deserialization (likely dead-drops).
 *
 * This is a thin wrapper to centralize unstructured packet handling.
 * Currently routes to handle_invalid_payload(), but can be extended later.
 *
 * @param payload     The raw (normalized) buffer
 * @param payload_len The length of the payload buffer
 * @param ip          The source IP address as a string (unused)
 */

void handle_unstructured_payload(const uint8_t *payload, size_t payload_len, const char *ip_addr) {

    LOGD("[payload] [unstructured] ⚠️ processing unstructured data.\n");
    //1 get deaddrops
    char match[512] = {0};
    size_t match_len = 0;
    const siglatch_deaddrop * deaddrop = lib.config.current_server_deaddrop_starts_with_buffer(payload,payload_len,match,sizeof(match),&match_len);
    const siglatch_server * server_conf = lib.config.get_current_server();
    if (!deaddrop  ){
      handle_invalid_payload(payload, payload_len);
      return;
    }
    if (deaddrop->require_ascii && !is_ascii(payload,payload_len) ) {
      LOGD("[payload] [unstructured] ⚠️  deaddrop matched to %s, but contains non ascii characters.\n",deaddrop->name);
      handle_invalid_payload(payload, payload_len);
      return;
    }

    char encrypted_str[8];
    snprintf(encrypted_str, sizeof(encrypted_str), "%d", server_conf->secure ? 1 : 0);
    //increment the payload to just past the matchstring, so it doesnt show in message.
    char payload_b64[512] = {0};
    base64_encode(payload + match_len, payload_len - match_len, payload_b64, sizeof(payload_b64));
    //base64_encode(payload, payload_len, payload_b64, sizeof(payload_b64));
    
  char *argv[] = {
    (char *)ip_addr,
    (char *)deaddrop->name,
    encrypted_str,
    payload_b64,
    NULL
  };
  //LOGI doesnt work for some reason...
  LOGD("[handle] ➡️ Routing to script: %s (Ip=%s, Action=%s,encrypted=%s, exec_split=%d)\n", deaddrop->constructor, ip_addr, deaddrop->name,encrypted_str,deaddrop->exec_split);

  // --- 5. Launch action script ---
  runShell(deaddrop->constructor, 4, argv,deaddrop->exec_split);

  return;
    
}

/**
 * @brief Handles packets that failed deserialization (likely dead-drops).
 *
 * This is a thin wrapper to centralize unstructured packet handling.
 * Currently routes to handle_invalid_payload(), but can be extended later.
 *
 * @param payload     The raw (normalized) buffer
 * @param payload_len The length of the payload buffer
 * @param ip          The source IP address as a string (unused)
 * @param encrypted   Whether the original packet was encrypted (unused)
 */

static void handle_invalid_payload(const unsigned char *buf, size_t buflen) {
    if (is_ascii(buf, buflen)) {
        LOGW("[payload] ⚠️ Unmatched deaddrop payload is ASCII, but invalid packet structure.\n");
        printASCII(buf, buflen);
    } else {
        LOGW("[payload] ⚠️ Unmatched deaddrop  payload is binary/non-ASCII and invalid structure.\n");
        printHEX(buf, buflen);
    }

    // Optional later:
    // - Stat counter: invalid_drops++
    // - Metrics tracking
    // - Maybe accept raw blobs for dead-drops someday
    // - file uploads , etc etc etc
}


static int is_ascii(const unsigned char *buf, size_t len) {
  if (!buf) return 0;
    for (size_t i = 0; i < len; ++i) {
        if (buf[i] < 32 || buf[i] > 126) {
            return 0;  // Not ASCII
        }
    }
    return 1;  // All characters are printable ASCII
}

static void printASCII(const unsigned char *input, size_t input_len) {
  if (!input || input_len == 0) return;
    LOGD("⚠️  Printable ASCII payload detected:\n");
    LOGD("%.*s\n", (int)input_len, input);
}


static void printHEX(const unsigned char *input, size_t input_len) {
    if (!input || input_len == 0) {
        LOGW("⚠️  printHEX called with null or empty input");
        return;
    }

    LOGD("🔎 Binary (non-ASCII) payload:");

    char line[256] = {0};
    size_t pos = 0;
    size_t limit = (input_len > 512) ? 512 : input_len;

    for (size_t i = 0; i < limit; ++i) {
        if (pos >= sizeof(line) - 4) break;  // Leave space for null and safety
        int written = snprintf(line + pos, sizeof(line) - pos, "%02X ", input[i]);
        if (written <= 0 || (size_t)written >= sizeof(line) - pos) break;
        pos += (size_t)written;
    }

    if (input_len > 512 && pos + 18 < sizeof(line)) {
        strncat(line, "... (truncated)", sizeof(line) - strlen(line) - 1);
    }

    LOGD("%s\n", line);
}

/*
  
void printRawIfAscii(const unsigned char *input, size_t input_len){
  if (is_ascii(input, input_len)) {
    LOGD( "⚠️  Input is entirely printable ASCII — probably unencrypted\n");
    LOGD("☠️  Unencrypted knock payload: '%s'\n", input);
  }else {
    LOGD("☠️  ☠️  ☠️  Unencrypted knock payload CONTAINS NON ASCII CHARACTERS☠️  ☠️  ☠️ \n" );
    for (size_t i = 0; i < input_len; ++i) {
      LOGD("%02X ", input[i]);
    }
    LOGD("\n");
  }
}
*/

/*
static float compute_ascii_ratio(const uint8_t *buf, size_t len) {
    if (!buf || len == 0) return 0.0f;

    size_t ascii_count = 0;
    for (size_t i = 0; i < len; ++i) {
        if (buf[i] >= 32 && buf[i] <= 126) {
            ascii_count++;
        }
    }

    return (float)ascii_count / (float)len;
}
*/

/**
 * @brief Chooses the more "likely plaintext" buffer between raw and decrypted.
 *
 * This is a temporary heuristic — currently based on ASCII printable ratio.
 *
 * @param raw       The original UDP buffer
 * @param raw_len   Its length
 * @param decrypted The normalized/decrypted payload
 * @param dec_len   Its length
 * @return const uint8_t* Pointer to whichever buffer looks more like plaintext
 */
/*
const uint8_t *choose_best_dead_drop(
    const uint8_t *raw, size_t raw_len,
    const uint8_t *decrypted, size_t dec_len
) {
    float raw_score = compute_ascii_ratio(raw, raw_len);
    float dec_score = compute_ascii_ratio(decrypted, dec_len);

    return (dec_score >= raw_score) ? decrypted : raw;
}
*/
