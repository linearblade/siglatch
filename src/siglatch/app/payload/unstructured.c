/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "unstructured.h"

#include <stdio.h>
#include <string.h>

#include "../app.h"
#include "../../lib.h"
#include "../../../stdlib/base64.h"

static int app_payload_unstructured_is_ascii(const unsigned char *buf, size_t len);
static void app_payload_unstructured_print_ascii(const unsigned char *input, size_t input_len);
static void app_payload_unstructured_print_hex(const unsigned char *input, size_t input_len);
static void app_payload_unstructured_handle_invalid(
    const unsigned char *buf,
    size_t buflen);

int app_payload_unstructured_init(void) {
  return 1;
}

void app_payload_unstructured_shutdown(void) {
}

void app_payload_unstructured_handle(
    const AppRuntimeListenerState *listener,
    const uint8_t *payload,
    size_t payload_len,
    const char *ip_addr) {
  const siglatch_deaddrop *deaddrop = NULL;
  char match[512] = {0};
  size_t match_len = 0;
  char encrypted_str[8];
  char payload_b64[512] = {0};
  char *argv[5] = {0};

  LOGD("[payload] [unstructured] processing unstructured data.\n");

  if (!listener || !listener->server) {
    LOGE("[payload] [unstructured] current server context is NULL; dropping packet.\n");
    return;
  }

  deaddrop = app.server.deaddrop_starts_with_buffer(
      listener->server, payload, payload_len, match, sizeof(match), &match_len);
  if (!deaddrop) {
    app_payload_unstructured_handle_invalid(payload, payload_len);
    return;
  }

  if (deaddrop->require_ascii &&
      !app_payload_unstructured_is_ascii(payload, payload_len)) {
    LOGD("[payload] [unstructured] deaddrop matched to %s, but contains non ascii characters.\n",
         deaddrop->name);
    app_payload_unstructured_handle_invalid(payload, payload_len);
    return;
  }

  snprintf(encrypted_str, sizeof(encrypted_str), "%d", listener->server->secure ? 1 : 0);
  base64_encode(payload + match_len, payload_len - match_len, payload_b64, sizeof(payload_b64));

  argv[0] = (char *)ip_addr;
  argv[1] = (char *)deaddrop->name;
  argv[2] = encrypted_str;
  argv[3] = payload_b64;
  argv[4] = NULL;

  LOGD("[handle] Routing to script: %s (Ip=%s, Action=%s,encrypted=%s, exec_split=%d)\n",
       deaddrop->constructor,
       ip_addr,
       deaddrop->name,
       encrypted_str,
       deaddrop->exec_split);

  app.payload.run_shell(
      deaddrop->constructor,
      4,
      argv,
      deaddrop->exec_split,
      deaddrop->run_as[0] ? deaddrop->run_as : NULL);
}

static void app_payload_unstructured_handle_invalid(
    const unsigned char *buf,
    size_t buflen) {
  if (app_payload_unstructured_is_ascii(buf, buflen)) {
    LOGW("[payload] Unmatched deaddrop payload is ASCII, but invalid packet structure.\n");
    app_payload_unstructured_print_ascii(buf, buflen);
  } else {
    LOGW("[payload] Unmatched deaddrop  payload is binary/non-ASCII and invalid structure.\n");
    app_payload_unstructured_print_hex(buf, buflen);
  }
}

static int app_payload_unstructured_is_ascii(const unsigned char *buf, size_t len) {
  if (!buf) {
    return 0;
  }

  for (size_t i = 0; i < len; ++i) {
    if (buf[i] < 32 || buf[i] > 126) {
      return 0;
    }
  }

  return 1;
}

static void app_payload_unstructured_print_ascii(
    const unsigned char *input,
    size_t input_len) {
  if (!input || input_len == 0) {
    return;
  }

  LOGD("Printable ASCII payload detected:\n");
  LOGD("%.*s\n", (int)input_len, input);
}

static void app_payload_unstructured_print_hex(
    const unsigned char *input,
    size_t input_len) {
  char line[256] = {0};
  size_t pos = 0;
  size_t limit = 0;

  if (!input || input_len == 0) {
    LOGW("printHEX called with null or empty input");
    return;
  }

  LOGD("Binary (non-ASCII) payload:");

  limit = (input_len > 512) ? 512 : input_len;
  for (size_t i = 0; i < limit; ++i) {
    int written = 0;

    if (pos >= sizeof(line) - 4) {
      break;
    }

    written = snprintf(line + pos, sizeof(line) - pos, "%02X ", input[i]);
    if (written <= 0 || (size_t)written >= sizeof(line) - pos) {
      break;
    }

    pos += (size_t)written;
  }

  if (input_len > 512 && pos + 18 < sizeof(line)) {
    strncat(line, "... (truncated)", sizeof(line) - strlen(line) - 1);
  }

  LOGD("%s\n", line);
}
