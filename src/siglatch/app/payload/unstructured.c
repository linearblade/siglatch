/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "unstructured.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "../app.h"
#include "../../lib.h"
#include "../../../stdlib/base64.h"

static int app_payload_unstructured_is_ascii(const unsigned char *buf, size_t len);
static void app_payload_unstructured_print_ascii(const unsigned char *input, size_t input_len);
static void app_payload_unstructured_print_hex(const unsigned char *input, size_t input_len);
static void app_payload_unstructured_handle_invalid(
    const unsigned char *buf,
    size_t buflen);
static int app_payload_unstructured_base64_size(size_t input_len, size_t *out_size);

int app_payload_unstructured_init(void) {
  return 1;
}

void app_payload_unstructured_shutdown(void) {
}

void app_payload_unstructured_handle(
    const AppRuntimeListenerState *listener,
    AppConnectionJob *job) {
  const siglatch_deaddrop *deaddrop = NULL;
  char match[512] = {0};
  size_t match_len = 0;
  char encrypted_str[8];
  char empty_payload_b64[1] = {0};
  char *payload_b64 = empty_payload_b64;
  char *argv[5] = {0};
  size_t payload_b64_size = 0;
  size_t payload_tail_len = 0;
  int shell_exit_code = 127;
  const uint8_t *payload = NULL;
  size_t payload_len = 0;
  const char *ip_addr = NULL;
  int payload_b64_allocated = 0;

  LOGD("[payload] [unstructured] processing unstructured data.\n");

  if (!listener || !listener->server || !job) {
    LOGE("[payload] [unstructured] current server context is NULL; dropping packet.\n");
    return;
  }

  payload = job->request.payload_buffer;
  payload_len = job->request.payload_len;
  ip_addr = job->ip;

  if (payload_len > 0u && !payload) {
    LOGE("[payload] [unstructured] payload buffer is NULL for non-empty input\n");
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
  payload_tail_len = payload_len - match_len;
  if (payload_tail_len > 0u) {
    if (!app_payload_unstructured_base64_size(payload_tail_len, &payload_b64_size)) {
      LOGE("[payload] [unstructured] payload too large for base64 buffer (%zu bytes)\n",
           payload_tail_len);
      return;
    }

    payload_b64 = (char *)malloc(payload_b64_size);
    if (!payload_b64) {
      LOGE("[payload] [unstructured] failed to allocate base64 buffer for %zu bytes\n",
           payload_tail_len);
      return;
    }
    payload_b64_allocated = 1;

    if (base64_encode(payload + match_len,
                      payload_tail_len,
                      payload_b64,
                      payload_b64_size) < 0) {
      LOGE("[payload] [unstructured] payload too large for base64 buffer (%zu bytes)\n",
           payload_tail_len);
      free(payload_b64);
      return;
    }
  }

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

  job->response_len = 0u;
  job->should_reply = 0;
  if (!app.daemon.job.reserve_response(job, APP_JOB_RESPONSE_BLOCK_SIZE)) {
    LOGE("[payload] [unstructured] failed to reserve response buffer for dead-drop output\n");
    goto cleanup;
  }

  memset(job->response_buffer, 0, job->response_cap);
  if (!app.payload.run_shell_capture(
          deaddrop->constructor,
          4,
          argv,
          deaddrop->exec_split,
          deaddrop->run_as[0] ? deaddrop->run_as : NULL,
          job->response_buffer,
          job->response_cap,
          &job->response_len,
          &shell_exit_code)) {
    LOGE("[payload] [unstructured] failed to capture dead-drop response for %s\n",
         deaddrop->name);
    job->response_len = 0u;
    job->should_reply = 0;
    goto cleanup;
  }

  if (job->response_len > 0u) {
    job->should_reply = 1;
  } else {
  }

cleanup:
  if (payload_b64_allocated) {
    free(payload_b64);
  }
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

static int app_payload_unstructured_base64_size(size_t input_len, size_t *out_size) {
  size_t groups = 0;

  if (!out_size) {
    return 0;
  }

  if (input_len > SIZE_MAX - 2u) {
    return 0;
  }

  groups = (input_len + 2u) / 3u;
  if (groups > (SIZE_MAX - 1u) / 4u) {
    return 0;
  }

  *out_size = groups * 4u + 1u;
  return 1;
}

static int app_payload_unstructured_is_ascii(const unsigned char *buf, size_t len) {
  if (!buf) {
    return 0;
  }

  for (size_t i = 0; i < len; ++i) {
    if (buf[i] == '\n' || buf[i] == '\r' || buf[i] == '\t') {
      continue;
    }

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
