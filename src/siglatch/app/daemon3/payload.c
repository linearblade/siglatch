/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "payload.h"

#include <stdio.h>
#include <string.h>

#include "../app.h"
#include "../../lib.h"
#include "../../../shared/knock/response.h"
#include "../../../stdlib/base64.h"

static int app_daemon3_payload_reply_action_prefix(uint8_t action_id,
                                                   char *out,
                                                   size_t out_size);
static int app_daemon3_payload_build_semantic_reply(
    const AppConnectionJob *job,
    const AppActionReply *reply,
    uint8_t *out_buf,
    size_t out_size,
    size_t *out_len);
static int app_daemon3_payload_stage_reply(
    AppRuntimeListenerState *listener,
    SiglatchOpenSSLSession *session,
    AppConnectionJob *job,
    const AppActionReply *reply);
static int app_daemon3_payload_dispatch_action(
    AppRuntimeListenerState *listener,
    const AppConnectionJob *job,
    SiglatchOpenSSLSession *session,
    const siglatch_user *user,
    const siglatch_action *action,
    AppConnectionJob *out_job);

static int app_daemon3_payload_init(void) {
  return 1;
}

static void app_daemon3_payload_shutdown(void) {
}

static int app_daemon3_payload_reply_action_prefix(uint8_t action_id,
                                                   char *out,
                                                   size_t out_size) {
  const siglatch_action *action = NULL;

  if (!out || out_size == 0u || action_id == 0u) {
    return 0;
  }

  action = app.config.action_by_id(action_id);
  if (action && action->label[0] != '\0') {
    snprintf(out, out_size, "%s", action->label);
    return 1;
  }

  snprintf(out, out_size, "%u", (unsigned int)action_id);
  return 1;
}

static int app_daemon3_payload_build_semantic_reply(
    const AppConnectionJob *job,
    const AppActionReply *reply,
    uint8_t *out_buf,
    size_t out_size,
    size_t *out_len) {
  uint8_t flags = 0;
  char action_prefix[64] = {0};
  char rendered_message[APP_ACTION_REPLY_MESSAGE_MAX + MAX_ACTION_NAME + 8] = {0};
  size_t rendered_len = 0;
  size_t max_text_len = 0;
  size_t message_len = 0;

  if (!job || !reply || !out_buf || !out_len) {
    return 0;
  }

  *out_len = 0;

  if (!reply->should_reply) {
    return 1;
  }

  if (out_size < SL_KNOCK_RESPONSE_PAYLOAD_HEADER_SIZE) {
    return 0;
  }

  out_buf[0] = reply->ok ? SL_KNOCK_RESPONSE_STATUS_OK : SL_KNOCK_RESPONSE_STATUS_ERROR;
  out_buf[1] = job->action_id;

  if (app_daemon3_payload_reply_action_prefix(job->action_id,
                                              action_prefix,
                                              sizeof(action_prefix))) {
    if (reply->message[0] != '\0') {
      snprintf(rendered_message, sizeof(rendered_message), "%s: %s",
               action_prefix, reply->message);
    } else {
      snprintf(rendered_message, sizeof(rendered_message), "%s", action_prefix);
    }
  } else if (reply->message[0] != '\0') {
    snprintf(rendered_message, sizeof(rendered_message), "%s", reply->message);
  }

  rendered_len = strnlen(rendered_message, sizeof(rendered_message));
  max_text_len = out_size - SL_KNOCK_RESPONSE_PAYLOAD_HEADER_SIZE;
  if (max_text_len > (sizeof(((KnockPacket *)0)->payload) - SL_KNOCK_RESPONSE_PAYLOAD_HEADER_SIZE)) {
    max_text_len = sizeof(((KnockPacket *)0)->payload) - SL_KNOCK_RESPONSE_PAYLOAD_HEADER_SIZE;
  }
  message_len = rendered_len;
  if (message_len > max_text_len) {
    message_len = max_text_len;
    flags |= SL_KNOCK_RESPONSE_FLAG_TRUNCATED;
  }

  if (reply->truncated || rendered_len >= sizeof(rendered_message)) {
    flags |= SL_KNOCK_RESPONSE_FLAG_TRUNCATED;
  }

  out_buf[2] = flags;

  if (message_len > 0u) {
    memcpy(out_buf + SL_KNOCK_RESPONSE_PAYLOAD_HEADER_SIZE, rendered_message, message_len);
  }

  *out_len = SL_KNOCK_RESPONSE_PAYLOAD_HEADER_SIZE + message_len;
  return 1;
}

static int app_daemon3_payload_consume(AppRuntimeListenerState *listener,
                                       AppConnectionJob *job,
                                       SiglatchOpenSSLSession *session) {
  const siglatch_user *user = NULL;
  const siglatch_action *action = NULL;

  if (!listener || !listener->server || !job || !session) {
    return 0;
  }
  /*

   // legacy route until I finish inspecting
      if (!app.inbound.crypto.validate_signature(session, &pkt)) {
    LOGE("[daemon3.payload] Dropping structured packet due to invalid signature (user_id=%u action_id=%u)\n",
         job->user_id,
         job->action_id);
    return 0;
  }
   */
  if (!job->authorized) {
    LOGW("[daemon3.payload] Dropping unauthorized job (user_id=%u action_id=%u)\n",
         job->user_id,
         job->action_id);
    return 0;
  }

  if (job->wire_version == 0u) {
    LOGD("[daemon3.payload] Routing raw unstructured payload to fallback handler\n");
    app.payload.unstructured.handle(listener,
                                    job->payload_buffer,
                                    job->payload_len,
                                    job->ip);
    return 1;
  }

  if (!app.daemon3.request.bind_user_action(listener, job, session, &user, &action)) {
    return 0;
  }

  if (!app.daemon3.policy.enforce(listener, job, user, action)) {
    return 0;
  }

  return app_daemon3_payload_dispatch_action(listener, job, session, user, action, job);
}

static int app_daemon3_payload_stage_reply(
    AppRuntimeListenerState *listener,
    SiglatchOpenSSLSession *session,
    AppConnectionJob *job,
    const AppActionReply *reply) {
  size_t response_len = 0;

  if (!listener || !session || !job || !reply) {
    return 0;
  }

  job->should_reply = reply->should_reply ? 1 : 0;
  job->response_len = 0;
  memset(job->response_buffer, 0, sizeof(job->response_buffer));

  if (!reply->should_reply) {
    return 1;
  }

  (void)listener;
  (void)session;

  if (!app_daemon3_payload_build_semantic_reply(job,
                                                reply,
                                                job->response_buffer,
                                                sizeof(job->response_buffer),
                                                &response_len)) {
    return 0;
  }

  job->response_len = response_len;
  return 1;
}

static int app_daemon3_payload_dispatch_action(
    AppRuntimeListenerState *listener,
    const AppConnectionJob *job,
    SiglatchOpenSSLSession *session,
    const siglatch_user *user,
    const siglatch_action *action,
    AppConnectionJob *out_job) {
  AppBuiltinContext builtin_ctx = {0};
  AppBuiltinContext *builtin_ctx_ptr = &builtin_ctx;
  AppActionReply builtin_reply = {0};
  AppObjectContext object_ctx = {0};
  AppActionReply object_reply = {0};
  AppActionReply shell_reply = {0};
  char payload_b64[512] = {0};
  char user_id_str[16];
  char action_id_str[16];
  char encrypted_str[8];
  char *argv[8] = {0};
  int shell_exit_code = 127;
  int ok = 0;

  LOGD("[daemon3.payload] Routing normalized unit to action handlers\n");

  if (!listener || !listener->server || !job || !session || !user || !action || !out_job) {
    LOGE("[daemon3.payload] Invalid arguments to dispatch_action\n");
    return 0;
  }

  if (app.builtin.is_action(action)) {
    const siglatch_user *reply_user = user;

    if (!app.builtin.build_context(
            builtin_ctx_ptr, listener, job, session, user, action, job->ip)) {
      LOGE("[daemon3.payload] Failed to build builtin context for action (%s)\n", action->name);
      return 0;
    }

    LOGD("[daemon3.payload] Routing to builtin: %s (Ip=%s, User=%s, Action=%s)\n",
         action->builtin,
         job->ip,
         user->name,
         action->name);

    ok = app.builtin.handle(builtin_ctx_ptr, &builtin_reply);
    if (!ok) {
      if (builtin_reply.should_reply) {
        reply_user = app.config.user_by_id(job->user_id);
        if (!reply_user || !app.inbound.crypto.assign_session_to_user(session, reply_user)) {
          LOGE("[daemon3.payload] Failed to rebuild user crypto context for builtin error reply (%s)\n",
               action->name);
          return 0;
        }
      }

      if (!app_daemon3_payload_stage_reply(listener, session, out_job, &builtin_reply)) {
        LOGE("[daemon3.payload] Builtin error reply stage failed for action (%s)\n", action->name);
        return 0;
      }
      return 0;
    }

    if (builtin_reply.should_reply) {
      reply_user = app.config.user_by_id(job->user_id);
      if (!reply_user || !app.inbound.crypto.assign_session_to_user(session, reply_user)) {
        LOGE("[daemon3.payload] Failed to rebuild user crypto context for builtin reply (%s)\n",
             action->name);
        return 0;
      }
    }

    if (!app_daemon3_payload_stage_reply(listener, session, out_job, &builtin_reply)) {
      LOGE("[daemon3.payload] Builtin reply stage failed for action (%s)\n", action->name);
      return 0;
    }

    return 1;
  }

  if (action->handler == SL_ACTION_HANDLER_STATIC ||
      action->handler == SL_ACTION_HANDLER_DYNAMIC) {
    if (!app.object.build_context(
            &object_ctx, listener, job, session, user, action, job->ip)) {
      LOGE("[daemon3.payload] Failed to build object context for action (%s)\n", action->name);
      return 0;
    }

    LOGD("[daemon3.payload] Routing to %s object: %s (Ip=%s, User=%s, Action=%s)\n",
         action->handler == SL_ACTION_HANDLER_STATIC ? "static" : "dynamic",
         action->object,
         job->ip,
         user->name,
         action->name);

    if (action->handler == SL_ACTION_HANDLER_STATIC) {
      ok = app.object.run_static(&object_ctx, &object_reply);
    } else {
      ok = app.object.run_dynamic(&object_ctx, &object_reply);
    }

    if (!app_daemon3_payload_stage_reply(listener, session, out_job, &object_reply)) {
      LOGE("[daemon3.payload] Object reply stage failed for action (%s)\n", action->name);
      return 0;
    }

    return ok;
  }

  if (action->constructor[0] == '\0') {
    LOGW("[daemon3.payload] Shell action ID %u has no constructor\n", job->action_id);
    return 0;
  }

  // $fixup: this scratch buffer is still capped at 512 bytes; widen it when
  // shell payload handling is revisited.
  base64_encode(job->payload_buffer, job->payload_len, payload_b64, sizeof(payload_b64));

  snprintf(user_id_str, sizeof(user_id_str), "%u", job->user_id);
  snprintf(action_id_str, sizeof(action_id_str), "%u", job->action_id);
  snprintf(encrypted_str, sizeof(encrypted_str), "%d", listener->server->secure ? 1 : 0);

  argv[0] = (char *)job->ip;
  argv[1] = user_id_str;
  argv[2] = (char *)user->name;
  argv[3] = action_id_str;
  argv[4] = (char *)action->name;
  argv[5] = encrypted_str;
  argv[6] = payload_b64;
  argv[7] = NULL;

  LOGD("[daemon3.payload] Routing to script: %s (Ip=%s, User=%s, Action=%s, execSplit=%d)\n",
       action->constructor,
       job->ip,
       user->name,
       action->name,
       action->exec_split);

  if (!app.payload.run_shell_wait(
          action->constructor,
          7,
          argv,
          action->exec_split,
          action->run_as[0] ? action->run_as : NULL,
          &shell_exit_code)) {
    app.payload.reply.set(&shell_reply, 0, "ERROR %s exec_failed", action->name);
    if (!app_daemon3_payload_stage_reply(listener, session, out_job, &shell_reply)) {
      LOGE("[daemon3.payload] Shell error reply stage failed for action (%s)\n", action->name);
    }
    return 0;
  }

  if (shell_exit_code == 0) {
    app.payload.reply.set(&shell_reply, 1, "OK %s", action->name);
  } else if (shell_exit_code == 126 && action->run_as[0] != '\0') {
    app.payload.reply.set(&shell_reply, 0, "ERROR %s run_as_failed", action->name);
  } else {
    app.payload.reply.set(&shell_reply, 0, "ERROR %s rc=%d", action->name, shell_exit_code);
  }

  if (!app_daemon3_payload_stage_reply(listener, session, out_job, &shell_reply)) {
    LOGE("[daemon3.payload] Shell reply stage failed for action (%s)\n", action->name);
    return 0;
  }

  return shell_exit_code == 0;
}

static const AppDaemon3PayloadLib app_payload_instance = {
  .init = app_daemon3_payload_init,
  .shutdown = app_daemon3_payload_shutdown,
  .consume = app_daemon3_payload_consume
};

const AppDaemon3PayloadLib *get_app_daemon3_payload_lib(void) {
  return &app_payload_instance;
}
