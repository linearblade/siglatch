/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "object.h"

#include <dlfcn.h>
#include <errno.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../app.h"
#include "../../lib.h"

typedef struct {
  const char *name;
  AppObjectHandlerFn handle;
} AppStaticObjectEntry;

typedef struct {
  int handler_ok;
  AppActionReply reply;
} AppObjectChildResult;

static int app_object_init(void);
static void app_object_shutdown(void);
static int app_object_supports_static(const char *name);
static int app_object_supports_dynamic(const char *path, const char *name);
static int app_object_build_context(
    AppObjectContext *out,
    AppRuntimeListenerState *listener,
    const KnockPacket *packet,
    SiglatchOpenSSLSession *session,
    const siglatch_user *user,
    const siglatch_action *action,
    const char *ip_addr);
static int app_object_run_static(const AppObjectContext *ctx, AppActionReply *reply);
static int app_object_run_dynamic(const AppObjectContext *ctx, AppActionReply *reply);

static const AppStaticObjectEntry *app_object_lookup_static(const char *name);
static int app_object_run_static_child(const AppObjectContext *ctx, AppObjectChildResult *out_result);
static int app_object_run_dynamic_child(const AppObjectContext *ctx, AppObjectChildResult *out_result);
static int app_object_run_forked(const AppObjectContext *ctx,
                                 int is_dynamic,
                                 AppActionReply *reply);
static int app_object_reply_pipe_write(int fd, const void *buf, size_t len);
static int app_object_reply_pipe_read(int fd, void *buf, size_t len);

static const AppStaticObjectEntry app_static_objects[] = {
  {"test_static", app_object_test_static_handle},
  {"sample_blurt_static", siglatch_object_sample_blurt_static_handle}
};

static int app_object_init(void) {
  if (!app_object_test_static_init()) {
    return 0;
  }

  if (!siglatch_object_sample_blurt_static_init()) {
    app_object_test_static_shutdown();
    return 0;
  }

  return 1;
}

static void app_object_shutdown(void) {
  siglatch_object_sample_blurt_static_shutdown();
  app_object_test_static_shutdown();
}

static int app_object_supports_static(const char *name) {
  return app_object_lookup_static(name) != NULL;
}

static int app_object_supports_dynamic(const char *path, const char *name) {
  void *handle = NULL;
  void *symbol = NULL;

  if (!path || path[0] == '\0' || !name || name[0] == '\0') {
    return 0;
  }

  handle = dlopen(path, RTLD_LAZY | RTLD_LOCAL);
  if (!handle) {
    return 0;
  }

  symbol = dlsym(handle, name);
  dlclose(handle);
  return symbol != NULL;
}

static int app_object_build_context(
    AppObjectContext *out,
    AppRuntimeListenerState *listener,
    const KnockPacket *packet,
    SiglatchOpenSSLSession *session,
    const siglatch_user *user,
    const siglatch_action *action,
    const char *ip_addr) {
  if (!out || !listener || !packet || !session || !user || !action || !ip_addr) {
    return 0;
  }

  *out = (AppObjectContext){
    .listener = listener,
    .packet = packet,
    .session = session,
    .user = user,
    .action = action,
    .ip_addr = ip_addr
  };

  return 1;
}

static int app_object_run_static(const AppObjectContext *ctx, AppActionReply *reply) {
  return app_object_run_forked(ctx, 0, reply);
}

static int app_object_run_dynamic(const AppObjectContext *ctx, AppActionReply *reply) {
  return app_object_run_forked(ctx, 1, reply);
}

static const AppStaticObjectEntry *app_object_lookup_static(const char *name) {
  size_t i = 0;

  if (!name || name[0] == '\0') {
    return NULL;
  }

  for (i = 0; i < sizeof(app_static_objects) / sizeof(app_static_objects[0]); ++i) {
    if (strcmp(app_static_objects[i].name, name) == 0) {
      return &app_static_objects[i];
    }
  }

  return NULL;
}

static int app_object_run_static_child(const AppObjectContext *ctx, AppObjectChildResult *out_result) {
  const AppStaticObjectEntry *entry = NULL;

  if (!ctx || !ctx->action || !out_result) {
    return 0;
  }

  entry = app_object_lookup_static(ctx->action->object);
  if (!entry || !entry->handle) {
    app_action_reply_set(&out_result->reply, 0, "ERROR %s object_not_found", ctx->action->name);
    return 0;
  }

  out_result->handler_ok = entry->handle(ctx, &out_result->reply) ? 1 : 0;
  return out_result->handler_ok;
}

static int app_object_run_dynamic_child(const AppObjectContext *ctx, AppObjectChildResult *out_result) {
  void *handle = NULL;
  AppObjectHandlerFn handler = NULL;
  int ok = 0;
  const char *dl_error = NULL;

  if (!ctx || !ctx->action || !out_result) {
    return 0;
  }

  handle = dlopen(ctx->action->object_path, RTLD_LAZY | RTLD_LOCAL);
  if (!handle) {
    dl_error = dlerror();
    app_action_reply_set(&out_result->reply, 0, "ERROR %s object_load_failed", ctx->action->name);
    LOGE("[object] dlopen failed for %s: %s\n",
         ctx->action->object_path,
         dl_error ? dl_error : "(unknown)");
    return 0;
  }

  handler = (AppObjectHandlerFn)dlsym(handle, ctx->action->object);
  if (!handler) {
    dl_error = dlerror();
    app_action_reply_set(&out_result->reply, 0, "ERROR %s symbol_not_found", ctx->action->name);
    LOGE("[object] dlsym failed for %s in %s: %s\n",
         ctx->action->object,
         ctx->action->object_path,
         dl_error ? dl_error : "(unknown)");
    dlclose(handle);
    return 0;
  }

  ok = handler(ctx, &out_result->reply) ? 1 : 0;
  out_result->handler_ok = ok;
  dlclose(handle);
  return ok;
}

static int app_object_run_forked(const AppObjectContext *ctx,
                                 int is_dynamic,
                                 AppActionReply *reply) {
  int pipefd[2] = {-1, -1};
  pid_t pid = -1;
  AppObjectChildResult child_result = {0};
  int read_ok = 0;

  if (!ctx || !ctx->action || !reply) {
    return 0;
  }

  app_action_reply_reset(reply);

  if (pipe(pipefd) != 0) {
    LOGPERR("pipe");
    app_action_reply_set(reply, 0, "ERROR %s object_ipc_failed", ctx->action->name);
    return 0;
  }

  pid = fork();
  if (pid < 0) {
    LOGPERR("fork");
    close(pipefd[0]);
    close(pipefd[1]);
    app_action_reply_set(reply, 0, "ERROR %s object_exec_failed", ctx->action->name);
    return 0;
  }

  if (pid == 0) {
    int ok = 0;

    close(pipefd[0]);
    memset(&child_result, 0, sizeof(child_result));

    if (ctx->action->run_as[0] != '\0' &&
        !lib.process.user.drop_to_name(ctx->action->run_as)) {
      LOGE("[object] Failed to drop privileges to user '%s'\n", ctx->action->run_as);
      LOGPERR("drop_to_name");
      app_action_reply_set(&child_result.reply, 0, "ERROR %s run_as_failed", ctx->action->name);
      child_result.handler_ok = 0;
      app_object_reply_pipe_write(pipefd[1], &child_result, sizeof(child_result));
      close(pipefd[1]);
      _exit(126);
    }

    if (is_dynamic) {
      ok = app_object_run_dynamic_child(ctx, &child_result);
    } else {
      ok = app_object_run_static_child(ctx, &child_result);
    }

    if (!child_result.reply.should_reply) {
      if (ok) {
        app_action_reply_set(&child_result.reply, 1, "OK %s", ctx->action->name);
      } else {
        app_action_reply_set(&child_result.reply, 0, "ERROR %s object_failed", ctx->action->name);
      }
    }

    child_result.handler_ok = ok ? 1 : 0;
    app_object_reply_pipe_write(pipefd[1], &child_result, sizeof(child_result));
    close(pipefd[1]);
    _exit(ok ? 0 : 1);
  }

  close(pipefd[1]);
  read_ok = app_object_reply_pipe_read(pipefd[0], &child_result, sizeof(child_result));
  close(pipefd[0]);

  while (waitpid(pid, NULL, 0) < 0 && errno == EINTR) {
  }

  if (!read_ok) {
    app_action_reply_set(reply, 0, "ERROR %s object_ipc_failed", ctx->action->name);
    return 0;
  }

  *reply = child_result.reply;
  return child_result.handler_ok;
}

static int app_object_reply_pipe_write(int fd, const void *buf, size_t len) {
  const uint8_t *cursor = (const uint8_t *)buf;
  size_t written_total = 0;

  while (written_total < len) {
    ssize_t written = write(fd, cursor + written_total, len - written_total);
    if (written < 0) {
      if (errno == EINTR) {
        continue;
      }
      return 0;
    }
    written_total += (size_t)written;
  }

  return 1;
}

static int app_object_reply_pipe_read(int fd, void *buf, size_t len) {
  uint8_t *cursor = (uint8_t *)buf;
  size_t read_total = 0;

  while (read_total < len) {
    ssize_t chunk = read(fd, cursor + read_total, len - read_total);
    if (chunk == 0) {
      return 0;
    }
    if (chunk < 0) {
      if (errno == EINTR) {
        continue;
      }
      return 0;
    }
    read_total += (size_t)chunk;
  }

  return 1;
}

static const AppObjectLib app_object_instance = {
  .init = app_object_init,
  .shutdown = app_object_shutdown,
  .supports_static = app_object_supports_static,
  .supports_dynamic = app_object_supports_dynamic,
  .build_context = app_object_build_context,
  .run_static = app_object_run_static,
  .run_dynamic = app_object_run_dynamic
};

const AppObjectLib *get_app_object_lib(void) {
  return &app_object_instance;
}
