/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "payload.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../../lib.h"

static int app_payload_parse_cmd(
    const char *input,
    size_t input_len,
    char *cmd,
    size_t cmd_size,
    char *arg,
    size_t arg_size);
static pid_t app_payload_fork_exec(const char *cmd, char *const argv[], const char *run_as);
static int app_payload_waitpid_exit_code(pid_t pid, int *out_exit_code);
static int app_payload_run_shell_wait(
    const char *script_path,
    int argc,
    char *argv[],
    int exec_split,
    const char *run_as,
    int *out_exit_code);

static int app_payload_init(void) {
  if (!app_payload_codec_init()) {
    return 0;
  }

  if (!app_payload_digest_init()) {
    app_payload_codec_shutdown();
    return 0;
  }

  if (!app_payload_structured_init()) {
    app_payload_digest_shutdown();
    app_payload_codec_shutdown();
    return 0;
  }

  if (!app_payload_unstructured_init()) {
    app_payload_structured_shutdown();
    app_payload_digest_shutdown();
    app_payload_codec_shutdown();
    return 0;
  }

  return 1;
}

static void app_payload_shutdown(void) {
  app_payload_unstructured_shutdown();
  app_payload_structured_shutdown();
  app_payload_digest_shutdown();
  app_payload_codec_shutdown();
}

static int app_payload_run_shell(
    const char *script_path,
    int argc,
    char *argv[],
    int exec_split,
    const char *run_as) {
  char *final_argv[argc + 3];
  int i = 0;
  pid_t pid = -1;

  if (!script_path || argc < 1 || !argv || !argv[0]) {
    LOGE("[runShell] Invalid parameters\n");
    return 0;
  }

  if (exec_split && strchr(script_path, ' ') != NULL) {
    char cmd[128] = {0};
    char script[256] = {0};

    if (!app_payload_parse_cmd(
            script_path, strlen(script_path), cmd, sizeof(cmd), script, sizeof(script))) {
      LOGE("[runShell] Failed to parse constructor: %s\n", script_path);
      return 0;
    }

    final_argv[i++] = cmd;
    if (script[0] != '\0' && strcmp(cmd, script) != 0) {
      final_argv[i++] = script;
    }

    for (int j = 0; j < argc; ++j) {
      final_argv[i++] = argv[j];
    }

    final_argv[i] = NULL;
    pid = app_payload_fork_exec(cmd, final_argv, run_as);
  } else {
    final_argv[0] = (char *)script_path;
    for (int j = 0; j < argc; ++j) {
      final_argv[j + 1] = argv[j];
    }
    final_argv[argc + 1] = NULL;
    pid = app_payload_fork_exec(script_path, final_argv, run_as);
  }

  if (pid > 0) {
    LOGT("[runShell] Spawned child PID: %d\n", pid);
    return 1;
  } else {
    LOGPERR("fork");
    return 0;
  }
}

static int app_payload_run_shell_wait(
    const char *script_path,
    int argc,
    char *argv[],
    int exec_split,
    const char *run_as,
    int *out_exit_code) {
  char *final_argv[argc + 3];
  int i = 0;
  pid_t pid = -1;

  if (!script_path || argc < 1 || !argv || !argv[0] || !out_exit_code) {
    LOGE("[runShellWait] Invalid parameters\n");
    return 0;
  }

  *out_exit_code = 127;

  if (exec_split && strchr(script_path, ' ') != NULL) {
    char cmd[128] = {0};
    char script[256] = {0};

    if (!app_payload_parse_cmd(
            script_path, strlen(script_path), cmd, sizeof(cmd), script, sizeof(script))) {
      LOGE("[runShellWait] Failed to parse constructor: %s\n", script_path);
      return 0;
    }

    final_argv[i++] = cmd;
    if (script[0] != '\0' && strcmp(cmd, script) != 0) {
      final_argv[i++] = script;
    }

    for (int j = 0; j < argc; ++j) {
      final_argv[i++] = argv[j];
    }

    final_argv[i] = NULL;
    pid = app_payload_fork_exec(cmd, final_argv, run_as);
  } else {
    final_argv[0] = (char *)script_path;
    for (int j = 0; j < argc; ++j) {
      final_argv[j + 1] = argv[j];
    }
    final_argv[argc + 1] = NULL;
    pid = app_payload_fork_exec(script_path, final_argv, run_as);
  }

  if (pid < 0) {
    LOGPERR("fork");
    return 0;
  }

  LOGT("[runShellWait] Spawned child PID: %d\n", pid);
  return app_payload_waitpid_exit_code(pid, out_exit_code);
}

static int app_payload_parse_cmd(
    const char *input,
    size_t input_len,
    char *cmd,
    size_t cmd_size,
    char *arg,
    size_t arg_size) {
  size_t i = 0;
  size_t cmd_len = 0;
  size_t arg_len = 0;

  if (!input || !cmd || !arg || cmd_size == 0 || arg_size == 0) {
    return 0;
  }

  while (i < input_len && input[i] == ' ') {
    i++;
  }

  while (i + cmd_len < input_len && input[i + cmd_len] != ' ') {
    cmd_len++;
  }

  if (cmd_len >= cmd_size) {
    return 0;
  }

  strncpy(cmd, input + i, cmd_len);
  cmd[cmd_len] = '\0';

  i += cmd_len;
  while (i < input_len && input[i] == ' ') {
    i++;
  }

  arg_len = input_len - i;
  if (arg_len >= arg_size) {
    arg_len = arg_size - 1;
  }

  strncpy(arg, input + i, arg_len);
  arg[arg_len] = '\0';

  return 1;
}

static pid_t app_payload_fork_exec(const char *cmd, char *const argv[], const char *run_as) {
  pid_t pid = fork();
  if (pid == 0) {
    if (run_as && run_as[0] != '\0') {
      if (!lib.process.user.drop_to_name(run_as)) {
        LOGE("[runShell] Failed to drop privileges to user '%s'\n", run_as);
        LOGPERR("drop_to_name");
        _exit(126);
      }
    }

    execv(cmd, argv);
    LOGPERR("execv");
    _exit(127);
  } else if (pid > 0) {
    return pid;
  } else {
    return -1;
  }
}

static int app_payload_waitpid_exit_code(pid_t pid, int *out_exit_code) {
  int status = 0;
  pid_t waited = -1;

  if (pid <= 0 || !out_exit_code) {
    return 0;
  }

  do {
    waited = waitpid(pid, &status, 0);
  } while (waited < 0 && errno == EINTR);

  if (waited != pid) {
    LOGPERR("waitpid");
    return 0;
  }

  if (WIFEXITED(status)) {
    *out_exit_code = WEXITSTATUS(status);
    return 1;
  }

  if (WIFSIGNALED(status)) {
    *out_exit_code = 128 + WTERMSIG(status);
    return 1;
  }

  *out_exit_code = 127;
  return 1;
}

static const AppPayloadLib app_payload_instance = {
  .init = app_payload_init,
  .shutdown = app_payload_shutdown,
  .run_shell = app_payload_run_shell,
  .run_shell_wait = app_payload_run_shell_wait,
  .codec = {
    .init = app_payload_codec_init,
    .shutdown = app_payload_codec_shutdown,
    .pack = app_payload_codec_pack,
    .unpack = app_payload_codec_unpack,
    .validate = app_payload_codec_validate,
    .deserialize = app_payload_codec_deserialize,
    .deserialize_strerror = app_payload_codec_deserialize_strerror
  },
  .digest = {
    .init = app_payload_digest_init,
    .shutdown = app_payload_digest_shutdown,
    .generate = app_payload_digest_generate,
    .generate_oneshot = app_payload_digest_generate_oneshot,
    .sign = app_payload_digest_sign,
    .validate = app_payload_digest_validate
  },
  .structured = {
    .init = app_payload_structured_init,
    .shutdown = app_payload_structured_shutdown,
    .handle = app_payload_structured_handle
  },
  .unstructured = {
    .init = app_payload_unstructured_init,
    .shutdown = app_payload_unstructured_shutdown,
    .handle = app_payload_unstructured_handle
  }
};

const AppPayloadLib *get_app_payload_lib(void) {
  return &app_payload_instance;
}
