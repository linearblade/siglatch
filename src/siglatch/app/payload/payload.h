/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_SERVER_APP_PAYLOAD_H
#define SIGLATCH_SERVER_APP_PAYLOAD_H

#include "digest/digest.h"
#include "reply.h"
#include "unstructured.h"

typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
  int (*run_shell)(const char *script_path, int argc, char *argv[], int exec_split,
                   const char *run_as);
  int (*run_shell_wait)(const char *script_path, int argc, char *argv[], int exec_split,
                        const char *run_as, int *out_exit_code);
  int (*run_shell_capture)(const char *script_path,
                           int argc,
                           char *argv[],
                           int exec_split,
                           const char *run_as,
                           uint8_t *out_buf,
                           size_t out_cap,
                           size_t *out_len,
                           int *out_exit_code);
  AppPayloadDigestLib digest;
  AppPayloadReplyLib reply;
  AppPayloadUnstructuredLib unstructured;
} AppPayloadLib;

const AppPayloadLib *get_app_payload_lib(void);

#endif
