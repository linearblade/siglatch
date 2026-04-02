/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_KNOCK_APP_COMMAND_H
#define SIGLATCH_KNOCK_APP_COMMAND_H

#include <stdint.h>
#include "opts/contract.h"

typedef enum {
  APP_CMD_HELP = 0,
  APP_CMD_TRANSMIT,
  APP_CMD_ALIAS,
  APP_CMD_OUTPUT_MODE_DEFAULT,
  APP_CMD_SEND_FROM_DEFAULT,
  APP_CMD_ERROR
} AppCommandType;

typedef enum {
  APP_ALIAS_OP_INVALID = 0,
  APP_ALIAS_OP_SET_USER,
  APP_ALIAS_OP_SET_ACTION,
  APP_ALIAS_OP_SHOW_USER,
  APP_ALIAS_OP_SHOW_USER_ALL,
  APP_ALIAS_OP_DELETE_USER,
  APP_ALIAS_OP_DELETE_USER_MAP,
  APP_ALIAS_OP_SHOW_ACTION,
  APP_ALIAS_OP_SHOW_ACTION_ALL,
  APP_ALIAS_OP_DELETE_ACTION,
  APP_ALIAS_OP_DELETE_ACTION_MAP,
  APP_ALIAS_OP_SHOW_HOST,
  APP_ALIAS_OP_SHOW_HOSTS,
  APP_ALIAS_OP_DELETE_HOST
} AppAliasOp;

typedef struct {
  AppAliasOp op;
  char host[256];
  char name[128];
  uint32_t id;
  int confirm_yes;
  int output_mode;
} AppAliasCommand;

typedef struct {
  int mode;
} AppOutputModeDefaultCommand;

typedef struct {
  int clear;
  char host[256];
  char user[128];
  char ip[64];
} AppSendFromDefaultCommand;

typedef struct AppCommand {
  AppCommandType type;
  int ok;
  int exit_code;
  int dump_requested;
  char error[256];
  union {
    Opts transmit;
    AppAliasCommand alias;
    AppOutputModeDefaultCommand outdef;
    AppSendFromDefaultCommand send_from_default;
  } as;
} AppCommand;

#endif
