/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#ifndef SIGLATCH_STDLIB_SIGNAL_H
#define SIGLATCH_STDLIB_SIGNAL_H

#include <signal.h>
#include <stddef.h>

#define LIB_SIGNAL_MAX_SIGNALS 16

typedef struct {
  volatile sig_atomic_t should_exit;
  volatile sig_atomic_t last_signal;
  volatile sig_atomic_t pending;
  volatile sig_atomic_t delivery_count;
  int wake_write_fd;
} SignalState;

typedef enum {
  LIB_SIGNAL_POLICY_GRACEFUL = 0,
  LIB_SIGNAL_POLICY_GRACEFUL_THEN_HARD = 1,
  LIB_SIGNAL_POLICY_HARD_EXIT = 2
} SignalPolicy;

typedef struct {
  const int *signals;
  size_t signal_count;
  int set_should_exit;
  int wake_write_fd;
  SignalPolicy policy;
} SignalInstallConfig;

typedef struct {
  int (*init)(void);
  void (*shutdown)(void);
  void (*state_reset)(SignalState *state);
  int (*install)(SignalState *state, const SignalInstallConfig *cfg);
  void (*uninstall)(void);
  int (*should_exit)(const SignalState *state);
  int (*last_signal)(const SignalState *state);
  int (*take_last_signal)(SignalState *state);
  int (*has_pending)(const SignalState *state);
  void (*clear_pending)(SignalState *state);
  void (*request_exit)(SignalState *state);
} SignalLib;

int lib_signal_init(void);
void lib_signal_shutdown(void);
void lib_signal_state_reset(SignalState *state);
int lib_signal_install(SignalState *state, const SignalInstallConfig *cfg);
void lib_signal_uninstall(void);
int lib_signal_should_exit(const SignalState *state);
int lib_signal_last_signal(const SignalState *state);
int lib_signal_take_last_signal(SignalState *state);
int lib_signal_has_pending(const SignalState *state);
void lib_signal_clear_pending(SignalState *state);
void lib_signal_request_exit(SignalState *state);
const SignalLib *get_lib_signal(void);

#endif
