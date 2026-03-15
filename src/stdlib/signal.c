/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "signal.h"

#include <string.h>
#include <unistd.h>

static SignalState *g_signal_state = NULL;
static struct sigaction g_signal_previous[LIB_SIGNAL_MAX_SIGNALS];
static int g_signal_installed[LIB_SIGNAL_MAX_SIGNALS];
static size_t g_signal_installed_count = 0;
static int g_signal_set_should_exit = 1;
static SignalPolicy g_signal_policy = LIB_SIGNAL_POLICY_GRACEFUL;
static const int g_signal_default_set[] = {SIGINT, SIGTERM};

static void lib_signal_handle(int sig) {
  SignalState *state = g_signal_state;

  if (!state) {
    return;
  }

  state->last_signal = sig;
  state->pending = 1;
  if (state->delivery_count < ((sig_atomic_t)~0 >> 1)) {
    state->delivery_count++;
  }

  if (g_signal_policy == LIB_SIGNAL_POLICY_HARD_EXIT) {
    _exit(128 + sig);
  }

  if (g_signal_policy == LIB_SIGNAL_POLICY_GRACEFUL_THEN_HARD &&
      state->delivery_count > 1) {
    _exit(128 + sig);
  }

  if (g_signal_set_should_exit) {
    state->should_exit = 1;
  }

  if (state->wake_write_fd >= 0) {
    unsigned char byte = (unsigned char)sig;
    (void)write(state->wake_write_fd, &byte, 1);
  }
}

int lib_signal_init(void) {
  return 1;
}

void lib_signal_shutdown(void) {
  lib_signal_uninstall();
}

void lib_signal_state_reset(SignalState *state) {
  if (!state) {
    return;
  }

  *state = (SignalState){0};
  state->wake_write_fd = -1;
}

int lib_signal_install(SignalState *state, const SignalInstallConfig *cfg) {
  struct sigaction sa;
  const int *signals = g_signal_default_set;
  size_t signal_count = sizeof(g_signal_default_set) / sizeof(g_signal_default_set[0]);
  size_t i = 0;

  if (!state) {
    return 0;
  }

  if (cfg && cfg->signals && cfg->signal_count > 0) {
    signals = cfg->signals;
    signal_count = cfg->signal_count;
  } else if (cfg && cfg->signal_count > 0 && !cfg->signals) {
    return 0;
  }

  if (signal_count == 0 || signal_count > LIB_SIGNAL_MAX_SIGNALS) {
    return 0;
  }

  lib_signal_uninstall();
  lib_signal_state_reset(state);

  state->wake_write_fd = cfg ? cfg->wake_write_fd : -1;
  g_signal_state = state;
  g_signal_set_should_exit = (!cfg || cfg->set_should_exit) ? 1 : 0;
  g_signal_policy = cfg ? cfg->policy : LIB_SIGNAL_POLICY_GRACEFUL;

  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = lib_signal_handle;
  sigemptyset(&sa.sa_mask);

  for (i = 0; i < signal_count; ++i) {
    if (sigaction(signals[i], &sa, &g_signal_previous[i]) != 0) {
      while (i > 0) {
        --i;
        sigaction(g_signal_installed[i], &g_signal_previous[i], NULL);
      }
      g_signal_state = NULL;
      g_signal_installed_count = 0;
      return 0;
    }

    g_signal_installed[i] = signals[i];
  }

  g_signal_installed_count = signal_count;
  return 1;
}

void lib_signal_uninstall(void) {
  size_t i = 0;

  for (i = 0; i < g_signal_installed_count; ++i) {
    sigaction(g_signal_installed[i], &g_signal_previous[i], NULL);
    g_signal_installed[i] = 0;
    memset(&g_signal_previous[i], 0, sizeof(g_signal_previous[i]));
  }

  g_signal_installed_count = 0;
  g_signal_state = NULL;
  g_signal_set_should_exit = 1;
  g_signal_policy = LIB_SIGNAL_POLICY_GRACEFUL;
}

int lib_signal_should_exit(const SignalState *state) {
  if (!state) {
    return 0;
  }

  return state->should_exit ? 1 : 0;
}

int lib_signal_last_signal(const SignalState *state) {
  if (!state) {
    return 0;
  }

  return (int)state->last_signal;
}

int lib_signal_take_last_signal(SignalState *state) {
  int sig = 0;

  if (!state) {
    return 0;
  }

  sig = (int)state->last_signal;
  state->last_signal = 0;
  state->pending = 0;
  return sig;
}

int lib_signal_has_pending(const SignalState *state) {
  if (!state) {
    return 0;
  }

  return state->pending ? 1 : 0;
}

void lib_signal_clear_pending(SignalState *state) {
  if (!state) {
    return;
  }

  state->last_signal = 0;
  state->pending = 0;
}

void lib_signal_request_exit(SignalState *state) {
  if (!state) {
    return;
  }

  state->should_exit = 1;
  state->pending = 1;
}

static const SignalLib lib_signal_instance = {
  .init = lib_signal_init,
  .shutdown = lib_signal_shutdown,
  .state_reset = lib_signal_state_reset,
  .install = lib_signal_install,
  .uninstall = lib_signal_uninstall,
  .should_exit = lib_signal_should_exit,
  .last_signal = lib_signal_last_signal,
  .take_last_signal = lib_signal_take_last_signal,
  .has_pending = lib_signal_has_pending,
  .clear_pending = lib_signal_clear_pending,
  .request_exit = lib_signal_request_exit
};

const SignalLib *get_lib_signal(void) {
  return &lib_signal_instance;
}
