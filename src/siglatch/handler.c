/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */


#define MAX_SEQ 3
#define MAX_CLIENTS 64

const char *SEQUENCE[MAX_SEQ] = { "step1", "step2", "step3" };



typedef struct {
  char ip[INET_ADDRSTRLEN];
  int progress;
  time_t last_time;
} ClientState;

ClientState clients[MAX_CLIENTS];

void log_message(const char *msg) {
  FILE *f = fopen("/tmp/knocker.log", "a");
  if (f) {
    time_t now = time(NULL);
    fprintf(f, "[%ld] %s\n", now, msg);
    fclose(f);
  }
}

int find_or_create_client(const char *ip) {
  time_t now = time(NULL);
  for (int i = 0; i < MAX_CLIENTS; ++i) {
    if (strcmp(clients[i].ip, ip) == 0)
      return i;
    if (clients[i].ip[0] == '\0') {
      strncpy(clients[i].ip, ip, sizeof(clients[i].ip));
      clients[i].progress = 0;
      clients[i].last_time = now;
      return i;
    }
  }
  return -1;
}

void trigger_dummy_action(const char *ip) {
  char msg[256];
  snprintf(msg, sizeof(msg), "VALID SEQUENCE FROM %s", ip);
  log_message(msg);
}


void handle_packet(const char *msg, const char *ip) {
  char logbuf[256];
  
  // 🔹 Log every packet received
  snprintf(logbuf, sizeof(logbuf), "Received from %s: '%s'", ip, msg);
  log_message(logbuf);
  
  int idx = find_or_create_client(ip);
  if (idx == -1) {
    snprintf(logbuf, sizeof(logbuf), "No slot available for IP %s", ip);
    log_message(logbuf);
    return;
  }

  ClientState *state = &clients[idx];
  time_t now = time(NULL);

  // 🔹 Reset progress if too much time has passed
  if (now - state->last_time > 10) {
    snprintf(logbuf, sizeof(logbuf), "Timeout for %s, resetting sequence", ip);
    log_message(logbuf);
    state->progress = 0;
  }
  state->last_time = now;

  snprintf(logbuf, sizeof(logbuf),
	   "Client %s: Expected '%s', Got '%s'",
	   ip, SEQUENCE[state->progress], msg);
  log_message(logbuf);

  // 🔹 Sequence match logic
  if (strcmp(msg, SEQUENCE[state->progress]) == 0) {
    state->progress++;
    snprintf(logbuf, sizeof(logbuf),
	     "Match for %s, Progress: %d", ip, state->progress);
    log_message(logbuf);

    if (state->progress == MAX_SEQ) {
      log_message("Sequence complete! Triggering action.");
      trigger_dummy_action(ip);
      state->progress = 0;
    }
  } else {
    log_message("Mismatch, resetting sequence.");
    state->progress = 0;
  }
}
