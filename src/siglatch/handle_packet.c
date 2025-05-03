/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "handle_packet.h"
#include "lib.h" 
#include "../stdlib/base64.h"
#include "../stdlib/utils.h"
#include "config.h"
#include "decrypt.h"

// Forward declaration
void handle_structured_payload(
			       const KnockPacket *pkt,
			       SiglatchOpenSSLSession *session,
			       const char *ip
			       );

int runShell(const char *script_path, int argc, char *argv[],int exec_split);
static int validatePayload(const KnockPacket *pkt);
static int handle_packet( const KnockPacket *pkt, const char *ip_addr,  int valid_signature) ;
static int parseCmd(const char *input, size_t input_len, char *cmd, size_t cmd_size, char *arg, size_t arg_size);
static pid_t fork_exec(const char *cmd, char *const argv[]);
/**
 * @brief Processes a successfully deserialized (structured) knock payload.
 *
 * Validates the packet contents, remaps the OpenSSL session to the correct user,
 * verifies the signature, and finally dispatches to the packet handler.
 *
 * @param pkt             Deserialized KnockPacket
 * @param session         Pointer to the active OpenSSL session (used for HMAC validation)
 * @param ip              IP address of the remote client (as string)
 */
void handle_structured_payload(
    const KnockPacket *pkt,
    SiglatchOpenSSLSession *session,
    const char *ip
) {
    if (!validatePayload(pkt)) {
        LOGW("❌ Packet failed semantic validation (e.g. replay nonce)\n");
        return;
    }

    dumpDigest("Received Packet HMAC (server)", pkt->hmac, sizeof(pkt->hmac));
    dumpPacketFields("Server Received Packet", pkt);

    const siglatch_user *user = lib.config.user_by_id( pkt->user_id);
    if (!user) {
        LOGW("❌ No matching enabled user for user_id %u\n", pkt->user_id);
        return;
    }

    if (!session_assign_to_user(session, user)) {
        LOGE("❌ Failed to assign session to user ID: %u\n", pkt->user_id);
        return;
    }

    int signature_valid = validateSignature(session, pkt);

    LOGD("routing to handle packet...\n");
    handle_packet( pkt, ip, signature_valid);
}



static int validatePayload(const KnockPacket *pkt) {
    if (!pkt) {
        LOGE("[validate] ❌ Null KnockPacket pointer\n");
        return 0;
    }

    time_t now = lib.time.now();

    // 🧠 Format a nonce string based on challenge and timestamp
    char nonce_str[64];
    snprintf(nonce_str, sizeof(nonce_str), "%u-%u", pkt->timestamp, pkt->challenge);

    if (lib.nonce.check(nonce_str, now)) {
        LOGW("[validate] Replay detected for nonce: %s\n", nonce_str);
        return 0;  // Drop duplicate
    } else {
        LOGT("[validate] ✅ Nonce accepted: %s\n", nonce_str);
        lib.nonce.add(nonce_str, now);
    }

    return 1;  // ✅ Passed
}


static int handle_packet( const KnockPacket *pkt, const char *ip_addr,  int valid_signature) {
  LOGD("TRYING HANDLE PACKET\n");
  if ( !pkt || !ip_addr) {
    LOGE("[handle] ❌ Invalid arguments to handle_packet\n");
    return 0;
  }
  if (valid_signature){
    LOGT("✅ sigature validated");
  }else {
    LOGE("⚠️  invalid signature");
  }
  // --- 1. Lookup user ---
  const char * username = lib.config.username_by_id( pkt->user_id);
  
  if (username[0] == '\0') {
    LOGE("[handle] ⚠️  User found for ID=%u, but username is NULL\n", pkt->user_id);
    return 0;
  }
  //const char *username = username;
  
  // --- 2. Lookup action ---
  const siglatch_action * action = lib.config.action_by_id(pkt->action_id);
  
  if (!action || action->constructor[0] == '\0') {
    LOGW("[handle] ⚠️  Unknown action ID: %u\n", pkt->action_id);
    return 0;
  }
  if (!lib.config.current_server_action_available(action->name)) {
    LOGE("[handle] ❌ Action not permitted on this server.\n");
    return 0 ;
  }
  if (!action->enabled){
    LOGE("[handle] ❌ Action is disabled.\n");
    return 0 ;
  }
    
  // --- 3. Base64-encode payload ---
  char payload_b64[512] = {0};
  base64_encode(pkt->payload, pkt->payload_len, payload_b64, sizeof(payload_b64));

  // --- 3. Base64-encode payload --- does the full size
  //char payload_b64[512] = {0};
  //base64_encode(pkt->payload, sizeof(pkt->payload), payload_b64, sizeof(payload_b64));
  const siglatch_server * server_conf = lib.config.get_current_server();
  if (!server_conf){
    LOGE("UNABLE TO HANDLE PACKET, SERVER MISCONFIGURATION, SERVER CONFIG NOT FOUND\n");
    return 0;
  }
  // --- 4. Prepare arguments ---
  char user_id_str[16], action_id_str[16], encrypted_str[8];
  snprintf(user_id_str, sizeof(user_id_str), "%u", pkt->user_id);
  snprintf(action_id_str, sizeof(action_id_str), "%u", pkt->action_id);
  snprintf(encrypted_str, sizeof(encrypted_str), "%d", server_conf->secure ? 1 : 0);

  char *argv[] = {
    (char *)ip_addr,
    user_id_str,
    (char *)username,
    action_id_str,
    (char *)action->name,
    encrypted_str,
    payload_b64,
    NULL
  };
  //LOGI doesnt work for some reason...
  LOGD("[handle] ➡️ Routing to script: %s (Ip=%s, User=%s, Action=%s,execSplit = %d)\n", action->constructor, ip_addr,username, action->name,action->exec_split);

  // --- 5. Launch action script ---
  return runShell(action->constructor, 7, argv,action->exec_split);
}

 int runShell2(const char *script_path, int argc, char *argv[]) {
    if (!script_path || argc < 1 || !argv) {
        LOGE("[runShell] ❌ Invalid parameters\n");
        return 0;
    }
    if (!argv[0]) {
      LOGE("[runShell] ❌ argv[0] is NULL — invalid script invocation\n");
      return 0;
    }
    pid_t pid = fork();
    if (pid == 0) {
        // Child process
        execv(script_path, argv);
        LOGPERR("execv");  // Only if exec fails
        exit(127);
    } else if (pid > 0) {
        // Parent
        LOGT("[runShell] 🧵 Spawned child PID: %d\n", pid);
        return 1;
    } else {
        // Fork failed
        LOGPERR("fork");
        return 0;
    }
}



int runShell(const char *script_path, int argc, char *argv[], int exec_split) {
  if (!script_path || argc < 1 || !argv || !argv[0]) {
    LOGE("[runShell] ❌ Invalid parameters\n");
    return 0;
  }

  char *final_argv[argc + 3];  // room for cmd + script + NULL
  int i = 0;

  // Smart default behavior: split unless explicitly told not to
  pid_t pid;
  if (exec_split && strchr(script_path, ' ') != NULL) {
    // Split it
    char cmd[128] = {0}, script[256] = {0};
    if (!parseCmd(script_path, strlen(script_path), cmd, sizeof(cmd), script, sizeof(script))) {
      LOGE("[runShell] ❌ Failed to parse constructor: %s\n", script_path);
      return 0;
    }

    final_argv[i++] = cmd;
    if (script[0] != '\0' && strcmp(cmd, script) != 0)
      final_argv[i++] = script;

    for (int j = 0; j < argc; ++j)
      final_argv[i++] = argv[j];

    final_argv[i] = NULL;
    pid = fork_exec(cmd, final_argv);
  } else {
    // Direct exec (either no space, or exec_split == 0)
    final_argv[0] = (char *)script_path;
    for (int j = 0; j < argc; ++j)
      final_argv[j + 1] = argv[j];
    final_argv[argc + 1] = NULL;
    pid = fork_exec(script_path, final_argv);
  }
 
  if (pid == 0) {
    // Child process
    LOGPERR("execv");  // Only if exec fails
    exit(127);
  } else if (pid > 0) {
    // Parent
    LOGT("[runShell] 🧵 Spawned child PID: %d\n", pid);
    return 1;
  } else {
    // Fork failed
    LOGPERR("fork");
    return 0;
  }

  //exit(127);
}
static int parseCmd(const char *input, size_t input_len, char *cmd, size_t cmd_size, char *arg, size_t arg_size) {
  if (!input || !cmd || !arg || cmd_size == 0 || arg_size == 0)
    return 0;

  // Skip leading spaces
  size_t i = 0;
  while (i < input_len && input[i] == ' ') i++;

  // Find the first space (separator between cmd and arg)
  size_t cmd_len = 0;
  while (i + cmd_len < input_len && input[i + cmd_len] != ' ') cmd_len++;

  if (cmd_len >= cmd_size)
    return 0;  // Not enough space in cmd buffer

  strncpy(cmd, input + i, cmd_len);
  cmd[cmd_len] = '\0';

  // Skip past cmd and any following space(s)
  i += cmd_len;
  while (i < input_len && input[i] == ' ') i++;

  // Copy the rest into arg
  size_t arg_len = input_len - i;
  if (arg_len >= arg_size)
    arg_len = arg_size - 1;

  strncpy(arg, input + i, arg_len);
  arg[arg_len] = '\0';

  return 1;  // Success
}

//eventually we will add client responses, so we need to fork and return a zer0 for the child, so it can send a reply.
static pid_t fork_exec(const char *cmd, char *const argv[]) {
  pid_t pid = fork();
  if (pid == 0) {
    // Child
    execv(cmd, argv);
    return pid;
  } else if (pid > 0) {
    // Parent
    return pid;  // Return child PID
  } else {
    // Fork failed
    return -1;
  }
}
