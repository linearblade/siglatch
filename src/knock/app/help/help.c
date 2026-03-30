/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "help.h"

#include <stdio.h>

static int app_help_init(void) {
  return 1;
}

static void app_help_shutdown(void) {
}

static void app_help_print_help(void) {
  printf("\033[1mSiglatch Client - Secure UDP Knock Packet Sender\033[0m\n");
  printf("Send encrypted, signed knock payloads over UDP to a listening server.\n");
  printf("Payloads are required for dead-drop mode (null payloads will not send).\n");
  printf("HMAC signature validation is currently disabled for dead-drop transmission.\n");
  printf("(Signature injection is scheduled for a later date.)\n\n");

  printf("The default configuration directory for each host resides at:\n");
  printf("  ~/.config/siglatch/<host>\n\n");
  printf("Example layout:\n");
  printf("  ~/.config/siglatch/localhost/\n");
  printf("  ├── action.map       # Action alias map\n");
  printf("  ├── client.root.conf # Per-user source-bind defaults (optional)\n");
  printf("  ├── hmac.key         # HMAC key (symmetric)\n");
  printf("  ├── server.pub.pem   # Server public key (for encryption)\n");
  printf("  ├── user.pri.pem     # Client private key (optional, for decryption)\n");
  printf("  ├── user.pub.pem     # Client public key (optional, for handshake)\n");
  printf("  └── user.map         # User alias map\n\n");
  printf("Note: The client performs no hostname resolution.\n");
  printf("      (e.g., \"localhost\" and \"127.0.0.1\" are treated as separate entries)\n\n");

  printf("\033[1mUsage:\033[0m\n");
  printf("  program [options] <host> <user-alias-or-id> <action-alias-or-id> <payload>\n\n");
  printf("  Use \033[36m--help\033[0m to display this information.\n\n");

  printf("\033[1mOptions:\033[0m\n");
  printf("  \033[36m--help\033[0m                     Show this help message and exit\n");
  printf("  \033[36m--port <num>\033[0m              Override UDP destination port (default: 50000)\n");
  printf("  \033[36m--hmac-key <path>\033[0m         Path to HMAC key file\n");
  printf("  \033[36m--protocol <v1|v2|v3>\033[0m    Select wire protocol for structured sends (default: v1)\n");
  printf("  \033[36m--server-key <path>\033[0m       Path to server public key file\n");
  printf("  \033[36m--client-key <path>\033[0m       Path to client private key file\n");
  printf("  \033[36m--no-hmac\033[0m                 Disable HMAC signing (for testing)\n");
  printf("  \033[36m--dummy-hmac\033[0m              Use dummy HMAC signing (fills signature with 0x42)\n");
  printf("  \033[36m--stdin\033[0m                   Read payload from stdin instead of argument\n");
  printf("  \033[36m--opts-dump\033[0m               Dump parsed options for debugging\n");
  printf("  \033[36m--no-encrypt\033[0m              Disable payload encryption\n");
  printf("  \033[36m--dead-drop\033[0m               Send raw payload without structure\n");
  printf("  \033[36m--send-from <ipv4>\033[0m       Bind outbound UDP sends to a local IPv4\n");
  printf("  \033[36m--verbose <level>\033[0m         Set log verbosity (0-5, default 3 = INFO)\n");
  printf("  \033[36m--log <file>\033[0m              Log output to specified file (optional)\n\n");
  printf("  \033[36m--output-mode <mode>\033[0m      Set output mode for this run: unicode|ascii\n");
  printf("  \033[36m--output-mode-default <mode>\033[0m Save default output mode in ~/.config/siglatch/client.conf\n\n");
  printf("  Output mode precedence: --output-mode, then SIGLATCH_OUTPUT_MODE, then client.conf default, then compile default.\n\n");

  printf("\033[1mSource Bind Defaults:\033[0m\n");
  printf("  \033[36m--send-from-default <host> <user> <ipv4>\033[0m\n");
  printf("    Persist a default local IPv4 bind for a specific host/user pair.\n");
  printf("    Example: program --send-from-default localhost root 192.168.1.210\n\n");

  printf("  \033[36m--send-from-default-clear <host> <user>\033[0m\n");
  printf("    Clear a persisted local IPv4 bind default for a specific host/user pair.\n");
  printf("    Example: program --send-from-default-clear localhost root\n\n");

  printf("\033[1mAlias Commands:\033[0m\n");
  printf("  \033[36m--alias-user <host> <user> <id>\033[0m\n");
  printf("    Create or update a user alias.\n");
  printf("    Example: program --alias-user localhost root 1\n\n");

  printf("  \033[36m--alias-action <host> <action> <id>\033[0m\n");
  printf("    Create or update an action alias.\n");
  printf("    Example: program --alias-action localhost grant_ip 3\n\n");

  printf("  \033[36m--alias-user-show [<host>]\033[0m\n");
  printf("    Show user aliases for a host or all hosts.\n");
  printf("    Examples:\n");
  printf("      program --alias-user-show localhost\n");
  printf("      program --alias-user-show\n\n");

  printf("  \033[36m--alias-user-delete <host> <user>\033[0m\n");
  printf("    Delete a user alias.\n");
  printf("    Example: program --alias-user-delete localhost root\n\n");

  printf("  \033[36m--alias-user-delete-map <host> YES\033[0m\n");
  printf("    Delete the user alias map (requires YES confirmation).\n");
  printf("    Example: program --alias-user-delete-map localhost YES\n\n");

  printf("  \033[36m--alias-action-show [<host>]\033[0m\n");
  printf("    Show action aliases for a host or all hosts.\n");
  printf("    Examples:\n");
  printf("      program --alias-action-show localhost\n");
  printf("      program --alias-action-show\n\n");

  printf("  \033[36m--alias-action-delete <host> <action>\033[0m\n");
  printf("    Delete an action alias.\n");
  printf("    Example: program --alias-action-delete localhost grant_ip\n\n");

  printf("  \033[36m--alias-show <host>\033[0m\n");
  printf("    Show both user and action aliases.\n");
  printf("    Example: program --alias-show localhost\n\n");

  printf("  \033[36m--alias-show-hosts\033[0m\n");
  printf("    List hosts that have alias maps under ~/.config/siglatch.\n");
  printf("    Example: program --alias-show-hosts\n\n");

  printf("  \033[36m--alias-delete <host> YES\033[0m\n");
  printf("    Delete both user and action maps (requires YES confirmation).\n");
  printf("    Example: program --alias-delete localhost YES\n\n");

  printf("  \033[36m--alias-action-delete-map <host> YES\033[0m\n");
  printf("    Delete the action alias map (requires YES confirmation).\n");
  printf("    Example: program --alias-action-delete-map localhost YES\n\n");

  printf("\033[1mExamples:\033[0m\n");
  printf("  program localhost root login \"Hello World\"\n");
  printf("  program myserver.com guest openvpn \"Connect to VPN\"\n");
  printf("  program --protocol v3 localhost root login \"Hello World\"\n");
  printf("  program --stdin localhost root login < input.txt\n");
  printf("  program --send-from 127.0.0.1 localhost root login \"Hello World\"\n");
  printf("  program --send-from-default localhost root 192.168.1.210\n");
  printf("  program --send-from-default-clear localhost root\n");
  printf("\n");

  printf("  # Manage aliases\n");
  printf("  program --alias-user 127.0.0.1 admin 2\n");
  printf("  program --alias-action 127.0.0.1 grant_ip 3\n");
}

static void app_help_error_message(void) {
  fprintf(stderr, "Use --help for usage.\n");
}

static const AppHelpLib app_help_instance = {
  .init = app_help_init,
  .shutdown = app_help_shutdown,
  .printHelp = app_help_print_help,
  .errorMessage = app_help_error_message
};

const AppHelpLib *get_app_help_lib(void) {
  return &app_help_instance;
}
