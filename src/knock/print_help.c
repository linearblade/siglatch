/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include <stdio.h>
/*
Usage:
  program [options] <user-alias-or-id> <action-alias-or-id> <payload>

Use --help to display this information.

Options:
  --help                    Show this help message and exit
  --config-dir <path>        Load default keys and alias maps from a directory
  --hmac-key <path>          Path to HMAC key file
  --server-key <path>        Path to server public key file
  --client-key <path>        Path to client private key file
  --no-hmac                  Disable HMAC signing
  --dummy-hmac               Use dummy HMAC signing (for testing)
  --no-encrypt               Disable payload encryption
  --dead-drop                Send raw payload without structure
  --user-map <path>          Path to user alias map file
  --action-map <path>        Path to action alias map file
  --alias-user <host> <user> <id>    Create or update a user alias mapping
  --alias-action <host> <action> <id> Create or update an action alias mapping
  --verbose <level>          Set log verbosity (0-5, default 3 = INFO)
  --log <file>               Log output to specified file (optional)

Alias Commands (manage aliases separately):
  --alias-user <host> <user> <id>      
      Example: --alias-user 127.0.0.1 root 1

  --alias-action <host> <action> <id>  
      Example: --alias-action 127.0.0.1 login 1

Examples:
  program root login "Hello World"
  program guest openvpn "Connect to VPN"
  program --config-dir ~/.config/siglatch admin grant_ip "Temporary access"

  # Manage aliases
  program --alias-user 127.0.0.1 admin 2
  program --alias-action 127.0.0.1 grant_ip 3
 */
//

#include <stdio.h>

void printHelp(void) {
    // Header
    printf("\033[1mSiglatch Client - Secure UDP Knock Packet Sender\033[0m\n");
    printf("Send encrypted, signed knock payloads over UDP to a listening server.\n");
    printf("Payloads are required for dead-drop mode (null payloads will not send).\n");
    printf("HMAC signature validation is currently disabled for dead-drop transmission.\n");
    printf("(Signature injection is scheduled for a later date.)\n\n");

    // Config Dir Note
    printf("The default configuration directory for each host resides at:\n");
    printf("  ~/.config/siglatch/<host>\n\n");
    printf("Example layout:\n");
    printf("  ~/.config/siglatch/localhost/\n");
    printf("  ├── action.map       # Action alias map\n");
    printf("  ├── hmac.key         # HMAC key (symmetric)\n");
    printf("  ├── server.pub.pem   # Server public key (for encryption)\n");
    printf("  ├── user.pri.pem     # Client private key (optional, for decryption)\n");
    printf("  ├── user.pub.pem     # Client public key (optional, for handshake)\n");
    printf("  └── user.map         # User alias map\n\n");
    printf("Note: The client performs no hostname resolution.\n");
    printf("      (e.g., \"localhost\" and \"127.0.0.1\" are treated as separate entries)\n\n");

    // Usage
    printf("\033[1mUsage:\033[0m\n");
    printf("  program [options] <host> <user-alias-or-id> <action-alias-or-id> <payload>\n\n");
    printf("  Use \033[36m--help\033[0m to display this information.\n\n");

    // Options
    printf("\033[1mOptions:\033[0m\n");
    printf("  \033[36m--help\033[0m                     Show this help message and exit\n");
    printf("  \033[36m--port <num>\033[0m              Override UDP destination port (default: 50000)\n");
    printf("  \033[36m--hmac-key <path>\033[0m         Path to HMAC key file\n");
    printf("  \033[36m--server-key <path>\033[0m       Path to server public key file\n");
    printf("  \033[36m--client-key <path>\033[0m       Path to client private key file\n");
    printf("  \033[36m--no-hmac\033[0m                 Disable HMAC signing (for testing)\n");
    printf("  \033[36m--dummy-hmac\033[0m              Use dummy HMAC signing (fills signature with 0x42)\n");
    printf("  \033[36m--stdin\033[0m                   Read payload from stdin instead of argument\n");
    printf("  \033[36m--opts-dump\033[0m               Dump parsed options for debugging\n");
    printf("  \033[36m--no-encrypt\033[0m              Disable payload encryption\n");
    printf("  \033[36m--dead-drop\033[0m               Send raw payload without structure\n");
    printf("  \033[36m--verbose <level>\033[0m         Set log verbosity (0-5, default 3 = INFO)\n");
    printf("  \033[36m--log <file>\033[0m              Log output to specified file (optional)\n\n");

    // Alias Commands
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

    printf("  \033[36m--alias-delete <host> YES\033[0m\n");
    printf("    Delete both user and action maps (requires YES confirmation).\n");
    printf("    Example: program --alias-delete localhost YES\n\n");

    printf("  \033[36m--alias-action-delete-map <host> YES\033[0m\n");
    printf("    Delete the action alias map (requires YES confirmation).\n");
    printf("    Example: program --alias-action-delete-map localhost YES\n\n");

    // Examples
    printf("\033[1mExamples:\033[0m\n");
    printf("  program localhost root login \"Hello World\"\n");
    printf("  program myserver.com guest openvpn \"Connect to VPN\"\n");
    printf("  program --stdin localhost root login < input.txt\n");
    printf("  program --config-dir ~/.config/siglatch admin grant_ip \"Temporary access\"\n\n");

    printf("  # Manage aliases\n");
    printf("  program --alias-user 127.0.0.1 admin 2\n");
    printf("  program --alias-action 127.0.0.1 grant_ip 3\n");
}

/*
void printHelp(void) {
    printf("\033[1mSiglatch Client - Secure UDP Knock Packet Sender\033[0m\n");
    printf("Send encrypted, signed knock payloads over UDP to a listening server.\n\n");

    printf("\033[1mUsage:\033[0m\n");
    printf("  program [options] <user-alias-or-id> <action-alias-or-id> <payload>\n\n");
    printf("  Use \033[36m--help\033[0m to display this information.\n\n");

    printf("\033[1mOptions:\033[0m\n");
    printf("  \033[36m--help\033[0m                     Show this help message and exit\n");
    printf("  \033[36m--config-dir <path>\033[0m         Load default keys and alias maps from a directory\n");
    printf("  \033[36m--hmac-key <path>\033[0m            Path to HMAC key file\n");
    printf("  \033[36m--server-key <path>\033[0m          Path to server public key file\n");
    printf("  \033[36m--client-key <path>\033[0m          Path to client private key file\n");
    printf("  \033[36m--no-hmac\033[0m                   Disable HMAC signing\n");
    printf("  \033[36m--dummy-hmac\033[0m                Use dummy HMAC signing (for testing)\n");
    printf("  \033[36m--no-encrypt\033[0m                Disable payload encryption\n");
    printf("  \033[36m--dead-drop\033[0m                 Send raw payload without structure\n");
    printf("  \033[36m--user-map <path>\033[0m            Path to user alias map file\n");
    printf("  \033[36m--action-map <path>\033[0m          Path to action alias map file\n");
    printf("  \033[36m--alias-user <host> <user> <id>\033[0m    Create or update a user alias\n");
    printf("  \033[36m--alias-action <host> <action> <id>\033[0m Create or update an action alias\n");
    printf("  \033[36m--verbose <level>\033[0m            Set log verbosity (0-5, default 3 = INFO)\n");
    printf("  \033[36m--log <file>\033[0m                 Log output to specified file (optional)\n\n");

    printf("\033[1mAlias Commands (manage aliases separately):\033[0m\n");
    printf("  \033[36m--alias-user <host> <user> <id>\033[0m\n");
    printf("    Example: \033[0mprogram --alias-user 127.0.0.1 root 1\n\n");
    printf("  \033[36m--alias-action <host> <action> <id>\033[0m\n");
    printf("    Example: \033[0mprogram --alias-action 127.0.0.1 login 1\n\n");

    printf("\033[1mExamples:\033[0m\n");
    printf("  program root login \"Hello World\"\n");
    printf("  program guest openvpn \"Connect to VPN\"\n");
    printf("  program --config-dir ~/.config/siglatch admin grant_ip \"Temporary access\"\n\n");

    printf("  # Manage aliases\n");
    printf("  program --alias-user 127.0.0.1 admin 2\n");
    printf("  program --alias-action 127.0.0.1 grant_ip 3\n\n");
}
*/
