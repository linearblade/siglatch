#include <stdio.h>
#include <openssl/evp.h>
#include "config.h"
#include "lib.h"
/*
void dump_config(const siglatch_config *cfg) {
    if (!cfg) {
        lib.log.console("❌ No config to dump.\n");
        return;
    }

    lib.log.console("🔐 siglatch config dump:\n\n");
    lib.log.console("  Port: %d\n", cfg->port);
    lib.log.console("  Private key path: %s\n", cfg->priv_key_path);
    if (cfg->master_privkey) {
      lib.log.console("  ✅ Master private key loaded from %s\n", cfg->priv_key_path);
    }else {
      lib.log.console("  ❌ Master private key not loaded\n");
    }
    lib.log.console("  Actions (%d):\n", cfg->action_count);
    for (int i = 0; i < cfg->action_count; ++i) {
        const siglatch_action *a = &cfg->actions[i];
        lib.log.console("    - [%s]\n", a->name);
        lib.log.console("      Constructor: %s\n", a->constructor);
        lib.log.console("      Destructor : %s\n", a->destructor);
        lib.log.console("      Keepalive  : %d\n", a->keepalive_interval);
    }

    lib.log.console("\n  Users (%d):\n", cfg->user_count);
    for (int i = 0; i < cfg->user_count; ++i) {
        const siglatch_user *u = &cfg->users[i];
        lib.log.console("    - [%s]\n", u->name);
        lib.log.console("      Enabled : %s\n", u->enabled ? "yes" : "no");
        lib.log.console("      Key file: %s\n", u->key_file);
	if (u->pubkey) {
	  lib.log.console("      ✅ User public key loaded from %s\n", u->key_file);
	}else {
	  lib.log.console("      ❌ User public key not loaded\n");
	}

        lib.log.console("      Actions :\n");
        for (int j = 0; j < u->action_count; ++j) {
            lib.log.console("        - %s\n", u->actions[j]);
        }
        lib.log.console("\n");
    }
}
*/


void dump_config(const siglatch_config *cfg) {
    if (!cfg) {
        lib.log.console("❌ No config to dump.\n");
        return;
    }

    lib.log.console("🔐 siglatch config dump:\n\n");
    lib.log.console("  Port: %d\n", cfg->port);
    lib.log.console("  Private key path: %s\n", cfg->priv_key_path);
    if (cfg->master_privkey) {
        lib.log.console("  ✅ Master private key loaded from %s\n", cfg->priv_key_path);
    } else {
        lib.log.console("  ❌ Master private key not loaded\n");
    }
    lib.log.console("  Actions (%d):\n", cfg->action_count);
    for (int i = 0; i < cfg->action_count; ++i) {
        const siglatch_action *a = &cfg->actions[i];
        lib.log.console("    - [%s]\n", a->name);
        lib.log.console("      Constructor: %s\n", a->constructor);
        lib.log.console("      Destructor : %s\n", a->destructor);
        lib.log.console("      Keepalive  : %d\n", a->keepalive_interval);
    }

    lib.log.console("\n  Users (%d):\n", cfg->user_count);
    for (int i = 0; i < cfg->user_count; ++i) {
        const siglatch_user *u = &cfg->users[i];
        lib.log.console("    - [%s]\n", u->name);
        lib.log.console("      Enabled : %s\n", u->enabled ? "yes" : "no");
        lib.log.console("      Key file: %s\n", u->key_file);
        if (u->pubkey) {
            lib.log.console("      ✅ User public key loaded from %s\n", u->key_file);
        } else {
            lib.log.console("      ❌ User public key not loaded\n");
        }

        lib.log.console("      HMAC file: %s\n", u->hmac_file);
        // Check if hmac_key appears loaded
        int all_zero = 1;
        for (int j = 0; j < sizeof(u->hmac_key); ++j) {
            if (u->hmac_key[j] != 0) {
                all_zero = 0;
                break;
            }
        }
        if (!all_zero) {
            lib.log.console("      ✅ HMAC key loaded from %s\n", u->hmac_file);
        } else {
            lib.log.console("      ❌ HMAC key not loaded\n");
        }

        lib.log.console("      Actions :\n");
        for (int j = 0; j < u->action_count; ++j) {
            lib.log.console("        - %s\n", u->actions[j]);
        }
        lib.log.console("\n");
    }
}
