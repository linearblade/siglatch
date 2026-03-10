/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h> // for access(), F_OK
#include <dirent.h>
#include "lib.h"
#include "app/app.h"
#include "parse_opts_alias.h"
#include "print_help.h"

static int handle_alias_user(int argc, char *argv[]);
static int handle_alias_action(int argc, char *argv[]);

// show/delete handlers
static int handle_alias_user_show_all(int argc, char *argv[]);
static int handle_alias_user_show(int argc, char *argv[]);
static int handle_alias_user_delete(int argc, char *argv[]);
static int handle_alias_user_delete_map(int argc, char *argv[]);
static int handle_alias_action_show_all(int argc, char *argv[]);
static int handle_alias_action_show(int argc, char *argv[]);
static int handle_alias_action_delete(int argc, char *argv[]);
static int handle_alias_action_delete_map(int argc, char *argv[]);
// combined handlers

static int handle_alias_show(int argc, char *argv[]);
static int handle_alias_delete(int argc, char *argv[]);
static const char *alias_home_or_error(void);
static int build_alias_root_path(char *out, size_t out_size);
static int build_alias_host_path(char *out, size_t out_size, const char *host, const char *filename);

static const char *alias_home_or_error(void) {
    const char *home = getenv("HOME");

    if (!home || !*home) {
        lib.print.uc_fprintf(stderr, "err", "HOME environment variable not set\n");
        return NULL;
    }

    return home;
}

static int build_alias_root_path(char *out, size_t out_size) {
    const char *home = alias_home_or_error();
    int written = 0;

    if (!out || out_size == 0) {
        return 0;
    }

    if (!home) {
        return 0;
    }

    written = snprintf(out, out_size, "%s/.config/siglatch", home);
    if (written < 0 || (size_t)written >= out_size) {
        lib.print.uc_fprintf(stderr, "err", "Alias base path too long\n");
        return 0;
    }

    return 1;
}

static int build_alias_host_path(char *out, size_t out_size, const char *host, const char *filename) {
    const char *home = alias_home_or_error();
    int written = 0;

    if (!out || out_size == 0 || !host || !*host) {
        return 0;
    }

    if (!home) {
        return 0;
    }

    if (filename && *filename) {
        written = snprintf(out, out_size, "%s/.config/siglatch/%s/%s", home, host, filename);
    } else {
        written = snprintf(out, out_size, "%s/.config/siglatch/%s", home, host);
    }

    if (written < 0 || (size_t)written >= out_size) {
        lib.print.uc_fprintf(stderr, "err", "Alias path too long for host: %s\n", host);
        return 0;
    }

    return 1;
}
/*
  --alias-user
--alias-action
--alias-user-show
--alias-user-delete
--alias-user-delete-map
--alias-action-show
--alias-action-delete
--alias-show
--alias-delete
--alias-action-delete-map

 */
int handle_alias(int argc, char *argv[]) {
    if (argc < 2) {
        return 0; // Not enough arguments
    }

    if (strcmp(argv[1], "--alias-user") == 0) {
        if (argc < 5) {
            lib.print.uc_fprintf(stderr, "err", "Not enough arguments for --alias-user\n");
	    exit(2);
        }
        if (!app.env.ensure_host_config_dir(argv[2])) {
            lib.print.uc_fprintf(stderr, "err", "Failed to ensure host directory: %s\n", argv[2]);
	    exit(2);
        }
        if (!handle_alias_user(argc, argv)) {
            lib.print.uc_fprintf(stderr, "err", "Failed to handle alias user\n");
	    exit(2);
        }
        exit(0); // Graceful die
    }

    if (strcmp(argv[1], "--alias-action") == 0) {
        if (argc < 5) {
            lib.print.uc_fprintf(stderr, "err", "Not enough arguments for --alias-action\n");
	    exit(2);
        }
        if (!app.env.ensure_host_config_dir(argv[2])) {
            lib.print.uc_fprintf(stderr, "err", "Failed to ensure host directory: %s\n", argv[2]);
	    exit(2);
        }
        if (!handle_alias_action(argc, argv)) {
            lib.print.uc_fprintf(stderr, "err", "Failed to handle alias action\n");
	    exit(2);
        }
        exit(0); // Graceful die
    }

    if (strcmp(argv[1], "--alias-user-show") == 0) {
      if (argc == 2) {
        if (!handle_alias_user_show_all(argc, argv)) {
	  lib.print.uc_fprintf(stderr, "err", "Failed to show all user aliases\n");
	  exit(2);
        }
        exit(0);
      }

      if (argc < 3) {
        lib.print.uc_fprintf(stderr, "err", "Not enough arguments for --alias-user-show\n");
        exit(2);
      }

      if (!handle_alias_user_show(argc, argv)) {
        lib.print.uc_fprintf(stderr, "err", "Failed to show user aliases\n");
        exit(2);
      }
      exit(0);
    }
    

    if (strcmp(argv[1], "--alias-user-delete") == 0) {
      if (argc < 4) {
        lib.print.uc_fprintf(stderr, "err", "Not enough arguments for --alias-user-delete\n");
        exit(2);
      }
      if (!handle_alias_user_delete(argc, argv)) {
        lib.print.uc_fprintf(stderr, "err", "Failed to delete user alias\n");
        exit(2);
      }
      exit(0); // Graceful die
    }
    
    if (strcmp(argv[1], "--alias-user-delete-map") == 0) {
      if (argc < 4) {
        lib.print.uc_fprintf(stderr, "err", "Not enough arguments for --alias-user-delete-map (you must type YES)\n");
        exit(2);
      }
      if (strcmp(argv[3], "YES") != 0) {
        lib.print.uc_fprintf(stderr, "err", "You must confirm map deletion by typing YES\n");
        exit(2);
      }
      if (!handle_alias_user_delete_map(argc, argv)) {
        lib.print.uc_fprintf(stderr, "err", "Failed to delete user alias map file\n");
        exit(2);
      }
      exit(0);
    }

    if (strcmp(argv[1], "--alias-action-show") == 0) {
      if (argc == 2) {
        // No host provided -> Show all action aliases
        if (!handle_alias_action_show_all(argc, argv)) {
	  lib.print.uc_fprintf(stderr, "err", "Failed to show all action aliases\n");
	  exit(2);
        }
        exit(0);
      }

      if (argc < 3) {
        lib.print.uc_fprintf(stderr, "err", "Not enough arguments for --alias-action-show\n");
        exit(2);
      }

      if (!handle_alias_action_show(argc, argv)) {
        lib.print.uc_fprintf(stderr, "err", "Failed to show action aliases\n");
        exit(2);
      }
      exit(0); // Graceful die
    }
    

    if (strcmp(argv[1], "--alias-action-delete") == 0) {
      if (argc < 4) {
        lib.print.uc_fprintf(stderr, "err", "Not enough arguments for --alias-action-delete\n");
        exit(2);
      }
      if (!handle_alias_action_delete(argc, argv)) {
        lib.print.uc_fprintf(stderr, "err", "Failed to delete action alias\n");
        exit(2);
      }
      exit(0); // Graceful die
    }

    if (strcmp(argv[1], "--alias-show") == 0) {
      if (argc < 3) {
        lib.print.uc_fprintf(stderr, "err", "Not enough arguments for --alias-show\n");
        exit(2);
      }
      if (!handle_alias_show(argc, argv)) {
        lib.print.uc_fprintf(stderr, "err", "Failed to show aliases\n");
        exit(2);
      }
      exit(0);
    }
    if (strcmp(argv[1], "--alias-delete") == 0) {
      if (argc < 4) {
        lib.print.uc_fprintf(stderr, "err", "Not enough arguments for --alias-delete (you must type YES)\n");
        exit(2);
      }
      if (strcmp(argv[3], "YES") != 0) {
        lib.print.uc_fprintf(stderr, "err", "You must confirm destructive alias wipe by typing YES\n");
        exit(2);
      }
      if (!handle_alias_delete(argc, argv)) {
        lib.print.uc_fprintf(stderr, "err", "Failed to delete all aliases\n");
        exit(2);
      }
      exit(0);
    }

    if (strcmp(argv[1], "--alias-action-delete-map") == 0) {
      if (argc < 4) {
        lib.print.uc_fprintf(stderr, "err", "Not enough arguments for --alias-action-delete-map (you must type YES)\n");
        exit(2);
      }
      if (strcmp(argv[3], "YES") != 0) {
        lib.print.uc_fprintf(stderr, "err", "You must confirm map deletion by typing YES\n");
        exit(2);
      }
      if (!handle_alias_action_delete_map(argc, argv)) {
        lib.print.uc_fprintf(stderr, "err", "Failed to delete action alias map file\n");
        exit(2);
      }
      exit(0);
    }

    // end of alias hell. if you reached the bottom of the pit, your S.O.L.
    lib.print.uc_fprintf(stderr, "err", "Unknown alias command: %s\n", argv[1]);
    return 0;
}



static int handle_alias_user(int argc, char *argv[]) {
    const char *host = argv[2];
    const char *user = argv[3];
    const char *id_str = argv[4];

    uint32_t user_id = (uint32_t)atoi(id_str);
    if (user_id == 0) {
        lib.print.uc_fprintf(stderr, "err", "Invalid user ID: %s\n", id_str);
        return 0;
    }

    char path[PATH_MAX] = {0};
    if (!build_alias_host_path(path, sizeof(path), host, "user.map")) {
        return 0;
    }

    AliasEntry *aliases = NULL;
    size_t alias_count = 0;

    if (access(path, F_OK) == 0) {
        // Alias file exists
        if (!app.alias.read_map(path, &aliases, &alias_count)) {
            lib.print.uc_fprintf(stderr, "err", "Failed to read existing alias file: %s\n", path);
            return 0;
        }
    } else {
        // Alias file does not exist
        aliases = NULL;
        alias_count = 0;
    }

    if (!app.alias.update_entry(&aliases, &alias_count, user, host, user_id)) {
        lib.print.uc_fprintf(stderr, "err", "Failed to update alias entry in memory\n");
        return 0;
    }

    if (!app.alias.write_map(path, aliases, alias_count)) {
        lib.print.uc_fprintf(stderr, "err", "Failed to write alias map back to disk: %s\n", path);
        return 0;
    }

    lib.print.uc_printf("ok", "User alias updated successfully: %s -> %s (id=%u)\n", user, host, user_id);
    return 1;
}



static int handle_alias_action(int argc, char *argv[]) {
    const char *host = argv[2];
    const char *action = argv[3];
    const char *id_str = argv[4];

    uint32_t action_id = (uint32_t)atoi(id_str);
    if (action_id == 0) {
        lib.print.uc_fprintf(stderr, "err", "Invalid action ID: %s\n", id_str);
        return 0;
    }

    char path[PATH_MAX] = {0};
    if (!build_alias_host_path(path, sizeof(path), host, "action.map")) {
        return 0;
    }

    AliasEntry *aliases = NULL;
    size_t alias_count = 0;

    if (access(path, F_OK) == 0) {
        // Alias file exists
        if (!app.alias.read_map(path, &aliases, &alias_count)) {
            lib.print.uc_fprintf(stderr, "err", "Failed to read existing alias file: %s\n", path);
            return 0;
        }
    } else {
        // Alias file does not exist
        aliases = NULL;
        alias_count = 0;
    }

    if (!app.alias.update_entry(&aliases, &alias_count, action, host, action_id)) {
        lib.print.uc_fprintf(stderr, "err", "Failed to update alias entry in memory\n");
        return 0;
    }

    if (!app.alias.write_map(path, aliases, alias_count)) {
        lib.print.uc_fprintf(stderr, "err", "Failed to write alias map back to disk: %s\n", path);
        return 0;
    }

    lib.print.uc_printf("ok", "Action alias updated successfully: %s -> %s (id=%u)\n", action, host, action_id);
    return 1;
}


static int handle_alias_user_show(int argc, char *argv[]) {
    if (argc < 3) {
        lib.print.uc_fprintf(stderr, "err", "Not enough arguments for --alias-user-show\n");
        return 0;
    }

    const char *host = argv[2];

    char path[PATH_MAX] = {0};
    if (!build_alias_host_path(path, sizeof(path), host, "user.map")) {
        return 0;
    }

    AliasEntry *aliases = NULL;
    size_t alias_count = 0;

    if (access(path, F_OK) != 0) {
        lib.print.uc_fprintf(stderr, "err", "No user aliases found for host: %s\n", host);
        return 0;
    }

    if (!app.alias.read_map(path, &aliases, &alias_count)) {
        lib.print.uc_fprintf(stderr, "err", "Failed to read user alias map: %s\n", path);
        return 0;
    }

    lib.print.uc_printf("users", "User Aliases for %s:\n", host);
    for (size_t i = 0; i < alias_count; i++) {
        printf("  - %s -> %s (id=%u)\n", aliases[i].name, aliases[i].host, aliases[i].id);
    }

    if (alias_count == 0) {
        printf("  (No user aliases found)\n");
    }

    free(aliases);
    return 1;
}

static int handle_alias_user_delete(int argc, char *argv[]) {
    if (argc < 4) {
        lib.print.uc_fprintf(stderr, "err", "Not enough arguments for --alias-user-delete\n");
        return 0;
    }

    const char *host = argv[2];
    const char *user = argv[3];

    char path[PATH_MAX] = {0};
    if (!build_alias_host_path(path, sizeof(path), host, "user.map")) {
        return 0;
    }

    if (access(path, F_OK) != 0) {
        lib.print.uc_fprintf(stderr, "err", "User alias map does not exist: %s\n", path);
        return 0;
    }

    AliasEntry *aliases = NULL;
    size_t alias_count = 0;

    if (!app.alias.read_map(path, &aliases, &alias_count)) {
        lib.print.uc_fprintf(stderr, "err", "Failed to read user alias map: %s\n", path);
        return 0;
    }

    int found = 0;
    size_t new_count = 0;

    for (size_t i = 0; i < alias_count; i++) {
        if (strcmp(aliases[i].name, user) == 0) {
            found = 1;
            continue; // Skip this entry
        }
        // Move entry down if needed
        aliases[new_count++] = aliases[i];
    }

    if (!found) {
        lib.print.uc_fprintf(stderr, "warn", "Alias not found for user: %s\n", user);
        free(aliases);
        return 0;
    }

    if (!app.alias.write_map(path, aliases, new_count)) {
        lib.print.uc_fprintf(stderr, "err", "Failed to write updated alias map after deletion\n");
        free(aliases);
        return 0;
    }

    lib.print.uc_printf("del", "Deleted user alias: %s -> %s\n", user, host);
    free(aliases);
    return 1;
}

static int handle_alias_action_show(int argc, char *argv[]) {
    if (argc < 3) {
        lib.print.uc_fprintf(stderr, "err", "Not enough arguments for --alias-action-show\n");
        return 0;
    }

    const char *host = argv[2];

    char path[PATH_MAX] = {0};
    if (!build_alias_host_path(path, sizeof(path), host, "action.map")) {
        return 0;
    }

    AliasEntry *aliases = NULL;
    size_t alias_count = 0;

    if (access(path, F_OK) != 0) {
        lib.print.uc_fprintf(stderr, "err", "No action aliases found for host: %s\n", host);
        return 0;
    }

    if (!app.alias.read_map(path, &aliases, &alias_count)) {
        lib.print.uc_fprintf(stderr, "err", "Failed to read action alias map: %s\n", path);
        return 0;
    }

    lib.print.uc_printf("target", "Action Aliases for %s:\n", host);
    for (size_t i = 0; i < alias_count; i++) {
        printf("  - %s -> %s (id=%u)\n", aliases[i].name, aliases[i].host, aliases[i].id);
    }

    if (alias_count == 0) {
        printf("  (No action aliases found)\n");
    }

    free(aliases);
    return 1;
}


static int handle_alias_action_delete(int argc, char *argv[]) {
    if (argc < 4) {
        lib.print.uc_fprintf(stderr, "err", "Not enough arguments for --alias-action-delete\n");
        return 0;
    }

    const char *host = argv[2];
    const char *action = argv[3];

    char path[PATH_MAX] = {0};
    if (!build_alias_host_path(path, sizeof(path), host, "action.map")) {
        return 0;
    }

    if (access(path, F_OK) != 0) {
        lib.print.uc_fprintf(stderr, "err", "Action alias map does not exist: %s\n", path);
        return 0;
    }

    AliasEntry *aliases = NULL;
    size_t alias_count = 0;

    if (!app.alias.read_map(path, &aliases, &alias_count)) {
        lib.print.uc_fprintf(stderr, "err", "Failed to read action alias map: %s\n", path);
        return 0;
    }

    int found = 0;
    size_t new_count = 0;

    for (size_t i = 0; i < alias_count; i++) {
        if (strcmp(aliases[i].name, action) == 0) {
            found = 1;
            continue; // Skip this entry
        }
        // Move entry down if needed
        aliases[new_count++] = aliases[i];
    }

    if (!found) {
        lib.print.uc_fprintf(stderr, "warn", "Alias not found for action: %s\n", action);
        free(aliases);
        return 0;
    }

    if (!app.alias.write_map(path, aliases, new_count)) {
        lib.print.uc_fprintf(stderr, "err", "Failed to write updated alias map after deletion\n");
        free(aliases);
        return 0;
    }

    lib.print.uc_printf("del", "Deleted action alias: %s -> %s\n", action, host);
    free(aliases);
    return 1;
}


static int handle_alias_action_show_all(int argc, char *argv[]) {
    (void)argc;
    (void)argv;

    char base_path[PATH_MAX] = {0};
    if (!build_alias_root_path(base_path, sizeof(base_path))) {
        return 0;
    }

    DIR *dir = opendir(base_path);
    if (!dir) {
        lib.print.uc_fprintf(stderr, "err", "Failed to open siglatch config directory: %s\n", base_path);
        return 0;
    }

    struct dirent *entry;
    int found_any = 0;

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type != DT_DIR) {
            continue;
        }

        const char *name = entry->d_name;

        if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
            continue;
        }

        // Found a host directory
        found_any = 1;

        // Fake argv to pass host to existing handler
        char *fake_argv[] = { "program", "--alias-action-show", (char *)name };

        printf("\n");
        if (!handle_alias_action_show(3, fake_argv)) {
            lib.print.uc_fprintf(stderr, "warn", "Failed to show action aliases for host: %s\n", name);
        }
    }

    closedir(dir);

    if (!found_any) {
        lib.print.uc_printf("warn", "No hosts found under: %s\n", base_path);
    }

    return 1;
}

static int handle_alias_user_show_all(int argc, char *argv[]) {
    (void)argc;
    (void)argv;

    char base_path[PATH_MAX] = {0};
    if (!build_alias_root_path(base_path, sizeof(base_path))) {
        return 0;
    }

    DIR *dir = opendir(base_path);
    if (!dir) {
        lib.print.uc_fprintf(stderr, "err", "Failed to open siglatch config directory: %s\n", base_path);
        return 0;
    }

    struct dirent *entry;
    int found_any = 0;

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type != DT_DIR) {
            continue;
        }

        const char *name = entry->d_name;

        if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
            continue;
        }

        // Found a host directory
        found_any = 1;

        // Fake argv to pass host to existing handler
        char *fake_argv[] = { "program", "--alias-user-show", (char *)name };

        printf("\n");
        if (!handle_alias_user_show(3, fake_argv)) {
            lib.print.uc_fprintf(stderr, "warn", "Failed to show user aliases for host: %s\n", name);
        }
    }

    closedir(dir);

    if (!found_any) {
        lib.print.uc_printf("warn", "No hosts found under: %s\n", base_path);
    }

    return 1;
}


static int handle_alias_show(int argc, char *argv[]) {
    if (argc < 3) {
        lib.print.uc_fprintf(stderr, "err", "Not enough arguments for --alias-show\n");
        return 0;
    }

    const char *host = argv[2];

    // Fake up argc/argv to call internal handlers cleanly
    char *fake_argv_user[] = { "program", "--alias-user-show", (char *)host };
    char *fake_argv_action[] = { "program", "--alias-action-show", (char *)host };

    printf("\n");
    if (!handle_alias_user_show(3, fake_argv_user)) {
        lib.print.uc_fprintf(stderr, "warn", "Failed to show user aliases for host: %s\n", host);
    }

    printf("\n");
    if (!handle_alias_action_show(3, fake_argv_action)) {
        lib.print.uc_fprintf(stderr, "warn", "Failed to show action aliases for host: %s\n", host);
    }

    return 1;
}


#include <unistd.h>

static int handle_alias_delete(int argc, char *argv[]) {
    if (argc < 4) {
        lib.print.uc_fprintf(stderr, "err", "Not enough arguments for --alias-delete (missing YES confirmation)\n");
        return 0;
    }

    const char *host = argv[2];
    const char *confirmation = argv[3];

    if (strcmp(confirmation, "YES") != 0) {
        lib.print.uc_fprintf(stderr, "err", "You must confirm alias wipe by typing YES\n");
        return 0;
    }

    char base_path[PATH_MAX] = {0};
    if (!build_alias_host_path(base_path, sizeof(base_path), host, NULL)) {
        return 0;
    }

    // Target files
    char user_map_path[PATH_MAX] = {0};
    snprintf(user_map_path, sizeof(user_map_path), "%s/user.map", base_path);

    char action_map_path[PATH_MAX] = {0};
    snprintf(action_map_path, sizeof(action_map_path), "%s/action.map", base_path);

    int success = 1;

    if (access(user_map_path, F_OK) == 0) {
        if (unlink(user_map_path) != 0) {
            lib.print.uc_fprintf(stderr, "err", "Failed to delete user alias file: %s (%s)\n", user_map_path, strerror(errno));
            success = 0;
        } else {
            lib.print.uc_printf("del", "Deleted user alias file: %s\n", user_map_path);
        }
    } else {
        lib.print.uc_printf("warn", "User alias file does not exist: %s\n", user_map_path);
    }

    if (access(action_map_path, F_OK) == 0) {
        if (unlink(action_map_path) != 0) {
            lib.print.uc_fprintf(stderr, "err", "Failed to delete action alias file: %s (%s)\n", action_map_path, strerror(errno));
            success = 0;
        } else {
            lib.print.uc_printf("del", "Deleted action alias file: %s\n", action_map_path);
        }
    } else {
        lib.print.uc_printf("warn", "Action alias file does not exist: %s\n", action_map_path);
    }

    return success;
}


static int handle_alias_user_delete_map(int argc, char *argv[]) {
    if (argc < 4) {
        lib.print.uc_fprintf(stderr, "err", "Not enough arguments for --alias-user-delete-map\n");
        return 0;
    }

    const char *host = argv[2];
    const char *confirmation = argv[3];

    if (strcmp(confirmation, "YES") != 0) {
        lib.print.uc_fprintf(stderr, "err", "You must confirm deletion by typing YES\n");
        return 0;
    }

    char path[PATH_MAX] = {0};
    if (!build_alias_host_path(path, sizeof(path), host, "user.map")) {
        return 0;
    }

    if (access(path, F_OK) != 0) {
        lib.print.uc_fprintf(stderr, "warn", "User map file does not exist: %s\n", path);
        return 0;
    }

    if (unlink(path) != 0) {
        lib.print.uc_fprintf(stderr, "err", "Failed to delete user map file: %s (%s)\n", path, strerror(errno));
        return 0;
    }

    lib.print.uc_printf("del", "Deleted user map file for host: %s\n", host);
    return 1;
}

static int handle_alias_action_delete_map(int argc, char *argv[]) {
    if (argc < 4) {
        lib.print.uc_fprintf(stderr, "err", "Not enough arguments for --alias-action-delete-map\n");
        return 0;
    }

    const char *host = argv[2];
    const char *confirmation = argv[3];

    if (strcmp(confirmation, "YES") != 0) {
        lib.print.uc_fprintf(stderr, "err", "You must confirm deletion by typing YES\n");
        return 0;
    }

    char path[PATH_MAX] = {0};
    if (!build_alias_host_path(path, sizeof(path), host, "action.map")) {
        return 0;
    }

    if (access(path, F_OK) != 0) {
        lib.print.uc_fprintf(stderr, "warn", "Action map file does not exist: %s\n", path);
        return 0;
    }

    if (unlink(path) != 0) {
        lib.print.uc_fprintf(stderr, "err", "Failed to delete action map file: %s (%s)\n", path, strerror(errno));
        return 0;
    }

    lib.print.uc_printf("del", "Deleted action map file for host: %s\n", host);
    return 1;
}
