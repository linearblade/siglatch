#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h> // for access(), F_OK
#include <dirent.h>
#include "parse_opts.h"
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
            fprintf(stderr, "❌ Not enough arguments for --alias-user\n");
	    exit(2);
        }
        if (!ensure_dir_exists(argv[2])) {
            fprintf(stderr, "❌ Failed to ensure host directory: %s\n", argv[2]);
	    exit(2);
        }
        if (!handle_alias_user(argc, argv)) {
            fprintf(stderr, "❌ Failed to handle alias user\n");
	    exit(2);
        }
        exit(0); // Graceful die
    }

    if (strcmp(argv[1], "--alias-action") == 0) {
        if (argc < 5) {
            fprintf(stderr, "❌ Not enough arguments for --alias-action\n");
	    exit(2);
        }
        if (!ensure_dir_exists(argv[2])) {
            fprintf(stderr, "❌ Failed to ensure host directory: %s\n", argv[2]);
	    exit(2);
        }
        if (!handle_alias_action(argc, argv)) {
            fprintf(stderr, "❌ Failed to handle alias action\n");
	    exit(2);
        }
        exit(0); // Graceful die
    }

    if (strcmp(argv[1], "--alias-user-show") == 0) {
      if (argc == 2) {
        if (!handle_alias_user_show_all(argc, argv)) {
	  fprintf(stderr, "❌ Failed to show all user aliases\n");
	  exit(2);
        }
        exit(0);
      }

      if (argc < 3) {
        fprintf(stderr, "❌ Not enough arguments for --alias-user-show\n");
        exit(2);
      }

      if (!handle_alias_user_show(argc, argv)) {
        fprintf(stderr, "❌ Failed to show user aliases\n");
        exit(2);
      }
      exit(0);
    }
    

    if (strcmp(argv[1], "--alias-user-delete") == 0) {
      if (argc < 4) {
        fprintf(stderr, "❌ Not enough arguments for --alias-user-delete\n");
        exit(2);
      }
      if (!handle_alias_user_delete(argc, argv)) {
        fprintf(stderr, "❌ Failed to delete user alias\n");
        exit(2);
      }
      exit(0); // Graceful die
    }
    
    if (strcmp(argv[1], "--alias-user-delete-map") == 0) {
      if (argc < 4) {
        fprintf(stderr, "❌ Not enough arguments for --alias-user-delete-map (you must type YES)\n");
        exit(2);
      }
      if (strcmp(argv[3], "YES") != 0) {
        fprintf(stderr, "❌ You must confirm map deletion by typing YES\n");
        exit(2);
      }
      if (!handle_alias_user_delete_map(argc, argv)) {
        fprintf(stderr, "❌ Failed to delete user alias map file\n");
        exit(2);
      }
      exit(0);
    }

    if (strcmp(argv[1], "--alias-action-show") == 0) {
      if (argc == 2) {
        // No host provided -> Show all action aliases
        if (!handle_alias_action_show_all(argc, argv)) {
	  fprintf(stderr, "❌ Failed to show all action aliases\n");
	  exit(2);
        }
        exit(0);
      }

      if (argc < 3) {
        fprintf(stderr, "❌ Not enough arguments for --alias-action-show\n");
        exit(2);
      }

      if (!handle_alias_action_show(argc, argv)) {
        fprintf(stderr, "❌ Failed to show action aliases\n");
        exit(2);
      }
      exit(0); // Graceful die
    }
    

    if (strcmp(argv[1], "--alias-action-delete") == 0) {
      if (argc < 4) {
        fprintf(stderr, "❌ Not enough arguments for --alias-action-delete\n");
        exit(2);
      }
      if (!handle_alias_action_delete(argc, argv)) {
        fprintf(stderr, "❌ Failed to delete action alias\n");
        exit(2);
      }
      exit(0); // Graceful die
    }

    if (strcmp(argv[1], "--alias-show") == 0) {
      if (argc < 3) {
        fprintf(stderr, "❌ Not enough arguments for --alias-show\n");
        exit(2);
      }
      if (!handle_alias_show(argc, argv)) {
        fprintf(stderr, "❌ Failed to show aliases\n");
        exit(2);
      }
      exit(0);
    }
    if (strcmp(argv[1], "--alias-delete") == 0) {
      if (argc < 4) {
        fprintf(stderr, "❌ Not enough arguments for --alias-delete (you must type YES)\n");
        exit(2);
      }
      if (strcmp(argv[3], "YES") != 0) {
        fprintf(stderr, "❌ You must confirm destructive alias wipe by typing YES\n");
        exit(2);
      }
      if (!handle_alias_delete(argc, argv)) {
        fprintf(stderr, "❌ Failed to delete all aliases\n");
        exit(2);
      }
      exit(0);
    }

    if (strcmp(argv[1], "--alias-action-delete-map") == 0) {
      if (argc < 4) {
        fprintf(stderr, "❌ Not enough arguments for --alias-action-delete-map (you must type YES)\n");
        exit(2);
      }
      if (strcmp(argv[3], "YES") != 0) {
        fprintf(stderr, "❌ You must confirm map deletion by typing YES\n");
        exit(2);
      }
      if (!handle_alias_action_delete_map(argc, argv)) {
        fprintf(stderr, "❌ Failed to delete action alias map file\n");
        exit(2);
      }
      exit(0);
    }

    // end of alias hell. if you reached the bottom of the pit, your S.O.L.
    fprintf(stderr, "❌ Unknown alias command: %s\n", argv[1]);
    return 0;
}



static int handle_alias_user(int argc, char *argv[]) {
    const char *host = argv[2];
    const char *user = argv[3];
    const char *id_str = argv[4];

    uint32_t user_id = (uint32_t)atoi(id_str);
    if (user_id == 0) {
        fprintf(stderr, "❌ Invalid user ID: %s\n", id_str);
        return 0;
    }

    char path[PATH_MAX] = {0};
    snprintf(path, sizeof(path), "%s/.config/siglatch/%s/user.map", getenv("HOME"), host);

    AliasEntry *aliases = NULL;
    size_t alias_count = 0;

    if (access(path, F_OK) == 0) {
        // Alias file exists
        if (!read_alias_map(path, &aliases, &alias_count)) {
            fprintf(stderr, "❌ Failed to read existing alias file: %s\n", path);
            return 0;
        }
    } else {
        // Alias file does not exist
        aliases = NULL;
        alias_count = 0;
    }

    if (!update_alias_entry(&aliases, &alias_count, user, host, user_id)) {
        fprintf(stderr, "❌ Failed to update alias entry in memory\n");
        return 0;
    }

    if (!write_alias_map(path, aliases, alias_count)) {
        fprintf(stderr, "❌ Failed to write alias map back to disk: %s\n", path);
        return 0;
    }

    printf("✅ User alias updated successfully: %s -> %s (id=%u)\n", user, host, user_id);
    return 1;
}



static int handle_alias_action(int argc, char *argv[]) {
    const char *host = argv[2];
    const char *action = argv[3];
    const char *id_str = argv[4];

    uint32_t action_id = (uint32_t)atoi(id_str);
    if (action_id == 0) {
        fprintf(stderr, "❌ Invalid action ID: %s\n", id_str);
        return 0;
    }

    char path[PATH_MAX] = {0};
    snprintf(path, sizeof(path), "%s/.config/siglatch/%s/action.map", getenv("HOME"), host);

    AliasEntry *aliases = NULL;
    size_t alias_count = 0;

    if (access(path, F_OK) == 0) {
        // Alias file exists
        if (!read_alias_map(path, &aliases, &alias_count)) {
            fprintf(stderr, "❌ Failed to read existing alias file: %s\n", path);
            return 0;
        }
    } else {
        // Alias file does not exist
        aliases = NULL;
        alias_count = 0;
    }

    if (!update_alias_entry(&aliases, &alias_count, action, host, action_id)) {
        fprintf(stderr, "❌ Failed to update alias entry in memory\n");
        return 0;
    }

    if (!write_alias_map(path, aliases, alias_count)) {
        fprintf(stderr, "❌ Failed to write alias map back to disk: %s\n", path);
        return 0;
    }

    printf("✅ Action alias updated successfully: %s -> %s (id=%u)\n", action, host, action_id);
    return 1;
}


static int handle_alias_user_show(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "❌ Not enough arguments for --alias-user-show\n");
        return 0;
    }

    const char *host = argv[2];

    char path[PATH_MAX] = {0};
    snprintf(path, sizeof(path), "%s/.config/siglatch/%s/user.map", getenv("HOME"), host);

    AliasEntry *aliases = NULL;
    size_t alias_count = 0;

    if (access(path, F_OK) != 0) {
        fprintf(stderr, "❌ No user aliases found for host: %s\n", host);
        return 0;
    }

    if (!read_alias_map(path, &aliases, &alias_count)) {
        fprintf(stderr, "❌ Failed to read user alias map: %s\n", path);
        return 0;
    }

    printf("👥 User Aliases for %s:\n", host);
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
        fprintf(stderr, "❌ Not enough arguments for --alias-user-delete\n");
        return 0;
    }

    const char *host = argv[2];
    const char *user = argv[3];

    char path[PATH_MAX] = {0};
    snprintf(path, sizeof(path), "%s/.config/siglatch/%s/user.map", getenv("HOME"), host);

    if (access(path, F_OK) != 0) {
        fprintf(stderr, "❌ User alias map does not exist: %s\n", path);
        return 0;
    }

    AliasEntry *aliases = NULL;
    size_t alias_count = 0;

    if (!read_alias_map(path, &aliases, &alias_count)) {
        fprintf(stderr, "❌ Failed to read user alias map: %s\n", path);
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
        fprintf(stderr, "⚠️  Alias not found for user: %s\n", user);
        free(aliases);
        return 0;
    }

    if (!write_alias_map(path, aliases, new_count)) {
        fprintf(stderr, "❌ Failed to write updated alias map after deletion\n");
        free(aliases);
        return 0;
    }

    printf("🗑️  Deleted user alias: %s -> %s\n", user, host);
    free(aliases);
    return 1;
}

static int handle_alias_action_show(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "❌ Not enough arguments for --alias-action-show\n");
        return 0;
    }

    const char *host = argv[2];

    char path[PATH_MAX] = {0};
    snprintf(path, sizeof(path), "%s/.config/siglatch/%s/action.map", getenv("HOME"), host);

    AliasEntry *aliases = NULL;
    size_t alias_count = 0;

    if (access(path, F_OK) != 0) {
        fprintf(stderr, "❌ No action aliases found for host: %s\n", host);
        return 0;
    }

    if (!read_alias_map(path, &aliases, &alias_count)) {
        fprintf(stderr, "❌ Failed to read action alias map: %s\n", path);
        return 0;
    }

    printf("🎯 Action Aliases for %s:\n", host);
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
        fprintf(stderr, "❌ Not enough arguments for --alias-action-delete\n");
        return 0;
    }

    const char *host = argv[2];
    const char *action = argv[3];

    char path[PATH_MAX] = {0};
    snprintf(path, sizeof(path), "%s/.config/siglatch/%s/action.map", getenv("HOME"), host);

    if (access(path, F_OK) != 0) {
        fprintf(stderr, "❌ Action alias map does not exist: %s\n", path);
        return 0;
    }

    AliasEntry *aliases = NULL;
    size_t alias_count = 0;

    if (!read_alias_map(path, &aliases, &alias_count)) {
        fprintf(stderr, "❌ Failed to read action alias map: %s\n", path);
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
        fprintf(stderr, "⚠️  Alias not found for action: %s\n", action);
        free(aliases);
        return 0;
    }

    if (!write_alias_map(path, aliases, new_count)) {
        fprintf(stderr, "❌ Failed to write updated alias map after deletion\n");
        free(aliases);
        return 0;
    }

    printf("🗑️  Deleted action alias: %s -> %s\n", action, host);
    free(aliases);
    return 1;
}


static int handle_alias_action_show_all(int argc, char *argv[]) {
    (void)argc;
    (void)argv;

    const char *home = getenv("HOME");
    if (!home) {
        fprintf(stderr, "❌ HOME environment variable not set\n");
        return 0;
    }

    char base_path[PATH_MAX] = {0};
    snprintf(base_path, sizeof(base_path), "%s/.config/siglatch", home);

    DIR *dir = opendir(base_path);
    if (!dir) {
        fprintf(stderr, "❌ Failed to open siglatch config directory: %s\n", base_path);
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
            fprintf(stderr, "⚠️  Failed to show action aliases for host: %s\n", name);
        }
    }

    closedir(dir);

    if (!found_any) {
        printf("⚠️  No hosts found under: %s\n", base_path);
    }

    return 1;
}

static int handle_alias_user_show_all(int argc, char *argv[]) {
    (void)argc;
    (void)argv;

    const char *home = getenv("HOME");
    if (!home) {
        fprintf(stderr, "❌ HOME environment variable not set\n");
        return 0;
    }

    char base_path[PATH_MAX] = {0};
    snprintf(base_path, sizeof(base_path), "%s/.config/siglatch", home);

    DIR *dir = opendir(base_path);
    if (!dir) {
        fprintf(stderr, "❌ Failed to open siglatch config directory: %s\n", base_path);
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
            fprintf(stderr, "⚠️  Failed to show user aliases for host: %s\n", name);
        }
    }

    closedir(dir);

    if (!found_any) {
        printf("⚠️  No hosts found under: %s\n", base_path);
    }

    return 1;
}


static int handle_alias_show(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "❌ Not enough arguments for --alias-show\n");
        return 0;
    }

    const char *host = argv[2];

    // Fake up argc/argv to call internal handlers cleanly
    char *fake_argv_user[] = { "program", "--alias-user-show", (char *)host };
    char *fake_argv_action[] = { "program", "--alias-action-show", (char *)host };

    printf("\n");
    if (!handle_alias_user_show(3, fake_argv_user)) {
        fprintf(stderr, "⚠️  Failed to show user aliases for host: %s\n", host);
    }

    printf("\n");
    if (!handle_alias_action_show(3, fake_argv_action)) {
        fprintf(stderr, "⚠️  Failed to show action aliases for host: %s\n", host);
    }

    return 1;
}


#include <unistd.h>

static int handle_alias_delete(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "❌ Not enough arguments for --alias-delete (missing YES confirmation)\n");
        return 0;
    }

    const char *host = argv[2];
    const char *confirmation = argv[3];

    if (strcmp(confirmation, "YES") != 0) {
        fprintf(stderr, "❌ You must confirm alias wipe by typing YES\n");
        return 0;
    }

    char base_path[PATH_MAX] = {0};
    snprintf(base_path, sizeof(base_path), "%s/.config/siglatch/%s", getenv("HOME"), host);

    // Target files
    char user_map_path[PATH_MAX] = {0};
    snprintf(user_map_path, sizeof(user_map_path), "%s/user.map", base_path);

    char action_map_path[PATH_MAX] = {0};
    snprintf(action_map_path, sizeof(action_map_path), "%s/action.map", base_path);

    int success = 1;

    if (access(user_map_path, F_OK) == 0) {
        if (unlink(user_map_path) != 0) {
            fprintf(stderr, "❌ Failed to delete user alias file: %s (%s)\n", user_map_path, strerror(errno));
            success = 0;
        } else {
            printf("🗑️  Deleted user alias file: %s\n", user_map_path);
        }
    } else {
        printf("⚠️  User alias file does not exist: %s\n", user_map_path);
    }

    if (access(action_map_path, F_OK) == 0) {
        if (unlink(action_map_path) != 0) {
            fprintf(stderr, "❌ Failed to delete action alias file: %s (%s)\n", action_map_path, strerror(errno));
            success = 0;
        } else {
            printf("🗑️  Deleted action alias file: %s\n", action_map_path);
        }
    } else {
        printf("⚠️  Action alias file does not exist: %s\n", action_map_path);
    }

    return success;
}


static int handle_alias_user_delete_map(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "❌ Not enough arguments for --alias-user-delete-map\n");
        return 0;
    }

    const char *host = argv[2];
    const char *confirmation = argv[3];

    if (strcmp(confirmation, "YES") != 0) {
        fprintf(stderr, "❌ You must confirm deletion by typing YES\n");
        return 0;
    }

    char path[PATH_MAX] = {0};
    snprintf(path, sizeof(path), "%s/.config/siglatch/%s/user.map", getenv("HOME"), host);

    if (access(path, F_OK) != 0) {
        fprintf(stderr, "⚠️  User map file does not exist: %s\n", path);
        return 0;
    }

    if (unlink(path) != 0) {
        fprintf(stderr, "❌ Failed to delete user map file: %s (%s)\n", path, strerror(errno));
        return 0;
    }

    printf("🗑️  Deleted user map file for host: %s\n", host);
    return 1;
}

static int handle_alias_action_delete_map(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "❌ Not enough arguments for --alias-action-delete-map\n");
        return 0;
    }

    const char *host = argv[2];
    const char *confirmation = argv[3];

    if (strcmp(confirmation, "YES") != 0) {
        fprintf(stderr, "❌ You must confirm deletion by typing YES\n");
        return 0;
    }

    char path[PATH_MAX] = {0};
    snprintf(path, sizeof(path), "%s/.config/siglatch/%s/action.map", getenv("HOME"), host);

    if (access(path, F_OK) != 0) {
        fprintf(stderr, "⚠️  Action map file does not exist: %s\n", path);
        return 0;
    }

    if (unlink(path) != 0) {
        fprintf(stderr, "❌ Failed to delete action map file: %s (%s)\n", path, strerror(errno));
        return 0;
    }

    printf("🗑️  Deleted action map file for host: %s\n", host);
    return 1;
}
