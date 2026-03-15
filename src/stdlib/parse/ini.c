/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include "ini.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define INI_LINE_BUFFER_SIZE 4096

static IniContext ini_ctx = {0};

static int ini_set_context(const IniContext *ctx) {
  if (!ctx || !ctx->str ||
      !ctx->str->dup ||
      !ctx->str->len ||
      !ctx->str->trim ||
      !ctx->str->is_blank ||
      !ctx->str->split_kv) {
    return 0;
  }

  ini_ctx = *ctx;
  return 1;
}

static int ini_init(const IniContext *ctx) {
  return ini_set_context(ctx);
}

static void ini_shutdown(void) {
  ini_ctx = (IniContext){0};
}

static void ini_error_set(IniError *error, size_t line, const char *fmt, ...) {
  va_list args;

  if (!error) {
    return;
  }

  error->line = line;

  va_start(args, fmt);
  vsnprintf(error->message, sizeof(error->message), fmt, args);
  va_end(args);
}

static void ini_error_clear(IniError *error) {
  if (!error) {
    return;
  }

  error->line = 0;
  error->message[0] = '\0';
}

static void ini_free_section(IniSection *section) {
  size_t i = 0;

  if (!section) {
    return;
  }

  free(section->name);
  section->name = NULL;

  for (i = 0; i < section->entry_count; ++i) {
    free(section->entries[i].key);
    free(section->entries[i].value);
  }

  free(section->entries);
  section->entries = NULL;
  section->entry_count = 0;
  section->line = 0;
}

static void ini_destroy(IniDocument *document) {
  size_t i = 0;

  if (!document) {
    return;
  }

  ini_free_section(&document->global);

  for (i = 0; i < document->section_count; ++i) {
    ini_free_section(&document->sections[i]);
  }

  free(document->sections);
  free(document);
}

static IniSection *ini_append_section(IniDocument *document,
                                      const char *name,
                                      size_t line,
                                      IniError *error) {
  IniSection *sections = NULL;
  IniSection *section = NULL;
  size_t next_count = 0;

  if (!document || !name) {
    ini_error_set(error, line, "Invalid section append request");
    return NULL;
  }

  next_count = document->section_count + 1;
  sections = (IniSection *)realloc(document->sections, next_count * sizeof(*sections));
  if (!sections) {
    ini_error_set(error, line, "Out of memory while adding section");
    return NULL;
  }

  document->sections = sections;
  section = &document->sections[document->section_count];
  *section = (IniSection){0};

  section->name = ini_ctx.str->dup(name);
  if (!section->name) {
    ini_error_set(error, line, "Out of memory while copying section name");
    return NULL;
  }

  section->line = line;
  document->section_count = next_count;
  return section;
}

static int ini_append_entry(IniSection *section,
                            const char *key,
                            const char *value,
                            size_t line,
                            IniError *error) {
  IniEntry *entries = NULL;
  IniEntry *entry = NULL;
  size_t next_count = 0;

  if (!section || !key || !value) {
    ini_error_set(error, line, "Invalid key/value append request");
    return 0;
  }

  next_count = section->entry_count + 1;
  entries = (IniEntry *)realloc(section->entries, next_count * sizeof(*entries));
  if (!entries) {
    ini_error_set(error, line, "Out of memory while adding key/value");
    return 0;
  }

  section->entries = entries;
  entry = &section->entries[section->entry_count];
  *entry = (IniEntry){0};

  entry->key = ini_ctx.str->dup(key);
  if (!entry->key) {
    ini_error_set(error, line, "Out of memory while copying key");
    return 0;
  }

  entry->value = ini_ctx.str->dup(value);
  if (!entry->value) {
    free(entry->key);
    entry->key = NULL;
    ini_error_set(error, line, "Out of memory while copying value");
    return 0;
  }

  entry->line = line;
  section->entry_count = next_count;
  return 1;
}

static int ini_parse_section_name(char *text,
                                  char **name_out,
                                  size_t line,
                                  IniError *error) {
  size_t len = 0;
  char *name = NULL;

  if (!text || !name_out) {
    ini_error_set(error, line, "Invalid section header");
    return 0;
  }

  if (!ini_ctx.str) {
    ini_error_set(error, line, "INI parser is not initialized");
    return 0;
  }

  len = ini_ctx.str->len(text);
  if (len < 2 || text[0] != '[' || text[len - 1] != ']') {
    ini_error_set(error, line, "Invalid section header '%s'", text);
    return 0;
  }

  text[len - 1] = '\0';
  name = ini_ctx.str->trim(text + 1);
  if (*name == '\0') {
    ini_error_set(error, line, "Section name cannot be empty");
    return 0;
  }

  *name_out = name;
  return 1;
}

static const IniSection *ini_find_section(const IniDocument *document, const char *name) {
  size_t i = 0;

  if (!document) {
    return NULL;
  }

  if (!name || *name == '\0') {
    return &document->global;
  }

  for (i = 0; i < document->section_count; ++i) {
    if (document->sections[i].name &&
        strcmp(document->sections[i].name, name) == 0) {
      return &document->sections[i];
    }
  }

  return NULL;
}

static const IniEntry *ini_find_entry(const IniSection *section, const char *key) {
  size_t i = 0;

  if (!section || !key) {
    return NULL;
  }

  for (i = 0; i < section->entry_count; ++i) {
    if (section->entries[i].key &&
        strcmp(section->entries[i].key, key) == 0) {
      return &section->entries[i];
    }
  }

  return NULL;
}

static const char *ini_get(const IniDocument *document, const char *section, const char *key) {
  const IniSection *target_section = NULL;
  const IniEntry *entry = NULL;

  target_section = ini_find_section(document, section);
  if (!target_section) {
    return NULL;
  }

  entry = ini_find_entry(target_section, key);
  return entry ? entry->value : NULL;
}

static IniDocument *ini_read_file(const char *path, IniError *error) {
  FILE *fp = NULL;
  IniDocument *document = NULL;
  IniSection *current = NULL;
  char line[INI_LINE_BUFFER_SIZE];
  size_t line_number = 0;

  if (!path) {
    ini_error_set(error, 0, "Missing INI file path");
    return NULL;
  }

  if (!ini_ctx.str) {
    ini_error_set(error, 0, "INI parser is not initialized");
    return NULL;
  }

  ini_error_clear(error);

  fp = fopen(path, "r");
  if (!fp) {
    ini_error_set(error, 0, "Failed to open INI file '%s'", path);
    return NULL;
  }

  document = (IniDocument *)calloc(1, sizeof(*document));
  if (!document) {
    fclose(fp);
    ini_error_set(error, 0, "Out of memory while creating INI document");
    return NULL;
  }

  current = &document->global;

  while (fgets(line, sizeof(line), fp)) {
    char *trimmed = line;
    char *section_name = NULL;
    char *key = NULL;
    char *value = NULL;

    line_number++;

    if (!strchr(line, '\n') && !feof(fp)) {
      ini_error_set(error, line_number, "INI line exceeds %d bytes", INI_LINE_BUFFER_SIZE - 1);
      goto fail;
    }

    trimmed = ini_ctx.str->trim(trimmed);

    if (line_number == 1 &&
        (unsigned char)trimmed[0] == 0xEF &&
        (unsigned char)trimmed[1] == 0xBB &&
        (unsigned char)trimmed[2] == 0xBF) {
      trimmed += 3;
      trimmed = ini_ctx.str->trim(trimmed);
    }

    if (ini_ctx.str->is_blank(trimmed)) {
      continue;
    }

    if (trimmed[0] == '#' || trimmed[0] == ';') {
      continue;
    }

    if (trimmed[0] == '[') {
      current = NULL;

      if (!ini_parse_section_name(trimmed, &section_name, line_number, error)) {
        goto fail;
      }

      current = ini_append_section(document, section_name, line_number, error);
      if (!current) {
        goto fail;
      }

      continue;
    }

    if (!ini_ctx.str->split_kv(trimmed, &key, &value)) {
      ini_error_set(error, line_number, "Invalid INI line '%s'", trimmed);
      goto fail;
    }

    if (*key == '\0') {
      ini_error_set(error, line_number, "INI key cannot be empty");
      goto fail;
    }

    if (!ini_append_entry(current, key, value, line_number, error)) {
      goto fail;
    }
  }

  if (ferror(fp)) {
    ini_error_set(error, line_number, "Failed while reading INI file '%s'", path);
    goto fail;
  }

  fclose(fp);
  return document;

fail:
  fclose(fp);
  ini_destroy(document);
  return NULL;
}

static const IniLib instance = {
  .init = ini_init,
  .shutdown = ini_shutdown,
  .set_context = ini_set_context,
  .read_file = ini_read_file,
  .destroy = ini_destroy,
  .find_section = ini_find_section,
  .find_entry = ini_find_entry,
  .get = ini_get
};

const IniLib *get_lib_parse_ini(void) {
  return &instance;
}
