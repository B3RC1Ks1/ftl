#pragma once
#include "ftl.h"
#include <stdint.h>

typedef struct snapdb snapdb_t;

int snapdb_open(snapdb_t **out, const char *path, int create_fresh);
int snapdb_close(snapdb_t *db);

int snapshot_create(snapdb_t *db, ftl_t *ftl, const char *id);
int snapshot_restore(snapdb_t *db, ftl_t *ftl, const char *id);

void snapshot_list(const snapdb_t *db);
