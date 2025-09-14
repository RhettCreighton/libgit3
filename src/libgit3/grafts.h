/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_graft_h__
#define INCLUDE_graft_h__

#include "common.h"
#include "oidarray.h"

/** graft commit */
typedef struct {
	git3_oid oid;
	git3_array_oid_t parents;
} git3_commit_graft;

typedef struct git3_grafts git3_grafts;

int git3_grafts_new(git3_grafts **out, git3_oid_t oid_type);
int git3_grafts_open(git3_grafts **out, const char *path, git3_oid_t oid_type);
int git3_grafts_open_or_refresh(git3_grafts **out, const char *path, git3_oid_t oid_type);
void git3_grafts_free(git3_grafts *grafts);
void git3_grafts_clear(git3_grafts *grafts);

int git3_grafts_refresh(git3_grafts *grafts);
int git3_grafts_parse(git3_grafts *grafts, const char *buf, size_t len);
int git3_grafts_add(git3_grafts *grafts, const git3_oid *oid, git3_array_oid_t parents);
int git3_grafts_remove(git3_grafts *grafts, const git3_oid *oid);
int git3_grafts_get(git3_commit_graft **out, git3_grafts *grafts, const git3_oid *oid);
int git3_grafts_oids(git3_oid **out, size_t *out_len, git3_grafts *grafts);
size_t git3_grafts_size(git3_grafts *grafts);

#endif
