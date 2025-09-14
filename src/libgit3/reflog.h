/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_reflog_h__
#define INCLUDE_reflog_h__

#include "common.h"

#include "git3/reflog.h"
#include "vector.h"

#define GIT3_REFLOG_DIR "logs/"
#define GIT3_REFLOG_DIR_MODE 0777
#define GIT3_REFLOG_FILE_MODE 0666

struct git3_reflog_entry {
	git3_oid oid_old;
	git3_oid oid_cur;

	git3_signature *committer;

	char *msg;
};

struct git3_reflog {
	git3_refdb *db;
	char *ref_name;
	git3_oid_t oid_type;
	git3_vector entries;
};

GIT3_INLINE(size_t) reflog_inverse_index(size_t idx, size_t total)
{
	return (total - 1) - idx;
}

void git3_reflog_entry__free(git3_reflog_entry *entry);

#endif
