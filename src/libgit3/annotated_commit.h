/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_annotated_commit_h__
#define INCLUDE_annotated_commit_h__

#include "common.h"

#include "oidarray.h"

#include "git3/oid.h"

typedef enum {
	GIT3_ANNOTATED_COMMIT_REAL = 1,
	GIT3_ANNOTATED_COMMIT_VIRTUAL = 2
} git3_annotated_commit_t;

/**
 * Internal structure for merge inputs.  An annotated commit is generally
 * "real" and backed by an actual commit in the repository, but merge will
 * internally create "virtual" commits that are in-memory intermediate
 * commits backed by an index.
 */
struct git3_annotated_commit {
	git3_annotated_commit_t type;

	/* real commit */
	git3_commit *commit;
	git3_tree *tree;

	/* virtual commit structure */
	git3_index *index;
	git3_array_oid_t parents;

	/* how this commit was looked up */
	const char *description;

	const char *ref_name;
	const char *remote_url;

	char id_str[GIT3_OID_MAX_HEXSIZE + 1];
};

extern int git3_annotated_commit_from_head(git3_annotated_commit **out,
	git3_repository *repo);
extern int git3_annotated_commit_from_commit(git3_annotated_commit **out,
	git3_commit *commit);

#endif
