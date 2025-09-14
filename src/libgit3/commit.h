/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_commit_h__
#define INCLUDE_commit_h__

#include "common.h"

#include "git3/commit.h"
#include "tree.h"
#include "repository.h"
#include "array.h"

#include <time.h>

struct git3_commit {
	git3_object object;

	git3_array_t(git3_oid) parent_ids;
	git3_oid tree_id;

	git3_signature *author;
	git3_signature *committer;

	char *message_encoding;
	char *raw_message;
	char *raw_header;

	char *summary;
	char *body;
};

typedef struct {
	git3_oid_t oid_type;
	unsigned int flags;
} git3_commit__parse_options;

typedef enum {
	/** Only parse parents and committer info */
	GIT3_COMMIT_PARSE_QUICK = (1 << 0)
} git3_commit__parse_flags;

int git3_commit__header_field(
	git3_str *out,
	const git3_commit *commit,
	const char *field);

int git3_commit__extract_signature(
	git3_str *signature,
	git3_str *signed_data,
	git3_repository *repo,
	git3_oid *commit_id,
	const char *field);

int git3_commit__create_buffer(
	git3_str *out,
	git3_repository *repo,
	const git3_signature *author,
	const git3_signature *committer,
	const char *message_encoding,
	const char *message,
	const git3_tree *tree,
	size_t parent_count,
	const git3_commit *parents[]);

int git3_commit__parse(
	void *commit,
	git3_odb_object *obj,
	git3_oid_t oid_type);

int git3_commit__parse_raw(
	void *commit,
	const char *data,
	size_t size,
	git3_oid_t oid_type);

int git3_commit__parse_ext(
	git3_commit *commit,
	git3_odb_object *odb_obj,
	git3_commit__parse_options *parse_opts);

void git3_commit__free(void *commit);

#endif
