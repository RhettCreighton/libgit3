/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "grafts.h"

#include "futils.h"
#include "oid.h"
#include "oidarray.h"
#include "parse.h"
#include "hashmap_oid.h"

GIT3_HASHMAP_OID_SETUP(git3_grafts_oidmap, git3_commit_graft *);

struct git3_grafts {
	/* Map of `git3_commit_graft`s */
	git3_grafts_oidmap commits;

	/* Type of object IDs */
	git3_oid_t oid_type;

	/* File backing the graft. NULL if it's an in-memory graft */
	char *path;
	unsigned char path_checksum[GIT3_HASH_SHA256_SIZE];
};

int git3_grafts_new(git3_grafts **out, git3_oid_t oid_type)
{
	git3_grafts *grafts;

	GIT3_ASSERT_ARG(out && oid_type);

	grafts = git3__calloc(1, sizeof(*grafts));
	GIT3_ERROR_CHECK_ALLOC(grafts);

	grafts->oid_type = oid_type;

	*out = grafts;
	return 0;
}

int git3_grafts_open(
	git3_grafts **out,
	const char *path,
	git3_oid_t oid_type)
{
	git3_grafts *grafts = NULL;
	int error;

	GIT3_ASSERT_ARG(out && path && oid_type);

	if ((error = git3_grafts_new(&grafts, oid_type)) < 0)
		goto error;

	grafts->path = git3__strdup(path);
	GIT3_ERROR_CHECK_ALLOC(grafts->path);

	if ((error = git3_grafts_refresh(grafts)) < 0)
		goto error;

	*out = grafts;

error:
	if (error < 0)
		git3_grafts_free(grafts);

	return error;
}

int git3_grafts_open_or_refresh(
	git3_grafts **out,
	const char *path,
	git3_oid_t oid_type)
{
	GIT3_ASSERT_ARG(out && path && oid_type);

	return *out ? git3_grafts_refresh(*out) : git3_grafts_open(out, path, oid_type);
}

void git3_grafts_free(git3_grafts *grafts)
{
	if (!grafts)
		return;
	git3__free(grafts->path);
	git3_grafts_clear(grafts);
	git3_grafts_oidmap_dispose(&grafts->commits);
	git3__free(grafts);
}

void git3_grafts_clear(git3_grafts *grafts)
{
	git3_hashmap_iter_t iter = GIT3_HASHMAP_ITER_INIT;
	git3_commit_graft *graft;

	if (!grafts)
		return;

	while (git3_grafts_oidmap_iterate(&iter, NULL, &graft, &grafts->commits) == 0) {
		git3__free(graft->parents.ptr);
		git3__free(graft);
	}

	git3_grafts_oidmap_clear(&grafts->commits);
}

int git3_grafts_refresh(git3_grafts *grafts)
{
	git3_str contents = GIT3_STR_INIT;
	int error, updated = 0;

	GIT3_ASSERT_ARG(grafts);

	if (!grafts->path)
		return 0;

	if ((error = git3_futils_readbuffer_updated(&contents, grafts->path,
				grafts->path_checksum, &updated)) < 0) {

		if (error == GIT3_ENOTFOUND) {
			git3_grafts_clear(grafts);
			error = 0;
		}

		goto cleanup;
	}

	if (!updated) {
		goto cleanup;
	}

	if ((error = git3_grafts_parse(grafts, contents.ptr, contents.size)) < 0)
		goto cleanup;

cleanup:
	git3_str_dispose(&contents);
	return error;
}

int git3_grafts_parse(git3_grafts *grafts, const char *buf, size_t len)
{
	git3_array_oid_t parents = GIT3_ARRAY_INIT;
	git3_parse_ctx parser;
	int error;

	git3_grafts_clear(grafts);

	if ((error = git3_parse_ctx_init(&parser, buf, len)) < 0)
		goto error;

	for (; parser.remain_len; git3_parse_advance_line(&parser)) {
		git3_oid graft_oid;

		if ((error = git3_parse_advance_oid(&graft_oid, &parser, grafts->oid_type)) < 0) {
			git3_error_set(GIT3_ERROR_GRAFTS, "invalid graft OID at line %" PRIuZ, parser.line_num);
			goto error;
		}

		while (parser.line_len && git3_parse_advance_expected(&parser, "\n", 1) != 0) {
			git3_oid *id = git3_array_alloc(parents);
			GIT3_ERROR_CHECK_ALLOC(id);

			if ((error = git3_parse_advance_expected(&parser, " ", 1)) < 0 ||
			    (error = git3_parse_advance_oid(id, &parser, grafts->oid_type)) < 0) {
				git3_error_set(GIT3_ERROR_GRAFTS, "invalid parent OID at line %" PRIuZ, parser.line_num);
				goto error;
			}
		}

		if ((error = git3_grafts_add(grafts, &graft_oid, parents)) < 0)
			goto error;

		git3_array_clear(parents);
	}

error:
	git3_array_clear(parents);
	return error;
}

int git3_grafts_add(git3_grafts *grafts, const git3_oid *oid, git3_array_oid_t parents)
{
	git3_commit_graft *graft;
	git3_oid *parent_oid;
	int error;
	size_t i;

	GIT3_ASSERT_ARG(grafts && oid);

	graft = git3__calloc(1, sizeof(*graft));
	GIT3_ERROR_CHECK_ALLOC(graft);

	git3_array_init_to_size(graft->parents, git3_array_size(parents));
	git3_array_foreach(parents, i, parent_oid) {
		git3_oid *id = git3_array_alloc(graft->parents);
		GIT3_ERROR_CHECK_ALLOC(id);

		git3_oid_cpy(id, parent_oid);
	}
	git3_oid_cpy(&graft->oid, oid);

	if ((error = git3_grafts_remove(grafts, &graft->oid)) < 0 && error != GIT3_ENOTFOUND)
		goto cleanup;

	if ((error = git3_grafts_oidmap_put(&grafts->commits, &graft->oid, graft)) < 0)
		goto cleanup;

	return 0;

cleanup:
	git3_array_clear(graft->parents);
	git3__free(graft);
	return error;
}

int git3_grafts_remove(git3_grafts *grafts, const git3_oid *oid)
{
	git3_commit_graft *graft;
	int error;

	GIT3_ASSERT_ARG(grafts && oid);

	if (git3_grafts_oidmap_get(&graft, &grafts->commits, oid) != 0)
		return GIT3_ENOTFOUND;

	if ((error = git3_grafts_oidmap_remove(&grafts->commits, oid)) < 0)
		return error;

	git3__free(graft->parents.ptr);
	git3__free(graft);

	return 0;
}

int git3_grafts_get(git3_commit_graft **out, git3_grafts *grafts, const git3_oid *oid)
{
	GIT3_ASSERT_ARG(out && grafts && oid);
	return git3_grafts_oidmap_get(out, &grafts->commits, oid);
}

int git3_grafts_oids(git3_oid **out, size_t *out_len, git3_grafts *grafts)
{
	git3_hashmap_iter_t iter = GIT3_HASHMAP_ITER_INIT;
	git3_array_oid_t array = GIT3_ARRAY_INIT;
	const git3_oid *oid;
	size_t existing;

	GIT3_ASSERT_ARG(out && grafts);

	if ((existing = git3_grafts_oidmap_size(&grafts->commits)) > 0)
		git3_array_init_to_size(array, existing);

	while (git3_grafts_oidmap_iterate(&iter, &oid, NULL, &grafts->commits) == 0) {
		git3_oid *cpy = git3_array_alloc(array);
		GIT3_ERROR_CHECK_ALLOC(cpy);
		git3_oid_cpy(cpy, oid);
	}

	*out = array.ptr;
	*out_len = array.size;

	return 0;
}

size_t git3_grafts_size(git3_grafts *grafts)
{
	return git3_grafts_oidmap_size(&grafts->commits);
}
