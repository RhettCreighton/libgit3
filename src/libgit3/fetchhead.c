/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "fetchhead.h"

#include "git3/types.h"
#include "git3/oid.h"

#include "str.h"
#include "futils.h"
#include "filebuf.h"
#include "refs.h"
#include "net.h"
#include "repository.h"

int git3_fetchhead_ref_cmp(const void *a, const void *b)
{
	const git3_fetchhead_ref *one = (const git3_fetchhead_ref *)a;
	const git3_fetchhead_ref *two = (const git3_fetchhead_ref *)b;

	if (one->is_merge && !two->is_merge)
		return -1;
	if (two->is_merge && !one->is_merge)
		return 1;

	if (one->ref_name && two->ref_name)
		return strcmp(one->ref_name, two->ref_name);
	else if (one->ref_name)
		return -1;
	else if (two->ref_name)
		return 1;

	return 0;
}

static char *sanitized_remote_url(const char *remote_url)
{
	git3_net_url url = GIT3_NET_URL_INIT;
	char *sanitized = NULL;
	int error;

	if (git3_net_url_parse(&url, remote_url) == 0) {
		git3_str buf = GIT3_STR_INIT;

		git3__free(url.username);
		git3__free(url.password);
		url.username = url.password = NULL;

		if ((error = git3_net_url_fmt(&buf, &url)) < 0)
			goto fallback;

		sanitized = git3_str_detach(&buf);
	}

fallback:
	if (!sanitized)
		sanitized = git3__strdup(remote_url);

	git3_net_url_dispose(&url);
	return sanitized;
}

int git3_fetchhead_ref_create(
	git3_fetchhead_ref **out,
	git3_oid *oid,
	unsigned int is_merge,
	const char *ref_name,
	const char *remote_url)
{
	git3_fetchhead_ref *fetchhead_ref;

	GIT3_ASSERT_ARG(out);
	GIT3_ASSERT_ARG(oid);

	*out = NULL;

	fetchhead_ref = git3__malloc(sizeof(git3_fetchhead_ref));
	GIT3_ERROR_CHECK_ALLOC(fetchhead_ref);

	memset(fetchhead_ref, 0x0, sizeof(git3_fetchhead_ref));

	git3_oid_cpy(&fetchhead_ref->oid, oid);
	fetchhead_ref->is_merge = is_merge;

	if (ref_name) {
		fetchhead_ref->ref_name = git3__strdup(ref_name);
		GIT3_ERROR_CHECK_ALLOC(fetchhead_ref->ref_name);
	}

	if (remote_url) {
		fetchhead_ref->remote_url = sanitized_remote_url(remote_url);
		GIT3_ERROR_CHECK_ALLOC(fetchhead_ref->remote_url);
	}

	*out = fetchhead_ref;

	return 0;
}

static int fetchhead_ref_write(
	git3_filebuf *file,
	git3_fetchhead_ref *fetchhead_ref)
{
	char oid[GIT3_OID_MAX_HEXSIZE + 1];
	const char *type, *name;
	int head = 0;

	GIT3_ASSERT_ARG(file);
	GIT3_ASSERT_ARG(fetchhead_ref);

	git3_oid_tostr(oid, GIT3_OID_MAX_HEXSIZE + 1, &fetchhead_ref->oid);

	if (git3__prefixcmp(fetchhead_ref->ref_name, GIT3_REFS_HEADS_DIR) == 0) {
		type = "branch ";
		name = fetchhead_ref->ref_name + strlen(GIT3_REFS_HEADS_DIR);
	} else if(git3__prefixcmp(fetchhead_ref->ref_name,
		GIT3_REFS_TAGS_DIR) == 0) {
		type = "tag ";
		name = fetchhead_ref->ref_name + strlen(GIT3_REFS_TAGS_DIR);
	} else if (!git3__strcmp(fetchhead_ref->ref_name, GIT3_HEAD_FILE)) {
		head = 1;
	} else {
		type = "";
		name = fetchhead_ref->ref_name;
	}

	if (head)
		return git3_filebuf_printf(file, "%s\t\t%s\n", oid, fetchhead_ref->remote_url);

	return git3_filebuf_printf(file, "%s\t%s\t%s'%s' of %s\n",
		oid,
		(fetchhead_ref->is_merge) ? "" : "not-for-merge",
		type,
		name,
		fetchhead_ref->remote_url);
}

int git3_fetchhead_write(git3_repository *repo, git3_vector *fetchhead_refs)
{
	git3_filebuf file = GIT3_FILEBUF_INIT;
	git3_str path = GIT3_STR_INIT;
	unsigned int i;
	git3_fetchhead_ref *fetchhead_ref;

	GIT3_ASSERT_ARG(repo);
	GIT3_ASSERT_ARG(fetchhead_refs);

	if (git3_str_joinpath(&path, repo->gitdir, GIT3_FETCH_HEAD_FILE) < 0)
		return -1;

	if (git3_filebuf_open(&file, path.ptr, GIT3_FILEBUF_APPEND, GIT3_REFS_FILE_MODE) < 0) {
		git3_str_dispose(&path);
		return -1;
	}

	git3_str_dispose(&path);

	git3_vector_sort(fetchhead_refs);

	git3_vector_foreach(fetchhead_refs, i, fetchhead_ref)
		fetchhead_ref_write(&file, fetchhead_ref);

	return git3_filebuf_commit(&file);
}

static int fetchhead_ref_parse(
	git3_oid *oid,
	unsigned int *is_merge,
	git3_str *ref_name,
	const char **remote_url,
	char *line,
	size_t line_num,
	git3_oid_t oid_type)
{
	char *oid_str, *is_merge_str, *desc, *name = NULL;
	const char *type = NULL;
	int error = 0;

	*remote_url = NULL;

	if (!*line) {
		git3_error_set(GIT3_ERROR_FETCHHEAD,
			"empty line in FETCH_HEAD line %"PRIuZ, line_num);
		return -1;
	}

	/* Compat with old git clients that wrote FETCH_HEAD like a loose ref. */
	if ((oid_str = git3__strsep(&line, "\t")) == NULL) {
		oid_str = line;
		line += strlen(line);

		*is_merge = 1;
	}

	if (strlen(oid_str) != git3_oid_hexsize(oid_type)) {
		git3_error_set(GIT3_ERROR_FETCHHEAD,
			"invalid object ID in FETCH_HEAD line %"PRIuZ, line_num);
		return -1;
	}

	if (git3_oid_from_string(oid, oid_str, oid_type) < 0) {
		const git3_error *oid_err = git3_error_last();
		const char *err_msg = oid_err ? oid_err->message : "invalid object ID";

		git3_error_set(GIT3_ERROR_FETCHHEAD, "%s in FETCH_HEAD line %"PRIuZ,
			err_msg, line_num);
		return -1;
	}

	/* Parse new data from newer git clients */
	if (*line) {
		if ((is_merge_str = git3__strsep(&line, "\t")) == NULL) {
			git3_error_set(GIT3_ERROR_FETCHHEAD,
				"invalid description data in FETCH_HEAD line %"PRIuZ, line_num);
			return -1;
		}

		if (*is_merge_str == '\0')
			*is_merge = 1;
		else if (strcmp(is_merge_str, "not-for-merge") == 0)
			*is_merge = 0;
		else {
			git3_error_set(GIT3_ERROR_FETCHHEAD,
				"invalid for-merge entry in FETCH_HEAD line %"PRIuZ, line_num);
			return -1;
		}

		if ((desc = line) == NULL) {
			git3_error_set(GIT3_ERROR_FETCHHEAD,
				"invalid description in FETCH_HEAD line %"PRIuZ, line_num);
			return -1;
		}

		if (git3__prefixcmp(desc, "branch '") == 0) {
			type = GIT3_REFS_HEADS_DIR;
			name = desc + 8;
		} else if (git3__prefixcmp(desc, "tag '") == 0) {
			type = GIT3_REFS_TAGS_DIR;
			name = desc + 5;
		} else if (git3__prefixcmp(desc, "'") == 0)
			name = desc + 1;

		if (name) {
			if ((desc = strstr(name, "' ")) == NULL ||
				git3__prefixcmp(desc, "' of ") != 0) {
				git3_error_set(GIT3_ERROR_FETCHHEAD,
					"invalid description in FETCH_HEAD line %"PRIuZ, line_num);
				return -1;
			}

			*desc = '\0';
			desc += 5;
		}

		*remote_url = desc;
	}

	git3_str_clear(ref_name);

	if (type)
		git3_str_join(ref_name, '/', type, name);
	else if(name)
		git3_str_puts(ref_name, name);

	return error;
}

int git3_repository_fetchhead_foreach(
	git3_repository *repo,
	git3_repository_fetchhead_foreach_cb cb,
	void *payload)
{
	git3_str path = GIT3_STR_INIT, file = GIT3_STR_INIT, name = GIT3_STR_INIT;
	const char *ref_name;
	git3_oid oid;
	const char *remote_url;
	unsigned int is_merge = 0;
	char *buffer, *line;
	size_t line_num = 0;
	int error = 0;

	GIT3_ASSERT_ARG(repo);
	GIT3_ASSERT_ARG(cb);

	if (git3_str_joinpath(&path, repo->gitdir, GIT3_FETCH_HEAD_FILE) < 0)
		return -1;

	if ((error = git3_futils_readbuffer(&file, git3_str_cstr(&path))) < 0)
		goto done;

	buffer = file.ptr;

	while ((line = git3__strsep(&buffer, "\n")) != NULL) {
		++line_num;

		if ((error = fetchhead_ref_parse(&oid, &is_merge, &name,
				&remote_url, line, line_num,
				repo->oid_type)) < 0)
			goto done;

		if (git3_str_len(&name) > 0)
			ref_name = git3_str_cstr(&name);
		else
			ref_name = NULL;

		error = cb(ref_name, remote_url, &oid, is_merge, payload);
		if (error) {
			git3_error_set_after_callback(error);
			goto done;
		}
	}

	if (*buffer) {
		git3_error_set(GIT3_ERROR_FETCHHEAD, "no EOL at line %"PRIuZ, line_num+1);
		error = -1;
		goto done;
	}

done:
	git3_str_dispose(&file);
	git3_str_dispose(&path);
	git3_str_dispose(&name);

	return error;
}

void git3_fetchhead_ref_free(git3_fetchhead_ref *fetchhead_ref)
{
	if (fetchhead_ref == NULL)
		return;

	git3__free(fetchhead_ref->remote_url);
	git3__free(fetchhead_ref->ref_name);
	git3__free(fetchhead_ref);
}

