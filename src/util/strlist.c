/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include <stdio.h>

#include "git3_util.h"
#include "vector.h"
#include "strlist.h"

int git3_strlist_copy(char ***out, const char **in, size_t len)
{
	char **dup;
	size_t i;

	dup = git3__calloc(len, sizeof(char *));
	GIT3_ERROR_CHECK_ALLOC(dup);

	for (i = 0; i < len; i++) {
		dup[i] = git3__strdup(in[i]);
		GIT3_ERROR_CHECK_ALLOC(dup[i]);
	}

	*out = dup;
	return 0;
}

int git3_strlist_copy_with_null(char ***out, const char **in, size_t len)
{
	char **dup;
	size_t new_len, i;

	GIT3_ERROR_CHECK_ALLOC_ADD(&new_len, len, 1);

	dup = git3__calloc(new_len, sizeof(char *));
	GIT3_ERROR_CHECK_ALLOC(dup);

	for (i = 0; i < len; i++) {
		dup[i] = git3__strdup(in[i]);
		GIT3_ERROR_CHECK_ALLOC(dup[i]);
	}

	*out = dup;
	return 0;
}

bool git3_strlist_contains_prefix(
	const char **strings,
	size_t len,
	const char *str,
	size_t n)
{
	size_t i;

	for (i = 0; i < len; i++) {
		if (strncmp(strings[i], str, n) == 0)
			return true;
	}

	return false;
}

bool git3_strlist_contains_key(
	const char **strings,
	size_t len,
	const char *key,
	char delimiter)
{
	const char *c;

	for (c = key; *c; c++) {
		if (*c == delimiter)
			break;
	}

	return *c ?
	       git3_strlist_contains_prefix(strings, len, key, (c - key)) :
	       false;
}

void git3_strlist_free(char **strings, size_t len)
{
	size_t i;

	if (!strings)
		return;

	for (i = 0; i < len; i++)
		git3__free(strings[i]);

	git3__free(strings);
}

void git3_strlist_free_with_null(char **strings)
{
	char **s;

	if (!strings)
		return;

	for (s = strings; *s; s++)
		git3__free(*s);

	git3__free(strings);
}
