/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "common.h"

#include "git3/sys/filter.h"
#include "filter.h"
#include "str.h"

static int ident_find_id(
	const char **id_start, const char **id_end, const char *start, size_t len)
{
	const char *end = start + len, *found = NULL;

	while (len > 3 && (found = memchr(start, '$', len)) != NULL) {
		size_t remaining = (size_t)(end - found) - 1;
		if (remaining < 3)
			return GIT3_ENOTFOUND;

		start = found + 1;
		len   = remaining;

		if (start[0] == 'I' && start[1] == 'd')
			break;
	}

	if (len < 3 || !found)
		return GIT3_ENOTFOUND;
	*id_start = found;

	if ((found = memchr(start + 2, '$', len - 2)) == NULL)
		return GIT3_ENOTFOUND;

	*id_end = found + 1;
	return 0;
}

static int ident_insert_id(
	git3_str *to, const git3_str *from, const git3_filter_source *src)
{
	char oid[GIT3_OID_MAX_HEXSIZE + 1];
	const char *id_start, *id_end, *from_end = from->ptr + from->size;
	size_t need_size;

	/* replace $Id$ with blob id */

	if (!git3_filter_source_id(src))
		return GIT3_PASSTHROUGH;

	git3_oid_tostr(oid, sizeof(oid), git3_filter_source_id(src));

	if (ident_find_id(&id_start, &id_end, from->ptr, from->size) < 0)
		return GIT3_PASSTHROUGH;

	need_size = (size_t)(id_start - from->ptr) +
		5 /* "$Id: " */ + GIT3_OID_MAX_HEXSIZE + 2 /* " $" */ +
		(size_t)(from_end - id_end);

	if (git3_str_grow(to, need_size) < 0)
		return -1;

	git3_str_set(to, from->ptr, (size_t)(id_start - from->ptr));
	git3_str_put(to, "$Id: ", 5);
	git3_str_puts(to, oid);
	git3_str_put(to, " $", 2);
	git3_str_put(to, id_end, (size_t)(from_end - id_end));

	return git3_str_oom(to) ? -1 : 0;
}

static int ident_remove_id(
	git3_str *to, const git3_str *from)
{
	const char *id_start, *id_end, *from_end = from->ptr + from->size;
	size_t need_size;

	if (ident_find_id(&id_start, &id_end, from->ptr, from->size) < 0)
		return GIT3_PASSTHROUGH;

	need_size = (size_t)(id_start - from->ptr) +
		4 /* "$Id$" */ + (size_t)(from_end - id_end);

	if (git3_str_grow(to, need_size) < 0)
		return -1;

	git3_str_set(to, from->ptr, (size_t)(id_start - from->ptr));
	git3_str_put(to, "$Id$", 4);
	git3_str_put(to, id_end, (size_t)(from_end - id_end));

	return git3_str_oom(to) ? -1 : 0;
}

static int ident_apply(
	git3_filter     *self,
	void          **payload,
	git3_str        *to,
	const git3_str  *from,
	const git3_filter_source *src)
{
	GIT3_UNUSED(self); GIT3_UNUSED(payload);

	/* Don't filter binary files */
	if (git3_str_is_binary(from))
		return GIT3_PASSTHROUGH;

	if (git3_filter_source_mode(src) == GIT3_FILTER_SMUDGE)
		return ident_insert_id(to, from, src);
	else
		return ident_remove_id(to, from);
}

static int ident_stream(
	git3_writestream **out,
	git3_filter *self,
	void **payload,
	const git3_filter_source *src,
	git3_writestream *next)
{
	return git3_filter_buffered_stream_new(out,
		self, ident_apply, NULL, payload, src, next);
}

git3_filter *git3_ident_filter_new(void)
{
	git3_filter *f = git3__calloc(1, sizeof(git3_filter));
	if (f == NULL)
		return NULL;

	f->version = GIT3_FILTER_VERSION;
	f->attributes = "+ident"; /* apply to files with ident attribute set */
	f->shutdown = git3_filter_free;
	f->stream   = ident_stream;

	return f;
}
