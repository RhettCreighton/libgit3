/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "buf.h"
#include "common.h"

int git3_buf_sanitize(git3_buf *buf)
{
	GIT3_ASSERT_ARG(buf);

	if (buf->reserved > 0)
		buf->ptr[0] = '\0';
	else
		buf->ptr = git3_str__initstr;

	buf->size = 0;
	return 0;
}

int git3_buf_tostr(git3_str *out, git3_buf *buf)
{
	GIT3_ASSERT_ARG(out);
	GIT3_ASSERT_ARG(buf);

	if (git3_buf_sanitize(buf) < 0)
		return -1;

	out->ptr = buf->ptr;
	out->asize = buf->reserved;
	out->size = buf->size;

	buf->ptr = git3_str__initstr;
	buf->reserved = 0;
	buf->size = 0;

	return 0;
}

int git3_buf_fromstr(git3_buf *out, git3_str *str)
{
	GIT3_ASSERT_ARG(out);
	GIT3_ASSERT_ARG(str);

	out->ptr = str->ptr;
	out->reserved = str->asize;
	out->size = str->size;

	str->ptr = git3_str__initstr;
	str->asize = 0;
	str->size = 0;

	return 0;
}

void git3_buf_dispose(git3_buf *buf)
{
	if (!buf)
		return;

	if (buf->ptr != git3_str__initstr)
		git3__free(buf->ptr);

	buf->ptr = git3_str__initstr;
	buf->reserved = 0;
	buf->size = 0;
}

#ifndef GIT3_DEPRECATE_HARD
int git3_buf_grow(git3_buf *buffer, size_t target_size)
{
	char *newptr;

	if (buffer->reserved >= target_size)
		return 0;

	if (buffer->ptr == git3_str__initstr)
		newptr = git3__malloc(target_size);
	else
		newptr = git3__realloc(buffer->ptr, target_size);

	if (!newptr)
		return -1;

	buffer->ptr = newptr;
	buffer->reserved = target_size;
	return 0;
}

int git3_buf_set(git3_buf *buffer, const void *data, size_t datalen)
{
	size_t alloclen;

	GIT3_ERROR_CHECK_ALLOC_ADD(&alloclen, datalen, 1);

	if (git3_buf_grow(buffer, alloclen) < 0)
		return -1;

	memmove(buffer->ptr, data, datalen);
	buffer->size = datalen;
	buffer->ptr[buffer->size] = '\0';

	return 0;
}

int git3_buf_is_binary(const git3_buf *buf)
{
	git3_str str = GIT3_STR_INIT_CONST(buf->ptr, buf->size);
	return git3_str_is_binary(&str);
}

int git3_buf_contains_nul(const git3_buf *buf)
{
	git3_str str = GIT3_STR_INIT_CONST(buf->ptr, buf->size);
	return git3_str_contains_nul(&str);
}

void git3_buf_free(git3_buf *buffer)
{
	git3_buf_dispose(buffer);
}

#endif
