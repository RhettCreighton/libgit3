/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_oid_h__
#define INCLUDE_oid_h__

#include "common.h"

#include "git3/experimental.h"
#include "git3/oid.h"
#include "hash.h"

#ifdef GIT3_EXPERIMENTAL_SHA256
# define GIT3_OID_NONE { 0, { 0 } }
# define GIT3_OID_INIT(type, ...) { type, __VA_ARGS__ }
#else
# define GIT3_OID_NONE { { 0 } }
# define GIT3_OID_INIT(type, ...) { __VA_ARGS__ }
#endif

extern const git3_oid git3_oid__empty_blob_sha1;
extern const git3_oid git3_oid__empty_tree_sha1;

GIT3_INLINE(git3_oid_t) git3_oid_type(const git3_oid *oid)
{
	/* For QED/libgit3: Always use the type field for proper SHA3-256 support */
	return oid->type;
}

GIT3_INLINE(size_t) git3_oid_size(git3_oid_t type)
{
	switch (type) {
	case GIT3_OID_SHA1:
		return GIT3_OID_SHA1_SIZE;

	case GIT3_OID_SHA3_256:
		return GIT3_OID_SHA3_256_SIZE;

#ifdef GIT3_EXPERIMENTAL_SHA256
	case GIT3_OID_SHA256:
		return GIT3_OID_SHA256_SIZE;
#endif

	}

	return 0;
}

GIT3_INLINE(size_t) git3_oid_hexsize(git3_oid_t type)
{
	switch (type) {
	case GIT3_OID_SHA1:
		return GIT3_OID_SHA1_HEXSIZE;

	case GIT3_OID_SHA3_256:
		return GIT3_OID_SHA3_256_HEXSIZE;

#ifdef GIT3_EXPERIMENTAL_SHA256
	case GIT3_OID_SHA256:
		return GIT3_OID_SHA256_HEXSIZE;
#endif

	}

	return 0;
}

GIT3_INLINE(bool) git3_oid_type_is_valid(git3_oid_t type)
{
	return (type == GIT3_OID_SHA1
	     || type == GIT3_OID_SHA3_256
#ifdef GIT3_EXPERIMENTAL_SHA256
	     || type == GIT3_OID_SHA256
#endif
	);
}

GIT3_INLINE(const char *) git3_oid_type_name(git3_oid_t type)
{
	switch (type) {
	case GIT3_OID_SHA1:
		return "sha1";

	case GIT3_OID_SHA3_256:
		return "sha3-256";

#ifdef GIT3_EXPERIMENTAL_SHA256
	case GIT3_OID_SHA256:
		return "sha256";
#endif
	}

	return "unknown";
}

GIT3_INLINE(git3_oid_t) git3_oid_type_fromstr(const char *name)
{
	if (strcmp(name, "sha1") == 0)
		return GIT3_OID_SHA1;

	if (strcmp(name, "sha3-256") == 0)
		return GIT3_OID_SHA3_256;

#ifdef GIT3_EXPERIMENTAL_SHA256
	if (strcmp(name, "sha256") == 0)
		return GIT3_OID_SHA256;
#endif

	return 0;
}

GIT3_INLINE(git3_oid_t) git3_oid_type_fromstrn(const char *name, size_t len)
{
	if (len == CONST_STRLEN("sha1") && strncmp(name, "sha1", len) == 0)
		return GIT3_OID_SHA1;

	if (len == CONST_STRLEN("sha3-256") && strncmp(name, "sha3-256", len) == 0)
		return GIT3_OID_SHA3_256;

#ifdef GIT3_EXPERIMENTAL_SHA256
	if (len == CONST_STRLEN("sha256") && strncmp(name, "sha256", len) == 0)
		return GIT3_OID_SHA256;
#endif

	return 0;
}

GIT3_INLINE(git3_hash_algorithm_t) git3_oid_algorithm(git3_oid_t type)
{
	switch (type) {
	case GIT3_OID_SHA1:
		return GIT3_HASH_ALGORITHM_SHA1;

	case GIT3_OID_SHA3_256:
		return GIT3_HASH_ALGORITHM_SHA3_256;

#ifdef GIT3_EXPERIMENTAL_SHA256
	case GIT3_OID_SHA256:
		return GIT3_HASH_ALGORITHM_SHA256;
#endif

	}

	return 0;
}

/**
 * Format a git3_oid into a newly allocated c-string.
 *
 * The c-string is owned by the caller and needs to be manually freed.
 *
 * @param id the oid structure to format
 * @return the c-string; NULL if memory is exhausted. Caller must
 *			deallocate the string with git3__free().
 */
char *git3_oid_allocfmt(const git3_oid *id);

/**
 * Format the requested nibbles of an object id.
 *
 * @param str the string to write into
 * @param oid the oid structure to format
 * @param start the starting number of nibbles
 * @param count the number of nibbles to format
 */
GIT3_INLINE(void) git3_oid_fmt_substr(
	char *str,
	const git3_oid *oid,
	size_t start,
	size_t count)
{
	static char hex[] = "0123456789abcdef";
	size_t i, end = start + count, min = start / 2, max = end / 2;

	if (start & 1)
		*str++ = hex[oid->id[min++] & 0x0f];

	for (i = min; i < max; i++) {
		*str++ = hex[oid->id[i] >> 4];
		*str++ = hex[oid->id[i] & 0x0f];
	}

	if (end & 1)
		*str++ = hex[oid->id[i] >> 4];
}

GIT3_INLINE(int) git3_oid_raw_ncmp(
	const unsigned char *sha1,
	const unsigned char *sha2,
	size_t len)
{
	if (len > GIT3_OID_MAX_HEXSIZE)
		len = GIT3_OID_MAX_HEXSIZE;

	while (len > 1) {
		if (*sha1 != *sha2)
			return 1;
		sha1++;
		sha2++;
		len -= 2;
	};

	if (len)
		if ((*sha1 ^ *sha2) & 0xf0)
			return 1;

	return 0;
}

GIT3_INLINE(int) git3_oid_raw_cmp(
	const unsigned char *sha1,
	const unsigned char *sha2,
	size_t size)
{
	return memcmp(sha1, sha2, size);
}

GIT3_INLINE(int) git3_oid_raw_cpy(
	unsigned char *dst,
	const unsigned char *src,
	size_t size)
{
	memcpy(dst, src, size);
	return 0;
}

/*
 * Compare two oid structures.
 *
 * @param a first oid structure.
 * @param b second oid structure.
 * @return <0, 0, >0 if a < b, a == b, a > b.
 */
GIT3_INLINE(int) git3_oid__cmp(const git3_oid *a, const git3_oid *b)
{
#ifdef GIT3_EXPERIMENTAL_SHA256
	if (a->type != b->type)
		return a->type - b->type;

	return git3_oid_raw_cmp(a->id, b->id, git3_oid_size(a->type));
#else
	return git3_oid_raw_cmp(a->id, b->id, git3_oid_size(GIT3_OID_SHA1));
#endif
}

GIT3_INLINE(void) git3_oid__cpy_prefix(
	git3_oid *out, const git3_oid *id, size_t len)
{
#ifdef GIT3_EXPERIMENTAL_SHA256
	out->type = id->type;
#endif

	memcpy(&out->id, id->id, (len + 1) / 2);

	if (len & 1)
		out->id[len / 2] &= 0xF0;
}

GIT3_INLINE(bool) git3_oid__is_hexstr(const char *str, git3_oid_t type)
{
	size_t i;

	for (i = 0; str[i] != '\0'; i++) {
		if (git3__fromhex(str[i]) < 0)
			return false;
	}

	return (i == git3_oid_hexsize(type));
}

GIT3_INLINE(void) git3_oid_clear(git3_oid *out, git3_oid_t type)
{
	memset(out->id, 0, git3_oid_size(type));

#ifdef GIT3_EXPERIMENTAL_SHA256
	out->type = type;
#endif
}

/* SHA256 support */

#ifndef GIT3_EXPERIMENTAL_SHA256
int git3_oid_from_string(git3_oid *out, const char *str, git3_oid_t type);
int git3_oid_from_prefix(git3_oid *out, const char *str, size_t len, git3_oid_t type);
int git3_oid_from_raw(git3_oid *out, const unsigned char *data, git3_oid_t type);
#endif

int git3_oid_global_init(void);

#endif
