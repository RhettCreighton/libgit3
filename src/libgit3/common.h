/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_common_h__
#define INCLUDE_common_h__

#include "git3_util.h"
#include "errors.h"

/*
* Include the declarations for deprecated functions; this ensures
* that they're decorated with the proper extern/visibility attributes.
*/
#include "git3/deprecated.h"

#include "posix.h"

/**
 * Initialize a structure with a version.
 */
GIT3_INLINE(void) git3__init_structure(void *structure, size_t len, unsigned int version)
{
	memset(structure, 0, len);
	*((int*)structure) = version;
}
#define GIT3_INIT_STRUCTURE(S,V) git3__init_structure(S, sizeof(*S), V)

#define GIT3_INIT_STRUCTURE_FROM_TEMPLATE(PTR,VERSION,TYPE,TPL) do { \
	TYPE _tmpl = TPL; \
	GIT3_ERROR_CHECK_VERSION(&(VERSION), _tmpl.version, #TYPE);      \
	memcpy((PTR), &_tmpl, sizeof(_tmpl)); } while (0)

/**
 * Check a versioned structure for validity
 */
GIT3_INLINE(int) git3_error__check_version(const void *structure, unsigned int expected_max, const char *name)
{
	unsigned int actual;

	if (!structure)
		return 0;

	actual = *(const unsigned int*)structure;
	if (actual > 0 && actual <= expected_max)
		return 0;

	git3_error_set(GIT3_ERROR_INVALID, "invalid version %d on %s", actual, name);
	return -1;
}
#define GIT3_ERROR_CHECK_VERSION(S,V,N) if (git3_error__check_version(S,V,N) < 0) return -1

#endif
