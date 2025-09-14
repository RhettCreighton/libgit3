/*
 * libgit3 packfile fuzzer target.
 *
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "git3.h"
#include "object.h"

#include "standalone_driver.h"

#define UNUSED(x) (void)(x)

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	UNUSED(argc);
	UNUSED(argv);

	if (git3_libgit3_init() < 0)
		abort();

	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	const git3_object_t types[] = {
		GIT3_OBJECT_BLOB, GIT3_OBJECT_TREE, GIT3_OBJECT_COMMIT, GIT3_OBJECT_TAG
	};
	git3_object *object = NULL;
	size_t i;

	/*
	 * Brute-force parse this as every object type. We want
	 * to stress the parsing logic anyway, so this is fine
	 * to do.
	 */
	for (i = 0; i < ARRAY_SIZE(types); i++) {
		if (git3_object__from_raw(&object, (const char *) data, size, types[i], GIT3_OID_SHA1) < 0)
			continue;
		git3_object_free(object);
		object = NULL;
	}

	return 0;
}
