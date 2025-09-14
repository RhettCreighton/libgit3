/*
 * libgit3 revparse fuzzer target.
 *
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include <stdio.h>
#include <string.h>

#include "git3.h"

#include "standalone_driver.h"
#include "fuzzer_utils.h"

#define UNUSED(x) (void)(x)

static git3_repository *repo;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	UNUSED(argc);
	UNUSED(argv);

	if (git3_libgit3_init() < 0)
		abort();

	if (git3_libgit3_opts(GIT3_OPT_SET_PACK_MAX_OBJECTS, 10000000) < 0)
		abort();

	repo = fuzzer_repo_init();
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	git3_object *obj = NULL;
	char *c;

	if ((c = calloc(1, size + 1)) == NULL)
		abort();

	memcpy(c, data, size);

	git3_revparse_single(&obj, repo, c);
	git3_object_free(obj);
	free(c);

	return 0;
}
