/*
 * libgit3 patch parser fuzzer target.
 *
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "git3.h"
#include "patch.h"
#include "patch_parse.h"

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
	if (size) {
		git3_patch *patch = NULL;
		git3_patch_options opts = GIT3_PATCH_OPTIONS_INIT;
		opts.prefix_len = (uint32_t)data[0];
		git3_patch_from_buffer(&patch, (const char *)data + 1, size - 1,
		                      &opts);
		git3_patch_free(patch);
	}
	return 0;
}
