/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include <stdio.h>

#include "git3.h"
#include "futils.h"
#include "path.h"

#include "standalone_driver.h"

static int run_one_file(const char *filename)
{
	git3_str buf = GIT3_STR_INIT;
	int error = 0;

	if (git3_futils_readbuffer(&buf, filename) < 0) {
		fprintf(stderr, "Failed to read %s: %s\n", filename, git3_error_last()->message);
		error = -1;
		goto exit;
	}

	LLVMFuzzerTestOneInput((const unsigned char *)buf.ptr, buf.size);
exit:
	git3_str_dispose(&buf);
	return error;
}

int main(int argc, char **argv)
{
	git3_vector corpus_files = GIT3_VECTOR_INIT;
	char *filename = NULL;
	unsigned i = 0;
	int error = 0;

	if (git3_libgit3_init() < 0) {
		fprintf(stderr, "Failed to initialize libgit3\n");
		abort();
	}

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <corpus directory>\n", argv[0]);
		error = -1;
		goto exit;
	}

	fprintf(stderr, "Running %s against %s\n", argv[0], argv[1]);
	LLVMFuzzerInitialize(&argc, &argv);

	if (git3_fs_path_dirload(&corpus_files, argv[1], 0, 0x0) < 0) {
		fprintf(stderr, "Failed to scan corpus directory '%s': %s\n",
			argv[1], git3_error_last()->message);
		error = -1;
		goto exit;
	}
	git3_vector_foreach(&corpus_files, i, filename) {
		fprintf(stderr, "\tRunning %s...\n", filename);
		if (run_one_file(filename) < 0) {
			error = -1;
			goto exit;
		}
	}
	fprintf(stderr, "Done %d runs\n", i);

exit:
	git3_vector_dispose_deep(&corpus_files);
	git3_libgit3_shutdown();
	return error;
}
