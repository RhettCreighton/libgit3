/*
 * libgit3 packfile fuzzer target.
 *
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include <stdio.h>

#include "git3.h"
#include "git3/sys/mempack.h"
#include "common.h"
#include "str.h"

#include "standalone_driver.h"

static git3_odb *odb = NULL;
static git3_odb_backend *mempack = NULL;

/* Arbitrary object to seed the ODB. */
static const unsigned char base_obj[] = { 07, 076 };
static const unsigned int base_obj_len = 2;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	GIT3_UNUSED(argc);
	GIT3_UNUSED(argv);

	if (git3_libgit3_init() < 0) {
		fprintf(stderr, "Failed to initialize libgit3\n");
		abort();
	}
	if (git3_libgit3_opts(GIT3_OPT_SET_PACK_MAX_OBJECTS, 10000000) < 0) {
		fprintf(stderr, "Failed to limit maximum pack object count\n");
		abort();
	}

	if (git3_odb_new(&odb) < 0) {
		fprintf(stderr, "Failed to create the odb\n");
		abort();
	}

	if (git3_mempack_new(&mempack) < 0) {
		fprintf(stderr, "Failed to create the mempack\n");
		abort();
	}
	if (git3_odb_add_backend(odb, mempack, 999) < 0) {
		fprintf(stderr, "Failed to add the mempack\n");
		abort();
	}
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	git3_indexer_progress stats = {0, 0};
	git3_indexer *indexer = NULL;
	git3_str path = GIT3_STR_INIT;
	git3_oid oid;
	bool append_hash = false;
	int error;

	if (size == 0)
		return 0;

	if (!odb || !mempack) {
		fprintf(stderr, "Global state not initialized\n");
		abort();
	}
	git3_mempack_reset(mempack);

	if (git3_odb_write(&oid, odb, base_obj, base_obj_len, GIT3_OBJECT_BLOB) < 0) {
		fprintf(stderr, "Failed to add an object to the odb\n");
		abort();
	}

#ifdef GIT3_EXPERIMENTAL_SHA256
	error = git3_indexer_new(&indexer, ".", NULL);
#else
	error = git3_indexer_new(&indexer, ".", 0, odb, NULL);
#endif

	if (error < 0) {
		fprintf(stderr, "Failed to create the indexer: %s\n",
			git3_error_last()->message);
		abort();
	}

	/*
	 * If the first byte in the stream has the high bit set, append the
	 * SHA1 hash so that the packfile is somewhat valid.
	 */
	append_hash = *data & 0x80;
	++data;
	--size;

	if (git3_indexer_append(indexer, data, size, &stats) < 0)
		goto cleanup;
	if (append_hash) {
#ifdef GIT3_EXPERIMENTAL_SHA256
		if (git3_odb_hash(&oid, data, size, GIT3_OBJECT_BLOB, GIT3_OID_SHA1) < 0) {
			fprintf(stderr, "Failed to compute the SHA1 hash\n");
			abort();
		}
#else
		if (git3_odb_hash(&oid, data, size, GIT3_OBJECT_BLOB) < 0) {
			fprintf(stderr, "Failed to compute the SHA1 hash\n");
			abort();
		}
#endif

		if (git3_indexer_append(indexer, &oid.id, GIT3_OID_SHA1_SIZE, &stats) < 0) {
			goto cleanup;
		}
	}
	if (git3_indexer_commit(indexer, &stats) < 0)
		goto cleanup;

	if (git3_str_printf(&path, "pack-%s.idx", git3_indexer_name(indexer)) < 0)
		goto cleanup;
	p_unlink(git3_str_cstr(&path));

	git3_str_clear(&path);

	if (git3_str_printf(&path, "pack-%s.pack", git3_indexer_name(indexer)) < 0)
		goto cleanup;
	p_unlink(git3_str_cstr(&path));

cleanup:
	git3_mempack_reset(mempack);
	git3_indexer_free(indexer);
	git3_str_dispose(&path);
	return 0;
}
