/*
 * libgit3 commit-graph fuzzer target.
 *
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include <stdio.h>

#include "git3.h"

#include "common.h"
#include "str.h"
#include "futils.h"
#include "hash.h"
#include "commit_graph.h"

#include "standalone_driver.h"

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	GIT3_UNUSED(argc);
	GIT3_UNUSED(argv);

	if (git3_libgit3_init() < 0) {
		fprintf(stderr, "Failed to initialize libgit3\n");
		abort();
	}
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	git3_commit_graph_file file = {{0}};
	git3_commit_graph_entry e;
	git3_str commit_graph_buf = GIT3_STR_INIT;
	unsigned char hash[GIT3_HASH_SHA1_SIZE];
	git3_oid oid = GIT3_OID_NONE;
	bool append_hash = false;

	if (size < 4)
		return 0;

	/*
	 * If the first byte in the stream has the high bit set, append the
	 * SHA1 hash so that the file is somewhat valid.
	 */
	append_hash = *data & 0x80;
	/* Keep a 4-byte alignment to avoid unaligned accesses. */
	data += 4;
	size -= 4;

	if (append_hash) {
		if (git3_str_init(&commit_graph_buf, size + GIT3_HASH_SHA1_SIZE) < 0)
			goto cleanup;
		if (git3_hash_buf(hash, data, size, GIT3_HASH_ALGORITHM_SHA1) < 0) {
			fprintf(stderr, "Failed to compute the SHA1 hash\n");
			abort();
		}
		memcpy(commit_graph_buf.ptr, data, size);
		memcpy(commit_graph_buf.ptr + size, hash, GIT3_HASH_SHA1_SIZE);

		memcpy(oid.id, hash, GIT3_OID_SHA1_SIZE);
	} else {
		git3_str_attach_notowned(&commit_graph_buf, (char *)data, size);
	}

	if (git3_commit_graph_file_parse(
			    &file,
			    (const unsigned char *)git3_str_cstr(&commit_graph_buf),
			    git3_str_len(&commit_graph_buf))
	    < 0)
		goto cleanup;

	/* Search for any oid, just to exercise that codepath. */
	if (git3_commit_graph_entry_find(&e, &file, &oid, GIT3_OID_SHA1_HEXSIZE) < 0)
		goto cleanup;

cleanup:
	git3_commit_graph_file_close(&file);
	git3_str_dispose(&commit_graph_buf);
	return 0;
}
