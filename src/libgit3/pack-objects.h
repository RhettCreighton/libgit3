/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#ifndef INCLUDE_pack_objects_h__
#define INCLUDE_pack_objects_h__

#include "common.h"

#include "str.h"
#include "hash.h"
#include "zstream.h"
#include "pool.h"
#include "indexer.h"
#include "hashmap_oid.h"

#include "git3/oid.h"
#include "git3/pack.h"

#define GIT3_PACK_WINDOW 10 /* number of objects to possibly delta against */
#define GIT3_PACK_DEPTH 50 /* max delta depth */
#define GIT3_PACK_DELTA_CACHE_SIZE (256 * 1024 * 1024)
#define GIT3_PACK_DELTA_CACHE_LIMIT 1000
#define GIT3_PACK_BIG_FILE_THRESHOLD (512 * 1024 * 1024)

typedef struct git3_pobject {
	git3_oid id;
	git3_object_t type;
	off64_t offset;

	size_t size;

	unsigned int hash; /* name hint hash */

	struct git3_pobject *delta; /* delta base object */
	struct git3_pobject *delta_child; /* deltified objects who bases me */
	struct git3_pobject *delta_sibling; /* other deltified objects
					    * who uses the same base as
					    * me */

	void *delta_data;
	size_t delta_size;
	size_t z_delta_size;

	unsigned int written:1,
	             recursing:1,
	             tagged:1,
	             filled:1;
} git3_pobject;

typedef struct walk_object walk_object;

GIT3_HASHMAP_OID_STRUCT(git3_packbuilder_pobjectmap, git3_pobject *);
GIT3_HASHMAP_OID_STRUCT(git3_packbuilder_walk_objectmap, walk_object *);

struct git3_packbuilder {
	git3_repository *repo; /* associated repository */
	git3_odb *odb; /* associated object database */

	git3_oid_t oid_type;

	git3_hash_ctx ctx;
	git3_zstream zstream;

	uint32_t nr_objects,
		nr_deltified,
		nr_written,
		nr_remaining;

	size_t nr_alloc;

	git3_pobject *object_list;

	git3_packbuilder_pobjectmap object_ix;
	git3_packbuilder_walk_objectmap walk_objects;
	git3_pool object_pool;

#ifndef GIT3_DEPRECATE_HARD
	git3_oid pack_oid; /* hash of written pack */
#endif
	char *pack_name; /* name of written pack */

	/* synchronization objects */
	git3_mutex cache_mutex;
	git3_mutex progress_mutex;
	git3_cond progress_cond;

	/* configs */
	size_t delta_cache_size;
	size_t max_delta_cache_size;
	size_t cache_max_small_delta_size;
	size_t big_file_threshold;
	size_t window_memory_limit;

	unsigned int nr_threads; /* nr of threads to use */

	git3_packbuilder_progress progress_cb;
	void *progress_cb_payload;

	/* the time progress was last reported, in millisecond ticks */
	uint64_t last_progress_report_time;

	bool done;

	/* A non-zero error code in failure causes all threads to shut themselves
	   down. Some functions will return this error code.  */
	volatile int failure;
};

int git3_packbuilder__write_buf(git3_str *buf, git3_packbuilder *pb);
int git3_packbuilder__prepare(git3_packbuilder *pb);


#endif
