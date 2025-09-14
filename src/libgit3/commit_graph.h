/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#ifndef INCLUDE_commit_graph_h__
#define INCLUDE_commit_graph_h__

#include "common.h"

#include "git3/types.h"
#include "git3/sys/commit_graph.h"

#include "map.h"
#include "vector.h"
#include "oid.h"
#include "hash.h"

/**
 * A commit-graph file.
 *
 * This file contains metadata about commits, particularly the generation
 * number for each one. This can help speed up graph operations without
 * requiring a full graph traversal.
 *
 * Support for this feature was added in git 2.19.
 */
typedef struct git3_commit_graph_file {
	git3_map graph_map;

	/* The type of object IDs in the commit graph file. */
	git3_oid_t oid_type;

	/* The OID Fanout table. */
	const uint32_t *oid_fanout;
	/* The total number of commits in the graph. */
	uint32_t num_commits;

	/* The OID Lookup table. */
	unsigned char *oid_lookup;

	/*
	 * The Commit Data table. Each entry contains the OID of the commit followed
	 * by two 8-byte fields in network byte order:
	 * - The indices of the first two parents (32 bits each).
	 * - The generation number (first 30 bits) and commit time in seconds since
	 *   UNIX epoch (34 bits).
	 */
	const unsigned char *commit_data;

	/*
	 * The Extra Edge List table. Each 4-byte entry is a network byte order index
	 * of one of the i-th (i > 0) parents of commits in the `commit_data` table,
	 * when the commit has more than 2 parents.
	 */
	const unsigned char *extra_edge_list;
	/* The number of entries in the Extra Edge List table. Each entry is 4 bytes wide. */
	size_t num_extra_edge_list;

	/* The trailer of the file. Contains the SHA1-checksum of the whole file. */
	unsigned char checksum[GIT3_HASH_SHA1_SIZE];
} git3_commit_graph_file;

/**
 * An entry in the commit-graph file. Provides a subset of the information that
 * can be obtained from the commit header.
 */
typedef struct git3_commit_graph_entry {
	/* The generation number of the commit within the graph */
	size_t generation;

	/* Time in seconds from UNIX epoch. */
	git3_time_t commit_time;

	/* The number of parents of the commit. */
	size_t parent_count;

	/*
	 * The indices of the parent commits within the Commit Data table. The value
	 * of `GIT3_COMMIT_GRAPH_MISSING_PARENT` indicates that no parent is in that
	 * position.
	 */
	size_t parent_indices[2];

	/* The index within the Extra Edge List of any parent after the first two. */
	size_t extra_parents_index;

	/* The object ID of the root tree of the commit. */
	git3_oid tree_oid;

	/* The object ID hash of the requested commit. */
	git3_oid sha1;
} git3_commit_graph_entry;

/* A wrapper for git3_commit_graph_file to enable lazy loading in the ODB. */
struct git3_commit_graph {
	/* The path to the commit-graph file. Something like ".git/objects/info/commit-graph". */
	git3_str filename;

	/* The underlying commit-graph file. */
	git3_commit_graph_file *file;

	/* The object ID types in the commit graph. */
	git3_oid_t oid_type;

	/* Whether the commit-graph file was already checked for validity. */
	bool checked;
};

/** Create a new commit-graph, optionally opening the underlying file. */
int git3_commit_graph_new(
	git3_commit_graph **cgraph_out,
	const char *objects_dir,
	bool open_file,
	git3_oid_t oid_type);

/** Validate the checksum of a commit graph */
int git3_commit_graph_validate(git3_commit_graph *cgraph);

/** Open and validate a commit-graph file. */
int git3_commit_graph_file_open(
	git3_commit_graph_file **file_out,
	const char *path,
	git3_oid_t oid_type);

/*
 * Attempt to get the git3_commit_graph's commit-graph file. This object is
 * still owned by the git3_commit_graph. If the repository does not contain a commit graph,
 * it will return GIT3_ENOTFOUND.
 *
 * This function is not thread-safe.
 */
int git3_commit_graph_get_file(git3_commit_graph_file **file_out, git3_commit_graph *cgraph);

/* Marks the commit-graph file as needing a refresh. */
void git3_commit_graph_refresh(git3_commit_graph *cgraph);

/*
 * A writer for `commit-graph` files.
 */
struct git3_commit_graph_writer {
	/*
	 * The path of the `objects/info` directory where the `commit-graph` will be
	 * stored.
	 */
	git3_str objects_info_dir;

	/* The object ID type of the commit graph. */
	git3_oid_t oid_type;

	/* The list of packed commits. */
	git3_vector commits;
};

int git3_commit_graph__writer_dump(
	git3_str *cgraph,
	git3_commit_graph_writer *w);

/*
 * Returns whether the git3_commit_graph_file needs to be reloaded since the
 * contents of the commit-graph file have changed on disk.
 */
bool git3_commit_graph_file_needs_refresh(
		const git3_commit_graph_file *file, const char *path);

int git3_commit_graph_entry_find(
		git3_commit_graph_entry *e,
		const git3_commit_graph_file *file,
		const git3_oid *short_oid,
		size_t len);
int git3_commit_graph_entry_parent(
		git3_commit_graph_entry *parent,
		const git3_commit_graph_file *file,
		const git3_commit_graph_entry *entry,
		size_t n);
int git3_commit_graph_file_close(git3_commit_graph_file *cgraph);
void git3_commit_graph_file_free(git3_commit_graph_file *cgraph);

/* This is exposed for use in the fuzzers. */
int git3_commit_graph_file_parse(
		git3_commit_graph_file *file,
		const unsigned char *data,
		size_t size);

#endif
