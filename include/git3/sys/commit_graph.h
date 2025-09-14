/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_sys_git_commit_graph_h__
#define INCLUDE_sys_git_commit_graph_h__

#include "git3/common.h"
#include "git3/types.h"

/**
 * @file git3/sys/commit_graph.h
 * @brief Commit graphs store information about commit relationships
 * @defgroup git3_commit_graph Commit graphs
 * @ingroup Git
 * @{
 */
GIT3_BEGIN_DECL

/**
 * Options structure for `git3_commit_graph_open_new`.
 *
 * Initialize with `GIT3_COMMIT_GRAPH_OPEN_OPTIONS_INIT`. Alternatively,
 * you can use `git3_commit_graph_open_options_init`.
 */
typedef struct {
	unsigned int version;

#ifdef GIT3_EXPERIMENTAL_SHA256
	/** The object ID type that this commit graph contains. */
	git3_oid_t oid_type;
#endif
} git3_commit_graph_open_options;

/** Current version for the `git3_commit_graph_open_options` structure */
#define GIT3_COMMIT_GRAPH_OPEN_OPTIONS_VERSION 1

/** Static constructor for `git3_commit_graph_open_options` */
#define GIT3_COMMIT_GRAPH_OPEN_OPTIONS_INIT { \
		GIT3_COMMIT_GRAPH_OPEN_OPTIONS_VERSION \
	}

/**
 * Initialize git3_commit_graph_open_options structure
 *
 * Initializes a `git3_commit_graph_open_options` with default values.
 * Equivalent to creating an instance with
 * `GIT3_COMMIT_GRAPH_OPEN_OPTIONS_INIT`.
 *
 * @param opts The `git3_commit_graph_open_options` struct to initialize.
 * @param version The struct version; pass `GIT3_COMMIT_GRAPH_OPEN_OPTIONS_VERSION`.
 * @return Zero on success; -1 on failure.
 */
GIT3_EXTERN(int) git3_commit_graph_open_options_init(
	git3_commit_graph_open_options *opts,
	unsigned int version);


/**
 * Opens a `git3_commit_graph` from a path to an objects directory.
 *
 * This finds, opens, and validates the `commit-graph` file.
 *
 * @param cgraph_out the `git3_commit_graph` struct to initialize.
 * @param objects_dir the path to a git objects directory.
 * @return Zero on success; -1 on failure.
 */
GIT3_EXTERN(int) git3_commit_graph_open(
	git3_commit_graph **cgraph_out,
	const char *objects_dir
#ifdef GIT3_EXPERIMENTAL_SHA256
	, const git3_commit_graph_open_options *options
#endif
	);

/**
 * Frees commit-graph data. This should only be called when memory allocated
 * using `git3_commit_graph_open` is not returned to libgit3 because it was not
 * associated with the ODB through a successful call to
 * `git3_odb_set_commit_graph`.
 *
 * @param cgraph the commit-graph object to free. If NULL, no action is taken.
 */
GIT3_EXTERN(void) git3_commit_graph_free(git3_commit_graph *cgraph);


/**
 * The strategy to use when adding a new set of commits to a pre-existing
 * commit-graph chain.
 */
typedef enum {
	/**
	 * Do not split commit-graph files. The other split strategy-related option
	 * fields are ignored.
	 */
	GIT3_COMMIT_GRAPH_SPLIT_STRATEGY_SINGLE_FILE = 0
} git3_commit_graph_split_strategy_t;

/**
 * Options structure for `git3_commit_graph_writer_new`.
 *
 * Initialize with `GIT3_COMMIT_GRAPH_WRITER_OPTIONS_INIT`. Alternatively,
 * you can use `git3_commit_graph_writer_options_init`.
 */
typedef struct {
	unsigned int version;

#ifdef GIT3_EXPERIMENTAL_SHA256
	/** The object ID type that this commit graph contains. */
	git3_oid_t oid_type;
#endif

	/**
	 * The strategy to use when adding new commits to a pre-existing commit-graph
	 * chain.
	 */
	git3_commit_graph_split_strategy_t split_strategy;

	/**
	 * The number of commits in level N is less than X times the number of
	 * commits in level N + 1. Default is 2.
	 */
	float size_multiple;

	/**
	 * The number of commits in level N + 1 is more than C commits.
	 * Default is 64000.
	 */
	size_t max_commits;
} git3_commit_graph_writer_options;

/** Current version for the `git3_commit_graph_writer_options` structure */
#define GIT3_COMMIT_GRAPH_WRITER_OPTIONS_VERSION 1

/** Static constructor for `git3_commit_graph_writer_options` */
#define GIT3_COMMIT_GRAPH_WRITER_OPTIONS_INIT { \
		GIT3_COMMIT_GRAPH_WRITER_OPTIONS_VERSION \
	}

/**
 * Initialize git3_commit_graph_writer_options structure
 *
 * Initializes a `git3_commit_graph_writer_options` with default values. Equivalent to
 * creating an instance with `GIT3_COMMIT_GRAPH_WRITER_OPTIONS_INIT`.
 *
 * @param opts The `git3_commit_graph_writer_options` struct to initialize.
 * @param version The struct version; pass `GIT3_COMMIT_GRAPH_WRITER_OPTIONS_VERSION`.
 * @return Zero on success; -1 on failure.
 */
GIT3_EXTERN(int) git3_commit_graph_writer_options_init(
	git3_commit_graph_writer_options *opts,
	unsigned int version);

/**
 * Create a new writer for `commit-graph` files.
 *
 * @param out Location to store the writer pointer.
 * @param objects_info_dir The `objects/info` directory.
 * The `commit-graph` file will be written in this directory.
 * @param options The options for the commit graph writer.
 * @return 0 or an error code
 */
GIT3_EXTERN(int) git3_commit_graph_writer_new(
		git3_commit_graph_writer **out,
		const char *objects_info_dir,
		const git3_commit_graph_writer_options *options);

/**
 * Free the commit-graph writer and its resources.
 *
 * @param w The writer to free. If NULL no action is taken.
 */
GIT3_EXTERN(void) git3_commit_graph_writer_free(git3_commit_graph_writer *w);

/**
 * Add an `.idx` file (associated to a packfile) to the writer.
 *
 * @param w The writer.
 * @param repo The repository that owns the `.idx` file.
 * @param idx_path The path of an `.idx` file.
 * @return 0 or an error code
 */
GIT3_EXTERN(int) git3_commit_graph_writer_add_index_file(
		git3_commit_graph_writer *w,
		git3_repository *repo,
		const char *idx_path);

/**
 * Add a revwalk to the writer. This will add all the commits from the revwalk
 * to the commit-graph.
 *
 * @param w The writer.
 * @param walk The git3_revwalk.
 * @return 0 or an error code
 */
GIT3_EXTERN(int) git3_commit_graph_writer_add_revwalk(
		git3_commit_graph_writer *w,
		git3_revwalk *walk);

/**
 * Write a `commit-graph` file to a file.
 *
 * @param w The writer
 * @return 0 or an error code
 */
GIT3_EXTERN(int) git3_commit_graph_writer_commit(
		git3_commit_graph_writer *w);

/**
 * Dump the contents of the `commit-graph` to an in-memory buffer.
 *
 * @param[out] buffer Buffer where to store the contents of the `commit-graph`.
 * @param w The writer.
 * @return 0 or an error code
 */
GIT3_EXTERN(int) git3_commit_graph_writer_dump(
		git3_buf *buffer,
		git3_commit_graph_writer *w);

/** @} */
GIT3_END_DECL

#endif
