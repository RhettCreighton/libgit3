/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_git_types_h__
#define INCLUDE_git_types_h__

#include "common.h"

/**
 * @file git3/types.h
 * @brief libgit3 base & compatibility types
 * @ingroup Git
 * @{
 */
GIT3_BEGIN_DECL

/**
 * Cross-platform compatibility types for off_t / time_t
 *
 * NOTE: This needs to be in a public header so that both the library
 * implementation and client applications both agree on the same types.
 * Otherwise we get undefined behavior.
 *
 * Use the "best" types that each platform provides. Currently we truncate
 * these intermediate representations for compatibility with the git ABI, but
 * if and when it changes to support 64 bit types, our code will naturally
 * adapt.
 * NOTE: These types should match those that are returned by our internal
 * stat() functions, for all platforms.
 */
#include <sys/types.h>
#ifdef __amigaos4__
#include <stdint.h>
#endif

#if defined(_MSC_VER)

typedef __int64 git3_off_t;
typedef __time64_t git3_time_t;

#elif defined(__MINGW32__)

typedef off64_t git3_off_t;
typedef __time64_t git3_time_t;

#elif defined(__HAIKU__)

typedef __haiku_std_int64 git3_off_t;
typedef __haiku_std_int64 git3_time_t;

#else /* POSIX */

/*
 * Note: Can't use off_t since if a client program includes <sys/types.h>
 * before us (directly or indirectly), they'll get 32 bit off_t in their client
 * app, even though /we/ define _FILE_OFFSET_BITS=64.
 */
typedef int64_t git3_off_t;
typedef int64_t git3_time_t; /**< time in seconds from epoch */

#endif

/** The maximum size of an object */
typedef uint64_t git3_object_size_t;

#include "buffer.h"
#include "oid.h"

/** Basic type (loose or packed) of any Git object. */
typedef enum {
	GIT3_OBJECT_ANY =      -2, /**< Object can be any of the following */
	GIT3_OBJECT_INVALID =  -1, /**< Object is invalid. */
	GIT3_OBJECT_COMMIT =    1, /**< A commit object. */
	GIT3_OBJECT_TREE =      2, /**< A tree (directory listing) object. */
	GIT3_OBJECT_BLOB =      3, /**< A file revision object. */
	GIT3_OBJECT_TAG =       4  /**< An annotated tag object. */
} git3_object_t;

/**
 * An object database stores the objects (commit, trees, blobs, tags,
 * etc) for a repository.
 */
typedef struct git3_odb git3_odb;

/** A custom backend in an ODB */
typedef struct git3_odb_backend git3_odb_backend;

/**
 * A "raw" object read from the object database.
 */
typedef struct git3_odb_object git3_odb_object;

/** A stream to read/write from the ODB */
typedef struct git3_odb_stream git3_odb_stream;

/** A stream to write a packfile to the ODB */
typedef struct git3_odb_writepack git3_odb_writepack;

/** a writer for multi-pack-index files. */
typedef struct git3_midx_writer git3_midx_writer;

/** An open refs database handle. */
typedef struct git3_refdb git3_refdb;

/** A custom backend for refs */
typedef struct git3_refdb_backend git3_refdb_backend;

/** A git commit-graph */
typedef struct git3_commit_graph git3_commit_graph;

/** a writer for commit-graph files. */
typedef struct git3_commit_graph_writer git3_commit_graph_writer;

/**
 * Representation of an existing git repository,
 * including all its object contents
 */
typedef struct git3_repository git3_repository;

/** Representation of a working tree */
typedef struct git3_worktree git3_worktree;

/** Representation of a generic object in a repository */
typedef struct git3_object git3_object;

/** Representation of an in-progress walk through the commits in a repo */
typedef struct git3_revwalk git3_revwalk;

/** Parsed representation of a tag object. */
typedef struct git3_tag git3_tag;

/** In-memory representation of a blob object. */
typedef struct git3_blob git3_blob;

/** Parsed representation of a commit object. */
typedef struct git3_commit git3_commit;

/** Representation of each one of the entries in a tree object. */
typedef struct git3_tree_entry git3_tree_entry;

/** Representation of a tree object. */
typedef struct git3_tree git3_tree;

/** Constructor for in-memory trees */
typedef struct git3_treebuilder git3_treebuilder;

/** Memory representation of an index file. */
typedef struct git3_index git3_index;

/** An iterator for entries in the index. */
typedef struct git3_index_iterator git3_index_iterator;

/** An iterator for conflicts in the index. */
typedef struct git3_index_conflict_iterator git3_index_conflict_iterator;

/** Memory representation of a set of config files */
typedef struct git3_config git3_config;

/** Interface to access a configuration file */
typedef struct git3_config_backend git3_config_backend;

/** Representation of a reference log entry */
typedef struct git3_reflog_entry git3_reflog_entry;

/** Representation of a reference log */
typedef struct git3_reflog git3_reflog;

/** Representation of a git note */
typedef struct git3_note git3_note;

/** Representation of a git packbuilder */
typedef struct git3_packbuilder git3_packbuilder;

/** Time in a signature */
typedef struct git3_time {
	git3_time_t time; /**< time in seconds from epoch */
	int offset; /**< timezone offset, in minutes */
	char sign; /**< indicator for questionable '-0000' offsets in signature */
} git3_time;

/** An action signature (e.g. for committers, taggers, etc) */
typedef struct git3_signature {
	char *name; /**< full name of the author */
	char *email; /**< email of the author */
	git3_time when; /**< time when the action happened */
} git3_signature;

/** In-memory representation of a reference. */
typedef struct git3_reference git3_reference;

/** Iterator for references */
typedef struct git3_reference_iterator  git3_reference_iterator;

/** Transactional interface to references */
typedef struct git3_transaction git3_transaction;

/**
 * Annotated commits are commits with additional metadata about how the
 * commit was resolved, which can be used for maintaining the user's
 * "intent" through commands like merge and rebase.
 *
 * For example, if a user wants to conceptually "merge `HEAD`", then the
 * commit portion of an annotated commit will point to the `HEAD` commit,
 * but the _annotation_ will denote the ref `HEAD`. This allows git to
 * perform the internal bookkeeping so that the system knows both the
 * content of what is being merged but also how the content was looked up
 * so that it can be recorded in the reflog appropriately.
 */
typedef struct git3_annotated_commit git3_annotated_commit;

/** Representation of a status collection */
typedef struct git3_status_list git3_status_list;

/** Representation of a rebase */
typedef struct git3_rebase git3_rebase;

/** Basic type of any Git reference. */
typedef enum {
	GIT3_REFERENCE_INVALID  = 0, /**< Invalid reference */
	GIT3_REFERENCE_DIRECT   = 1, /**< A reference that points at an object id */
	GIT3_REFERENCE_SYMBOLIC = 2, /**< A reference that points at another reference */
	GIT3_REFERENCE_ALL      = GIT3_REFERENCE_DIRECT | GIT3_REFERENCE_SYMBOLIC
} git3_reference_t;

/** Basic type of any Git branch. */
typedef enum {
	GIT3_BRANCH_LOCAL = 1,
	GIT3_BRANCH_REMOTE = 2,
	GIT3_BRANCH_ALL = GIT3_BRANCH_LOCAL|GIT3_BRANCH_REMOTE
} git3_branch_t;

/** Valid modes for index and tree entries. */
typedef enum {
	GIT3_FILEMODE_UNREADABLE          = 0000000,
	GIT3_FILEMODE_TREE                = 0040000,
	GIT3_FILEMODE_BLOB                = 0100644,
	GIT3_FILEMODE_BLOB_EXECUTABLE     = 0100755,
	GIT3_FILEMODE_LINK                = 0120000,
	GIT3_FILEMODE_COMMIT              = 0160000
} git3_filemode_t;

/**
 * A refspec specifies the mapping between remote and local reference
 * names when fetch or pushing.
 */
typedef struct git3_refspec git3_refspec;

/**
 * Git's idea of a remote repository. A remote can be anonymous (in
 * which case it does not have backing configuration entries).
 */
typedef struct git3_remote git3_remote;

/**
 * Interface which represents a transport to communicate with a
 * remote.
 */
typedef struct git3_transport git3_transport;

/**
 * Preparation for a push operation. Can be used to configure what to
 * push and the level of parallelism of the packfile builder.
 */
typedef struct git3_push git3_push;

/* documentation in the definition */
typedef struct git3_remote_head git3_remote_head;
typedef struct git3_remote_callbacks git3_remote_callbacks;

/**
 * Parent type for `git3_cert_hostkey` and `git3_cert_x509`.
 */
typedef struct git3_cert git3_cert;

/**
 * Opaque structure representing a submodule.
 */
typedef struct git3_submodule git3_submodule;

/**
 * Submodule update values
 *
 * These values represent settings for the `submodule.$name.update`
 * configuration value which says how to handle `git submodule update` for
 * this submodule.  The value is usually set in the ".gitmodules" file and
 * copied to ".git/config" when the submodule is initialized.
 *
 * You can override this setting on a per-submodule basis with
 * `git3_submodule_set_update()` and write the changed value to disk using
 * `git3_submodule_save()`.  If you have overwritten the value, you can
 * revert it by passing `GIT3_SUBMODULE_UPDATE_RESET` to the set function.
 *
 * The values are:
 *
 * - GIT3_SUBMODULE_UPDATE_CHECKOUT: the default; when a submodule is
 *   updated, checkout the new detached HEAD to the submodule directory.
 * - GIT3_SUBMODULE_UPDATE_REBASE: update by rebasing the current checked
 *   out branch onto the commit from the superproject.
 * - GIT3_SUBMODULE_UPDATE_MERGE: update by merging the commit in the
 *   superproject into the current checkout out branch of the submodule.
 * - GIT3_SUBMODULE_UPDATE_NONE: do not update this submodule even when
 *   the commit in the superproject is updated.
 * - GIT3_SUBMODULE_UPDATE_DEFAULT: not used except as static initializer
 *   when we don't want any particular update rule to be specified.
 */
typedef enum {
	GIT3_SUBMODULE_UPDATE_CHECKOUT = 1,
	GIT3_SUBMODULE_UPDATE_REBASE   = 2,
	GIT3_SUBMODULE_UPDATE_MERGE    = 3,
	GIT3_SUBMODULE_UPDATE_NONE     = 4,

	GIT3_SUBMODULE_UPDATE_DEFAULT  = 0
} git3_submodule_update_t;

/**
 * Submodule ignore values
 *
 * These values represent settings for the `submodule.$name.ignore`
 * configuration value which says how deeply to look at the working
 * directory when getting submodule status.
 *
 * You can override this value in memory on a per-submodule basis with
 * `git3_submodule_set_ignore()` and can write the changed value to disk
 * with `git3_submodule_save()`.  If you have overwritten the value, you
 * can revert to the on disk value by using `GIT3_SUBMODULE_IGNORE_RESET`.
 *
 * The values are:
 *
 * - GIT3_SUBMODULE_IGNORE_UNSPECIFIED: use the submodule's configuration
 * - GIT3_SUBMODULE_IGNORE_NONE: don't ignore any change - i.e. even an
 *   untracked file, will mark the submodule as dirty.  Ignored files are
 *   still ignored, of course.
 * - GIT3_SUBMODULE_IGNORE_UNTRACKED: ignore untracked files; only changes
 *   to tracked files, or the index or the HEAD commit will matter.
 * - GIT3_SUBMODULE_IGNORE_DIRTY: ignore changes in the working directory,
 *   only considering changes if the HEAD of submodule has moved from the
 *   value in the superproject.
 * - GIT3_SUBMODULE_IGNORE_ALL: never check if the submodule is dirty
 * - GIT3_SUBMODULE_IGNORE_DEFAULT: not used except as static initializer
 *   when we don't want any particular ignore rule to be specified.
 */
typedef enum {
	GIT3_SUBMODULE_IGNORE_UNSPECIFIED  = -1, /**< use the submodule's configuration */

	GIT3_SUBMODULE_IGNORE_NONE      = 1,  /**< any change or untracked == dirty */
	GIT3_SUBMODULE_IGNORE_UNTRACKED = 2,  /**< dirty if tracked files change */
	GIT3_SUBMODULE_IGNORE_DIRTY     = 3,  /**< only dirty if HEAD moved */
	GIT3_SUBMODULE_IGNORE_ALL       = 4   /**< never dirty */
} git3_submodule_ignore_t;

/**
 * Options for submodule recurse.
 *
 * Represent the value of `submodule.$name.fetchRecurseSubmodules`
 *
 * * GIT3_SUBMODULE_RECURSE_NO    - do no recurse into submodules
 * * GIT3_SUBMODULE_RECURSE_YES   - recurse into submodules
 * * GIT3_SUBMODULE_RECURSE_ONDEMAND - recurse into submodules only when
 *                                    commit not already in local clone
 */
typedef enum {
	GIT3_SUBMODULE_RECURSE_NO = 0,
	GIT3_SUBMODULE_RECURSE_YES = 1,
	GIT3_SUBMODULE_RECURSE_ONDEMAND = 2
} git3_submodule_recurse_t;

typedef struct git3_writestream git3_writestream;

/** A type to write in a streaming fashion, for example, for filters. */
struct git3_writestream {
	int GIT3_CALLBACK(write)(git3_writestream *stream, const char *buffer, size_t len);
	int GIT3_CALLBACK(close)(git3_writestream *stream);
	void GIT3_CALLBACK(free)(git3_writestream *stream);
};

/** Representation of .mailmap file state. */
typedef struct git3_mailmap git3_mailmap;

/** @} */
GIT3_END_DECL

#endif
