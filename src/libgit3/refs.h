/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_refs_h__
#define INCLUDE_refs_h__

#include "common.h"

#include "git3/oid.h"
#include "git3/refs.h"
#include "git3/refdb.h"
#include "str.h"
#include "oid.h"

extern bool git3_reference__enable_symbolic_ref_target_validation;

#define GIT3_REFS_DIR "refs/"
#define GIT3_REFS_HEADS_DIR GIT3_REFS_DIR "heads/"
#define GIT3_REFS_TAGS_DIR GIT3_REFS_DIR "tags/"
#define GIT3_REFS_REMOTES_DIR GIT3_REFS_DIR "remotes/"
#define GIT3_REFS_NOTES_DIR GIT3_REFS_DIR "notes/"
#define GIT3_REFS_DIR_MODE 0777
#define GIT3_REFS_FILE_MODE 0666

#define GIT3_RENAMED_REF_FILE GIT3_REFS_DIR "RENAMED-REF"

#define GIT3_SYMREF "ref: "
#define GIT3_PACKEDREFS_FILE "packed-refs"
#define GIT3_PACKEDREFS_HEADER "# pack-refs with: peeled fully-peeled sorted "
#define GIT3_PACKEDREFS_FILE_MODE 0666

#define GIT3_HEAD_FILE "HEAD"
#define GIT3_ORIG_HEAD_FILE "ORIG_HEAD"
#define GIT3_FETCH_HEAD_FILE "FETCH_HEAD"
#define GIT3_MERGE_HEAD_FILE "MERGE_HEAD"
#define GIT3_REVERT_HEAD_FILE "REVERT_HEAD"
#define GIT3_CHERRYPICK_HEAD_FILE "CHERRY_PICK_HEAD"
#define GIT3_BISECT_LOG_FILE "BISECT_LOG"
#define GIT3_REBASE_MERGE_DIR "rebase-merge/"
#define GIT3_REBASE_MERGE_INTERACTIVE_FILE GIT3_REBASE_MERGE_DIR "interactive"
#define GIT3_REBASE_APPLY_DIR "rebase-apply/"
#define GIT3_REBASE_APPLY_REBASING_FILE GIT3_REBASE_APPLY_DIR "rebasing"
#define GIT3_REBASE_APPLY_APPLYING_FILE GIT3_REBASE_APPLY_DIR "applying"

#define GIT3_SEQUENCER_DIR "sequencer/"
#define GIT3_SEQUENCER_HEAD_FILE GIT3_SEQUENCER_DIR "head"
#define GIT3_SEQUENCER_OPTIONS_FILE GIT3_SEQUENCER_DIR "options"
#define GIT3_SEQUENCER_TODO_FILE GIT3_SEQUENCER_DIR "todo"

#define GIT3_STASH_FILE "stash"
#define GIT3_REFS_STASH_FILE GIT3_REFS_DIR GIT3_STASH_FILE

#define GIT3_REFERENCE_FORMAT__PRECOMPOSE_UNICODE	(1u << 16)
#define GIT3_REFERENCE_FORMAT__VALIDATION_DISABLE	(1u << 15)

#define GIT3_REFNAME_MAX 1024

typedef char git3_refname_t[GIT3_REFNAME_MAX];

struct git3_reference {
	git3_refdb *db;
	git3_reference_t type;

	union {
		git3_oid oid;
		char *symbolic;
	} target;

	git3_oid peel;
	char name[GIT3_FLEX_ARRAY];
};

/**
 * Reallocate the reference with a new name
 *
 * Note that this is a dangerous operation, as on success, all existing
 * pointers to the old reference will now be dangling. Only call this on objects
 * you control, possibly using `git3_reference_dup`.
 */
git3_reference *git3_reference__realloc(git3_reference **ptr_to_ref, const char *name);

int git3_reference__normalize_name(git3_str *buf, const char *name, unsigned int flags);
int git3_reference__update_terminal(git3_repository *repo, const char *ref_name, const git3_oid *oid, const git3_signature *sig, const char *log_message);
int git3_reference__name_is_valid(int *valid, const char *name, unsigned int flags);
int git3_reference__is_branch(const char *ref_name);
int git3_reference__is_remote(const char *ref_name);
int git3_reference__is_tag(const char *ref_name);
int git3_reference__is_note(const char *ref_name);
const char *git3_reference__shorthand(const char *name);

/*
 * A `git3_reference_cmp` wrapper suitable for passing to generic
 * comparators, like `vector_cmp` / `tsort` / etc.
 */
int git3_reference__cmp_cb(const void *a, const void *b);

/**
 * Lookup a reference by name and try to resolve to an OID.
 *
 * You can control how many dereferences this will attempt to resolve the
 * reference with the `max_deref` parameter, or pass -1 to use a sane
 * default.  If you pass 0 for `max_deref`, this will not attempt to resolve
 * the reference.  For any value of `max_deref` other than 0, not
 * successfully resolving the reference will be reported as an error.

 * The generated reference must be freed by the user.
 *
 * @param reference_out Pointer to the looked-up reference
 * @param repo The repository to look up the reference
 * @param name The long name for the reference (e.g. HEAD, ref/heads/master, refs/tags/v0.1.0, ...)
 * @param max_deref Maximum number of dereferences to make of symbolic refs, 0 means simple lookup, < 0 means use default reasonable value
 * @return 0 on success or < 0 on error; not being able to resolve the reference is an error unless 0 was passed for max_deref
 */
int git3_reference_lookup_resolved(
	git3_reference **reference_out,
	git3_repository *repo,
	const char *name,
	int max_deref);

int git3_reference__log_signature(git3_signature **out, git3_repository *repo);

/** Update a reference after a commit. */
int git3_reference__update_for_commit(
	git3_repository *repo,
	git3_reference *ref,
	const char *ref_name,
	const git3_oid *id,
	const char *operation);

int git3_reference__is_unborn_head(bool *unborn, const git3_reference *ref, git3_repository *repo);

#endif
