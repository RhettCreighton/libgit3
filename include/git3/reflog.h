/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_git_reflog_h__
#define INCLUDE_git_reflog_h__

#include "common.h"
#include "types.h"
#include "oid.h"

/**
 * @file git3/reflog.h
 * @brief Reference logs store how references change
 * @defgroup git3_reflog Reference logs store how references change
 * @ingroup Git
 * @{
 */
GIT3_BEGIN_DECL

/**
 * Read the reflog for the given reference
 *
 * If there is no reflog file for the given
 * reference yet, an empty reflog object will
 * be returned.
 *
 * The reflog must be freed manually by using
 * git3_reflog_free().
 *
 * @param out pointer to reflog
 * @param repo the repository
 * @param name reference to look up
 * @return 0 or an error code
 */
GIT3_EXTERN(int) git3_reflog_read(git3_reflog **out, git3_repository *repo,  const char *name);

/**
 * Write an existing in-memory reflog object back to disk
 * using an atomic file lock.
 *
 * @param reflog an existing reflog object
 * @return 0 or an error code
 */
GIT3_EXTERN(int) git3_reflog_write(git3_reflog *reflog);

/**
 * Add a new entry to the in-memory reflog.
 *
 * `msg` is optional and can be NULL.
 *
 * @param reflog an existing reflog object
 * @param id the OID the reference is now pointing to
 * @param committer the signature of the committer
 * @param msg the reflog message
 * @return 0 or an error code
 */
GIT3_EXTERN(int) git3_reflog_append(git3_reflog *reflog, const git3_oid *id, const git3_signature *committer, const char *msg);

/**
 * Rename a reflog
 *
 * The reflog to be renamed is expected to already exist
 *
 * The new name will be checked for validity.
 * See `git3_reference_create_symbolic()` for rules about valid names.
 *
 * @param repo the repository
 * @param old_name the old name of the reference
 * @param name the new name of the reference
 * @return 0 on success, GIT3_EINVALIDSPEC or an error code
 */
GIT3_EXTERN(int) git3_reflog_rename(git3_repository *repo, const char *old_name, const char *name);

/**
 * Delete the reflog for the given reference
 *
 * @param repo the repository
 * @param name the reflog to delete
 * @return 0 or an error code
 */
GIT3_EXTERN(int) git3_reflog_delete(git3_repository *repo, const char *name);

/**
 * Get the number of log entries in a reflog
 *
 * @param reflog the previously loaded reflog
 * @return the number of log entries
 */
GIT3_EXTERN(size_t) git3_reflog_entrycount(git3_reflog *reflog);

/**
 * Lookup an entry by its index
 *
 * Requesting the reflog entry with an index of 0 (zero) will
 * return the most recently created entry.
 *
 * @param reflog a previously loaded reflog
 * @param idx the position of the entry to lookup. Should be greater than or
 * equal to 0 (zero) and less than `git3_reflog_entrycount()`.
 * @return the entry; NULL if not found
 */
GIT3_EXTERN(const git3_reflog_entry *) git3_reflog_entry_byindex(const git3_reflog *reflog, size_t idx);

/**
 * Remove an entry from the reflog by its index
 *
 * To ensure there's no gap in the log history, set `rewrite_previous_entry`
 * param value to 1. When deleting entry `n`, member old_oid of entry `n-1`
 * (if any) will be updated with the value of member new_oid of entry `n+1`.
 *
 * @param reflog a previously loaded reflog.
 *
 * @param idx the position of the entry to remove. Should be greater than or
 * equal to 0 (zero) and less than `git3_reflog_entrycount()`.
 *
 * @param rewrite_previous_entry 1 to rewrite the history; 0 otherwise.
 *
 * @return 0 on success, GIT3_ENOTFOUND if the entry doesn't exist
 * or an error code.
 */
GIT3_EXTERN(int) git3_reflog_drop(
	git3_reflog *reflog,
	size_t idx,
	int rewrite_previous_entry);

/**
 * Get the old oid
 *
 * @param entry a reflog entry
 * @return the old oid
 */
GIT3_EXTERN(const git3_oid *) git3_reflog_entry_id_old(const git3_reflog_entry *entry);

/**
 * Get the new oid
 *
 * @param entry a reflog entry
 * @return the new oid at this time
 */
GIT3_EXTERN(const git3_oid *) git3_reflog_entry_id_new(const git3_reflog_entry *entry);

/**
 * Get the committer of this entry
 *
 * @param entry a reflog entry
 * @return the committer
 */
GIT3_EXTERN(const git3_signature *) git3_reflog_entry_committer(const git3_reflog_entry *entry);

/**
 * Get the log message
 *
 * @param entry a reflog entry
 * @return the log msg
 */
GIT3_EXTERN(const char *) git3_reflog_entry_message(const git3_reflog_entry *entry);

/**
 * Free the reflog
 *
 * @param reflog reflog to free
 */
GIT3_EXTERN(void) git3_reflog_free(git3_reflog *reflog);

/** @} */
GIT3_END_DECL

#endif
