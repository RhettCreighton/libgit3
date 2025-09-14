/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_refdb_h__
#define INCLUDE_refdb_h__

#include "common.h"

#include "git3/refdb.h"
#include "repository.h"

struct git3_refdb {
	git3_refcount rc;
	git3_repository *repo;
	git3_refdb_backend *backend;
};

void git3_refdb__free(git3_refdb *db);

int git3_refdb_exists(
	int *exists,
	git3_refdb *refdb,
	const char *ref_name);

int git3_refdb_lookup(
	git3_reference **out,
	git3_refdb *refdb,
	const char *ref_name);

/**
 * Resolve the reference by following symbolic references.
 *
 * Given a reference name, this function will follow any symbolic references up
 * to `max_nesting` deep and return the resolved direct reference. If any of
 * the intermediate symbolic references points to a non-existing reference,
 * then that symbolic reference is returned instead with an error code of `0`.
 * If the given reference is a direct reference already, it is returned
 * directly.
 *
 * If `max_nesting` is `0`, the reference will not be resolved. If it's
 * negative, it will be set to the default resolve depth which is `5`.
 *
 * @param out Pointer to store the result in.
 * @param db The refdb to use for resolving the reference.
 * @param ref_name The reference name to lookup and resolve.
 * @param max_nesting The maximum nesting depth.
 * @return `0` on success, a negative error code otherwise.
 */
int git3_refdb_resolve(
	git3_reference **out,
	git3_refdb *db,
	const char *ref_name,
	int max_nesting);

int git3_refdb_rename(
	git3_reference **out,
	git3_refdb *db,
	const char *old_name,
	const char *new_name,
	int force,
	const git3_signature *who,
	const char *message);

int git3_refdb_iterator(git3_reference_iterator **out, git3_refdb *db, const char *glob);
int git3_refdb_iterator_next(git3_reference **out, git3_reference_iterator *iter);
int git3_refdb_iterator_next_name(const char **out, git3_reference_iterator *iter);
void git3_refdb_iterator_free(git3_reference_iterator *iter);

int git3_refdb_write(git3_refdb *refdb, git3_reference *ref, int force, const git3_signature *who, const char *message, const git3_oid *old_id, const char *old_target);
int git3_refdb_delete(git3_refdb *refdb, const char *ref_name, const git3_oid *old_id, const char *old_target);

int git3_refdb_reflog_read(git3_reflog **out, git3_refdb *db,  const char *name);
int git3_refdb_reflog_write(git3_reflog *reflog);

/**
 * Determine whether a reflog entry should be created for the given reference.
 *
 * Whether or not writing to a reference should create a reflog entry is
 * dependent on a number of things. Most importantly, there's the
 * "core.logAllRefUpdates" setting that controls in which situations a
 * reference should get a corresponding reflog entry. The following values for
 * it are understood:
 *
 *     - "false": Do not log reference updates.
 *
 *     - "true": Log normal reference updates. This will write entries for
 *               references in "refs/heads", "refs/remotes", "refs/notes" and
 *               "HEAD" or if the reference already has a log entry.
 *
 *     - "always": Always create a reflog entry.
 *
 * If unset, the value will default to "true" for non-bare repositories and
 * "false" for bare ones.
 *
 * @param out pointer to which the result will be written, `1` means a reflog
 *            entry should be written, `0` means none should be written.
 * @param db The refdb to decide this for.
 * @param ref The reference one wants to check.
 * @return `0` on success, a negative error code otherwise.
 */
int git3_refdb_should_write_reflog(int *out, git3_refdb *db, const git3_reference *ref);

/**
 * Determine whether a reflog entry should be created for HEAD if creating one
 * for the given reference
 *
 * In case the given reference is being pointed to by HEAD, then creating a
 * reflog entry for this reference also requires us to create a corresponding
 * reflog entry for HEAD. This function can be used to determine that scenario.
 *
 * @param out pointer to which the result will be written, `1` means a reflog
 *            entry should be written, `0` means none should be written.
 * @param db The refdb to decide this for.
 * @param ref The reference one wants to check.
 * @return `0` on success, a negative error code otherwise.
 */
int git3_refdb_should_write_head_reflog(int *out, git3_refdb *db, const git3_reference *ref);

int git3_refdb_has_log(git3_refdb *db, const char *refname);
int git3_refdb_ensure_log(git3_refdb *refdb, const char *refname);

int git3_refdb_lock(void **payload, git3_refdb *db, const char *refname);
int git3_refdb_unlock(git3_refdb *db, void *payload, int success, int update_reflog, const git3_reference *ref, const git3_signature *sig, const char *message);

#endif
