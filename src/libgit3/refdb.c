/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "refdb.h"

#include "git3/object.h"
#include "git3/refs.h"
#include "git3/refdb.h"
#include "git3/sys/refdb_backend.h"

#include "hash.h"
#include "refs.h"
#include "reflog.h"
#include "posix.h"

#define DEFAULT_NESTING_LEVEL	5
#define MAX_NESTING_LEVEL		10

int git3_refdb_new(git3_refdb **out, git3_repository *repo)
{
	git3_refdb *db;

	GIT3_ASSERT_ARG(out);
	GIT3_ASSERT_ARG(repo);

	db = git3__calloc(1, sizeof(*db));
	GIT3_ERROR_CHECK_ALLOC(db);

	db->repo = repo;

	*out = db;
	GIT3_REFCOUNT_INC(db);
	return 0;
}

int git3_refdb_open(git3_refdb **out, git3_repository *repo)
{
	git3_refdb *db;
	git3_refdb_backend *dir;

	GIT3_ASSERT_ARG(out);
	GIT3_ASSERT_ARG(repo);

	*out = NULL;

	if (git3_refdb_new(&db, repo) < 0)
		return -1;

	/* Add the default (filesystem) backend */
	if (git3_refdb_backend_fs(&dir, repo) < 0) {
		git3_refdb_free(db);
		return -1;
	}

	db->repo = repo;
	db->backend = dir;

	*out = db;
	return 0;
}

static void refdb_free_backend(git3_refdb *db)
{
	if (db->backend)
		db->backend->free(db->backend);
}

int git3_refdb_set_backend(git3_refdb *db, git3_refdb_backend *backend)
{
	GIT3_ERROR_CHECK_VERSION(backend, GIT3_REFDB_BACKEND_VERSION, "git3_refdb_backend");

	if (!backend->exists || !backend->lookup || !backend->iterator ||
	    !backend->write || !backend->rename || !backend->del ||
	    !backend->has_log || !backend->ensure_log || !backend->free ||
	    !backend->reflog_read || !backend->reflog_write ||
	    !backend->reflog_rename || !backend->reflog_delete ||
	    (backend->lock && !backend->unlock)) {
		git3_error_set(GIT3_ERROR_REFERENCE, "incomplete refdb backend implementation");
		return GIT3_EINVALID;
	}

	refdb_free_backend(db);
	db->backend = backend;

	return 0;
}

int git3_refdb_compress(git3_refdb *db)
{
	GIT3_ASSERT_ARG(db);

	if (db->backend->compress)
		return db->backend->compress(db->backend);

	return 0;
}

void git3_refdb__free(git3_refdb *db)
{
	refdb_free_backend(db);
	git3__memzero(db, sizeof(*db));
	git3__free(db);
}

void git3_refdb_free(git3_refdb *db)
{
	if (db == NULL)
		return;

	GIT3_REFCOUNT_DEC(db, git3_refdb__free);
}

int git3_refdb_exists(int *exists, git3_refdb *refdb, const char *ref_name)
{
	GIT3_ASSERT_ARG(exists);
	GIT3_ASSERT_ARG(refdb);
	GIT3_ASSERT_ARG(refdb->backend);

	return refdb->backend->exists(exists, refdb->backend, ref_name);
}

int git3_refdb_lookup(git3_reference **out, git3_refdb *db, const char *ref_name)
{
	git3_reference *ref;
	int error;

	GIT3_ASSERT_ARG(db);
	GIT3_ASSERT_ARG(db->backend);
	GIT3_ASSERT_ARG(out);
	GIT3_ASSERT_ARG(ref_name);

	error = db->backend->lookup(&ref, db->backend, ref_name);
	if (error < 0)
		return error;

	GIT3_REFCOUNT_INC(db);
	ref->db = db;

	*out = ref;
	return 0;
}

int git3_refdb_resolve(
	git3_reference **out,
	git3_refdb *db,
	const char *ref_name,
	int max_nesting)
{
	git3_reference *ref = NULL;
	int error = 0, nesting;

	*out = NULL;

	if (max_nesting > MAX_NESTING_LEVEL)
		max_nesting = MAX_NESTING_LEVEL;
	else if (max_nesting < 0)
		max_nesting = DEFAULT_NESTING_LEVEL;

	if ((error = git3_refdb_lookup(&ref, db, ref_name)) < 0)
		goto out;

	for (nesting = 0; nesting < max_nesting; nesting++) {
		git3_reference *resolved;

		if (ref->type == GIT3_REFERENCE_DIRECT)
			break;

		if ((error = git3_refdb_lookup(&resolved, db, git3_reference_symbolic_target(ref))) < 0) {
			/* If we found a symbolic reference with a nonexistent target, return it. */
			if (error == GIT3_ENOTFOUND) {
				error = 0;
				*out = ref;
				ref = NULL;
			}
			goto out;
		}

		git3_reference_free(ref);
		ref = resolved;
	}

	if (ref->type != GIT3_REFERENCE_DIRECT && max_nesting != 0) {
		git3_error_set(GIT3_ERROR_REFERENCE,
			"cannot resolve reference (>%u levels deep)", max_nesting);
		error = -1;
		goto out;
	}

	*out = ref;
	ref = NULL;
out:
	git3_reference_free(ref);
	return error;
}

int git3_refdb_iterator(git3_reference_iterator **out, git3_refdb *db, const char *glob)
{
	int error;

	if (!db->backend || !db->backend->iterator) {
		git3_error_set(GIT3_ERROR_REFERENCE, "this backend doesn't support iterators");
		return -1;
	}

	if ((error = db->backend->iterator(out, db->backend, glob)) < 0)
		return error;

	GIT3_REFCOUNT_INC(db);
	(*out)->db = db;

	return 0;
}

int git3_refdb_iterator_next(git3_reference **out, git3_reference_iterator *iter)
{
	int error;

	if ((error = iter->next(out, iter)) < 0)
		return error;

	GIT3_REFCOUNT_INC(iter->db);
	(*out)->db = iter->db;

	return 0;
}

int git3_refdb_iterator_next_name(const char **out, git3_reference_iterator *iter)
{
	return iter->next_name(out, iter);
}

void git3_refdb_iterator_free(git3_reference_iterator *iter)
{
	GIT3_REFCOUNT_DEC(iter->db, git3_refdb__free);
	iter->free(iter);
}

int git3_refdb_write(git3_refdb *db, git3_reference *ref, int force, const git3_signature *who, const char *message, const git3_oid *old_id, const char *old_target)
{
	GIT3_ASSERT_ARG(db);
	GIT3_ASSERT_ARG(db->backend);

	GIT3_REFCOUNT_INC(db);
	ref->db = db;

	return db->backend->write(db->backend, ref, force, who, message, old_id, old_target);
}

int git3_refdb_rename(
	git3_reference **out,
	git3_refdb *db,
	const char *old_name,
	const char *new_name,
	int force,
	const git3_signature *who,
	const char *message)
{
	int error;

	GIT3_ASSERT_ARG(db);
	GIT3_ASSERT_ARG(db->backend);

	error = db->backend->rename(out, db->backend, old_name, new_name, force, who, message);
	if (error < 0)
		return error;

	if (out) {
		GIT3_REFCOUNT_INC(db);
		(*out)->db = db;
	}

	return 0;
}

int git3_refdb_delete(struct git3_refdb *db, const char *ref_name, const git3_oid *old_id, const char *old_target)
{
	GIT3_ASSERT_ARG(db);
	GIT3_ASSERT_ARG(db->backend);

	return db->backend->del(db->backend, ref_name, old_id, old_target);
}

int git3_refdb_reflog_read(git3_reflog **out, git3_refdb *db,  const char *name)
{
	int error;

	GIT3_ASSERT_ARG(db);
	GIT3_ASSERT_ARG(db->backend);

	if ((error = db->backend->reflog_read(out, db->backend, name)) < 0)
		return error;

	GIT3_REFCOUNT_INC(db);
	(*out)->db = db;

	return 0;
}

int git3_refdb_should_write_reflog(int *out, git3_refdb *db, const git3_reference *ref)
{
	int error, logall;

	error = git3_repository__configmap_lookup(&logall, db->repo, GIT3_CONFIGMAP_LOGALLREFUPDATES);
	if (error < 0)
		return error;

	/* Defaults to the opposite of the repo being bare */
	if (logall == GIT3_LOGALLREFUPDATES_UNSET)
		logall = !git3_repository_is_bare(db->repo);

	*out = 0;
	switch (logall) {
	case GIT3_LOGALLREFUPDATES_FALSE:
		*out = 0;
		break;

	case GIT3_LOGALLREFUPDATES_TRUE:
		/* Only write if it already has a log,
		 * or if it's under heads/, remotes/ or notes/
		 */
		*out = git3_refdb_has_log(db, ref->name) ||
			!git3__prefixcmp(ref->name, GIT3_REFS_HEADS_DIR) ||
			!git3__strcmp(ref->name, GIT3_HEAD_FILE) ||
			!git3__prefixcmp(ref->name, GIT3_REFS_REMOTES_DIR) ||
			!git3__prefixcmp(ref->name, GIT3_REFS_NOTES_DIR);
		break;

	case GIT3_LOGALLREFUPDATES_ALWAYS:
		*out = 1;
		break;
	}

	return 0;
}

int git3_refdb_should_write_head_reflog(int *out, git3_refdb *db, const git3_reference *ref)
{
	git3_reference *head = NULL, *resolved = NULL;
	const char *name;
	int error;

	*out = 0;

	if (ref->type == GIT3_REFERENCE_SYMBOLIC) {
		error = 0;
		goto out;
	}

	if ((error = git3_refdb_lookup(&head, db, GIT3_HEAD_FILE)) < 0)
		goto out;

	if (git3_reference_type(head) == GIT3_REFERENCE_DIRECT)
		goto out;

	/* Go down the symref chain until we find the branch */
	if ((error = git3_refdb_resolve(&resolved, db, git3_reference_symbolic_target(head), -1)) < 0) {
		if (error != GIT3_ENOTFOUND)
			goto out;
		error = 0;
		name = git3_reference_symbolic_target(head);
	} else if (git3_reference_type(resolved) == GIT3_REFERENCE_SYMBOLIC) {
		name = git3_reference_symbolic_target(resolved);
	} else {
		name = git3_reference_name(resolved);
	}

	if (strcmp(name, ref->name))
		goto out;

	*out = 1;

out:
	git3_reference_free(resolved);
	git3_reference_free(head);
	return error;
}

int git3_refdb_has_log(git3_refdb *db, const char *refname)
{
	GIT3_ASSERT_ARG(db);
	GIT3_ASSERT_ARG(refname);

	return db->backend->has_log(db->backend, refname);
}

int git3_refdb_ensure_log(git3_refdb *db, const char *refname)
{
	GIT3_ASSERT_ARG(db);
	GIT3_ASSERT_ARG(refname);

	return db->backend->ensure_log(db->backend, refname);
}

int git3_refdb_init_backend(git3_refdb_backend *backend, unsigned int version)
{
	GIT3_INIT_STRUCTURE_FROM_TEMPLATE(
		backend, version, git3_refdb_backend, GIT3_REFDB_BACKEND_INIT);
	return 0;
}

int git3_refdb_lock(void **payload, git3_refdb *db, const char *refname)
{
	GIT3_ASSERT_ARG(payload);
	GIT3_ASSERT_ARG(db);
	GIT3_ASSERT_ARG(refname);

	if (!db->backend->lock) {
		git3_error_set(GIT3_ERROR_REFERENCE, "backend does not support locking");
		return -1;
	}

	return db->backend->lock(payload, db->backend, refname);
}

int git3_refdb_unlock(git3_refdb *db, void *payload, int success, int update_reflog, const git3_reference *ref, const git3_signature *sig, const char *message)
{
	GIT3_ASSERT_ARG(db);

	return db->backend->unlock(db->backend, payload, success, update_reflog, ref, sig, message);
}
