/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "common.h"

#include "git3/object.h"

#include "repository.h"
#include "commit.h"
#include "tree.h"
#include "blob.h"
#include "tag.h"

/**
 * Commit
 */
int git3_commit_lookup(git3_commit **out, git3_repository *repo, const git3_oid *id)
{
	return git3_object_lookup((git3_object **)out, repo, id, GIT3_OBJECT_COMMIT);
}

int git3_commit_lookup_prefix(git3_commit **out, git3_repository *repo, const git3_oid *id, size_t len)
{
	return git3_object_lookup_prefix((git3_object **)out, repo, id, len, GIT3_OBJECT_COMMIT);
}

void git3_commit_free(git3_commit *obj)
{
	git3_object_free((git3_object *)obj);
}

const git3_oid *git3_commit_id(const git3_commit *obj)
{
	return git3_object_id((const git3_object *)obj);
}

git3_repository *git3_commit_owner(const git3_commit *obj)
{
	return git3_object_owner((const git3_object *)obj);
}

int git3_commit_dup(git3_commit **out, git3_commit *obj)
{
	return git3_object_dup((git3_object **)out, (git3_object *)obj);
}

/**
 * Tree
 */
int git3_tree_lookup(git3_tree **out, git3_repository *repo, const git3_oid *id)
{
	return git3_object_lookup((git3_object **)out, repo, id, GIT3_OBJECT_TREE);
}

int git3_tree_lookup_prefix(git3_tree **out, git3_repository *repo, const git3_oid *id, size_t len)
{
	return git3_object_lookup_prefix((git3_object **)out, repo, id, len, GIT3_OBJECT_TREE);
}

void git3_tree_free(git3_tree *obj)
{
	git3_object_free((git3_object *)obj);
}

const git3_oid *git3_tree_id(const git3_tree *obj)
{
	return git3_object_id((const git3_object *)obj);
}

git3_repository *git3_tree_owner(const git3_tree *obj)
{
	return git3_object_owner((const git3_object *)obj);
}

int git3_tree_dup(git3_tree **out, git3_tree *obj)
{
	return git3_object_dup((git3_object **)out, (git3_object *)obj);
}

/**
 * Tag
 */
int git3_tag_lookup(git3_tag **out, git3_repository *repo, const git3_oid *id)
{
	return git3_object_lookup((git3_object **)out, repo, id, GIT3_OBJECT_TAG);
}

int git3_tag_lookup_prefix(git3_tag **out, git3_repository *repo, const git3_oid *id, size_t len)
{
	return git3_object_lookup_prefix((git3_object **)out, repo, id, len, GIT3_OBJECT_TAG);
}

void git3_tag_free(git3_tag *obj)
{
	git3_object_free((git3_object *)obj);
}

const git3_oid *git3_tag_id(const git3_tag *obj)
{
	return git3_object_id((const git3_object *)obj);
}

git3_repository *git3_tag_owner(const git3_tag *obj)
{
	return git3_object_owner((const git3_object *)obj);
}

int git3_tag_dup(git3_tag **out, git3_tag *obj)
{
	return git3_object_dup((git3_object **)out, (git3_object *)obj);
}

/**
 * Blob
 */
int git3_blob_lookup(git3_blob **out, git3_repository *repo, const git3_oid *id)
{
	return git3_object_lookup((git3_object **)out, repo, id, GIT3_OBJECT_BLOB);
}

int git3_blob_lookup_prefix(git3_blob **out, git3_repository *repo, const git3_oid *id, size_t len)
{
	return git3_object_lookup_prefix((git3_object **)out, repo, id, len, GIT3_OBJECT_BLOB);
}

void git3_blob_free(git3_blob *obj)
{
	git3_object_free((git3_object *)obj);
}

const git3_oid *git3_blob_id(const git3_blob *obj)
{
	return git3_object_id((const git3_object *)obj);
}

git3_repository *git3_blob_owner(const git3_blob *obj)
{
	return git3_object_owner((const git3_object *)obj);
}

int git3_blob_dup(git3_blob **out, git3_blob *obj)
{
	return git3_object_dup((git3_object **)out, (git3_object *)obj);
}
