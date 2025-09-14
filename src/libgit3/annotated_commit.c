/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "annotated_commit.h"

#include "refs.h"
#include "cache.h"

#include "git3/commit.h"
#include "git3/refs.h"
#include "git3/repository.h"
#include "git3/annotated_commit.h"
#include "git3/revparse.h"
#include "git3/tree.h"
#include "git3/index.h"

static int annotated_commit_init(
	git3_annotated_commit **out,
	git3_commit *commit,
	const char *description)
{
	git3_annotated_commit *annotated_commit;
	int error = 0;

	GIT3_ASSERT_ARG(out);
	GIT3_ASSERT_ARG(commit);

	*out = NULL;

	annotated_commit = git3__calloc(1, sizeof(git3_annotated_commit));
	GIT3_ERROR_CHECK_ALLOC(annotated_commit);

	annotated_commit->type = GIT3_ANNOTATED_COMMIT_REAL;

	if ((error = git3_commit_dup(&annotated_commit->commit, commit)) < 0)
		goto done;

	git3_oid_tostr(annotated_commit->id_str, GIT3_OID_MAX_HEXSIZE + 1,
		git3_commit_id(commit));

	if (!description)
		description = annotated_commit->id_str;

	annotated_commit->description = git3__strdup(description);
	GIT3_ERROR_CHECK_ALLOC(annotated_commit->description);

done:
	if (!error)
		*out = annotated_commit;

	return error;
}

static int annotated_commit_init_from_id(
	git3_annotated_commit **out,
	git3_repository *repo,
	const git3_oid *id,
	const char *description)
{
	git3_commit *commit = NULL;
	int error = 0;

	GIT3_ASSERT_ARG(out);
	GIT3_ASSERT_ARG(repo);
	GIT3_ASSERT_ARG(id);

	*out = NULL;

	if ((error = git3_commit_lookup(&commit, repo, id)) < 0)
		goto done;

	error = annotated_commit_init(out, commit, description);

done:
	git3_commit_free(commit);
	return error;
}

int git3_annotated_commit_lookup(
	git3_annotated_commit **out,
	git3_repository *repo,
	const git3_oid *id)
{
	return annotated_commit_init_from_id(out, repo, id, NULL);
}

int git3_annotated_commit_from_commit(
	git3_annotated_commit **out,
	git3_commit *commit)
{
	return annotated_commit_init(out, commit, NULL);
}

int git3_annotated_commit_from_revspec(
	git3_annotated_commit **out,
	git3_repository *repo,
	const char *revspec)
{
	git3_object *obj, *commit;
	int error;

	GIT3_ASSERT_ARG(out);
	GIT3_ASSERT_ARG(repo);
	GIT3_ASSERT_ARG(revspec);

	if ((error = git3_revparse_single(&obj, repo, revspec)) < 0)
		return error;

	if ((error = git3_object_peel(&commit, obj, GIT3_OBJECT_COMMIT))) {
		git3_object_free(obj);
		return error;
	}

	error = annotated_commit_init(out, (git3_commit *)commit, revspec);

	git3_object_free(obj);
	git3_object_free(commit);

	return error;
}

int git3_annotated_commit_from_ref(
	git3_annotated_commit **out,
	git3_repository *repo,
	const git3_reference *ref)
{
	git3_object *peeled;
	int error = 0;

	GIT3_ASSERT_ARG(out);
	GIT3_ASSERT_ARG(repo);
	GIT3_ASSERT_ARG(ref);

	*out = NULL;

	if ((error = git3_reference_peel(&peeled, ref, GIT3_OBJECT_COMMIT)) < 0)
		return error;

	error = annotated_commit_init_from_id(out,
		repo,
		git3_object_id(peeled),
		git3_reference_name(ref));

	if (!error) {
		(*out)->ref_name = git3__strdup(git3_reference_name(ref));
		GIT3_ERROR_CHECK_ALLOC((*out)->ref_name);
	}

	git3_object_free(peeled);
	return error;
}

int git3_annotated_commit_from_head(
	git3_annotated_commit **out,
	git3_repository *repo)
{
	git3_reference *head;
	int error;

	GIT3_ASSERT_ARG(out);
	GIT3_ASSERT_ARG(repo);

	*out = NULL;

	if ((error = git3_reference_lookup(&head, repo, GIT3_HEAD_FILE)) < 0)
		return -1;

	error = git3_annotated_commit_from_ref(out, repo, head);

	git3_reference_free(head);
	return error;
}

int git3_annotated_commit_from_fetchhead(
	git3_annotated_commit **out,
	git3_repository *repo,
	const char *branch_name,
	const char *remote_url,
	const git3_oid *id)
{
	GIT3_ASSERT_ARG(out);
	GIT3_ASSERT_ARG(repo);
	GIT3_ASSERT_ARG(branch_name);
	GIT3_ASSERT_ARG(remote_url);
	GIT3_ASSERT_ARG(id);

	if (annotated_commit_init_from_id(out, repo, id, branch_name) < 0)
		return -1;

	(*out)->ref_name = git3__strdup(branch_name);
	GIT3_ERROR_CHECK_ALLOC((*out)->ref_name);

	(*out)->remote_url = git3__strdup(remote_url);
	GIT3_ERROR_CHECK_ALLOC((*out)->remote_url);

	return 0;
}


const git3_oid *git3_annotated_commit_id(
	const git3_annotated_commit *annotated_commit)
{
	GIT3_ASSERT_ARG_WITH_RETVAL(annotated_commit, NULL);
	return git3_commit_id(annotated_commit->commit);
}

const char *git3_annotated_commit_ref(
	const git3_annotated_commit *annotated_commit)
{
	GIT3_ASSERT_ARG_WITH_RETVAL(annotated_commit, NULL);
	return annotated_commit->ref_name;
}

void git3_annotated_commit_free(git3_annotated_commit *annotated_commit)
{
	if (annotated_commit == NULL)
		return;

	switch (annotated_commit->type) {
		case GIT3_ANNOTATED_COMMIT_REAL:
			git3_commit_free(annotated_commit->commit);
			git3_tree_free(annotated_commit->tree);
			git3__free((char *)annotated_commit->description);
			git3__free((char *)annotated_commit->ref_name);
			git3__free((char *)annotated_commit->remote_url);
			break;
		case GIT3_ANNOTATED_COMMIT_VIRTUAL:
			git3_index_free(annotated_commit->index);
			git3_array_clear(annotated_commit->parents);
			break;
		default:
			abort();
	}

	git3__free(annotated_commit);
}
