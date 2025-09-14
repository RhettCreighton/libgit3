/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "merge.h"

#include "posix.h"
#include "str.h"
#include "repository.h"
#include "revwalk.h"
#include "commit_list.h"
#include "fs_path.h"
#include "refs.h"
#include "object.h"
#include "iterator.h"
#include "refs.h"
#include "diff.h"
#include "diff_generate.h"
#include "diff_tform.h"
#include "checkout.h"
#include "tree.h"
#include "blob.h"
#include "oid.h"
#include "index.h"
#include "filebuf.h"
#include "config.h"
#include "oidarray.h"
#include "annotated_commit.h"
#include "commit.h"
#include "oidarray.h"
#include "merge_driver.h"
#include "array.h"

#include "git3/types.h"
#include "git3/repository.h"
#include "git3/object.h"
#include "git3/commit.h"
#include "git3/merge.h"
#include "git3/refs.h"
#include "git3/reset.h"
#include "git3/checkout.h"
#include "git3/signature.h"
#include "git3/config.h"
#include "git3/tree.h"
#include "git3/oidarray.h"
#include "git3/annotated_commit.h"
#include "git3/sys/index.h"
#include "git3/sys/hashsig.h"

#define GIT3_MERGE_INDEX_ENTRY_EXISTS(X)	((X).mode != 0)
#define GIT3_MERGE_INDEX_ENTRY_ISFILE(X) S_ISREG((X).mode)


typedef enum {
	TREE_IDX_ANCESTOR = 0,
	TREE_IDX_OURS = 1,
	TREE_IDX_THEIRS = 2
} merge_tree_index_t;

/* Tracks D/F conflicts */
struct merge_diff_df_data {
	const char *df_path;
	const char *prev_path;
	git3_merge_diff *prev_conflict;
};

/*
 * This acts as a negative cache entry marker. In case we've tried to calculate
 * similarity metrics for a given blob already but `git3_hashsig` determined
 * that it's too small in order to have a meaningful hash signature, we will
 * insert the address of this marker instead of `NULL`. Like this, we can
 * easily check whether we have checked a gien entry already and skip doing the
 * calculation again and again.
 */
static int cache_invalid_marker;

/* Merge base computation */

static int merge_bases_many(git3_commit_list **out, git3_revwalk **walk_out, git3_repository *repo, size_t length, const git3_oid input_array[])
{
	git3_revwalk *walk = NULL;
	git3_vector list;
	git3_commit_list *result = NULL;
	git3_commit_list_node *commit;
	int error = -1;
	unsigned int i;

	if (length < 2) {
		git3_error_set(GIT3_ERROR_INVALID, "at least two commits are required to find an ancestor");
		return -1;
	}

	if (git3_vector_init(&list, length - 1, NULL) < 0)
		return -1;

	if (git3_revwalk_new(&walk, repo) < 0)
		goto on_error;

	for (i = 1; i < length; i++) {
		commit = git3_revwalk__commit_lookup(walk, &input_array[i]);
		if (commit == NULL)
			goto on_error;

		git3_vector_insert(&list, commit);
	}

	commit = git3_revwalk__commit_lookup(walk, &input_array[0]);
	if (commit == NULL)
		goto on_error;

	if (git3_merge__bases_many(&result, walk, commit, &list, 0) < 0)
		goto on_error;

	if (!result) {
		git3_error_set(GIT3_ERROR_MERGE, "no merge base found");
		error = GIT3_ENOTFOUND;
		goto on_error;
	}

	*out = result;
	*walk_out = walk;

	git3_vector_dispose(&list);
	return 0;

on_error:
	git3_vector_dispose(&list);
	git3_revwalk_free(walk);
	return error;
}

int git3_merge_base_many(git3_oid *out, git3_repository *repo, size_t length, const git3_oid input_array[])
{
	git3_revwalk *walk;
	git3_commit_list *result = NULL;
	int error = 0;

	GIT3_ASSERT_ARG(out);
	GIT3_ASSERT_ARG(repo);
	GIT3_ASSERT_ARG(input_array);

	if ((error = merge_bases_many(&result, &walk, repo, length, input_array)) < 0)
		return error;

	git3_oid_cpy(out, &result->item->oid);

	git3_commit_list_free(&result);
	git3_revwalk_free(walk);

	return 0;
}

int git3_merge_bases_many(git3_oidarray *out, git3_repository *repo, size_t length, const git3_oid input_array[])
{
	git3_revwalk *walk;
	git3_commit_list *list, *result = NULL;
	int error = 0;
	git3_array_oid_t array;

	GIT3_ASSERT_ARG(out);
	GIT3_ASSERT_ARG(repo);
	GIT3_ASSERT_ARG(input_array);

	if ((error = merge_bases_many(&result, &walk, repo, length, input_array)) < 0)
		return error;

	git3_array_init(array);

	list = result;
	while (list) {
		git3_oid *id = git3_array_alloc(array);
		if (id == NULL) {
			error = -1;
			goto cleanup;
		}

		git3_oid_cpy(id, &list->item->oid);
		list = list->next;
	}

	git3_oidarray__from_array(out, &array);

cleanup:
	git3_commit_list_free(&result);
	git3_revwalk_free(walk);

	return error;
}

int git3_merge_base_octopus(git3_oid *out, git3_repository *repo, size_t length, const git3_oid input_array[])
{
	git3_oid result;
	unsigned int i;
	int error = -1;

	GIT3_ASSERT_ARG(out);
	GIT3_ASSERT_ARG(repo);
	GIT3_ASSERT_ARG(input_array);

	if (length < 2) {
		git3_error_set(GIT3_ERROR_INVALID, "at least two commits are required to find an ancestor");
		return -1;
	}

	result = input_array[0];
	for (i = 1; i < length; i++) {
		error = git3_merge_base(&result, repo, &result, &input_array[i]);
		if (error < 0)
			return error;
	}

	*out = result;

	return 0;
}

static int merge_bases(git3_commit_list **out, git3_revwalk **walk_out, git3_repository *repo, const git3_oid *one, const git3_oid *two)
{
	git3_revwalk *walk;
	git3_vector list;
	git3_commit_list *result = NULL;
	git3_commit_list_node *commit;
	void *contents[1];

	if (git3_revwalk_new(&walk, repo) < 0)
		return -1;

	commit = git3_revwalk__commit_lookup(walk, two);
	if (commit == NULL)
		goto on_error;

	/* This is just one value, so we can do it on the stack */
	memset(&list, 0x0, sizeof(git3_vector));
	contents[0] = commit;
	list.length = 1;
	list.contents = contents;

	commit = git3_revwalk__commit_lookup(walk, one);
	if (commit == NULL)
		goto on_error;

	if (git3_merge__bases_many(&result, walk, commit, &list, 0) < 0)
		goto on_error;

	if (!result) {
		git3_revwalk_free(walk);
		git3_error_set(GIT3_ERROR_MERGE, "no merge base found");
		return GIT3_ENOTFOUND;
	}

	*out = result;
	*walk_out = walk;

	return 0;

on_error:
	git3_revwalk_free(walk);
	return -1;

}

int git3_merge_base(git3_oid *out, git3_repository *repo, const git3_oid *one, const git3_oid *two)
{
	int error;
	git3_revwalk *walk;
	git3_commit_list *result;

	if ((error = merge_bases(&result, &walk, repo, one, two)) < 0)
		return error;

	git3_oid_cpy(out, &result->item->oid);
	git3_commit_list_free(&result);
	git3_revwalk_free(walk);

	return 0;
}

int git3_merge_bases(git3_oidarray *out, git3_repository *repo, const git3_oid *one, const git3_oid *two)
{
	int error;
	git3_revwalk *walk;
	git3_commit_list *result, *list;
	git3_array_oid_t array;

	git3_array_init(array);

	if ((error = merge_bases(&result, &walk, repo, one, two)) < 0)
		return error;

	list = result;
	while (list) {
		git3_oid *id = git3_array_alloc(array);
		if (id == NULL)
			goto on_error;

		git3_oid_cpy(id, &list->item->oid);
		list = list->next;
	}

	git3_oidarray__from_array(out, &array);
	git3_commit_list_free(&result);
	git3_revwalk_free(walk);

	return 0;

on_error:
	git3_commit_list_free(&result);
	git3_revwalk_free(walk);
	return -1;
}

static int interesting(git3_pqueue *list)
{
	size_t i;

	for (i = 0; i < git3_pqueue_size(list); i++) {
		git3_commit_list_node *commit = git3_pqueue_get(list, i);
		if ((commit->flags & STALE) == 0)
			return 1;
	}

	return 0;
}

static int clear_commit_marks_1(git3_commit_list **plist,
		git3_commit_list_node *commit, unsigned int mark)
{
	while (commit) {
		unsigned int i;

		if (!(mark & commit->flags))
			return 0;

		commit->flags &= ~mark;

		for (i = 1; i < commit->out_degree; i++) {
			git3_commit_list_node *p = commit->parents[i];
			if (git3_commit_list_insert(p, plist) == NULL)
				return -1;
		}

		commit = commit->out_degree ? commit->parents[0] : NULL;
	}

	return 0;
}

static int clear_commit_marks_many(git3_vector *commits, unsigned int mark)
{
	git3_commit_list *list = NULL;
	git3_commit_list_node *c;
	unsigned int i;

	git3_vector_foreach(commits, i, c) {
		if (git3_commit_list_insert(c, &list) == NULL)
			return -1;
	}

	while (list)
		if (clear_commit_marks_1(&list, git3_commit_list_pop(&list), mark) < 0)
			return -1;
	return 0;
}

static int clear_commit_marks(git3_commit_list_node *commit, unsigned int mark)
{
	git3_commit_list *list = NULL;
	if (git3_commit_list_insert(commit, &list) == NULL)
		return -1;
	while (list)
		if (clear_commit_marks_1(&list, git3_commit_list_pop(&list), mark) < 0)
			return -1;
	return 0;
}

static int paint_down_to_common(
		git3_commit_list **out,
		git3_revwalk *walk,
		git3_commit_list_node *one,
		git3_vector *twos,
		uint32_t minimum_generation)
{
	git3_pqueue list;
	git3_commit_list *result = NULL;
	git3_commit_list_node *two;

	int error;
	unsigned int i;

	if (git3_pqueue_init(&list, 0, twos->length * 2, git3_commit_list_generation_cmp) < 0)
		return -1;

	one->flags |= PARENT1;
	if (git3_pqueue_insert(&list, one) < 0)
		return -1;

	git3_vector_foreach(twos, i, two) {
		if (git3_commit_list_parse(walk, two) < 0)
			return -1;

		two->flags |= PARENT2;
		if (git3_pqueue_insert(&list, two) < 0)
			return -1;
	}

	/* as long as there are non-STALE commits */
	while (interesting(&list)) {
		git3_commit_list_node *commit = git3_pqueue_pop(&list);
		int flags;

		if (commit == NULL)
			break;

		flags = commit->flags & (PARENT1 | PARENT2 | STALE);
		if (flags == (PARENT1 | PARENT2)) {
			if (!(commit->flags & RESULT)) {
				commit->flags |= RESULT;
				if (git3_commit_list_insert(commit, &result) == NULL)
					return -1;
			}
			/* we mark the parents of a merge stale */
			flags |= STALE;
		}

		for (i = 0; i < commit->out_degree; i++) {
			git3_commit_list_node *p = commit->parents[i];
			if ((p->flags & flags) == flags)
				continue;
			if (p->generation < minimum_generation)
				continue;

			if ((error = git3_commit_list_parse(walk, p)) < 0)
				return error;

			p->flags |= flags;
			if (git3_pqueue_insert(&list, p) < 0)
				return -1;
		}
	}

	git3_pqueue_free(&list);
	*out = result;
	return 0;
}

static int remove_redundant(git3_revwalk *walk, git3_vector *commits, uint32_t minimum_generation)
{
	git3_vector work = GIT3_VECTOR_INIT;
	unsigned char *redundant;
	unsigned int *filled_index;
	unsigned int i, j;
	int error = 0;

	redundant = git3__calloc(commits->length, 1);
	GIT3_ERROR_CHECK_ALLOC(redundant);
	filled_index = git3__calloc((commits->length - 1), sizeof(unsigned int));
	GIT3_ERROR_CHECK_ALLOC(filled_index);

	for (i = 0; i < commits->length; ++i) {
		if ((error = git3_commit_list_parse(walk, commits->contents[i])) < 0)
			goto done;
	}

	for (i = 0; i < commits->length; ++i) {
		git3_commit_list *common = NULL;
		git3_commit_list_node *commit = commits->contents[i];

		if (redundant[i])
			continue;

		git3_vector_clear(&work);

		for (j = 0; j < commits->length; j++) {
			if (i == j || redundant[j])
				continue;

			filled_index[work.length] = j;
			if ((error = git3_vector_insert(&work, commits->contents[j])) < 0)
				goto done;
		}

		error = paint_down_to_common(&common, walk, commit, &work, minimum_generation);
		if (error < 0)
			goto done;

		if (commit->flags & PARENT2)
			redundant[i] = 1;

		for (j = 0; j < work.length; j++) {
			git3_commit_list_node *w = work.contents[j];
			if (w->flags & PARENT1)
				redundant[filled_index[j]] = 1;
		}

		git3_commit_list_free(&common);

		if ((error = clear_commit_marks(commit, ALL_FLAGS)) < 0 ||
		    (error = clear_commit_marks_many(&work, ALL_FLAGS)) < 0)
				goto done;
	}

	for (i = 0; i < commits->length; ++i) {
		if (redundant[i])
			commits->contents[i] = NULL;
	}

done:
	git3__free(redundant);
	git3__free(filled_index);
	git3_vector_dispose(&work);
	return error;
}

int git3_merge__bases_many(
		git3_commit_list **out,
		git3_revwalk *walk,
		git3_commit_list_node *one,
		git3_vector *twos,
		uint32_t minimum_generation)
{
	int error;
	unsigned int i;
	git3_commit_list_node *two;
	git3_commit_list *result = NULL, *tmp = NULL;

	/* If there's only the one commit, there can be no merge bases */
	if (twos->length == 0) {
		*out = NULL;
		return 0;
	}

	/* if the commit is repeated, we have a our merge base already */
	git3_vector_foreach(twos, i, two) {
		if (one == two)
			return git3_commit_list_insert(one, out) ? 0 : -1;
	}

	if (git3_commit_list_parse(walk, one) < 0)
		return -1;

	error = paint_down_to_common(&result, walk, one, twos, minimum_generation);
	if (error < 0)
		return error;

	/* filter out any stale commits in the results */
	tmp = result;
	result = NULL;

	while (tmp) {
		git3_commit_list_node *c = git3_commit_list_pop(&tmp);
		if (!(c->flags & STALE))
			if (git3_commit_list_insert_by_date(c, &result) == NULL)
				return -1;
	}

	/*
	 * more than one merge base -- see if there are redundant merge
	 * bases and remove them
	 */
	if (result && result->next) {
		git3_vector redundant = GIT3_VECTOR_INIT;

		while (result)
			git3_vector_insert(&redundant, git3_commit_list_pop(&result));

		if ((error = clear_commit_marks(one, ALL_FLAGS)) < 0 ||
		    (error = clear_commit_marks_many(twos, ALL_FLAGS)) < 0 ||
		    (error = remove_redundant(walk, &redundant, minimum_generation)) < 0) {
			git3_vector_dispose(&redundant);
			return error;
		}

		git3_vector_foreach(&redundant, i, two) {
			if (two != NULL)
				git3_commit_list_insert_by_date(two, &result);
		}

		git3_vector_dispose(&redundant);
	}

	*out = result;
	return 0;
}

int git3_repository_mergehead_foreach(
	git3_repository *repo,
	git3_repository_mergehead_foreach_cb cb,
	void *payload)
{
	git3_str merge_head_path = GIT3_STR_INIT, merge_head_file = GIT3_STR_INIT;
	char *buffer, *line;
	size_t line_num = 1;
	git3_oid oid;
	int error = 0;

	GIT3_ASSERT_ARG(repo);
	GIT3_ASSERT_ARG(cb);

	if ((error = git3_str_joinpath(&merge_head_path, repo->gitdir,
		GIT3_MERGE_HEAD_FILE)) < 0)
		return error;

	if ((error = git3_futils_readbuffer(&merge_head_file,
		git3_str_cstr(&merge_head_path))) < 0)
		goto cleanup;

	buffer = merge_head_file.ptr;

	while ((line = git3__strsep(&buffer, "\n")) != NULL) {
		if (strlen(line) != git3_oid_hexsize(repo->oid_type)) {
			git3_error_set(GIT3_ERROR_INVALID, "unable to parse OID - invalid length");
			error = -1;
			goto cleanup;
		}

		if ((error = git3_oid_from_string(&oid, line, repo->oid_type)) < 0)
			goto cleanup;

		if ((error = cb(&oid, payload)) != 0) {
			git3_error_set_after_callback(error);
			goto cleanup;
		}

		++line_num;
	}

	if (*buffer) {
		git3_error_set(GIT3_ERROR_MERGE, "no EOL at line %"PRIuZ, line_num);
		error = -1;
		goto cleanup;
	}

cleanup:
	git3_str_dispose(&merge_head_path);
	git3_str_dispose(&merge_head_file);

	return error;
}

GIT3_INLINE(int) index_entry_cmp(const git3_index_entry *a, const git3_index_entry *b)
{
	int value = 0;

	if (a->path == NULL)
		return (b->path == NULL) ? 0 : 1;

	if ((value = a->mode - b->mode) == 0 &&
		(value = git3_oid__cmp(&a->id, &b->id)) == 0)
		value = strcmp(a->path, b->path);

	return value;
}

/* Conflict resolution */

static int merge_conflict_resolve_trivial(
	int *resolved,
	git3_merge_diff_list *diff_list,
	const git3_merge_diff *conflict)
{
	int ours_empty, theirs_empty;
	int ours_changed, theirs_changed, ours_theirs_differ;
	git3_index_entry const *result = NULL;
	int error = 0;

	GIT3_ASSERT_ARG(resolved);
	GIT3_ASSERT_ARG(diff_list);
	GIT3_ASSERT_ARG(conflict);

	*resolved = 0;

	if (conflict->type == GIT3_MERGE_DIFF_DIRECTORY_FILE ||
		conflict->type == GIT3_MERGE_DIFF_RENAMED_ADDED)
		return 0;

	if (conflict->our_status == GIT3_DELTA_RENAMED ||
		conflict->their_status == GIT3_DELTA_RENAMED)
		return 0;

	ours_empty = !GIT3_MERGE_INDEX_ENTRY_EXISTS(conflict->our_entry);
	theirs_empty = !GIT3_MERGE_INDEX_ENTRY_EXISTS(conflict->their_entry);

	ours_changed = (conflict->our_status != GIT3_DELTA_UNMODIFIED);
	theirs_changed = (conflict->their_status != GIT3_DELTA_UNMODIFIED);
	ours_theirs_differ = ours_changed && theirs_changed &&
		index_entry_cmp(&conflict->our_entry, &conflict->their_entry);

	/*
	 * Note: with only one ancestor, some cases are not distinct:
	 *
	 * 16: ancest:anc1/anc2, head:anc1, remote:anc2 = result:no merge
	 * 3: ancest:(empty)^, head:head, remote:(empty) = result:no merge
	 * 2: ancest:(empty)^, head:(empty), remote:remote = result:no merge
	 *
	 * Note that the two cases that take D/F conflicts into account
	 * specifically do not need to be explicitly tested, as D/F conflicts
	 * would fail the *empty* test:
	 *
	 * 3ALT: ancest:(empty)+, head:head, remote:*empty* = result:head
	 * 2ALT: ancest:(empty)+, head:*empty*, remote:remote = result:remote
	 *
	 * Note that many of these cases need not be explicitly tested, as
	 * they simply degrade to "all different" cases (eg, 11):
	 *
	 * 4: ancest:(empty)^, head:head, remote:remote = result:no merge
	 * 7: ancest:ancest+, head:(empty), remote:remote = result:no merge
	 * 9: ancest:ancest+, head:head, remote:(empty) = result:no merge
	 * 11: ancest:ancest+, head:head, remote:remote = result:no merge
	 */

	/* 5ALT: ancest:*, head:head, remote:head = result:head */
	if (ours_changed && !ours_empty && !ours_theirs_differ)
		result = &conflict->our_entry;
	/* 6: ancest:ancest+, head:(empty), remote:(empty) = result:no merge */
	else if (ours_changed && ours_empty && theirs_empty)
		*resolved = 0;
	/* 8: ancest:ancest^, head:(empty), remote:ancest = result:no merge */
	else if (ours_empty && !theirs_changed)
		*resolved = 0;
	/* 10: ancest:ancest^, head:ancest, remote:(empty) = result:no merge */
	else if (!ours_changed && theirs_empty)
		*resolved = 0;
	/* 13: ancest:ancest+, head:head, remote:ancest = result:head */
	else if (ours_changed && !theirs_changed)
		result = &conflict->our_entry;
	/* 14: ancest:ancest+, head:ancest, remote:remote = result:remote */
	else if (!ours_changed && theirs_changed)
		result = &conflict->their_entry;
	else
		*resolved = 0;

	if (result != NULL &&
		GIT3_MERGE_INDEX_ENTRY_EXISTS(*result) &&
		(error = git3_vector_insert(&diff_list->staged, (void *)result)) >= 0)
		*resolved = 1;

	/* Note: trivial resolution does not update the REUC. */

	return error;
}

static int merge_conflict_resolve_one_removed(
	int *resolved,
	git3_merge_diff_list *diff_list,
	const git3_merge_diff *conflict)
{
	int ours_empty, theirs_empty;
	int ours_changed, theirs_changed;
	int error = 0;

	GIT3_ASSERT_ARG(resolved);
	GIT3_ASSERT_ARG(diff_list);
	GIT3_ASSERT_ARG(conflict);

	*resolved = 0;

	if (conflict->type == GIT3_MERGE_DIFF_DIRECTORY_FILE ||
		conflict->type == GIT3_MERGE_DIFF_RENAMED_ADDED)
		return 0;

	ours_empty = !GIT3_MERGE_INDEX_ENTRY_EXISTS(conflict->our_entry);
	theirs_empty = !GIT3_MERGE_INDEX_ENTRY_EXISTS(conflict->their_entry);

	ours_changed = (conflict->our_status != GIT3_DELTA_UNMODIFIED);
	theirs_changed = (conflict->their_status != GIT3_DELTA_UNMODIFIED);

	/* Removed in both */
	if (ours_changed && ours_empty && theirs_empty)
		*resolved = 1;
	/* Removed in ours */
	else if (ours_empty && !theirs_changed)
		*resolved = 1;
	/* Removed in theirs */
	else if (!ours_changed && theirs_empty)
		*resolved = 1;

	if (*resolved)
		git3_vector_insert(&diff_list->resolved, (git3_merge_diff *)conflict);

	return error;
}

static int merge_conflict_resolve_one_renamed(
	int *resolved,
	git3_merge_diff_list *diff_list,
	const git3_merge_diff *conflict)
{
	int ours_renamed, theirs_renamed;
	int ours_changed, theirs_changed;
	git3_index_entry *merged;
	int error = 0;

	GIT3_ASSERT_ARG(resolved);
	GIT3_ASSERT_ARG(diff_list);
	GIT3_ASSERT_ARG(conflict);

	*resolved = 0;

	if (!GIT3_MERGE_INDEX_ENTRY_EXISTS(conflict->our_entry) ||
		!GIT3_MERGE_INDEX_ENTRY_EXISTS(conflict->their_entry))
		return 0;

	ours_renamed = (conflict->our_status == GIT3_DELTA_RENAMED);
	theirs_renamed = (conflict->their_status == GIT3_DELTA_RENAMED);

	if (!ours_renamed && !theirs_renamed)
		return 0;

	/* Reject one file in a 2->1 conflict */
	if (conflict->type == GIT3_MERGE_DIFF_BOTH_RENAMED_2_TO_1 ||
		conflict->type == GIT3_MERGE_DIFF_BOTH_RENAMED_1_TO_2 ||
		conflict->type == GIT3_MERGE_DIFF_RENAMED_ADDED)
		return 0;

	ours_changed = (git3_oid__cmp(&conflict->ancestor_entry.id, &conflict->our_entry.id) != 0) ||
		(conflict->ancestor_entry.mode != conflict->our_entry.mode);

	theirs_changed = (git3_oid__cmp(&conflict->ancestor_entry.id, &conflict->their_entry.id) != 0) ||
		(conflict->ancestor_entry.mode != conflict->their_entry.mode);

	/* if both are modified (and not to a common target) require a merge */
	if (ours_changed && theirs_changed &&
		git3_oid__cmp(&conflict->our_entry.id, &conflict->their_entry.id) != 0)
		return 0;

	if ((merged = git3_pool_malloc(&diff_list->pool, sizeof(git3_index_entry))) == NULL)
		return -1;

	if (ours_changed)
		memcpy(merged, &conflict->our_entry, sizeof(git3_index_entry));
	else
		memcpy(merged, &conflict->their_entry, sizeof(git3_index_entry));

	if (ours_renamed)
		merged->path = conflict->our_entry.path;
	else
		merged->path = conflict->their_entry.path;

	*resolved = 1;

	git3_vector_insert(&diff_list->staged, merged);
	git3_vector_insert(&diff_list->resolved, (git3_merge_diff *)conflict);

	return error;
}

static bool merge_conflict_can_resolve_contents(
	const git3_merge_diff *conflict)
{
	if (!GIT3_MERGE_INDEX_ENTRY_EXISTS(conflict->our_entry) ||
		!GIT3_MERGE_INDEX_ENTRY_EXISTS(conflict->their_entry))
		return false;

	/* Reject D/F conflicts */
	if (conflict->type == GIT3_MERGE_DIFF_DIRECTORY_FILE)
		return false;

	/* Reject submodules. */
	if (S_ISGITLINK(conflict->ancestor_entry.mode) ||
		S_ISGITLINK(conflict->our_entry.mode) ||
		S_ISGITLINK(conflict->their_entry.mode))
		return false;

	/* Reject link/file conflicts. */
	if ((S_ISLNK(conflict->ancestor_entry.mode) ^
			S_ISLNK(conflict->our_entry.mode)) ||
		(S_ISLNK(conflict->ancestor_entry.mode) ^
			S_ISLNK(conflict->their_entry.mode)))
		return false;

	/* Reject name conflicts */
	if (conflict->type == GIT3_MERGE_DIFF_BOTH_RENAMED_2_TO_1 ||
		conflict->type == GIT3_MERGE_DIFF_RENAMED_ADDED)
		return false;

	if ((conflict->our_status & GIT3_DELTA_RENAMED) == GIT3_DELTA_RENAMED &&
		(conflict->their_status & GIT3_DELTA_RENAMED) == GIT3_DELTA_RENAMED &&
		strcmp(conflict->ancestor_entry.path, conflict->their_entry.path) != 0)
		return false;

	return true;
}

static int merge_conflict_invoke_driver(
	git3_index_entry **out,
	const char *name,
	git3_merge_driver *driver,
	git3_merge_diff_list *diff_list,
	git3_merge_driver_source *src)
{
	git3_index_entry *result;
	git3_buf buf = {0};
	const char *path;
	uint32_t mode;
	git3_odb *odb = NULL;
	git3_oid oid;
	int error;

	*out = NULL;

	if ((error = driver->apply(driver, &path, &mode, &buf, name, src)) < 0 ||
		(error = git3_repository_odb(&odb, src->repo)) < 0 ||
		(error = git3_odb_write(&oid, odb, buf.ptr, buf.size, GIT3_OBJECT_BLOB)) < 0)
		goto done;

	result = git3_pool_mallocz(&diff_list->pool, sizeof(git3_index_entry));
	GIT3_ERROR_CHECK_ALLOC(result);

	git3_oid_cpy(&result->id, &oid);
	result->mode = mode;
	result->file_size = (uint32_t)buf.size;

	result->path = git3_pool_strdup(&diff_list->pool, path);
	GIT3_ERROR_CHECK_ALLOC(result->path);

	*out = result;

done:
	git3_buf_dispose(&buf);
	git3_odb_free(odb);

	return error;
}

static int merge_conflict_resolve_contents(
	int *resolved,
	git3_merge_diff_list *diff_list,
	const git3_merge_diff *conflict,
	const git3_merge_options *merge_opts,
	const git3_merge_file_options *file_opts)
{
	git3_merge_driver_source source = {0};
	git3_merge_file_result result = {0};
	git3_merge_driver *driver;
	git3_merge_driver__builtin builtin = {{0}};
	git3_index_entry *merge_result;
	git3_odb *odb = NULL;
	const char *name;
	bool fallback = false;
	int error;

	GIT3_ASSERT_ARG(resolved);
	GIT3_ASSERT_ARG(diff_list);
	GIT3_ASSERT_ARG(conflict);

	*resolved = 0;

	if (!merge_conflict_can_resolve_contents(conflict))
		return 0;

	source.repo = diff_list->repo;
	source.default_driver = merge_opts->default_driver;
	source.file_opts = file_opts;
	source.ancestor = GIT3_MERGE_INDEX_ENTRY_EXISTS(conflict->ancestor_entry) ?
		&conflict->ancestor_entry : NULL;
	source.ours = GIT3_MERGE_INDEX_ENTRY_EXISTS(conflict->our_entry) ?
		&conflict->our_entry : NULL;
	source.theirs = GIT3_MERGE_INDEX_ENTRY_EXISTS(conflict->their_entry) ?
		&conflict->their_entry : NULL;

	if (file_opts->favor != GIT3_MERGE_FILE_FAVOR_NORMAL) {
		/* if the user requested a particular type of resolution (via the
		 * favor flag) then let that override the gitattributes and use
		 * the builtin driver.
		 */
		name = "text";
		builtin.base.apply = git3_merge_driver__builtin_apply;
		builtin.favor = file_opts->favor;

		driver = &builtin.base;
	} else {
		/* find the merge driver for this file */
		if ((error = git3_merge_driver_for_source(&name, &driver, &source)) < 0)
			goto done;

		if (driver == NULL)
			fallback = true;
	}

	if (driver) {
		error = merge_conflict_invoke_driver(&merge_result, name, driver,
			diff_list, &source);

		if (error == GIT3_PASSTHROUGH)
			fallback = true;
	}

	if (fallback) {
		error = merge_conflict_invoke_driver(&merge_result, "text",
			&git3_merge_driver__text.base, diff_list, &source);
	}

	if (error < 0) {
		if (error == GIT3_EMERGECONFLICT)
			error = 0;

		goto done;
	}

	git3_vector_insert(&diff_list->staged, merge_result);
	git3_vector_insert(&diff_list->resolved, (git3_merge_diff *)conflict);

	*resolved = 1;

done:
	git3_merge_file_result_free(&result);
	git3_odb_free(odb);

	return error;
}

static int merge_conflict_resolve(
	int *out,
	git3_merge_diff_list *diff_list,
	const git3_merge_diff *conflict,
	const git3_merge_options *merge_opts,
	const git3_merge_file_options *file_opts)
{
	int resolved = 0;
	int error = 0;

	*out = 0;

	if ((error = merge_conflict_resolve_trivial(
			&resolved, diff_list, conflict)) < 0)
		goto done;

	if (!resolved && (error = merge_conflict_resolve_one_removed(
			&resolved, diff_list, conflict)) < 0)
		goto done;

	if (!resolved && (error = merge_conflict_resolve_one_renamed(
			&resolved, diff_list, conflict)) < 0)
		goto done;

	if (!resolved && (error = merge_conflict_resolve_contents(
			&resolved, diff_list, conflict, merge_opts, file_opts)) < 0)
		goto done;

	*out = resolved;

done:
	return error;
}

/* Rename detection and coalescing */

struct merge_diff_similarity {
	unsigned char similarity;
	size_t other_idx;
};

static int index_entry_similarity_calc(
	void **out,
	git3_repository *repo,
	git3_index_entry *entry,
	const git3_merge_options *opts)
{
	git3_blob *blob;
	git3_diff_file diff_file;
	git3_object_size_t blobsize;
	int error;

	if (*out || *out == &cache_invalid_marker)
		return 0;

	*out = NULL;

	git3_oid_clear(&diff_file.id, repo->oid_type);

	if ((error = git3_blob_lookup(&blob, repo, &entry->id)) < 0)
		return error;

	git3_oid_cpy(&diff_file.id, &entry->id);
	diff_file.path = entry->path;
	diff_file.size = entry->file_size;
	diff_file.mode = entry->mode;
	diff_file.flags = 0;

	blobsize = git3_blob_rawsize(blob);

	/* file too big for rename processing */
	if (!git3__is_sizet(blobsize))
		return 0;

	error = opts->metric->buffer_signature(out, &diff_file,
		git3_blob_rawcontent(blob), (size_t)blobsize,
		opts->metric->payload);
	if (error == GIT3_EBUFS)
		*out = &cache_invalid_marker;

	git3_blob_free(blob);

	return error;
}

static int index_entry_similarity_inexact(
	git3_repository *repo,
	git3_index_entry *a,
	size_t a_idx,
	git3_index_entry *b,
	size_t b_idx,
	void **cache,
	const git3_merge_options *opts)
{
	int score = 0;
	int error = 0;

	if (!GIT3_MODE_ISBLOB(a->mode) || !GIT3_MODE_ISBLOB(b->mode))
		return 0;

	/* update signature cache if needed */
	if ((error = index_entry_similarity_calc(&cache[a_idx], repo, a, opts)) < 0 ||
	    (error = index_entry_similarity_calc(&cache[b_idx], repo, b, opts)) < 0)
		return error;

	/* some metrics may not wish to process this file (too big / too small) */
	if (cache[a_idx] == &cache_invalid_marker || cache[b_idx] == &cache_invalid_marker)
		return 0;

	/* compare signatures */
	if (opts->metric->similarity(&score, cache[a_idx], cache[b_idx], opts->metric->payload) < 0)
		return -1;

	/* clip score */
	if (score < 0)
		score = 0;
	else if (score > 100)
		score = 100;

	return score;
}

/* Tracks deletes by oid for merge_diff_mark_similarity_exact().  This is a
* non-shrinking queue where next_pos is the next position to dequeue.
*/
typedef struct {
	git3_array_t(size_t) arr;
	size_t next_pos;
	size_t first_entry;
} deletes_by_oid_queue;

GIT3_HASHMAP_OID_SETUP(git3_merge_deletes_oidmap, deletes_by_oid_queue *);

static void deletes_by_oid_dispose(git3_merge_deletes_oidmap *map)
{
	git3_hashmap_iter_t iter = GIT3_HASHMAP_ITER_INIT;
	deletes_by_oid_queue *queue;

	if (!map)
		return;

	while (git3_merge_deletes_oidmap_iterate(&iter, NULL, &queue, map) == 0)
		git3_array_clear(queue->arr);

	git3_merge_deletes_oidmap_dispose(map);
}

static int deletes_by_oid_enqueue(git3_merge_deletes_oidmap *map, git3_pool *pool, const git3_oid *id, size_t idx)
{
	deletes_by_oid_queue *queue;
	size_t *array_entry;

	if (git3_merge_deletes_oidmap_get(&queue, map, id) != 0) {
		queue = git3_pool_malloc(pool, sizeof(deletes_by_oid_queue));
		GIT3_ERROR_CHECK_ALLOC(queue);

		git3_array_init(queue->arr);
		queue->next_pos = 0;
		queue->first_entry = idx;

		if (git3_merge_deletes_oidmap_put(map, id, queue) < 0)
			return -1;
	} else {
		array_entry = git3_array_alloc(queue->arr);
		GIT3_ERROR_CHECK_ALLOC(array_entry);
		*array_entry = idx;
	}

	return 0;
}

static int deletes_by_oid_dequeue(size_t *idx, git3_merge_deletes_oidmap *map, const git3_oid *id)
{
	deletes_by_oid_queue *queue;
	size_t *array_entry;
	int error;

	if ((error = git3_merge_deletes_oidmap_get(&queue, map, id)) != 0)
		return error;

	if (queue->next_pos == 0) {
		*idx = queue->first_entry;
	} else {
		array_entry = git3_array_get(queue->arr, queue->next_pos - 1);
		if (array_entry == NULL)
			return GIT3_ENOTFOUND;

		*idx = *array_entry;
	}

	queue->next_pos++;
	return 0;
}

static int merge_diff_mark_similarity_exact(
	git3_merge_diff_list *diff_list,
	struct merge_diff_similarity *similarity_ours,
	struct merge_diff_similarity *similarity_theirs)
{
	size_t i, j;
	git3_merge_diff *conflict_src, *conflict_tgt;
	git3_merge_deletes_oidmap ours_deletes_by_oid = GIT3_HASHMAP_INIT,
	                         theirs_deletes_by_oid = GIT3_HASHMAP_INIT;
	int error = 0;

	/* Build a map of object ids to conflicts */
	git3_vector_foreach(&diff_list->conflicts, i, conflict_src) {
		/* Items can be the source of a rename iff they have an item in the
		* ancestor slot and lack an item in the ours or theirs slot. */
		if (!GIT3_MERGE_INDEX_ENTRY_EXISTS(conflict_src->ancestor_entry))
			continue;

		/*
		 * Ignore empty files because it has always the same blob sha1
		 * and will lead to incorrect matches between all entries.
		 */
		if (git3_oid_equal(&conflict_src->ancestor_entry.id, &git3_oid__empty_blob_sha1))
			continue;

		if (!GIT3_MERGE_INDEX_ENTRY_EXISTS(conflict_src->our_entry)) {
			error = deletes_by_oid_enqueue(&ours_deletes_by_oid, &diff_list->pool, &conflict_src->ancestor_entry.id, i);
			if (error < 0)
				goto done;
		}

		if (!GIT3_MERGE_INDEX_ENTRY_EXISTS(conflict_src->their_entry)) {
			error = deletes_by_oid_enqueue(&theirs_deletes_by_oid, &diff_list->pool, &conflict_src->ancestor_entry.id, i);
			if (error < 0)
				goto done;
		}
	}

	git3_vector_foreach(&diff_list->conflicts, j, conflict_tgt) {
		if (GIT3_MERGE_INDEX_ENTRY_EXISTS(conflict_tgt->ancestor_entry))
			continue;

		if (GIT3_MERGE_INDEX_ENTRY_EXISTS(conflict_tgt->our_entry)) {
			if (deletes_by_oid_dequeue(&i, &ours_deletes_by_oid, &conflict_tgt->our_entry.id) == 0) {
				similarity_ours[i].similarity = 100;
				similarity_ours[i].other_idx = j;

				similarity_ours[j].similarity = 100;
				similarity_ours[j].other_idx = i;
			}
		}

		if (GIT3_MERGE_INDEX_ENTRY_EXISTS(conflict_tgt->their_entry)) {
			if (deletes_by_oid_dequeue(&i, &theirs_deletes_by_oid, &conflict_tgt->their_entry.id) == 0) {
				similarity_theirs[i].similarity = 100;
				similarity_theirs[i].other_idx = j;

				similarity_theirs[j].similarity = 100;
				similarity_theirs[j].other_idx = i;
			}
		}
	}

done:
	deletes_by_oid_dispose(&ours_deletes_by_oid);
	deletes_by_oid_dispose(&theirs_deletes_by_oid);

	return error;
}

static int merge_diff_mark_similarity_inexact(
	git3_repository *repo,
	git3_merge_diff_list *diff_list,
	struct merge_diff_similarity *similarity_ours,
	struct merge_diff_similarity *similarity_theirs,
	void **cache,
	const git3_merge_options *opts)
{
	size_t i, j;
	git3_merge_diff *conflict_src, *conflict_tgt;
	int similarity;

	git3_vector_foreach(&diff_list->conflicts, i, conflict_src) {
		/* Items can be the source of a rename iff they have an item in the
		 * ancestor slot and lack an item in the ours or theirs slot. */
		if (!GIT3_MERGE_INDEX_ENTRY_EXISTS(conflict_src->ancestor_entry) ||
			(GIT3_MERGE_INDEX_ENTRY_EXISTS(conflict_src->our_entry) &&
			 GIT3_MERGE_INDEX_ENTRY_EXISTS(conflict_src->their_entry)))
			continue;

		git3_vector_foreach(&diff_list->conflicts, j, conflict_tgt) {
			size_t our_idx = diff_list->conflicts.length + j;
			size_t their_idx = (diff_list->conflicts.length * 2) + j;

			if (GIT3_MERGE_INDEX_ENTRY_EXISTS(conflict_tgt->ancestor_entry))
				continue;

			if (GIT3_MERGE_INDEX_ENTRY_EXISTS(conflict_tgt->our_entry) &&
				!GIT3_MERGE_INDEX_ENTRY_EXISTS(conflict_src->our_entry)) {
				similarity = index_entry_similarity_inexact(repo, &conflict_src->ancestor_entry, i, &conflict_tgt->our_entry, our_idx, cache, opts);

				if (similarity == GIT3_EBUFS)
					continue;
				else if (similarity < 0)
					return similarity;

				if (similarity > similarity_ours[i].similarity &&
					similarity > similarity_ours[j].similarity) {
					/* Clear previous best similarity */
					if (similarity_ours[i].similarity > 0)
						similarity_ours[similarity_ours[i].other_idx].similarity = 0;

					if (similarity_ours[j].similarity > 0)
						similarity_ours[similarity_ours[j].other_idx].similarity = 0;

					similarity_ours[i].similarity = similarity;
					similarity_ours[i].other_idx = j;

					similarity_ours[j].similarity = similarity;
					similarity_ours[j].other_idx = i;
				}
			}

			if (GIT3_MERGE_INDEX_ENTRY_EXISTS(conflict_tgt->their_entry) &&
				!GIT3_MERGE_INDEX_ENTRY_EXISTS(conflict_src->their_entry)) {
				similarity = index_entry_similarity_inexact(repo, &conflict_src->ancestor_entry, i, &conflict_tgt->their_entry, their_idx, cache, opts);

				if (similarity > similarity_theirs[i].similarity &&
					similarity > similarity_theirs[j].similarity) {
					/* Clear previous best similarity */
					if (similarity_theirs[i].similarity > 0)
						similarity_theirs[similarity_theirs[i].other_idx].similarity = 0;

					if (similarity_theirs[j].similarity > 0)
						similarity_theirs[similarity_theirs[j].other_idx].similarity = 0;

					similarity_theirs[i].similarity = similarity;
					similarity_theirs[i].other_idx = j;

					similarity_theirs[j].similarity = similarity;
					similarity_theirs[j].other_idx = i;
				}
			}
		}
	}

	return 0;
}

/*
 * Rename conflicts:
 *
 *      Ancestor   Ours   Theirs
 *
 * 0a   A          A      A        No rename
 *  b   A          A*     A        No rename (ours was rewritten)
 *  c   A          A      A*       No rename (theirs rewritten)
 * 1a   A          A      B[A]     Rename or rename/edit
 *  b   A          B[A]   A        (automergeable)
 * 2    A          B[A]   B[A]     Both renamed (automergeable)
 * 3a   A          B[A]            Rename/delete
 *  b   A                 B[A]      (same)
 * 4a   A          B[A]   B        Rename/add [B~ours B~theirs]
 *  b   A          B      B[A]      (same)
 * 5    A          B[A]   C[A]     Both renamed ("1 -> 2")
 * 6    A          C[A]            Both renamed ("2 -> 1")
 *      B                 C[B]     [C~ours C~theirs]    (automergeable)
 */
static void merge_diff_mark_rename_conflict(
	git3_merge_diff_list *diff_list,
	struct merge_diff_similarity *similarity_ours,
	bool ours_renamed,
	size_t ours_source_idx,
	struct merge_diff_similarity *similarity_theirs,
	bool theirs_renamed,
	size_t theirs_source_idx,
	git3_merge_diff *target,
	const git3_merge_options *opts)
{
	git3_merge_diff *ours_source = NULL, *theirs_source = NULL;

	if (ours_renamed)
		ours_source = diff_list->conflicts.contents[ours_source_idx];

	if (theirs_renamed)
		theirs_source = diff_list->conflicts.contents[theirs_source_idx];

	/* Detect 2->1 conflicts */
	if (ours_renamed && theirs_renamed) {
		/* Both renamed to the same target name. */
		if (ours_source_idx == theirs_source_idx)
			ours_source->type = GIT3_MERGE_DIFF_BOTH_RENAMED;
		else {
			ours_source->type = GIT3_MERGE_DIFF_BOTH_RENAMED_2_TO_1;
			theirs_source->type = GIT3_MERGE_DIFF_BOTH_RENAMED_2_TO_1;
		}
	} else if (ours_renamed) {
		/* If our source was also renamed in theirs, this is a 1->2 */
		if (similarity_theirs[ours_source_idx].similarity >= opts->rename_threshold)
			ours_source->type = GIT3_MERGE_DIFF_BOTH_RENAMED_1_TO_2;

		else if (GIT3_MERGE_INDEX_ENTRY_EXISTS(target->their_entry)) {
			ours_source->type = GIT3_MERGE_DIFF_RENAMED_ADDED;
			target->type = GIT3_MERGE_DIFF_RENAMED_ADDED;
		}

		else if (!GIT3_MERGE_INDEX_ENTRY_EXISTS(ours_source->their_entry))
			ours_source->type = GIT3_MERGE_DIFF_RENAMED_DELETED;

		else if (ours_source->type == GIT3_MERGE_DIFF_MODIFIED_DELETED)
			ours_source->type = GIT3_MERGE_DIFF_RENAMED_MODIFIED;
	} else if (theirs_renamed) {
		/* If their source was also renamed in ours, this is a 1->2 */
		if (similarity_ours[theirs_source_idx].similarity >= opts->rename_threshold)
			theirs_source->type = GIT3_MERGE_DIFF_BOTH_RENAMED_1_TO_2;

		else if (GIT3_MERGE_INDEX_ENTRY_EXISTS(target->our_entry)) {
			theirs_source->type = GIT3_MERGE_DIFF_RENAMED_ADDED;
			target->type = GIT3_MERGE_DIFF_RENAMED_ADDED;
		}

		else if (!GIT3_MERGE_INDEX_ENTRY_EXISTS(theirs_source->our_entry))
			theirs_source->type = GIT3_MERGE_DIFF_RENAMED_DELETED;

		else if (theirs_source->type == GIT3_MERGE_DIFF_MODIFIED_DELETED)
			theirs_source->type = GIT3_MERGE_DIFF_RENAMED_MODIFIED;
	}
}

GIT3_INLINE(void) merge_diff_coalesce_rename(
	git3_index_entry *source_entry,
	git3_delta_t *source_status,
	git3_index_entry *target_entry,
	git3_delta_t *target_status)
{
	/* Coalesce the rename target into the rename source. */
	memcpy(source_entry, target_entry, sizeof(git3_index_entry));
	*source_status = GIT3_DELTA_RENAMED;

	memset(target_entry, 0x0, sizeof(git3_index_entry));
	*target_status = GIT3_DELTA_UNMODIFIED;
}

static void merge_diff_list_coalesce_renames(
	git3_merge_diff_list *diff_list,
	struct merge_diff_similarity *similarity_ours,
	struct merge_diff_similarity *similarity_theirs,
	const git3_merge_options *opts)
{
	size_t i;
	bool ours_renamed = 0, theirs_renamed = 0;
	size_t ours_source_idx = 0, theirs_source_idx = 0;
	git3_merge_diff *ours_source, *theirs_source, *target;

	for (i = 0; i < diff_list->conflicts.length; i++) {
		target = diff_list->conflicts.contents[i];

		ours_renamed = 0;
		theirs_renamed = 0;

		if (GIT3_MERGE_INDEX_ENTRY_EXISTS(target->our_entry) &&
			similarity_ours[i].similarity >= opts->rename_threshold) {
			ours_source_idx = similarity_ours[i].other_idx;

			ours_source = diff_list->conflicts.contents[ours_source_idx];

			merge_diff_coalesce_rename(
				&ours_source->our_entry,
				&ours_source->our_status,
				&target->our_entry,
				&target->our_status);

			similarity_ours[ours_source_idx].similarity = 0;
			similarity_ours[i].similarity = 0;

			ours_renamed = 1;
		}

		/* insufficient to determine direction */
		if (GIT3_MERGE_INDEX_ENTRY_EXISTS(target->their_entry) &&
			similarity_theirs[i].similarity >= opts->rename_threshold) {
			theirs_source_idx = similarity_theirs[i].other_idx;

			theirs_source = diff_list->conflicts.contents[theirs_source_idx];

			merge_diff_coalesce_rename(
				&theirs_source->their_entry,
				&theirs_source->their_status,
				&target->their_entry,
				&target->their_status);

			similarity_theirs[theirs_source_idx].similarity = 0;
			similarity_theirs[i].similarity = 0;

			theirs_renamed = 1;
		}

		merge_diff_mark_rename_conflict(diff_list,
			similarity_ours, ours_renamed, ours_source_idx,
			similarity_theirs, theirs_renamed, theirs_source_idx,
			target, opts);
	}
}

static int merge_diff_empty(const git3_vector *conflicts, size_t idx, void *p)
{
	git3_merge_diff *conflict = conflicts->contents[idx];

	GIT3_UNUSED(p);

	return (!GIT3_MERGE_INDEX_ENTRY_EXISTS(conflict->ancestor_entry) &&
		!GIT3_MERGE_INDEX_ENTRY_EXISTS(conflict->our_entry) &&
		!GIT3_MERGE_INDEX_ENTRY_EXISTS(conflict->their_entry));
}

static void merge_diff_list_count_candidates(
	git3_merge_diff_list *diff_list,
	size_t *src_count,
	size_t *tgt_count)
{
	git3_merge_diff *entry;
	size_t i;

	*src_count = 0;
	*tgt_count = 0;

	git3_vector_foreach(&diff_list->conflicts, i, entry) {
		if (GIT3_MERGE_INDEX_ENTRY_EXISTS(entry->ancestor_entry) &&
			(!GIT3_MERGE_INDEX_ENTRY_EXISTS(entry->our_entry) ||
			!GIT3_MERGE_INDEX_ENTRY_EXISTS(entry->their_entry)))
			(*src_count)++;
		else if (!GIT3_MERGE_INDEX_ENTRY_EXISTS(entry->ancestor_entry))
			(*tgt_count)++;
	}
}

int git3_merge_diff_list__find_renames(
	git3_repository *repo,
	git3_merge_diff_list *diff_list,
	const git3_merge_options *opts)
{
	struct merge_diff_similarity *similarity_ours, *similarity_theirs;
	void **cache = NULL;
	size_t cache_size = 0;
	size_t src_count, tgt_count, i;
	int error = 0;

	GIT3_ASSERT_ARG(diff_list);
	GIT3_ASSERT_ARG(opts);

	if ((opts->flags & GIT3_MERGE_FIND_RENAMES) == 0 ||
	    !diff_list->conflicts.length)
		return 0;

	similarity_ours = git3__calloc(diff_list->conflicts.length,
		sizeof(struct merge_diff_similarity));
	GIT3_ERROR_CHECK_ALLOC(similarity_ours);

	similarity_theirs = git3__calloc(diff_list->conflicts.length,
		sizeof(struct merge_diff_similarity));
	GIT3_ERROR_CHECK_ALLOC(similarity_theirs);

	/* Calculate similarity between items that were deleted from the ancestor
	 * and added in the other branch.
	 */
	if ((error = merge_diff_mark_similarity_exact(diff_list, similarity_ours, similarity_theirs)) < 0)
		goto done;

	if (opts->rename_threshold < 100 && diff_list->conflicts.length <= opts->target_limit) {
		GIT3_ERROR_CHECK_ALLOC_MULTIPLY(&cache_size, diff_list->conflicts.length, 3);
		cache = git3__calloc(cache_size, sizeof(void *));
		GIT3_ERROR_CHECK_ALLOC(cache);

		merge_diff_list_count_candidates(diff_list, &src_count, &tgt_count);

		if (src_count > opts->target_limit || tgt_count > opts->target_limit) {
			/* TODO: report! */
		} else {
			if ((error = merge_diff_mark_similarity_inexact(
				repo, diff_list, similarity_ours, similarity_theirs, cache, opts)) < 0)
				goto done;
		}
	}

	/* For entries that are appropriately similar, merge the new name's entry
	 * into the old name.
	 */
	merge_diff_list_coalesce_renames(diff_list, similarity_ours, similarity_theirs, opts);

	/* And remove any entries that were merged and are now empty. */
	git3_vector_remove_matching(&diff_list->conflicts, merge_diff_empty, NULL);

done:
	if (cache != NULL) {
		for (i = 0; i < cache_size; ++i) {
			if (cache[i] != NULL && cache[i] != &cache_invalid_marker)
				opts->metric->free_signature(cache[i], opts->metric->payload);
		}

		git3__free(cache);
	}

	git3__free(similarity_ours);
	git3__free(similarity_theirs);

	return error;
}

/* Directory/file conflict handling */

GIT3_INLINE(const char *) merge_diff_path(
	const git3_merge_diff *conflict)
{
	if (GIT3_MERGE_INDEX_ENTRY_EXISTS(conflict->ancestor_entry))
		return conflict->ancestor_entry.path;
	else if (GIT3_MERGE_INDEX_ENTRY_EXISTS(conflict->our_entry))
		return conflict->our_entry.path;
	else if (GIT3_MERGE_INDEX_ENTRY_EXISTS(conflict->their_entry))
		return conflict->their_entry.path;

	return NULL;
}

GIT3_INLINE(bool) merge_diff_any_side_added_or_modified(
	const git3_merge_diff *conflict)
{
	if (conflict->our_status == GIT3_DELTA_ADDED ||
		conflict->our_status == GIT3_DELTA_MODIFIED ||
		conflict->their_status == GIT3_DELTA_ADDED ||
		conflict->their_status == GIT3_DELTA_MODIFIED)
		return true;

	return false;
}

GIT3_INLINE(bool) path_is_prefixed(const char *parent, const char *child)
{
	size_t child_len = strlen(child);
	size_t parent_len = strlen(parent);

	if (child_len < parent_len ||
		strncmp(parent, child, parent_len) != 0)
		return 0;

	return (child[parent_len] == '/');
}

GIT3_INLINE(int) merge_diff_detect_df_conflict(
	struct merge_diff_df_data *df_data,
	git3_merge_diff *conflict)
{
	const char *cur_path = merge_diff_path(conflict);

	/* Determine if this is a D/F conflict or the child of one */
	if (df_data->df_path &&
		path_is_prefixed(df_data->df_path, cur_path))
		conflict->type = GIT3_MERGE_DIFF_DF_CHILD;
	else if(df_data->df_path)
		df_data->df_path = NULL;
	else if (df_data->prev_path &&
		merge_diff_any_side_added_or_modified(df_data->prev_conflict) &&
		merge_diff_any_side_added_or_modified(conflict) &&
		path_is_prefixed(df_data->prev_path, cur_path)) {
		conflict->type = GIT3_MERGE_DIFF_DF_CHILD;

		df_data->prev_conflict->type = GIT3_MERGE_DIFF_DIRECTORY_FILE;
		df_data->df_path = df_data->prev_path;
	}

	df_data->prev_path = cur_path;
	df_data->prev_conflict = conflict;

	return 0;
}

/* Conflict handling */

GIT3_INLINE(int) merge_diff_detect_type(
	git3_merge_diff *conflict)
{
	if (conflict->our_status == GIT3_DELTA_ADDED &&
		conflict->their_status == GIT3_DELTA_ADDED)
		conflict->type = GIT3_MERGE_DIFF_BOTH_ADDED;
	else if (conflict->our_status == GIT3_DELTA_MODIFIED &&
			 conflict->their_status == GIT3_DELTA_MODIFIED)
		conflict->type = GIT3_MERGE_DIFF_BOTH_MODIFIED;
	else if (conflict->our_status == GIT3_DELTA_DELETED &&
			 conflict->their_status == GIT3_DELTA_DELETED)
		conflict->type = GIT3_MERGE_DIFF_BOTH_DELETED;
	else if (conflict->our_status == GIT3_DELTA_MODIFIED &&
			 conflict->their_status == GIT3_DELTA_DELETED)
		conflict->type = GIT3_MERGE_DIFF_MODIFIED_DELETED;
	else if (conflict->our_status == GIT3_DELTA_DELETED &&
			 conflict->their_status == GIT3_DELTA_MODIFIED)
		conflict->type = GIT3_MERGE_DIFF_MODIFIED_DELETED;
	else
		conflict->type = GIT3_MERGE_DIFF_NONE;

	return 0;
}

GIT3_INLINE(int) index_entry_dup_pool(
	git3_index_entry *out,
	git3_pool *pool,
	const git3_index_entry *src)
{
	if (src != NULL) {
		memcpy(out, src, sizeof(git3_index_entry));
		if ((out->path = git3_pool_strdup(pool, src->path)) == NULL)
			return -1;
	}

	return 0;
}

GIT3_INLINE(int) merge_delta_type_from_index_entries(
	const git3_index_entry *ancestor,
	const git3_index_entry *other)
{
	if (ancestor == NULL && other == NULL)
		return GIT3_DELTA_UNMODIFIED;
	else if (ancestor == NULL && other != NULL)
		return GIT3_DELTA_ADDED;
	else if (ancestor != NULL && other == NULL)
		return GIT3_DELTA_DELETED;
	else if (S_ISDIR(ancestor->mode) ^ S_ISDIR(other->mode))
		return GIT3_DELTA_TYPECHANGE;
	else if(S_ISLNK(ancestor->mode) ^ S_ISLNK(other->mode))
		return GIT3_DELTA_TYPECHANGE;
	else if (git3_oid__cmp(&ancestor->id, &other->id) ||
			 ancestor->mode != other->mode)
		return GIT3_DELTA_MODIFIED;

	return GIT3_DELTA_UNMODIFIED;
}

static git3_merge_diff *merge_diff_from_index_entries(
	git3_merge_diff_list *diff_list,
	const git3_index_entry **entries)
{
	git3_merge_diff *conflict;
	git3_pool *pool = &diff_list->pool;

	if ((conflict = git3_pool_mallocz(pool, sizeof(git3_merge_diff))) == NULL)
		return NULL;

	if (index_entry_dup_pool(&conflict->ancestor_entry, pool, entries[TREE_IDX_ANCESTOR]) < 0 ||
		index_entry_dup_pool(&conflict->our_entry, pool, entries[TREE_IDX_OURS]) < 0 ||
		index_entry_dup_pool(&conflict->their_entry, pool, entries[TREE_IDX_THEIRS]) < 0)
		return NULL;

	conflict->our_status = merge_delta_type_from_index_entries(
		entries[TREE_IDX_ANCESTOR], entries[TREE_IDX_OURS]);
	conflict->their_status = merge_delta_type_from_index_entries(
		entries[TREE_IDX_ANCESTOR], entries[TREE_IDX_THEIRS]);

	return conflict;
}

/* Merge trees */

static int merge_diff_list_insert_conflict(
	git3_merge_diff_list *diff_list,
	struct merge_diff_df_data *merge_df_data,
	const git3_index_entry *tree_items[3])
{
	git3_merge_diff *conflict;

	if ((conflict = merge_diff_from_index_entries(diff_list, tree_items)) == NULL ||
		merge_diff_detect_type(conflict) < 0 ||
		merge_diff_detect_df_conflict(merge_df_data, conflict) < 0 ||
		git3_vector_insert(&diff_list->conflicts, conflict) < 0)
		return -1;

	return 0;
}

static int merge_diff_list_insert_unmodified(
	git3_merge_diff_list *diff_list,
	const git3_index_entry *tree_items[3])
{
	int error = 0;
	git3_index_entry *entry;

	entry = git3_pool_malloc(&diff_list->pool, sizeof(git3_index_entry));
	GIT3_ERROR_CHECK_ALLOC(entry);

	if ((error = index_entry_dup_pool(entry, &diff_list->pool, tree_items[0])) >= 0)
		error = git3_vector_insert(&diff_list->staged, entry);

	return error;
}

struct merge_diff_find_data {
	git3_merge_diff_list *diff_list;
	struct merge_diff_df_data df_data;
};

static int queue_difference(const git3_index_entry **entries, void *data)
{
	struct merge_diff_find_data *find_data = data;
	bool item_modified = false;
	size_t i;

	if (!entries[0] || !entries[1] || !entries[2]) {
		item_modified = true;
	} else {
		for (i = 1; i < 3; i++) {
			if (index_entry_cmp(entries[0], entries[i]) != 0) {
				item_modified = true;
				break;
			}
		}
	}

	return item_modified ?
		merge_diff_list_insert_conflict(
			find_data->diff_list, &find_data->df_data, entries) :
		merge_diff_list_insert_unmodified(find_data->diff_list, entries);
}

int git3_merge_diff_list__find_differences(
	git3_merge_diff_list *diff_list,
	git3_iterator *ancestor_iter,
	git3_iterator *our_iter,
	git3_iterator *their_iter)
{
	git3_iterator *iterators[3] = { ancestor_iter, our_iter, their_iter };
	struct merge_diff_find_data find_data = { diff_list };

	return git3_iterator_walk(iterators, 3, queue_difference, &find_data);
}

git3_merge_diff_list *git3_merge_diff_list__alloc(git3_repository *repo)
{
	git3_merge_diff_list *diff_list = git3__calloc(1, sizeof(git3_merge_diff_list));

	if (diff_list == NULL)
		return NULL;

	diff_list->repo = repo;


	if (git3_pool_init(&diff_list->pool, 1) < 0 ||
	    git3_vector_init(&diff_list->staged, 0, NULL) < 0 ||
	    git3_vector_init(&diff_list->conflicts, 0, NULL) < 0 ||
	    git3_vector_init(&diff_list->resolved, 0, NULL) < 0) {
	    git3_merge_diff_list__free(diff_list);
		return NULL;
	}

	return diff_list;
}

void git3_merge_diff_list__free(git3_merge_diff_list *diff_list)
{
	if (!diff_list)
		return;

	git3_vector_dispose(&diff_list->staged);
	git3_vector_dispose(&diff_list->conflicts);
	git3_vector_dispose(&diff_list->resolved);
	git3_pool_clear(&diff_list->pool);
	git3__free(diff_list);
}

static int merge_normalize_opts(
	git3_repository *repo,
	git3_merge_options *opts,
	const git3_merge_options *given)
{
	git3_config *cfg = NULL;
	git3_config_entry *entry = NULL;
	int error = 0;

	GIT3_ASSERT_ARG(repo);
	GIT3_ASSERT_ARG(opts);

	if ((error = git3_repository_config__weakptr(&cfg, repo)) < 0)
		return error;

	if (given != NULL) {
		memcpy(opts, given, sizeof(git3_merge_options));
	} else {
		git3_merge_options init = GIT3_MERGE_OPTIONS_INIT;
		memcpy(opts, &init, sizeof(init));
	}

	if ((opts->flags & GIT3_MERGE_FIND_RENAMES) && !opts->rename_threshold)
		opts->rename_threshold = GIT3_MERGE_DEFAULT_RENAME_THRESHOLD;

	if (given && given->default_driver) {
		opts->default_driver = git3__strdup(given->default_driver);
		GIT3_ERROR_CHECK_ALLOC(opts->default_driver);
	} else {
		error = git3_config_get_entry(&entry, cfg, "merge.default");

		if (error == 0) {
			opts->default_driver = git3__strdup(entry->value);
			GIT3_ERROR_CHECK_ALLOC(opts->default_driver);
		} else if (error == GIT3_ENOTFOUND) {
			error = 0;
		} else {
			goto done;
		}
	}

	if (!opts->target_limit) {
		int limit = git3_config__get_int_force(cfg, "merge.renamelimit", 0);

		if (!limit)
			limit = git3_config__get_int_force(cfg, "diff.renamelimit", 0);

		opts->target_limit = (limit <= 0) ?
			GIT3_MERGE_DEFAULT_TARGET_LIMIT : (unsigned int)limit;
	}

	/* assign the internal metric with whitespace flag as payload */
	if (!opts->metric) {
		opts->metric = git3__malloc(sizeof(git3_diff_similarity_metric));
		GIT3_ERROR_CHECK_ALLOC(opts->metric);

		opts->metric->file_signature = git3_diff_find_similar__hashsig_for_file;
		opts->metric->buffer_signature = git3_diff_find_similar__hashsig_for_buf;
		opts->metric->free_signature = git3_diff_find_similar__hashsig_free;
		opts->metric->similarity = git3_diff_find_similar__calc_similarity;
		opts->metric->payload = (void *)GIT3_HASHSIG_SMART_WHITESPACE;
	}

done:
	git3_config_entry_free(entry);
	return error;
}


static int merge_index_insert_reuc(
	git3_index *index,
	size_t idx,
	const git3_index_entry *entry)
{
	const git3_index_reuc_entry *reuc;
	int mode[3] = { 0, 0, 0 };
	git3_oid const *oid[3] = { NULL, NULL, NULL };
	size_t i;

	if (!GIT3_MERGE_INDEX_ENTRY_EXISTS(*entry))
		return 0;

	if ((reuc = git3_index_reuc_get_bypath(index, entry->path)) != NULL) {
		for (i = 0; i < 3; i++) {
			mode[i] = reuc->mode[i];
			oid[i] = &reuc->oid[i];
		}
	}

	mode[idx] = entry->mode;
	oid[idx] = &entry->id;

	return git3_index_reuc_add(index, entry->path,
		mode[0], oid[0], mode[1], oid[1], mode[2], oid[2]);
}

static int index_update_reuc(git3_index *index, git3_merge_diff_list *diff_list)
{
	int error;
	size_t i;
	git3_merge_diff *conflict;

	/* Add each entry in the resolved conflict to the REUC independently, since
	 * the paths may differ due to renames. */
	git3_vector_foreach(&diff_list->resolved, i, conflict) {
		const git3_index_entry *ancestor =
			GIT3_MERGE_INDEX_ENTRY_EXISTS(conflict->ancestor_entry) ?
			&conflict->ancestor_entry : NULL;

		const git3_index_entry *ours =
			GIT3_MERGE_INDEX_ENTRY_EXISTS(conflict->our_entry) ?
			&conflict->our_entry : NULL;

		const git3_index_entry *theirs =
			GIT3_MERGE_INDEX_ENTRY_EXISTS(conflict->their_entry) ?
			&conflict->their_entry : NULL;

		if (ancestor != NULL &&
			(error = merge_index_insert_reuc(index, TREE_IDX_ANCESTOR, ancestor)) < 0)
			return error;

		if (ours != NULL &&
			(error = merge_index_insert_reuc(index, TREE_IDX_OURS, ours)) < 0)
			return error;

		if (theirs != NULL &&
			(error = merge_index_insert_reuc(index, TREE_IDX_THEIRS, theirs)) < 0)
			return error;
	}

	return 0;
}

static int index_from_diff_list(
	git3_index **out,
	git3_merge_diff_list *diff_list,
	git3_oid_t oid_type,
	bool skip_reuc)
{
	git3_index *index;
	size_t i;
	git3_merge_diff *conflict;
	git3_index_options index_opts = GIT3_INDEX_OPTIONS_INIT;
	int error = 0;

	*out = NULL;

	index_opts.oid_type = oid_type;

	if ((error = git3_index_new_ext(&index, &index_opts)) < 0)
		return error;

	if ((error = git3_index__fill(index, &diff_list->staged)) < 0)
		goto on_error;

	git3_vector_foreach(&diff_list->conflicts, i, conflict) {
		const git3_index_entry *ancestor =
			GIT3_MERGE_INDEX_ENTRY_EXISTS(conflict->ancestor_entry) ?
			&conflict->ancestor_entry : NULL;

		const git3_index_entry *ours =
			GIT3_MERGE_INDEX_ENTRY_EXISTS(conflict->our_entry) ?
			&conflict->our_entry : NULL;

		const git3_index_entry *theirs =
			GIT3_MERGE_INDEX_ENTRY_EXISTS(conflict->their_entry) ?
			&conflict->their_entry : NULL;

		if ((error = git3_index_conflict_add(index, ancestor, ours, theirs)) < 0)
			goto on_error;
	}

	/* Add each rename entry to the rename portion of the index. */
	git3_vector_foreach(&diff_list->conflicts, i, conflict) {
		const char *ancestor_path, *our_path, *their_path;

		if (!GIT3_MERGE_INDEX_ENTRY_EXISTS(conflict->ancestor_entry))
			continue;

		ancestor_path = conflict->ancestor_entry.path;

		our_path =
			GIT3_MERGE_INDEX_ENTRY_EXISTS(conflict->our_entry) ?
			conflict->our_entry.path : NULL;

		their_path =
			GIT3_MERGE_INDEX_ENTRY_EXISTS(conflict->their_entry) ?
			conflict->their_entry.path : NULL;

		if ((our_path && strcmp(ancestor_path, our_path) != 0) ||
			(their_path && strcmp(ancestor_path, their_path) != 0)) {
			if ((error = git3_index_name_add(index, ancestor_path, our_path, their_path)) < 0)
				goto on_error;
		}
	}

	if (!skip_reuc) {
		if ((error = index_update_reuc(index, diff_list)) < 0)
			goto on_error;
	}

	*out = index;
	return 0;

on_error:
	git3_index_free(index);
	return error;
}

static git3_iterator *iterator_given_or_empty(git3_iterator **empty, git3_iterator *given)
{
	git3_iterator_options opts = GIT3_ITERATOR_OPTIONS_INIT;

	if (given)
		return given;

	opts.flags = GIT3_ITERATOR_DONT_IGNORE_CASE;

	if (git3_iterator_for_nothing(empty, &opts) < 0)
		return NULL;

	return *empty;
}

int git3_merge__iterators(
	git3_index **out,
	git3_repository *repo,
	git3_iterator *ancestor_iter,
	git3_iterator *our_iter,
	git3_iterator *theirs_iter,
	const git3_merge_options *given_opts)
{
	git3_iterator *empty_ancestor = NULL,
		*empty_ours = NULL,
		*empty_theirs = NULL;
	git3_merge_diff_list *diff_list;
	git3_merge_options opts;
	git3_merge_file_options file_opts = GIT3_MERGE_FILE_OPTIONS_INIT;
	git3_merge_diff *conflict;
	git3_vector changes;
	size_t i;
	int error = 0;

	GIT3_ASSERT_ARG(out);
	GIT3_ASSERT_ARG(repo);

	*out = NULL;

	GIT3_ERROR_CHECK_VERSION(
		given_opts, GIT3_MERGE_OPTIONS_VERSION, "git3_merge_options");

	if ((error = merge_normalize_opts(repo, &opts, given_opts)) < 0)
		return error;

	file_opts.favor = opts.file_favor;
	file_opts.flags = opts.file_flags;

	/* use the git-inspired labels when virtual base building */
	if (opts.flags & GIT3_MERGE_VIRTUAL_BASE) {
		file_opts.ancestor_label = "merged common ancestors";
		file_opts.our_label = "Temporary merge branch 1";
		file_opts.their_label = "Temporary merge branch 2";
		file_opts.flags |= GIT3_MERGE_FILE_ACCEPT_CONFLICTS;
		file_opts.marker_size = GIT3_MERGE_CONFLICT_MARKER_SIZE + 2;
	}

	diff_list = git3_merge_diff_list__alloc(repo);
	GIT3_ERROR_CHECK_ALLOC(diff_list);

	ancestor_iter = iterator_given_or_empty(&empty_ancestor, ancestor_iter);
	our_iter = iterator_given_or_empty(&empty_ours, our_iter);
	theirs_iter = iterator_given_or_empty(&empty_theirs, theirs_iter);

	if ((error = git3_merge_diff_list__find_differences(
			diff_list, ancestor_iter, our_iter, theirs_iter)) < 0 ||
		(error = git3_merge_diff_list__find_renames(repo, diff_list, &opts)) < 0)
		goto done;

	memcpy(&changes, &diff_list->conflicts, sizeof(git3_vector));
	git3_vector_clear(&diff_list->conflicts);

	git3_vector_foreach(&changes, i, conflict) {
		int resolved = 0;

		if ((error = merge_conflict_resolve(
			&resolved, diff_list, conflict, &opts, &file_opts)) < 0)
			goto done;

		if (!resolved) {
			if ((opts.flags & GIT3_MERGE_FAIL_ON_CONFLICT)) {
				git3_error_set(GIT3_ERROR_MERGE, "merge conflicts exist");
				error = GIT3_EMERGECONFLICT;
				goto done;
			}

			git3_vector_insert(&diff_list->conflicts, conflict);
		}
	}

	error = index_from_diff_list(out, diff_list, repo->oid_type,
		(opts.flags & GIT3_MERGE_SKIP_REUC));

done:
	if (!given_opts || !given_opts->metric)
		git3__free(opts.metric);

	git3__free((char *)opts.default_driver);

	git3_merge_diff_list__free(diff_list);
	git3_iterator_free(empty_ancestor);
	git3_iterator_free(empty_ours);
	git3_iterator_free(empty_theirs);

	return error;
}

int git3_merge_trees(
	git3_index **out,
	git3_repository *repo,
	const git3_tree *ancestor_tree,
	const git3_tree *our_tree,
	const git3_tree *their_tree,
	const git3_merge_options *merge_opts)
{
	git3_iterator *ancestor_iter = NULL, *our_iter = NULL, *their_iter = NULL;
	git3_iterator_options iter_opts = GIT3_ITERATOR_OPTIONS_INIT;
	git3_index_options index_opts = GIT3_INDEX_OPTIONS_FOR_REPO(repo);
	int error;

	GIT3_ASSERT_ARG(out);
	GIT3_ASSERT_ARG(repo);

	/* if one side is treesame to the ancestor, take the other side */
	if (ancestor_tree && merge_opts && (merge_opts->flags & GIT3_MERGE_SKIP_REUC)) {
		const git3_tree *result = NULL;
		const git3_oid *ancestor_tree_id = git3_tree_id(ancestor_tree);

		if (our_tree && !git3_oid_cmp(ancestor_tree_id, git3_tree_id(our_tree)))
			result = their_tree;
		else if (their_tree && !git3_oid_cmp(ancestor_tree_id, git3_tree_id(their_tree)))
			result = our_tree;

		if (result) {
			if ((error = git3_index_new_ext(out, &index_opts)) == 0)
				error = git3_index_read_tree(*out, result);

			return error;
		}
	}

	iter_opts.flags = GIT3_ITERATOR_DONT_IGNORE_CASE;

	if ((error = git3_iterator_for_tree(
			&ancestor_iter, (git3_tree *)ancestor_tree, &iter_opts)) < 0 ||
		(error = git3_iterator_for_tree(
			&our_iter, (git3_tree *)our_tree, &iter_opts)) < 0 ||
		(error = git3_iterator_for_tree(
			&their_iter, (git3_tree *)their_tree, &iter_opts)) < 0)
		goto done;

	error = git3_merge__iterators(
		out, repo, ancestor_iter, our_iter, their_iter, merge_opts);

done:
	git3_iterator_free(ancestor_iter);
	git3_iterator_free(our_iter);
	git3_iterator_free(their_iter);

	return error;
}

static int merge_annotated_commits(
	git3_index **index_out,
	git3_annotated_commit **base_out,
	git3_repository *repo,
	git3_annotated_commit *our_commit,
	git3_annotated_commit *their_commit,
	size_t recursion_level,
	const git3_merge_options *opts);

GIT3_INLINE(int) insert_head_ids(
	git3_array_oid_t *ids,
	const git3_annotated_commit *annotated_commit)
{
	git3_oid *id;
	size_t i;

	if (annotated_commit->type == GIT3_ANNOTATED_COMMIT_REAL) {
		id = git3_array_alloc(*ids);
		GIT3_ERROR_CHECK_ALLOC(id);

		git3_oid_cpy(id, git3_commit_id(annotated_commit->commit));
	} else {
		for (i = 0; i < annotated_commit->parents.size; i++) {
			id = git3_array_alloc(*ids);
			GIT3_ERROR_CHECK_ALLOC(id);

			git3_oid_cpy(id, &annotated_commit->parents.ptr[i]);
		}
	}

	return 0;
}

static int create_virtual_base(
	git3_annotated_commit **out,
	git3_repository *repo,
	git3_annotated_commit *one,
	git3_annotated_commit *two,
	const git3_merge_options *opts,
	size_t recursion_level)
{
	git3_annotated_commit *result = NULL;
	git3_index *index = NULL;
	git3_merge_options virtual_opts = GIT3_MERGE_OPTIONS_INIT;

	/* Conflicts in the merge base creation do not propagate to conflicts
	 * in the result; the conflicted base will act as the common ancestor.
	 */
	if (opts)
		memcpy(&virtual_opts, opts, sizeof(git3_merge_options));

	virtual_opts.flags &= ~GIT3_MERGE_FAIL_ON_CONFLICT;
	virtual_opts.flags |= GIT3_MERGE_VIRTUAL_BASE;

	if ((merge_annotated_commits(&index, NULL, repo, one, two,
			recursion_level + 1, &virtual_opts)) < 0)
		return -1;

	result = git3__calloc(1, sizeof(git3_annotated_commit));
	GIT3_ERROR_CHECK_ALLOC(result);
	result->type = GIT3_ANNOTATED_COMMIT_VIRTUAL;
	result->index = index;

	if (insert_head_ids(&result->parents, one) < 0 ||
		insert_head_ids(&result->parents, two) < 0) {
		git3_annotated_commit_free(result);
		return -1;
	}

	*out = result;
	return 0;
}

static int compute_base(
	git3_annotated_commit **out,
	git3_repository *repo,
	const git3_annotated_commit *one,
	const git3_annotated_commit *two,
	const git3_merge_options *given_opts,
	size_t recursion_level)
{
	git3_array_oid_t head_ids = GIT3_ARRAY_INIT;
	git3_oidarray bases = {0};
	git3_annotated_commit *base = NULL, *other = NULL, *new_base = NULL;
	git3_merge_options opts = GIT3_MERGE_OPTIONS_INIT;
	size_t i, base_count;
	int error;

	*out = NULL;

	if (given_opts)
		memcpy(&opts, given_opts, sizeof(git3_merge_options));

	/* With more than two commits, merge_bases_many finds the base of
	 * the first commit and a hypothetical merge of the others. Since
	 * "one" may itself be a virtual commit, which insert_head_ids
	 * substitutes multiple ancestors for, it needs to be added
	 * after "two" which is always a single real commit.
	 */
	if ((error = insert_head_ids(&head_ids, two)) < 0 ||
		(error = insert_head_ids(&head_ids, one)) < 0 ||
		(error = git3_merge_bases_many(&bases, repo,
			head_ids.size, head_ids.ptr)) < 0)
		goto done;

	base_count = (opts.flags & GIT3_MERGE_NO_RECURSIVE) ? 0 : bases.count;

	if (base_count)
		git3_oidarray__reverse(&bases);

	if ((error = git3_annotated_commit_lookup(&base, repo, &bases.ids[0])) < 0)
		goto done;

	for (i = 1; i < base_count; i++) {
		recursion_level++;

		if (opts.recursion_limit && recursion_level > opts.recursion_limit)
			break;

		if ((error = git3_annotated_commit_lookup(&other, repo,
				&bases.ids[i])) < 0 ||
			(error = create_virtual_base(&new_base, repo, base, other, &opts,
				recursion_level)) < 0)
			goto done;

		git3_annotated_commit_free(base);
		git3_annotated_commit_free(other);

		base = new_base;
		new_base = NULL;
		other = NULL;
	}

done:
	if (error == 0)
		*out = base;
	else
		git3_annotated_commit_free(base);

	git3_annotated_commit_free(other);
	git3_annotated_commit_free(new_base);
	git3_oidarray_dispose(&bases);
	git3_array_clear(head_ids);
	return error;
}

static int iterator_for_annotated_commit(
	git3_iterator **out,
	git3_annotated_commit *commit)
{
	git3_iterator_options opts = GIT3_ITERATOR_OPTIONS_INIT;
	int error;

	opts.flags = GIT3_ITERATOR_DONT_IGNORE_CASE;

	if (commit == NULL) {
		error = git3_iterator_for_nothing(out, &opts);
	} else if (commit->type == GIT3_ANNOTATED_COMMIT_VIRTUAL) {
		error = git3_iterator_for_index(out, git3_index_owner(commit->index), commit->index, &opts);
	} else {
		if (!commit->tree &&
			(error = git3_commit_tree(&commit->tree, commit->commit)) < 0)
			goto done;

		error = git3_iterator_for_tree(out, commit->tree, &opts);
	}

done:
	return error;
}

static int merge_annotated_commits(
	git3_index **index_out,
	git3_annotated_commit **base_out,
	git3_repository *repo,
	git3_annotated_commit *ours,
	git3_annotated_commit *theirs,
	size_t recursion_level,
	const git3_merge_options *opts)
{
	git3_annotated_commit *base = NULL;
	git3_iterator *base_iter = NULL, *our_iter = NULL, *their_iter = NULL;
	int error;

	if ((error = compute_base(&base, repo, ours, theirs, opts,
		recursion_level)) < 0) {

		if (error != GIT3_ENOTFOUND)
			goto done;

		git3_error_clear();
	}

	if ((error = iterator_for_annotated_commit(&base_iter, base)) < 0 ||
		(error = iterator_for_annotated_commit(&our_iter, ours)) < 0 ||
		(error = iterator_for_annotated_commit(&their_iter, theirs)) < 0 ||
		(error = git3_merge__iterators(index_out, repo, base_iter, our_iter,
			their_iter, opts)) < 0)
		goto done;

	if (base_out) {
		*base_out = base;
		base = NULL;
	}

done:
	git3_annotated_commit_free(base);
	git3_iterator_free(base_iter);
	git3_iterator_free(our_iter);
	git3_iterator_free(their_iter);
	return error;
}


int git3_merge_commits(
	git3_index **out,
	git3_repository *repo,
	const git3_commit *our_commit,
	const git3_commit *their_commit,
	const git3_merge_options *opts)
{
	git3_annotated_commit *ours = NULL, *theirs = NULL, *base = NULL;
	int error = 0;

	if ((error = git3_annotated_commit_from_commit(&ours, (git3_commit *)our_commit)) < 0 ||
		(error = git3_annotated_commit_from_commit(&theirs, (git3_commit *)their_commit)) < 0)
		goto done;

	error = merge_annotated_commits(out, &base, repo, ours, theirs, 0, opts);

done:
	git3_annotated_commit_free(ours);
	git3_annotated_commit_free(theirs);
	git3_annotated_commit_free(base);
	return error;
}

/* Merge setup / cleanup */

static int write_merge_head(
	git3_repository *repo,
	const git3_annotated_commit *heads[],
	size_t heads_len)
{
	git3_filebuf file = GIT3_FILEBUF_INIT;
	git3_str file_path = GIT3_STR_INIT;
	size_t i;
	int error = 0;

	GIT3_ASSERT_ARG(repo);
	GIT3_ASSERT_ARG(heads);

	if ((error = git3_str_joinpath(&file_path, repo->gitdir, GIT3_MERGE_HEAD_FILE)) < 0 ||
		(error = git3_filebuf_open(&file, file_path.ptr, GIT3_FILEBUF_CREATE_LEADING_DIRS, GIT3_MERGE_FILE_MODE)) < 0)
		goto cleanup;

	for (i = 0; i < heads_len; i++) {
		if ((error = git3_filebuf_printf(&file, "%s\n", heads[i]->id_str)) < 0)
			goto cleanup;
	}

	error = git3_filebuf_commit(&file);

cleanup:
	if (error < 0)
		git3_filebuf_cleanup(&file);

	git3_str_dispose(&file_path);

	return error;
}

static int write_merge_mode(git3_repository *repo)
{
	git3_filebuf file = GIT3_FILEBUF_INIT;
	git3_str file_path = GIT3_STR_INIT;
	int error = 0;

	GIT3_ASSERT_ARG(repo);

	if ((error = git3_str_joinpath(&file_path, repo->gitdir, GIT3_MERGE_MODE_FILE)) < 0 ||
		(error = git3_filebuf_open(&file, file_path.ptr, GIT3_FILEBUF_CREATE_LEADING_DIRS, GIT3_MERGE_FILE_MODE)) < 0)
		goto cleanup;

	if ((error = git3_filebuf_write(&file, "no-ff", 5)) < 0)
		goto cleanup;

	error = git3_filebuf_commit(&file);

cleanup:
	if (error < 0)
		git3_filebuf_cleanup(&file);

	git3_str_dispose(&file_path);

	return error;
}

struct merge_msg_entry {
	const git3_annotated_commit *merge_head;
	bool written;
};

static int msg_entry_is_branch(
	const struct merge_msg_entry *entry,
	git3_vector *entries)
{
	GIT3_UNUSED(entries);

	return (entry->written == 0 &&
		entry->merge_head->remote_url == NULL &&
		entry->merge_head->ref_name != NULL &&
		git3__strncmp(GIT3_REFS_HEADS_DIR, entry->merge_head->ref_name, strlen(GIT3_REFS_HEADS_DIR)) == 0);
}

static int msg_entry_is_tracking(
	const struct merge_msg_entry *entry,
	git3_vector *entries)
{
	GIT3_UNUSED(entries);

	return (entry->written == 0 &&
		entry->merge_head->remote_url == NULL &&
		entry->merge_head->ref_name != NULL &&
		git3__strncmp(GIT3_REFS_REMOTES_DIR, entry->merge_head->ref_name, strlen(GIT3_REFS_REMOTES_DIR)) == 0);
}

static int msg_entry_is_tag(
	const struct merge_msg_entry *entry,
	git3_vector *entries)
{
	GIT3_UNUSED(entries);

	return (entry->written == 0 &&
		entry->merge_head->remote_url == NULL &&
		entry->merge_head->ref_name != NULL &&
		git3__strncmp(GIT3_REFS_TAGS_DIR, entry->merge_head->ref_name, strlen(GIT3_REFS_TAGS_DIR)) == 0);
}

static int msg_entry_is_remote(
	const struct merge_msg_entry *entry,
	git3_vector *entries)
{
	if (entry->written == 0 &&
		entry->merge_head->remote_url != NULL &&
		entry->merge_head->ref_name != NULL &&
		git3__strncmp(GIT3_REFS_HEADS_DIR, entry->merge_head->ref_name, strlen(GIT3_REFS_HEADS_DIR)) == 0)
	{
		struct merge_msg_entry *existing;

		/* Match only branches from the same remote */
		if (entries->length == 0)
			return 1;

		existing = git3_vector_get(entries, 0);

		return (git3__strcmp(existing->merge_head->remote_url,
			entry->merge_head->remote_url) == 0);
	}

	return 0;
}

static int msg_entry_is_oid(
	const struct merge_msg_entry *merge_msg_entry)
{
	return (merge_msg_entry->written == 0 &&
		merge_msg_entry->merge_head->ref_name == NULL &&
		merge_msg_entry->merge_head->remote_url == NULL);
}

static int merge_msg_entry_written(
	const struct merge_msg_entry *merge_msg_entry)
{
	return (merge_msg_entry->written == 1);
}

static int merge_msg_entries(
	git3_vector *v,
	const struct merge_msg_entry *entries,
	size_t len,
	int (*match)(const struct merge_msg_entry *entry, git3_vector *entries))
{
	size_t i;
	int matches, total = 0;

	git3_vector_clear(v);

	for (i = 0; i < len; i++) {
		if ((matches = match(&entries[i], v)) < 0)
			return matches;
		else if (!matches)
			continue;

		git3_vector_insert(v, (struct merge_msg_entry *)&entries[i]);
		total++;
	}

	return total;
}

static int merge_msg_write_entries(
	git3_filebuf *file,
	git3_vector *entries,
	const char *item_name,
	const char *item_plural_name,
	size_t ref_name_skip,
	const char *source,
	char sep)
{
	struct merge_msg_entry *entry;
	size_t i;
	int error = 0;

	if (entries->length == 0)
		return 0;

	if (sep && (error = git3_filebuf_printf(file, "%c ", sep)) < 0)
		goto done;

	if ((error = git3_filebuf_printf(file, "%s ",
		(entries->length == 1) ? item_name : item_plural_name)) < 0)
		goto done;

	git3_vector_foreach(entries, i, entry) {
		if (i > 0 &&
			(error = git3_filebuf_printf(file, "%s", (i == entries->length - 1) ? " and " : ", ")) < 0)
			goto done;

		if ((error = git3_filebuf_printf(file, "'%s'", entry->merge_head->ref_name + ref_name_skip)) < 0)
			goto done;

		entry->written = 1;
	}

	if (source)
		error = git3_filebuf_printf(file, " of %s", source);

done:
	return error;
}

static int merge_msg_write_branches(
	git3_filebuf *file,
	git3_vector *entries,
	char sep)
{
	return merge_msg_write_entries(file, entries,
		"branch", "branches", strlen(GIT3_REFS_HEADS_DIR), NULL, sep);
}

static int merge_msg_write_tracking(
	git3_filebuf *file,
	git3_vector *entries,
	char sep)
{
	return merge_msg_write_entries(file, entries,
		"remote-tracking branch", "remote-tracking branches", 0, NULL, sep);
}

static int merge_msg_write_tags(
	git3_filebuf *file,
	git3_vector *entries,
	char sep)
{
	return merge_msg_write_entries(file, entries,
		"tag", "tags", strlen(GIT3_REFS_TAGS_DIR), NULL, sep);
}

static int merge_msg_write_remotes(
	git3_filebuf *file,
	git3_vector *entries,
	char sep)
{
	const char *source;

	if (entries->length == 0)
		return 0;

	source = ((struct merge_msg_entry *)entries->contents[0])->merge_head->remote_url;

	return merge_msg_write_entries(file, entries,
		"branch", "branches", strlen(GIT3_REFS_HEADS_DIR), source, sep);
}

static int write_merge_msg(
	git3_repository *repo,
	const git3_annotated_commit *heads[],
	size_t heads_len)
{
	git3_filebuf file = GIT3_FILEBUF_INIT;
	git3_str file_path = GIT3_STR_INIT;
	struct merge_msg_entry *entries;
	git3_vector matching = GIT3_VECTOR_INIT;
	size_t i;
	char sep = 0;
	int error = 0;

	GIT3_ASSERT_ARG(repo);
	GIT3_ASSERT_ARG(heads);

	entries = git3__calloc(heads_len, sizeof(struct merge_msg_entry));
	GIT3_ERROR_CHECK_ALLOC(entries);

	if (git3_vector_init(&matching, heads_len, NULL) < 0) {
		git3__free(entries);
		return -1;
	}

	for (i = 0; i < heads_len; i++)
		entries[i].merge_head = heads[i];

	if ((error = git3_str_joinpath(&file_path, repo->gitdir, GIT3_MERGE_MSG_FILE)) < 0 ||
		(error = git3_filebuf_open(&file, file_path.ptr, GIT3_FILEBUF_CREATE_LEADING_DIRS, GIT3_MERGE_FILE_MODE)) < 0 ||
		(error = git3_filebuf_write(&file, "Merge ", 6)) < 0)
		goto cleanup;

	/*
	 * This is to emulate the format of MERGE_MSG by core git.
	 *
	 * Core git will write all the commits specified by OID, in the order
	 * provided, until the first named branch or tag is reached, at which
	 * point all branches will be written in the order provided, then all
	 * tags, then all remote tracking branches and finally all commits that
	 * were specified by OID that were not already written.
	 *
	 * Yes.  Really.
	 */
	for (i = 0; i < heads_len; i++) {
		if (!msg_entry_is_oid(&entries[i]))
			break;

		if ((error = git3_filebuf_printf(&file,
			"%scommit '%s'", (i > 0) ? "; " : "",
			entries[i].merge_head->id_str)) < 0)
			goto cleanup;

		entries[i].written = 1;
	}

	if (i)
		sep = ';';

	if ((error = merge_msg_entries(&matching, entries, heads_len, msg_entry_is_branch)) < 0 ||
		(error = merge_msg_write_branches(&file, &matching, sep)) < 0)
		goto cleanup;

	if (matching.length)
		sep =',';

	if ((error = merge_msg_entries(&matching, entries, heads_len, msg_entry_is_tracking)) < 0 ||
		(error = merge_msg_write_tracking(&file, &matching, sep)) < 0)
		goto cleanup;

	if (matching.length)
		sep =',';

	if ((error = merge_msg_entries(&matching, entries, heads_len, msg_entry_is_tag)) < 0 ||
		(error = merge_msg_write_tags(&file, &matching, sep)) < 0)
		goto cleanup;

	if (matching.length)
		sep =',';

	/* We should never be called with multiple remote branches, but handle
	 * it in case we are... */
	while ((error = merge_msg_entries(&matching, entries, heads_len, msg_entry_is_remote)) > 0) {
		if ((error = merge_msg_write_remotes(&file, &matching, sep)) < 0)
			goto cleanup;

		if (matching.length)
			sep =',';
	}

	if (error < 0)
		goto cleanup;

	for (i = 0; i < heads_len; i++) {
		if (merge_msg_entry_written(&entries[i]))
			continue;

		if ((error = git3_filebuf_printf(&file, "; commit '%s'",
			entries[i].merge_head->id_str)) < 0)
			goto cleanup;
	}

	if ((error = git3_filebuf_printf(&file, "\n")) < 0 ||
		(error = git3_filebuf_commit(&file)) < 0)
		goto cleanup;

cleanup:
	if (error < 0)
		git3_filebuf_cleanup(&file);

	git3_str_dispose(&file_path);

	git3_vector_dispose(&matching);
	git3__free(entries);

	return error;
}

int git3_merge__setup(
	git3_repository *repo,
	const git3_annotated_commit *our_head,
	const git3_annotated_commit *heads[],
	size_t heads_len)
{
	int error = 0;

	GIT3_ASSERT_ARG(repo);
	GIT3_ASSERT_ARG(our_head);
	GIT3_ASSERT_ARG(heads);

	if ((error = git3_repository__set_orig_head(repo, git3_annotated_commit_id(our_head))) == 0 &&
		(error = write_merge_head(repo, heads, heads_len)) == 0 &&
		(error = write_merge_mode(repo)) == 0) {
		error = write_merge_msg(repo, heads, heads_len);
	}

	return error;
}

/* Merge branches */

static int merge_ancestor_head(
	git3_annotated_commit **ancestor_head,
	git3_repository *repo,
	const git3_annotated_commit *our_head,
	const git3_annotated_commit **their_heads,
	size_t their_heads_len)
{
	git3_oid *oids, ancestor_oid;
	size_t i, alloc_len;
	int error = 0;

	GIT3_ASSERT_ARG(repo);
	GIT3_ASSERT_ARG(our_head);
	GIT3_ASSERT_ARG(their_heads);

	GIT3_ERROR_CHECK_ALLOC_ADD(&alloc_len, their_heads_len, 1);
	oids = git3__calloc(alloc_len, sizeof(git3_oid));
	GIT3_ERROR_CHECK_ALLOC(oids);

	git3_oid_cpy(&oids[0], git3_commit_id(our_head->commit));

	for (i = 0; i < their_heads_len; i++)
		git3_oid_cpy(&oids[i + 1], git3_annotated_commit_id(their_heads[i]));

	if ((error = git3_merge_base_many(&ancestor_oid, repo, their_heads_len + 1, oids)) < 0)
		goto on_error;

	error = git3_annotated_commit_lookup(ancestor_head, repo, &ancestor_oid);

on_error:
	git3__free(oids);
	return error;
}

static const char *merge_their_label(const char *branchname)
{
	const char *slash;

	if ((slash = strrchr(branchname, '/')) == NULL)
		return branchname;

	if (*(slash+1) == '\0')
		return "theirs";

	return slash+1;
}

static int merge_normalize_checkout_opts(
	git3_checkout_options *out,
	git3_repository *repo,
	const git3_checkout_options *given_checkout_opts,
	unsigned int checkout_strategy,
	git3_annotated_commit *ancestor,
	const git3_annotated_commit *our_head,
	const git3_annotated_commit **their_heads,
	size_t their_heads_len)
{
	git3_checkout_options default_checkout_opts = GIT3_CHECKOUT_OPTIONS_INIT;
	int error = 0;

	GIT3_UNUSED(repo);

	if (given_checkout_opts != NULL)
		memcpy(out, given_checkout_opts, sizeof(git3_checkout_options));
	else
		memcpy(out, &default_checkout_opts, sizeof(git3_checkout_options));

	out->checkout_strategy = checkout_strategy;

	if (!out->ancestor_label) {
		if (ancestor && ancestor->type == GIT3_ANNOTATED_COMMIT_REAL)
			out->ancestor_label = git3_commit_summary(ancestor->commit);
		else if (ancestor)
			out->ancestor_label = "merged common ancestors";
		else
			out->ancestor_label = "empty base";
	}

	if (!out->our_label) {
		if (our_head && our_head->ref_name)
			out->our_label = our_head->ref_name;
		else
			out->our_label = "ours";
	}

	if (!out->their_label) {
		if (their_heads_len == 1 && their_heads[0]->ref_name)
			out->their_label = merge_their_label(their_heads[0]->ref_name);
		else if (their_heads_len == 1)
			out->their_label = their_heads[0]->id_str;
		else
			out->their_label = "theirs";
	}

	return error;
}

static int merge_check_index(size_t *conflicts, git3_repository *repo, git3_index *index_new, git3_vector *merged_paths)
{
	git3_tree *head_tree = NULL;
	git3_index *index_repo = NULL;
	git3_iterator *iter_repo = NULL, *iter_new = NULL;
	git3_iterator_options iter_opts = GIT3_ITERATOR_OPTIONS_INIT;
	git3_diff *staged_diff_list = NULL, *index_diff_list = NULL;
	git3_diff_delta *delta;
	git3_diff_options opts = GIT3_DIFF_OPTIONS_INIT;
	git3_vector staged_paths = GIT3_VECTOR_INIT;
	size_t i;
	int error = 0;

	GIT3_UNUSED(merged_paths);

	*conflicts = 0;

	/* No staged changes may exist unless the change staged is identical to
	 * the result of the merge.  This allows one to apply to merge manually,
	 * then run merge.  Any other staged change would be overwritten by
	 * a reset merge.
	 */
	if ((error = git3_repository_head_tree(&head_tree, repo)) < 0 ||
		(error = git3_repository_index(&index_repo, repo)) < 0 ||
		(error = git3_diff_tree_to_index(&staged_diff_list, repo, head_tree, index_repo, &opts)) < 0)
		goto done;

	if (staged_diff_list->deltas.length == 0)
		goto done;

	git3_vector_foreach(&staged_diff_list->deltas, i, delta) {
		if ((error = git3_vector_insert(&staged_paths, (char *)delta->new_file.path)) < 0)
			goto done;
	}

	iter_opts.flags = GIT3_ITERATOR_DONT_IGNORE_CASE;
	iter_opts.pathlist.strings = (char **)staged_paths.contents;
	iter_opts.pathlist.count = staged_paths.length;

	if ((error = git3_iterator_for_index(&iter_repo, repo, index_repo, &iter_opts)) < 0 ||
		(error = git3_iterator_for_index(&iter_new, repo, index_new, &iter_opts)) < 0 ||
		(error = git3_diff__from_iterators(&index_diff_list, repo, iter_repo, iter_new, &opts)) < 0)
		goto done;

	*conflicts = index_diff_list->deltas.length;

done:
	git3_tree_free(head_tree);
	git3_index_free(index_repo);
	git3_iterator_free(iter_repo);
	git3_iterator_free(iter_new);
	git3_diff_free(staged_diff_list);
	git3_diff_free(index_diff_list);
	git3_vector_dispose(&staged_paths);

	return error;
}

static int merge_check_workdir(size_t *conflicts, git3_repository *repo, git3_index *index_new, git3_vector *merged_paths)
{
	git3_diff *wd_diff_list = NULL;
	git3_diff_options opts = GIT3_DIFF_OPTIONS_INIT;
	int error = 0;

	GIT3_UNUSED(index_new);

	*conflicts = 0;

	/* We need to have merged at least 1 file for the possibility to exist to
	 * have conflicts with the workdir. Passing 0 as the pathspec count parameter
	 * will consider all files in the working directory, that is, we may detect
	 * a conflict if there were untracked files in the workdir prior to starting
	 * the merge. This typically happens when cherry-picking a commit whose
	 * changes have already been applied.
	 */
	if (merged_paths->length == 0)
		return 0;

	opts.flags |= GIT3_DIFF_INCLUDE_UNTRACKED;

	/* Workdir changes may exist iff they do not conflict with changes that
	 * will be applied by the merge (including conflicts).  Ensure that there
	 * are no changes in the workdir to these paths.
	 */
	opts.flags |= GIT3_DIFF_DISABLE_PATHSPEC_MATCH;
	opts.pathspec.count = merged_paths->length;
	opts.pathspec.strings = (char **)merged_paths->contents;
	opts.ignore_submodules = GIT3_SUBMODULE_IGNORE_ALL;

	if ((error = git3_diff_index_to_workdir(&wd_diff_list, repo, NULL, &opts)) < 0)
		goto done;

	*conflicts = wd_diff_list->deltas.length;

done:
	git3_diff_free(wd_diff_list);

	return error;
}

int git3_merge__check_result(git3_repository *repo, git3_index *index_new)
{
	git3_tree *head_tree = NULL;
	git3_iterator *iter_head = NULL, *iter_new = NULL;
	git3_iterator_options iter_opts = GIT3_ITERATOR_OPTIONS_INIT;
	git3_diff *merged_list = NULL;
	git3_diff_options opts = GIT3_DIFF_OPTIONS_INIT;
	git3_diff_delta *delta;
	git3_vector paths = GIT3_VECTOR_INIT;
	size_t i, index_conflicts = 0, wd_conflicts = 0, conflicts;
	const git3_index_entry *e;
	int error = 0;

	iter_opts.flags = GIT3_ITERATOR_DONT_IGNORE_CASE;

	if ((error = git3_repository_head_tree(&head_tree, repo)) < 0 ||
		(error = git3_iterator_for_tree(&iter_head, head_tree, &iter_opts)) < 0 ||
		(error = git3_iterator_for_index(&iter_new, repo, index_new, &iter_opts)) < 0 ||
		(error = git3_diff__from_iterators(&merged_list, repo, iter_head, iter_new, &opts)) < 0)
		goto done;

	git3_vector_foreach(&merged_list->deltas, i, delta) {
		if ((error = git3_vector_insert(&paths, (char *)delta->new_file.path)) < 0)
			goto done;
	}

	for (i = 0; i < git3_index_entrycount(index_new); i++) {
		e = git3_index_get_byindex(index_new, i);

		if (git3_index_entry_is_conflict(e) &&
			(git3_vector_last(&paths) == NULL ||
			strcmp(git3_vector_last(&paths), e->path) != 0)) {

			if ((error = git3_vector_insert(&paths, (char *)e->path)) < 0)
				goto done;
		}
	}

	/* Make sure the index and workdir state do not prevent merging */
	if ((error = merge_check_index(&index_conflicts, repo, index_new, &paths)) < 0 ||
		(error = merge_check_workdir(&wd_conflicts, repo, index_new, &paths)) < 0)
		goto done;

	if ((conflicts = index_conflicts + wd_conflicts) > 0) {
		git3_error_set(GIT3_ERROR_MERGE, "%" PRIuZ " uncommitted change%s would be overwritten by merge",
			conflicts, (conflicts != 1) ? "s" : "");
		error = GIT3_ECONFLICT;
	}

done:
	git3_vector_dispose(&paths);
	git3_tree_free(head_tree);
	git3_iterator_free(iter_head);
	git3_iterator_free(iter_new);
	git3_diff_free(merged_list);

	return error;
}

int git3_merge__append_conflicts_to_merge_msg(
	git3_repository *repo,
	git3_index *index)
{
	git3_filebuf file = GIT3_FILEBUF_INIT;
	git3_str file_path = GIT3_STR_INIT;
	const char *last = NULL;
	size_t i;
	int error;

	if (!git3_index_has_conflicts(index))
		return 0;

	if ((error = git3_str_joinpath(&file_path, repo->gitdir, GIT3_MERGE_MSG_FILE)) < 0 ||
		(error = git3_filebuf_open(&file, file_path.ptr, GIT3_FILEBUF_APPEND, GIT3_MERGE_FILE_MODE)) < 0)
		goto cleanup;

	git3_filebuf_printf(&file, "\n#Conflicts:\n");

	for (i = 0; i < git3_index_entrycount(index); i++) {
		const git3_index_entry *e = git3_index_get_byindex(index, i);

		if (!git3_index_entry_is_conflict(e))
			continue;

		if (last == NULL || strcmp(e->path, last) != 0)
			git3_filebuf_printf(&file, "#\t%s\n", e->path);

		last = e->path;
	}

	error = git3_filebuf_commit(&file);

cleanup:
	if (error < 0)
		git3_filebuf_cleanup(&file);

	git3_str_dispose(&file_path);

	return error;
}

static int merge_state_cleanup(git3_repository *repo)
{
	const char *state_files[] = {
		GIT3_MERGE_HEAD_FILE,
		GIT3_MERGE_MODE_FILE,
		GIT3_MERGE_MSG_FILE,
	};

	return git3_repository__cleanup_files(repo, state_files, ARRAY_SIZE(state_files));
}

static int merge_heads(
	git3_annotated_commit **ancestor_head_out,
	git3_annotated_commit **our_head_out,
	git3_repository *repo,
	git3_reference *our_ref,
	const git3_annotated_commit **their_heads,
	size_t their_heads_len)
{
	git3_annotated_commit *ancestor_head = NULL, *our_head = NULL;
	int error = 0;

	*ancestor_head_out = NULL;
	*our_head_out = NULL;

	if ((error = git3_annotated_commit_from_ref(&our_head, repo, our_ref)) < 0)
		goto done;

	if ((error = merge_ancestor_head(&ancestor_head, repo, our_head, their_heads, their_heads_len)) < 0) {
		if (error != GIT3_ENOTFOUND)
			goto done;

		git3_error_clear();
		error = 0;
	}

	*ancestor_head_out = ancestor_head;
	*our_head_out = our_head;

done:
	if (error < 0) {
		git3_annotated_commit_free(ancestor_head);
		git3_annotated_commit_free(our_head);
	}

	return error;
}

static int merge_preference(git3_merge_preference_t *out, git3_repository *repo)
{
	git3_config *config;
	const char *value;
	int bool_value, error = 0;

	*out = GIT3_MERGE_PREFERENCE_NONE;

	if ((error = git3_repository_config_snapshot(&config, repo)) < 0)
		goto done;

	if ((error = git3_config_get_string(&value, config, "merge.ff")) < 0) {
		if (error == GIT3_ENOTFOUND) {
			git3_error_clear();
			error = 0;
		}

		goto done;
	}

	if (git3_config_parse_bool(&bool_value, value) == 0) {
		if (!bool_value)
			*out |= GIT3_MERGE_PREFERENCE_NO_FASTFORWARD;
	} else {
		if (strcasecmp(value, "only") == 0)
			*out |= GIT3_MERGE_PREFERENCE_FASTFORWARD_ONLY;
	}

done:
	git3_config_free(config);
	return error;
}

int git3_merge_analysis_for_ref(
	git3_merge_analysis_t *analysis_out,
	git3_merge_preference_t *preference_out,
	git3_repository *repo,
	git3_reference *our_ref,
	const git3_annotated_commit **their_heads,
	size_t their_heads_len)
{
	git3_annotated_commit *ancestor_head = NULL, *our_head = NULL;
	int error = 0;
	bool unborn;

	GIT3_ASSERT_ARG(analysis_out);
	GIT3_ASSERT_ARG(preference_out);
	GIT3_ASSERT_ARG(repo);
	GIT3_ASSERT_ARG(their_heads && their_heads_len > 0);

	if (their_heads_len != 1) {
		git3_error_set(GIT3_ERROR_MERGE, "can only merge a single branch");
		error = -1;
		goto done;
	}

	*analysis_out = GIT3_MERGE_ANALYSIS_NONE;

	if ((error = merge_preference(preference_out, repo)) < 0)
		goto done;

	if ((error = git3_reference__is_unborn_head(&unborn, our_ref, repo)) < 0)
		goto done;

	if (unborn) {
		*analysis_out |= GIT3_MERGE_ANALYSIS_FASTFORWARD | GIT3_MERGE_ANALYSIS_UNBORN;
		error = 0;
		goto done;
	}

	if ((error = merge_heads(&ancestor_head, &our_head, repo, our_ref, their_heads, their_heads_len)) < 0)
		goto done;

	/* We're up-to-date if we're trying to merge our own common ancestor. */
	if (ancestor_head && git3_oid_equal(
		git3_annotated_commit_id(ancestor_head), git3_annotated_commit_id(their_heads[0])))
		*analysis_out |= GIT3_MERGE_ANALYSIS_UP_TO_DATE;

	/* We're fastforwardable if we're our own common ancestor. */
	else if (ancestor_head && git3_oid_equal(
		git3_annotated_commit_id(ancestor_head), git3_annotated_commit_id(our_head)))
		*analysis_out |= GIT3_MERGE_ANALYSIS_FASTFORWARD | GIT3_MERGE_ANALYSIS_NORMAL;

	/* Otherwise, just a normal merge is possible. */
	else
		*analysis_out |= GIT3_MERGE_ANALYSIS_NORMAL;

done:
	git3_annotated_commit_free(ancestor_head);
	git3_annotated_commit_free(our_head);
	return error;
}

int git3_merge_analysis(
	git3_merge_analysis_t *analysis_out,
	git3_merge_preference_t *preference_out,
	git3_repository *repo,
	const git3_annotated_commit **their_heads,
	size_t their_heads_len)
{
	git3_reference *head_ref = NULL;
	int error = 0;

	if ((error = git3_reference_lookup(&head_ref, repo, GIT3_HEAD_FILE)) < 0) {
		git3_error_set(GIT3_ERROR_MERGE, "failed to lookup HEAD reference");
		return error;
	}

	error = git3_merge_analysis_for_ref(analysis_out, preference_out, repo, head_ref, their_heads, their_heads_len);

	git3_reference_free(head_ref);

	return error;
}

int git3_merge(
	git3_repository *repo,
	const git3_annotated_commit **their_heads,
	size_t their_heads_len,
	const git3_merge_options *merge_opts,
	const git3_checkout_options *given_checkout_opts)
{
	git3_reference *our_ref = NULL;
	git3_checkout_options checkout_opts;
	git3_annotated_commit *our_head = NULL, *base = NULL;
	git3_index *repo_index = NULL, *index = NULL;
	git3_indexwriter indexwriter = GIT3_INDEXWRITER_INIT;
	unsigned int checkout_strategy;
	int error = 0;

	GIT3_ASSERT_ARG(repo);
	GIT3_ASSERT_ARG(their_heads && their_heads_len > 0);

	if (their_heads_len != 1) {
		git3_error_set(GIT3_ERROR_MERGE, "can only merge a single branch");
		return -1;
	}

	if ((error = git3_repository__ensure_not_bare(repo, "merge")) < 0)
		goto done;

	checkout_strategy = given_checkout_opts ?
		given_checkout_opts->checkout_strategy : 0;

	if ((error = git3_indexwriter_init_for_operation(&indexwriter, repo,
		&checkout_strategy)) < 0)
		goto done;

	if ((error = git3_repository_index(&repo_index, repo) < 0) ||
	    (error = git3_index_read(repo_index, 0) < 0))
		goto done;

	/* Write the merge setup files to the repository. */
	if ((error = git3_annotated_commit_from_head(&our_head, repo)) < 0 ||
		(error = git3_merge__setup(repo, our_head, their_heads,
			their_heads_len)) < 0)
		goto done;

	/* TODO: octopus */

	if ((error = merge_annotated_commits(&index, &base, repo, our_head,
			(git3_annotated_commit *)their_heads[0], 0, merge_opts)) < 0 ||
		(error = git3_merge__check_result(repo, index)) < 0 ||
		(error = git3_merge__append_conflicts_to_merge_msg(repo, index)) < 0)
		goto done;

	/* check out the merge results */

	if ((error = merge_normalize_checkout_opts(&checkout_opts, repo,
			given_checkout_opts, checkout_strategy,
			base, our_head, their_heads, their_heads_len)) < 0 ||
		(error = git3_checkout_index(repo, index, &checkout_opts)) < 0)
		goto done;

	error = git3_indexwriter_commit(&indexwriter);

done:
	if (error < 0)
		merge_state_cleanup(repo);

	git3_indexwriter_cleanup(&indexwriter);
	git3_index_free(index);
	git3_annotated_commit_free(our_head);
	git3_annotated_commit_free(base);
	git3_reference_free(our_ref);
	git3_index_free(repo_index);

	return error;
}

int git3_merge_options_init(git3_merge_options *opts, unsigned int version)
{
	GIT3_INIT_STRUCTURE_FROM_TEMPLATE(
		opts, version, git3_merge_options, GIT3_MERGE_OPTIONS_INIT);
	return 0;
}

#ifndef GIT3_DEPRECATE_HARD
int git3_merge_init_options(git3_merge_options *opts, unsigned int version)
{
	return git3_merge_options_init(opts, version);
}
#endif

int git3_merge_file_input_init(git3_merge_file_input *input, unsigned int version)
{
	GIT3_INIT_STRUCTURE_FROM_TEMPLATE(
		input, version, git3_merge_file_input, GIT3_MERGE_FILE_INPUT_INIT);
	return 0;
}

#ifndef GIT3_DEPRECATE_HARD
int git3_merge_file_init_input(git3_merge_file_input *input, unsigned int version)
{
	return git3_merge_file_input_init(input, version);
}
#endif

int git3_merge_file_options_init(
	git3_merge_file_options *opts, unsigned int version)
{
	GIT3_INIT_STRUCTURE_FROM_TEMPLATE(
		opts, version, git3_merge_file_options, GIT3_MERGE_FILE_OPTIONS_INIT);
	return 0;
}

#ifndef GIT3_DEPRECATE_HARD
int git3_merge_file_init_options(
	git3_merge_file_options *opts, unsigned int version)
{
	return git3_merge_file_options_init(opts, version);
}
#endif
