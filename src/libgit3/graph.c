/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "common.h"

#include "revwalk.h"
#include "merge.h"
#include "git3/graph.h"

static int interesting(git3_pqueue *list, git3_commit_list *roots)
{
	unsigned int i;

	for (i = 0; i < git3_pqueue_size(list); i++) {
		git3_commit_list_node *commit = git3_pqueue_get(list, i);
		if ((commit->flags & STALE) == 0)
			return 1;
	}

	while(roots) {
		if ((roots->item->flags & STALE) == 0)
			return 1;
		roots = roots->next;
	}

	return 0;
}

static int mark_parents(git3_revwalk *walk, git3_commit_list_node *one,
	git3_commit_list_node *two)
{
	unsigned int i;
	git3_commit_list *roots = NULL;
	git3_pqueue list;

	/* if the commit is repeated, we have a our merge base already */
	if (one == two) {
		one->flags |= PARENT1 | PARENT2 | RESULT;
		return 0;
	}

	if (git3_pqueue_init(&list, 0, 2, git3_commit_list_generation_cmp) < 0)
		return -1;

	if (git3_commit_list_parse(walk, one) < 0)
		goto on_error;
	one->flags |= PARENT1;
	if (git3_pqueue_insert(&list, one) < 0)
		goto on_error;

	if (git3_commit_list_parse(walk, two) < 0)
		goto on_error;
	two->flags |= PARENT2;
	if (git3_pqueue_insert(&list, two) < 0)
		goto on_error;

	/* as long as there are non-STALE commits */
	while (interesting(&list, roots)) {
		git3_commit_list_node *commit = git3_pqueue_pop(&list);
		unsigned int flags;

		if (commit == NULL)
			break;

		flags = commit->flags & (PARENT1 | PARENT2 | STALE);
		if (flags == (PARENT1 | PARENT2)) {
			if (!(commit->flags & RESULT))
				commit->flags |= RESULT;
			/* we mark the parents of a merge stale */
			flags |= STALE;
		}

		for (i = 0; i < commit->out_degree; i++) {
			git3_commit_list_node *p = commit->parents[i];
			if ((p->flags & flags) == flags)
				continue;

			if (git3_commit_list_parse(walk, p) < 0)
				goto on_error;

			p->flags |= flags;
			if (git3_pqueue_insert(&list, p) < 0)
				goto on_error;
		}

		/* Keep track of root commits, to make sure the path gets marked */
		if (commit->out_degree == 0) {
			if (git3_commit_list_insert(commit, &roots) == NULL)
				goto on_error;
		}
	}

	git3_commit_list_free(&roots);
	git3_pqueue_free(&list);
	return 0;

on_error:
	git3_commit_list_free(&roots);
	git3_pqueue_free(&list);
	return -1;
}


static int ahead_behind(git3_commit_list_node *one, git3_commit_list_node *two,
	size_t *ahead, size_t *behind)
{
	git3_commit_list_node *commit;
	git3_pqueue pq;
	int error = 0, i;
	*ahead = 0;
	*behind = 0;

	if (git3_pqueue_init(&pq, 0, 2, git3_commit_list_time_cmp) < 0)
		return -1;

	if ((error = git3_pqueue_insert(&pq, one)) < 0 ||
		(error = git3_pqueue_insert(&pq, two)) < 0)
		goto done;

	while ((commit = git3_pqueue_pop(&pq)) != NULL) {
		if (commit->flags & RESULT ||
			(commit->flags & (PARENT1 | PARENT2)) == (PARENT1 | PARENT2))
			continue;
		else if (commit->flags & PARENT1)
			(*ahead)++;
		else if (commit->flags & PARENT2)
			(*behind)++;

		for (i = 0; i < commit->out_degree; i++) {
			git3_commit_list_node *p = commit->parents[i];
			if ((error = git3_pqueue_insert(&pq, p)) < 0)
				goto done;
		}
		commit->flags |= RESULT;
	}

done:
	git3_pqueue_free(&pq);
	return error;
}

int git3_graph_ahead_behind(size_t *ahead, size_t *behind, git3_repository *repo,
	const git3_oid *local, const git3_oid *upstream)
{
	git3_revwalk *walk;
	git3_commit_list_node *commit_u, *commit_l;

	if (git3_revwalk_new(&walk, repo) < 0)
		return -1;

	commit_u = git3_revwalk__commit_lookup(walk, upstream);
	if (commit_u == NULL)
		goto on_error;

	commit_l = git3_revwalk__commit_lookup(walk, local);
	if (commit_l == NULL)
		goto on_error;

	if (mark_parents(walk, commit_l, commit_u) < 0)
		goto on_error;
	if (ahead_behind(commit_l, commit_u, ahead, behind) < 0)
		goto on_error;

	git3_revwalk_free(walk);

	return 0;

on_error:
	git3_revwalk_free(walk);
	return -1;
}

int git3_graph_descendant_of(git3_repository *repo, const git3_oid *commit, const git3_oid *ancestor)
{
	if (git3_oid_equal(commit, ancestor))
		return 0;

	return git3_graph_reachable_from_any(repo, ancestor, commit, 1);
}

int git3_graph_reachable_from_any(
		git3_repository *repo,
		const git3_oid *commit_id,
		const git3_oid descendant_array[],
		size_t length)
{
	git3_revwalk *walk = NULL;
	git3_vector list;
	git3_commit_list *result = NULL;
	git3_commit_list_node *commit;
	size_t i;
	uint32_t minimum_generation = 0xffffffff;
	int error = 0;

	if (!length)
		return 0;

	for (i = 0; i < length; ++i) {
		if (git3_oid_equal(commit_id, &descendant_array[i]))
			return 1;
	}

	if ((error = git3_vector_init(&list, length + 1, NULL)) < 0)
		return error;

	if ((error = git3_revwalk_new(&walk, repo)) < 0)
		goto done;

	for (i = 0; i < length; i++) {
		commit = git3_revwalk__commit_lookup(walk, &descendant_array[i]);
		if (commit == NULL) {
			error = -1;
			goto done;
		}

		git3_vector_insert(&list, commit);
		if (minimum_generation > commit->generation)
			minimum_generation = commit->generation;
	}

	commit = git3_revwalk__commit_lookup(walk, commit_id);
	if (commit == NULL) {
		error = -1;
		goto done;
	}

	if (minimum_generation > commit->generation)
		minimum_generation = commit->generation;

	if ((error = git3_merge__bases_many(&result, walk, commit, &list, minimum_generation)) < 0)
		goto done;

	if (result) {
		error = git3_oid_equal(commit_id, &result->item->oid);
	} else {
		/* No merge-base found, it's not a descendant */
		error = 0;
	}

done:
	git3_commit_list_free(&result);
	git3_vector_dispose(&list);
	git3_revwalk_free(walk);
	return error;
}
