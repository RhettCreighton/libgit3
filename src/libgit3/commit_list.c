/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "commit_list.h"

#include "revwalk.h"
#include "pool.h"
#include "odb.h"
#include "commit.h"

int git3_commit_list_generation_cmp(const void *a, const void *b)
{
	uint32_t generation_a = ((git3_commit_list_node *) a)->generation;
	uint32_t generation_b = ((git3_commit_list_node *) b)->generation;

	if (!generation_a || !generation_b) {
		/* Fall back to comparing by timestamps if at least one commit lacks a generation. */
		return git3_commit_list_time_cmp(a, b);
	}

	if (generation_a < generation_b)
		return 1;
	if (generation_a > generation_b)
		return -1;

	return 0;
}

int git3_commit_list_time_cmp(const void *a, const void *b)
{
	int64_t time_a = ((git3_commit_list_node *) a)->time;
	int64_t time_b = ((git3_commit_list_node *) b)->time;

	if (time_a < time_b)
		return 1;
	if (time_a > time_b)
		return -1;

	return 0;
}

git3_commit_list *git3_commit_list_create(git3_commit_list_node *item, git3_commit_list *next) {
	git3_commit_list *new_list = git3__malloc(sizeof(git3_commit_list));
	if (new_list != NULL) {
		new_list->item = item;
		new_list->next = next;
	}
	return new_list;
}

git3_commit_list *git3_commit_list_insert(git3_commit_list_node *item, git3_commit_list **list_p)
{
	git3_commit_list *new_list = git3_commit_list_create(item, *list_p);
	*list_p = new_list;
	return new_list;
}

git3_commit_list *git3_commit_list_insert_by_date(git3_commit_list_node *item, git3_commit_list **list_p)
{
	git3_commit_list **pp = list_p;
	git3_commit_list *p;

	while ((p = *pp) != NULL) {
		if (git3_commit_list_time_cmp(p->item, item) > 0)
			break;

		pp = &p->next;
	}

	return git3_commit_list_insert(item, pp);
}

git3_commit_list_node *git3_commit_list_alloc_node(git3_revwalk *walk)
{
	return (git3_commit_list_node *)git3_pool_mallocz(&walk->commit_pool, 1);
}

static git3_commit_list_node **alloc_parents(
	git3_revwalk *walk, git3_commit_list_node *commit, size_t n_parents)
{
	size_t bytes;

	if (n_parents <= PARENTS_PER_COMMIT)
		return (git3_commit_list_node **)((char *)commit + sizeof(git3_commit_list_node));

	if (git3__multiply_sizet_overflow(&bytes, n_parents, sizeof(git3_commit_list_node *)))
		return NULL;

	return (git3_commit_list_node **)git3_pool_malloc(&walk->commit_pool, bytes);
}


void git3_commit_list_free(git3_commit_list **list_p)
{
	git3_commit_list *list = *list_p;

	if (list == NULL)
		return;

	while (list) {
		git3_commit_list *temp = list;
		list = temp->next;
		git3__free(temp);
	}

	*list_p = NULL;
}

git3_commit_list_node *git3_commit_list_pop(git3_commit_list **stack)
{
	git3_commit_list *top = *stack;
	git3_commit_list_node *item = top ? top->item : NULL;

	if (top) {
		*stack = top->next;
		git3__free(top);
	}
	return item;
}

static int commit_quick_parse(
	git3_revwalk *walk,
	git3_commit_list_node *node,
	git3_odb_object *obj)
{
	git3_oid *parent_oid;
	git3_commit *commit;
	git3_commit__parse_options parse_opts = {
		walk->repo->oid_type,
		GIT3_COMMIT_PARSE_QUICK
	};
	size_t i;

	commit = git3__calloc(1, sizeof(*commit));
	GIT3_ERROR_CHECK_ALLOC(commit);
	commit->object.repo = walk->repo;

	if (git3_commit__parse_ext(commit, obj, &parse_opts) < 0) {
		git3__free(commit);
		return -1;
	}

	if (!git3__is_uint16(git3_array_size(commit->parent_ids))) {
		git3__free(commit);
		git3_error_set(GIT3_ERROR_INVALID, "commit has more than 2^16 parents");
		return -1;
	}

	node->generation = 0;
	node->time = commit->committer->when.time;
	node->out_degree = (uint16_t) git3_array_size(commit->parent_ids);
	node->parents = alloc_parents(walk, node, node->out_degree);
	GIT3_ERROR_CHECK_ALLOC(node->parents);

	git3_array_foreach(commit->parent_ids, i, parent_oid) {
		node->parents[i] = git3_revwalk__commit_lookup(walk, parent_oid);
	}

	git3_commit__free(commit);

	node->parsed = 1;

	return 0;
}

int git3_commit_list_parse(git3_revwalk *walk, git3_commit_list_node *commit)
{
	git3_odb_object *obj;
	git3_commit_graph_file *cgraph_file = NULL;
	int error;

	if (commit->parsed)
		return 0;

	/* Let's try to use the commit graph first. */
	git3_odb__get_commit_graph_file(&cgraph_file, walk->odb);
	if (cgraph_file) {
		git3_commit_graph_entry e;

		error = git3_commit_graph_entry_find(&e, cgraph_file,
			&commit->oid, git3_oid_size(walk->repo->oid_type));

		if (error == 0 && git3__is_uint16(e.parent_count)) {
			size_t i;
			commit->generation = (uint32_t)e.generation;
			commit->time = e.commit_time;
			commit->out_degree = (uint16_t)e.parent_count;
			commit->parents = alloc_parents(walk, commit, commit->out_degree);
			GIT3_ERROR_CHECK_ALLOC(commit->parents);

			for (i = 0; i < commit->out_degree; ++i) {
				git3_commit_graph_entry parent;
				error = git3_commit_graph_entry_parent(&parent, cgraph_file, &e, i);
				if (error < 0)
					return error;
				commit->parents[i] = git3_revwalk__commit_lookup(walk, &parent.sha1);
			}
			commit->parsed = 1;
			return 0;
		}
	}

	if ((error = git3_odb_read(&obj, walk->odb, &commit->oid)) < 0)
		return error;

	if (obj->cached.type != GIT3_OBJECT_COMMIT) {
		git3_error_set(GIT3_ERROR_INVALID, "object is no commit object");
		error = -1;
	} else
		error = commit_quick_parse(walk, commit, obj);

	git3_odb_object_free(obj);
	return error;
}

