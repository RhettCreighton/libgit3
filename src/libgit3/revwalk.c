/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "revwalk.h"

#include "commit.h"
#include "odb.h"
#include "pool.h"

#include "git3/revparse.h"
#include "merge.h"
#include "vector.h"
#include "hashmap_oid.h"

GIT3_HASHMAP_OID_FUNCTIONS(git3_revwalk_oidmap, GIT3_HASHMAP_INLINE, git3_commit_list_node *);

static int get_revision(git3_commit_list_node **out, git3_revwalk *walk, git3_commit_list **list);

git3_commit_list_node *git3_revwalk__commit_lookup(
	git3_revwalk *walk, const git3_oid *oid)
{
	git3_commit_list_node *commit;

	/* lookup and reserve space if not already present */
	if (git3_revwalk_oidmap_get(&commit, &walk->commits, oid) == 0)
		return commit;

	commit = git3_commit_list_alloc_node(walk);
	if (commit == NULL)
		return NULL;

	git3_oid_cpy(&commit->oid, oid);

	if (git3_revwalk_oidmap_put(&walk->commits, &commit->oid, commit) < 0)
		return NULL;

	return commit;
}

int git3_revwalk__push_commit(git3_revwalk *walk, const git3_oid *oid, const git3_revwalk__push_options *opts)
{
	git3_oid commit_id;
	int error;
	git3_object *obj, *oobj;
	git3_commit_list_node *commit;
	git3_commit_list *list;

	if ((error = git3_object_lookup(&oobj, walk->repo, oid, GIT3_OBJECT_ANY)) < 0)
		return error;

	error = git3_object_peel(&obj, oobj, GIT3_OBJECT_COMMIT);
	git3_object_free(oobj);

	if (error == GIT3_ENOTFOUND || error == GIT3_EINVALIDSPEC || error == GIT3_EPEEL) {
		/* If this comes from e.g. push_glob("tags"), ignore this */
		if (opts->from_glob)
			return 0;

		git3_error_set(GIT3_ERROR_INVALID, "object is not a committish");
		return error;
	}
	if (error < 0)
		return error;

	git3_oid_cpy(&commit_id, git3_object_id(obj));
	git3_object_free(obj);

	commit = git3_revwalk__commit_lookup(walk, &commit_id);
	if (commit == NULL)
		return -1; /* error already reported by failed lookup */

	/* A previous hide already told us we don't want this commit  */
	if (commit->uninteresting)
		return 0;

	if (opts->uninteresting) {
		walk->limited = 1;
		walk->did_hide = 1;
	} else {
		walk->did_push = 1;
	}

	commit->uninteresting = opts->uninteresting;
	list = walk->user_input;

	/* To insert by date, we need to parse so we know the date. */
	if (opts->insert_by_date && ((error = git3_commit_list_parse(walk, commit)) < 0))
		return error;

	if ((opts->insert_by_date == 0 ||
	    git3_commit_list_insert_by_date(commit, &list) == NULL) &&
	    git3_commit_list_insert(commit, &list) == NULL) {
		git3_error_set_oom();
		return -1;
	}

	walk->user_input = list;

	return 0;
}

int git3_revwalk_push(git3_revwalk *walk, const git3_oid *oid)
{
	git3_revwalk__push_options opts = GIT3_REVWALK__PUSH_OPTIONS_INIT;

	GIT3_ASSERT_ARG(walk);
	GIT3_ASSERT_ARG(oid);

	return git3_revwalk__push_commit(walk, oid, &opts);
}


int git3_revwalk_hide(git3_revwalk *walk, const git3_oid *oid)
{
	git3_revwalk__push_options opts = GIT3_REVWALK__PUSH_OPTIONS_INIT;

	GIT3_ASSERT_ARG(walk);
	GIT3_ASSERT_ARG(oid);

	opts.uninteresting = 1;
	return git3_revwalk__push_commit(walk, oid, &opts);
}

int git3_revwalk__push_ref(git3_revwalk *walk, const char *refname, const git3_revwalk__push_options *opts)
{
	git3_oid oid;

	int error = git3_reference_name_to_id(&oid, walk->repo, refname);
	if (opts->from_glob && (error == GIT3_ENOTFOUND || error == GIT3_EINVALIDSPEC || error == GIT3_EPEEL)) {
		return 0;
	} else if (error < 0) {
		return -1;
	}

	return git3_revwalk__push_commit(walk, &oid, opts);
}

int git3_revwalk__push_glob(git3_revwalk *walk, const char *glob, const git3_revwalk__push_options *given_opts)
{
	git3_revwalk__push_options opts = GIT3_REVWALK__PUSH_OPTIONS_INIT;
	int error = 0;
	git3_str buf = GIT3_STR_INIT;
	git3_reference *ref;
	git3_reference_iterator *iter;
	size_t wildcard;

	GIT3_ASSERT_ARG(walk);
	GIT3_ASSERT_ARG(glob);

	if (given_opts)
		memcpy(&opts, given_opts, sizeof(opts));

	/* refs/ is implied if not given in the glob */
	if (git3__prefixcmp(glob, GIT3_REFS_DIR) != 0)
		git3_str_joinpath(&buf, GIT3_REFS_DIR, glob);
	else
		git3_str_puts(&buf, glob);
	GIT3_ERROR_CHECK_ALLOC_STR(&buf);

	/* If no '?', '*' or '[' exist, we append '/ *' to the glob */
	wildcard = strcspn(glob, "?*[");
	if (!glob[wildcard])
		git3_str_put(&buf, "/*", 2);

	if ((error = git3_reference_iterator_glob_new(&iter, walk->repo, buf.ptr)) < 0)
		goto out;

	opts.from_glob = true;
	while ((error = git3_reference_next(&ref, iter)) == 0) {
		error = git3_revwalk__push_ref(walk, git3_reference_name(ref), &opts);
		git3_reference_free(ref);
		if (error < 0)
			break;
	}
	git3_reference_iterator_free(iter);

	if (error == GIT3_ITEROVER)
		error = 0;
out:
	git3_str_dispose(&buf);
	return error;
}

int git3_revwalk_push_glob(git3_revwalk *walk, const char *glob)
{
	git3_revwalk__push_options opts = GIT3_REVWALK__PUSH_OPTIONS_INIT;

	GIT3_ASSERT_ARG(walk);
	GIT3_ASSERT_ARG(glob);

	return git3_revwalk__push_glob(walk, glob, &opts);
}

int git3_revwalk_hide_glob(git3_revwalk *walk, const char *glob)
{
	git3_revwalk__push_options opts = GIT3_REVWALK__PUSH_OPTIONS_INIT;

	GIT3_ASSERT_ARG(walk);
	GIT3_ASSERT_ARG(glob);

	opts.uninteresting = 1;
	return git3_revwalk__push_glob(walk, glob, &opts);
}

int git3_revwalk_push_head(git3_revwalk *walk)
{
	git3_revwalk__push_options opts = GIT3_REVWALK__PUSH_OPTIONS_INIT;

	GIT3_ASSERT_ARG(walk);

	return git3_revwalk__push_ref(walk, GIT3_HEAD_FILE, &opts);
}

int git3_revwalk_hide_head(git3_revwalk *walk)
{
	git3_revwalk__push_options opts = GIT3_REVWALK__PUSH_OPTIONS_INIT;

	GIT3_ASSERT_ARG(walk);

	opts.uninteresting = 1;
	return git3_revwalk__push_ref(walk, GIT3_HEAD_FILE, &opts);
}

int git3_revwalk_push_ref(git3_revwalk *walk, const char *refname)
{
	git3_revwalk__push_options opts = GIT3_REVWALK__PUSH_OPTIONS_INIT;

	GIT3_ASSERT_ARG(walk);
	GIT3_ASSERT_ARG(refname);

	return git3_revwalk__push_ref(walk, refname, &opts);
}

int git3_revwalk_push_range(git3_revwalk *walk, const char *range)
{
	git3_revwalk__push_options opts = GIT3_REVWALK__PUSH_OPTIONS_INIT;
	git3_revspec revspec;
	int error = 0;

	if ((error = git3_revparse(&revspec, walk->repo, range)))
		return error;

	if (!revspec.to) {
		git3_error_set(GIT3_ERROR_INVALID, "invalid revspec: range not provided");
		error = GIT3_EINVALIDSPEC;
		goto out;
	}

	if (revspec.flags & GIT3_REVSPEC_MERGE_BASE) {
		/* TODO: support "<commit>...<commit>" */
		git3_error_set(GIT3_ERROR_INVALID, "symmetric differences not implemented in revwalk");
		error = GIT3_EINVALIDSPEC;
		goto out;
	}

	opts.uninteresting = 1;
	if ((error = git3_revwalk__push_commit(walk, git3_object_id(revspec.from), &opts)))
		goto out;

	opts.uninteresting = 0;
	error = git3_revwalk__push_commit(walk, git3_object_id(revspec.to), &opts);

out:
	git3_object_free(revspec.from);
	git3_object_free(revspec.to);
	return error;
}

int git3_revwalk_hide_ref(git3_revwalk *walk, const char *refname)
{
	git3_revwalk__push_options opts = GIT3_REVWALK__PUSH_OPTIONS_INIT;

	GIT3_ASSERT_ARG(walk);
	GIT3_ASSERT_ARG(refname);

	opts.uninteresting = 1;
	return git3_revwalk__push_ref(walk, refname, &opts);
}

static int revwalk_enqueue_timesort(git3_revwalk *walk, git3_commit_list_node *commit)
{
	return git3_pqueue_insert(&walk->iterator_time, commit);
}

static int revwalk_enqueue_unsorted(git3_revwalk *walk, git3_commit_list_node *commit)
{
	return git3_commit_list_insert(commit, &walk->iterator_rand) ? 0 : -1;
}

static int revwalk_next_timesort(git3_commit_list_node **object_out, git3_revwalk *walk)
{
	git3_commit_list_node *next;

	while ((next = git3_pqueue_pop(&walk->iterator_time)) != NULL) {
		/* Some commits might become uninteresting after being added to the list */
		if (!next->uninteresting) {
			*object_out = next;
			return 0;
		}
	}

	git3_error_clear();
	return GIT3_ITEROVER;
}

static int revwalk_next_unsorted(git3_commit_list_node **object_out, git3_revwalk *walk)
{
	int error;
	git3_commit_list_node *next;

	while (!(error = get_revision(&next, walk, &walk->iterator_rand))) {
		/* Some commits might become uninteresting after being added to the list */
		if (!next->uninteresting) {
			*object_out = next;
			return 0;
		}
	}

	return error;
}

static int revwalk_next_toposort(git3_commit_list_node **object_out, git3_revwalk *walk)
{
	int error;
	git3_commit_list_node *next;

	while (!(error = get_revision(&next, walk, &walk->iterator_topo))) {
		/* Some commits might become uninteresting after being added to the list */
		if (!next->uninteresting) {
			*object_out = next;
			return 0;
		}
	}

	return error;
}

static int revwalk_next_reverse(git3_commit_list_node **object_out, git3_revwalk *walk)
{
	*object_out = git3_commit_list_pop(&walk->iterator_reverse);
	return *object_out ? 0 : GIT3_ITEROVER;
}

static void mark_parents_uninteresting(git3_commit_list_node *commit)
{
	unsigned short i;
	git3_commit_list *parents = NULL;

	for (i = 0; i < commit->out_degree; i++)
		git3_commit_list_insert(commit->parents[i], &parents);


	while (parents) {
		commit = git3_commit_list_pop(&parents);

		while (commit) {
			if (commit->uninteresting)
				break;

			commit->uninteresting = 1;
			/*
			 * If we've reached this commit some other way
			 * already, we need to mark its parents uninteresting
			 * as well.
			 */
			if (!commit->parents)
				break;

			for (i = 0; i < commit->out_degree; i++)
				git3_commit_list_insert(commit->parents[i], &parents);
			commit = commit->parents[0];
		}
	}
}

static int add_parents_to_list(git3_revwalk *walk, git3_commit_list_node *commit, git3_commit_list **list)
{
	unsigned short i;
	int error;

	if (commit->added)
		return 0;

	commit->added = 1;

	/*
	 * Go full on in the uninteresting case as we want to include
	 * as many of these as we can.
	 *
	 * Usually we haven't parsed the parent of a parent, but if we
	 * have it we reached it via other means so we want to mark
	 * its parents recursively too.
	 */
	if (commit->uninteresting) {
		for (i = 0; i < commit->out_degree; i++) {
			git3_commit_list_node *p = commit->parents[i];
			p->uninteresting = 1;

			/* git does it gently here, but we don't like missing objects */
			if ((error = git3_commit_list_parse(walk, p)) < 0)
				return error;

			if (p->parents)
				mark_parents_uninteresting(p);

			p->seen = 1;
			git3_commit_list_insert_by_date(p, list);
		}

		return 0;
	}

	/*
	 * Now on to what we do if the commit is indeed
	 * interesting. Here we do want things like first-parent take
	 * effect as this is what we'll be showing.
	 */
	for (i = 0; i < commit->out_degree; i++) {
		git3_commit_list_node *p = commit->parents[i];

		if ((error = git3_commit_list_parse(walk, p)) < 0)
			return error;

		if (walk->hide_cb && walk->hide_cb(&p->oid, walk->hide_cb_payload))
			continue;

		if (!p->seen) {
			p->seen = 1;
			git3_commit_list_insert_by_date(p, list);
		}

		if (walk->first_parent)
			break;
	}
	return 0;
}

/* How many uninteresting commits we want to look at after we run out of interesting ones */
#define SLOP 5

static int still_interesting(git3_commit_list *list, int64_t time, int slop)
{
	/* The empty list is pretty boring */
	if (!list)
		return 0;

	/*
	 * If the destination list has commits with an earlier date than our
	 * source, we want to reset the slop counter as we're not done.
	 */
	if (time <= list->item->time)
		return SLOP;

	for (; list; list = list->next) {
		/*
		 * If the destination list still contains interesting commits we
		 * want to continue looking.
		 */
		if (!list->item->uninteresting || list->item->time > time)
			return SLOP;
	}

	/* Everything's uninteresting, reduce the count */
	return slop - 1;
}

static int limit_list(git3_commit_list **out, git3_revwalk *walk, git3_commit_list *commits)
{
	int error, slop = SLOP;
	int64_t time = INT64_MAX;
	git3_commit_list *list = commits;
	git3_commit_list *newlist = NULL;
	git3_commit_list **p = &newlist;

	while (list) {
		git3_commit_list_node *commit = git3_commit_list_pop(&list);

		if ((error = add_parents_to_list(walk, commit, &list)) < 0)
			return error;

		if (commit->uninteresting) {
			mark_parents_uninteresting(commit);

			slop = still_interesting(list, time, slop);
			if (slop)
				continue;

			break;
		}

		if (walk->hide_cb && walk->hide_cb(&commit->oid, walk->hide_cb_payload))
			continue;

		time = commit->time;
		p = &git3_commit_list_insert(commit, p)->next;
	}

	git3_commit_list_free(&list);
	*out = newlist;
	return 0;
}

static int get_revision(git3_commit_list_node **out, git3_revwalk *walk, git3_commit_list **list)
{
	int error;
	git3_commit_list_node *commit;

	commit = git3_commit_list_pop(list);
	if (!commit) {
		git3_error_clear();
		return GIT3_ITEROVER;
	}

	/*
	 * If we did not run limit_list and we must add parents to the
	 * list ourselves.
	 */
	if (!walk->limited) {
		if ((error = add_parents_to_list(walk, commit, list)) < 0)
			return error;
	}

	*out = commit;
	return 0;
}

static int sort_in_topological_order(git3_commit_list **out, git3_revwalk *walk, git3_commit_list *list)
{
	git3_commit_list *ll = NULL, *newlist, **pptr;
	git3_commit_list_node *next;
	git3_pqueue queue;
	git3_vector_cmp queue_cmp = NULL;
	unsigned short i;
	int error;

	if (walk->sorting & GIT3_SORT_TIME)
		queue_cmp = git3_commit_list_time_cmp;

	if ((error = git3_pqueue_init(&queue, 0, 8, queue_cmp)))
		return error;

	/*
	 * Start by resetting the in-degree to 1 for the commits in
	 * our list. We want to go through this list again, so we
	 * store it in the commit list as we extract it from the lower
	 * machinery.
	 */
	for (ll = list; ll; ll = ll->next) {
		ll->item->in_degree = 1;
	}

	/*
	 * Count up how many children each commit has. We limit
	 * ourselves to those commits in the original list (in-degree
	 * of 1) avoiding setting it for any parent that was hidden.
	 */
	for(ll = list; ll; ll = ll->next) {
		for (i = 0; i < ll->item->out_degree; ++i) {
			git3_commit_list_node *parent = ll->item->parents[i];
			if (parent->in_degree)
				parent->in_degree++;
		}
	}

	/*
	 * Now we find the tips i.e. those not reachable from any other node
	 * i.e. those which still have an in-degree of 1.
	 */
	for(ll = list; ll; ll = ll->next) {
		if (ll->item->in_degree == 1) {
			if ((error = git3_pqueue_insert(&queue, ll->item)))
				goto cleanup;
		}
	}

	/*
	 * We need to output the tips in the order that they came out of the
	 * traversal, so if we're not doing time-sorting, we need to reverse the
	 * pqueue in order to get them to come out as we inserted them.
	 */
	if ((walk->sorting & GIT3_SORT_TIME) == 0)
		git3_pqueue_reverse(&queue);


	pptr = &newlist;
	newlist = NULL;
	while ((next = git3_pqueue_pop(&queue)) != NULL) {
		for (i = 0; i < next->out_degree; ++i) {
			git3_commit_list_node *parent = next->parents[i];
			if (parent->in_degree == 0)
				continue;

			if (--parent->in_degree == 1) {
				if ((error = git3_pqueue_insert(&queue, parent)))
					goto cleanup;
			}
		}

		/* All the children of 'item' have been emitted (since we got to it via the priority queue) */
		next->in_degree = 0;

		pptr = &git3_commit_list_insert(next, pptr)->next;
	}

	*out = newlist;
	error = 0;

cleanup:
	git3_pqueue_free(&queue);
	return error;
}

static int prepare_walk(git3_revwalk *walk)
{
	int error = 0;
	git3_commit_list *list, *commits = NULL, *commits_last = NULL;
	git3_commit_list_node *next;

	/* If there were no pushes, we know that the walk is already over */
	if (!walk->did_push) {
		git3_error_clear();
		return GIT3_ITEROVER;
	}

	/*
	 * This is a bit convoluted, but necessary to maintain the order of
	 * the commits. This is especially important in situations where
	 * git3_revwalk__push_glob is called with a git3_revwalk__push_options
	 * setting insert_by_date = 1, which is critical for fetch negotiation.
	 */
	for (list = walk->user_input; list; list = list->next) {
		git3_commit_list_node *commit = list->item;
		if ((error = git3_commit_list_parse(walk, commit)) < 0)
			return error;

		if (commit->uninteresting)
			mark_parents_uninteresting(commit);

		if (!commit->seen) {
			git3_commit_list *new_list = NULL;
			if ((new_list = git3_commit_list_create(commit, NULL)) == NULL) {
				git3_error_set_oom();
				return -1;
			}

			commit->seen = 1;
			if (commits_last == NULL)
				commits = new_list;
			else
				commits_last->next = new_list;

			commits_last = new_list;
		}
	}

	if (walk->limited && (error = limit_list(&commits, walk, commits)) < 0)
		return error;

	if (walk->sorting & GIT3_SORT_TOPOLOGICAL) {
		error = sort_in_topological_order(&walk->iterator_topo, walk, commits);
		git3_commit_list_free(&commits);

		if (error < 0)
			return error;

		walk->get_next = &revwalk_next_toposort;
	} else if (walk->sorting & GIT3_SORT_TIME) {
		for (list = commits; list && !error; list = list->next)
			error = walk->enqueue(walk, list->item);

		git3_commit_list_free(&commits);

		if (error < 0)
			return error;
	} else {
		walk->iterator_rand = commits;
		walk->get_next = revwalk_next_unsorted;
	}

	if (walk->sorting & GIT3_SORT_REVERSE) {

		while ((error = walk->get_next(&next, walk)) == 0)
			if (git3_commit_list_insert(next, &walk->iterator_reverse) == NULL)
				return -1;

		if (error != GIT3_ITEROVER)
			return error;

		walk->get_next = &revwalk_next_reverse;
	}

	walk->walking = 1;
	return 0;
}


int git3_revwalk_new(git3_revwalk **revwalk_out, git3_repository *repo)
{
	git3_revwalk *walk = git3__calloc(1, sizeof(git3_revwalk));
	GIT3_ERROR_CHECK_ALLOC(walk);

	if (git3_pqueue_init(&walk->iterator_time, 0, 8, git3_commit_list_time_cmp) < 0 ||
	    git3_pool_init(&walk->commit_pool, COMMIT_ALLOC) < 0)
		return -1;

	walk->get_next = &revwalk_next_unsorted;
	walk->enqueue = &revwalk_enqueue_unsorted;

	walk->repo = repo;

	if (git3_repository_odb(&walk->odb, repo) < 0) {
		git3_revwalk_free(walk);
		return -1;
	}

	*revwalk_out = walk;
	return 0;
}

void git3_revwalk_free(git3_revwalk *walk)
{
	if (walk == NULL)
		return;

	git3_revwalk_reset(walk);
	git3_odb_free(walk->odb);

	git3_revwalk_oidmap_dispose(&walk->commits);
	git3_pool_clear(&walk->commit_pool);
	git3_pqueue_free(&walk->iterator_time);
	git3__free(walk);
}

git3_repository *git3_revwalk_repository(git3_revwalk *walk)
{
	GIT3_ASSERT_ARG_WITH_RETVAL(walk, NULL);

	return walk->repo;
}

int git3_revwalk_sorting(git3_revwalk *walk, unsigned int sort_mode)
{
	GIT3_ASSERT_ARG(walk);

	if (walk->walking)
		git3_revwalk_reset(walk);

	walk->sorting = sort_mode;

	if (walk->sorting & GIT3_SORT_TIME) {
		walk->get_next = &revwalk_next_timesort;
		walk->enqueue = &revwalk_enqueue_timesort;
	} else {
		walk->get_next = &revwalk_next_unsorted;
		walk->enqueue = &revwalk_enqueue_unsorted;
	}

	if (walk->sorting != GIT3_SORT_NONE)
		walk->limited = 1;

	return 0;
}

int git3_revwalk_simplify_first_parent(git3_revwalk *walk)
{
	walk->first_parent = 1;
	return 0;
}

int git3_revwalk_next(git3_oid *oid, git3_revwalk *walk)
{
	int error;
	git3_commit_list_node *next;

	GIT3_ASSERT_ARG(walk);
	GIT3_ASSERT_ARG(oid);

	if (!walk->walking) {
		if ((error = prepare_walk(walk)) < 0)
			return error;
	}

	error = walk->get_next(&next, walk);

	if (error == GIT3_ITEROVER) {
		git3_revwalk_reset(walk);
		git3_error_clear();
		return GIT3_ITEROVER;
	}

	if (!error)
		git3_oid_cpy(oid, &next->oid);

	return error;
}

int git3_revwalk_reset(git3_revwalk *walk)
{
	git3_commit_list_node *commit;
	git3_hashmap_iter_t iter = GIT3_HASHMAP_ITER_INIT;

	GIT3_ASSERT_ARG(walk);

	while (git3_revwalk_oidmap_iterate(&iter, NULL, &commit, &walk->commits) == 0) {
		commit->seen = 0;
		commit->in_degree = 0;
		commit->topo_delay = 0;
		commit->uninteresting = 0;
		commit->added = 0;
		commit->flags = 0;
	}

	git3_pqueue_clear(&walk->iterator_time);
	git3_commit_list_free(&walk->iterator_topo);
	git3_commit_list_free(&walk->iterator_rand);
	git3_commit_list_free(&walk->iterator_reverse);
	git3_commit_list_free(&walk->user_input);
	walk->first_parent = 0;
	walk->walking = 0;
	walk->limited = 0;
	walk->did_push = walk->did_hide = 0;
	walk->sorting = GIT3_SORT_NONE;

	return 0;
}

int git3_revwalk_add_hide_cb(
	git3_revwalk *walk,
	git3_revwalk_hide_cb hide_cb,
	void *payload)
{
	GIT3_ASSERT_ARG(walk);

	if (walk->walking)
		git3_revwalk_reset(walk);

	walk->hide_cb = hide_cb;
	walk->hide_cb_payload = payload;

	if (hide_cb)
		walk->limited = 1;

	return 0;
}

