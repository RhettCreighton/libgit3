/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "common.h"

#include "git3/describe.h"
#include "git3/diff.h"
#include "git3/status.h"

#include "buf.h"
#include "commit.h"
#include "commit_list.h"
#include "refs.h"
#include "repository.h"
#include "revwalk.h"
#include "strarray.h"
#include "tag.h"
#include "vector.h"
#include "wildmatch.h"
#include "hashmap_oid.h"

/* Ported from https://github.com/git/git/blob/89dde7882f71f846ccd0359756d27bebc31108de/builtin/describe.c */

struct commit_name {
	git3_tag *tag;
	unsigned prio:2; /* annotated tag = 2, tag = 1, head = 0 */
	unsigned name_checked:1;
	git3_oid sha1;
	char *path;

	/* The original key for the hashmap */
	git3_oid peeled;
};

GIT3_HASHMAP_OID_SETUP(git3_describe_oidmap, struct commit_name *);

static struct commit_name *find_commit_name(
	git3_describe_oidmap *names,
	const git3_oid *peeled)
{
	struct commit_name *result;

	if (git3_describe_oidmap_get(&result, names, peeled) == 0)
		return result;

	return NULL;
}

static int replace_name(
	git3_tag **tag,
	git3_repository *repo,
	struct commit_name *e,
	unsigned int prio,
	const git3_oid *sha1)
{
	git3_time_t e_time = 0, t_time = 0;

	if (!e || e->prio < prio)
		return 1;

	if (e->prio == 2 && prio == 2) {
		/* Multiple annotated tags point to the same commit.
		 * Select one to keep based upon their tagger date.
		 */
		git3_tag *t = NULL;

		if (!e->tag) {
			if (git3_tag_lookup(&t, repo, &e->sha1) < 0)
				return 1;
			e->tag = t;
		}

		if (git3_tag_lookup(&t, repo, sha1) < 0)
			return 0;

		*tag = t;

		if (e->tag->tagger)
			e_time = e->tag->tagger->when.time;

		if (t->tagger)
			t_time = t->tagger->when.time;

		if (e_time < t_time)
			return 1;
	}

	return 0;
}

static int add_to_known_names(
	git3_repository *repo,
	git3_describe_oidmap *names,
	const char *path,
	const git3_oid *peeled,
	unsigned int prio,
	const git3_oid *sha1)
{
	struct commit_name *e = find_commit_name(names, peeled);
	bool found = (e != NULL);

	git3_tag *tag = NULL;
	if (replace_name(&tag, repo, e, prio, sha1)) {
		if (!found) {
			e = git3__malloc(sizeof(struct commit_name));
			GIT3_ERROR_CHECK_ALLOC(e);

			e->path = NULL;
			e->tag = NULL;
		}

		if (e->tag)
			git3_tag_free(e->tag);
		e->tag = tag;
		e->prio = prio;
		e->name_checked = 0;
		git3_oid_cpy(&e->sha1, sha1);
		git3__free(e->path);
		e->path = git3__strdup(path);
		git3_oid_cpy(&e->peeled, peeled);

		if (!found && git3_describe_oidmap_put(names, &e->peeled, e) < 0)
			return -1;
	}
	else
		git3_tag_free(tag);

	return 0;
}

static int retrieve_peeled_tag_or_object_oid(
	git3_oid *peeled_out,
	git3_oid *ref_target_out,
	git3_repository *repo,
	const char *refname)
{
	git3_reference *ref;
	git3_object *peeled = NULL;
	int error;

	if ((error = git3_reference_lookup_resolved(&ref, repo, refname, -1)) < 0)
		return error;

	if ((error = git3_reference_peel(&peeled, ref, GIT3_OBJECT_ANY)) < 0)
		goto cleanup;

	git3_oid_cpy(ref_target_out, git3_reference_target(ref));
	git3_oid_cpy(peeled_out, git3_object_id(peeled));

	if (git3_oid_cmp(ref_target_out, peeled_out) != 0)
		error = 1; /* The reference was pointing to a annotated tag */
	else
		error = 0; /* Any other object */

cleanup:
	git3_reference_free(ref);
	git3_object_free(peeled);
	return error;
}

struct git3_describe_result {
	int dirty;
	int exact_match;
	int fallback_to_id;
	git3_oid commit_id;
	git3_repository *repo;
	struct commit_name *name;
	struct possible_tag *tag;
};

struct get_name_data
{
	git3_describe_options *opts;
	git3_repository *repo;
	git3_describe_oidmap names;
	git3_describe_result *result;
};

static int commit_name_dup(struct commit_name **out, struct commit_name *in)
{
	struct commit_name *name;

	name = git3__malloc(sizeof(struct commit_name));
	GIT3_ERROR_CHECK_ALLOC(name);

	memcpy(name, in,  sizeof(struct commit_name));
	name->tag = NULL;
	name->path = NULL;

	if (in->tag && git3_tag_dup(&name->tag, in->tag) < 0)
		return -1;

	name->path = git3__strdup(in->path);
	GIT3_ERROR_CHECK_ALLOC(name->path);

	*out = name;
	return 0;
}

static int get_name(const char *refname, void *payload)
{
	struct get_name_data *data;
	bool is_tag, is_annotated, all;
	git3_oid peeled, sha1;
	unsigned int prio;
	int error = 0;

	data = (struct get_name_data *)payload;
	is_tag = !git3__prefixcmp(refname, GIT3_REFS_TAGS_DIR);
	all = data->opts->describe_strategy == GIT3_DESCRIBE_ALL;

	/* Reject anything outside refs/tags/ unless --all */
	if (!all && !is_tag)
		return 0;

	/* Accept only tags that match the pattern, if given */
	if (data->opts->pattern && (!is_tag || wildmatch(data->opts->pattern,
		refname + strlen(GIT3_REFS_TAGS_DIR), 0)))
				return 0;

	/* Is it annotated? */
	if ((error = retrieve_peeled_tag_or_object_oid(
		&peeled, &sha1, data->repo, refname)) < 0)
		return error;

	is_annotated = error;

	/*
	 * By default, we only use annotated tags, but with --tags
	 * we fall back to lightweight ones (even without --tags,
	 * we still remember lightweight ones, only to give hints
	 * in an error message).  --all allows any refs to be used.
	 */
	if (is_annotated)
		prio = 2;
	else if (is_tag)
		prio = 1;
	else
		prio = 0;

	add_to_known_names(data->repo, &data->names,
		all ? refname + strlen(GIT3_REFS_DIR) : refname + strlen(GIT3_REFS_TAGS_DIR),
		&peeled, prio, &sha1);
	return 0;
}

struct possible_tag {
	struct commit_name *name;
	int depth;
	int found_order;
	unsigned flag_within;
};

static int possible_tag_dup(struct possible_tag **out, struct possible_tag *in)
{
	struct possible_tag *tag;
	int error;

	tag = git3__malloc(sizeof(struct possible_tag));
	GIT3_ERROR_CHECK_ALLOC(tag);

	memcpy(tag, in, sizeof(struct possible_tag));
	tag->name = NULL;

	if ((error = commit_name_dup(&tag->name, in->name)) < 0) {
		git3__free(tag);
		*out = NULL;
		return error;
	}

	*out = tag;
	return 0;
}

static int compare_pt(const void *a_, const void *b_)
{
	struct possible_tag *a = (struct possible_tag *)a_;
	struct possible_tag *b = (struct possible_tag *)b_;
	if (a->depth != b->depth)
		return a->depth - b->depth;
	if (a->found_order != b->found_order)
		return a->found_order - b->found_order;
	return 0;
}

#define SEEN (1u << 0)

static unsigned long finish_depth_computation(
	git3_pqueue *list,
	git3_revwalk *walk,
	struct possible_tag *best)
{
	unsigned long seen_commits = 0;
	int error, i;

	while (git3_pqueue_size(list) > 0) {
		git3_commit_list_node *c = git3_pqueue_pop(list);
		seen_commits++;
		if (c->flags & best->flag_within) {
			size_t index = 0;
			while (git3_pqueue_size(list) > index) {
				git3_commit_list_node *i = git3_pqueue_get(list, index);
				if (!(i->flags & best->flag_within))
					break;
				index++;
			}
			if (index > git3_pqueue_size(list))
				break;
		} else
			best->depth++;
		for (i = 0; i < c->out_degree; i++) {
			git3_commit_list_node *p = c->parents[i];
			if ((error = git3_commit_list_parse(walk, p)) < 0)
				return error;
			if (!(p->flags & SEEN))
				if ((error = git3_pqueue_insert(list, p)) < 0)
					return error;
			p->flags |= c->flags;
		}
	}
	return seen_commits;
}

static int display_name(git3_str *buf, git3_repository *repo, struct commit_name *n)
{
	if (n->prio == 2 && !n->tag) {
		if (git3_tag_lookup(&n->tag, repo, &n->sha1) < 0) {
			git3_error_set(GIT3_ERROR_TAG, "annotated tag '%s' not available", n->path);
			return -1;
		}
	}

	if (n->tag && !n->name_checked) {
		if (!git3_tag_name(n->tag)) {
			git3_error_set(GIT3_ERROR_TAG, "annotated tag '%s' has no embedded name", n->path);
			return -1;
		}

		/* TODO: Cope with warnings
		if (strcmp(n->tag->tag, all ? n->path + 5 : n->path))
			warning(_("tag '%s' is really '%s' here"), n->tag->tag, n->path);
		*/

		n->name_checked = 1;
	}

	if (n->tag)
		git3_str_printf(buf, "%s", git3_tag_name(n->tag));
	else
		git3_str_printf(buf, "%s", n->path);

	return 0;
}

static int find_unique_abbrev_size(
	int *out,
	git3_repository *repo,
	const git3_oid *oid_in,
	unsigned int abbreviated_size)
{
	size_t size = abbreviated_size;
	git3_odb *odb;
	git3_oid dummy;
	size_t hexsize;
	int error;

	if ((error = git3_repository_odb__weakptr(&odb, repo)) < 0)
		return error;

	hexsize = git3_oid_hexsize(repo->oid_type);

	while (size < hexsize) {
		if ((error = git3_odb_exists_prefix(&dummy, odb, oid_in, size)) == 0) {
			*out = (int) size;
			return 0;
		}

		/* If the error wasn't that it's not unique, then it's a proper error */
		if (error != GIT3_EAMBIGUOUS)
			return error;

		/* Try again with a larger size */
		size++;
	}

	/* If we didn't find any shorter prefix, we have to do the whole thing */
	*out = (int)hexsize;

	return 0;
}

static int show_suffix(
	git3_str *buf,
	int depth,
	git3_repository *repo,
	const git3_oid *id,
	unsigned int abbrev_size)
{
	int error, size = 0;

	char hex_oid[GIT3_OID_MAX_HEXSIZE];

	if ((error = find_unique_abbrev_size(&size, repo, id, abbrev_size)) < 0)
		return error;

	git3_oid_fmt(hex_oid, id);

	git3_str_printf(buf, "-%d-g", depth);

	git3_str_put(buf, hex_oid, size);

	return git3_str_oom(buf) ? -1 : 0;
}

#define MAX_CANDIDATES_TAGS FLAG_BITS - 1

static int describe_not_found(const git3_oid *oid, const char *message_format) {
	char oid_str[GIT3_OID_MAX_HEXSIZE + 1];
	git3_oid_tostr(oid_str, sizeof(oid_str), oid);

	git3_error_set(GIT3_ERROR_DESCRIBE, message_format, oid_str);
	return GIT3_ENOTFOUND;
}

static int describe(
	struct get_name_data *data,
	git3_commit *commit)
{
	struct commit_name *n;
	struct possible_tag *best;
	bool all, tags;
	git3_revwalk *walk = NULL;
	git3_pqueue list;
	git3_commit_list_node *cmit, *gave_up_on = NULL;
	git3_vector all_matches = GIT3_VECTOR_INIT;
	unsigned int match_cnt = 0, annotated_cnt = 0, cur_match;
	unsigned long seen_commits = 0;	/* TODO: Check long */
	unsigned int unannotated_cnt = 0;
	int error;

	if (git3_vector_init(&all_matches, MAX_CANDIDATES_TAGS, compare_pt) < 0)
		return -1;

	if ((error = git3_pqueue_init(&list, 0, 2, git3_commit_list_time_cmp)) < 0)
		goto cleanup;

	all = data->opts->describe_strategy == GIT3_DESCRIBE_ALL;
	tags = data->opts->describe_strategy == GIT3_DESCRIBE_TAGS;

	git3_oid_cpy(&data->result->commit_id, git3_commit_id(commit));

	n = find_commit_name(&data->names, git3_commit_id(commit));
	if (n && (tags || all || n->prio == 2)) {
		/*
		 * Exact match to an existing ref.
		 */
		data->result->exact_match = 1;
		if ((error = commit_name_dup(&data->result->name, n)) < 0)
			goto cleanup;

		goto cleanup;
	}

	if (!data->opts->max_candidates_tags) {
		error = describe_not_found(
			git3_commit_id(commit),
			"cannot describe - no tag exactly matches '%s'");

		goto cleanup;
	}

	if ((error = git3_revwalk_new(&walk, git3_commit_owner(commit))) < 0)
		goto cleanup;

	if ((cmit = git3_revwalk__commit_lookup(walk, git3_commit_id(commit))) == NULL)
		goto cleanup;

	if ((error = git3_commit_list_parse(walk, cmit)) < 0)
		goto cleanup;

	cmit->flags = SEEN;

	if ((error = git3_pqueue_insert(&list, cmit)) < 0)
		goto cleanup;

	while (git3_pqueue_size(&list) > 0)
	{
		int i;

		git3_commit_list_node *c = (git3_commit_list_node *)git3_pqueue_pop(&list);
		seen_commits++;

		n = find_commit_name(&data->names, &c->oid);

		if (n) {
			if (!tags && !all && n->prio < 2) {
				unannotated_cnt++;
			} else if (match_cnt < data->opts->max_candidates_tags) {
				struct possible_tag *t = git3__malloc(sizeof(struct commit_name));
				GIT3_ERROR_CHECK_ALLOC(t);
				if ((error = git3_vector_insert(&all_matches, t)) < 0)
					goto cleanup;

				match_cnt++;

				t->name = n;
				t->depth = seen_commits - 1;
				t->flag_within = 1u << match_cnt;
				t->found_order = match_cnt;
				c->flags |= t->flag_within;
				if (n->prio == 2)
					annotated_cnt++;
			}
			else {
				gave_up_on = c;
				break;
			}
		}

		for (cur_match = 0; cur_match < match_cnt; cur_match++) {
			struct possible_tag *t = git3_vector_get(&all_matches, cur_match);
			if (!(c->flags & t->flag_within))
				t->depth++;
		}

		if (annotated_cnt && (git3_pqueue_size(&list) == 0)) {
			/*
			if (debug) {
				char oid_str[GIT3_OID_MAX_HEXSIZE + 1];
				git3_oid_tostr(oid_str, sizeof(oid_str), &c->oid);

				fprintf(stderr, "finished search at %s\n", oid_str);
			}
			*/
			break;
		}
		for (i = 0; i < c->out_degree; i++) {
			git3_commit_list_node *p = c->parents[i];
			if ((error = git3_commit_list_parse(walk, p)) < 0)
				goto cleanup;
			if (!(p->flags & SEEN))
				if ((error = git3_pqueue_insert(&list, p)) < 0)
					goto cleanup;
			p->flags |= c->flags;

			if (data->opts->only_follow_first_parent)
				break;
		}
	}

	if (!match_cnt) {
		if (data->opts->show_commit_oid_as_fallback) {
			data->result->fallback_to_id = 1;
			git3_oid_cpy(&data->result->commit_id, &cmit->oid);

			goto cleanup;
		}
		if (unannotated_cnt) {
			error = describe_not_found(git3_commit_id(commit),
				"cannot describe - "
				"no annotated tags can describe '%s'; "
			    "however, there were unannotated tags.");
			goto cleanup;
		}
		else {
			error = describe_not_found(git3_commit_id(commit),
				"cannot describe - "
				"no tags can describe '%s'.");
			goto cleanup;
		}
	}

	git3_vector_sort(&all_matches);

	best = (struct possible_tag *)git3_vector_get(&all_matches, 0);

	if (gave_up_on) {
		if ((error = git3_pqueue_insert(&list, gave_up_on)) < 0)
			goto cleanup;
		seen_commits--;
	}
	if ((error = finish_depth_computation(
		&list, walk, best)) < 0)
		goto cleanup;

	seen_commits += error;
	if ((error = possible_tag_dup(&data->result->tag, best)) < 0)
		goto cleanup;

	/*
	{
		static const char *prio_names[] = {
			"head", "lightweight", "annotated",
		};

		char oid_str[GIT3_OID_MAX_HEXSIZE + 1];

		if (debug) {
			for (cur_match = 0; cur_match < match_cnt; cur_match++) {
				struct possible_tag *t = (struct possible_tag *)git3_vector_get(&all_matches, cur_match);
				fprintf(stderr, " %-11s %8d %s\n",
					prio_names[t->name->prio],
					t->depth, t->name->path);
			}
			fprintf(stderr, "traversed %lu commits\n", seen_commits);
			if (gave_up_on) {
				git3_oid_tostr(oid_str, sizeof(oid_str), &gave_up_on->oid);
				fprintf(stderr,
					"more than %i tags found; listed %i most recent\n"
					"gave up search at %s\n",
					data->opts->max_candidates_tags, data->opts->max_candidates_tags,
					oid_str);
			}
		}
	}
	*/

	git3_oid_cpy(&data->result->commit_id, &cmit->oid);

cleanup:
	{
		size_t i;
		struct possible_tag *match;
		git3_vector_foreach(&all_matches, i, match) {
			git3__free(match);
		}
	}
	git3_vector_dispose(&all_matches);
	git3_pqueue_free(&list);
	git3_revwalk_free(walk);
	return error;
}

static int normalize_options(
	git3_describe_options *dst,
	const git3_describe_options *src)
{
	git3_describe_options default_options = GIT3_DESCRIBE_OPTIONS_INIT;
	if (!src) src = &default_options;

	*dst = *src;

	if (dst->max_candidates_tags > GIT3_DESCRIBE_DEFAULT_MAX_CANDIDATES_TAGS)
		dst->max_candidates_tags = GIT3_DESCRIBE_DEFAULT_MAX_CANDIDATES_TAGS;

	return 0;
}

int git3_describe_commit(
	git3_describe_result **result,
	git3_object *committish,
	git3_describe_options *opts)
{
	struct get_name_data data = {0};
	struct commit_name *name;
	git3_commit *commit;
	git3_describe_options normalized;
	git3_hashmap_iter_t iter = GIT3_HASHMAP_INIT;
	int error = -1;

	GIT3_ASSERT_ARG(result);
	GIT3_ASSERT_ARG(committish);

	data.result = git3__calloc(1, sizeof(git3_describe_result));
	GIT3_ERROR_CHECK_ALLOC(data.result);
	data.result->repo = git3_object_owner(committish);

	data.repo = git3_object_owner(committish);

	if ((error = normalize_options(&normalized, opts)) < 0)
		return error;

	GIT3_ERROR_CHECK_VERSION(
		&normalized,
		GIT3_DESCRIBE_OPTIONS_VERSION,
		"git3_describe_options");
	data.opts = &normalized;

	/** TODO: contains to be implemented */

	if ((error = git3_object_peel((git3_object **)(&commit), committish, GIT3_OBJECT_COMMIT)) < 0)
		goto cleanup;

	if ((error = git3_reference_foreach_name(
			git3_object_owner(committish),
			get_name, &data)) < 0)
				goto cleanup;

	if (git3_describe_oidmap_size(&data.names) == 0 && !normalized.show_commit_oid_as_fallback) {
		git3_error_set(GIT3_ERROR_DESCRIBE, "cannot describe - "
			"no reference found, cannot describe anything.");
		error = -1;
		goto cleanup;
	}

	if ((error = describe(&data, commit)) < 0)
		goto cleanup;

cleanup:
	git3_commit_free(commit);

	while (git3_describe_oidmap_iterate(&iter, NULL, &name, &data.names) == 0) {
		git3_tag_free(name->tag);
		git3__free(name->path);
		git3__free(name);
	}

	git3_describe_oidmap_dispose(&data.names);

	if (error < 0)
		git3_describe_result_free(data.result);
	else
		*result = data.result;

	return error;
}

int git3_describe_workdir(
	git3_describe_result **out,
	git3_repository *repo,
	git3_describe_options *opts)
{
	int error;
	git3_oid current_id;
	git3_status_list *status = NULL;
	git3_status_options status_opts = GIT3_STATUS_OPTIONS_INIT;
	git3_describe_result *result = NULL;
	git3_object *commit;

	if ((error = git3_reference_name_to_id(&current_id, repo, GIT3_HEAD_FILE)) < 0)
		return error;

	if ((error = git3_object_lookup(&commit, repo, &current_id, GIT3_OBJECT_COMMIT)) < 0)
		return error;

	/* The first step is to perform a describe of HEAD, so we can leverage this */
	if ((error = git3_describe_commit(&result, commit, opts)) < 0)
		goto out;

	if ((error = git3_status_list_new(&status, repo, &status_opts)) < 0)
		goto out;


	if (git3_status_list_entrycount(status) > 0)
		result->dirty = 1;

out:
	git3_object_free(commit);
	git3_status_list_free(status);

	if (error < 0)
		git3_describe_result_free(result);
	else
		*out = result;

	return error;
}

static int normalize_format_options(
	git3_describe_format_options *dst,
	const git3_describe_format_options *src)
{
	if (!src) {
		git3_describe_format_options_init(dst, GIT3_DESCRIBE_FORMAT_OPTIONS_VERSION);
		return 0;
	}

	memcpy(dst, src, sizeof(git3_describe_format_options));
	return 0;
}

static int git3_describe__format(
	git3_str *out,
	const git3_describe_result *result,
	const git3_describe_format_options *given)
{
	int error;
	git3_repository *repo;
	struct commit_name *name;
	git3_describe_format_options opts;

	GIT3_ASSERT_ARG(out);
	GIT3_ASSERT_ARG(result);

	GIT3_ERROR_CHECK_VERSION(given, GIT3_DESCRIBE_FORMAT_OPTIONS_VERSION, "git3_describe_format_options");
	normalize_format_options(&opts, given);

	if (opts.always_use_long_format && opts.abbreviated_size == 0) {
		git3_error_set(GIT3_ERROR_DESCRIBE, "cannot describe - "
			"'always_use_long_format' is incompatible with a zero"
			"'abbreviated_size'");
		return -1;
	}


	repo = result->repo;

	/* If we did find an exact match, then it's the easier method */
	if (result->exact_match) {
		name = result->name;
		if ((error = display_name(out, repo, name)) < 0)
			return error;

		if (opts.always_use_long_format) {
			const git3_oid *id = name->tag ? git3_tag_target_id(name->tag) : &result->commit_id;
			if ((error = show_suffix(out, 0, repo, id, opts.abbreviated_size)) < 0)
				return error;
		}

		if (result->dirty && opts.dirty_suffix)
			git3_str_puts(out, opts.dirty_suffix);

		return git3_str_oom(out) ? -1 : 0;
	}

	/* If we didn't find *any* tags, we fall back to the commit's id */
	if (result->fallback_to_id) {
		char hex_oid[GIT3_OID_MAX_HEXSIZE + 1] = {0};
		int size = 0;

		if ((error = find_unique_abbrev_size(
			     &size, repo, &result->commit_id, opts.abbreviated_size)) < 0)
			return -1;

		git3_oid_fmt(hex_oid, &result->commit_id);
		git3_str_put(out, hex_oid, size);

		if (result->dirty && opts.dirty_suffix)
			git3_str_puts(out, opts.dirty_suffix);

		return git3_str_oom(out) ? -1 : 0;
	}

	/* Lastly, if we found a matching tag, we show that */
	name = result->tag->name;

	if ((error = display_name(out, repo, name)) < 0)
		return error;

	if (opts.abbreviated_size) {
		if ((error = show_suffix(out, result->tag->depth, repo,
			&result->commit_id, opts.abbreviated_size)) < 0)
			return error;
	}

	if (result->dirty && opts.dirty_suffix) {
		git3_str_puts(out, opts.dirty_suffix);
	}

	return git3_str_oom(out) ? -1 : 0;
}

int git3_describe_format(
	git3_buf *out,
	const git3_describe_result *result,
	const git3_describe_format_options *given)
{
	GIT3_BUF_WRAP_PRIVATE(out, git3_describe__format, result, given);
}

void git3_describe_result_free(git3_describe_result *result)
{
	if (result == NULL)
		return;

	if (result->name) {
		git3_tag_free(result->name->tag);
		git3__free(result->name->path);
		git3__free(result->name);
	}

	if (result->tag) {
		git3_tag_free(result->tag->name->tag);
		git3__free(result->tag->name->path);
		git3__free(result->tag->name);
		git3__free(result->tag);
	}

	git3__free(result);
}

int git3_describe_options_init(git3_describe_options *opts, unsigned int version)
{
	GIT3_INIT_STRUCTURE_FROM_TEMPLATE(
		opts, version, git3_describe_options, GIT3_DESCRIBE_OPTIONS_INIT);
	return 0;
}

#ifndef GIT3_DEPRECATE_HARD
int git3_describe_init_options(git3_describe_options *opts, unsigned int version)
{
	return git3_describe_options_init(opts, version);
}
#endif

int git3_describe_format_options_init(git3_describe_format_options *opts, unsigned int version)
{
	GIT3_INIT_STRUCTURE_FROM_TEMPLATE(
		opts, version, git3_describe_format_options, GIT3_DESCRIBE_FORMAT_OPTIONS_INIT);
	return 0;
}

#ifndef GIT3_DEPRECATE_HARD
int git3_describe_init_format_options(git3_describe_format_options *opts, unsigned int version)
{
	return git3_describe_format_options_init(opts, version);
}
#endif
