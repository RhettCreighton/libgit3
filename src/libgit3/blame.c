/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "blame.h"

#include "git3/commit.h"
#include "git3/revparse.h"
#include "git3/revwalk.h"
#include "git3/tree.h"
#include "git3/diff.h"
#include "git3/blob.h"
#include "git3/signature.h"
#include "git3/mailmap.h"
#include "util.h"
#include "repository.h"
#include "blame_git.h"

static int hunk_byfinalline_search_cmp(const void *key, const void *entry)
{
	git3_blame_hunk *hunk = (git3_blame_hunk*)entry;

	size_t lineno = *(size_t*)key;
	size_t lines_in_hunk = hunk->lines_in_hunk;
	size_t final_start_line_number = hunk->final_start_line_number;

	if (lineno < final_start_line_number)
		return -1;
	if (lineno >= final_start_line_number + lines_in_hunk)
		return 1;
	return 0;
}

static int paths_cmp(const void *a, const void *b) { return git3__strcmp((char*)a, (char*)b); }
static int hunk_cmp(const void *_a, const void *_b)
{
	git3_blame_hunk *a = (git3_blame_hunk*)_a,
						*b = (git3_blame_hunk*)_b;

	if (a->final_start_line_number > b->final_start_line_number)
		return 1;
	else if (a->final_start_line_number < b->final_start_line_number)
		return -1;
	else
		return 0;
}

static bool hunk_ends_at_or_before_line(git3_blame_hunk *hunk, size_t line)
{
	return line >= (hunk->final_start_line_number + hunk->lines_in_hunk - 1);
}

static bool hunk_starts_at_or_after_line(git3_blame_hunk *hunk, size_t line)
{
	return line <= hunk->final_start_line_number;
}

static git3_blame_hunk *new_hunk(
	size_t start,
	size_t lines,
	size_t orig_start,
	const char *path,
	git3_blame *blame)
{
	git3_blame_hunk *hunk = git3__calloc(1, sizeof(git3_blame_hunk));
	if (!hunk) return NULL;

	hunk->lines_in_hunk = lines;
	hunk->final_start_line_number = start;
	hunk->orig_start_line_number = orig_start;
	hunk->orig_path = path ? git3__strdup(path) : NULL;
	git3_oid_clear(&hunk->orig_commit_id, blame->repository->oid_type);
	git3_oid_clear(&hunk->final_commit_id, blame->repository->oid_type);

	return hunk;
}

static void free_hunk(git3_blame_hunk *hunk)
{
	git3__free((char *)hunk->orig_path);
	git3__free((char *)hunk->summary);
	git3_signature_free(hunk->final_signature);
	git3_signature_free(hunk->final_committer);
	git3_signature_free(hunk->orig_signature);
	git3_signature_free(hunk->orig_committer);
	git3__free(hunk);
}

static git3_blame_hunk *dup_hunk(git3_blame_hunk *hunk, git3_blame *blame)
{
	git3_blame_hunk *newhunk = new_hunk(
			hunk->final_start_line_number,
			hunk->lines_in_hunk,
			hunk->orig_start_line_number,
			hunk->orig_path,
			blame);

	if (!newhunk)
		return NULL;

	git3_oid_cpy(&newhunk->orig_commit_id, &hunk->orig_commit_id);
	git3_oid_cpy(&newhunk->final_commit_id, &hunk->final_commit_id);
	newhunk->boundary = hunk->boundary;

	if (git3_signature_dup(&newhunk->final_signature, hunk->final_signature) < 0 ||
	    git3_signature_dup(&newhunk->final_committer, hunk->final_committer) < 0 ||
	    git3_signature_dup(&newhunk->orig_signature, hunk->orig_signature) < 0 ||
	    git3_signature_dup(&newhunk->orig_committer, hunk->orig_committer) < 0 ||
	    (newhunk->summary = git3__strdup(hunk->summary)) == NULL) {
		free_hunk(newhunk);
		return NULL;
	}

	return newhunk;
}

/* Starting with the hunk that includes start_line, shift all following hunks'
 * final_start_line by shift_by lines */
static void shift_hunks_by(git3_vector *v, size_t start_line, int shift_by)
{
	size_t i;
	for (i = 0; i < v->length; i++) {
		git3_blame_hunk *hunk = (git3_blame_hunk*)v->contents[i];
		if(hunk->final_start_line_number < start_line){
		        continue;
		}
		hunk->final_start_line_number += shift_by;
	}
}

git3_blame *git3_blame__alloc(
	git3_repository *repo,
	git3_blame_options opts,
	const char *path)
{
	git3_blame *gbr = git3__calloc(1, sizeof(git3_blame));
	if (!gbr)
		return NULL;

	gbr->repository = repo;
	gbr->options = opts;

	if (git3_vector_init(&gbr->hunks, 8, hunk_cmp) < 0 ||
	    git3_vector_init(&gbr->paths, 8, paths_cmp) < 0 ||
	    (gbr->path = git3__strdup(path)) == NULL ||
	    git3_vector_insert(&gbr->paths, git3__strdup(path)) < 0) {
		git3_blame_free(gbr);
		return NULL;
	}

	if (opts.flags & GIT3_BLAME_USE_MAILMAP &&
	    git3_mailmap_from_repository(&gbr->mailmap, repo) < 0) {
		git3_blame_free(gbr);
		return NULL;
	}

	return gbr;
}

void git3_blame_free(git3_blame *blame)
{
	size_t i;
	git3_blame_hunk *hunk;

	if (!blame) return;

	git3_vector_foreach(&blame->hunks, i, hunk)
		free_hunk(hunk);

	git3_vector_dispose(&blame->hunks);
	git3_array_clear(blame->lines);

	git3_vector_dispose_deep(&blame->paths);

	git3_array_clear(blame->line_index);

	git3_mailmap_free(blame->mailmap);

	git3__free(blame->path);
	git3_blob_free(blame->final_blob);
	git3__free(blame);
}

size_t git3_blame_hunkcount(git3_blame *blame)
{
	GIT3_ASSERT_ARG(blame);

	return blame->hunks.length;
}

size_t git3_blame_linecount(git3_blame *blame)
{
	GIT3_ASSERT_ARG(blame);

	return git3_array_size(blame->line_index);
}

const git3_blame_line *git3_blame_line_byindex(
	git3_blame *blame,
	size_t idx)
{
	GIT3_ASSERT_ARG_WITH_RETVAL(blame, NULL);
	GIT3_ASSERT_WITH_RETVAL(idx > 0 && idx <= git3_array_size(blame->line_index), NULL);

	return git3_array_get(blame->lines, idx - 1);
}

const git3_blame_hunk *git3_blame_hunk_byindex(
	git3_blame *blame,
	size_t index)
{
	GIT3_ASSERT_ARG_WITH_RETVAL(blame, NULL);
	return git3_vector_get(&blame->hunks, index);
}

const git3_blame_hunk *git3_blame_hunk_byline(
	git3_blame *blame,
	size_t lineno)
{
	size_t i, new_lineno = lineno;

	GIT3_ASSERT_ARG_WITH_RETVAL(blame, NULL);

	if (git3_vector_bsearch2(&i, &blame->hunks,
			hunk_byfinalline_search_cmp, &new_lineno) != 0)
		return NULL;

	return git3_blame_hunk_byindex(blame, i);
}

#ifndef GIT3_DEPRECATE_HARD
uint32_t git3_blame_get_hunk_count(git3_blame *blame)
{
	size_t count = git3_blame_hunkcount(blame);
	GIT3_ASSERT(count < UINT32_MAX);
	return (uint32_t)count;
}

const git3_blame_hunk *git3_blame_get_hunk_byindex(
	git3_blame *blame,
	uint32_t index)
{
	return git3_blame_hunk_byindex(blame, index);
}

const git3_blame_hunk *git3_blame_get_hunk_byline(
	git3_blame *blame,
	size_t lineno)
{
	return git3_blame_hunk_byline(blame, lineno);
}
#endif

static int normalize_options(
		git3_blame_options *out,
		const git3_blame_options *in,
		git3_repository *repo)
{
	git3_blame_options dummy = GIT3_BLAME_OPTIONS_INIT;
	if (!in) in = &dummy;

	memcpy(out, in, sizeof(git3_blame_options));

	/* No newest_commit => HEAD */
	if (git3_oid_is_zero(&out->newest_commit)) {
		if (git3_reference_name_to_id(&out->newest_commit, repo, "HEAD") < 0) {
			return -1;
		}
	}

	/* min_line 0 really means 1 */
	if (!out->min_line) out->min_line = 1;
	/* max_line 0 really means N, but we don't know N yet */

	/* Fix up option implications */
	if (out->flags & GIT3_BLAME_TRACK_COPIES_ANY_COMMIT_COPIES)
		out->flags |= GIT3_BLAME_TRACK_COPIES_SAME_COMMIT_COPIES;
	if (out->flags & GIT3_BLAME_TRACK_COPIES_SAME_COMMIT_COPIES)
		out->flags |= GIT3_BLAME_TRACK_COPIES_SAME_COMMIT_MOVES;
	if (out->flags & GIT3_BLAME_TRACK_COPIES_SAME_COMMIT_MOVES)
		out->flags |= GIT3_BLAME_TRACK_COPIES_SAME_FILE;

	return 0;
}

static git3_blame_hunk *split_hunk_in_vector(
		git3_vector *vec,
		git3_blame_hunk *hunk,
		size_t rel_line,
		bool return_new,
		git3_blame *blame)
{
	size_t new_line_count;
	git3_blame_hunk *nh;

	/* Don't split if already at a boundary */
	if (rel_line <= 0 ||
	    rel_line >= hunk->lines_in_hunk)
	{
		return hunk;
	}

	new_line_count = hunk->lines_in_hunk - rel_line;
	nh = new_hunk(hunk->final_start_line_number + rel_line,
		new_line_count, hunk->orig_start_line_number + rel_line,
		hunk->orig_path, blame);

	if (!nh)
		return NULL;

	git3_oid_cpy(&nh->final_commit_id, &hunk->final_commit_id);
	git3_oid_cpy(&nh->orig_commit_id, &hunk->orig_commit_id);

	/* Adjust hunk that was split */
	hunk->lines_in_hunk -= new_line_count;
	git3_vector_insert_sorted(vec, nh, NULL);
	{
		git3_blame_hunk *ret = return_new ? nh : hunk;
		return ret;
	}
}

/*
 * Construct a list of char indices for where lines begin
 * Adapted from core git:
 * https://github.com/gitster/git/blob/be5c9fb9049ed470e7005f159bb923a5f4de1309/builtin/blame.c#L1760-L1789
 */
static int index_blob_lines(git3_blame *blame)
{
    const char *buf = blame->final_buf;
    size_t len = blame->final_buf_size;
    int num = 0, incomplete = 0, bol = 1;
    git3_blame_line *line = NULL;
    size_t *i;

    if (len && buf[len-1] != '\n')
        incomplete++; /* incomplete line at the end */

    while (len--) {
        if (bol) {
            i = git3_array_alloc(blame->line_index);
            GIT3_ERROR_CHECK_ALLOC(i);
            *i = buf - blame->final_buf;

            GIT3_ASSERT(line == NULL);
            line = git3_array_alloc(blame->lines);
            GIT3_ERROR_CHECK_ALLOC(line);

            line->ptr = buf;
            bol = 0;
        }

        if (*buf++ == '\n') {
            GIT3_ASSERT(line);
            line->len = (buf - line->ptr) - 1;
            line = NULL;

            num++;
            bol = 1;
        }
    }

    i = git3_array_alloc(blame->line_index);
    GIT3_ERROR_CHECK_ALLOC(i);
    *i = buf - blame->final_buf;

    if (!bol) {
        GIT3_ASSERT(line);
        line->len = buf - line->ptr;
	line = NULL;
    }

    GIT3_ASSERT(!line);

    blame->num_lines = num + incomplete;
    return blame->num_lines;
}

static git3_blame_hunk *hunk_from_entry(git3_blame__entry *e, git3_blame *blame)
{
	const char *summary;
	git3_blame_hunk *h = new_hunk(
		e->lno+1, e->num_lines, e->s_lno+1, e->suspect->path,
		blame);

	if (!h)
		return NULL;

	git3_oid_cpy(&h->final_commit_id, git3_commit_id(e->suspect->commit));
	git3_oid_cpy(&h->orig_commit_id, git3_commit_id(e->suspect->commit));

	if (git3_commit_author_with_mailmap(
		&h->final_signature, e->suspect->commit, blame->mailmap) < 0 ||
	    git3_commit_committer_with_mailmap(
		&h->final_committer, e->suspect->commit, blame->mailmap) < 0 ||
	    git3_signature_dup(&h->orig_signature, h->final_signature) < 0 ||
	    git3_signature_dup(&h->orig_committer, h->final_committer) < 0 ||
	    (summary = git3_commit_summary(e->suspect->commit)) == NULL ||
	    (h->summary = git3__strdup(summary)) == NULL) {
		free_hunk(h);
		return NULL;
	}

	h->boundary = e->is_boundary ? 1 : 0;
	return h;
}

static int load_blob(git3_blame *blame)
{
	int error;

	if (blame->final_blob) return 0;

	error = git3_commit_lookup(&blame->final, blame->repository, &blame->options.newest_commit);
	if (error < 0)
		goto cleanup;
	error = git3_object_lookup_bypath((git3_object**)&blame->final_blob,
			(git3_object*)blame->final, blame->path, GIT3_OBJECT_BLOB);

cleanup:
	return error;
}

static int blame_internal(git3_blame *blame)
{
	int error;
	git3_blame__entry *ent = NULL;
	git3_blame__origin *o;

	if ((error = load_blob(blame)) < 0 ||
	    (error = git3_blame__get_origin(&o, blame, blame->final, blame->path)) < 0)
		goto on_error;

	if (git3_blob_rawsize(blame->final_blob) > SIZE_MAX) {
		git3_error_set(GIT3_ERROR_NOMEMORY, "blob is too large to blame");
		error = -1;
		goto on_error;
	}

	blame->final_buf = git3_blob_rawcontent(blame->final_blob);
	blame->final_buf_size = (size_t)git3_blob_rawsize(blame->final_blob);

	ent = git3__calloc(1, sizeof(git3_blame__entry));
	GIT3_ERROR_CHECK_ALLOC(ent);

	ent->num_lines = index_blob_lines(blame);
	ent->lno = blame->options.min_line - 1;
	ent->num_lines = ent->num_lines - blame->options.min_line + 1;
	if (blame->options.max_line > 0)
		ent->num_lines = blame->options.max_line - blame->options.min_line + 1;
	ent->s_lno = ent->lno;
	ent->suspect = o;

	blame->ent = ent;

	if ((error = git3_blame__like_git(blame, blame->options.flags)) < 0)
		goto on_error;

	for (ent = blame->ent; ent; ent = ent->next) {
		git3_blame_hunk *h = hunk_from_entry(ent, blame);
		git3_vector_insert(&blame->hunks, h);
	}

on_error:
	for (ent = blame->ent; ent; ) {
		git3_blame__entry *next = ent->next;
		git3_blame__free_entry(ent);
		ent = next;
	}

	return error;
}

/*******************************************************************************
 * File blaming
 ******************************************************************************/

int git3_blame_file(
		git3_blame **out,
		git3_repository *repo,
		const char *path,
		git3_blame_options *options)
{
	int error = -1;
	git3_blame_options normOptions = GIT3_BLAME_OPTIONS_INIT;
	git3_blame *blame = NULL;

	GIT3_ASSERT_ARG(out);
	GIT3_ASSERT_ARG(repo);
	GIT3_ASSERT_ARG(path);

	if ((error = normalize_options(&normOptions, options, repo)) < 0)
		goto on_error;

	blame = git3_blame__alloc(repo, normOptions, path);
	GIT3_ERROR_CHECK_ALLOC(blame);

	if ((error = load_blob(blame)) < 0)
		goto on_error;

	if ((error = blame_internal(blame)) < 0)
		goto on_error;

	*out = blame;
	return 0;

on_error:
	git3_blame_free(blame);
	return error;
}

/*******************************************************************************
 * Buffer blaming
 *******************************************************************************/

static bool hunk_is_bufferblame(git3_blame_hunk *hunk)
{
	return hunk && git3_oid_is_zero(&hunk->final_commit_id);
}

static int buffer_hunk_cb(
	const git3_diff_delta *delta,
	const git3_diff_hunk *hunk,
	void *payload)
{
	git3_blame *blame = (git3_blame*)payload;
	uint32_t wedge_line;

	GIT3_UNUSED(delta);

	wedge_line = (hunk->new_start >= hunk->old_start || hunk->old_lines==0) ? hunk->new_start : hunk->old_start;
	blame->current_diff_line = wedge_line;
	blame->current_hunk = (git3_blame_hunk*)git3_blame_hunk_byline(blame, wedge_line);
	if (!blame->current_hunk) {
		/* Line added at the end of the file */
		blame->current_hunk = new_hunk(wedge_line, 0, wedge_line,
			blame->path, blame);
		blame->current_diff_line++;
		GIT3_ERROR_CHECK_ALLOC(blame->current_hunk);
		git3_vector_insert(&blame->hunks, blame->current_hunk);
	} else if (!hunk_starts_at_or_after_line(blame->current_hunk, wedge_line)){
		/* If this hunk doesn't start between existing hunks, split a hunk up so it does */
		blame->current_hunk = split_hunk_in_vector(&blame->hunks, blame->current_hunk,
				wedge_line - blame->current_hunk->final_start_line_number, true,
				blame);
		GIT3_ERROR_CHECK_ALLOC(blame->current_hunk);
	}

	return 0;
}

static int ptrs_equal_cmp(const void *a, const void *b) { return a<b ? -1 : a>b ? 1 : 0; }
static int buffer_line_cb(
	const git3_diff_delta *delta,
	const git3_diff_hunk *hunk,
	const git3_diff_line *line,
	void *payload)
{
	git3_blame *blame = (git3_blame*)payload;

	GIT3_UNUSED(delta);
	GIT3_UNUSED(hunk);
	GIT3_UNUSED(line);

	if (line->origin == GIT3_DIFF_LINE_ADDITION) {
		if (hunk_is_bufferblame(blame->current_hunk) &&
		    hunk_ends_at_or_before_line(blame->current_hunk, blame->current_diff_line)) {
			/* Append to the current buffer-blame hunk */
			blame->current_hunk->lines_in_hunk++;
			shift_hunks_by(&blame->hunks, blame->current_diff_line, 1);
		} else {
			/* Create a new buffer-blame hunk with this line */
			shift_hunks_by(&blame->hunks, blame->current_diff_line, 1);
			blame->current_hunk = new_hunk(blame->current_diff_line, 1, 0, blame->path, blame);
			GIT3_ERROR_CHECK_ALLOC(blame->current_hunk);
			git3_vector_insert_sorted(&blame->hunks, blame->current_hunk, NULL);
		}
		blame->current_diff_line++;
	}

	if (line->origin == GIT3_DIFF_LINE_DELETION) {
		/* Trim the line from the current hunk; remove it if it's now empty */
		size_t shift_base = blame->current_diff_line + blame->current_hunk->lines_in_hunk;

		if (--(blame->current_hunk->lines_in_hunk) == 0) {
			size_t i;
			size_t i_next;
			if (!git3_vector_search2(&i, &blame->hunks, ptrs_equal_cmp, blame->current_hunk)) {
				git3_vector_remove(&blame->hunks, i);
				free_hunk(blame->current_hunk);
				i_next = min( i , blame->hunks.length -1);
				blame->current_hunk = (git3_blame_hunk*)git3_blame_hunk_byindex(blame, (uint32_t)i_next);
			}
		}
		shift_hunks_by(&blame->hunks, shift_base, -1);
	}
	return 0;
}

int git3_blame_buffer(
		git3_blame **out,
		git3_blame *reference,
		const char *buffer,
		size_t buffer_len)
{
	git3_blame *blame;
	git3_diff_options diffopts = GIT3_DIFF_OPTIONS_INIT;
	size_t i;
	git3_blame_hunk *hunk;

	diffopts.context_lines = 0;

	GIT3_ASSERT_ARG(out);
	GIT3_ASSERT_ARG(reference);
	GIT3_ASSERT_ARG(buffer && buffer_len);

	blame = git3_blame__alloc(reference->repository, reference->options, reference->path);
	GIT3_ERROR_CHECK_ALLOC(blame);

	/* Duplicate all of the hunk structures in the reference blame */
	git3_vector_foreach(&reference->hunks, i, hunk) {
		git3_blame_hunk *h = dup_hunk(hunk, blame);
		GIT3_ERROR_CHECK_ALLOC(h);

		git3_vector_insert(&blame->hunks, h);
	}

	/* Diff to the reference blob */
	git3_diff_blob_to_buffer(reference->final_blob, blame->path,
		buffer, buffer_len, blame->path, &diffopts,
		NULL, NULL, buffer_hunk_cb, buffer_line_cb, blame);

	*out = blame;
	return 0;
}

int git3_blame_options_init(git3_blame_options *opts, unsigned int version)
{
	GIT3_INIT_STRUCTURE_FROM_TEMPLATE(
		opts, version, git3_blame_options, GIT3_BLAME_OPTIONS_INIT);
	return 0;
}

#ifndef GIT3_DEPRECATE_HARD
int git3_blame_init_options(git3_blame_options *opts, unsigned int version)
{
	return git3_blame_options_init(opts, version);
}
#endif
