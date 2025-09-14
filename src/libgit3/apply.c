/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "git3/apply.h"
#include "git3/patch.h"
#include "git3/filter.h"
#include "git3/blob.h"
#include "git3/index.h"
#include "git3/checkout.h"
#include "git3/repository.h"
#include "array.h"
#include "patch.h"
#include "futils.h"
#include "delta.h"
#include "zstream.h"
#include "reader.h"
#include "index.h"
#include "repository.h"
#include "hashmap_str.h"
#include "apply.h"

typedef struct {
	/* The lines that we allocate ourself are allocated out of the pool.
	 * (Lines may have been allocated out of the diff.)
	 */
	git3_pool pool;
	git3_vector lines;
} patch_image;

static int apply_err(const char *fmt, ...) GIT3_FORMAT_PRINTF(1, 2);
static int apply_err(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	git3_error_vset(GIT3_ERROR_PATCH, fmt, ap);
	va_end(ap);

	return GIT3_EAPPLYFAIL;
}

static void patch_line_init(
	git3_diff_line *out,
	const char *in,
	size_t in_len,
	size_t in_offset)
{
	out->content = in;
	out->content_len = in_len;
	out->content_offset = in_offset;
}

#define PATCH_IMAGE_INIT { GIT3_POOL_INIT, GIT3_VECTOR_INIT }

static int patch_image_init_fromstr(
	patch_image *out, const char *in, size_t in_len)
{
	git3_diff_line *line;
	const char *start, *end;

	memset(out, 0x0, sizeof(patch_image));

	if (git3_pool_init(&out->pool, sizeof(git3_diff_line)) < 0)
		return -1;

	if (!in_len)
		return 0;

	for (start = in; start < in + in_len; start = end) {
		end = memchr(start, '\n', in_len - (start - in));

		if (end == NULL)
			end = in + in_len;

		else if (end < in + in_len)
			end++;

		line = git3_pool_mallocz(&out->pool, 1);
		GIT3_ERROR_CHECK_ALLOC(line);

		if (git3_vector_insert(&out->lines, line) < 0)
			return -1;

		patch_line_init(line, start, (end - start), (start - in));
	}

	return 0;
}

static void patch_image_free(patch_image *image)
{
	if (image == NULL)
		return;

	git3_pool_clear(&image->pool);
	git3_vector_dispose(&image->lines);
}

static bool match_hunk(
	patch_image *image,
	patch_image *preimage,
	size_t linenum)
{
	bool match = 0;
	size_t i;

	/* Ensure this hunk is within the image boundaries. */
	if (git3_vector_length(&preimage->lines) + linenum >
		git3_vector_length(&image->lines))
		return 0;

	match = 1;

	/* Check exact match. */
	for (i = 0; i < git3_vector_length(&preimage->lines); i++) {
		git3_diff_line *preimage_line = git3_vector_get(&preimage->lines, i);
		git3_diff_line *image_line = git3_vector_get(&image->lines, linenum + i);

		if (preimage_line->content_len != image_line->content_len ||
			memcmp(preimage_line->content, image_line->content, image_line->content_len) != 0) {
			match = 0;
			break;
		}
	}

	return match;
}

static bool find_hunk_linenum(
	size_t *out,
	patch_image *image,
	patch_image *preimage,
	size_t linenum)
{
	size_t max = git3_vector_length(&image->lines);
	bool match;

	if (linenum > max)
		linenum = max;

	match = match_hunk(image, preimage, linenum);

	*out = linenum;
	return match;
}

static int update_hunk(
	patch_image *image,
	size_t linenum,
	patch_image *preimage,
	patch_image *postimage)
{
	size_t postlen = git3_vector_length(&postimage->lines);
	size_t prelen = git3_vector_length(&preimage->lines);
	size_t i;
	int error = 0;

	if (postlen > prelen)
		error = git3_vector_insert_null(
			&image->lines, linenum, (postlen - prelen));
	else if (prelen > postlen)
		error = git3_vector_remove_range(
			&image->lines, linenum, (prelen - postlen));

	if (error) {
		git3_error_set_oom();
		return -1;
	}

	for (i = 0; i < git3_vector_length(&postimage->lines); i++) {
		image->lines.contents[linenum + i] =
			git3_vector_get(&postimage->lines, i);
	}

	return 0;
}

typedef struct {
	git3_apply_options opts;
	size_t skipped_new_lines;
	size_t skipped_old_lines;
} apply_hunks_ctx;

static int apply_hunk(
	patch_image *image,
	git3_patch *patch,
	git3_patch_hunk *hunk,
	apply_hunks_ctx *ctx)
{
	patch_image preimage = PATCH_IMAGE_INIT, postimage = PATCH_IMAGE_INIT;
	size_t line_num, i;
	int error = 0;

	if (ctx->opts.hunk_cb) {
		error = ctx->opts.hunk_cb(&hunk->hunk, ctx->opts.payload);

		if (error) {
			if (error > 0) {
				ctx->skipped_new_lines += hunk->hunk.new_lines;
				ctx->skipped_old_lines += hunk->hunk.old_lines;
				error = 0;
			}

			goto done;
		}
	}

	for (i = 0; i < hunk->line_count; i++) {
		size_t linenum = hunk->line_start + i;
		git3_diff_line *line = git3_array_get(patch->lines, linenum), *prev;

		if (!line) {
			error = apply_err("preimage does not contain line %"PRIuZ, linenum);
			goto done;
		}

		switch (line->origin) {
			case GIT3_DIFF_LINE_CONTEXT_EOFNL:
			case GIT3_DIFF_LINE_DEL_EOFNL:
			case GIT3_DIFF_LINE_ADD_EOFNL:
				prev = i ? git3_array_get(patch->lines, linenum - 1) : NULL;
				if (prev && prev->content[prev->content_len - 1] == '\n')
					prev->content_len -= 1;
				break;
			case GIT3_DIFF_LINE_CONTEXT:
				if ((error = git3_vector_insert(&preimage.lines, line)) < 0 ||
				    (error = git3_vector_insert(&postimage.lines, line)) < 0)
					goto done;
				break;
			case GIT3_DIFF_LINE_DELETION:
				if ((error = git3_vector_insert(&preimage.lines, line)) < 0)
					goto done;
				break;
			case GIT3_DIFF_LINE_ADDITION:
				if ((error = git3_vector_insert(&postimage.lines, line)) < 0)
					goto done;
				break;
		}
	}

	if (hunk->hunk.new_start) {
		line_num = hunk->hunk.new_start -
			ctx->skipped_new_lines +
			ctx->skipped_old_lines -
			1;
	} else {
		line_num = 0;
	}

	if (!find_hunk_linenum(&line_num, image, &preimage, line_num)) {
		error = apply_err("hunk at line %d did not apply",
			hunk->hunk.new_start);
		goto done;
	}

	error = update_hunk(image, line_num, &preimage, &postimage);

done:
	patch_image_free(&preimage);
	patch_image_free(&postimage);

	return error;
}

static int apply_hunks(
	git3_str *out,
	const char *source,
	size_t source_len,
	git3_patch *patch,
	apply_hunks_ctx *ctx)
{
	git3_patch_hunk *hunk;
	git3_diff_line *line;
	patch_image image;
	size_t i;
	int error = 0;

	if ((error = patch_image_init_fromstr(&image, source, source_len)) < 0)
		goto done;

	git3_array_foreach(patch->hunks, i, hunk) {
		if ((error = apply_hunk(&image, patch, hunk, ctx)) < 0)
			goto done;
	}

	git3_vector_foreach(&image.lines, i, line)
		git3_str_put(out, line->content, line->content_len);

done:
	patch_image_free(&image);

	return error;
}

static int apply_binary_delta(
	git3_str *out,
	const char *source,
	size_t source_len,
	git3_diff_binary_file *binary_file)
{
	git3_str inflated = GIT3_STR_INIT;
	int error = 0;

	/* no diff means identical contents */
	if (binary_file->datalen == 0)
		return git3_str_put(out, source, source_len);

	error = git3_zstream_inflatebuf(&inflated,
		binary_file->data, binary_file->datalen);

	if (!error && inflated.size != binary_file->inflatedlen) {
		error = apply_err("inflated delta does not match expected length");
		git3_str_dispose(out);
	}

	if (error < 0)
		goto done;

	if (binary_file->type == GIT3_DIFF_BINARY_DELTA) {
		void *data;
		size_t data_len;

		error = git3_delta_apply(&data, &data_len, (void *)source, source_len,
			(void *)inflated.ptr, inflated.size);

		out->ptr = data;
		out->size = data_len;
		out->asize = data_len;
	}
	else if (binary_file->type == GIT3_DIFF_BINARY_LITERAL) {
		git3_str_swap(out, &inflated);
	}
	else {
		error = apply_err("unknown binary delta type");
		goto done;
	}

done:
	git3_str_dispose(&inflated);
	return error;
}

static int apply_binary(
	git3_str *out,
	const char *source,
	size_t source_len,
	git3_patch *patch)
{
	git3_str reverse = GIT3_STR_INIT;
	int error = 0;

	if (!patch->binary.contains_data) {
		error = apply_err("patch does not contain binary data");
		goto done;
	}

	if (!patch->binary.old_file.datalen && !patch->binary.new_file.datalen)
		goto done;

	/* first, apply the new_file delta to the given source */
	if ((error = apply_binary_delta(out, source, source_len,
			&patch->binary.new_file)) < 0)
		goto done;

	/* second, apply the old_file delta to sanity check the result */
	if ((error = apply_binary_delta(&reverse, out->ptr, out->size,
			&patch->binary.old_file)) < 0)
		goto done;

	/* Verify that the resulting file with the reverse patch applied matches the source file */
	if (source_len != reverse.size ||
		(source_len && memcmp(source, reverse.ptr, source_len) != 0)) {
		error = apply_err("binary patch did not apply cleanly");
		goto done;
	}

done:
	if (error < 0)
		git3_str_dispose(out);

	git3_str_dispose(&reverse);
	return error;
}

int git3_apply__patch(
	git3_str *contents_out,
	char **filename_out,
	unsigned int *mode_out,
	const char *source,
	size_t source_len,
	git3_patch *patch,
	const git3_apply_options *given_opts)
{
	apply_hunks_ctx ctx = { GIT3_APPLY_OPTIONS_INIT };
	char *filename = NULL;
	unsigned int mode = 0;
	int error = 0;

	GIT3_ASSERT_ARG(contents_out);
	GIT3_ASSERT_ARG(filename_out);
	GIT3_ASSERT_ARG(mode_out);
	GIT3_ASSERT_ARG(source || !source_len);
	GIT3_ASSERT_ARG(patch);

	if (given_opts)
		memcpy(&ctx.opts, given_opts, sizeof(git3_apply_options));

	*filename_out = NULL;
	*mode_out = 0;

	if (patch->delta->status != GIT3_DELTA_DELETED) {
		const git3_diff_file *newfile = &patch->delta->new_file;

		filename = git3__strdup(newfile->path);
		mode = newfile->mode ?
			newfile->mode : GIT3_FILEMODE_BLOB;
	}

	if (patch->delta->flags & GIT3_DIFF_FLAG_BINARY)
		error = apply_binary(contents_out, source, source_len, patch);
	else if (patch->hunks.size)
		error = apply_hunks(contents_out, source, source_len, patch, &ctx);
	else
		error = git3_str_put(contents_out, source, source_len);

	if (error)
		goto done;

	if (patch->delta->status == GIT3_DELTA_DELETED &&
		git3_str_len(contents_out) > 0) {
		error = apply_err("removal patch leaves file contents");
		goto done;
	}

	*filename_out = filename;
	*mode_out = mode;

done:
	if (error < 0)
		git3__free(filename);

	return error;
}

static int apply_one(
	git3_repository *repo,
	git3_reader *preimage_reader,
	git3_index *preimage,
	git3_reader *postimage_reader,
	git3_index *postimage,
	git3_diff *diff,
	git3_hashset_str *removed_paths,
	size_t i,
	const git3_apply_options *opts)
{
	git3_patch *patch = NULL;
	git3_str pre_contents = GIT3_STR_INIT, post_contents = GIT3_STR_INIT;
	const git3_diff_delta *delta;
	char *filename = NULL;
	unsigned int mode;
	git3_oid pre_id, post_id;
	git3_filemode_t pre_filemode;
	git3_index_entry pre_entry, post_entry;
	bool skip_preimage = false;
	int error;

	if ((error = git3_patch_from_diff(&patch, diff, i)) < 0)
		goto done;

	delta = git3_patch_get_delta(patch);

	if (opts->delta_cb) {
		error = opts->delta_cb(delta, opts->payload);

		if (error) {
			if (error > 0)
				error = 0;

			goto done;
		}
	}

	/*
	 * Ensure that the file has not been deleted or renamed if we're
	 * applying a modification delta.
	 */
	if (delta->status != GIT3_DELTA_RENAMED &&
	    delta->status != GIT3_DELTA_ADDED) {
		if (git3_hashset_str_contains(removed_paths, delta->old_file.path)) {
			error = apply_err("path '%s' has been renamed or deleted", delta->old_file.path);
			goto done;
		}
	}

	/*
	 * We may be applying a second delta to an already seen file.  If so,
	 * use the already modified data in the postimage instead of the
	 * content from the index or working directory.  (Don't do this in
	 * the case of a rename, which must be specified before additional
	 * deltas since we apply deltas to the target filename.)
	 */
	if (delta->status != GIT3_DELTA_RENAMED) {
		if ((error = git3_reader_read(&pre_contents, &pre_id, &pre_filemode,
		    postimage_reader, delta->old_file.path)) == 0) {
			skip_preimage = true;
		} else if (error == GIT3_ENOTFOUND) {
			git3_error_clear();
			error = 0;
		} else {
			goto done;
		}
	}

	if (!skip_preimage && delta->status != GIT3_DELTA_ADDED) {
		error = git3_reader_read(&pre_contents, &pre_id, &pre_filemode,
			preimage_reader, delta->old_file.path);

		/* ENOTFOUND means the preimage was not found; apply failed. */
		if (error == GIT3_ENOTFOUND)
			error = GIT3_EAPPLYFAIL;

		/* When applying to BOTH, the index did not match the workdir. */
		if (error == GIT3_READER_MISMATCH)
			error = apply_err("%s: does not match index", delta->old_file.path);

		if (error < 0)
			goto done;

		/*
		 * We need to populate the preimage data structure with the
		 * contents that we are using as the preimage for this file.
		 * This allows us to apply patches to files that have been
		 * modified in the working directory.  During checkout,
		 * we will use this expected preimage as the baseline, and
		 * limit checkout to only the paths affected by patch
		 * application.  (Without this, we would fail to write the
		 * postimage contents to any file that had been modified
		 * from HEAD on-disk, even if the patch application succeeded.)
		 * Use the contents from the delta where available - some
		 * fields may not be available, like the old file mode (eg in
		 * an exact rename situation) so trust the patch parsing to
		 * validate and use the preimage data in that case.
		 */
		if (preimage) {
			memset(&pre_entry, 0, sizeof(git3_index_entry));
			pre_entry.path = delta->old_file.path;
			pre_entry.mode = delta->old_file.mode ? delta->old_file.mode : pre_filemode;
			git3_oid_cpy(&pre_entry.id, &pre_id);

			if ((error = git3_index_add(preimage, &pre_entry)) < 0)
				goto done;
		}
	}

	if (delta->status != GIT3_DELTA_DELETED) {
		if ((error = git3_apply__patch(&post_contents, &filename, &mode,
				pre_contents.ptr, pre_contents.size, patch, opts)) < 0 ||
			(error = git3_blob_create_from_buffer(&post_id, repo,
				post_contents.ptr, post_contents.size)) < 0)
			goto done;

		memset(&post_entry, 0, sizeof(git3_index_entry));
		post_entry.path = filename;
		post_entry.mode = mode;
		git3_oid_cpy(&post_entry.id, &post_id);

		if ((error = git3_index_add(postimage, &post_entry)) < 0)
			goto done;
	}

	if (delta->status == GIT3_DELTA_RENAMED ||
	    delta->status == GIT3_DELTA_DELETED)
		error = git3_hashset_str_add(removed_paths, delta->old_file.path);

	if (delta->status == GIT3_DELTA_RENAMED ||
	    delta->status == GIT3_DELTA_ADDED)
		git3_hashset_str_remove(removed_paths, delta->new_file.path);

done:
	git3_str_dispose(&pre_contents);
	git3_str_dispose(&post_contents);
	git3__free(filename);
	git3_patch_free(patch);

	return error;
}

static int apply_deltas(
	git3_repository *repo,
	git3_reader *pre_reader,
	git3_index *preimage,
	git3_reader *post_reader,
	git3_index *postimage,
	git3_diff *diff,
	const git3_apply_options *opts)
{
	git3_hashset_str removed_paths = GIT3_HASHSET_INIT;
	size_t i;
	int error = 0;

	for (i = 0; i < git3_diff_num_deltas(diff); i++) {
		if ((error = apply_one(repo, pre_reader, preimage, post_reader, postimage, diff, &removed_paths, i, opts)) < 0)
			goto done;
	}

done:
	git3_hashset_str_dispose(&removed_paths);
	return error;
}

int git3_apply_to_tree(
	git3_index **out,
	git3_repository *repo,
	git3_tree *preimage,
	git3_diff *diff,
	const git3_apply_options *given_opts)
{
	git3_index *postimage = NULL;
	git3_reader *pre_reader = NULL, *post_reader = NULL;
	git3_index_options index_opts = GIT3_INDEX_OPTIONS_FOR_REPO(repo);
	git3_apply_options opts = GIT3_APPLY_OPTIONS_INIT;
	const git3_diff_delta *delta;
	size_t i;
	int error = 0;

	GIT3_ASSERT_ARG(out);
	GIT3_ASSERT_ARG(repo);
	GIT3_ASSERT_ARG(preimage);
	GIT3_ASSERT_ARG(diff);

	*out = NULL;

	if (given_opts)
		memcpy(&opts, given_opts, sizeof(git3_apply_options));

	if ((error = git3_reader_for_tree(&pre_reader, preimage)) < 0)
		goto done;

	/*
	 * put the current tree into the postimage as-is - the diff will
	 * replace any entries contained therein
	 */
	if ((error = git3_index_new_ext(&postimage, &index_opts)) < 0 ||
		(error = git3_index_read_tree(postimage, preimage)) < 0 ||
		(error = git3_reader_for_index(&post_reader, repo, postimage)) < 0)
		goto done;

	/*
	 * Remove the old paths from the index before applying diffs -
	 * we need to do a full pass to remove them before adding deltas,
	 * in order to handle rename situations.
	 */
	for (i = 0; i < git3_diff_num_deltas(diff); i++) {
		delta = git3_diff_get_delta(diff, i);

		if (delta->status == GIT3_DELTA_DELETED ||
			delta->status == GIT3_DELTA_RENAMED) {
			if ((error = git3_index_remove(postimage,
					delta->old_file.path, 0)) < 0)
				goto done;
		}
	}

	if ((error = apply_deltas(repo, pre_reader, NULL, post_reader, postimage, diff, &opts)) < 0)
		goto done;

	*out = postimage;

done:
	if (error < 0)
		git3_index_free(postimage);

	git3_reader_free(pre_reader);
	git3_reader_free(post_reader);

	return error;
}

static int git3_apply__to_workdir(
	git3_repository *repo,
	git3_diff *diff,
	git3_index *preimage,
	git3_index *postimage,
	git3_apply_location_t location,
	git3_apply_options *opts)
{
	git3_vector paths = GIT3_VECTOR_INIT;
	git3_checkout_options checkout_opts = GIT3_CHECKOUT_OPTIONS_INIT;
	const git3_diff_delta *delta;
	size_t i;
	int error;

	GIT3_UNUSED(opts);

	/*
	 * Limit checkout to the paths affected by the diff; this ensures
	 * that other modifications in the working directory are unaffected.
	 */
	if ((error = git3_vector_init(&paths, git3_diff_num_deltas(diff), NULL)) < 0)
		goto done;

	for (i = 0; i < git3_diff_num_deltas(diff); i++) {
		delta = git3_diff_get_delta(diff, i);

		if ((error = git3_vector_insert(&paths, (void *)delta->old_file.path)) < 0)
			goto done;

		if (strcmp(delta->old_file.path, delta->new_file.path) &&
		    (error = git3_vector_insert(&paths, (void *)delta->new_file.path)) < 0)
			goto done;
	}

	checkout_opts.checkout_strategy |= GIT3_CHECKOUT_DISABLE_PATHSPEC_MATCH;
	checkout_opts.checkout_strategy |= GIT3_CHECKOUT_DONT_WRITE_INDEX;

	if (location == GIT3_APPLY_LOCATION_WORKDIR)
		checkout_opts.checkout_strategy |= GIT3_CHECKOUT_DONT_UPDATE_INDEX;

	checkout_opts.paths.strings = (char **)paths.contents;
	checkout_opts.paths.count = paths.length;

	checkout_opts.baseline_index = preimage;

	error = git3_checkout_index(repo, postimage, &checkout_opts);

done:
	git3_vector_dispose(&paths);
	return error;
}

static int git3_apply__to_index(
	git3_repository *repo,
	git3_diff *diff,
	git3_index *preimage,
	git3_index *postimage,
	git3_apply_options *opts)
{
	git3_index *index = NULL;
	const git3_diff_delta *delta;
	const git3_index_entry *entry;
	size_t i;
	int error;

	GIT3_UNUSED(preimage);
	GIT3_UNUSED(opts);

	if ((error = git3_repository_index(&index, repo)) < 0)
		goto done;

	/* Remove deleted (or renamed) paths from the index. */
	for (i = 0; i < git3_diff_num_deltas(diff); i++) {
		delta = git3_diff_get_delta(diff, i);

		if (delta->status == GIT3_DELTA_DELETED ||
		    delta->status == GIT3_DELTA_RENAMED) {
			if ((error = git3_index_remove(index, delta->old_file.path, 0)) < 0)
				goto done;
		}
	}

	/* Then add the changes back to the index. */
	for (i = 0; i < git3_index_entrycount(postimage); i++) {
		entry = git3_index_get_byindex(postimage, i);

		if ((error = git3_index_add(index, entry)) < 0)
			goto done;
	}

done:
	git3_index_free(index);
	return error;
}

int git3_apply_options_init(git3_apply_options *opts, unsigned int version)
{
	GIT3_ASSERT_ARG(opts);

	GIT3_INIT_STRUCTURE_FROM_TEMPLATE(
		opts, version, git3_apply_options, GIT3_APPLY_OPTIONS_INIT);
	return 0;
}

/*
 * Handle the three application options ("locations"):
 *
 * GIT3_APPLY_LOCATION_WORKDIR: the default, emulates `git apply`.
 * Applies the diff only to the workdir items and ignores the index
 * entirely.
 *
 * GIT3_APPLY_LOCATION_INDEX: emulates `git apply --cached`.
 * Applies the diff only to the index items and ignores the workdir
 * completely.
 *
 * GIT3_APPLY_LOCATION_BOTH: emulates `git apply --index`.
 * Applies the diff to both the index items and the working directory
 * items.
 */

int git3_apply(
	git3_repository *repo,
	git3_diff *diff,
	git3_apply_location_t location,
	const git3_apply_options *given_opts)
{
	git3_indexwriter indexwriter = GIT3_INDEXWRITER_INIT;
	git3_index *index = NULL, *preimage = NULL, *postimage = NULL;
	git3_reader *pre_reader = NULL, *post_reader = NULL;
	git3_apply_options opts = GIT3_APPLY_OPTIONS_INIT;
	git3_index_options index_opts = GIT3_INDEX_OPTIONS_FOR_REPO(repo);
	int error = GIT3_EINVALID;

	GIT3_ASSERT_ARG(repo);
	GIT3_ASSERT_ARG(diff);

	GIT3_ERROR_CHECK_VERSION(
		given_opts, GIT3_APPLY_OPTIONS_VERSION, "git3_apply_options");

	if (given_opts)
		memcpy(&opts, given_opts, sizeof(git3_apply_options));

	/*
	 * by default, we apply a patch directly to the working directory;
	 * in `--cached` or `--index` mode, we apply to the contents already
	 * in the index.
	 */
	switch (location) {
	case GIT3_APPLY_LOCATION_BOTH:
		error = git3_reader_for_workdir(&pre_reader, repo, true);
		break;
	case GIT3_APPLY_LOCATION_INDEX:
		error = git3_reader_for_index(&pre_reader, repo, NULL);
		break;
	case GIT3_APPLY_LOCATION_WORKDIR:
		error = git3_reader_for_workdir(&pre_reader, repo, false);
		break;
	default:
		GIT3_ASSERT(false);
	}

	if (error < 0)
		goto done;

	/*
	 * Build the preimage and postimage (differences).  Note that
	 * this is not the complete preimage or postimage, it only
	 * contains the files affected by the patch.  We want to avoid
	 * having the full repo index, so we will limit our checkout
	 * to only write these files that were affected by the diff.
	 */
	if ((error = git3_index_new_ext(&preimage, &index_opts)) < 0 ||
	    (error = git3_index_new_ext(&postimage, &index_opts)) < 0 ||
	    (error = git3_reader_for_index(&post_reader, repo, postimage)) < 0)
		goto done;

	if (!(opts.flags & GIT3_APPLY_CHECK))
		if ((error = git3_repository_index(&index, repo)) < 0 ||
		    (error = git3_indexwriter_init(&indexwriter, index)) < 0)
			goto done;

	if ((error = apply_deltas(repo, pre_reader, preimage, post_reader, postimage, diff, &opts)) < 0)
		goto done;

	if ((opts.flags & GIT3_APPLY_CHECK))
		goto done;

	switch (location) {
	case GIT3_APPLY_LOCATION_BOTH:
		error = git3_apply__to_workdir(repo, diff, preimage, postimage, location, &opts);
		break;
	case GIT3_APPLY_LOCATION_INDEX:
		error = git3_apply__to_index(repo, diff, preimage, postimage, &opts);
		break;
	case GIT3_APPLY_LOCATION_WORKDIR:
		error = git3_apply__to_workdir(repo, diff, preimage, postimage, location, &opts);
		break;
	default:
		GIT3_ASSERT(false);
	}

	if (error < 0)
		goto done;

	error = git3_indexwriter_commit(&indexwriter);

done:
	git3_indexwriter_cleanup(&indexwriter);
	git3_index_free(postimage);
	git3_index_free(preimage);
	git3_index_free(index);
	git3_reader_free(pre_reader);
	git3_reader_free(post_reader);

	return error;
}
