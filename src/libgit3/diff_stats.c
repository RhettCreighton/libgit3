/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "diff_stats.h"

#include "buf.h"
#include "common.h"
#include "vector.h"
#include "diff.h"
#include "patch_generate.h"

#define DIFF_RENAME_FILE_SEPARATOR " => "
#define STATS_FULL_MIN_SCALE 7

typedef struct {
	size_t insertions;
	size_t deletions;
} diff_file_stats;

struct git3_diff_stats {
	git3_diff *diff;
	diff_file_stats *filestats;

	size_t files_changed;
	size_t insertions;
	size_t deletions;

	size_t max_name;
	size_t max_filestat;
	int max_digits;
};

static int digits_for_value(size_t val)
{
	int count = 1;
	size_t placevalue = 10;

	while (val >= placevalue) {
		++count;
		placevalue *= 10;
	}

	return count;
}

static int diff_file_stats_full_to_buf(
	git3_str *out,
	const git3_diff_delta *delta,
	const diff_file_stats *filestat,
	const git3_diff_stats *stats,
	size_t width)
{
	const char *old_path = NULL, *new_path = NULL, *adddel_path = NULL;
	size_t padding;
	git3_object_size_t old_size, new_size;

	old_path = delta->old_file.path;
	new_path = delta->new_file.path;
	old_size = delta->old_file.size;
	new_size = delta->new_file.size;

	if (old_path && new_path && strcmp(old_path, new_path) != 0) {
		size_t common_dirlen;
		int error;

		if ((common_dirlen = git3_fs_path_common_dirlen(old_path, new_path)) &&
		    common_dirlen <= INT_MAX) {
			error = git3_str_printf(out, " %.*s{%s"DIFF_RENAME_FILE_SEPARATOR"%s}",
					       (int) common_dirlen, old_path,
					       old_path + common_dirlen,
					       new_path + common_dirlen);
			padding = stats->max_name + common_dirlen - strlen(old_path)
			          - strlen(new_path) - 2 - strlen(DIFF_RENAME_FILE_SEPARATOR);
		} else {
			error = git3_str_printf(out, " %s" DIFF_RENAME_FILE_SEPARATOR "%s",
					       old_path, new_path);
			padding = stats->max_name - strlen(old_path)
			          - strlen(new_path) - strlen(DIFF_RENAME_FILE_SEPARATOR);
		}

		if (error < 0)
			goto on_error;
	} else {
		adddel_path = new_path ? new_path : old_path;
		if (git3_str_printf(out, " %s", adddel_path) < 0)
			goto on_error;

		padding = stats->max_name - strlen(adddel_path);
	}

	if (git3_str_putcn(out, ' ', padding) < 0 ||
		git3_str_puts(out, " | ") < 0)
		goto on_error;

	if (delta->flags & GIT3_DIFF_FLAG_BINARY) {
		if (git3_str_printf(out,
				"Bin %" PRId64 " -> %" PRId64 " bytes", old_size, new_size) < 0)
			goto on_error;
	}
	else {
		if (git3_str_printf(out,
				"%*" PRIuZ, stats->max_digits,
				filestat->insertions + filestat->deletions) < 0)
			goto on_error;

		if (filestat->insertions || filestat->deletions) {
			if (git3_str_putc(out, ' ') < 0)
				goto on_error;

			if (!width) {
				if (git3_str_putcn(out, '+', filestat->insertions) < 0 ||
					git3_str_putcn(out, '-', filestat->deletions) < 0)
					goto on_error;
			} else {
				size_t total = filestat->insertions + filestat->deletions;
				size_t full = (total * width + stats->max_filestat / 2) /
					stats->max_filestat;
				size_t plus = full * filestat->insertions / total;
				size_t minus = full - plus;

				if (git3_str_putcn(out, '+', max(plus,  1)) < 0 ||
					git3_str_putcn(out, '-', max(minus, 1)) < 0)
					goto on_error;
			}
		}
	}

	git3_str_putc(out, '\n');

on_error:
	return (git3_str_oom(out) ? -1 : 0);
}

static int diff_file_stats_number_to_buf(
	git3_str *out,
	const git3_diff_delta *delta,
	const diff_file_stats *filestats)
{
	int error;
	const char *path = delta->new_file.path;

	if (delta->flags & GIT3_DIFF_FLAG_BINARY)
		error = git3_str_printf(out, "%-8c" "%-8c" "%s\n", '-', '-', path);
	else
		error = git3_str_printf(out, "%-8" PRIuZ "%-8" PRIuZ "%s\n",
			filestats->insertions, filestats->deletions, path);

	return error;
}

static int diff_file_stats_summary_to_buf(
	git3_str *out,
	const git3_diff_delta *delta)
{
	if (delta->old_file.mode != delta->new_file.mode) {
		if (delta->old_file.mode == 0) {
			git3_str_printf(out, " create mode %06o %s\n",
				delta->new_file.mode, delta->new_file.path);
		}
		else if (delta->new_file.mode == 0) {
			git3_str_printf(out, " delete mode %06o %s\n",
				delta->old_file.mode, delta->old_file.path);
		}
		else {
			git3_str_printf(out, " mode change %06o => %06o %s\n",
				delta->old_file.mode, delta->new_file.mode, delta->new_file.path);
		}
	}

	return 0;
}

int git3_diff_get_stats(
	git3_diff_stats **out,
	git3_diff *diff)
{
	size_t i, deltas;
	size_t total_insertions = 0, total_deletions = 0;
	git3_diff_stats *stats = NULL;
	int error = 0;

	GIT3_ASSERT_ARG(out);
	GIT3_ASSERT_ARG(diff);

	stats = git3__calloc(1, sizeof(git3_diff_stats));
	GIT3_ERROR_CHECK_ALLOC(stats);

	deltas = git3_diff_num_deltas(diff);

	stats->filestats = git3__calloc(deltas, sizeof(diff_file_stats));
	if (!stats->filestats) {
		git3__free(stats);
		return -1;
	}

	stats->diff = diff;
	GIT3_REFCOUNT_INC(diff);

	for (i = 0; i < deltas && !error; ++i) {
		git3_patch *patch = NULL;
		size_t add = 0, remove = 0, namelen;
		const git3_diff_delta *delta;

		if ((error = git3_patch_from_diff(&patch, diff, i)) < 0)
			break;

		/* Length calculation for renames mirrors the actual presentation format
		 * generated in diff_file_stats_full_to_buf; namelen is the full length of
		 * what will be printed, taking into account renames and common prefixes.
		 */
		delta = patch->delta;
		namelen = strlen(delta->new_file.path);
		if (delta->old_file.path &&
		    strcmp(delta->old_file.path, delta->new_file.path) != 0) {
			size_t common_dirlen;
			if ((common_dirlen = git3_fs_path_common_dirlen(delta->old_file.path, delta->new_file.path)) &&
			    common_dirlen <= INT_MAX) {
				namelen += strlen(delta->old_file.path) + 2 +
				           strlen(DIFF_RENAME_FILE_SEPARATOR) - common_dirlen;
			} else {
				namelen += strlen(delta->old_file.path) +
				           strlen(DIFF_RENAME_FILE_SEPARATOR);
			}
		}

		/* and, of course, count the line stats */
		error = git3_patch_line_stats(NULL, &add, &remove, patch);

		git3_patch_free(patch);

		stats->filestats[i].insertions = add;
		stats->filestats[i].deletions = remove;

		total_insertions += add;
		total_deletions += remove;

		if (stats->max_name < namelen)
			stats->max_name = namelen;
		if (stats->max_filestat < add + remove)
			stats->max_filestat = add + remove;
	}

	stats->files_changed = deltas;
	stats->insertions = total_insertions;
	stats->deletions = total_deletions;
	stats->max_digits = digits_for_value(stats->max_filestat + 1);

	if (error < 0) {
		git3_diff_stats_free(stats);
		stats = NULL;
	}

	*out = stats;
	return error;
}

size_t git3_diff_stats_files_changed(
	const git3_diff_stats *stats)
{
	GIT3_ASSERT_ARG(stats);

	return stats->files_changed;
}

size_t git3_diff_stats_insertions(
	const git3_diff_stats *stats)
{
	GIT3_ASSERT_ARG(stats);

	return stats->insertions;
}

size_t git3_diff_stats_deletions(
	const git3_diff_stats *stats)
{
	GIT3_ASSERT_ARG(stats);

	return stats->deletions;
}

int git3_diff_stats_to_buf(
	git3_buf *out,
	const git3_diff_stats *stats,
	git3_diff_stats_format_t format,
	size_t width)
{
	GIT3_BUF_WRAP_PRIVATE(out, git3_diff__stats_to_buf, stats, format, width);
}

int git3_diff__stats_to_buf(
	git3_str *out,
	const git3_diff_stats *stats,
	git3_diff_stats_format_t format,
	size_t width)
{
	int error = 0;
	size_t i;
	const git3_diff_delta *delta;

	GIT3_ASSERT_ARG(out);
	GIT3_ASSERT_ARG(stats);

	if (format & GIT3_DIFF_STATS_NUMBER) {
		for (i = 0; i < stats->files_changed; ++i) {
			if ((delta = git3_diff_get_delta(stats->diff, i)) == NULL)
				continue;

			error = diff_file_stats_number_to_buf(
				out, delta, &stats->filestats[i]);
			if (error < 0)
				return error;
		}
	}

	if (format & GIT3_DIFF_STATS_FULL) {
		if (width > 0) {
			if (width > stats->max_name + stats->max_digits + 5)
				width -= (stats->max_name + stats->max_digits + 5);
			if (width < STATS_FULL_MIN_SCALE)
				width = STATS_FULL_MIN_SCALE;
		}
		if (width > stats->max_filestat)
			width = 0;

		for (i = 0; i < stats->files_changed; ++i) {
			if ((delta = git3_diff_get_delta(stats->diff, i)) == NULL)
				continue;

			error = diff_file_stats_full_to_buf(
				out, delta, &stats->filestats[i], stats, width);
			if (error < 0)
				return error;
		}
	}

	if (format & GIT3_DIFF_STATS_FULL || format & GIT3_DIFF_STATS_SHORT) {
		git3_str_printf(
			out, " %" PRIuZ " file%s changed",
			stats->files_changed, stats->files_changed != 1 ? "s" : "");

		if (stats->insertions || stats->deletions == 0)
			git3_str_printf(
				out, ", %" PRIuZ " insertion%s(+)",
				stats->insertions, stats->insertions != 1 ? "s" : "");

		if (stats->deletions || stats->insertions == 0)
			git3_str_printf(
				out, ", %" PRIuZ " deletion%s(-)",
				stats->deletions, stats->deletions != 1 ? "s" : "");

		git3_str_putc(out, '\n');

		if (git3_str_oom(out))
			return -1;
	}

	if (format & GIT3_DIFF_STATS_INCLUDE_SUMMARY) {
		for (i = 0; i < stats->files_changed; ++i) {
			if ((delta = git3_diff_get_delta(stats->diff, i)) == NULL)
				continue;

			error = diff_file_stats_summary_to_buf(out, delta);
			if (error < 0)
				return error;
		}
	}

	return error;
}

void git3_diff_stats_free(git3_diff_stats *stats)
{
	if (stats == NULL)
		return;

	git3_diff_free(stats->diff); /* bumped refcount in constructor */
	git3__free(stats->filestats);
	git3__free(stats);
}
