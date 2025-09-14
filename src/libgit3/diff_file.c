/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "diff_file.h"

#include "git3/blob.h"
#include "git3/submodule.h"
#include "diff.h"
#include "diff_generate.h"
#include "odb.h"
#include "futils.h"
#include "filter.h"

#define DIFF_MAX_FILESIZE 0x20000000

static bool diff_file_content_binary_by_size(git3_diff_file_content *fc)
{
	/* if we have diff opts, check max_size vs file size */
	if ((fc->file->flags & DIFF_FLAGS_KNOWN_BINARY) == 0 &&
		fc->opts_max_size > 0 &&
		fc->file->size > fc->opts_max_size)
		fc->file->flags |= GIT3_DIFF_FLAG_BINARY;

	return ((fc->file->flags & GIT3_DIFF_FLAG_BINARY) != 0);
}

static void diff_file_content_binary_by_content(git3_diff_file_content *fc)
{
	if ((fc->file->flags & DIFF_FLAGS_KNOWN_BINARY) != 0)
		return;

	switch (git3_diff_driver_content_is_binary(
		fc->driver, fc->map.data, fc->map.len)) {
	case 0: fc->file->flags |= GIT3_DIFF_FLAG_NOT_BINARY; break;
	case 1: fc->file->flags |= GIT3_DIFF_FLAG_BINARY; break;
	default: break;
	}
}

static int diff_file_content_init_common(
	git3_diff_file_content *fc, const git3_diff_options *opts)
{
	fc->opts_flags = opts ? opts->flags : GIT3_DIFF_NORMAL;

	if (opts && opts->max_size >= 0)
		fc->opts_max_size = opts->max_size ?
			opts->max_size : DIFF_MAX_FILESIZE;

	if (fc->src == GIT3_ITERATOR_EMPTY)
		fc->src = GIT3_ITERATOR_TREE;

	if (!fc->driver &&
		git3_diff_driver_lookup(&fc->driver, fc->repo,
		    NULL, fc->file->path) < 0)
		return -1;

	/* give driver a chance to modify options */
	git3_diff_driver_update_options(&fc->opts_flags, fc->driver);

	/* make sure file is conceivable mmap-able */
	if ((size_t)fc->file->size != fc->file->size)
		fc->file->flags |= GIT3_DIFF_FLAG_BINARY;
	/* check if user is forcing text diff the file */
	else if (fc->opts_flags & GIT3_DIFF_FORCE_TEXT) {
		fc->file->flags &= ~GIT3_DIFF_FLAG_BINARY;
		fc->file->flags |= GIT3_DIFF_FLAG_NOT_BINARY;
	}
	/* check if user is forcing binary diff the file */
	else if (fc->opts_flags & GIT3_DIFF_FORCE_BINARY) {
		fc->file->flags &= ~GIT3_DIFF_FLAG_NOT_BINARY;
		fc->file->flags |= GIT3_DIFF_FLAG_BINARY;
	}

	diff_file_content_binary_by_size(fc);

	if ((fc->flags & GIT3_DIFF_FLAG__NO_DATA) != 0) {
		fc->flags |= GIT3_DIFF_FLAG__LOADED;
		fc->map.len  = 0;
		fc->map.data = "";
	}

	if ((fc->flags & GIT3_DIFF_FLAG__LOADED) != 0)
		diff_file_content_binary_by_content(fc);

	return 0;
}

int git3_diff_file_content__init_from_diff(
	git3_diff_file_content *fc,
	git3_diff *diff,
	git3_diff_delta *delta,
	bool use_old)
{
	bool has_data = true;

	memset(fc, 0, sizeof(*fc));
	fc->repo = diff->repo;
	fc->file = use_old ? &delta->old_file : &delta->new_file;
	fc->src  = use_old ? diff->old_src : diff->new_src;

	if (git3_diff_driver_lookup(&fc->driver, fc->repo,
		    &diff->attrsession, fc->file->path) < 0)
		return -1;

	switch (delta->status) {
	case GIT3_DELTA_ADDED:
		has_data = !use_old; break;
	case GIT3_DELTA_DELETED:
		has_data = use_old; break;
	case GIT3_DELTA_UNTRACKED:
		has_data = (use_old == (diff->opts.flags & GIT3_DIFF_REVERSE)) &&
			(diff->opts.flags & GIT3_DIFF_SHOW_UNTRACKED_CONTENT) != 0;
		break;
	case GIT3_DELTA_UNREADABLE:
	case GIT3_DELTA_MODIFIED:
	case GIT3_DELTA_COPIED:
	case GIT3_DELTA_RENAMED:
		break;
	default:
		has_data = false;
		break;
	}

	if (!has_data)
		fc->flags |= GIT3_DIFF_FLAG__NO_DATA;

	return diff_file_content_init_common(fc, &diff->opts);
}

int git3_diff_file_content__init_from_src(
	git3_diff_file_content *fc,
	git3_repository *repo,
	const git3_diff_options *opts,
	const git3_diff_file_content_src *src,
	git3_diff_file *as_file)
{
	memset(fc, 0, sizeof(*fc));
	fc->repo = repo;
	fc->file = as_file;

	if (!src->blob && !src->buf) {
		fc->flags |= GIT3_DIFF_FLAG__NO_DATA;
		git3_oid_clear(&fc->file->id, opts->oid_type);
	} else {
		fc->flags |= GIT3_DIFF_FLAG__LOADED;
		fc->file->flags |= GIT3_DIFF_FLAG_VALID_ID;
		fc->file->mode = GIT3_FILEMODE_BLOB;

		if (src->blob) {
			git3_blob_dup((git3_blob **)&fc->blob, (git3_blob *) src->blob);
			fc->file->size = git3_blob_rawsize(src->blob);
			git3_oid_cpy(&fc->file->id, git3_blob_id(src->blob));
			fc->file->id_abbrev = (uint16_t)git3_oid_hexsize(repo->oid_type);

			fc->map.len  = (size_t)fc->file->size;
			fc->map.data = (char *)git3_blob_rawcontent(src->blob);

			fc->flags |= GIT3_DIFF_FLAG__FREE_BLOB;
		} else {
			int error;
			if ((error = git3_odb__hash(&fc->file->id, src->buf, src->buflen, GIT3_OBJECT_BLOB, opts->oid_type)) < 0)
				return error;
			fc->file->size = src->buflen;
			fc->file->id_abbrev = (uint16_t)git3_oid_hexsize(opts->oid_type);

			fc->map.len  = src->buflen;
			fc->map.data = (char *)src->buf;
		}
	}

	return diff_file_content_init_common(fc, opts);
}

static int diff_file_content_commit_to_str(
	git3_diff_file_content *fc, bool check_status)
{
	char oid[GIT3_OID_MAX_HEXSIZE+1];
	git3_str content = GIT3_STR_INIT;
	const char *status = "";

	if (check_status) {
		int error = 0;
		git3_submodule *sm = NULL;
		unsigned int sm_status = 0;
		const git3_oid *sm_head;

		if ((error = git3_submodule_lookup(&sm, fc->repo, fc->file->path)) < 0) {
			/* GIT3_EEXISTS means a "submodule" that has not been git added */
			if (error == GIT3_EEXISTS) {
				git3_error_clear();
				error = 0;
			}
			return error;
		}

		if ((error = git3_submodule_status(&sm_status, fc->repo, fc->file->path, GIT3_SUBMODULE_IGNORE_UNSPECIFIED)) < 0) {
			git3_submodule_free(sm);
			return error;
		}

		/* update OID if we didn't have it previously */
		if ((fc->file->flags & GIT3_DIFF_FLAG_VALID_ID) == 0 &&
			((sm_head = git3_submodule_wd_id(sm)) != NULL ||
			 (sm_head = git3_submodule_head_id(sm)) != NULL))
		{
			git3_oid_cpy(&fc->file->id, sm_head);
			fc->file->flags |= GIT3_DIFF_FLAG_VALID_ID;
		}

		if (GIT3_SUBMODULE_STATUS_IS_WD_DIRTY(sm_status))
			status = "-dirty";

		git3_submodule_free(sm);
	}

	git3_oid_tostr(oid, sizeof(oid), &fc->file->id);
	if (git3_str_printf(&content, "Subproject commit %s%s\n", oid, status) < 0)
		return -1;

	fc->map.len  = git3_str_len(&content);
	fc->map.data = git3_str_detach(&content);
	fc->flags |= GIT3_DIFF_FLAG__FREE_DATA;

	return 0;
}

static int diff_file_content_load_blob(
	git3_diff_file_content *fc,
	git3_diff_options *opts)
{
	int error = 0;
	git3_odb_object *odb_obj = NULL;

	if (git3_oid_is_zero(&fc->file->id))
		return 0;

	if (fc->file->mode == GIT3_FILEMODE_COMMIT)
		return diff_file_content_commit_to_str(fc, false);

	/* if we don't know size, try to peek at object header first */
	if (!fc->file->size) {
		if ((error = git3_diff_file__resolve_zero_size(
				fc->file, &odb_obj, fc->repo)) < 0)
			return error;
	}

	if ((opts->flags & GIT3_DIFF_SHOW_BINARY) == 0 &&
		diff_file_content_binary_by_size(fc))
		return 0;

	if (odb_obj != NULL) {
		error = git3_object__from_odb_object(
			(git3_object **)&fc->blob, fc->repo, odb_obj, GIT3_OBJECT_BLOB);
		git3_odb_object_free(odb_obj);
	} else {
		error = git3_blob_lookup(
			(git3_blob **)&fc->blob, fc->repo, &fc->file->id);
	}

	if (!error) {
		fc->flags |= GIT3_DIFF_FLAG__FREE_BLOB;
		fc->map.data = (void *)git3_blob_rawcontent(fc->blob);
		fc->map.len  = (size_t)git3_blob_rawsize(fc->blob);
	}

	return error;
}

static int diff_file_content_load_workdir_symlink_fake(
	git3_diff_file_content *fc, git3_str *path)
{
	git3_str target = GIT3_STR_INIT;
	int error;

	if ((error = git3_futils_readbuffer(&target, path->ptr)) < 0)
		return error;

	fc->map.len = git3_str_len(&target);
	fc->map.data = git3_str_detach(&target);
	fc->flags |= GIT3_DIFF_FLAG__FREE_DATA;

	git3_str_dispose(&target);
	return error;
}

static int diff_file_content_load_workdir_symlink(
	git3_diff_file_content *fc, git3_str *path)
{
	ssize_t alloc_len, read_len;
	int symlink_supported, error;

	if ((error = git3_repository__configmap_lookup(
		&symlink_supported, fc->repo, GIT3_CONFIGMAP_SYMLINKS)) < 0)
		return -1;

	if (!symlink_supported)
		return diff_file_content_load_workdir_symlink_fake(fc, path);

	/* link path on disk could be UTF-16, so prepare a buffer that is
	 * big enough to handle some UTF-8 data expansion
	 */
	alloc_len = (ssize_t)(fc->file->size * 2) + 1;

	fc->map.data = git3__calloc(alloc_len, sizeof(char));
	GIT3_ERROR_CHECK_ALLOC(fc->map.data);

	fc->flags |= GIT3_DIFF_FLAG__FREE_DATA;

	read_len = p_readlink(git3_str_cstr(path), fc->map.data, alloc_len);
	if (read_len < 0) {
		git3_error_set(GIT3_ERROR_OS, "failed to read symlink '%s'", fc->file->path);
		return -1;
	}

	fc->map.len = read_len;
	return 0;
}

static int diff_file_content_load_workdir_file(
	git3_diff_file_content *fc,
	git3_str *path,
	git3_diff_options *diff_opts)
{
	int error = 0;
	git3_filter_list *fl = NULL;
	git3_file fd = git3_futils_open_ro(git3_str_cstr(path));
	git3_str raw = GIT3_STR_INIT;
	git3_object_size_t new_file_size = 0;

	if (fd < 0)
		return fd;

	error = git3_futils_filesize(&new_file_size, fd);

	if (error < 0)
		goto cleanup;

	if (!(fc->file->flags & GIT3_DIFF_FLAG_VALID_SIZE)) {
		fc->file->size = new_file_size;
		fc->file->flags |= GIT3_DIFF_FLAG_VALID_SIZE;
	} else if (fc->file->size != new_file_size) {
		git3_error_set(GIT3_ERROR_FILESYSTEM, "file changed before we could read it");
		error = -1;
		goto cleanup;
	}

	/* if file is empty, don't attempt to mmap or readbuffer */
	if (fc->file->size == 0) {
		fc->map.len = 0;
		fc->map.data = git3_str__initstr;
		goto cleanup;
	}

	if ((diff_opts->flags & GIT3_DIFF_SHOW_BINARY) == 0 &&
		diff_file_content_binary_by_size(fc))
		goto cleanup;

	if ((error = git3_filter_list_load(
			&fl, fc->repo, NULL, fc->file->path,
			GIT3_FILTER_TO_ODB, GIT3_FILTER_ALLOW_UNSAFE)) < 0)
		goto cleanup;

	/* if there are no filters, try to mmap the file */
	if (fl == NULL) {
		if (!(error = git3_futils_mmap_ro(
				&fc->map, fd, 0, (size_t)fc->file->size))) {
			fc->flags |= GIT3_DIFF_FLAG__UNMAP_DATA;
			goto cleanup;
		}

		/* if mmap failed, fall through to try readbuffer below */
		git3_error_clear();
	}

	if (!(error = git3_futils_readbuffer_fd(&raw, fd, (size_t)fc->file->size))) {
		git3_str out = GIT3_STR_INIT;

		error = git3_filter_list__convert_buf(&out, fl, &raw);

		if (!error) {
			fc->map.len  = out.size;
			fc->map.data = out.ptr;
			fc->flags |= GIT3_DIFF_FLAG__FREE_DATA;
		}
	}

cleanup:
	git3_filter_list_free(fl);
	p_close(fd);

	return error;
}

static int diff_file_content_load_workdir(
	git3_diff_file_content *fc,
	git3_diff_options *diff_opts)
{
	int error = 0;
	git3_str path = GIT3_STR_INIT;

	if (fc->file->mode == GIT3_FILEMODE_COMMIT)
		return diff_file_content_commit_to_str(fc, true);

	if (fc->file->mode == GIT3_FILEMODE_TREE)
		return 0;

	if (git3_repository_workdir_path(&path, fc->repo, fc->file->path) < 0)
		return -1;

	if (S_ISLNK(fc->file->mode))
		error = diff_file_content_load_workdir_symlink(fc, &path);
	else
		error = diff_file_content_load_workdir_file(fc, &path, diff_opts);

	/* once data is loaded, update OID if we didn't have it previously */
	if (!error && (fc->file->flags & GIT3_DIFF_FLAG_VALID_ID) == 0) {
		error = git3_odb__hash(
			&fc->file->id, fc->map.data, fc->map.len,
			GIT3_OBJECT_BLOB, diff_opts->oid_type);
		fc->file->flags |= GIT3_DIFF_FLAG_VALID_ID;
	}

	git3_str_dispose(&path);
	return error;
}

int git3_diff_file_content__load(
	git3_diff_file_content *fc,
	git3_diff_options *diff_opts)
{
	int error = 0;

	if ((fc->flags & GIT3_DIFF_FLAG__LOADED) != 0)
		return 0;

	if ((fc->file->flags & GIT3_DIFF_FLAG_BINARY) != 0 &&
		(diff_opts->flags & GIT3_DIFF_SHOW_BINARY) == 0)
		return 0;

	if (fc->src == GIT3_ITERATOR_WORKDIR)
		error = diff_file_content_load_workdir(fc, diff_opts);
	else
		error = diff_file_content_load_blob(fc, diff_opts);
	if (error)
		return error;

	fc->flags |= GIT3_DIFF_FLAG__LOADED;

	diff_file_content_binary_by_content(fc);

	return 0;
}

void git3_diff_file_content__unload(git3_diff_file_content *fc)
{
	if ((fc->flags & GIT3_DIFF_FLAG__LOADED) == 0)
		return;

	if (fc->flags & GIT3_DIFF_FLAG__FREE_DATA) {
		git3__free(fc->map.data);
		fc->map.data = "";
		fc->map.len  = 0;
		fc->flags &= ~GIT3_DIFF_FLAG__FREE_DATA;
	}
	else if (fc->flags & GIT3_DIFF_FLAG__UNMAP_DATA) {
		git3_futils_mmap_free(&fc->map);
		fc->map.data = "";
		fc->map.len  = 0;
		fc->flags &= ~GIT3_DIFF_FLAG__UNMAP_DATA;
	}

	if (fc->flags & GIT3_DIFF_FLAG__FREE_BLOB) {
		git3_blob_free((git3_blob *)fc->blob);
		fc->blob = NULL;
		fc->flags &= ~GIT3_DIFF_FLAG__FREE_BLOB;
	}

	fc->flags &= ~GIT3_DIFF_FLAG__LOADED;
}

void git3_diff_file_content__clear(git3_diff_file_content *fc)
{
	git3_diff_file_content__unload(fc);

	/* for now, nothing else to do */
}
