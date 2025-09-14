/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "blob.h"

#include "git3/common.h"
#include "git3/object.h"
#include "git3/repository.h"
#include "git3/odb_backend.h"

#include "buf.h"
#include "filebuf.h"
#include "filter.h"

const void *git3_blob_rawcontent(const git3_blob *blob)
{
	GIT3_ASSERT_ARG_WITH_RETVAL(blob, NULL);

	if (blob->raw)
		return blob->data.raw.data;
	else
		return git3_odb_object_data(blob->data.odb);
}

git3_object_size_t git3_blob_rawsize(const git3_blob *blob)
{
	GIT3_ASSERT_ARG(blob);

	if (blob->raw)
		return blob->data.raw.size;
	else
		return (git3_object_size_t)git3_odb_object_size(blob->data.odb);
}

int git3_blob__getbuf(git3_str *buffer, git3_blob *blob)
{
	git3_object_size_t size = git3_blob_rawsize(blob);

	GIT3_ERROR_CHECK_BLOBSIZE(size);
	return git3_str_set(buffer, git3_blob_rawcontent(blob), (size_t)size);
}

void git3_blob__free(void *_blob)
{
	git3_blob *blob = (git3_blob *) _blob;
	if (!blob->raw)
		git3_odb_object_free(blob->data.odb);
	git3__free(blob);
}

int git3_blob__parse_raw(void *_blob, const char *data, size_t size, git3_oid_t oid_type)
{
	git3_blob *blob = (git3_blob *) _blob;

	GIT3_ASSERT_ARG(blob);
	GIT3_UNUSED(oid_type);

	blob->raw = 1;
	blob->data.raw.data = data;
	blob->data.raw.size = size;
	return 0;
}

int git3_blob__parse(void *_blob, git3_odb_object *odb_obj, git3_oid_t oid_type)
{
	git3_blob *blob = (git3_blob *) _blob;

	GIT3_ASSERT_ARG(blob);
	GIT3_UNUSED(oid_type);

	git3_cached_obj_incref((git3_cached_obj *)odb_obj);
	blob->raw = 0;
	blob->data.odb = odb_obj;
	return 0;
}

int git3_blob_create_from_buffer(
	git3_oid *id, git3_repository *repo, const void *buffer, size_t len)
{
	int error;
	git3_odb *odb;
	git3_odb_stream *stream;

	GIT3_ASSERT_ARG(id);
	GIT3_ASSERT_ARG(repo);

	if ((error = git3_repository_odb__weakptr(&odb, repo)) < 0 ||
		(error = git3_odb_open_wstream(&stream, odb, len, GIT3_OBJECT_BLOB)) < 0)
		return error;

	if ((error = git3_odb_stream_write(stream, buffer, len)) == 0)
		error = git3_odb_stream_finalize_write(id, stream);

	git3_odb_stream_free(stream);
	return error;
}

static int write_file_stream(
	git3_oid *id, git3_odb *odb, const char *path, git3_object_size_t file_size)
{
	int fd, error;
	char buffer[GIT3_BUFSIZE_FILEIO];
	git3_odb_stream *stream = NULL;
	ssize_t read_len = -1;
	git3_object_size_t written = 0;

	if ((error = git3_odb_open_wstream(
			&stream, odb, file_size, GIT3_OBJECT_BLOB)) < 0)
		return error;

	if ((fd = git3_futils_open_ro(path)) < 0) {
		git3_odb_stream_free(stream);
		return -1;
	}

	while (!error && (read_len = p_read(fd, buffer, sizeof(buffer))) > 0) {
		error = git3_odb_stream_write(stream, buffer, read_len);
		written += read_len;
	}

	p_close(fd);

	if (written != file_size || read_len < 0) {
		git3_error_set(GIT3_ERROR_OS, "failed to read file into stream");
		error = -1;
	}

	if (!error)
		error = git3_odb_stream_finalize_write(id, stream);

	git3_odb_stream_free(stream);
	return error;
}

static int write_file_filtered(
	git3_oid *id,
	git3_object_size_t *size,
	git3_odb *odb,
	const char *full_path,
	git3_filter_list *fl,
	git3_repository* repo)
{
	int error;
	git3_str tgt = GIT3_STR_INIT;

	error = git3_filter_list__apply_to_file(&tgt, fl, repo, full_path);

	/* Write the file to disk if it was properly filtered */
	if (!error) {
		*size = tgt.size;

		error = git3_odb_write(id, odb, tgt.ptr, tgt.size, GIT3_OBJECT_BLOB);
	}

	git3_str_dispose(&tgt);
	return error;
}

static int write_symlink(
	git3_oid *id, git3_odb *odb, const char *path, size_t link_size)
{
	char *link_data;
	ssize_t read_len;
	int error;

	link_data = git3__malloc(link_size);
	GIT3_ERROR_CHECK_ALLOC(link_data);

	read_len = p_readlink(path, link_data, link_size);
	if (read_len != (ssize_t)link_size) {
		git3_error_set(GIT3_ERROR_OS, "failed to create blob: cannot read symlink '%s'", path);
		git3__free(link_data);
		return -1;
	}

	error = git3_odb_write(id, odb, (void *)link_data, link_size, GIT3_OBJECT_BLOB);
	git3__free(link_data);
	return error;
}

int git3_blob__create_from_paths(
	git3_oid *id,
	struct stat *out_st,
	git3_repository *repo,
	const char *content_path,
	const char *hint_path,
	mode_t hint_mode,
	bool try_load_filters)
{
	int error;
	struct stat st;
	git3_odb *odb = NULL;
	git3_object_size_t size;
	mode_t mode;
	git3_str path = GIT3_STR_INIT;

	GIT3_ASSERT_ARG(hint_path || !try_load_filters);

	if (!content_path) {
		if (git3_repository_workdir_path(&path, repo, hint_path) < 0)
			return -1;

		content_path = path.ptr;
	}

	if ((error = git3_fs_path_lstat(content_path, &st)) < 0 ||
		(error = git3_repository_odb(&odb, repo)) < 0)
		goto done;

	if (S_ISDIR(st.st_mode)) {
		git3_error_set(GIT3_ERROR_ODB, "cannot create blob from '%s': it is a directory", content_path);
		error = GIT3_EDIRECTORY;
		goto done;
	}

	if (out_st)
		memcpy(out_st, &st, sizeof(st));

	size = st.st_size;
	mode = hint_mode ? hint_mode : st.st_mode;

	if (S_ISLNK(mode)) {
		error = write_symlink(id, odb, content_path, (size_t)size);
	} else {
		git3_filter_list *fl = NULL;

		if (try_load_filters)
			/* Load the filters for writing this file to the ODB */
			error = git3_filter_list_load(
				&fl, repo, NULL, hint_path,
				GIT3_FILTER_TO_ODB, GIT3_FILTER_DEFAULT);

		if (error < 0)
			/* well, that didn't work */;
		else if (fl == NULL)
			/* No filters need to be applied to the document: we can stream
			 * directly from disk */
			error = write_file_stream(id, odb, content_path, size);
		else {
			/* We need to apply one or more filters */
			error = write_file_filtered(id, &size, odb, content_path, fl, repo);

			git3_filter_list_free(fl);
		}

		/*
		 * TODO: eventually support streaming filtered files, for files
		 * which are bigger than a given threshold. This is not a priority
		 * because applying a filter in streaming mode changes the final
		 * size of the blob, and without knowing its final size, the blob
		 * cannot be written in stream mode to the ODB.
		 *
		 * The plan is to do streaming writes to a tempfile on disk and then
		 * opening streaming that file to the ODB, using
		 * `write_file_stream`.
		 *
		 * CAREFULLY DESIGNED APIS YO
		 */
	}

done:
	git3_odb_free(odb);
	git3_str_dispose(&path);

	return error;
}

int git3_blob_create_from_workdir(
	git3_oid *id, git3_repository *repo, const char *path)
{
	return git3_blob__create_from_paths(id, NULL, repo, NULL, path, 0, true);
}

int git3_blob_create_from_disk(
	git3_oid *id, git3_repository *repo, const char *path)
{
	int error;
	git3_str full_path = GIT3_STR_INIT;
	const char *workdir, *hintpath = NULL;

	if ((error = git3_fs_path_prettify(&full_path, path, NULL)) < 0) {
		git3_str_dispose(&full_path);
		return error;
	}

	workdir  = git3_repository_workdir(repo);

	if (workdir && !git3__prefixcmp(full_path.ptr, workdir))
		hintpath = full_path.ptr + strlen(workdir);

	error = git3_blob__create_from_paths(
		id, NULL, repo, git3_str_cstr(&full_path), hintpath, 0, !!hintpath);

	git3_str_dispose(&full_path);
	return error;
}

typedef struct {
	git3_writestream parent;
	git3_filebuf fbuf;
	git3_repository *repo;
	char *hintpath;
} blob_writestream;

static int blob_writestream_close(git3_writestream *_stream)
{
	blob_writestream *stream = (blob_writestream *) _stream;

	git3_filebuf_cleanup(&stream->fbuf);
	return 0;
}

static void blob_writestream_free(git3_writestream *_stream)
{
	blob_writestream *stream = (blob_writestream *) _stream;

	git3_filebuf_cleanup(&stream->fbuf);
	git3__free(stream->hintpath);
	git3__free(stream);
}

static int blob_writestream_write(git3_writestream *_stream, const char *buffer, size_t len)
{
	blob_writestream *stream = (blob_writestream *) _stream;

	return git3_filebuf_write(&stream->fbuf, buffer, len);
}

int git3_blob_create_from_stream(git3_writestream **out, git3_repository *repo, const char *hintpath)
{
	int error;
	git3_str path = GIT3_STR_INIT;
	blob_writestream *stream;

	GIT3_ASSERT_ARG(out);
	GIT3_ASSERT_ARG(repo);

	stream = git3__calloc(1, sizeof(blob_writestream));
	GIT3_ERROR_CHECK_ALLOC(stream);

	if (hintpath) {
		stream->hintpath = git3__strdup(hintpath);
		GIT3_ERROR_CHECK_ALLOC(stream->hintpath);
	}

	stream->repo = repo;
	stream->parent.write = blob_writestream_write;
	stream->parent.close = blob_writestream_close;
	stream->parent.free  = blob_writestream_free;

	if ((error = git3_repository__item_path(&path, repo, GIT3_REPOSITORY_ITEM_OBJECTS)) < 0
		|| (error = git3_str_joinpath(&path, path.ptr, "streamed")) < 0)
		goto cleanup;

	if ((error = git3_filebuf_open_withsize(&stream->fbuf, git3_str_cstr(&path), GIT3_FILEBUF_TEMPORARY,
					       0666, 2 * 1024 * 1024)) < 0)
		goto cleanup;

	*out = (git3_writestream *) stream;

cleanup:
	if (error < 0)
		blob_writestream_free((git3_writestream *) stream);

	git3_str_dispose(&path);
	return error;
}

int git3_blob_create_from_stream_commit(git3_oid *out, git3_writestream *_stream)
{
	int error;
	blob_writestream *stream = (blob_writestream *) _stream;

	/*
	 * We can make this more officient by avoiding writing to
	 * disk, but for now let's re-use the helper functions we
	 * have.
	 */
	if ((error = git3_filebuf_flush(&stream->fbuf)) < 0)
		goto cleanup;

	error = git3_blob__create_from_paths(out, NULL, stream->repo, stream->fbuf.path_lock,
					    stream->hintpath, 0, !!stream->hintpath);

cleanup:
	blob_writestream_free(_stream);
	return error;

}

int git3_blob_is_binary(const git3_blob *blob)
{
	git3_str content = GIT3_STR_INIT;
	git3_object_size_t size;

	GIT3_ASSERT_ARG(blob);

	size = git3_blob_rawsize(blob);

	git3_str_attach_notowned(&content, git3_blob_rawcontent(blob),
		(size_t)min(size, GIT3_FILTER_BYTES_TO_CHECK_NUL));
	return git3_str_is_binary(&content);
}

int git3_blob_data_is_binary(const char *str, size_t len)
{
	git3_str content = GIT3_STR_INIT;

	git3_str_attach_notowned(&content, str, len);

	return git3_str_is_binary(&content);
}

int git3_blob_filter_options_init(
	git3_blob_filter_options *opts,
	unsigned int version)
{
	GIT3_INIT_STRUCTURE_FROM_TEMPLATE(opts, version,
		git3_blob_filter_options, GIT3_BLOB_FILTER_OPTIONS_INIT);
	return 0;
}

int git3_blob_filter(
	git3_buf *out,
	git3_blob *blob,
	const char *path,
	git3_blob_filter_options *given_opts)
{
	git3_blob_filter_options opts = GIT3_BLOB_FILTER_OPTIONS_INIT;
	git3_filter_options filter_opts = GIT3_FILTER_OPTIONS_INIT;
	git3_filter_list *fl = NULL;
	int error = 0;

	GIT3_ASSERT_ARG(blob);
	GIT3_ASSERT_ARG(path);
	GIT3_ASSERT_ARG(out);

	GIT3_ERROR_CHECK_VERSION(
		given_opts, GIT3_BLOB_FILTER_OPTIONS_VERSION, "git3_blob_filter_options");

	if (given_opts != NULL)
		memcpy(&opts, given_opts, sizeof(git3_blob_filter_options));

	if ((opts.flags & GIT3_BLOB_FILTER_CHECK_FOR_BINARY) != 0 &&
	    git3_blob_is_binary(blob))
		return 0;

	if ((opts.flags & GIT3_BLOB_FILTER_NO_SYSTEM_ATTRIBUTES) != 0)
		filter_opts.flags |= GIT3_FILTER_NO_SYSTEM_ATTRIBUTES;

	if ((opts.flags & GIT3_BLOB_FILTER_ATTRIBUTES_FROM_HEAD) != 0)
		filter_opts.flags |= GIT3_FILTER_ATTRIBUTES_FROM_HEAD;

	if ((opts.flags & GIT3_BLOB_FILTER_ATTRIBUTES_FROM_COMMIT) != 0) {
		filter_opts.flags |= GIT3_FILTER_ATTRIBUTES_FROM_COMMIT;

#ifndef GIT3_DEPRECATE_HARD
		if (opts.commit_id)
			git3_oid_cpy(&filter_opts.attr_commit_id, opts.commit_id);
		else
#endif
		git3_oid_cpy(&filter_opts.attr_commit_id, &opts.attr_commit_id);
	}

	if (!(error = git3_filter_list_load_ext(
			&fl, git3_blob_owner(blob), blob, path,
			GIT3_FILTER_TO_WORKTREE, &filter_opts))) {

		error = git3_filter_list_apply_to_blob(out, fl, blob);

		git3_filter_list_free(fl);
	}

	return error;
}

/* Deprecated functions */

#ifndef GIT3_DEPRECATE_HARD
int git3_blob_create_frombuffer(
	git3_oid *id, git3_repository *repo, const void *buffer, size_t len)
{
	return git3_blob_create_from_buffer(id, repo, buffer, len);
}

int git3_blob_create_fromworkdir(git3_oid *id, git3_repository *repo, const char *relative_path)
{
	return git3_blob_create_from_workdir(id, repo, relative_path);
}

int git3_blob_create_fromdisk(git3_oid *id, git3_repository *repo, const char *path)
{
	return git3_blob_create_from_disk(id, repo, path);
}

int git3_blob_create_fromstream(
    git3_writestream **out,
    git3_repository *repo,
    const char *hintpath)
{
	return  git3_blob_create_from_stream(out, repo, hintpath);
}

int git3_blob_create_fromstream_commit(
	git3_oid *out,
	git3_writestream *stream)
{
	return git3_blob_create_from_stream_commit(out, stream);
}

int git3_blob_filtered_content(
	git3_buf *out,
	git3_blob *blob,
	const char *path,
	int check_for_binary_data)
{
	git3_blob_filter_options opts = GIT3_BLOB_FILTER_OPTIONS_INIT;

	if (check_for_binary_data)
		opts.flags |= GIT3_BLOB_FILTER_CHECK_FOR_BINARY;
	else
		opts.flags &= ~GIT3_BLOB_FILTER_CHECK_FOR_BINARY;

	return git3_blob_filter(out, blob, path, &opts);
}
#endif
