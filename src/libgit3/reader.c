/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "reader.h"

#include "futils.h"
#include "blob.h"

#include "git3/tree.h"
#include "git3/blob.h"
#include "git3/index.h"
#include "git3/repository.h"

/* tree reader */

typedef struct {
	git3_reader reader;
	git3_tree *tree;
} tree_reader;

static int tree_reader_read(
	git3_str *out,
	git3_oid *out_id,
	git3_filemode_t *out_filemode,
	git3_reader *_reader,
	const char *filename)
{
	tree_reader *reader = (tree_reader *)_reader;
	git3_tree_entry *tree_entry = NULL;
	git3_blob *blob = NULL;
	git3_object_size_t blobsize;
	int error;

	if ((error = git3_tree_entry_bypath(&tree_entry, reader->tree, filename)) < 0 ||
	    (error = git3_blob_lookup(&blob, git3_tree_owner(reader->tree), git3_tree_entry_id(tree_entry))) < 0)
		goto done;

	blobsize = git3_blob_rawsize(blob);
	GIT3_ERROR_CHECK_BLOBSIZE(blobsize);

	if ((error = git3_str_set(out, git3_blob_rawcontent(blob), (size_t)blobsize)) < 0)
		goto done;

	if (out_id)
		git3_oid_cpy(out_id, git3_tree_entry_id(tree_entry));

	if (out_filemode)
		*out_filemode = git3_tree_entry_filemode(tree_entry);

done:
	git3_blob_free(blob);
	git3_tree_entry_free(tree_entry);
	return error;
}

int git3_reader_for_tree(git3_reader **out, git3_tree *tree)
{
	tree_reader *reader;

	GIT3_ASSERT_ARG(out);
	GIT3_ASSERT_ARG(tree);

	reader = git3__calloc(1, sizeof(tree_reader));
	GIT3_ERROR_CHECK_ALLOC(reader);

	reader->reader.read = tree_reader_read;
	reader->tree = tree;

	*out = (git3_reader *)reader;
	return 0;
}

/* workdir reader */

typedef struct {
	git3_reader reader;
	git3_repository *repo;
	git3_index *index;
} workdir_reader;

static int workdir_reader_read(
	git3_str *out,
	git3_oid *out_id,
	git3_filemode_t *out_filemode,
	git3_reader *_reader,
	const char *filename)
{
	workdir_reader *reader = (workdir_reader *)_reader;
	git3_str path = GIT3_STR_INIT;
	struct stat st;
	git3_filemode_t filemode;
	git3_filter_list *filters = NULL;
	const git3_index_entry *idx_entry;
	git3_oid id;
	int error;

	if ((error = git3_repository_workdir_path(&path, reader->repo, filename)) < 0)
		goto done;

	if ((error = p_lstat(path.ptr, &st)) < 0) {
		if (error == -1 && errno == ENOENT)
			error = GIT3_ENOTFOUND;

		git3_error_set(GIT3_ERROR_OS, "could not stat '%s'", path.ptr);
		goto done;
	}

	filemode = git3_futils_canonical_mode(st.st_mode);

	/*
	 * Patch application - for example - uses the filtered version of
	 * the working directory data to match git.  So we will run the
	 * workdir -> ODB filter on the contents in this workdir reader.
	 */
	if ((error = git3_filter_list_load(&filters, reader->repo, NULL, filename,
		GIT3_FILTER_TO_ODB, GIT3_FILTER_DEFAULT)) < 0)
		goto done;

	if ((error = git3_filter_list__apply_to_file(out,
	    filters, reader->repo, path.ptr)) < 0)
		goto done;

	if (out_id || reader->index) {
		if ((error = git3_odb__hash(&id, out->ptr, out->size, GIT3_OBJECT_BLOB, reader->repo->oid_type)) < 0)
			goto done;
	}

	if (reader->index) {
		if (!(idx_entry = git3_index_get_bypath(reader->index, filename, 0)) ||
		    filemode != idx_entry->mode ||
		    !git3_oid_equal(&id, &idx_entry->id)) {
			error = GIT3_READER_MISMATCH;
			goto done;
		}
	}

	if (out_id)
		git3_oid_cpy(out_id, &id);

	if (out_filemode)
		*out_filemode = filemode;

done:
	git3_filter_list_free(filters);
	git3_str_dispose(&path);
	return error;
}

int git3_reader_for_workdir(
	git3_reader **out,
	git3_repository *repo,
	bool validate_index)
{
	workdir_reader *reader;
	int error;

	GIT3_ASSERT_ARG(out);
	GIT3_ASSERT_ARG(repo);

	reader = git3__calloc(1, sizeof(workdir_reader));
	GIT3_ERROR_CHECK_ALLOC(reader);

	reader->reader.read = workdir_reader_read;
	reader->repo = repo;

	if (validate_index &&
	    (error = git3_repository_index__weakptr(&reader->index, repo)) < 0) {
		git3__free(reader);
		return error;
	}

	*out = (git3_reader *)reader;
	return 0;
}

/* index reader */

typedef struct {
	git3_reader reader;
	git3_repository *repo;
	git3_index *index;
} index_reader;

static int index_reader_read(
	git3_str *out,
	git3_oid *out_id,
	git3_filemode_t *out_filemode,
	git3_reader *_reader,
	const char *filename)
{
	index_reader *reader = (index_reader *)_reader;
	const git3_index_entry *entry;
	git3_blob *blob;
	int error;

	if ((entry = git3_index_get_bypath(reader->index, filename, 0)) == NULL)
		return GIT3_ENOTFOUND;

	if ((error = git3_blob_lookup(&blob, reader->repo, &entry->id)) < 0)
		goto done;

	if (out_id)
		git3_oid_cpy(out_id, &entry->id);

	if (out_filemode)
		*out_filemode = entry->mode;

	error = git3_blob__getbuf(out, blob);

done:
	git3_blob_free(blob);
	return error;
}

int git3_reader_for_index(
	git3_reader **out,
	git3_repository *repo,
	git3_index *index)
{
	index_reader *reader;
	int error;

	GIT3_ASSERT_ARG(out);
	GIT3_ASSERT_ARG(repo);

	reader = git3__calloc(1, sizeof(index_reader));
	GIT3_ERROR_CHECK_ALLOC(reader);

	reader->reader.read = index_reader_read;
	reader->repo = repo;

	if (index) {
		reader->index = index;
	} else if ((error = git3_repository_index__weakptr(&reader->index, repo)) < 0) {
		git3__free(reader);
		return error;
	}

	*out = (git3_reader *)reader;
	return 0;
}

/* generic */

int git3_reader_read(
	git3_str *out,
	git3_oid *out_id,
	git3_filemode_t *out_filemode,
	git3_reader *reader,
	const char *filename)
{
	GIT3_ASSERT_ARG(out);
	GIT3_ASSERT_ARG(reader);
	GIT3_ASSERT_ARG(filename);

	return reader->read(out, out_id, out_filemode, reader, filename);
}

void git3_reader_free(git3_reader *reader)
{
	if (!reader)
		return;

	git3__free(reader);
}
