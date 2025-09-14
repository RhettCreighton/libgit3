/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "common.h"

#include <zlib.h>
#include "git3/repository.h"
#include "git3/indexer.h"
#include "git3/sys/odb_backend.h"
#include "delta.h"
#include "futils.h"
#include "hash.h"
#include "midx.h"
#include "mwindow.h"
#include "odb.h"
#include "pack.h"

#include "git3/odb_backend.h"

/* re-freshen pack files no more than every 2 seconds */
#define FRESHEN_FREQUENCY 2

struct pack_backend {
	git3_odb_backend parent;
	git3_odb_backend_pack_options opts;
	git3_midx_file *midx;
	git3_vector midx_packs;
	git3_vector packs;
	struct git3_pack_file *last_found;
	char *pack_folder;
};

struct pack_writepack {
	struct git3_odb_writepack parent;
	git3_indexer *indexer;
};

/**
 * The wonderful tale of a Packed Object lookup query
 * ===================================================
 *	A riveting and epic story of epicness and ASCII
 *			art, presented by yours truly,
 *				Sir Vicent of Marti
 *
 *
 *	Chapter 1: Once upon a time...
 *	Initialization of the Pack Backend
 *	--------------------------------------------------
 *
 * # git3_odb_backend_pack
 * | Creates the pack backend structure, initializes the
 * | callback pointers to our default read() and exist() methods,
 * | and tries to find the `pack` folder, if it exists. ODBs without a `pack`
 * | folder are ignored altogether. If there is a `pack` folder, it tries to
 * | preload all the known packfiles in the ODB.
 * |
 * |-# pack_backend__refresh
 *   | The `multi-pack-index` is loaded if it exists and is valid.
 *   | Then we run a `dirent` callback through every file in the pack folder,
 *   | even those present in `multi-pack-index`. The unindexed packfiles are
 *   | then sorted according to a sorting callback.
 *   |
 *   |-# refresh_multi_pack_index
 *   |   Detect the presence of the `multi-pack-index` file. If it needs to be
 *   |   refreshed, frees the old copy and tries to load the new one, together
 *   |   with all the packfiles it indexes. If the process fails, fall back to
 *   |   the old behavior, as if the `multi-pack-index` file was not there.
 *   |
 *   |-# packfile_load__cb
 *   | | This callback is called from `dirent` with every single file
 *   | | inside the pack folder. We find the packs by actually locating
 *   | | their index (ends in ".idx"). From that index, we verify that
 *   | | the corresponding packfile exists and is valid, and if so, we
 *   | | add it to the pack list.
 *   | |
 *   | # git3_mwindow_get_pack
 *   |   Make sure that there's a packfile to back this index, and store
 *   |   some very basic information regarding the packfile itself,
 *   |   such as the full path, the size, and the modification time.
 *   |   We don't actually open the packfile to check for internal consistency.
 *   |
 *   |-# packfile_sort__cb
 *       Sort all the preloaded packs according to some specific criteria:
 *       we prioritize the "newer" packs because it's more likely they
 *       contain the objects we are looking for, and we prioritize local
 *       packs over remote ones.
 *
 *
 *
 *	Chapter 2: To be, or not to be...
 *	A standard packed `exist` query for an OID
 *	--------------------------------------------------
 *
 * # pack_backend__exists / pack_backend__exists_prefix
 * | Check if the given oid (or an oid prefix) exists in any of the
 * | packs that have been loaded for our ODB.
 * |
 * |-# pack_entry_find / pack_entry_find_prefix
 *   | If there is a multi-pack-index present, search the oid in that
 *   | index first. If it is not found there, iterate through all the unindexed
 *   | packs that have been preloaded (starting by the pack where the latest
 *   | object was found) to try to find the OID in one of them.
 *   |
 *   |-# git3_midx_entry_find
 *   |   Search for the oid in the multi-pack-index. See
 *   |   <https://github.com/git/git/blob/master/Documentation/technical/pack-format.txt>
 *   |   for specifics on the multi-pack-index format and how do we find
 *   |   entries in it.
 *   |
 *   |-# git3_pack_entry_find
 *     | Check the index of an individual unindexed pack to see if the
 *     | OID can be found. If we can find the offset to that inside of the
 *     | index, that means the object is contained inside of the packfile and
 *     | we can stop searching. Before returning, we verify that the
 *     | packfile behind the index we are searching still exists on disk.
 *     |
 *     |-# pack_entry_find_offset
 *       | Mmap the actual index file to disk if it hasn't been opened
 *       | yet, and run a binary search through it to find the OID.
 *       | See <https://github.com/git/git/blob/master/Documentation/technical/pack-format.txt>
 *       | for specifics on the Packfile Index format and how do we find
 *       | entries in it.
 *       |
 *       |-# pack_index_open
 *         | Guess the name of the index based on the full path to the
 *         | packfile, open it and verify its contents. Only if the index
 *         | has not been opened already.
 *         |
 *         |-# pack_index_check
 *             Mmap the index file and do a quick run through the header
 *             to guess the index version (right now we support v1 and v2),
 *             and to verify that the size of the index makes sense.
 *
 *
 *
 *	Chapter 3: The neverending story...
 *	A standard packed `lookup` query for an OID
 *	--------------------------------------------------
 *
 * # pack_backend__read / pack_backend__read_prefix
 * | Check if the given oid (or an oid prefix) exists in any of the
 * | packs that have been loaded for our ODB. If it does, open the packfile and
 * | read from it.
 * |
 * |-# git3_packfile_unpack
 *     Armed with a packfile and the offset within it, we can finally unpack
 *     the object pointed at by the oid. This involves mmapping part of
 *     the `.pack` file, and uncompressing the object within it (if it is
 *     stored in the undelfitied representation), or finding a base object and
 *     applying some deltas to its uncompressed representation (if it is stored
 *     in the deltified representation). See
 *     <https://github.com/git/git/blob/master/Documentation/technical/pack-format.txt>
 *     for specifics on the Packfile format and how do we read from it.
 *
 */


/***********************************************************
 *
 * FORWARD DECLARATIONS
 *
 ***********************************************************/

static int packfile_sort__cb(const void *a_, const void *b_);

static int packfile_load__cb(void *_data, git3_str *path);

static int packfile_byname_search_cmp(const void *path, const void *pack_entry);

static int pack_entry_find(struct git3_pack_entry *e,
	struct pack_backend *backend, const git3_oid *oid);

/* Can find the offset of an object given
 * a prefix of an identifier.
 * Sets GIT3_EAMBIGUOUS if short oid is ambiguous.
 * This method assumes that len is between
 * GIT3_OID_MINPREFIXLEN and the hexsize for the hash type.
 */
static int pack_entry_find_prefix(
	struct git3_pack_entry *e,
	struct pack_backend *backend,
	const git3_oid *short_oid,
	size_t len);



/***********************************************************
 *
 * PACK WINDOW MANAGEMENT
 *
 ***********************************************************/

static int packfile_byname_search_cmp(const void *path_, const void *p_)
{
	const git3_str *path = (const git3_str *)path_;
	const struct git3_pack_file *p = (const struct git3_pack_file *)p_;

	return strncmp(p->pack_name, git3_str_cstr(path), git3_str_len(path));
}

static int packfile_sort__cb(const void *a_, const void *b_)
{
	const struct git3_pack_file *a = a_;
	const struct git3_pack_file *b = b_;
	int st;

	/*
	 * Local packs tend to contain objects specific to our
	 * variant of the project than remote ones. In addition,
	 * remote ones could be on a network mounted filesystem.
	 * Favor local ones for these reasons.
	 */
	st = a->pack_local - b->pack_local;
	if (st)
		return -st;

	/*
	 * Younger packs tend to contain more recent objects,
	 * and more recent objects tend to get accessed more
	 * often.
	 */
	if (a->mtime < b->mtime)
		return 1;
	else if (a->mtime == b->mtime)
		return 0;

	return -1;
}


static int packfile_load__cb(void *data, git3_str *path)
{
	struct pack_backend *backend = data;
	struct git3_pack_file *pack;
	const char *path_str = git3_str_cstr(path);
	git3_str index_prefix = GIT3_STR_INIT;
	size_t cmp_len = git3_str_len(path);
	int error;

	if (cmp_len <= strlen(".idx") || git3__suffixcmp(path_str, ".idx") != 0)
		return 0; /* not an index */

	cmp_len -= strlen(".idx");
	git3_str_attach_notowned(&index_prefix, path_str, cmp_len);

	if (git3_vector_search2(NULL, &backend->midx_packs, packfile_byname_search_cmp, &index_prefix) == 0)
		return 0;
	if (git3_vector_search2(NULL, &backend->packs, packfile_byname_search_cmp, &index_prefix) == 0)
		return 0;

	error = git3_mwindow_get_pack(&pack, path->ptr, backend->opts.oid_type);

	/* ignore missing .pack file as git does */
	if (error == GIT3_ENOTFOUND) {
		git3_error_clear();
		return 0;
	}

	if (!error)
		error = git3_vector_insert(&backend->packs, pack);

	return error;

}

static int pack_entry_find(struct git3_pack_entry *e, struct pack_backend *backend, const git3_oid *oid)
{
	struct git3_pack_file *last_found = backend->last_found, *p;
	git3_midx_entry midx_entry;
	size_t oid_hexsize = git3_oid_hexsize(backend->opts.oid_type);
	size_t i;

	if (backend->midx &&
		git3_midx_entry_find(&midx_entry, backend->midx, oid, oid_hexsize) == 0 &&
		midx_entry.pack_index < git3_vector_length(&backend->midx_packs)) {
		e->offset = midx_entry.offset;
		git3_oid_cpy(&e->id, &midx_entry.sha1);
		e->p = git3_vector_get(&backend->midx_packs, midx_entry.pack_index);
		return 0;
	}

	if (last_found &&
		git3_pack_entry_find(e, last_found, oid, oid_hexsize) == 0)
		return 0;

	git3_vector_foreach(&backend->packs, i, p) {
		if (p == last_found)
			continue;

		if (git3_pack_entry_find(e, p, oid, oid_hexsize) == 0) {
			backend->last_found = p;
			return 0;
		}
	}

	return git3_odb__error_notfound(
		"failed to find pack entry", oid, oid_hexsize);
}

static int pack_entry_find_prefix(
	struct git3_pack_entry *e,
	struct pack_backend *backend,
	const git3_oid *short_oid,
	size_t len)
{
	int error;
	size_t i;
	git3_oid found_full_oid;
	bool found = false;
	struct git3_pack_file *last_found = backend->last_found, *p;
	git3_midx_entry midx_entry;

#ifdef GIT3_EXPERIMENTAL_SHA256
	git3_oid_clear(&found_full_oid, short_oid->type);
#else
	git3_oid_clear(&found_full_oid, GIT3_OID_SHA3_256);
#endif

	if (backend->midx) {
		error = git3_midx_entry_find(&midx_entry, backend->midx, short_oid, len);
		if (error == GIT3_EAMBIGUOUS)
			return error;
		if (!error && midx_entry.pack_index < git3_vector_length(&backend->midx_packs)) {
			e->offset = midx_entry.offset;
			git3_oid_cpy(&e->id, &midx_entry.sha1);
			e->p = git3_vector_get(&backend->midx_packs, midx_entry.pack_index);
			git3_oid_cpy(&found_full_oid, &e->id);
			found = true;
		}
	}

	if (last_found) {
		error = git3_pack_entry_find(e, last_found, short_oid, len);
		if (error == GIT3_EAMBIGUOUS)
			return error;
		if (!error) {
			if (found && git3_oid_cmp(&e->id, &found_full_oid))
				return git3_odb__error_ambiguous("found multiple pack entries");
			git3_oid_cpy(&found_full_oid, &e->id);
			found = true;
		}
	}

	git3_vector_foreach(&backend->packs, i, p) {
		if (p == last_found)
			continue;

		error = git3_pack_entry_find(e, p, short_oid, len);
		if (error == GIT3_EAMBIGUOUS)
			return error;
		if (!error) {
			if (found && git3_oid_cmp(&e->id, &found_full_oid))
				return git3_odb__error_ambiguous("found multiple pack entries");
			git3_oid_cpy(&found_full_oid, &e->id);
			found = true;
			backend->last_found = p;
		}
	}

	if (!found)
		return git3_odb__error_notfound("no matching pack entry for prefix",
			short_oid, len);
	else
		return 0;
}

/***********************************************************
 *
 * MULTI-PACK-INDEX SUPPORT
 *
 * Functions needed to support the multi-pack-index.
 *
 ***********************************************************/

/*
 * Remove the multi-pack-index, and move all midx_packs to packs.
 */
static int remove_multi_pack_index(struct pack_backend *backend)
{
	size_t i, j = git3_vector_length(&backend->packs);
	struct pack_backend *p;
	int error = git3_vector_size_hint(
			&backend->packs,
			j + git3_vector_length(&backend->midx_packs));
	if (error < 0)
		return error;

	git3_vector_foreach(&backend->midx_packs, i, p)
		git3_vector_set(NULL, &backend->packs, j++, p);
	git3_vector_clear(&backend->midx_packs);

	git3_midx_free(backend->midx);
	backend->midx = NULL;

	return 0;
}

/*
 * Loads a single .pack file referred to by the multi-pack-index. These must
 * match the order in which they are declared in the multi-pack-index file,
 * since these files are referred to by their index.
 */
static int process_multi_pack_index_pack(
		struct pack_backend *backend,
		size_t i,
		const char *packfile_name)
{
	int error;
	struct git3_pack_file *pack;
	size_t found_position;
	git3_str pack_path = GIT3_STR_INIT, index_prefix = GIT3_STR_INIT;

	error = git3_str_joinpath(&pack_path, backend->pack_folder, packfile_name);
	if (error < 0)
		return error;

	/* This is ensured by midx_parse_packfile_name() */
	if (git3_str_len(&pack_path) <= strlen(".idx") || git3__suffixcmp(git3_str_cstr(&pack_path), ".idx") != 0)
		return git3_odb__error_notfound("midx file contained a non-index", NULL, 0);

	git3_str_attach_notowned(&index_prefix, git3_str_cstr(&pack_path), git3_str_len(&pack_path) - strlen(".idx"));

	if (git3_vector_search2(&found_position, &backend->packs, packfile_byname_search_cmp, &index_prefix) == 0) {
		/* Pack was found in the packs list. Moving it to the midx_packs list. */
		git3_str_dispose(&pack_path);
		git3_vector_set(NULL, &backend->midx_packs, i, git3_vector_get(&backend->packs, found_position));
		git3_vector_remove(&backend->packs, found_position);
		return 0;
	}

	/* Pack was not found. Allocate a new one. */
	error = git3_mwindow_get_pack(
		&pack,
		git3_str_cstr(&pack_path),
		backend->opts.oid_type);
	git3_str_dispose(&pack_path);
	if (error < 0)
		return error;

	git3_vector_set(NULL, &backend->midx_packs, i, pack);
	return 0;
}

/*
 * Reads the multi-pack-index. If this fails for whatever reason, the
 * multi-pack-index object is freed, and all the packfiles that are related to
 * it are moved to the unindexed packfiles vector.
 */
static int refresh_multi_pack_index(struct pack_backend *backend)
{
	int error;
	git3_str midx_path = GIT3_STR_INIT;
	const char *packfile_name;
	size_t i;

	error = git3_str_joinpath(&midx_path, backend->pack_folder, "multi-pack-index");
	if (error < 0)
		return error;

	/*
	 * Check whether the multi-pack-index has changed. If it has, close any
	 * old multi-pack-index and move all the packfiles to the unindexed
	 * packs. This is done to prevent losing any open packfiles in case
	 * refreshing the new multi-pack-index fails, or the file is deleted.
	 */
	if (backend->midx) {
		if (!git3_midx_needs_refresh(backend->midx, git3_str_cstr(&midx_path))) {
			git3_str_dispose(&midx_path);
			return 0;
		}
		error = remove_multi_pack_index(backend);
		if (error < 0) {
			git3_str_dispose(&midx_path);
			return error;
		}
	}

	error = git3_midx_open(&backend->midx, git3_str_cstr(&midx_path),
		backend->opts.oid_type);

	git3_str_dispose(&midx_path);
	if (error < 0)
		return error;

	git3_vector_resize_to(&backend->midx_packs, git3_vector_length(&backend->midx->packfile_names));

	git3_vector_foreach(&backend->midx->packfile_names, i, packfile_name) {
		error = process_multi_pack_index_pack(backend, i, packfile_name);
		if (error < 0) {
			/*
			 * Something failed during reading multi-pack-index.
			 * Restore the state of backend as if the
			 * multi-pack-index was never there, and move all
			 * packfiles that have been processed so far to the
			 * unindexed packs.
			 */
			git3_vector_resize_to(&backend->midx_packs, i);
			remove_multi_pack_index(backend);
			return error;
		}
	}

	return 0;
}

/***********************************************************
 *
 * PACKED BACKEND PUBLIC API
 *
 * Implement the git3_odb_backend API calls
 *
 ***********************************************************/
static int pack_backend__refresh(git3_odb_backend *backend_)
{
	int error;
	struct stat st;
	git3_str path = GIT3_STR_INIT;
	struct pack_backend *backend = (struct pack_backend *)backend_;

	if (backend->pack_folder == NULL)
		return 0;

	if (p_stat(backend->pack_folder, &st) < 0 || !S_ISDIR(st.st_mode))
		return git3_odb__error_notfound("failed to refresh packfiles", NULL, 0);

	if (refresh_multi_pack_index(backend) < 0) {
		/*
		 * It is okay if this fails. We will just not use the
		 * multi-pack-index in this case.
		 */
		git3_error_clear();
	}

	/* reload all packs */
	git3_str_sets(&path, backend->pack_folder);
	error = git3_fs_path_direach(&path, 0, packfile_load__cb, backend);

	git3_str_dispose(&path);
	git3_vector_sort(&backend->packs);

	return error;
}

static int pack_backend__read_header(
	size_t *len_p, git3_object_t *type_p,
	struct git3_odb_backend *backend, const git3_oid *oid)
{
	struct git3_pack_entry e;
	int error;

	GIT3_ASSERT_ARG(len_p);
	GIT3_ASSERT_ARG(type_p);
	GIT3_ASSERT_ARG(backend);
	GIT3_ASSERT_ARG(oid);

	if ((error = pack_entry_find(&e, (struct pack_backend *)backend, oid)) < 0)
		return error;

	return git3_packfile_resolve_header(len_p, type_p, e.p, e.offset);
}

static int pack_backend__freshen(
	git3_odb_backend *backend, const git3_oid *oid)
{
	struct git3_pack_entry e;
	time_t now;
	int error;

	if ((error = pack_entry_find(&e, (struct pack_backend *)backend, oid)) < 0)
		return error;

	now = time(NULL);

	if (e.p->last_freshen > now - FRESHEN_FREQUENCY)
		return 0;

	if ((error = git3_futils_touch(e.p->pack_name, &now)) < 0)
		return error;

	e.p->last_freshen = now;
	return 0;
}

static int pack_backend__read(
	void **buffer_p, size_t *len_p, git3_object_t *type_p,
	git3_odb_backend *backend, const git3_oid *oid)
{
	struct git3_pack_entry e;
	git3_rawobj raw = {NULL};
	int error;

	if ((error = pack_entry_find(&e, (struct pack_backend *)backend, oid)) < 0 ||
		(error = git3_packfile_unpack(&raw, e.p, &e.offset)) < 0)
		return error;

	*buffer_p = raw.data;
	*len_p = raw.len;
	*type_p = raw.type;

	return 0;
}

static int pack_backend__read_prefix(
	git3_oid *out_oid,
	void **buffer_p,
	size_t *len_p,
	git3_object_t *type_p,
	git3_odb_backend *_backend,
	const git3_oid *short_oid,
	size_t len)
{
	struct pack_backend *backend = (struct pack_backend *)_backend;
	int error = 0;

	if (len < GIT3_OID_MINPREFIXLEN)
		error = git3_odb__error_ambiguous("prefix length too short");

	else if (len >= git3_oid_hexsize(backend->opts.oid_type)) {
		/* We can fall back to regular read method */
		error = pack_backend__read(buffer_p, len_p, type_p, _backend, short_oid);
		if (!error)
			git3_oid_cpy(out_oid, short_oid);
	} else {
		struct git3_pack_entry e;
		git3_rawobj raw = {NULL};

		if ((error = pack_entry_find_prefix(&e,
				backend, short_oid, len)) == 0 &&
		    (error = git3_packfile_unpack(&raw, e.p, &e.offset)) == 0)
		{
			*buffer_p = raw.data;
			*len_p = raw.len;
			*type_p = raw.type;
			git3_oid_cpy(out_oid, &e.id);
		}
	}

	return error;
}

static int pack_backend__exists(git3_odb_backend *backend, const git3_oid *oid)
{
	struct git3_pack_entry e;
	return pack_entry_find(&e, (struct pack_backend *)backend, oid) == 0;
}

static int pack_backend__exists_prefix(
	git3_oid *out, git3_odb_backend *backend, const git3_oid *short_id, size_t len)
{
	int error;
	struct pack_backend *pb = (struct pack_backend *)backend;
	struct git3_pack_entry e = {0};

	error = pack_entry_find_prefix(&e, pb, short_id, len);
	git3_oid_cpy(out, &e.id);
	return error;
}

static int pack_backend__foreach(git3_odb_backend *_backend, git3_odb_foreach_cb cb, void *data)
{
	int error;
	struct git3_pack_file *p;
	struct pack_backend *backend;
	unsigned int i;

	GIT3_ASSERT_ARG(_backend);
	GIT3_ASSERT_ARG(cb);

	backend = (struct pack_backend *)_backend;

	/* Make sure we know about the packfiles */
	if ((error = pack_backend__refresh(_backend)) != 0)
		return error;

	if (backend->midx && (error = git3_midx_foreach_entry(backend->midx, cb, data)) != 0)
		return error;
	git3_vector_foreach(&backend->packs, i, p) {
		if ((error = git3_pack_foreach_entry(p, cb, data)) != 0)
			return error;
	}

	return 0;
}

static int pack_backend__writepack_append(struct git3_odb_writepack *_writepack, const void *data, size_t size, git3_indexer_progress *stats)
{
	struct pack_writepack *writepack = (struct pack_writepack *)_writepack;

	GIT3_ASSERT_ARG(writepack);

	return git3_indexer_append(writepack->indexer, data, size, stats);
}

static int pack_backend__writepack_commit(struct git3_odb_writepack *_writepack, git3_indexer_progress *stats)
{
	struct pack_writepack *writepack = (struct pack_writepack *)_writepack;

	GIT3_ASSERT_ARG(writepack);

	return git3_indexer_commit(writepack->indexer, stats);
}

static void pack_backend__writepack_free(struct git3_odb_writepack *_writepack)
{
	struct pack_writepack *writepack;

	if (!_writepack)
		return;

	writepack = (struct pack_writepack *)_writepack;

	git3_indexer_free(writepack->indexer);
	git3__free(writepack);
}

static int pack_backend__writepack(struct git3_odb_writepack **out,
	git3_odb_backend *_backend,
        git3_odb *odb,
	git3_indexer_progress_cb progress_cb,
	void *progress_payload)
{
	git3_indexer_options opts = GIT3_INDEXER_OPTIONS_INIT;
	struct pack_backend *backend;
	struct pack_writepack *writepack;
	int error;

	GIT3_ASSERT_ARG(out);
	GIT3_ASSERT_ARG(_backend);

	*out = NULL;

	opts.progress_cb = progress_cb;
	opts.progress_cb_payload = progress_payload;

	backend = (struct pack_backend *)_backend;

	writepack = git3__calloc(1, sizeof(struct pack_writepack));
	GIT3_ERROR_CHECK_ALLOC(writepack);

#ifdef GIT3_EXPERIMENTAL_SHA256
	opts.odb = odb;
	opts.oid_type = backend->opts.oid_type;

	error = git3_indexer_new(&writepack->indexer,
		backend->pack_folder,
		&opts);
#else
	error = git3_indexer_new(&writepack->indexer,
		backend->pack_folder, 0, odb, &opts);
#endif

	if (error < 0)
		return -1;

	writepack->parent.backend = _backend;
	writepack->parent.append = pack_backend__writepack_append;
	writepack->parent.commit = pack_backend__writepack_commit;
	writepack->parent.free = pack_backend__writepack_free;

	*out = (git3_odb_writepack *)writepack;

	return 0;
}

static int get_idx_path(
		git3_str *idx_path,
		struct pack_backend *backend,
		struct git3_pack_file *p)
{
	size_t path_len;
	int error;

	error = git3_fs_path_prettify(idx_path, p->pack_name, backend->pack_folder);
	if (error < 0)
		return error;
	path_len = git3_str_len(idx_path);
	if (path_len <= strlen(".pack") || git3__suffixcmp(git3_str_cstr(idx_path), ".pack") != 0)
		return git3_odb__error_notfound("packfile does not end in .pack", NULL, 0);
	path_len -= strlen(".pack");
	error = git3_str_splice(idx_path, path_len, strlen(".pack"), ".idx", strlen(".idx"));
	if (error < 0)
		return error;

	return 0;
}

static int pack_backend__writemidx(git3_odb_backend *_backend)
{
	struct pack_backend *backend;
	git3_midx_writer *w = NULL;
	struct git3_pack_file *p;
	size_t i;
	int error = 0;

#ifdef GIT3_EXPERIMENTAL_SHA256
	git3_midx_writer_options midx_opts = GIT3_MIDX_WRITER_OPTIONS_INIT;
#endif

	GIT3_ASSERT_ARG(_backend);

	backend = (struct pack_backend *)_backend;

#ifdef GIT3_EXPERIMENTAL_SHA256
	midx_opts.oid_type = backend->opts.oid_type;
#endif

	error = git3_midx_writer_new(&w, backend->pack_folder
#ifdef GIT3_EXPERIMENTAL_SHA256
		, &midx_opts
#endif
		);

	if (error < 0)
		return error;

	git3_vector_foreach(&backend->midx_packs, i, p) {
		git3_str idx_path = GIT3_STR_INIT;
		error = get_idx_path(&idx_path, backend, p);
		if (error < 0)
			goto cleanup;
		error = git3_midx_writer_add(w, git3_str_cstr(&idx_path));
		git3_str_dispose(&idx_path);
		if (error < 0)
			goto cleanup;
	}
	git3_vector_foreach(&backend->packs, i, p) {
		git3_str idx_path = GIT3_STR_INIT;
		error = get_idx_path(&idx_path, backend, p);
		if (error < 0)
			goto cleanup;
		error = git3_midx_writer_add(w, git3_str_cstr(&idx_path));
		git3_str_dispose(&idx_path);
		if (error < 0)
			goto cleanup;
	}

	/*
	 * Invalidate the previous midx before writing the new one.
	 */
	error = remove_multi_pack_index(backend);
	if (error < 0)
		goto cleanup;
	error = git3_midx_writer_commit(w);
	if (error < 0)
		goto cleanup;
	error = refresh_multi_pack_index(backend);

cleanup:
	git3_midx_writer_free(w);
	return error;
}

static void pack_backend__free(git3_odb_backend *_backend)
{
	struct pack_backend *backend;
	struct git3_pack_file *p;
	size_t i;

	if (!_backend)
		return;

	backend = (struct pack_backend *)_backend;

	git3_vector_foreach(&backend->midx_packs, i, p)
		git3_mwindow_put_pack(p);
	git3_vector_foreach(&backend->packs, i, p)
		git3_mwindow_put_pack(p);

	git3_midx_free(backend->midx);
	git3_vector_dispose(&backend->midx_packs);
	git3_vector_dispose(&backend->packs);
	git3__free(backend->pack_folder);
	git3__free(backend);
}

static int pack_backend__alloc(
	struct pack_backend **out,
	size_t initial_size,
	const git3_odb_backend_pack_options *opts)
{
	struct pack_backend *backend = git3__calloc(1, sizeof(struct pack_backend));
	GIT3_ERROR_CHECK_ALLOC(backend);

	if (git3_vector_init(&backend->midx_packs, 0, NULL) < 0) {
		git3__free(backend);
		return -1;
	}

	if (git3_vector_init(&backend->packs, initial_size, packfile_sort__cb) < 0) {
		git3_vector_dispose(&backend->midx_packs);
		git3__free(backend);
		return -1;
	}

	if (opts)
		memcpy(&backend->opts, opts, sizeof(git3_odb_backend_pack_options));

	if (!backend->opts.oid_type)
		backend->opts.oid_type = GIT3_OID_DEFAULT;

	backend->parent.version = GIT3_ODB_BACKEND_VERSION;

	backend->parent.read = &pack_backend__read;
	backend->parent.read_prefix = &pack_backend__read_prefix;
	backend->parent.read_header = &pack_backend__read_header;
	backend->parent.exists = &pack_backend__exists;
	backend->parent.exists_prefix = &pack_backend__exists_prefix;
	backend->parent.refresh = &pack_backend__refresh;
	backend->parent.foreach = &pack_backend__foreach;
	backend->parent.writepack = &pack_backend__writepack;
	backend->parent.writemidx = &pack_backend__writemidx;
	backend->parent.freshen = &pack_backend__freshen;
	backend->parent.free = &pack_backend__free;

	*out = backend;
	return 0;
}

#ifdef GIT3_EXPERIMENTAL_SHA256
int git3_odb_backend_one_pack(
	git3_odb_backend **backend_out,
	const char *idx,
	const git3_odb_backend_pack_options *opts)
#else
int git3_odb_backend_one_pack(
	git3_odb_backend **backend_out,
	const char *idx)
#endif
{
	struct pack_backend *backend = NULL;
	struct git3_pack_file *packfile = NULL;

#ifndef GIT3_EXPERIMENTAL_SHA256
	git3_odb_backend_pack_options *opts = NULL;
#endif

	git3_oid_t oid_type = opts ? opts->oid_type : 0;

	if (pack_backend__alloc(&backend, 1, opts) < 0)
		return -1;

	if (git3_mwindow_get_pack(&packfile, idx, oid_type) < 0 ||
	    git3_vector_insert(&backend->packs, packfile) < 0) {
		pack_backend__free((git3_odb_backend *)backend);
		return -1;
	}

	*backend_out = (git3_odb_backend *)backend;
	return 0;
}

#ifdef GIT3_EXPERIMENTAL_SHA256
int git3_odb_backend_pack(
	git3_odb_backend **backend_out,
	const char *objects_dir,
	const git3_odb_backend_pack_options *opts)
#else
int git3_odb_backend_pack(
	git3_odb_backend **backend_out,
	const char *objects_dir)
#endif
{
	int error = 0;
	struct pack_backend *backend = NULL;
	git3_str path = GIT3_STR_INIT;

#ifndef GIT3_EXPERIMENTAL_SHA256
	git3_odb_backend_pack_options *opts = NULL;
#endif

	if (pack_backend__alloc(&backend, 8, opts) < 0)
		return -1;

	if (!(error = git3_str_joinpath(&path, objects_dir, "pack")) &&
	    git3_fs_path_isdir(git3_str_cstr(&path))) {
		backend->pack_folder = git3_str_detach(&path);
		error = pack_backend__refresh((git3_odb_backend *)backend);
	}

	if (error < 0) {
		pack_backend__free((git3_odb_backend *)backend);
		backend = NULL;
	}

	*backend_out = (git3_odb_backend *)backend;

	git3_str_dispose(&path);

	return error;
}
