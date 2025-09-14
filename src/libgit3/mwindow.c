/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "mwindow.h"

#include "vector.h"
#include "futils.h"
#include "map.h"
#include "runtime.h"
#include "pack.h"

#define DEFAULT_WINDOW_SIZE \
	(sizeof(void*) >= 8 \
		? 1 * 1024 * 1024 * 1024 \
		: 32 * 1024 * 1024)

#define DEFAULT_MAPPED_LIMIT \
	((1024 * 1024) * (sizeof(void*) >= 8 ? UINT64_C(8192) : UINT64_C(256)))

/* default is unlimited */
#define DEFAULT_FILE_LIMIT 0

size_t git3_mwindow__window_size = DEFAULT_WINDOW_SIZE;
size_t git3_mwindow__mapped_limit = DEFAULT_MAPPED_LIMIT;
size_t git3_mwindow__file_limit = DEFAULT_FILE_LIMIT;

/* Mutex to control access to `git3_mwindow__mem_ctl` and `git3_mwindow__pack_cache`. */
git3_mutex git3_mwindow__mutex;

/* Whenever you want to read or modify this, grab `git3_mwindow__mutex` */
git3_mwindow_ctl git3_mwindow__mem_ctl;

/* Global list of mwindow files, to open packs once across repos */
GIT3_HASHMAP_STR_FUNCTIONS(git3_mwindow_packmap, , struct git3_pack_file *);
git3_mwindow_packmap git3_mwindow__pack_cache;

static void git3_mwindow_global_shutdown(void)
{
	git3_mutex_free(&git3_mwindow__mutex);
	git3_mwindow_packmap_dispose(&git3_mwindow__pack_cache);
}

int git3_mwindow_global_init(void)
{
	int error;

	if ((error = git3_mutex_init(&git3_mwindow__mutex)) < 0)
	    return error;

	return git3_runtime_shutdown_register(git3_mwindow_global_shutdown);
}

int git3_mwindow_get_pack(
	struct git3_pack_file **out,
	const char *path,
	git3_oid_t oid_type)
{
	struct git3_pack_file *pack;
	char *packname;
	int error;

	if ((error = git3_packfile__name(&packname, path)) < 0)
		return error;

	if (git3_mutex_lock(&git3_mwindow__mutex) < 0) {
		git3_error_set(GIT3_ERROR_OS, "failed to lock mwindow mutex");
		return -1;
	}

	error = git3_mwindow_packmap_get(&pack, &git3_mwindow__pack_cache, packname);
	git3__free(packname);

	if (error == 0) {
		git3_atomic32_inc(&pack->refcount);
		git3_mutex_unlock(&git3_mwindow__mutex);
		*out = pack;
		return 0;
	} else if (error != GIT3_ENOTFOUND) {
		return error;
	}

	/* If we didn't find it, we need to create it */
	if ((error = git3_packfile_alloc(&pack, path, oid_type)) < 0) {
		git3_mutex_unlock(&git3_mwindow__mutex);
		return error;
	}

	git3_atomic32_inc(&pack->refcount);

	error = git3_mwindow_packmap_put(&git3_mwindow__pack_cache, pack->pack_name, pack);
	git3_mutex_unlock(&git3_mwindow__mutex);

	if (error < 0) {
		git3_packfile_free(pack, false);
		return error;
	}

	*out = pack;
	return 0;
}

int git3_mwindow_put_pack(struct git3_pack_file *pack)
{
	int count, error;
	struct git3_pack_file *pack_to_delete = NULL;

	if ((error = git3_mutex_lock(&git3_mwindow__mutex)) < 0)
		return error;

	/* if we cannot find it, the state is corrupted */
	GIT3_ASSERT(git3_mwindow_packmap_contains(&git3_mwindow__pack_cache, pack->pack_name));

	count = git3_atomic32_dec(&pack->refcount);
	if (count == 0) {
		git3_mwindow_packmap_remove(&git3_mwindow__pack_cache, pack->pack_name);
		pack_to_delete = pack;
	}
	git3_mutex_unlock(&git3_mwindow__mutex);
	git3_packfile_free(pack_to_delete, false);

	return 0;
}

/*
 * Free all the windows in a sequence, typically because we're done
 * with the file. Needs to hold the git3_mwindow__mutex.
 */
static int git3_mwindow_free_all_locked(git3_mwindow_file *mwf)
{
	git3_mwindow_ctl *ctl = &git3_mwindow__mem_ctl;
	size_t i;

	/*
	 * Remove these windows from the global list
	 */
	for (i = 0; i < ctl->windowfiles.length; ++i){
		if (git3_vector_get(&ctl->windowfiles, i) == mwf) {
			git3_vector_remove(&ctl->windowfiles, i);
			break;
		}
	}

	if (ctl->windowfiles.length == 0) {
		git3_vector_dispose(&ctl->windowfiles);
		ctl->windowfiles.contents = NULL;
	}

	while (mwf->windows) {
		git3_mwindow *w = mwf->windows;
		GIT3_ASSERT(w->inuse_cnt == 0);

		ctl->mapped -= w->window_map.len;
		ctl->open_windows--;

		git3_futils_mmap_free(&w->window_map);

		mwf->windows = w->next;
		git3__free(w);
	}

	return 0;
}

int git3_mwindow_free_all(git3_mwindow_file *mwf)
{
	int error;

	if (git3_mutex_lock(&git3_mwindow__mutex)) {
		git3_error_set(GIT3_ERROR_THREAD, "unable to lock mwindow mutex");
		return -1;
	}

	error = git3_mwindow_free_all_locked(mwf);

	git3_mutex_unlock(&git3_mwindow__mutex);

	return error;
}

/*
 * Check if a window 'win' contains both the address 'offset' and 'extra'.
 *
 * 'extra' is the size of the hash we're using as we always want to make sure
 * that it's contained.
 */
int git3_mwindow_contains(git3_mwindow *win, off64_t offset, off64_t extra)
{
	off64_t win_off = win->offset;
	return win_off <= offset
		&& (offset + extra) <= (off64_t)(win_off + win->window_map.len);
}

#define GIT3_MWINDOW__LRU -1
#define GIT3_MWINDOW__MRU 1

/*
 * Find the least- or most-recently-used window in a file that is not currently
 * being used. The 'only_unused' flag controls whether the caller requires the
 * file to only have unused windows. If '*out_window' is non-null, it is used as
 * a starting point for the comparison.
 *
 * Returns whether such a window was found in the file.
 */
static bool git3_mwindow_scan_recently_used(
		git3_mwindow_file *mwf,
		git3_mwindow **out_window,
		git3_mwindow **out_last,
		bool only_unused,
		int comparison_sign)
{
	git3_mwindow *w, *w_last;
	git3_mwindow *lru_window = NULL, *lru_last = NULL;
	bool found = false;

	GIT3_ASSERT_ARG(mwf);
	GIT3_ASSERT_ARG(out_window);

	lru_window = *out_window;
	if (out_last)
		lru_last = *out_last;

	for (w_last = NULL, w = mwf->windows; w; w_last = w, w = w->next) {
		if (w->inuse_cnt) {
			if (only_unused)
				return false;
			/* This window is currently being used. Skip it. */
			continue;
		}

		/*
		 * If the current one is more (or less) recent than the last one,
		 * store it in the output parameter. If lru_window is NULL,
		 * it's the first loop, so store it as well.
		 */
		if (!lru_window || (comparison_sign * w->last_used) > lru_window->last_used) {
			lru_window = w;
			lru_last = w_last;
			found = true;
		}
	}

	if (!found)
		return false;

	*out_window = lru_window;
	if (out_last)
		*out_last = lru_last;
	return true;
}

/*
 * Close the least recently used window (that is currently not being used) out
 * of all the files. Called under lock from new_window_locked.
 */
static int git3_mwindow_close_lru_window_locked(void)
{
	git3_mwindow_ctl *ctl = &git3_mwindow__mem_ctl;
	git3_mwindow_file *cur;
	size_t i;
	git3_mwindow *lru_window = NULL, *lru_last = NULL, **list = NULL;

	git3_vector_foreach(&ctl->windowfiles, i, cur) {
		if (git3_mwindow_scan_recently_used(
				cur, &lru_window, &lru_last, false, GIT3_MWINDOW__LRU)) {
			list = &cur->windows;
		}
	}

	if (!lru_window) {
		git3_error_set(GIT3_ERROR_OS, "failed to close memory window; couldn't find LRU");
		return -1;
	}

	ctl->mapped -= lru_window->window_map.len;
	git3_futils_mmap_free(&lru_window->window_map);

	if (lru_last)
		lru_last->next = lru_window->next;
	else
		*list = lru_window->next;

	git3__free(lru_window);
	ctl->open_windows--;

	return 0;
}

/*
 * Finds the file that does not have any open windows AND whose
 * most-recently-used window is the least-recently used one across all
 * currently open files.
 *
 * Called under lock from new_window_locked.
 */
static int git3_mwindow_find_lru_file_locked(git3_mwindow_file **out)
{
	git3_mwindow_ctl *ctl = &git3_mwindow__mem_ctl;
	git3_mwindow_file *lru_file = NULL, *current_file = NULL;
	git3_mwindow *lru_window = NULL;
	size_t i;

	git3_vector_foreach(&ctl->windowfiles, i, current_file) {
		git3_mwindow *mru_window = NULL;
		if (!git3_mwindow_scan_recently_used(
				current_file, &mru_window, NULL, true, GIT3_MWINDOW__MRU)) {
			continue;
		}
		if (!lru_window || lru_window->last_used > mru_window->last_used) {
			lru_window = mru_window;
			lru_file = current_file;
		}
	}

	if (!lru_file) {
		git3_error_set(GIT3_ERROR_OS, "failed to close memory window file; couldn't find LRU");
		return -1;
	}

	*out = lru_file;
	return 0;
}

/* This gets called under lock from git3_mwindow_open */
static git3_mwindow *new_window_locked(
	git3_file fd,
	off64_t size,
	off64_t offset)
{
	git3_mwindow_ctl *ctl = &git3_mwindow__mem_ctl;
	size_t walign = git3_mwindow__window_size / 2;
	off64_t len;
	git3_mwindow *w;

	w = git3__calloc(1, sizeof(*w));

	if (w == NULL)
		return NULL;

	w->offset = (offset / walign) * walign;

	len = size - w->offset;
	if (len > (off64_t)git3_mwindow__window_size)
		len = (off64_t)git3_mwindow__window_size;

	ctl->mapped += (size_t)len;

	while (git3_mwindow__mapped_limit < ctl->mapped &&
			git3_mwindow_close_lru_window_locked() == 0) /* nop */;

	/*
	 * We treat `mapped_limit` as a soft limit. If we can't find a
	 * window to close and are above the limit, we still mmap the new
	 * window.
	 */

	if (git3_futils_mmap_ro(&w->window_map, fd, w->offset, (size_t)len) < 0) {
		/*
		 * The first error might be down to memory fragmentation even if
		 * we're below our soft limits, so free up what we can and try again.
		 */

		while (git3_mwindow_close_lru_window_locked() == 0)
			/* nop */;

		if (git3_futils_mmap_ro(&w->window_map, fd, w->offset, (size_t)len) < 0) {
			git3__free(w);
			return NULL;
		}
	}

	ctl->mmap_calls++;
	ctl->open_windows++;

	if (ctl->mapped > ctl->peak_mapped)
		ctl->peak_mapped = ctl->mapped;

	if (ctl->open_windows > ctl->peak_open_windows)
		ctl->peak_open_windows = ctl->open_windows;

	return w;
}

/*
 * Open a new window, closing the least recenty used until we have
 * enough space. Don't forget to add it to your list
 */
unsigned char *git3_mwindow_open(
	git3_mwindow_file *mwf,
	git3_mwindow **cursor,
	off64_t offset,
	size_t extra,
	unsigned int *left)
{
	git3_mwindow_ctl *ctl = &git3_mwindow__mem_ctl;
	git3_mwindow *w = *cursor;

	if (git3_mutex_lock(&git3_mwindow__mutex)) {
		git3_error_set(GIT3_ERROR_THREAD, "unable to lock mwindow mutex");
		return NULL;
	}

	if (!w || !(git3_mwindow_contains(w, offset, extra))) {
		if (w) {
			w->inuse_cnt--;
		}

		for (w = mwf->windows; w; w = w->next) {
			if (git3_mwindow_contains(w, offset, extra))
				break;
		}

		/*
		 * If there isn't a suitable window, we need to create a new
		 * one.
		 */
		if (!w) {
			w = new_window_locked(mwf->fd, mwf->size, offset);
			if (w == NULL) {
				git3_mutex_unlock(&git3_mwindow__mutex);
				return NULL;
			}
			w->next = mwf->windows;
			mwf->windows = w;
		}
	}

	/* If we changed w, store it in the cursor */
	if (w != *cursor) {
		w->last_used = ctl->used_ctr++;
		w->inuse_cnt++;
		*cursor = w;
	}

	offset -= w->offset;

	if (left)
		*left = (unsigned int)(w->window_map.len - offset);

	git3_mutex_unlock(&git3_mwindow__mutex);
	return (unsigned char *) w->window_map.data + offset;
}

int git3_mwindow_file_register(git3_mwindow_file *mwf)
{
	git3_vector closed_files = GIT3_VECTOR_INIT;
	git3_mwindow_ctl *ctl = &git3_mwindow__mem_ctl;
	int error;
	size_t i;
	git3_mwindow_file *closed_file = NULL;

	if (git3_mutex_lock(&git3_mwindow__mutex)) {
		git3_error_set(GIT3_ERROR_THREAD, "unable to lock mwindow mutex");
		return -1;
	}

	if (ctl->windowfiles.length == 0 &&
	    (error = git3_vector_init(&ctl->windowfiles, 8, NULL)) < 0) {
		git3_mutex_unlock(&git3_mwindow__mutex);
		goto cleanup;
	}

	if (git3_mwindow__file_limit) {
		git3_mwindow_file *lru_file;
		while (git3_mwindow__file_limit <= ctl->windowfiles.length &&
				git3_mwindow_find_lru_file_locked(&lru_file) == 0) {
			if ((error = git3_vector_insert(&closed_files, lru_file)) < 0) {
				/*
				 * Exceeding the file limit seems preferable to being open to
				 * data races that can end up corrupting the heap.
				 */
				break;
			}
			git3_mwindow_free_all_locked(lru_file);
		}
	}

	error = git3_vector_insert(&ctl->windowfiles, mwf);
	git3_mutex_unlock(&git3_mwindow__mutex);
	if (error < 0)
		goto cleanup;

	/*
	 * Once we have released the global windowfiles lock, we can close each
	 * individual file. Before doing so, acquire that file's lock to avoid
	 * closing a file that is currently being used.
	 */
	git3_vector_foreach(&closed_files, i, closed_file) {
		error = git3_mutex_lock(&closed_file->lock);
		if (error < 0)
			continue;
		p_close(closed_file->fd);
		closed_file->fd = -1;
		git3_mutex_unlock(&closed_file->lock);
	}

cleanup:
	git3_vector_dispose(&closed_files);
	return error;
}

void git3_mwindow_file_deregister(git3_mwindow_file *mwf)
{
	git3_mwindow_ctl *ctl = &git3_mwindow__mem_ctl;
	git3_mwindow_file *cur;
	size_t i;

	if (git3_mutex_lock(&git3_mwindow__mutex))
		return;

	git3_vector_foreach(&ctl->windowfiles, i, cur) {
		if (cur == mwf) {
			git3_vector_remove(&ctl->windowfiles, i);
			git3_mutex_unlock(&git3_mwindow__mutex);
			return;
		}
	}
	git3_mutex_unlock(&git3_mwindow__mutex);
}

void git3_mwindow_close(git3_mwindow **window)
{
	git3_mwindow *w = *window;
	if (w) {
		if (git3_mutex_lock(&git3_mwindow__mutex)) {
			git3_error_set(GIT3_ERROR_THREAD, "unable to lock mwindow mutex");
			return;
		}

		w->inuse_cnt--;
		git3_mutex_unlock(&git3_mwindow__mutex);
		*window = NULL;
	}
}
