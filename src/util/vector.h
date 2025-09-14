/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_vector_h__
#define INCLUDE_vector_h__

#include "git3_util.h"

typedef int (*git3_vector_cmp)(const void *, const void *);

enum {
	GIT3_VECTOR_SORTED = (1u << 0),
	GIT3_VECTOR_FLAG_MAX = (1u << 1)
};

typedef struct git3_vector {
	size_t _alloc_size;
	git3_vector_cmp _cmp;
	void **contents;
	size_t length;
	uint32_t flags;
} git3_vector;

#define GIT3_VECTOR_INIT {0}

GIT3_WARN_UNUSED_RESULT int git3_vector_init(
	git3_vector *v, size_t initial_size, git3_vector_cmp cmp);
void git3_vector_dispose(git3_vector *v);
void git3_vector_dispose_deep(git3_vector *v); /* free each entry and self */
void git3_vector_clear(git3_vector *v);
GIT3_WARN_UNUSED_RESULT int git3_vector_dup(
	git3_vector *v, const git3_vector *src, git3_vector_cmp cmp);
void git3_vector_swap(git3_vector *a, git3_vector *b);
int git3_vector_size_hint(git3_vector *v, size_t size_hint);

void **git3_vector_detach(size_t *size, size_t *asize, git3_vector *v);

void git3_vector_sort(git3_vector *v);

/** Linear search for matching entry using internal comparison function */
int git3_vector_search(size_t *at_pos, const git3_vector *v, const void *entry);

/** Linear search for matching entry using explicit comparison function */
int git3_vector_search2(size_t *at_pos, const git3_vector *v, git3_vector_cmp cmp, const void *key);

/**
 * Binary search for matching entry using explicit comparison function that
 * returns position where item would go if not found.
 */
int git3_vector_bsearch2(
	size_t *at_pos, git3_vector *v, git3_vector_cmp cmp, const void *key);

/** Binary search for matching entry using internal comparison function */
GIT3_INLINE(int) git3_vector_bsearch(size_t *at_pos, git3_vector *v, const void *key)
{
	return git3_vector_bsearch2(at_pos, v, v->_cmp, key);
}

GIT3_INLINE(void *) git3_vector_get(const git3_vector *v, size_t position)
{
	return (position < v->length) ? v->contents[position] : NULL;
}

#define GIT3_VECTOR_GET(V,I) ((I) < (V)->length ? (V)->contents[(I)] : NULL)

GIT3_INLINE(size_t) git3_vector_length(const git3_vector *v)
{
	return v->length;
}

GIT3_INLINE(void *) git3_vector_last(const git3_vector *v)
{
	return (v->length > 0) ? git3_vector_get(v, v->length - 1) : NULL;
}

#define git3_vector_foreach(v, iter, elem)	\
	for ((iter) = 0; (iter) < (v)->length && ((elem) = (v)->contents[(iter)], 1); (iter)++ )

#define git3_vector_rforeach(v, iter, elem)	\
	for ((iter) = (v)->length - 1; (iter) < SIZE_MAX && ((elem) = (v)->contents[(iter)], 1); (iter)-- )

int git3_vector_insert(git3_vector *v, void *element);
int git3_vector_insert_sorted(git3_vector *v, void *element,
	int (*on_dup)(void **old, void *new));
int git3_vector_remove(git3_vector *v, size_t idx);
void git3_vector_pop(git3_vector *v);
void git3_vector_uniq(git3_vector *v, void  (*git3_free_cb)(void *));

void git3_vector_remove_matching(
	git3_vector *v,
	int (*match)(const git3_vector *v, size_t idx, void *payload),
	void *payload);

int git3_vector_resize_to(git3_vector *v, size_t new_length);
int git3_vector_insert_null(git3_vector *v, size_t idx, size_t insert_len);
int git3_vector_remove_range(git3_vector *v, size_t idx, size_t remove_len);

int git3_vector_set(void **old, git3_vector *v, size_t position, void *value);

/** Check if vector is sorted */
#define git3_vector_is_sorted(V) (((V)->flags & GIT3_VECTOR_SORTED) != 0)

/** Directly set sorted state of vector */
#define git3_vector_set_sorted(V,S) do { \
	(V)->flags = (S) ? ((V)->flags | GIT3_VECTOR_SORTED) : \
		((V)->flags & ~GIT3_VECTOR_SORTED); } while (0)

/** Set the comparison function used for sorting the vector */
GIT3_INLINE(void) git3_vector_set_cmp(git3_vector *v, git3_vector_cmp cmp)
{
	if (cmp != v->_cmp) {
		v->_cmp = cmp;
		git3_vector_set_sorted(v, 0);
	}
}

/* Just use this in tests, not for realz. returns -1 if not sorted */
int git3_vector_verify_sorted(const git3_vector *v);

/**
 * Reverse the vector in-place.
 */
void git3_vector_reverse(git3_vector *v);

#endif
