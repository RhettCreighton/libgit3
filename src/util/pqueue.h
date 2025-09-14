/*
 * Copyright (C) the libgit3 contributors.  All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_pqueue_h__
#define INCLUDE_pqueue_h__

#include "git3_util.h"

#include "vector.h"

typedef git3_vector git3_pqueue;

enum {
	/* flag meaning: don't grow heap, keep highest values only */
	GIT3_PQUEUE_FIXED_SIZE = (GIT3_VECTOR_FLAG_MAX << 1)
};

/**
 * Initialize priority queue
 *
 * @param pq The priority queue struct to initialize
 * @param flags Flags (see above) to control queue behavior
 * @param init_size The initial queue size
 * @param cmp The entry priority comparison function
 * @return 0 on success, <0 on error
 */
extern int git3_pqueue_init(
	git3_pqueue *pq,
	uint32_t flags,
	size_t init_size,
	git3_vector_cmp cmp);

#define git3_pqueue_free  git3_vector_dispose
#define git3_pqueue_clear git3_vector_clear
#define git3_pqueue_size  git3_vector_length
#define git3_pqueue_get   git3_vector_get
#define git3_pqueue_reverse git3_vector_reverse

/**
 * Insert a new item into the queue
 *
 * @param pq The priority queue
 * @param item Pointer to the item data
 * @return 0 on success, <0 on failure
 */
extern int git3_pqueue_insert(git3_pqueue *pq, void *item);

/**
 * Remove the top item in the priority queue
 *
 * @param pq The priority queue
 * @return item from heap on success, NULL if queue is empty
 */
extern void *git3_pqueue_pop(git3_pqueue *pq);

#endif
