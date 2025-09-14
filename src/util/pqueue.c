/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "pqueue.h"

#include "util.h"

#define PQUEUE_LCHILD_OF(I) (((I)<<1)+1)
#define PQUEUE_RCHILD_OF(I) (((I)<<1)+2)
#define PQUEUE_PARENT_OF(I) (((I)-1)>>1)

int git3_pqueue_init(
	git3_pqueue *pq,
	uint32_t flags,
	size_t init_size,
	git3_vector_cmp cmp)
{
	int error = git3_vector_init(pq, init_size, cmp);

	if (!error) {
		/* mix in our flags */
		pq->flags |= flags;

		/* if fixed size heap, pretend vector is exactly init_size elements */
		if ((flags & GIT3_PQUEUE_FIXED_SIZE) && init_size > 0)
			pq->_alloc_size = init_size;
	}

	return error;
}

static void pqueue_up(git3_pqueue *pq, size_t el)
{
	size_t parent_el = PQUEUE_PARENT_OF(el);
	void *kid = git3_vector_get(pq, el);

	while (el > 0) {
		void *parent = pq->contents[parent_el];

		if (pq->_cmp(parent, kid) <= 0)
			break;

		pq->contents[el] = parent;

		el = parent_el;
		parent_el = PQUEUE_PARENT_OF(el);
	}

	pq->contents[el] = kid;
}

static void pqueue_down(git3_pqueue *pq, size_t el)
{
	void *parent = git3_vector_get(pq, el), *kid, *rkid;

	while (1) {
		size_t kid_el = PQUEUE_LCHILD_OF(el);

		if ((kid = git3_vector_get(pq, kid_el)) == NULL)
			break;

		if ((rkid = git3_vector_get(pq, kid_el + 1)) != NULL &&
			pq->_cmp(kid, rkid) > 0) {
			kid    = rkid;
			kid_el += 1;
		}

		if (pq->_cmp(parent, kid) <= 0)
			break;

		pq->contents[el] = kid;
		el = kid_el;
	}

	pq->contents[el] = parent;
}

int git3_pqueue_insert(git3_pqueue *pq, void *item)
{
	int error = 0;

	/* if heap is full, pop the top element if new one should replace it */
	if ((pq->flags & GIT3_PQUEUE_FIXED_SIZE) != 0 &&
		pq->length >= pq->_alloc_size)
	{
		/* skip this item if below min item in heap or if
		 * we do not have a comparison function */
		if (!pq->_cmp || pq->_cmp(item, git3_vector_get(pq, 0)) <= 0)
			return 0;
		/* otherwise remove the min item before inserting new */
		(void)git3_pqueue_pop(pq);
	}

	if (!(error = git3_vector_insert(pq, item)) && pq->_cmp)
		pqueue_up(pq, pq->length - 1);

	return error;
}

void *git3_pqueue_pop(git3_pqueue *pq)
{
	void *rval;

	if (!pq->_cmp) {
		rval = git3_vector_last(pq);
	} else {
		rval = git3_pqueue_get(pq, 0);
	}

	if (git3_pqueue_size(pq) > 1 && pq->_cmp) {
		/* move last item to top of heap, shrink, and push item down */
		pq->contents[0] = git3_vector_last(pq);
		git3_vector_pop(pq);
		pqueue_down(pq, 0);
	} else {
		/* all we need to do is shrink the heap in this case */
		git3_vector_pop(pq);
	}

	return rval;
}
