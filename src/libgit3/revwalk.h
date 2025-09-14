/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_revwalk_h__
#define INCLUDE_revwalk_h__

#include "common.h"

#include "git3/revwalk.h"
#include "commit_list.h"
#include "pqueue.h"
#include "pool.h"
#include "vector.h"
#include "hashmap_oid.h"

GIT3_HASHMAP_OID_STRUCT(git3_revwalk_oidmap, git3_commit_list_node *);

struct git3_revwalk {
	git3_repository *repo;
	git3_odb *odb;

	git3_revwalk_oidmap commits;
	git3_pool commit_pool;

	git3_commit_list *iterator_topo;
	git3_commit_list *iterator_rand;
	git3_commit_list *iterator_reverse;
	git3_pqueue iterator_time;

	int (*get_next)(git3_commit_list_node **, git3_revwalk *);
	int (*enqueue)(git3_revwalk *, git3_commit_list_node *);

	unsigned walking:1,
		first_parent: 1,
		did_hide: 1,
		did_push: 1,
		limited: 1;
	unsigned int sorting;

	/* the pushes and hides */
	git3_commit_list *user_input;

	/* hide callback */
	git3_revwalk_hide_cb hide_cb;
	void *hide_cb_payload;
};

git3_commit_list_node *git3_revwalk__commit_lookup(git3_revwalk *walk, const git3_oid *oid);

typedef struct {
	int uninteresting;
	int from_glob;
	int insert_by_date;
} git3_revwalk__push_options;

#define GIT3_REVWALK__PUSH_OPTIONS_INIT { 0 }

int git3_revwalk__push_commit(git3_revwalk *walk,
	const git3_oid *oid,
	const git3_revwalk__push_options *opts);

int git3_revwalk__push_ref(git3_revwalk *walk,
	const char *refname,
	const git3_revwalk__push_options *opts);

int git3_revwalk__push_glob(git3_revwalk *walk,
	const char *glob,
	const git3_revwalk__push_options *given_opts);

#endif
