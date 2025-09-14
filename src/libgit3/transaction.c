/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "transaction.h"

#include "repository.h"
#include "refdb.h"
#include "pool.h"
#include "reflog.h"
#include "signature.h"
#include "config.h"

#include "git3/transaction.h"
#include "git3/signature.h"
#include "git3/sys/refs.h"
#include "git3/sys/refdb_backend.h"

typedef enum {
	TRANSACTION_NONE,
	TRANSACTION_REFS,
	TRANSACTION_CONFIG
} transaction_t;

typedef struct {
	const char *name;
	void *payload;

	git3_reference_t ref_type;
	union {
		git3_oid id;
		char *symbolic;
	} target;
	git3_reflog *reflog;

	const char *message;
	git3_signature *sig;

	unsigned int committed :1,
		remove :1;
} transaction_node;

GIT3_HASHMAP_STR_SETUP(git3_transaction_nodemap, transaction_node *);

struct git3_transaction {
	transaction_t type;
	git3_repository *repo;
	git3_refdb *db;
	git3_config *cfg;
	void *cfg_data;

	git3_transaction_nodemap locks;
	git3_pool pool;
};

int git3_transaction_config_new(
	git3_transaction **out,
	git3_config *cfg,
	void *data)
{
	git3_transaction *tx;

	GIT3_ASSERT_ARG(out);
	GIT3_ASSERT_ARG(cfg);

	tx = git3__calloc(1, sizeof(git3_transaction));
	GIT3_ERROR_CHECK_ALLOC(tx);

	tx->type = TRANSACTION_CONFIG;
	tx->cfg = cfg;
	tx->cfg_data = data;

	*out = tx;
	return 0;
}

int git3_transaction_new(git3_transaction **out, git3_repository *repo)
{
	int error;
	git3_pool pool;
	git3_transaction *tx = NULL;

	GIT3_ASSERT_ARG(out);
	GIT3_ASSERT_ARG(repo);

	if ((error = git3_pool_init(&pool, 1)) < 0)
		goto on_error;

	tx = git3_pool_mallocz(&pool, sizeof(git3_transaction));
	if (!tx) {
		error = -1;
		goto on_error;
	}

	if ((error = git3_repository_refdb(&tx->db, repo)) < 0)
		goto on_error;

	tx->type = TRANSACTION_REFS;
	memcpy(&tx->pool, &pool, sizeof(git3_pool));
	tx->repo = repo;
	*out = tx;
	return 0;

on_error:
	git3_pool_clear(&pool);
	return error;
}

int git3_transaction_lock_ref(git3_transaction *tx, const char *refname)
{
	int error;
	transaction_node *node;

	GIT3_ASSERT_ARG(tx);
	GIT3_ASSERT_ARG(refname);

	node = git3_pool_mallocz(&tx->pool, sizeof(transaction_node));
	GIT3_ERROR_CHECK_ALLOC(node);

	node->name = git3_pool_strdup(&tx->pool, refname);
	GIT3_ERROR_CHECK_ALLOC(node->name);

	if ((error = git3_refdb_lock(&node->payload, tx->db, refname)) < 0)
		return error;

	if ((error = git3_transaction_nodemap_put(&tx->locks, node->name, node)) < 0)
		goto cleanup;

	return 0;

cleanup:
	git3_refdb_unlock(tx->db, node->payload, false, false, NULL, NULL, NULL);

	return error;
}

static int find_locked(transaction_node **out, git3_transaction *tx, const char *refname)
{
	transaction_node *node;
	int error;

	error = git3_transaction_nodemap_get(&node, &tx->locks, refname);

	if (error != 0) {
		git3_error_set(GIT3_ERROR_REFERENCE, "the specified reference is not locked");
		return GIT3_ENOTFOUND;
	}

	*out = node;
	return 0;
}

static int copy_common(transaction_node *node, git3_transaction *tx, const git3_signature *sig, const char *msg)
{
	if (sig && git3_signature__pdup(&node->sig, sig, &tx->pool) < 0)
		return -1;

	if (!node->sig) {
		git3_signature *tmp;
		int error;

		if (git3_reference__log_signature(&tmp, tx->repo) < 0)
			return -1;

		/* make sure the sig we use is in our pool */
		error = git3_signature__pdup(&node->sig, tmp, &tx->pool);
		git3_signature_free(tmp);
		if (error < 0)
			return error;
	}

	if (msg) {
		node->message = git3_pool_strdup(&tx->pool, msg);
		GIT3_ERROR_CHECK_ALLOC(node->message);
	}

	return 0;
}

int git3_transaction_set_target(git3_transaction *tx, const char *refname, const git3_oid *target, const git3_signature *sig, const char *msg)
{
	int error;
	transaction_node *node;

	GIT3_ASSERT_ARG(tx);
	GIT3_ASSERT_ARG(refname);
	GIT3_ASSERT_ARG(target);

	if ((error = find_locked(&node, tx, refname)) < 0)
		return error;

	if ((error = copy_common(node, tx, sig, msg)) < 0)
		return error;

	git3_oid_cpy(&node->target.id, target);
	node->ref_type = GIT3_REFERENCE_DIRECT;

	return 0;
}

int git3_transaction_set_symbolic_target(git3_transaction *tx, const char *refname, const char *target, const git3_signature *sig, const char *msg)
{
	int error;
	transaction_node *node;

	GIT3_ASSERT_ARG(tx);
	GIT3_ASSERT_ARG(refname);
	GIT3_ASSERT_ARG(target);

	if ((error = find_locked(&node, tx, refname)) < 0)
		return error;

	if ((error = copy_common(node, tx, sig, msg)) < 0)
		return error;

	node->target.symbolic = git3_pool_strdup(&tx->pool, target);
	GIT3_ERROR_CHECK_ALLOC(node->target.symbolic);
	node->ref_type = GIT3_REFERENCE_SYMBOLIC;

	return 0;
}

int git3_transaction_remove(git3_transaction *tx, const char *refname)
{
	int error;
	transaction_node *node;

	if ((error = find_locked(&node, tx, refname)) < 0)
		return error;

	node->remove = true;
	node->ref_type = GIT3_REFERENCE_DIRECT; /* the id will be ignored */

	return 0;
}

static int dup_reflog(git3_reflog **out, const git3_reflog *in, git3_pool *pool)
{
	git3_reflog *reflog;
	git3_reflog_entry *entries;
	size_t len, i;

	reflog = git3_pool_mallocz(pool, sizeof(git3_reflog));
	GIT3_ERROR_CHECK_ALLOC(reflog);

	reflog->ref_name = git3_pool_strdup(pool, in->ref_name);
	GIT3_ERROR_CHECK_ALLOC(reflog->ref_name);

	len = in->entries.length;
	reflog->entries.length = len;
	reflog->entries.contents = git3_pool_mallocz(pool, len * sizeof(void *));
	GIT3_ERROR_CHECK_ALLOC(reflog->entries.contents);

	entries = git3_pool_mallocz(pool, len * sizeof(git3_reflog_entry));
	GIT3_ERROR_CHECK_ALLOC(entries);

	for (i = 0; i < len; i++) {
		const git3_reflog_entry *src;
		git3_reflog_entry *tgt;

		tgt = &entries[i];
		reflog->entries.contents[i] = tgt;

		src = git3_vector_get(&in->entries, i);
		git3_oid_cpy(&tgt->oid_old, &src->oid_old);
		git3_oid_cpy(&tgt->oid_cur, &src->oid_cur);

		tgt->msg = git3_pool_strdup(pool, src->msg);
		GIT3_ERROR_CHECK_ALLOC(tgt->msg);

		if (git3_signature__pdup(&tgt->committer, src->committer, pool) < 0)
			return -1;
	}


	*out = reflog;
	return 0;
}

int git3_transaction_set_reflog(git3_transaction *tx, const char *refname, const git3_reflog *reflog)
{
	int error;
	transaction_node *node;

	GIT3_ASSERT_ARG(tx);
	GIT3_ASSERT_ARG(refname);
	GIT3_ASSERT_ARG(reflog);

	if ((error = find_locked(&node, tx, refname)) < 0)
		return error;

	if ((error = dup_reflog(&node->reflog, reflog, &tx->pool)) < 0)
		return error;

	return 0;
}

static int update_target(git3_refdb *db, transaction_node *node)
{
	git3_reference *ref;
	int error, update_reflog;

	if (node->ref_type == GIT3_REFERENCE_DIRECT) {
		ref = git3_reference__alloc(node->name, &node->target.id, NULL);
	} else if (node->ref_type == GIT3_REFERENCE_SYMBOLIC) {
		ref = git3_reference__alloc_symbolic(node->name, node->target.symbolic);
	} else {
		abort();
	}

	GIT3_ERROR_CHECK_ALLOC(ref);
	update_reflog = node->reflog == NULL;

	if (node->remove) {
		error =  git3_refdb_unlock(db, node->payload, 2, false, ref, NULL, NULL);
	} else if (node->ref_type == GIT3_REFERENCE_DIRECT) {
		error = git3_refdb_unlock(db, node->payload, true, update_reflog, ref, node->sig, node->message);
	} else if (node->ref_type == GIT3_REFERENCE_SYMBOLIC) {
		error = git3_refdb_unlock(db, node->payload, true, update_reflog, ref, node->sig, node->message);
	} else {
		abort();
	}

	git3_reference_free(ref);
	node->committed = true;

	return error;
}

int git3_transaction_commit(git3_transaction *tx)
{
	transaction_node *node;
	git3_hashmap_iter_t iter = GIT3_HASHMAP_ITER_INIT;
	int error = 0;

	GIT3_ASSERT_ARG(tx);

	if (tx->type == TRANSACTION_CONFIG) {
		error = git3_config_unlock(tx->cfg, tx->cfg_data, true);
		tx->cfg = NULL;
		tx->cfg_data = NULL;

		return error;
	}

	while (git3_transaction_nodemap_iterate(&iter, NULL, &node, &tx->locks) == 0) {
		if (node->reflog) {
			if ((error = tx->db->backend->reflog_write(tx->db->backend, node->reflog)) < 0)
				return error;
		}

		if (node->ref_type == GIT3_REFERENCE_INVALID) {
			/* ref was locked but not modified */
			if ((error = git3_refdb_unlock(tx->db, node->payload, false, false, NULL, NULL, NULL)) < 0) {
				return error;
			}
			node->committed = true;
		} else {
			if ((error = update_target(tx->db, node)) < 0)
				return error;
		}
	}

	return 0;
}

void git3_transaction_free(git3_transaction *tx)
{
	transaction_node *node;
	git3_pool pool;
	git3_hashmap_iter_t iter = GIT3_HASHMAP_ITER_INIT;

	if (!tx)
		return;

	if (tx->type == TRANSACTION_CONFIG) {
		if (tx->cfg)
			git3_config_unlock(tx->cfg, tx->cfg_data, false);

		git3__free(tx);
		return;
	}

	/* start by unlocking the ones we've left hanging, if any */
	while (git3_transaction_nodemap_iterate(&iter, NULL, &node, &tx->locks) == 0) {
		if (node->committed)
			continue;

		git3_refdb_unlock(tx->db, node->payload, false, false, NULL, NULL, NULL);
	}

	git3_refdb_free(tx->db);
	git3_transaction_nodemap_dispose(&tx->locks);

	/* tx is inside the pool, so we need to extract the data */
	memcpy(&pool, &tx->pool, sizeof(git3_pool));
	git3_pool_clear(&pool);
}
