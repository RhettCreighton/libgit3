/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_git_transaction_h__
#define INCLUDE_git_transaction_h__

#include "common.h"
#include "types.h"

/**
 * @file git3/transaction.h
 * @brief Transactional reference handling
 * @defgroup git3_transaction Transactional reference handling
 * @ingroup Git
 * @{
 */
GIT3_BEGIN_DECL

/**
 * Create a new transaction object
 *
 * This does not lock anything, but sets up the transaction object to
 * know from which repository to lock.
 *
 * @param out the resulting transaction
 * @param repo the repository in which to lock
 * @return 0 or an error code
 */
GIT3_EXTERN(int) git3_transaction_new(git3_transaction **out, git3_repository *repo);

/**
 * Lock a reference
 *
 * Lock the specified reference. This is the first step to updating a
 * reference.
 *
 * @param tx the transaction
 * @param refname the reference to lock
 * @return 0 or an error message
 */
GIT3_EXTERN(int) git3_transaction_lock_ref(git3_transaction *tx, const char *refname);

/**
 * Set the target of a reference
 *
 * Set the target of the specified reference. This reference must be
 * locked.
 *
 * @param tx the transaction
 * @param refname reference to update
 * @param target target to set the reference to
 * @param sig signature to use in the reflog; pass NULL to read the identity from the config
 * @param msg message to use in the reflog
 * @return 0, GIT3_ENOTFOUND if the reference is not among the locked ones, or an error code
 */
GIT3_EXTERN(int) git3_transaction_set_target(git3_transaction *tx, const char *refname, const git3_oid *target, const git3_signature *sig, const char *msg);

/**
 * Set the target of a reference
 *
 * Set the target of the specified reference. This reference must be
 * locked.
 *
 * @param tx the transaction
 * @param refname reference to update
 * @param target target to set the reference to
 * @param sig signature to use in the reflog; pass NULL to read the identity from the config
 * @param msg message to use in the reflog
 * @return 0, GIT3_ENOTFOUND if the reference is not among the locked ones, or an error code
 */
GIT3_EXTERN(int) git3_transaction_set_symbolic_target(git3_transaction *tx, const char *refname, const char *target, const git3_signature *sig, const char *msg);

/**
 * Set the reflog of a reference
 *
 * Set the specified reference's reflog. If this is combined with
 * setting the target, that update won't be written to the reflog.
 *
 * @param tx the transaction
 * @param refname the reference whose reflog to set
 * @param reflog the reflog as it should be written out
 * @return 0, GIT3_ENOTFOUND if the reference is not among the locked ones, or an error code
 */
GIT3_EXTERN(int) git3_transaction_set_reflog(git3_transaction *tx, const char *refname, const git3_reflog *reflog);

/**
 * Remove a reference
 *
 * @param tx the transaction
 * @param refname the reference to remove
 * @return 0, GIT3_ENOTFOUND if the reference is not among the locked ones, or an error code
 */
GIT3_EXTERN(int) git3_transaction_remove(git3_transaction *tx, const char *refname);

/**
 * Commit the changes from the transaction
 *
 * Perform the changes that have been queued. The updates will be made
 * one by one, and the first failure will stop the processing.
 *
 * @param tx the transaction
 * @return 0 or an error code
 */
GIT3_EXTERN(int) git3_transaction_commit(git3_transaction *tx);

/**
 * Free the resources allocated by this transaction
 *
 * If any references remain locked, they will be unlocked without any
 * changes made to them.
 *
 * @param tx the transaction
 */
GIT3_EXTERN(void) git3_transaction_free(git3_transaction *tx);

/** @} */
GIT3_END_DECL

#endif
