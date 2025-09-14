/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_sys_git_email_h__
#define INCLUDE_sys_git_email_h__

#include "git3/common.h"
#include "git3/diff.h"
#include "git3/email.h"
#include "git3/types.h"

/**
 * @file git3/sys/email.h
 * @brief Advanced git email creation routines
 * @defgroup git3_email Advanced git email creation routines
 * @ingroup Git
 * @{
 */
GIT3_BEGIN_DECL

/**
 * Create a diff for a commit in mbox format for sending via email.
 *
 * @param out buffer to store the e-mail patch in
 * @param diff the changes to include in the email
 * @param patch_idx the patch index
 * @param patch_count the total number of patches that will be included
 * @param commit_id the commit id for this change
 * @param summary the commit message for this change
 * @param body optional text to include above the diffstat
 * @param author the person who authored this commit
 * @param opts email creation options
 * @return 0 on success or an error code
 */
GIT3_EXTERN(int) git3_email_create_from_diff(
	git3_buf *out,
	git3_diff *diff,
	size_t patch_idx,
	size_t patch_count,
	const git3_oid *commit_id,
	const char *summary,
	const char *body,
	const git3_signature *author,
	const git3_email_create_options *opts);

/** @} */
GIT3_END_DECL

#endif
