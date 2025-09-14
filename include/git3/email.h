/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_git_email_h__
#define INCLUDE_git_email_h__

#include "common.h"
#include "diff.h"

/**
 * @file git3/email.h
 * @brief Produce email-ready patches
 * @ingroup Git
 * @{
 */
GIT3_BEGIN_DECL

/**
 * Formatting options for diff e-mail generation
 */
typedef enum {
	/** Normal patch, the default */
	GIT3_EMAIL_CREATE_DEFAULT = 0,

	/** Do not include patch numbers in the subject prefix. */
	GIT3_EMAIL_CREATE_OMIT_NUMBERS = (1u << 0),

	/**
	 * Include numbers in the subject prefix even when the
	 * patch is for a single commit (1/1).
	 */
	GIT3_EMAIL_CREATE_ALWAYS_NUMBER = (1u << 1),

	/** Do not perform rename or similarity detection. */
	GIT3_EMAIL_CREATE_NO_RENAMES = (1u << 2)
} git3_email_create_flags_t;

/**
 * Options for controlling the formatting of the generated e-mail.
 */
typedef struct {
	unsigned int version;

	/** see `git3_email_create_flags_t` above */
	uint32_t flags;

	/** Options to use when creating diffs */
	git3_diff_options diff_opts;

	/** Options for finding similarities within diffs */
	git3_diff_find_options diff_find_opts;

	/**
	 * The subject prefix, by default "PATCH".  If set to an empty
	 * string ("") then only the patch numbers will be shown in the
	 * prefix.  If the subject_prefix is empty and patch numbers
	 * are not being shown, the prefix will be omitted entirely.
	 */
	const char *subject_prefix;

	/**
	 * The starting patch number; this cannot be 0.  By default,
	 * this is 1.
	 */
	size_t start_number;

	/** The "re-roll" number.  By default, there is no re-roll. */
	size_t reroll_number;
} git3_email_create_options;

/** Current version for the `git3_email_create_options` structure */
#define GIT3_EMAIL_CREATE_OPTIONS_VERSION 1

/** Static constructor for `git3_email_create_options`
 *
 * By default, our options include rename detection and binary
 * diffs to match `git format-patch`.
 */
#define GIT3_EMAIL_CREATE_OPTIONS_INIT \
{ \
	GIT3_EMAIL_CREATE_OPTIONS_VERSION, \
	GIT3_EMAIL_CREATE_DEFAULT, \
	{ GIT3_DIFF_OPTIONS_VERSION, GIT3_DIFF_SHOW_BINARY, GIT3_SUBMODULE_IGNORE_UNSPECIFIED, {NULL,0}, NULL, NULL, NULL, 3 }, \
	GIT3_DIFF_FIND_OPTIONS_INIT \
}

/**
 * Create a diff for a commit in mbox format for sending via email.
 * The commit must not be a merge commit.
 *
 * @param out buffer to store the e-mail patch in
 * @param commit commit to create a patch for
 * @param opts email creation options
 * @return 0 or an error code
 */
GIT3_EXTERN(int) git3_email_create_from_commit(
	git3_buf *out,
	git3_commit *commit,
	const git3_email_create_options *opts);

/** @} */
GIT3_END_DECL

#endif
