/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_git_signature_h__
#define INCLUDE_git_signature_h__

#include "common.h"
#include "types.h"

/**
 * @file git3/signature.h
 * @brief Signatures are the actor in a repository and when they acted
 * @defgroup git3_signature Git signature creation
 * @ingroup Git
 *
 * Signatures contain the information about the actor (committer or
 * author) in a repository, and the time that they performed the
 * commit, or authoring.
 * @{
 */
GIT3_BEGIN_DECL

/**
 * Create a new action signature.
 *
 * Call `git3_signature_free()` to free the data.
 *
 * Note: angle brackets ('<' and '>') characters are not allowed
 * to be used in either the `name` or the `email` parameter.
 *
 * @param out new signature, in case of error NULL
 * @param name name of the person
 * @param email email of the person
 * @param time time (in seconds from epoch) when the action happened
 * @param offset timezone offset (in minutes) for the time
 * @return 0 or an error code
 */
GIT3_EXTERN(int) git3_signature_new(git3_signature **out, const char *name, const char *email, git3_time_t time, int offset);

/**
 * Create a new action signature with a timestamp of 'now'.
 *
 * Call `git3_signature_free()` to free the data.
 *
 * @param out new signature, in case of error NULL
 * @param name name of the person
 * @param email email of the person
 * @return 0 or an error code
 */
GIT3_EXTERN(int) git3_signature_now(git3_signature **out, const char *name, const char *email);

/**
 * Create a new author and/or committer signatures with default
 * information based on the configuration and environment variables.
 *
 * If `author_out` is set, it will be populated with the author
 * information. The `GIT3_AUTHOR_NAME` and `GIT3_AUTHOR_EMAIL`
 * environment variables will be honored, and `user.name` and
 * `user.email` configuration options will be honored if the
 * environment variables are unset. For timestamps, `GIT3_AUTHOR_DATE`
 * will be used, otherwise the current time will be used.
 *
 * If `committer_out` is set, it will be populated with the
 * committer information. The `GIT3_COMMITTER_NAME` and
 * `GIT3_COMMITTER_EMAIL` environment variables will be honored,
 * and `user.name` and `user.email` configuration options will
 * be honored if the environment variables are unset. For timestamps,
 * `GIT3_COMMITTER_DATE` will be used, otherwise the current time will
 * be used.
 *
 * If neither `GIT3_AUTHOR_DATE` nor `GIT3_COMMITTER_DATE` are set,
 * both timestamps will be set to the same time.
 *
 * It will return `GIT3_ENOTFOUND` if either the `user.name` or
 * `user.email` are not set and there is no fallback from an environment
 * variable. One of `author_out` or `committer_out` must be set.
 *
 * @param author_out pointer to set the author signature, or NULL
 * @param committer_out pointer to set the committer signature, or NULL
 * @param repo repository pointer
 * @return 0 on success, GIT3_ENOTFOUND if config is missing, or error code
 */
GIT3_EXTERN(int) git3_signature_default_from_env(
	git3_signature **author_out,
	git3_signature **committer_out,
	git3_repository *repo);

/**
 * Create a new action signature with default user and now timestamp.
 *
 * This looks up the user.name and user.email from the configuration and
 * uses the current time as the timestamp, and creates a new signature
 * based on that information.  It will return GIT3_ENOTFOUND if either the
 * user.name or user.email are not set.
 *
 * Note that these do not examine environment variables, only the
 * configuration files. Use `git3_signature_default_from_env` to
 * consider the environment variables.
 *
 * @param out new signature
 * @param repo repository pointer
 * @return 0 on success, GIT3_ENOTFOUND if config is missing, or error code
 */
GIT3_EXTERN(int) git3_signature_default(git3_signature **out, git3_repository *repo);

/**
 * Create a new signature by parsing the given buffer, which is
 * expected to be in the format "Real Name <email> timestamp tzoffset",
 * where `timestamp` is the number of seconds since the Unix epoch and
 * `tzoffset` is the timezone offset in `hhmm` format (note the lack
 * of a colon separator).
 *
 * @param out new signature
 * @param buf signature string
 * @return 0 on success, GIT3_EINVALID if the signature is not parseable, or an error code
 */
GIT3_EXTERN(int) git3_signature_from_buffer(git3_signature **out, const char *buf);

/**
 * Create a copy of an existing signature.  All internal strings are also
 * duplicated.
 *
 * Call `git3_signature_free()` to free the data.
 *
 * @param dest pointer where to store the copy
 * @param sig signature to duplicate
 * @return 0 or an error code
 */
GIT3_EXTERN(int) git3_signature_dup(git3_signature **dest, const git3_signature *sig);

/**
 * Free an existing signature.
 *
 * Because the signature is not an opaque structure, it is legal to free it
 * manually, but be sure to free the "name" and "email" strings in addition
 * to the structure itself.
 *
 * @param sig signature to free
 */
GIT3_EXTERN(void) git3_signature_free(git3_signature *sig);

/** @} */
GIT3_END_DECL

#endif
