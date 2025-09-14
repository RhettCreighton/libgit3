/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_git_refspec_h__
#define INCLUDE_git_refspec_h__

#include "common.h"
#include "types.h"
#include "net.h"
#include "buffer.h"

/**
 * @file git3/refspec.h
 * @brief Refspecs map local references to remote references
 * @defgroup git3_refspec Refspecs map local references to remote references
 * @ingroup Git
 * @{
 */
GIT3_BEGIN_DECL

/**
 * Parse a given refspec string
 *
 * @param refspec a pointer to hold the refspec handle
 * @param input the refspec string
 * @param is_fetch is this a refspec for a fetch
 * @return 0 if the refspec string could be parsed, -1 otherwise
 */
GIT3_EXTERN(int) git3_refspec_parse(git3_refspec **refspec, const char *input, int is_fetch);

/**
 * Free a refspec object which has been created by git3_refspec_parse
 *
 * @param refspec the refspec object
 */
GIT3_EXTERN(void) git3_refspec_free(git3_refspec *refspec);

/**
 * Get the source specifier
 *
 * @param refspec the refspec
 * @return the refspec's source specifier
 */
GIT3_EXTERN(const char *) git3_refspec_src(const git3_refspec *refspec);

/**
 * Get the destination specifier
 *
 * @param refspec the refspec
 * @return the refspec's destination specifier
 */
GIT3_EXTERN(const char *) git3_refspec_dst(const git3_refspec *refspec);

/**
 * Get the refspec's string
 *
 * @param refspec the refspec
 * @return the refspec's original string
 */
GIT3_EXTERN(const char *) git3_refspec_string(const git3_refspec *refspec);

/**
 * Get the force update setting
 *
 * @param refspec the refspec
 * @return 1 if force update has been set, 0 otherwise
 */
GIT3_EXTERN(int) git3_refspec_force(const git3_refspec *refspec);

/**
 * Get the refspec's direction.
 *
 * @param spec refspec
 * @return GIT3_DIRECTION_FETCH or GIT3_DIRECTION_PUSH
 */
GIT3_EXTERN(git3_direction) git3_refspec_direction(const git3_refspec *spec);

/**
 * Check if a refspec's source descriptor matches a negative reference
 *
 * @param refspec the refspec
 * @param refname the name of the reference to check
 * @return 1 if the refspec matches, 0 otherwise
 */
GIT3_EXTERN(int) git3_refspec_src_matches_negative(const git3_refspec *refspec, const char *refname);

/**
 * Check if a refspec's source descriptor matches a reference
 *
 * @param refspec the refspec
 * @param refname the name of the reference to check
 * @return 1 if the refspec matches, 0 otherwise
 */
GIT3_EXTERN(int) git3_refspec_src_matches(const git3_refspec *refspec, const char *refname);

/**
 * Check if a refspec's destination descriptor matches a reference
 *
 * @param refspec the refspec
 * @param refname the name of the reference to check
 * @return 1 if the refspec matches, 0 otherwise
 */
GIT3_EXTERN(int) git3_refspec_dst_matches(const git3_refspec *refspec, const char *refname);

/**
 * Transform a reference to its target following the refspec's rules
 *
 * @param out where to store the target name
 * @param spec the refspec
 * @param name the name of the reference to transform
 * @return 0, GIT3_EBUFS or another error
 */
GIT3_EXTERN(int) git3_refspec_transform(git3_buf *out, const git3_refspec *spec, const char *name);

/**
 * Transform a target reference to its source reference following the refspec's rules
 *
 * @param out where to store the source reference name
 * @param spec the refspec
 * @param name the name of the reference to transform
 * @return 0, GIT3_EBUFS or another error
 */
GIT3_EXTERN(int) git3_refspec_rtransform(git3_buf *out, const git3_refspec *spec, const char *name);

/** @} */
GIT3_END_DECL

#endif
