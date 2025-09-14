/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#ifndef INCLUDE_sys_git_remote_h
#define INCLUDE_sys_git_remote_h

#include "git3/remote.h"

/**
 * @file git3/sys/remote.h
 * @brief Low-level remote functionality for custom transports
 * @defgroup git3_remote Low-level remote functionality for custom transports
 * @ingroup Git
 * @{
*/

GIT3_BEGIN_DECL

/**
 * A remote's capabilities.
 */
typedef enum {
	/** Remote supports fetching an advertised object by ID. */
	GIT3_REMOTE_CAPABILITY_TIP_OID = (1 << 0),

	/** Remote supports fetching an individual reachable object. */
	GIT3_REMOTE_CAPABILITY_REACHABLE_OID = (1 << 1),

	/** Remote supports push options. */
	GIT3_REMOTE_CAPABILITY_PUSH_OPTIONS = (1 << 2),
} git3_remote_capability_t;

/**
 * Disposes libgit3-initialized fields from a git3_remote_connect_options.
 * This should only be used for git3_remote_connect_options returned by
 * git3_transport_remote_connect_options.
 *
 * Note that this does not free the `git3_remote_connect_options` itself, just
 * the memory pointed to by it.
 *
 * @param opts The `git3_remote_connect_options` struct to dispose.
 */
GIT3_EXTERN(void) git3_remote_connect_options_dispose(
		git3_remote_connect_options *opts);

/** @} */
GIT3_END_DECL

#endif
