/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_git_net_h__
#define INCLUDE_git_net_h__

#include "common.h"
#include "oid.h"
#include "types.h"

/**
 * @file git3/net.h
 * @brief Low-level networking functionality
 * @ingroup Git
 * @{
 */
GIT3_BEGIN_DECL

/** Default git protocol port number */
#define GIT3_DEFAULT_PORT "9418"

/**
 * Direction of the connection.
 *
 * We need this because we need to know whether we should call
 * git-upload-pack or git-receive-pack on the remote end when get_refs
 * gets called.
 */
typedef enum {
	GIT3_DIRECTION_FETCH = 0,
	GIT3_DIRECTION_PUSH  = 1
} git3_direction;

/**
 * Description of a reference advertised by a remote server, given out
 * on `ls` calls.
 */
struct git3_remote_head {
	int local; /* available locally */
	git3_oid oid;
	git3_oid loid;
	char *name;
	/**
	 * If the server send a symref mapping for this ref, this will
	 * point to the target.
	 */
	char *symref_target;
};

/** @} */
GIT3_END_DECL

#endif
