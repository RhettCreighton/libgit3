/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_transports_libssh2_h__
#define INCLUDE_transports_libssh2_h__

#include "common.h"

#include "git3.h"
#include "git3/transport.h"
#include "git3/sys/transport.h"

int git3_transport_ssh_libssh2_global_init(void);

int git3_smart_subtransport_ssh_libssh2(
	git3_smart_subtransport **out,
	git3_transport *owner,
	void *param);

int git3_smart_subtransport_ssh_libssh2_set_paths(
	git3_smart_subtransport *subtransport,
	const char *cmd_uploadpack,
	const char *cmd_receivepack);

#endif
