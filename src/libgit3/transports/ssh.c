/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "ssh_exec.h"
#include "ssh_libssh2.h"

#include "transports/smart.h"

int git3_smart_subtransport_ssh(
	git3_smart_subtransport **out,
	git3_transport *owner,
	void *param)
{
#ifdef GIT3_SSH_LIBSSH2
	return git3_smart_subtransport_ssh_libssh2(out, owner, param);
#elif GIT3_SSH_EXEC
	return git3_smart_subtransport_ssh_exec(out, owner, param);
#else
	GIT3_UNUSED(out);
	GIT3_UNUSED(owner);
	GIT3_UNUSED(param);

	git3_error_set(GIT3_ERROR_INVALID, "cannot create SSH transport; library was built without SSH support");
	return -1;
#endif
}

static int transport_set_paths(git3_transport *t, git3_strarray *paths)
{
	transport_smart *smart = (transport_smart *)t;

#ifdef GIT3_SSH_LIBSSH2
	return git3_smart_subtransport_ssh_libssh2_set_paths(
		(git3_smart_subtransport *)smart->wrapped,
		paths->strings[0],
		paths->strings[1]);
#elif GIT3_SSH_EXEC
	return git3_smart_subtransport_ssh_exec_set_paths(
		(git3_smart_subtransport *)smart->wrapped,
		paths->strings[0],
		paths->strings[1]);
#else
	GIT3_UNUSED(t);
	GIT3_UNUSED(smart);
	GIT3_UNUSED(paths);

	GIT3_ASSERT(!"cannot create SSH library; library was built without SSH support");
	return -1;
#endif
}

int git3_transport_ssh_with_paths(
	git3_transport **out,
	git3_remote *owner,
	void *payload)
{
	git3_strarray *paths = (git3_strarray *) payload;
	git3_transport *transport;
	int error;

	git3_smart_subtransport_definition ssh_definition = {
		git3_smart_subtransport_ssh,
		0, /* no RPC */
		NULL
	};

	if (paths->count != 2) {
		git3_error_set(GIT3_ERROR_SSH, "invalid ssh paths, must be two strings");
		return GIT3_EINVALIDSPEC;
	}

	if ((error = git3_transport_smart(&transport, owner, &ssh_definition)) < 0)
		return error;

	if ((error = transport_set_paths(transport, paths)) < 0)
		return error;

	*out = transport;
	return 0;
}

