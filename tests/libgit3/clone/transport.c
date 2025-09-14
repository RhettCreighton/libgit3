#include "clar_libgit3.h"

#include "git3/clone.h"
#include "git3/transport.h"
#include "git3/sys/transport.h"
#include "futils.h"

static int custom_transport(
	git3_transport **out,
	git3_remote *owner,
	void *payload)
{
	*((int*)payload) = 1;

	return git3_transport_local(out, owner, payload);
}

static int custom_transport_remote_create(
	git3_remote **out,
	git3_repository *repo,
	const char *name,
	const char *url,
	void *payload)
{
	int error;

	GIT3_UNUSED(payload);

	if ((error = git3_remote_create(out, repo, name, url)) < 0)
		return error;

	return 0;
}

void test_clone_transport__custom_transport(void)
{
	git3_repository *repo;
	git3_clone_options clone_opts = GIT3_CLONE_OPTIONS_INIT;
	int custom_transport_used = 0;

	clone_opts.remote_cb = custom_transport_remote_create;
	clone_opts.fetch_opts.callbacks.transport = custom_transport;
	clone_opts.fetch_opts.callbacks.payload = &custom_transport_used;

	cl_git_pass(git3_clone(&repo, cl_fixture("testrepo.git"), "./custom_transport.git", &clone_opts));
	git3_repository_free(repo);

	cl_git_pass(git3_futils_rmdir_r("./custom_transport.git", NULL, GIT3_RMDIR_REMOVE_FILES));

	cl_assert(custom_transport_used == 1);
}
