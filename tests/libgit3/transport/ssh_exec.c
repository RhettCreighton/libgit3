#include "clar_libgit3.h"
#include "git3/sys/remote.h"
#include "git3/sys/transport.h"


void test_transport_ssh_exec__reject_injection_username(void)
{
#ifndef GIT3_SSH_EXEC
	cl_skip();
#else
	git3_remote *remote;
	git3_repository *repo;
	git3_transport *transport;
	const char *url = "-oProxyCommand=git@somehost:somepath";
	git3_remote_connect_options opts = GIT3_REMOTE_CONNECT_OPTIONS_INIT;


	cl_git_pass(git3_repository_init(&repo, "./transport-username", 0));
	cl_git_pass(git3_remote_create(&remote, repo, "test",
				      cl_fixture("testrepo.git")));
	cl_git_pass(git3_transport_new(&transport, remote, url));
	cl_git_fail_with(-1, transport->connect(transport, url,
						GIT3_SERVICE_UPLOADPACK_LS, &opts));

	transport->free(transport);
	git3_remote_free(remote);
	git3_repository_free(repo);
#endif
}

void test_transport_ssh_exec__reject_injection_hostname(void)
{
#ifndef GIT3_SSH_EXEC
	cl_skip();
#else
	git3_remote *remote;
	git3_repository *repo;
	git3_transport *transport;
	const char *url = "-oProxyCommand=somehost:somepath-hostname";
	git3_remote_connect_options opts = GIT3_REMOTE_CONNECT_OPTIONS_INIT;


	cl_git_pass(git3_repository_init(&repo, "./transport-hostname", 0));
	cl_git_pass(git3_remote_create(&remote, repo, "test",
				      cl_fixture("testrepo.git")));
	cl_git_pass(git3_transport_new(&transport, remote, url));
	cl_git_fail_with(-1, transport->connect(transport, url,
						GIT3_SERVICE_UPLOADPACK_LS, &opts));

	transport->free(transport);
	git3_remote_free(remote);
	git3_repository_free(repo);
#endif
}

void test_transport_ssh_exec__reject_injection_path(void)
{
#ifndef GIT3_SSH_EXEC
	cl_skip();
#else
	git3_remote *remote;
	git3_repository *repo;
	git3_transport *transport;
	const char *url = "git@somehost:-somepath";
	git3_remote_connect_options opts = GIT3_REMOTE_CONNECT_OPTIONS_INIT;


	cl_git_pass(git3_repository_init(&repo, "./transport-path", 0));
	cl_git_pass(git3_remote_create(&remote, repo, "test",
				      cl_fixture("testrepo.git")));
	cl_git_pass(git3_transport_new(&transport, remote, url));
	cl_git_fail_with(-1, transport->connect(transport, url,
						GIT3_SERVICE_UPLOADPACK_LS, &opts));

	transport->free(transport);
	git3_remote_free(remote);
	git3_repository_free(repo);
#endif
}
