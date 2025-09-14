#include "clar_libgit3.h"

#include "git3/clone.h"
#include "clone.h"
#include "path.h"
#include "posix.h"
#include "futils.h"

static int file_url(git3_str *buf, const char *host, const char *path)
{
	if (path[0] == '/')
		path++;

	git3_str_clear(buf);
	return git3_str_printf(buf, "file://%s/%s", host, path);
}

#ifdef GIT3_WIN32
static int git3_style_unc_path(git3_str *buf, const char *host, const char *path)
{
	git3_str_clear(buf);

	if (host)
		git3_str_printf(buf, "//%s/", host);

	if (path[0] == '/')
		path++;

	if (git3__isalpha(path[0]) && path[1] == ':' && path[2] == '/') {
		git3_str_printf(buf, "%c$/", path[0]);
		path += 3;
	}

	git3_str_puts(buf, path);

	return git3_str_oom(buf) ? -1 : 0;
}

static int unc_path(git3_str *buf, const char *host, const char *path)
{
	char *c;

	if (git3_style_unc_path(buf, host, path) < 0)
		return -1;

	for (c = buf->ptr; *c; c++)
		if (*c == '/')
			*c = '\\';

	return 0;
}
#endif

void test_clone_local__should_clone_local(void)
{
	git3_str buf = GIT3_STR_INIT;
	bool local;

	/* we use a fixture path because it needs to exist for us to want to clone */
	const char *path = cl_fixture("testrepo.git");

	/* empty string */
	cl_git_pass(file_url(&buf, "", path));
	cl_git_pass(git3_clone__should_clone_local(&local, buf.ptr, GIT3_CLONE_LOCAL_AUTO));
	cl_assert_equal_i(false, local);

	cl_git_pass(git3_clone__should_clone_local(&local, buf.ptr, GIT3_CLONE_LOCAL_AUTO));
	cl_assert_equal_i(false, local);

	cl_git_pass(git3_clone__should_clone_local(&local, buf.ptr, GIT3_CLONE_LOCAL));
	cl_assert_equal_i(true, local);

	cl_git_pass(git3_clone__should_clone_local(&local, buf.ptr, GIT3_CLONE_LOCAL_NO_LINKS));
	cl_assert_equal_i(true, local);

	cl_git_pass(git3_clone__should_clone_local(&local, buf.ptr, GIT3_CLONE_NO_LOCAL));
	cl_assert_equal_i(false, local);

	/* localhost is special */
	cl_git_pass(file_url(&buf, "localhost", path));
	cl_git_pass(git3_clone__should_clone_local(&local, buf.ptr, GIT3_CLONE_LOCAL_AUTO));
	cl_assert_equal_i(false, local);

	cl_git_pass(git3_clone__should_clone_local(&local, buf.ptr, GIT3_CLONE_LOCAL));
	cl_assert_equal_i(true, local);

	cl_git_pass(git3_clone__should_clone_local(&local, buf.ptr, GIT3_CLONE_LOCAL_NO_LINKS));
	cl_assert_equal_i(true, local);

	cl_git_pass(git3_clone__should_clone_local(&local, buf.ptr, GIT3_CLONE_NO_LOCAL));
	cl_assert_equal_i(false, local);

	/* a remote host */
	cl_git_pass(file_url(&buf, "other-host.mycompany.com", path));

	cl_git_pass(git3_clone__should_clone_local(&local, buf.ptr, GIT3_CLONE_LOCAL_AUTO));
	cl_assert_equal_i(false, local);

	cl_git_pass(git3_clone__should_clone_local(&local, buf.ptr, GIT3_CLONE_LOCAL));
	cl_assert_equal_i(false, local);

	cl_git_pass(git3_clone__should_clone_local(&local, buf.ptr, GIT3_CLONE_LOCAL_NO_LINKS));
	cl_assert_equal_i(false, local);

	cl_git_pass(git3_clone__should_clone_local(&local, buf.ptr, GIT3_CLONE_NO_LOCAL));
	cl_assert_equal_i(false, local);

	/* Ensure that file:/// urls are percent decoded: .git == %2e%67%69%74 */
	cl_git_pass(file_url(&buf, "", path));
	git3_str_shorten(&buf, 4);
	cl_git_pass(git3_str_puts(&buf, "%2e%67%69%74"));

	cl_git_pass(git3_clone__should_clone_local(&local, buf.ptr, GIT3_CLONE_LOCAL_AUTO));
	cl_assert_equal_i(false, local);

	cl_git_pass(git3_clone__should_clone_local(&local, buf.ptr, GIT3_CLONE_LOCAL));
	cl_assert_equal_i(true, local);

	cl_git_pass(git3_clone__should_clone_local(&local, buf.ptr, GIT3_CLONE_LOCAL_NO_LINKS));
	cl_assert_equal_i(true, local);

	cl_git_pass(git3_clone__should_clone_local(&local, buf.ptr, GIT3_CLONE_NO_LOCAL));
	cl_assert_equal_i(false, local);

	/* a local path on disk */
	cl_git_pass(git3_clone__should_clone_local(&local, path, GIT3_CLONE_LOCAL_AUTO));
	cl_assert_equal_i(true, local);

	cl_git_pass(git3_clone__should_clone_local(&local, path, GIT3_CLONE_LOCAL));

	cl_assert_equal_i(true, local);

	cl_git_pass(git3_clone__should_clone_local(&local, path, GIT3_CLONE_LOCAL_NO_LINKS));
	cl_assert_equal_i(true, local);

	cl_git_pass(git3_clone__should_clone_local(&local, path, GIT3_CLONE_NO_LOCAL));
	cl_assert_equal_i(false, local);

	git3_str_dispose(&buf);
}

void test_clone_local__hardlinks(void)
{
	git3_repository *repo;
	git3_clone_options opts = GIT3_CLONE_OPTIONS_INIT;
	git3_str buf = GIT3_STR_INIT;
	struct stat st;

	/*
	 * In this first clone, we just copy over, since the temp dir
	 * will often be in a different filesystem, so we cannot
	 * link. It also allows us to control the number of links
	 */
	opts.bare = true;
	opts.local = GIT3_CLONE_LOCAL_NO_LINKS;
	cl_git_pass(git3_clone(&repo, cl_fixture("testrepo.git"), "./clone.git", &opts));
	git3_repository_free(repo);

	/* This second clone is in the same filesystem, so we can hardlink */

	opts.local = GIT3_CLONE_LOCAL;
	cl_git_pass(git3_clone(&repo, cl_git_path_url("clone.git"), "./clone2.git", &opts));

#ifndef GIT3_WIN32
	git3_str_clear(&buf);
	cl_git_pass(git3_str_join_n(&buf, '/', 4, git3_repository_path(repo), "objects", "08", "b041783f40edfe12bb406c9c9a8a040177c125"));

	cl_git_pass(p_stat(buf.ptr, &st));
	cl_assert_equal_i(2, st.st_nlink);
#endif

	git3_repository_free(repo);
	git3_str_clear(&buf);

	opts.local = GIT3_CLONE_LOCAL_NO_LINKS;
	cl_git_pass(git3_clone(&repo, cl_git_path_url("clone.git"), "./clone3.git", &opts));

	git3_str_clear(&buf);
	cl_git_pass(git3_str_join_n(&buf, '/', 4, git3_repository_path(repo), "objects", "08", "b041783f40edfe12bb406c9c9a8a040177c125"));

	cl_git_pass(p_stat(buf.ptr, &st));
	cl_assert_equal_i(1, st.st_nlink);

	git3_repository_free(repo);

	/* this one should automatically use links */
	cl_git_pass(git3_clone(&repo, "./clone.git", "./clone4.git", NULL));

#ifndef GIT3_WIN32
	git3_str_clear(&buf);
	cl_git_pass(git3_str_join_n(&buf, '/', 4, git3_repository_path(repo), "objects", "08", "b041783f40edfe12bb406c9c9a8a040177c125"));

	cl_git_pass(p_stat(buf.ptr, &st));
	cl_assert_equal_i(3, st.st_nlink);
#endif

	git3_str_dispose(&buf);
	git3_repository_free(repo);

	cl_git_pass(git3_futils_rmdir_r("./clone.git", NULL, GIT3_RMDIR_REMOVE_FILES));
	cl_git_pass(git3_futils_rmdir_r("./clone2.git", NULL, GIT3_RMDIR_REMOVE_FILES));
	cl_git_pass(git3_futils_rmdir_r("./clone3.git", NULL, GIT3_RMDIR_REMOVE_FILES));
	cl_git_pass(git3_futils_rmdir_r("./clone4.git", NULL, GIT3_RMDIR_REMOVE_FILES));
}

void test_clone_local__standard_unc_paths_are_written_git_style(void)
{
#ifdef GIT3_WIN32
	git3_repository *repo;
	git3_remote *remote;
	git3_clone_options opts = GIT3_CLONE_OPTIONS_INIT;
	git3_str unc = GIT3_STR_INIT, git3_unc = GIT3_STR_INIT;

	/* we use a fixture path because it needs to exist for us to want to clone */
	const char *path = cl_fixture("testrepo.git");

	cl_git_pass(unc_path(&unc, "localhost", path));
	cl_git_pass(git3_style_unc_path(&git3_unc, "localhost", path));

	cl_git_pass(git3_clone(&repo, unc.ptr, "./clone.git", &opts));
	cl_git_pass(git3_remote_lookup(&remote, repo, "origin"));

	cl_assert_equal_s(git3_unc.ptr, git3_remote_url(remote));

	git3_remote_free(remote);
	git3_repository_free(repo);
	git3_str_dispose(&unc);
	git3_str_dispose(&git3_unc);

	cl_git_pass(git3_futils_rmdir_r("./clone.git", NULL, GIT3_RMDIR_REMOVE_FILES));
#endif
}

void test_clone_local__git_style_unc_paths(void)
{
#ifdef GIT3_WIN32
	git3_repository *repo;
	git3_remote *remote;
	git3_clone_options opts = GIT3_CLONE_OPTIONS_INIT;
	git3_str git3_unc = GIT3_STR_INIT;

	/* we use a fixture path because it needs to exist for us to want to clone */
	const char *path = cl_fixture("testrepo.git");

	cl_git_pass(git3_style_unc_path(&git3_unc, "localhost", path));

	cl_git_pass(git3_clone(&repo, git3_unc.ptr, "./clone.git", &opts));
	cl_git_pass(git3_remote_lookup(&remote, repo, "origin"));

	cl_assert_equal_s(git3_unc.ptr, git3_remote_url(remote));

	git3_remote_free(remote);
	git3_repository_free(repo);
	git3_str_dispose(&git3_unc);

	cl_git_pass(git3_futils_rmdir_r("./clone.git", NULL, GIT3_RMDIR_REMOVE_FILES));
#endif
}

void test_clone_local__shallow_fails(void)
{
	git3_repository *repo;
	git3_clone_options opts = GIT3_CLONE_OPTIONS_INIT;

	opts.fetch_opts.depth = 4;

	cl_git_fail_with(GIT3_ENOTSUPPORTED, git3_clone(&repo, cl_fixture("testrepo.git"), "./clone.git", &opts));
}
