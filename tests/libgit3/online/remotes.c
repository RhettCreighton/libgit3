#include "clar_libgit3.h"

#define URL "https://github.com/libgit3/TestGitRepository"
#define REFSPEC "refs/heads/first-merge:refs/remotes/origin/first-merge"

static int remote_single_branch(git3_remote **out, git3_repository *repo, const char *name, const char *url, void *payload)
{
	GIT3_UNUSED(payload);

	cl_git_pass(git3_remote_create_with_fetchspec(out, repo, name, url, REFSPEC));

	return 0;
}

void test_online_remotes__single_branch(void)
{
	git3_clone_options opts = GIT3_CLONE_OPTIONS_INIT;
	git3_repository *repo;
	git3_remote *remote;
	git3_strarray refs;
	size_t i, count = 0;

	opts.remote_cb = remote_single_branch;
	opts.checkout_branch = "first-merge";

	cl_git_pass(git3_clone(&repo, URL, "./single-branch", &opts));
	cl_git_pass(git3_reference_list(&refs, repo));

	for (i = 0; i < refs.count; i++) {
		if (!git3__prefixcmp(refs.strings[i], "refs/heads/"))
			count++;
	}
	cl_assert_equal_i(1, count);

	git3_strarray_dispose(&refs);

	cl_git_pass(git3_remote_lookup(&remote, repo, "origin"));
	cl_git_pass(git3_remote_get_fetch_refspecs(&refs, remote));

	cl_assert_equal_i(1, refs.count);
	cl_assert_equal_s(REFSPEC, refs.strings[0]);

	git3_strarray_dispose(&refs);
	git3_remote_free(remote);
	git3_repository_free(repo);
}

void test_online_remotes__restricted_refspecs(void)
{
	git3_clone_options opts = GIT3_CLONE_OPTIONS_INIT;
	git3_repository *repo;

	opts.remote_cb = remote_single_branch;

	cl_git_fail_with(GIT3_EINVALIDSPEC, git3_clone(&repo, URL, "./restrict-refspec", &opts));
}

void test_online_remotes__detached_remote_fails_downloading(void)
{
	git3_remote *remote;

	cl_git_pass(git3_remote_create_detached(&remote, URL));
	cl_git_pass(git3_remote_connect(remote, GIT3_DIRECTION_FETCH, NULL, NULL, NULL));
	cl_git_fail(git3_remote_download(remote, NULL, NULL));

	git3_remote_free(remote);
}

void test_online_remotes__detached_remote_fails_uploading(void)
{
	git3_remote *remote;

	cl_git_pass(git3_remote_create_detached(&remote, URL));
	cl_git_pass(git3_remote_connect(remote, GIT3_DIRECTION_FETCH, NULL, NULL, NULL));
	cl_git_fail(git3_remote_upload(remote, NULL, NULL));

	git3_remote_free(remote);
}

void test_online_remotes__detached_remote_fails_pushing(void)
{
	git3_remote *remote;

	cl_git_pass(git3_remote_create_detached(&remote, URL));
	cl_git_pass(git3_remote_connect(remote, GIT3_DIRECTION_FETCH, NULL, NULL, NULL));
	cl_git_fail(git3_remote_push(remote, NULL, NULL));

	git3_remote_free(remote);
}

void test_online_remotes__detached_remote_succeeds_ls(void)
{
	const char *refs[] = {
	    "HEAD",
	    "refs/heads/first-merge",
	    "refs/heads/master",
	    "refs/heads/no-parent",
	    "refs/tags/annotated_tag",
	    "refs/tags/annotated_tag^{}",
	    "refs/tags/blob",
	    "refs/tags/commit_tree",
	    "refs/tags/nearly-dangling",
	};
	const git3_remote_head **heads;
	git3_remote *remote;
	size_t i, j, n;

	cl_git_pass(git3_remote_create_detached(&remote, URL));
	cl_git_pass(git3_remote_connect(remote, GIT3_DIRECTION_FETCH, NULL, NULL, NULL));
	cl_git_pass(git3_remote_ls(&heads, &n, remote));

	cl_assert_equal_sz(n, 9);
	for (i = 0; i < n; i++) {
		char found = false;

		for (j = 0; j < ARRAY_SIZE(refs); j++) {
			if (!strcmp(heads[i]->name, refs[j])) {
				found = true;
				break;
			}
		}

		cl_assert_(found, heads[i]->name);
	}

	git3_remote_free(remote);
}
