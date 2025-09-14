#include "clar_libgit3.h"
#include "posix.h"
#include "path.h"
#include "submodule_helpers.h"
#include "futils.h"

static git3_repository *g_repo = NULL;

void test_submodule_init__cleanup(void)
{
	cl_git_sandbox_cleanup();
}

void test_submodule_init__absolute_url(void)
{
	git3_submodule *sm;
	git3_config *cfg;
	git3_str absolute_url = GIT3_STR_INIT;
	const char *config_url;

	g_repo = setup_fixture_submodule_simple();

	cl_assert(git3_fs_path_dirname_r(&absolute_url, git3_repository_workdir(g_repo)) > 0);
	cl_git_pass(git3_str_joinpath(&absolute_url, absolute_url.ptr, "testrepo.git"));

	/* write the absolute url to the .gitmodules file*/
	cl_git_pass(git3_submodule_set_url(g_repo, "testrepo", absolute_url.ptr));

	cl_git_pass(git3_submodule_lookup(&sm, g_repo, "testrepo"));

	/* verify that the .gitmodules is set with an absolute path*/
	cl_assert_equal_s(absolute_url.ptr, git3_submodule_url(sm));

	/* init and verify that absolute path is written to .git/config */
	cl_git_pass(git3_submodule_init(sm, false));

	cl_git_pass(git3_repository_config_snapshot(&cfg, g_repo));

	cl_git_pass(git3_config_get_string(&config_url, cfg, "submodule.testrepo.url"));
	cl_assert_equal_s(absolute_url.ptr, config_url);

	git3_str_dispose(&absolute_url);
	git3_config_free(cfg);
	git3_submodule_free(sm);
}

void test_submodule_init__relative_url(void)
{
	git3_submodule *sm;
	git3_config *cfg;
	git3_str absolute_url = GIT3_STR_INIT;
	const char *config_url;

	g_repo = setup_fixture_submodule_simple();

	cl_assert(git3_fs_path_dirname_r(&absolute_url, git3_repository_workdir(g_repo)) > 0);
	cl_git_pass(git3_str_joinpath(&absolute_url, absolute_url.ptr, "testrepo.git"));

	cl_git_pass(git3_submodule_lookup(&sm, g_repo, "testrepo"));

	/* verify that the .gitmodules is set with an absolute path*/
	cl_assert_equal_s("../testrepo.git", git3_submodule_url(sm));

	/* init and verify that absolute path is written to .git/config */
	cl_git_pass(git3_submodule_init(sm, false));

	cl_git_pass(git3_repository_config_snapshot(&cfg, g_repo));

	cl_git_pass(git3_config_get_string(&config_url, cfg, "submodule.testrepo.url"));
	cl_assert_equal_s(absolute_url.ptr, config_url);

	git3_str_dispose(&absolute_url);
	git3_config_free(cfg);
	git3_submodule_free(sm);
}

void test_submodule_init__relative_url_detached_head(void)
{
	git3_submodule *sm;
	git3_config *cfg;
	git3_str absolute_url = GIT3_STR_INIT;
	const char *config_url;
	git3_reference *head_ref = NULL;
	git3_object *head_commit = NULL;

	g_repo = setup_fixture_submodule_simple();

	/* Put the parent repository into a detached head state. */
	cl_git_pass(git3_repository_head(&head_ref, g_repo));
	cl_git_pass(git3_reference_peel(&head_commit, head_ref, GIT3_OBJECT_COMMIT));

	cl_git_pass(git3_repository_set_head_detached(g_repo, git3_commit_id((git3_commit *)head_commit)));

	cl_assert(git3_fs_path_dirname_r(&absolute_url, git3_repository_workdir(g_repo)) > 0);
	cl_git_pass(git3_str_joinpath(&absolute_url, absolute_url.ptr, "testrepo.git"));

	cl_git_pass(git3_submodule_lookup(&sm, g_repo, "testrepo"));

	/* verify that the .gitmodules is set with an absolute path*/
	cl_assert_equal_s("../testrepo.git", git3_submodule_url(sm));

	/* init and verify that absolute path is written to .git/config */
	cl_git_pass(git3_submodule_init(sm, false));

	cl_git_pass(git3_repository_config_snapshot(&cfg, g_repo));

	cl_git_pass(git3_config_get_string(&config_url, cfg, "submodule.testrepo.url"));
	cl_assert_equal_s(absolute_url.ptr, config_url);

	git3_str_dispose(&absolute_url);
	git3_config_free(cfg);
	git3_object_free(head_commit);
	git3_reference_free(head_ref);
	git3_submodule_free(sm);
}
