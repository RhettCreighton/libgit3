#include "clar_libgit3.h"
#include "posix.h"
#include "path.h"
#include "submodule_helpers.h"
#include "config/config_helpers.h"

static git3_repository *g_repo = NULL;

#define SM_LIBGIT3_URL    "https://github.com/libgit3/libgit3.git"
#define SM_LIBGIT3_BRANCH "github-branch"
#define SM_LIBGIT3        "sm_libgit3"

void test_submodule_modify__initialize(void)
{
	g_repo = setup_fixture_submod2();
}

static int delete_one_config(const git3_config_entry *entry, void *payload)
{
	git3_config *cfg = payload;
	return git3_config_delete_entry(cfg, entry->name);
}

static int init_one_submodule(
	git3_submodule *sm, const char *name, void *payload)
{
	GIT3_UNUSED(name);
	GIT3_UNUSED(payload);
	return git3_submodule_init(sm, false);
}

void test_submodule_modify__init(void)
{
	git3_config *cfg;
	const char *str;

	/* erase submodule data from .git/config */
	cl_git_pass(git3_repository_config(&cfg, g_repo));
	cl_git_pass(
		git3_config_foreach_match(cfg, "submodule\\..*", delete_one_config, cfg));
	git3_config_free(cfg);

	/* confirm no submodule data in config */
	cl_git_pass(git3_repository_config_snapshot(&cfg, g_repo));
	cl_git_fail_with(GIT3_ENOTFOUND, git3_config_get_string(&str, cfg, "submodule.sm_unchanged.url"));
	cl_git_fail_with(GIT3_ENOTFOUND, git3_config_get_string(&str, cfg, "submodule.sm_changed_head.url"));
	cl_git_fail_with(GIT3_ENOTFOUND, git3_config_get_string(&str, cfg, "submodule.sm_added_and_uncommited.url"));
	git3_config_free(cfg);

	/* call init and see that settings are copied */
	cl_git_pass(git3_submodule_foreach(g_repo, init_one_submodule, NULL));

	/* confirm submodule data in config */
	cl_git_pass(git3_repository_config_snapshot(&cfg, g_repo));
	cl_git_pass(git3_config_get_string(&str, cfg, "submodule.sm_unchanged.url"));
	cl_assert(git3__suffixcmp(str, "/submod2_target") == 0);
	cl_git_pass(git3_config_get_string(&str, cfg, "submodule.sm_changed_head.url"));
	cl_assert(git3__suffixcmp(str, "/submod2_target") == 0);
	cl_git_pass(git3_config_get_string(&str, cfg, "submodule.sm_added_and_uncommited.url"));
	cl_assert(git3__suffixcmp(str, "/submod2_target") == 0);
	git3_config_free(cfg);
}

static int sync_one_submodule(
	git3_submodule *sm, const char *name, void *payload)
{
	GIT3_UNUSED(name);
	GIT3_UNUSED(payload);
	return git3_submodule_sync(sm);
}

static void assert_submodule_url_is_synced(
	git3_submodule *sm, const char *parent_key, const char *child_key)
{
	git3_repository *smrepo;

	assert_config_entry_value(g_repo, parent_key, git3_submodule_url(sm));

	cl_git_pass(git3_submodule_open(&smrepo, sm));
	assert_config_entry_value(smrepo, child_key,  git3_submodule_url(sm));
	git3_repository_free(smrepo);
}

void test_submodule_modify__sync(void)
{
	git3_submodule *sm1, *sm2, *sm3;
	git3_config *cfg;
	const char *str;

#define SM1 "sm_unchanged"
#define SM2 "sm_changed_head"
#define SM3 "sm_added_and_uncommited"

	/* look up some submodules */
	cl_git_pass(git3_submodule_lookup(&sm1, g_repo, SM1));
	cl_git_pass(git3_submodule_lookup(&sm2, g_repo, SM2));
	cl_git_pass(git3_submodule_lookup(&sm3, g_repo, SM3));

	/* At this point, the .git/config URLs for the submodules have
	 * not be rewritten with the absolute paths (although the
	 * .gitmodules have.  Let's confirm that they DO NOT match
	 * yet, then we can do a sync to make them match...
	 */

	/* check submodule info does not match before sync */
	cl_git_pass(git3_repository_config_snapshot(&cfg, g_repo));
	cl_git_pass(git3_config_get_string(&str, cfg, "submodule."SM1".url"));
	cl_assert(strcmp(git3_submodule_url(sm1), str) != 0);
	cl_git_pass(git3_config_get_string(&str, cfg, "submodule."SM2".url"));
	cl_assert(strcmp(git3_submodule_url(sm2), str) != 0);
	cl_git_pass(git3_config_get_string(&str, cfg, "submodule."SM3".url"));
	cl_assert(strcmp(git3_submodule_url(sm3), str) != 0);
	git3_config_free(cfg);

	/* sync all the submodules */
	cl_git_pass(git3_submodule_foreach(g_repo, sync_one_submodule, NULL));

	/* check that submodule config is updated */
	assert_submodule_url_is_synced(
		sm1, "submodule."SM1".url", "remote.origin.url");
	assert_submodule_url_is_synced(
		sm2, "submodule."SM2".url", "remote.origin.url");
	assert_submodule_url_is_synced(
		sm3, "submodule."SM3".url", "remote.origin.url");

	git3_submodule_free(sm1);
	git3_submodule_free(sm2);
	git3_submodule_free(sm3);
}

static void assert_ignore_change(git3_submodule_ignore_t ignore)
{
	git3_submodule *sm;

	cl_git_pass(git3_submodule_set_ignore(g_repo, "sm_changed_head", ignore));

	cl_git_pass(git3_submodule_lookup(&sm, g_repo, "sm_changed_head"));
	cl_assert_equal_i(ignore, git3_submodule_ignore(sm));
	git3_submodule_free(sm);
}

void test_submodule_modify__set_ignore(void)
{
	assert_ignore_change(GIT3_SUBMODULE_IGNORE_UNTRACKED);
	assert_ignore_change(GIT3_SUBMODULE_IGNORE_NONE);
	assert_ignore_change(GIT3_SUBMODULE_IGNORE_ALL);
}

static void assert_update_change(git3_submodule_update_t update)
{
	git3_submodule *sm;

	cl_git_pass(git3_submodule_set_update(g_repo, "sm_changed_head", update));

	cl_git_pass(git3_submodule_lookup(&sm, g_repo, "sm_changed_head"));
	cl_assert_equal_i(update, git3_submodule_update_strategy(sm));
	git3_submodule_free(sm);
}

void test_submodule_modify__set_update(void)
{
	assert_update_change(GIT3_SUBMODULE_UPDATE_REBASE);
	assert_update_change(GIT3_SUBMODULE_UPDATE_NONE);
	assert_update_change(GIT3_SUBMODULE_UPDATE_CHECKOUT);
}

static void assert_recurse_change(git3_submodule_recurse_t recurse)
{
	git3_submodule *sm;

	cl_git_pass(git3_submodule_set_fetch_recurse_submodules(g_repo, "sm_changed_head", recurse));

	cl_git_pass(git3_submodule_lookup(&sm, g_repo, "sm_changed_head"));
	cl_assert_equal_i(recurse, git3_submodule_fetch_recurse_submodules(sm));
	git3_submodule_free(sm);
}

void test_submodule_modify__set_fetch_recurse_submodules(void)
{
	assert_recurse_change(GIT3_SUBMODULE_RECURSE_YES);
	assert_recurse_change(GIT3_SUBMODULE_RECURSE_NO);
	assert_recurse_change(GIT3_SUBMODULE_RECURSE_ONDEMAND);
}

void test_submodule_modify__set_branch(void)
{
	git3_submodule *sm;

	cl_git_pass(git3_submodule_lookup(&sm, g_repo, "sm_changed_head"));
	cl_assert(git3_submodule_branch(sm) == NULL);
	git3_submodule_free(sm);

	cl_git_pass(git3_submodule_set_branch(g_repo, "sm_changed_head", SM_LIBGIT3_BRANCH));
	cl_git_pass(git3_submodule_lookup(&sm, g_repo, "sm_changed_head"));
	cl_assert_equal_s(SM_LIBGIT3_BRANCH, git3_submodule_branch(sm));
	git3_submodule_free(sm);

	cl_git_pass(git3_submodule_set_branch(g_repo, "sm_changed_head", NULL));
	cl_git_pass(git3_submodule_lookup(&sm, g_repo, "sm_changed_head"));
	cl_assert(git3_submodule_branch(sm) == NULL);
	git3_submodule_free(sm);
}

void test_submodule_modify__set_url(void)
{
	git3_submodule *sm;

	cl_git_pass(git3_submodule_set_url(g_repo, "sm_changed_head", SM_LIBGIT3_URL));
	cl_git_pass(git3_submodule_lookup(&sm, g_repo, "sm_changed_head"));
	cl_assert_equal_s(SM_LIBGIT3_URL, git3_submodule_url(sm));
	git3_submodule_free(sm);
}

void test_submodule_modify__set_relative_url(void)
{
	git3_str path = GIT3_STR_INIT;
	git3_repository *repo;
	git3_submodule *sm;

	cl_git_pass(git3_submodule_set_url(g_repo, SM1, "../relative-url"));
	cl_git_pass(git3_submodule_lookup(&sm, g_repo, SM1));
	cl_git_pass(git3_submodule_sync(sm));
	cl_git_pass(git3_submodule_open(&repo, sm));

	cl_git_pass(git3_str_joinpath(&path, clar_sandbox_path(), "relative-url"));

	assert_config_entry_value(g_repo, "submodule."SM1".url", path.ptr);
	assert_config_entry_value(repo, "remote.origin.url", path.ptr);

	git3_repository_free(repo);
	git3_submodule_free(sm);
	git3_str_dispose(&path);
}
