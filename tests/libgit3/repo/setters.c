#include "clar_libgit3.h"
#include "git3/sys/repository.h"

#include "index.h"
#include "odb.h"
#include "posix.h"
#include "util.h"
#include "path.h"
#include "futils.h"

static git3_repository *repo;

void test_repo_setters__initialize(void)
{
	cl_fixture_sandbox("testrepo.git");
	cl_git_pass(git3_repository_open(&repo, "testrepo.git"));
	cl_must_pass(p_mkdir("new_workdir", 0777));
}

void test_repo_setters__cleanup(void)
{
	git3_repository_free(repo);
	repo = NULL;

	cl_fixture_cleanup("testrepo.git");
	cl_fixture_cleanup("new_workdir");
}

void test_repo_setters__setting_a_workdir_turns_a_bare_repository_into_a_standard_one(void)
{
	cl_assert(git3_repository_is_bare(repo) == 1);

	cl_assert(git3_repository_workdir(repo) == NULL);
	cl_git_pass(git3_repository_set_workdir(repo, "./new_workdir", false));

	cl_assert(git3_repository_workdir(repo) != NULL);
	cl_assert(git3_repository_is_bare(repo) == 0);
}

void test_repo_setters__setting_a_workdir_prettifies_its_path(void)
{
	cl_git_pass(git3_repository_set_workdir(repo, "./new_workdir", false));

	cl_assert(git3__suffixcmp(git3_repository_workdir(repo), "new_workdir/") == 0);
}

void test_repo_setters__setting_a_workdir_creates_a_gitlink(void)
{
	git3_config *cfg;
	git3_buf buf = GIT3_BUF_INIT;
	git3_str content = GIT3_STR_INIT;

	cl_git_pass(git3_repository_set_workdir(repo, "./new_workdir", true));

	cl_assert(git3_fs_path_isfile("./new_workdir/.git"));

	cl_git_pass(git3_futils_readbuffer(&content, "./new_workdir/.git"));
	cl_assert(git3__prefixcmp(git3_str_cstr(&content), "gitdir: ") == 0);
	cl_assert(git3__suffixcmp(git3_str_cstr(&content), "testrepo.git/\n") == 0);
	git3_str_dispose(&content);

	cl_git_pass(git3_repository_config(&cfg, repo));
	cl_git_pass(git3_config_get_string_buf(&buf, cfg, "core.worktree"));
	cl_assert(git3__suffixcmp(buf.ptr, "new_workdir/") == 0);

	git3_buf_dispose(&buf);
	git3_config_free(cfg);
}

void test_repo_setters__setting_a_new_index_on_a_repo_which_has_already_loaded_one_properly_honors_the_refcount(void)
{
	git3_index *new_index;
	git3_index_options index_opts = GIT3_INDEX_OPTIONS_INIT;

	index_opts.oid_type = GIT3_OID_SHA1;

	cl_git_pass(git3_index_open_ext(&new_index, "./my-index", &index_opts));
	cl_assert(((git3_refcount *)new_index)->refcount.val == 1);

	git3_repository_set_index(repo, new_index);
	cl_assert(((git3_refcount *)new_index)->refcount.val == 2);

	git3_repository_free(repo);
	cl_assert(((git3_refcount *)new_index)->refcount.val == 1);

	git3_index_free(new_index);

	/*
	 * Ensure the cleanup method won't try to free the repo as it's already been taken care of
	 */
	repo = NULL;
}

void test_repo_setters__setting_a_new_odb_on_a_repo_which_already_loaded_one_properly_honors_the_refcount(void)
{
	git3_odb *new_odb;

	cl_git_pass(git3_odb_open(&new_odb, "./testrepo.git/objects"));
	cl_assert(((git3_refcount *)new_odb)->refcount.val == 1);

	git3_repository_set_odb(repo, new_odb);
	cl_assert(((git3_refcount *)new_odb)->refcount.val == 2);

	git3_repository_free(repo);
	cl_assert(((git3_refcount *)new_odb)->refcount.val == 1);

	git3_odb_free(new_odb);

	/*
	 * Ensure the cleanup method won't try to free the repo as it's already been taken care of
	 */
	repo = NULL;
}
