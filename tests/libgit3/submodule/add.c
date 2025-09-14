#include "clar_libgit3.h"
#include "posix.h"
#include "path.h"
#include "submodule_helpers.h"
#include "config/config_helpers.h"
#include "futils.h"
#include "repository.h"
#include "git3/sys/commit.h"

static git3_repository *g_repo = NULL;
static const char *valid_blob_id = "fa49b077972391ad58037050f2a75f74e3671e92";

void test_submodule_add__cleanup(void)
{
	cl_git_sandbox_cleanup();
}

static void assert_submodule_url(const char* name, const char *url)
{
	git3_str key = GIT3_STR_INIT;


	cl_git_pass(git3_str_printf(&key, "submodule.%s.url", name));
	assert_config_entry_value(g_repo, git3_str_cstr(&key), url);

	git3_str_dispose(&key);
}

void test_submodule_add__url_absolute(void)
{
	git3_submodule *sm;
	git3_repository *repo;
	git3_str dot_git_content = GIT3_STR_INIT;

	g_repo = setup_fixture_submod2();

	/* re-add existing submodule */
	cl_git_fail_with(
		GIT3_EEXISTS,
		git3_submodule_add_setup(NULL, g_repo, "whatever", "sm_unchanged", 1));

	/* add a submodule using a gitlink */

	cl_git_pass(
		git3_submodule_add_setup(&sm, g_repo, "https://github.com/libgit3/libgit3.git", "sm_libgit3", 1)
		);
	git3_submodule_free(sm);

	cl_assert(git3_fs_path_isfile("submod2/" "sm_libgit3" "/.git"));

	cl_assert(git3_fs_path_isdir("submod2/.git/modules"));
	cl_assert(git3_fs_path_isdir("submod2/.git/modules/" "sm_libgit3"));
	cl_assert(git3_fs_path_isfile("submod2/.git/modules/" "sm_libgit3" "/HEAD"));
	assert_submodule_url("sm_libgit3", "https://github.com/libgit3/libgit3.git");

	cl_git_pass(git3_repository_open(&repo, "submod2/" "sm_libgit3"));

	/* Verify worktree path is relative */
	assert_config_entry_value(repo, "core.worktree", "../../../sm_libgit3/");

	/* Verify gitdir path is relative */
	cl_git_pass(git3_futils_readbuffer(&dot_git_content, "submod2/" "sm_libgit3" "/.git"));
	cl_assert_equal_s("gitdir: ../.git/modules/sm_libgit3/\n", dot_git_content.ptr);

	git3_repository_free(repo);
	git3_str_dispose(&dot_git_content);

	/* add a submodule not using a gitlink */

	cl_git_pass(
		git3_submodule_add_setup(&sm, g_repo, "https://github.com/libgit3/libgit3.git", "sm_libgit3b", 0)
		);
	git3_submodule_free(sm);

	cl_assert(git3_fs_path_isdir("submod2/" "sm_libgit3b" "/.git"));
	cl_assert(git3_fs_path_isfile("submod2/" "sm_libgit3b" "/.git/HEAD"));
	cl_assert(!git3_fs_path_exists("submod2/.git/modules/" "sm_libgit3b"));
	assert_submodule_url("sm_libgit3b", "https://github.com/libgit3/libgit3.git");
}

void test_submodule_add__url_relative(void)
{
	git3_submodule *sm;
	git3_remote *remote;
	git3_strarray problems = {0};

	/* default remote url is https://github.com/libgit3/false.git */
	g_repo = cl_git_sandbox_init("testrepo2");

	/* make sure we don't default to origin - rename origin -> test_remote */
	cl_git_pass(git3_remote_rename(&problems, g_repo, "origin", "test_remote"));
	cl_assert_equal_i(0, problems.count);
	git3_strarray_dispose(&problems);
	cl_git_fail(git3_remote_lookup(&remote, g_repo, "origin"));

	cl_git_pass(
		git3_submodule_add_setup(&sm, g_repo, "../TestGitRepository", "TestGitRepository", 1)
		);
	git3_submodule_free(sm);

	assert_submodule_url("TestGitRepository", "https://github.com/libgit3/TestGitRepository");
}

void test_submodule_add__url_relative_to_origin(void)
{
	git3_submodule *sm;

	/* default remote url is https://github.com/libgit3/false.git */
	g_repo = cl_git_sandbox_init("testrepo2");

	cl_git_pass(
		git3_submodule_add_setup(&sm, g_repo, "../TestGitRepository", "TestGitRepository", 1)
		);
	git3_submodule_free(sm);

	assert_submodule_url("TestGitRepository", "https://github.com/libgit3/TestGitRepository");
}

void test_submodule_add__url_relative_to_workdir(void)
{
	git3_submodule *sm;

	/* In this repo, HEAD (master) has no remote tracking branc h*/
	g_repo = cl_git_sandbox_init("testrepo");

	cl_git_pass(
		git3_submodule_add_setup(&sm, g_repo, "./", "TestGitRepository", 1)
		);
	git3_submodule_free(sm);

	assert_submodule_url("TestGitRepository", git3_repository_workdir(g_repo));
}

static void test_add_entry(
	git3_index *index,
	const char *idstr,
	const char *path,
	git3_filemode_t mode)
{
	git3_index_entry entry = {{0}};

	cl_git_pass(git3_oid_from_string(&entry.id, idstr, GIT3_OID_SHA1));

	entry.path = path;
	entry.mode = mode;

	cl_git_pass(git3_index_add(index, &entry));
}

void test_submodule_add__path_exists_in_index(void)
{
	git3_index *index;
	git3_submodule *sm;
	git3_str filename = GIT3_STR_INIT;

	g_repo = cl_git_sandbox_init("testrepo");

	cl_git_pass(git3_str_joinpath(&filename, "subdirectory", "test.txt"));

	cl_git_pass(git3_repository_index__weakptr(&index, g_repo));

	test_add_entry(index, valid_blob_id, filename.ptr, GIT3_FILEMODE_BLOB);

	cl_git_fail_with(git3_submodule_add_setup(&sm, g_repo, "./", "subdirectory", 1), GIT3_EEXISTS);

	git3_submodule_free(sm);
	git3_str_dispose(&filename);
}

void test_submodule_add__file_exists_in_index(void)
{
	git3_index *index;
	git3_submodule *sm;
	git3_str name = GIT3_STR_INIT;

	g_repo = cl_git_sandbox_init("testrepo");

	cl_git_pass(git3_repository_index__weakptr(&index, g_repo));

	test_add_entry(index, valid_blob_id, "subdirectory", GIT3_FILEMODE_BLOB);

	cl_git_fail_with(git3_submodule_add_setup(&sm, g_repo, "./", "subdirectory", 1), GIT3_EEXISTS);

	git3_submodule_free(sm);
	git3_str_dispose(&name);
}

void test_submodule_add__submodule_clone(void)
{
	git3_oid tree_id, commit_id;
	git3_signature *sig;
	git3_submodule *sm;
	git3_index *index;

	g_repo = cl_git_sandbox_init("empty_standard_repo");

	/* Create the submodule structure, clone into it and finalize */
	cl_git_pass(git3_submodule_add_setup(&sm, g_repo, cl_fixture("testrepo.git"), "testrepo-add", true));
	cl_git_pass(git3_submodule_clone(NULL, sm, NULL));
	cl_git_pass(git3_submodule_add_finalize(sm));

	/* Create the submodule commit */
	cl_git_pass(git3_repository_index(&index, g_repo));
	cl_git_pass(git3_index_write_tree(&tree_id, index));
	cl_git_pass(git3_signature_now(&sig, "Submoduler", "submoduler@local"));
	cl_git_pass(git3_commit_create_from_ids(&commit_id, g_repo, "HEAD", sig, sig, NULL, "A submodule\n",
					       &tree_id, 0, NULL));

	assert_submodule_exists(g_repo, "testrepo-add");

	git3_signature_free(sig);
	git3_submodule_free(sm);
	git3_index_free(index);
}

void test_submodule_add__submodule_clone_into_nonempty_dir_succeeds(void)
{
	git3_submodule *sm;

	g_repo = cl_git_sandbox_init("empty_standard_repo");

	cl_git_pass(p_mkdir("empty_standard_repo/sm", 0777));
	cl_git_mkfile("empty_standard_repo/sm/foobar", "");

	/* Create the submodule structure, clone into it and finalize */
	cl_git_pass(git3_submodule_add_setup(&sm, g_repo, cl_fixture("testrepo.git"), "sm", true));
	cl_git_pass(git3_submodule_clone(NULL, sm, NULL));
	cl_git_pass(git3_submodule_add_finalize(sm));

	cl_assert(git3_fs_path_exists("empty_standard_repo/sm/foobar"));

	assert_submodule_exists(g_repo, "sm");

	git3_submodule_free(sm);
}

void test_submodule_add__submodule_clone_twice_fails(void)
{
	git3_submodule *sm;

	g_repo = cl_git_sandbox_init("empty_standard_repo");

	/* Create the submodule structure, clone into it and finalize */
	cl_git_pass(git3_submodule_add_setup(&sm, g_repo, cl_fixture("testrepo.git"), "sm", true));
	cl_git_pass(git3_submodule_clone(NULL, sm, NULL));
	cl_git_pass(git3_submodule_add_finalize(sm));

	cl_git_fail(git3_submodule_clone(NULL, sm, NULL));

	git3_submodule_free(sm);
}
