#include "clar_libgit3.h"

#include "git3/clone.h"
#include "../submodule/submodule_helpers.h"
#include "remote.h"
#include "futils.h"
#include "repository.h"
#include "index.h"

#define LIVE_REPO_URL "git://github.com/libgit3/TestGitRepository"

static git3_clone_options g_options;
static git3_repository *g_repo;
static git3_reference* g_ref;
static git3_remote* g_remote;

void test_clone_nonetwork__initialize(void)
{
	git3_checkout_options dummy_opts = GIT3_CHECKOUT_OPTIONS_INIT;
	git3_fetch_options dummy_fetch = GIT3_FETCH_OPTIONS_INIT;

	g_repo = NULL;

	memset(&g_options, 0, sizeof(git3_clone_options));
	g_options.version = GIT3_CLONE_OPTIONS_VERSION;
	g_options.checkout_opts = dummy_opts;
	g_options.fetch_opts = dummy_fetch;
}

void test_clone_nonetwork__cleanup(void)
{
	if (g_repo) {
		git3_repository_free(g_repo);
		g_repo = NULL;
	}

	if (g_ref) {
		git3_reference_free(g_ref);
		g_ref = NULL;
	}

	if (g_remote) {
		git3_remote_free(g_remote);
		g_remote = NULL;
	}

	cl_fixture_cleanup("./foo");
}

void test_clone_nonetwork__bad_urls(void)
{
	/* Clone should clean up the mess if the URL isn't a git repository */
	cl_git_fail(git3_clone(&g_repo, "not_a_repo", "./foo", &g_options));
	cl_assert(!git3_fs_path_exists("./foo"));
	g_options.bare = true;
	cl_git_fail(git3_clone(&g_repo, "not_a_repo", "./foo", &g_options));
	cl_assert(!git3_fs_path_exists("./foo"));

	cl_git_fail(git3_clone(&g_repo, "git://example.com:asdf", "./foo", &g_options));
	cl_git_fail(git3_clone(&g_repo, "https://example.com:asdf/foo", "./foo", &g_options));
	cl_git_fail(git3_clone(&g_repo, "git://github.com/git://github.com/foo/bar.git.git",
				"./foo", &g_options));
	cl_git_fail(git3_clone(&g_repo, "arrbee:my/bad:password@github.com:1111/strange:words.git",
				"./foo", &g_options));
}

void test_clone_nonetwork__do_not_clean_existing_directory(void)
{
	/* Clone should not remove the directory if it already exists, but
	 * Should clean up entries it creates. */
	p_mkdir("./foo", GIT3_DIR_MODE);
	cl_git_fail(git3_clone(&g_repo, "not_a_repo", "./foo", &g_options));
	cl_assert(git3_fs_path_is_empty_dir("./foo"));

	/* Try again with a bare repository. */
	g_options.bare = true;
	cl_git_fail(git3_clone(&g_repo, "not_a_repo", "./foo", &g_options));
	cl_assert(git3_fs_path_is_empty_dir("./foo"));
}

void test_clone_nonetwork__local(void)
{
	cl_git_pass(git3_clone(&g_repo, cl_git_fixture_url("testrepo.git"), "./foo", &g_options));
}

void test_clone_nonetwork__local_absolute_path(void)
{
	const char *local_src;
	local_src = cl_fixture("testrepo.git");
	cl_git_pass(git3_clone(&g_repo, local_src, "./foo", &g_options));
}

void test_clone_nonetwork__local_bare(void)
{
	g_options.bare = true;
	cl_git_pass(git3_clone(&g_repo, cl_git_fixture_url("testrepo.git"), "./foo", &g_options));
}

void test_clone_nonetwork__fail_when_the_target_is_a_file(void)
{
	cl_git_mkfile("./foo", "Bar!");
	cl_git_fail(git3_clone(&g_repo, cl_git_fixture_url("testrepo.git"), "./foo", &g_options));
}

void test_clone_nonetwork__fail_with_already_existing_but_non_empty_directory(void)
{
	p_mkdir("./foo", GIT3_DIR_MODE);
	cl_git_mkfile("./foo/bar", "Baz!");
	cl_git_fail(git3_clone(&g_repo, cl_git_fixture_url("testrepo.git"), "./foo", &g_options));
}

static int custom_origin_name_remote_create(
	git3_remote **out,
	git3_repository *repo,
	const char *name,
	const char *url,
	void *payload)
{
	GIT3_UNUSED(name);
	GIT3_UNUSED(payload);

	return git3_remote_create(out, repo, "my_origin", url);
}

void test_clone_nonetwork__custom_origin_name(void)
{
	g_options.remote_cb = custom_origin_name_remote_create;
	cl_git_pass(git3_clone(&g_repo, cl_git_fixture_url("testrepo.git"), "./foo", &g_options));

	cl_git_pass(git3_remote_lookup(&g_remote, g_repo, "my_origin"));
}

void test_clone_nonetwork__defaults(void)
{
	cl_git_pass(git3_clone(&g_repo, cl_git_fixture_url("testrepo.git"), "./foo", NULL));
	cl_assert(g_repo);
	cl_git_pass(git3_remote_lookup(&g_remote, g_repo, "origin"));
}

void test_clone_nonetwork__cope_with_already_existing_directory(void)
{
	p_mkdir("./foo", GIT3_DIR_MODE);
	cl_git_pass(git3_clone(&g_repo, cl_git_fixture_url("testrepo.git"), "./foo", &g_options));
}

void test_clone_nonetwork__can_prevent_the_checkout_of_a_standard_repo(void)
{
	git3_str path = GIT3_STR_INIT;

	g_options.checkout_opts.checkout_strategy = 0;
	cl_git_pass(git3_clone(&g_repo, cl_git_fixture_url("testrepo.git"), "./foo", &g_options));

	cl_git_pass(git3_str_joinpath(&path, git3_repository_workdir(g_repo), "master.txt"));
	cl_assert_equal_i(false, git3_fs_path_isfile(git3_str_cstr(&path)));

	git3_str_dispose(&path);
}

void test_clone_nonetwork__can_checkout_given_branch(void)
{
	git3_reference *remote_head;

	g_options.checkout_branch = "test";
	cl_git_pass(git3_clone(&g_repo, cl_git_fixture_url("testrepo.git"), "./foo", &g_options));

	cl_assert_equal_i(0, git3_repository_head_unborn(g_repo));

	cl_git_pass(git3_repository_head(&g_ref, g_repo));
	cl_assert_equal_s(git3_reference_name(g_ref), "refs/heads/test");

	cl_assert(git3_fs_path_exists("foo/readme.txt"));

	cl_git_pass(git3_reference_lookup(&remote_head, g_repo, "refs/remotes/origin/HEAD"));
	cl_assert_equal_i(GIT3_REFERENCE_SYMBOLIC, git3_reference_type(remote_head));
	cl_assert_equal_s("refs/remotes/origin/master", git3_reference_symbolic_target(remote_head));

	git3_reference_free(remote_head);
}

static int clone_cancel_fetch_transfer_progress_cb(
	const git3_indexer_progress *stats, void *data)
{
	GIT3_UNUSED(stats); GIT3_UNUSED(data);
	return -54321;
}

void test_clone_nonetwork__can_cancel_clone_in_fetch(void)
{
	g_options.checkout_branch = "test";

	g_options.fetch_opts.callbacks.transfer_progress =
		clone_cancel_fetch_transfer_progress_cb;

	cl_git_fail_with(git3_clone(
		&g_repo, cl_git_fixture_url("testrepo.git"), "./foo", &g_options),
		-54321);

	cl_assert(!g_repo);
	cl_assert(!git3_fs_path_exists("foo/readme.txt"));
}

static int clone_cancel_checkout_cb(
	git3_checkout_notify_t why,
	const char *path,
	const git3_diff_file *b,
	const git3_diff_file *t,
	const git3_diff_file *w,
	void *payload)
{
	const char *at_file = payload;
	GIT3_UNUSED(why); GIT3_UNUSED(b); GIT3_UNUSED(t); GIT3_UNUSED(w);
	if (!strcmp(path, at_file))
		return -12345;
	return 0;
}

void test_clone_nonetwork__can_cancel_clone_in_checkout(void)
{
	g_options.checkout_branch = "test";

	g_options.checkout_opts.notify_flags = GIT3_CHECKOUT_NOTIFY_UPDATED;
	g_options.checkout_opts.notify_cb = clone_cancel_checkout_cb;
	g_options.checkout_opts.notify_payload = "readme.txt";

	cl_git_fail_with(git3_clone(
		&g_repo, cl_git_fixture_url("testrepo.git"), "./foo", &g_options),
		-12345);

	cl_assert(!g_repo);
	cl_assert(!git3_fs_path_exists("foo/readme.txt"));
}

void test_clone_nonetwork__can_detached_head(void)
{
	git3_object *obj;
	git3_repository *cloned;
	git3_reference *cloned_head;

	cl_git_pass(git3_clone(&g_repo, cl_git_fixture_url("testrepo.git"), "./foo", &g_options));

	cl_git_pass(git3_revparse_single(&obj, g_repo, "master~1"));
	cl_git_pass(git3_repository_set_head_detached(g_repo, git3_object_id(obj)));

	cl_git_pass(git3_clone(&cloned, "./foo", "./foo1", &g_options));

	cl_assert(git3_repository_head_detached(cloned));

	cl_git_pass(git3_repository_head(&cloned_head, cloned));
	cl_assert_equal_oid(git3_object_id(obj), git3_reference_target(cloned_head));

	git3_object_free(obj);
	git3_reference_free(cloned_head);
	git3_repository_free(cloned);

	cl_fixture_cleanup("./foo1");
}

void test_clone_nonetwork__clone_tag_to_tree(void)
{
	git3_repository *stage;
	git3_index_entry entry;
	git3_index *index;
	git3_odb *odb;
	git3_oid tree_id;
	git3_tree *tree;
	git3_reference *tag;
	git3_tree_entry *tentry;
	git3_index_options index_opts = GIT3_INDEX_OPTIONS_INIT;

	const char *file_path = "some/deep/path.txt";
	const char *file_content = "some content\n";
	const char *tag_name = "refs/tags/tree-tag";

	index_opts.oid_type = GIT3_OID_SHA1;

	stage = cl_git_sandbox_init("testrepo.git");
	cl_git_pass(git3_repository_odb(&odb, stage));
	cl_git_pass(git3_index_new_ext(&index, &index_opts));

	memset(&entry, 0, sizeof(git3_index_entry));
	entry.path = file_path;
	entry.mode = GIT3_FILEMODE_BLOB;
	cl_git_pass(git3_odb_write(&entry.id, odb, file_content, strlen(file_content), GIT3_OBJECT_BLOB));

	cl_git_pass(git3_index_add(index, &entry));
	cl_git_pass(git3_index_write_tree_to(&tree_id, index, stage));
	cl_git_pass(git3_reference_create(&tag, stage, tag_name, &tree_id, 0, NULL));
	git3_reference_free(tag);
	git3_odb_free(odb);
	git3_index_free(index);

	g_options.local = GIT3_CLONE_NO_LOCAL;
	cl_git_pass(git3_clone(&g_repo, cl_git_path_url(git3_repository_path(stage)), "./foo", &g_options));
	git3_repository_free(stage);

	cl_git_pass(git3_reference_lookup(&tag, g_repo, tag_name));
	cl_git_pass(git3_tree_lookup(&tree, g_repo, git3_reference_target(tag)));
	git3_reference_free(tag);

	cl_git_pass(git3_tree_entry_bypath(&tentry, tree, file_path));
	git3_tree_entry_free(tentry);
	git3_tree_free(tree);

	cl_fixture_cleanup("testrepo.git");
}

static void assert_correct_reflog(const char *name)
{
	git3_reflog *log;
	const git3_reflog_entry *entry;
	git3_str expected_message = GIT3_STR_INIT;

	git3_str_printf(&expected_message,
		"clone: from %s", cl_git_fixture_url("testrepo.git"));

	cl_git_pass(git3_reflog_read(&log, g_repo, name));
	cl_assert_equal_i(1, git3_reflog_entrycount(log));
	entry = git3_reflog_entry_byindex(log, 0);
	cl_assert_equal_s(expected_message.ptr, git3_reflog_entry_message(entry));

	git3_reflog_free(log);

	git3_str_dispose(&expected_message);
}

void test_clone_nonetwork__clone_updates_reflog_properly(void)
{
	cl_git_pass(git3_clone(&g_repo, cl_git_fixture_url("testrepo.git"), "./foo", &g_options));
	assert_correct_reflog("HEAD");
	assert_correct_reflog("refs/heads/master");
}

static void cleanup_repository(void *path)
{
	if (g_repo) {
		git3_repository_free(g_repo);
		g_repo = NULL;
	}

	cl_fixture_cleanup((const char *)path);
}

void test_clone_nonetwork__clone_from_empty_sets_upstream(void)
{
	git3_config *config;
	git3_repository *repo;
	const char *str;

	/* Create an empty repo to clone from */
	cl_set_cleanup(&cleanup_repository, "./test1");
	cl_git_pass(git3_repository_init(&g_repo, "./test1", 0));
	cl_set_cleanup(&cleanup_repository, "./repowithunborn");
	cl_git_pass(git3_clone(&repo, "./test1", "./repowithunborn", NULL));

	cl_git_pass(git3_repository_config_snapshot(&config, repo));

	cl_git_pass(git3_config_get_string(&str, config, "branch.master.remote"));
	cl_assert_equal_s("origin", str);
	cl_git_pass(git3_config_get_string(&str, config, "branch.master.merge"));
	cl_assert_equal_s("refs/heads/master", str);

	git3_config_free(config);
	git3_repository_free(repo);
	cl_fixture_cleanup("./repowithunborn");
}
