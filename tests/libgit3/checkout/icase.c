#include "clar_libgit3.h"

#include "git3/checkout.h"
#include "refs.h"
#include "path.h"
#include "repository.h"

#ifdef GIT3_WIN32
# include <windows.h>
#else
# include <dirent.h>
#endif

static git3_repository *repo;
static git3_object *obj;
static git3_checkout_options checkout_opts;

void test_checkout_icase__initialize(void)
{
	git3_oid id;
	git3_config *cfg;
	int icase = 0;

	repo = cl_git_sandbox_init("testrepo");

	cl_git_pass(git3_repository_config_snapshot(&cfg, repo));
	git3_config_get_bool(&icase, cfg, "core.ignorecase");
	git3_config_free(cfg);

	if (!icase)
		cl_skip();

	cl_git_pass(git3_reference_name_to_id(&id, repo, "refs/heads/dir"));
	cl_git_pass(git3_object_lookup(&obj, repo, &id, GIT3_OBJECT_ANY));

	git3_checkout_options_init(&checkout_opts, GIT3_CHECKOUT_OPTIONS_VERSION);
}

void test_checkout_icase__cleanup(void)
{
	git3_object_free(obj);
	cl_git_sandbox_cleanup();
}

static char *get_filename(const char *in)
{
	char *search_dirname, *search_filename, *filename = NULL;
	git3_str out = GIT3_STR_INIT;
	DIR *dir;
	struct dirent *de;

	cl_assert(search_dirname = git3_fs_path_dirname(in));
	cl_assert(search_filename = git3_fs_path_basename(in));

	cl_assert(dir = opendir(search_dirname));

	while ((de = readdir(dir))) {
		if (strcasecmp(de->d_name, search_filename) == 0) {
			git3_str_join(&out, '/', search_dirname, de->d_name);
			filename = git3_str_detach(&out);
			break;
		}
	}

	closedir(dir);

	git3__free(search_dirname);
	git3__free(search_filename);
	git3_str_dispose(&out);

	return filename;
}

static void assert_name_is(const char *expected)
{
	char *actual;
	size_t actual_len, expected_len, start;

	cl_assert(actual = get_filename(expected));

	expected_len = strlen(expected);
	actual_len = strlen(actual);
	cl_assert(actual_len >= expected_len);

	start = actual_len - expected_len;
	cl_assert_equal_s(expected, actual + start);

	if (start)
		cl_assert_equal_strn("/", actual + (start - 1), 1);

	git3__free(actual);
}

static int symlink_or_fake(git3_repository *repo, const char *a, const char *b)
{
	int symlinks;

	cl_git_pass(git3_repository__configmap_lookup(&symlinks, repo, GIT3_CONFIGMAP_SYMLINKS));

	if (symlinks)
		return p_symlink(a, b);
	else
		return git3_futils_fake_symlink(a, b);
}

void test_checkout_icase__refuses_to_overwrite_files_for_files(void)
{
	checkout_opts.checkout_strategy = GIT3_CHECKOUT_RECREATE_MISSING;

	cl_git_write2file("testrepo/BRANCH_FILE.txt", "neue file\n", 10, \
		O_WRONLY | O_CREAT | O_TRUNC, 0644);

	cl_git_fail(git3_checkout_tree(repo, obj, &checkout_opts));
	assert_name_is("testrepo/BRANCH_FILE.txt");
}

void test_checkout_icase__overwrites_files_for_files_when_forced(void)
{
	checkout_opts.checkout_strategy = GIT3_CHECKOUT_FORCE;

	cl_git_write2file("testrepo/NEW.txt", "neue file\n", 10, \
		O_WRONLY | O_CREAT | O_TRUNC, 0644);

	cl_git_pass(git3_checkout_tree(repo, obj, &checkout_opts));
	assert_name_is("testrepo/new.txt");
}

void test_checkout_icase__refuses_to_overwrite_links_for_files(void)
{
	checkout_opts.checkout_strategy = GIT3_CHECKOUT_RECREATE_MISSING;

	cl_must_pass(symlink_or_fake(repo, "../tmp", "testrepo/BRANCH_FILE.txt"));

	cl_git_fail(git3_checkout_tree(repo, obj, &checkout_opts));

	cl_assert(!git3_fs_path_exists("tmp"));
	assert_name_is("testrepo/BRANCH_FILE.txt");
}

void test_checkout_icase__overwrites_links_for_files_when_forced(void)
{
	checkout_opts.checkout_strategy = GIT3_CHECKOUT_FORCE;

	cl_must_pass(symlink_or_fake(repo, "../tmp", "testrepo/NEW.txt"));

	cl_git_pass(git3_checkout_tree(repo, obj, &checkout_opts));

	cl_assert(!git3_fs_path_exists("tmp"));
	assert_name_is("testrepo/new.txt");
}

void test_checkout_icase__overwrites_empty_folders_for_files(void)
{
	checkout_opts.checkout_strategy = GIT3_CHECKOUT_RECREATE_MISSING;

	cl_must_pass(p_mkdir("testrepo/NEW.txt", 0777));

	cl_git_pass(git3_checkout_tree(repo, obj, &checkout_opts));

	assert_name_is("testrepo/new.txt");
	cl_assert(!git3_fs_path_isdir("testrepo/new.txt"));
}

void test_checkout_icase__refuses_to_overwrite_populated_folders_for_files(void)
{
	checkout_opts.checkout_strategy = GIT3_CHECKOUT_RECREATE_MISSING;

	cl_must_pass(p_mkdir("testrepo/BRANCH_FILE.txt", 0777));
	cl_git_write2file("testrepo/BRANCH_FILE.txt/foobar", "neue file\n", 10, \
		O_WRONLY | O_CREAT | O_TRUNC, 0644);

	cl_git_fail(git3_checkout_tree(repo, obj, &checkout_opts));

	assert_name_is("testrepo/BRANCH_FILE.txt");
	cl_assert(git3_fs_path_isdir("testrepo/BRANCH_FILE.txt"));
}

void test_checkout_icase__overwrites_folders_for_files_when_forced(void)
{
	checkout_opts.checkout_strategy = GIT3_CHECKOUT_FORCE;

	cl_must_pass(p_mkdir("testrepo/NEW.txt", 0777));
	cl_git_write2file("testrepo/NEW.txt/foobar", "neue file\n", 10, \
		O_WRONLY | O_CREAT | O_TRUNC, 0644);

	cl_git_pass(git3_checkout_tree(repo, obj, &checkout_opts));

	assert_name_is("testrepo/new.txt");
	cl_assert(!git3_fs_path_isdir("testrepo/new.txt"));
}

void test_checkout_icase__refuses_to_overwrite_files_for_folders(void)
{
	checkout_opts.checkout_strategy = GIT3_CHECKOUT_RECREATE_MISSING;

	cl_git_write2file("testrepo/A", "neue file\n", 10, \
		O_WRONLY | O_CREAT | O_TRUNC, 0644);

	cl_git_fail(git3_checkout_tree(repo, obj, &checkout_opts));
	assert_name_is("testrepo/A");
	cl_assert(!git3_fs_path_isdir("testrepo/A"));
}

void test_checkout_icase__overwrites_files_for_folders_when_forced(void)
{
	checkout_opts.checkout_strategy = GIT3_CHECKOUT_FORCE;

	cl_git_write2file("testrepo/A", "neue file\n", 10, \
		O_WRONLY | O_CREAT | O_TRUNC, 0644);

	cl_git_pass(git3_checkout_tree(repo, obj, &checkout_opts));
	assert_name_is("testrepo/a");
	cl_assert(git3_fs_path_isdir("testrepo/a"));
}

void test_checkout_icase__refuses_to_overwrite_links_for_folders(void)
{
	checkout_opts.checkout_strategy = GIT3_CHECKOUT_RECREATE_MISSING;

	cl_must_pass(symlink_or_fake(repo, "..", "testrepo/A"));

	cl_git_fail(git3_checkout_tree(repo, obj, &checkout_opts));

	cl_assert(!git3_fs_path_exists("b.txt"));
	assert_name_is("testrepo/A");
}

void test_checkout_icase__overwrites_links_for_folders_when_forced(void)
{
	checkout_opts.checkout_strategy = GIT3_CHECKOUT_FORCE;

	cl_must_pass(symlink_or_fake(repo, "..", "testrepo/A"));

	cl_git_pass(git3_checkout_tree(repo, obj, &checkout_opts));

	cl_assert(!git3_fs_path_exists("b.txt"));
	assert_name_is("testrepo/a");
}

void test_checkout_icase__ignores_unstaged_casechange(void)
{
	git3_reference *orig_ref, *br2_ref;
	git3_commit *orig, *br2;
	git3_checkout_options checkout_opts = GIT3_CHECKOUT_OPTIONS_INIT;

	cl_git_pass(git3_reference_lookup_resolved(&orig_ref, repo, "HEAD", 100));
	cl_git_pass(git3_commit_lookup(&orig, repo, git3_reference_target(orig_ref)));
	cl_git_pass(git3_reset(repo, (git3_object *)orig, GIT3_RESET_HARD, NULL));

	cl_rename("testrepo/branch_file.txt", "testrepo/Branch_File.txt");

	cl_git_pass(git3_reference_lookup_resolved(&br2_ref, repo, "refs/heads/br2", 100));
	cl_git_pass(git3_commit_lookup(&br2, repo, git3_reference_target(br2_ref)));

	cl_git_pass(git3_checkout_tree(repo, (const git3_object *)br2, &checkout_opts));

	git3_commit_free(orig);
	git3_commit_free(br2);
	git3_reference_free(orig_ref);
	git3_reference_free(br2_ref);
}

void test_checkout_icase__conflicts_with_casechanged_subtrees(void)
{
	git3_reference *orig_ref;
	git3_object *orig, *subtrees;
	git3_oid oid;
	git3_checkout_options checkout_opts = GIT3_CHECKOUT_OPTIONS_INIT;

	cl_git_pass(git3_reference_lookup_resolved(&orig_ref, repo, "HEAD", 100));
	cl_git_pass(git3_object_lookup(&orig, repo, git3_reference_target(orig_ref), GIT3_OBJECT_COMMIT));
	cl_git_pass(git3_reset(repo, (git3_object *)orig, GIT3_RESET_HARD, NULL));

	cl_must_pass(p_mkdir("testrepo/AB", 0777));
	cl_must_pass(p_mkdir("testrepo/AB/C", 0777));
	cl_git_write2file("testrepo/AB/C/3.txt", "Foobar!\n", 8, O_RDWR|O_CREAT, 0666);

	cl_git_pass(git3_reference_name_to_id(&oid, repo, "refs/heads/subtrees"));
	cl_git_pass(git3_object_lookup(&subtrees, repo, &oid, GIT3_OBJECT_ANY));

	cl_git_fail(git3_checkout_tree(repo, subtrees, &checkout_opts));

	git3_object_free(orig);
	git3_object_free(subtrees);
    git3_reference_free(orig_ref);
}

