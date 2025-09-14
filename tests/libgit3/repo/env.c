#include "clar_libgit3.h"
#include "futils.h"
#include "sysdir.h"
#include <ctype.h>

static void clear_git_env(void)
{
	cl_setenv("GIT3_DIR", NULL);
	cl_setenv("GIT3_CEILING_DIRECTORIES", NULL);
	cl_setenv("GIT3_INDEX_FILE", NULL);
	cl_setenv("GIT3_NAMESPACE", NULL);
	cl_setenv("GIT3_OBJECT_DIRECTORY", NULL);
	cl_setenv("GIT3_ALTERNATE_OBJECT_DIRECTORIES", NULL);
	cl_setenv("GIT3_WORK_TREE", NULL);
	cl_setenv("GIT3_COMMON_DIR", NULL);
}

void test_repo_env__initialize(void)
{
	clear_git_env();
}

void test_repo_env__cleanup(void)
{
	cl_git_sandbox_cleanup();

	if (git3_fs_path_isdir("attr"))
		git3_futils_rmdir_r("attr", NULL, GIT3_RMDIR_REMOVE_FILES);
	if (git3_fs_path_isdir("testrepo.git"))
		git3_futils_rmdir_r("testrepo.git", NULL, GIT3_RMDIR_REMOVE_FILES);
	if (git3_fs_path_isdir("peeled.git"))
		git3_futils_rmdir_r("peeled.git", NULL, GIT3_RMDIR_REMOVE_FILES);

	cl_fixture_cleanup("test_workdir");
	cl_fixture_cleanup("test_global_conf");
	cl_fixture_cleanup("test_system_conf");

	clear_git_env();
}

static int GIT3_FORMAT_PRINTF(2, 3) cl_setenv_printf(const char *name, const char *fmt, ...)
{
	int ret;
	va_list args;
	git3_str buf = GIT3_STR_INIT;

	va_start(args, fmt);
	cl_git_pass(git3_str_vprintf(&buf, fmt, args));
	va_end(args);

	ret = cl_setenv(name, git3_str_cstr(&buf));
	git3_str_dispose(&buf);
	return ret;
}

/* Helper functions for test_repo_open__env, passing through the file and line
 * from the caller rather than those of the helper. The expression strings
 * distinguish between the possible failures within the helper. */

static void env_pass_(const char *path, const char *file, const char *func, int line)
{
	git3_repository *repo;
	cl_git_expect(git3_repository_open_ext(NULL, path, GIT3_REPOSITORY_OPEN_FROM_ENV, NULL), 0, file, func, line);
	cl_git_expect(git3_repository_open_ext(&repo, path, GIT3_REPOSITORY_OPEN_FROM_ENV, NULL), 0, file, func, line);
	cl_assert_at_line(git3__suffixcmp(git3_repository_path(repo), "attr/.git/") == 0, file, func, line);
	cl_assert_at_line(git3__suffixcmp(git3_repository_workdir(repo), "attr/") == 0, file, func, line);
	cl_assert_at_line(!git3_repository_is_bare(repo), file, func, line);
	git3_repository_free(repo);
}
#define env_pass(path) env_pass_((path), __FILE__, __func__, __LINE__)

#define cl_git_fail_at_line(expr, file, func, line) clar__assert((expr) < 0, file, func, line, "Expected function call to fail: " #expr, NULL, 1)

static void env_fail_(const char *path, const char *file, const char *func, int line)
{
	git3_repository *repo;
	cl_git_fail_at_line(git3_repository_open_ext(NULL, path, GIT3_REPOSITORY_OPEN_FROM_ENV, NULL), file, func, line);
	cl_git_fail_at_line(git3_repository_open_ext(&repo, path, GIT3_REPOSITORY_OPEN_FROM_ENV, NULL), file, func, line);
}
#define env_fail(path) env_fail_((path), __FILE__, __func__, __LINE__)

static void env_cd_(
	const char *path,
	void (*passfail_)(const char *, const char *, const char *, int),
	const char *file, const char *func, int line)
{
	git3_str cwd_buf = GIT3_STR_INIT;
	cl_git_pass(git3_fs_path_prettify_dir(&cwd_buf, ".", NULL));
	cl_must_pass(p_chdir(path));
	passfail_(NULL, file, func, line);
	cl_must_pass(p_chdir(git3_str_cstr(&cwd_buf)));
	git3_str_dispose(&cwd_buf);
}
#define env_cd_pass(path) env_cd_((path), env_pass_, __FILE__, __func__, __LINE__)
#define env_cd_fail(path) env_cd_((path), env_fail_, __FILE__, __func__, __LINE__)

static void env_check_objects_(bool a, bool t, bool p, const char *file, const char *func, int line)
{
	git3_repository *repo;
	git3_oid oid_a, oid_t, oid_p;
	git3_object *object;
	cl_git_pass(git3_oid_from_string(&oid_a, "45141a79a77842c59a63229403220a4e4be74e3d", GIT3_OID_SHA1));
	cl_git_pass(git3_oid_from_string(&oid_t, "1385f264afb75a56a5bec74243be9b367ba4ca08", GIT3_OID_SHA1));
	cl_git_pass(git3_oid_from_string(&oid_p, "0df1a5865c8abfc09f1f2182e6a31be550e99f07", GIT3_OID_SHA1));
	cl_git_expect(git3_repository_open_ext(&repo, "attr", GIT3_REPOSITORY_OPEN_FROM_ENV, NULL), 0, file, func, line);

	if (a) {
		cl_git_expect(git3_object_lookup(&object, repo, &oid_a, GIT3_OBJECT_BLOB), 0, file, func, line);
		git3_object_free(object);
	} else {
		cl_git_fail_at_line(git3_object_lookup(&object, repo, &oid_a, GIT3_OBJECT_BLOB), file, func, line);
	}

	if (t) {
		cl_git_expect(git3_object_lookup(&object, repo, &oid_t, GIT3_OBJECT_BLOB), 0, file, func, line);
		git3_object_free(object);
	} else {
		cl_git_fail_at_line(git3_object_lookup(&object, repo, &oid_t, GIT3_OBJECT_BLOB), file, func, line);
	}

	if (p) {
		cl_git_expect(git3_object_lookup(&object, repo, &oid_p, GIT3_OBJECT_COMMIT), 0, file, func, line);
		git3_object_free(object);
	} else {
		cl_git_fail_at_line(git3_object_lookup(&object, repo, &oid_p, GIT3_OBJECT_COMMIT), file, func, line);
	}

	git3_repository_free(repo);
}
#define env_check_objects(a, t, t2) env_check_objects_((a), (t), (t2), __FILE__, __func__, __LINE__)

void test_repo_env__open(void)
{
	git3_repository *repo = NULL;
	git3_str repo_dir_buf = GIT3_STR_INIT;
	const char *repo_dir = NULL;
	git3_index *index = NULL;
	const char *t_obj = "testrepo.git/objects";
	const char *p_obj = "peeled.git/objects";

	clear_git_env();

	cl_fixture_sandbox("attr");
	cl_fixture_sandbox("testrepo.git");
	cl_fixture_sandbox("peeled.git");
	cl_git_pass(p_rename("attr/.gitted", "attr/.git"));

	cl_git_pass(git3_fs_path_prettify_dir(&repo_dir_buf, "attr", NULL));
	repo_dir = git3_str_cstr(&repo_dir_buf);

	/* GIT3_DIR that doesn't exist */
	cl_setenv("GIT3_DIR", "does-not-exist");
	env_fail(NULL);
	/* Explicit start_path overrides GIT3_DIR */
	env_pass("attr");
	env_pass("attr/.git");
	env_pass("attr/sub");
	env_pass("attr/sub/sub");

	/* GIT3_DIR with relative paths */
	cl_setenv("GIT3_DIR", "attr/.git");
	env_pass(NULL);
	cl_setenv("GIT3_DIR", "attr");
	env_fail(NULL);
	cl_setenv("GIT3_DIR", "attr/sub");
	env_fail(NULL);
	cl_setenv("GIT3_DIR", "attr/sub/sub");
	env_fail(NULL);

	/* GIT3_DIR with absolute paths */
	cl_setenv_printf("GIT3_DIR", "%s/.git", repo_dir);
	env_pass(NULL);
	cl_setenv("GIT3_DIR", repo_dir);
	env_fail(NULL);
	cl_setenv_printf("GIT3_DIR", "%s/sub", repo_dir);
	env_fail(NULL);
	cl_setenv_printf("GIT3_DIR", "%s/sub/sub", repo_dir);
	env_fail(NULL);
	cl_setenv("GIT3_DIR", NULL);

	/* Searching from the current directory */
	env_cd_pass("attr");
	env_cd_pass("attr/.git");
	env_cd_pass("attr/sub");
	env_cd_pass("attr/sub/sub");

	/* A ceiling directory blocks searches from ascending into that
	 * directory, but doesn't block the start_path itself. */
	cl_setenv("GIT3_CEILING_DIRECTORIES", repo_dir);
	env_cd_pass("attr");
	env_cd_fail("attr/sub");
	env_cd_fail("attr/sub/sub");

	cl_setenv_printf("GIT3_CEILING_DIRECTORIES", "%s/sub", repo_dir);
	env_cd_pass("attr");
	env_cd_pass("attr/sub");
	env_cd_fail("attr/sub/sub");

	/* Multiple ceiling directories */
	cl_setenv_printf("GIT3_CEILING_DIRECTORIES", "123%c%s/sub%cabc",
		GIT3_PATH_LIST_SEPARATOR, repo_dir, GIT3_PATH_LIST_SEPARATOR);
	env_cd_pass("attr");
	env_cd_pass("attr/sub");
	env_cd_fail("attr/sub/sub");

	cl_setenv_printf("GIT3_CEILING_DIRECTORIES", "%s%c%s/sub",
		repo_dir, GIT3_PATH_LIST_SEPARATOR, repo_dir);
	env_cd_pass("attr");
	env_cd_fail("attr/sub");
	env_cd_fail("attr/sub/sub");

	cl_setenv_printf("GIT3_CEILING_DIRECTORIES", "%s/sub%c%s",
		repo_dir, GIT3_PATH_LIST_SEPARATOR, repo_dir);
	env_cd_pass("attr");
	env_cd_fail("attr/sub");
	env_cd_fail("attr/sub/sub");

	cl_setenv_printf("GIT3_CEILING_DIRECTORIES", "%s%c%s/sub/sub",
		repo_dir, GIT3_PATH_LIST_SEPARATOR, repo_dir);
	env_cd_pass("attr");
	env_cd_fail("attr/sub");
	env_cd_fail("attr/sub/sub");

	cl_setenv("GIT3_CEILING_DIRECTORIES", NULL);

	/* Index files */
	cl_setenv("GIT3_INDEX_FILE", cl_fixture("gitgit.index"));
	cl_git_pass(git3_repository_open_ext(&repo, "attr", GIT3_REPOSITORY_OPEN_FROM_ENV, NULL));
	cl_git_pass(git3_repository_index(&index, repo));
	cl_assert_equal_s(git3_index_path(index), cl_fixture("gitgit.index"));
	cl_assert_equal_i(git3_index_entrycount(index), 1437);
	git3_index_free(index);
	git3_repository_free(repo);
	cl_setenv("GIT3_INDEX_FILE", NULL);

	/* Namespaces */
	cl_setenv("GIT3_NAMESPACE", "some-namespace");
	cl_git_pass(git3_repository_open_ext(&repo, "attr", GIT3_REPOSITORY_OPEN_FROM_ENV, NULL));
	cl_assert_equal_s(git3_repository_get_namespace(repo), "some-namespace");
	git3_repository_free(repo);
	cl_setenv("GIT3_NAMESPACE", NULL);

	/* Object directories and alternates */
	env_check_objects(true, false, false);

	cl_setenv("GIT3_OBJECT_DIRECTORY", t_obj);
	env_check_objects(false, true, false);
	cl_setenv("GIT3_OBJECT_DIRECTORY", NULL);

	cl_setenv("GIT3_ALTERNATE_OBJECT_DIRECTORIES", t_obj);
	env_check_objects(true, true, false);
	cl_setenv("GIT3_ALTERNATE_OBJECT_DIRECTORIES", NULL);

	cl_setenv("GIT3_OBJECT_DIRECTORY", p_obj);
	env_check_objects(false, false, true);
	cl_setenv("GIT3_OBJECT_DIRECTORY", NULL);

	cl_setenv("GIT3_OBJECT_DIRECTORY", t_obj);
	cl_setenv("GIT3_ALTERNATE_OBJECT_DIRECTORIES", p_obj);
	env_check_objects(false, true, true);
	cl_setenv("GIT3_ALTERNATE_OBJECT_DIRECTORIES", NULL);
	cl_setenv("GIT3_OBJECT_DIRECTORY", NULL);

	cl_setenv_printf("GIT3_ALTERNATE_OBJECT_DIRECTORIES",
			"%s%c%s", t_obj, GIT3_PATH_LIST_SEPARATOR, p_obj);
	env_check_objects(true, true, true);
	cl_setenv("GIT3_ALTERNATE_OBJECT_DIRECTORIES", NULL);

	cl_setenv_printf("GIT3_ALTERNATE_OBJECT_DIRECTORIES",
			"%s%c%s", p_obj, GIT3_PATH_LIST_SEPARATOR, t_obj);
	env_check_objects(true, true, true);
	cl_setenv("GIT3_ALTERNATE_OBJECT_DIRECTORIES", NULL);

	cl_fixture_cleanup("peeled.git");
	cl_fixture_cleanup("testrepo.git");
	cl_fixture_cleanup("attr");

	git3_str_dispose(&repo_dir_buf);

	clear_git_env();
}

void test_repo_env__work_tree(void)
{
	git3_repository *repo;
	const char *test_path;

	cl_fixture_sandbox("attr");
	cl_git_pass(p_rename("attr/.gitted", "attr/.git"));

	cl_must_pass(p_mkdir("test_workdir", 0777));
	test_path = cl_git_sandbox_path(1, "test_workdir", NULL);

	cl_setenv("GIT3_WORK_TREE", test_path);
	cl_git_pass(git3_repository_open_ext(&repo, "attr", GIT3_REPOSITORY_OPEN_FROM_ENV, NULL));
	cl_assert_equal_s(test_path, git3_repository_workdir(repo));
	git3_repository_free(repo);
	cl_setenv("GIT3_WORK_TREE", NULL);
}

void test_repo_env__commondir(void)
{
	git3_repository *repo;
	const char *test_path;

	cl_fixture_sandbox("attr");
	cl_git_pass(p_rename("attr/.gitted", "attr/.git"));

	cl_fixture_sandbox("testrepo.git");
	cl_git_pass(p_rename("testrepo.git", "test_commondir"));

	test_path = cl_git_sandbox_path(1, "test_commondir", NULL);

	cl_setenv("GIT3_COMMON_DIR", test_path);
	cl_git_pass(git3_repository_open_ext(&repo, "attr", GIT3_REPOSITORY_OPEN_FROM_ENV, NULL));
	cl_assert_equal_s(test_path, git3_repository_commondir(repo));
	git3_repository_free(repo);
	cl_setenv("GIT3_COMMON_DIR", NULL);
}

void test_repo_env__config(void)
{
	git3_repository *repo;
	git3_config *config;
	const char *system_path, *global_path;
	int s, g;

	cl_fixture_sandbox("attr");
	cl_git_pass(p_rename("attr/.gitted", "attr/.git"));

	cl_git_rewritefile("test_system_conf", "[tttest]\n\tsys = true\n");
	cl_git_rewritefile("test_global_conf", "[tttest]\n\tglb = true\n");

	system_path = cl_git_sandbox_path(0, "test_system_conf", NULL);
	cl_setenv("GIT3_CONFIG_SYSTEM", system_path);

	global_path = cl_git_sandbox_path(0, "test_global_conf", NULL);
	cl_setenv("GIT3_CONFIG_GLOBAL", global_path);

	/* Ensure we can override the system and global files */

	cl_git_pass(git3_repository_open_ext(&repo, "attr", GIT3_REPOSITORY_OPEN_FROM_ENV, NULL));
	cl_git_pass(git3_repository_config(&config, repo));

	cl_git_pass(git3_config_get_bool(&s, config, "tttest.sys"));
	cl_assert_equal_i(1, s);
	cl_git_pass(git3_config_get_bool(&g, config, "tttest.glb"));
	cl_assert_equal_i(1, g);

	git3_config_free(config);
	git3_repository_free(repo);

	/* Further ensure we can ignore the system file. */
	cl_setenv("GIT3_CONFIG_NOSYSTEM", "TrUe");

	cl_git_pass(git3_repository_open_ext(&repo, "attr", GIT3_REPOSITORY_OPEN_FROM_ENV, NULL));
	cl_git_pass(git3_repository_config(&config, repo));

	cl_git_fail_with(GIT3_ENOTFOUND, git3_config_get_bool(&s, config, "tttest.sys"));
	cl_git_pass(git3_config_get_bool(&g, config, "tttest.glb"));
	cl_assert_equal_i(1, g);

	git3_config_free(config);
	git3_repository_free(repo);

	cl_setenv("GIT3_CONFIG_NOSYSTEM", NULL);
	cl_setenv("GIT3_CONFIG_SYSTEM", NULL);
	cl_setenv("GIT3_CONFIG_GLOBAL", NULL);
}
