#include "clar_libgit3.h"
#include "futils.h"

void test_config_global__initialize(void)
{
	git3_str path = GIT3_STR_INIT;

	cl_git_pass(git3_futils_mkdir_r("home", 0777));
	cl_git_pass(git3_fs_path_prettify(&path, "home", NULL));
	cl_git_pass(git3_libgit3_opts(
		GIT3_OPT_SET_SEARCH_PATH, GIT3_CONFIG_LEVEL_GLOBAL, path.ptr));

	cl_git_pass(git3_futils_mkdir_r("xdg/git", 0777));
	cl_git_pass(git3_fs_path_prettify(&path, "xdg/git", NULL));
	cl_git_pass(git3_libgit3_opts(
		GIT3_OPT_SET_SEARCH_PATH, GIT3_CONFIG_LEVEL_XDG, path.ptr));

	cl_git_pass(git3_futils_mkdir_r("etc", 0777));
	cl_git_pass(git3_fs_path_prettify(&path, "etc", NULL));
	cl_git_pass(git3_libgit3_opts(
		GIT3_OPT_SET_SEARCH_PATH, GIT3_CONFIG_LEVEL_SYSTEM, path.ptr));

	cl_git_pass(git3_futils_mkdir_r("programdata", 0777));
	cl_git_pass(git3_fs_path_prettify(&path, "programdata", NULL));
	cl_git_pass(git3_libgit3_opts(
		GIT3_OPT_SET_SEARCH_PATH, GIT3_CONFIG_LEVEL_PROGRAMDATA, path.ptr));

	git3_str_dispose(&path);
}

void test_config_global__cleanup(void)
{
	cl_sandbox_set_search_path_defaults();
	cl_git_pass(git3_futils_rmdir_r("home", NULL, GIT3_RMDIR_REMOVE_FILES));
	cl_git_pass(git3_futils_rmdir_r("xdg", NULL, GIT3_RMDIR_REMOVE_FILES));
	cl_git_pass(git3_futils_rmdir_r("etc", NULL, GIT3_RMDIR_REMOVE_FILES));
}

void test_config_global__open_global(void)
{
	git3_config *cfg, *global, *selected, *dummy;
	int32_t value;

	cl_git_mkfile("home/.gitconfig", "[global]\n  test = 4567\n");

	cl_git_pass(git3_config_open_default(&cfg));
	cl_git_pass(git3_config_get_int32(&value, cfg, "global.test"));
	cl_assert_equal_i(4567, value);

	cl_git_pass(git3_config_open_level(&global, cfg, GIT3_CONFIG_LEVEL_GLOBAL));
	cl_git_pass(git3_config_get_int32(&value, global, "global.test"));
	cl_assert_equal_i(4567, value);

	cl_git_fail(git3_config_open_level(&dummy, cfg, GIT3_CONFIG_LEVEL_XDG));

	cl_git_pass(git3_config_open_global(&selected, cfg));
	cl_git_pass(git3_config_get_int32(&value, selected, "global.test"));
	cl_assert_equal_i(4567, value);

	git3_config_free(selected);
	git3_config_free(global);
	git3_config_free(cfg);
}

void test_config_global__open_symlinked_global(void)
{
#ifndef GIT3_WIN32
	git3_config *cfg;
	int32_t value;

	cl_git_mkfile("home/.gitconfig.linked", "[global]\n  test = 4567\n");
	cl_must_pass(symlink(".gitconfig.linked", "home/.gitconfig"));

	cl_git_pass(git3_config_open_default(&cfg));
	cl_git_pass(git3_config_get_int32(&value, cfg, "global.test"));
	cl_assert_equal_i(4567, value);

	git3_config_free(cfg);
#endif
}

void test_config_global__lock_missing_global_config(void)
{
	git3_config *cfg;
	git3_config_entry *entry;
	git3_transaction *transaction;

	(void)p_unlink("home/.gitconfig"); /* No global config */

	cl_git_pass(git3_config_open_default(&cfg));
	cl_git_pass(git3_config_lock(&transaction, cfg));
	cl_git_pass(git3_config_set_string(cfg, "assertion.fail", "boom"));
	cl_git_pass(git3_transaction_commit(transaction));
	git3_transaction_free(transaction);

	/* cfg is updated */
	cl_git_pass(git3_config_get_entry(&entry, cfg, "assertion.fail"));
	cl_assert_equal_s("boom", entry->value);

	git3_config_entry_free(entry);
	git3_config_free(cfg);

	/* We can reread the new value from the global config */
	cl_git_pass(git3_config_open_default(&cfg));
	cl_git_pass(git3_config_get_entry(&entry, cfg, "assertion.fail"));
	cl_assert_equal_s("boom", entry->value);

	git3_config_entry_free(entry);
	git3_config_free(cfg);
}

void test_config_global__open_xdg(void)
{
	git3_config *cfg, *xdg, *selected;
	const char *str = "teststring";
	const char *key = "this.variable";
	git3_buf buf = {0};

	cl_git_mkfile("xdg/git/config", "# XDG config\n[core]\n  test = 1\n");

	cl_git_pass(git3_config_open_default(&cfg));
	cl_git_pass(git3_config_open_level(&xdg, cfg, GIT3_CONFIG_LEVEL_XDG));
	cl_git_pass(git3_config_open_global(&selected, cfg));

	cl_git_pass(git3_config_set_string(xdg, key, str));
	cl_git_pass(git3_config_get_string_buf(&buf, selected, key));
	cl_assert_equal_s(str, buf.ptr);

	git3_buf_dispose(&buf);
	git3_config_free(selected);
	git3_config_free(xdg);
	git3_config_free(cfg);
}

void test_config_global__open_programdata(void)
{
	git3_config *cfg;
	git3_repository *repo;
	git3_buf dir_path = GIT3_BUF_INIT;
	git3_str config_path = GIT3_STR_INIT;
	git3_buf var_contents = GIT3_BUF_INIT;

	if (cl_is_env_set("GITTEST_INVASIVE_FS_STRUCTURE"))
		cl_skip();

	cl_git_pass(git3_libgit3_opts(GIT3_OPT_GET_SEARCH_PATH,
		GIT3_CONFIG_LEVEL_PROGRAMDATA, &dir_path));

	if (!git3_fs_path_isdir(dir_path.ptr))
		cl_git_pass(p_mkdir(dir_path.ptr, 0777));

	cl_git_pass(git3_str_joinpath(&config_path, dir_path.ptr, "config"));

	cl_git_pass(git3_config_open_ondisk(&cfg, config_path.ptr));
	cl_git_pass(git3_config_set_string(cfg, "programdata.var", "even higher level"));

	git3_str_dispose(&config_path);
	git3_config_free(cfg);

	git3_config_open_default(&cfg);
	cl_git_pass(git3_config_get_string_buf(&var_contents, cfg, "programdata.var"));
	cl_assert_equal_s("even higher level", var_contents.ptr);

	git3_config_free(cfg);
	git3_buf_dispose(&var_contents);

	cl_git_pass(git3_repository_init(&repo, "./foo.git", true));
	cl_git_pass(git3_repository_config(&cfg, repo));
	cl_git_pass(git3_config_get_string_buf(&var_contents, cfg, "programdata.var"));
	cl_assert_equal_s("even higher level", var_contents.ptr);

	git3_config_free(cfg);
	git3_buf_dispose(&dir_path);
	git3_buf_dispose(&var_contents);
	git3_repository_free(repo);
	cl_fixture_cleanup("./foo.git");
}
