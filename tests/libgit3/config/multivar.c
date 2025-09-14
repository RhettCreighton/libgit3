#include "clar_libgit3.h"
#include "config.h"
#include "config/config_helpers.h"

static const char *_name = "remote.ab.url";

void test_config_multivar__initialize(void)
{
	cl_fixture_sandbox("config");
}

void test_config_multivar__cleanup(void)
{
	cl_fixture_cleanup("config");
}

static int mv_read_cb(const git3_config_entry *entry, void *data)
{
	int *n = (int *) data;

	if (!strcmp(entry->name, _name))
		(*n)++;

	return 0;
}

void test_config_multivar__foreach(void)
{
	git3_config *cfg;
	int n = 0;

	cl_git_pass(git3_config_open_ondisk(&cfg, cl_fixture("config/config11")));

	cl_git_pass(git3_config_foreach(cfg, mv_read_cb, &n));
	cl_assert(n == 2);

	git3_config_free(cfg);
}

static int cb(const git3_config_entry *entry, void *data)
{
	int *n = (int *) data;

	GIT3_UNUSED(entry);

	(*n)++;

	return 0;
}

static void check_get_multivar_foreach(
	git3_config *cfg, int expected, int expected_patterned)
{
	int n = 0;

	if (expected > 0) {
		cl_git_pass(git3_config_get_multivar_foreach(cfg, _name, NULL, cb, &n));
		cl_assert_equal_i(expected, n);
	} else {
		cl_assert_equal_i(GIT3_ENOTFOUND,
			git3_config_get_multivar_foreach(cfg, _name, NULL, cb, &n));
	}

	n = 0;

	if (expected_patterned > 0) {
		cl_git_pass(git3_config_get_multivar_foreach(cfg, _name, "example", cb, &n));
		cl_assert_equal_i(expected_patterned, n);
	} else {
		cl_assert_equal_i(GIT3_ENOTFOUND,
			git3_config_get_multivar_foreach(cfg, _name, "example", cb, &n));
	}
}

static void check_get_multivar(git3_config *cfg, int expected)
{
	git3_config_iterator *iter;
	git3_config_entry *entry;
	int n = 0;

	cl_git_pass(git3_config_multivar_iterator_new(&iter, cfg, _name, NULL));

	while (git3_config_next(&entry, iter) == 0)
		n++;

	cl_assert_equal_i(expected, n);
	git3_config_iterator_free(iter);

}

void test_config_multivar__get(void)
{
	git3_config *cfg;

	cl_git_pass(git3_config_open_ondisk(&cfg, "config/config11"));
	check_get_multivar_foreach(cfg, 2, 1);

	/* add another that has the _name entry */
	cl_git_pass(git3_config_add_file_ondisk(cfg, "config/config9", GIT3_CONFIG_LEVEL_SYSTEM, NULL, 1));
	check_get_multivar_foreach(cfg, 3, 2);

	/* add another that does not have the _name entry */
	cl_git_pass(git3_config_add_file_ondisk(cfg, "config/config0", GIT3_CONFIG_LEVEL_GLOBAL, NULL, 1));
	check_get_multivar_foreach(cfg, 3, 2);

	/* add another that does not have the _name entry at the end */
	cl_git_pass(git3_config_add_file_ondisk(cfg, "config/config1", GIT3_CONFIG_LEVEL_APP, NULL, 1));
	check_get_multivar_foreach(cfg, 3, 2);

	/* drop original file */
	cl_git_pass(git3_config_add_file_ondisk(cfg, "config/config2", GIT3_CONFIG_LEVEL_LOCAL, NULL, 1));
	check_get_multivar_foreach(cfg, 1, 1);

	/* drop other file with match */
	cl_git_pass(git3_config_add_file_ondisk(cfg, "config/config3", GIT3_CONFIG_LEVEL_SYSTEM, NULL, 1));
	check_get_multivar_foreach(cfg, 0, 0);

	/* reload original file (add different place in order) */
	cl_git_pass(git3_config_add_file_ondisk(cfg, "config/config11", GIT3_CONFIG_LEVEL_SYSTEM, NULL, 1));
	check_get_multivar_foreach(cfg, 2, 1);

	check_get_multivar(cfg, 2);

	git3_config_free(cfg);
}

void test_config_multivar__add(void)
{
	git3_config *cfg;
	int n;

	cl_git_pass(git3_config_open_ondisk(&cfg, "config/config11"));
	cl_git_pass(git3_config_set_multivar(cfg, _name, "non-existent", "git://git.otherplace.org/libgit3"));

	n = 0;
	cl_git_pass(git3_config_get_multivar_foreach(cfg, _name, NULL, cb, &n));
	cl_assert_equal_i(n, 3);

	n = 0;
	cl_git_pass(git3_config_get_multivar_foreach(cfg, _name, "otherplace", cb, &n));
	cl_assert_equal_i(n, 1);

	git3_config_free(cfg);

	/* We know it works in memory, let's see if the file is written correctly */

	cl_git_pass(git3_config_open_ondisk(&cfg, "config/config11"));

	n = 0;
	cl_git_pass(git3_config_get_multivar_foreach(cfg, _name, NULL, cb, &n));
	cl_assert_equal_i(n, 3);

	n = 0;
	cl_git_pass(git3_config_get_multivar_foreach(cfg, _name, "otherplace", cb, &n));
	cl_assert_equal_i(n, 1);

	git3_config_free(cfg);
}

void test_config_multivar__add_new(void)
{
	const char *var = "a.brand.new";
	git3_config *cfg;
	int n;

	cl_git_pass(git3_config_open_ondisk(&cfg, "config/config11"));

	cl_git_pass(git3_config_set_multivar(cfg, var, "$^", "variable"));
	n = 0;
	cl_git_pass(git3_config_get_multivar_foreach(cfg, var, NULL, cb, &n));
	cl_assert_equal_i(n, 1);

	git3_config_free(cfg);
}

void test_config_multivar__replace(void)
{
	git3_config *cfg;
	int n;

	cl_git_pass(git3_config_open_ondisk(&cfg, "config/config11"));

	n = 0;
	cl_git_pass(git3_config_get_multivar_foreach(cfg, _name, NULL, cb, &n));
	cl_assert(n == 2);

	cl_git_pass(git3_config_set_multivar(cfg, _name, "github", "git://git.otherplace.org/libgit3"));

	n = 0;
	cl_git_pass(git3_config_get_multivar_foreach(cfg, _name, NULL, cb, &n));
	cl_assert(n == 2);

	git3_config_free(cfg);

	cl_git_pass(git3_config_open_ondisk(&cfg, "config/config11"));

	n = 0;
	cl_git_pass(git3_config_get_multivar_foreach(cfg, _name, NULL, cb, &n));
	cl_assert(n == 2);

	git3_config_free(cfg);
}

void test_config_multivar__replace_multiple(void)
{
	git3_config *cfg;
	int n;

	cl_git_pass(git3_config_open_ondisk(&cfg, "config/config11"));
	cl_git_pass(git3_config_set_multivar(cfg, _name, "git://", "git://git.otherplace.org/libgit3"));

	n = 0;
	cl_git_pass(git3_config_get_multivar_foreach(cfg, _name, "otherplace", cb, &n));
	cl_assert_equal_i(n, 2);

	git3_config_free(cfg);

	cl_git_pass(git3_config_open_ondisk(&cfg, "config/config11"));

	n = 0;
	cl_git_pass(git3_config_get_multivar_foreach(cfg, _name, "otherplace", cb, &n));
	cl_assert_equal_i(n, 2);

	git3_config_free(cfg);
}

void test_config_multivar__delete(void)
{
	git3_config *cfg;
	int n;

	cl_git_pass(git3_config_open_ondisk(&cfg, "config/config11"));

	n = 0;
	cl_git_pass(git3_config_get_multivar_foreach(cfg, _name, NULL, cb, &n));
	cl_assert_equal_i(2, n);

	cl_git_pass(git3_config_delete_multivar(cfg, _name, "github"));

	n = 0;
	cl_git_pass(git3_config_get_multivar_foreach(cfg, _name, NULL, cb, &n));
	cl_assert_equal_i(1, n);

	git3_config_free(cfg);

	cl_git_pass(git3_config_open_ondisk(&cfg, "config/config11"));

	n = 0;
	cl_git_pass(git3_config_get_multivar_foreach(cfg, _name, NULL, cb, &n));
	cl_assert_equal_i(1, n);

	git3_config_free(cfg);
}

void test_config_multivar__delete_multiple(void)
{
	git3_config *cfg;
	int n;

	cl_git_pass(git3_config_open_ondisk(&cfg, "config/config11"));

	n = 0;
	cl_git_pass(git3_config_get_multivar_foreach(cfg, _name, NULL, cb, &n));
	cl_assert(n == 2);

	cl_git_pass(git3_config_delete_multivar(cfg, _name, "git"));

	n = 0;
	cl_git_fail_with(git3_config_get_multivar_foreach(cfg, _name, NULL, cb, &n), GIT3_ENOTFOUND);

	git3_config_free(cfg);

	cl_git_pass(git3_config_open_ondisk(&cfg, "config/config11"));

	n = 0;
	cl_git_fail_with(git3_config_get_multivar_foreach(cfg, _name, NULL, cb, &n), GIT3_ENOTFOUND);

	git3_config_free(cfg);
}

void test_config_multivar__delete_notfound(void)
{
	git3_config *cfg;

	cl_git_pass(git3_config_open_ondisk(&cfg, "config/config11"));

	cl_git_fail_with(git3_config_delete_multivar(cfg, "remote.ab.noturl", "git"), GIT3_ENOTFOUND);

	git3_config_free(cfg);
}

void test_config_multivar__rename_section(void)
{
	git3_repository *repo;
	git3_config *cfg;
	int n;

	repo = cl_git_sandbox_init("testrepo");
	cl_git_pass(git3_repository_config(&cfg, repo));

	cl_git_pass(git3_config_set_multivar(cfg, "branch.foo.name", "^$", "bar"));
	cl_git_pass(git3_config_set_multivar(cfg, "branch.foo.name", "^$", "xyzzy"));
	n = 0;
	cl_git_pass(git3_config_get_multivar_foreach(
	        cfg, "branch.foo.name", NULL, cb, &n));
	cl_assert(n == 2);

	cl_git_pass(
		    git3_config_rename_section(repo, "branch.foo", "branch.foobar"));

	assert_config_entry_existence(repo, "branch.foo.name", false);
	n = 0;
	cl_git_pass(git3_config_get_multivar_foreach(
	        cfg, "branch.foobar.name", NULL, cb, &n));
	cl_assert(n == 2);

	git3_config_free(cfg);
	cl_git_sandbox_cleanup();
}
