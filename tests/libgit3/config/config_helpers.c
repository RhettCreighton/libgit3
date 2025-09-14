#include "clar_libgit3.h"
#include "config_helpers.h"
#include "repository.h"

void assert_config_entry_existence(
	git3_repository *repo,
	const char *name,
	bool is_supposed_to_exist)
{
	git3_config *config;
	git3_config_entry *entry = NULL;
	int result;

	cl_git_pass(git3_repository_config__weakptr(&config, repo));

	result = git3_config_get_entry(&entry, config, name);
	git3_config_entry_free(entry);

	if (is_supposed_to_exist)
		cl_git_pass(result);
	else
		cl_assert_equal_i(GIT3_ENOTFOUND, result);
}

void assert_config_entry_value(
	git3_repository *repo,
	const char *name,
	const char *expected_value)
{
	git3_config *config;
	git3_buf buf = GIT3_BUF_INIT;

	cl_git_pass(git3_repository_config__weakptr(&config, repo));

	cl_git_pass(git3_config_get_string_buf(&buf, config, name));

	cl_assert_equal_s(expected_value, buf.ptr);
	git3_buf_dispose(&buf);
}

static int count_config_entries_cb(
	const git3_config_entry *entry,
	void *payload)
{
	int *how_many = (int *)payload;

	GIT3_UNUSED(entry);

	(*how_many)++;

	return 0;
}

int count_config_entries_match(git3_repository *repo, const char *pattern)
{
	git3_config *config;
	int how_many = 0;

	cl_git_pass(git3_repository_config(&config, repo));

	cl_assert_equal_i(0, git3_config_foreach_match(
		config,	pattern, count_config_entries_cb, &how_many));

	git3_config_free(config);

	return how_many;
}
