#include "clar_libgit3.h"
#include "refs.h"
#include "repo_helpers.h"
#include "posix.h"

void make_head_unborn(git3_repository* repo, const char *target)
{
	git3_reference *head;

	cl_git_pass(git3_reference_symbolic_create(&head, repo, GIT3_HEAD_FILE, target, 1, NULL));
	git3_reference_free(head);
}

void delete_head(git3_repository* repo)
{
	git3_str head_path = GIT3_STR_INIT;

	cl_git_pass(git3_str_joinpath(&head_path, git3_repository_path(repo), GIT3_HEAD_FILE));
	cl_git_pass(p_unlink(git3_str_cstr(&head_path)));

	git3_str_dispose(&head_path);
}

void create_tmp_global_config(const char *dirname, const char *key, const char *val)
{
	git3_str path = GIT3_STR_INIT;
	git3_config *config;

	cl_git_pass(git3_libgit3_opts(GIT3_OPT_SET_SEARCH_PATH,
		GIT3_CONFIG_LEVEL_GLOBAL, dirname));
	cl_must_pass(p_mkdir(dirname, 0777));
	cl_git_pass(git3_str_joinpath(&path, dirname, ".gitconfig"));
	cl_git_pass(git3_config_open_ondisk(&config, path.ptr));
	cl_git_pass(git3_config_set_string(config, key, val));
	git3_config_free(config);
	git3_str_dispose(&path);
}
