#include "clar_libgit3.h"
#include "config/config_helpers.h"

#include "repository.h"

static git3_repository *_repo;
static const char *_remote_name = "test";

void test_network_remote_rename__initialize(void)
{
	_repo = cl_git_sandbox_init("testrepo.git");
}

void test_network_remote_rename__cleanup(void)
{
	cl_git_sandbox_cleanup();
}

void test_network_remote_rename__renaming_a_remote_moves_related_configuration_section(void)
{
	git3_strarray problems = {0};

	assert_config_entry_existence(_repo, "remote.test.fetch", true);
	assert_config_entry_existence(_repo, "remote.just/renamed.fetch", false);

	cl_git_pass(git3_remote_rename(&problems, _repo, _remote_name, "just/renamed"));
	cl_assert_equal_i(0, problems.count);
	git3_strarray_dispose(&problems);

	assert_config_entry_existence(_repo, "remote.test.fetch", false);
	assert_config_entry_existence(_repo, "remote.just/renamed.fetch", true);
}

void test_network_remote_rename__renaming_a_remote_updates_branch_related_configuration_entries(void)
{
	git3_strarray problems = {0};

	assert_config_entry_value(_repo, "branch.master.remote", "test");

	cl_git_pass(git3_remote_rename(&problems, _repo, _remote_name, "just/renamed"));
	cl_assert_equal_i(0, problems.count);
	git3_strarray_dispose(&problems);

	assert_config_entry_value(_repo, "branch.master.remote", "just/renamed");
}

void test_network_remote_rename__renaming_a_remote_updates_default_fetchrefspec(void)
{
	git3_strarray problems = {0};

	cl_git_pass(git3_remote_rename(&problems, _repo, _remote_name, "just/renamed"));
	cl_assert_equal_i(0, problems.count);
	git3_strarray_dispose(&problems);

	assert_config_entry_value(_repo, "remote.just/renamed.fetch", "+refs/heads/*:refs/remotes/just/renamed/*");
}

void test_network_remote_rename__renaming_a_remote_without_a_fetchrefspec_doesnt_create_one(void)
{
	git3_config *config;
	git3_remote *remote;
	git3_strarray problems = {0};

	cl_git_pass(git3_repository_config__weakptr(&config, _repo));
	cl_git_pass(git3_config_delete_entry(config, "remote.test.fetch"));

	cl_git_pass(git3_remote_lookup(&remote, _repo, "test"));
	git3_remote_free(remote);

	assert_config_entry_existence(_repo, "remote.test.fetch", false);

	cl_git_pass(git3_remote_rename(&problems, _repo, _remote_name, "just/renamed"));
	cl_assert_equal_i(0, problems.count);
	git3_strarray_dispose(&problems);

	assert_config_entry_existence(_repo, "remote.just/renamed.fetch", false);
}

void test_network_remote_rename__renaming_a_remote_notifies_of_non_default_fetchrefspec(void)
{
	git3_config *config;
	git3_remote *remote;
	git3_strarray problems = {0};

	cl_git_pass(git3_repository_config__weakptr(&config, _repo));
	cl_git_pass(git3_config_set_string(config, "remote.test.fetch", "+refs/*:refs/*"));
	cl_git_pass(git3_remote_lookup(&remote, _repo, "test"));
	git3_remote_free(remote);

	cl_git_pass(git3_remote_rename(&problems, _repo, _remote_name, "just/renamed"));
	cl_assert_equal_i(1, problems.count);
	cl_assert_equal_s("+refs/*:refs/*", problems.strings[0]);
	git3_strarray_dispose(&problems);

	assert_config_entry_value(_repo, "remote.just/renamed.fetch", "+refs/*:refs/*");

	git3_strarray_dispose(&problems);
}

void test_network_remote_rename__new_name_can_contain_dots(void)
{
	git3_strarray problems = {0};

	cl_git_pass(git3_remote_rename(&problems, _repo, _remote_name, "just.renamed"));
	cl_assert_equal_i(0, problems.count);
	git3_strarray_dispose(&problems);
	assert_config_entry_existence(_repo, "remote.just.renamed.fetch", true);
}

void test_network_remote_rename__new_name_must_conform_to_reference_naming_conventions(void)
{
	git3_strarray problems = {0};

	cl_assert_equal_i(
		GIT3_EINVALIDSPEC,
		git3_remote_rename(&problems, _repo, _remote_name, "new@{name"));
}

void test_network_remote_rename__renamed_name_is_persisted(void)
{
	git3_remote *renamed;
	git3_repository *another_repo;
	git3_strarray problems = {0};

	cl_git_fail(git3_remote_lookup(&renamed, _repo, "just/renamed"));

	cl_git_pass(git3_remote_rename(&problems, _repo, _remote_name, "just/renamed"));
	cl_assert_equal_i(0, problems.count);
	git3_strarray_dispose(&problems);

	cl_git_pass(git3_repository_open(&another_repo, "testrepo.git"));
	cl_git_pass(git3_remote_lookup(&renamed, _repo, "just/renamed"));

	git3_remote_free(renamed);
	git3_repository_free(another_repo);
}

void test_network_remote_rename__cannot_overwrite_an_existing_remote(void)
{
	git3_strarray problems = {0};

	cl_assert_equal_i(GIT3_EEXISTS, git3_remote_rename(&problems, _repo, _remote_name, "test"));
	cl_assert_equal_i(GIT3_EEXISTS, git3_remote_rename(&problems, _repo, _remote_name, "test_with_pushurl"));
}

void test_network_remote_rename__renaming_a_remote_moves_the_underlying_reference(void)
{
	git3_reference *underlying;
	git3_strarray problems = {0};

	cl_assert_equal_i(GIT3_ENOTFOUND, git3_reference_lookup(&underlying, _repo, "refs/remotes/just/renamed"));
	cl_git_pass(git3_reference_lookup(&underlying, _repo, "refs/remotes/test/master"));
	git3_reference_free(underlying);

	cl_git_pass(git3_remote_rename(&problems, _repo, _remote_name, "just/renamed"));
	cl_assert_equal_i(0, problems.count);
	git3_strarray_dispose(&problems);

	cl_assert_equal_i(GIT3_ENOTFOUND, git3_reference_lookup(&underlying, _repo, "refs/remotes/test/master"));
	cl_git_pass(git3_reference_lookup(&underlying, _repo, "refs/remotes/just/renamed/master"));
	git3_reference_free(underlying);
}

void test_network_remote_rename__overwrite_ref_in_target(void)
{
	git3_oid id;
	char idstr[GIT3_OID_SHA1_HEXSIZE + 1] = {0};
	git3_reference *ref;
	git3_branch_t btype;
	git3_branch_iterator *iter;
	git3_strarray problems = {0};

	cl_git_pass(git3_oid_from_string(&id, "a65fedf39aefe402d3bb6e24df4d4f5fe4547750", GIT3_OID_SHA1));
	cl_git_pass(git3_reference_create(&ref, _repo, "refs/remotes/renamed/master", &id, 1, NULL));
	git3_reference_free(ref);

	cl_git_pass(git3_remote_rename(&problems, _repo, _remote_name, "renamed"));
	cl_assert_equal_i(0, problems.count);
	git3_strarray_dispose(&problems);

	/* make sure there's only one remote-tracking branch */
	cl_git_pass(git3_branch_iterator_new(&iter, _repo, GIT3_BRANCH_REMOTE));
	cl_git_pass(git3_branch_next(&ref, &btype, iter));
	cl_assert_equal_s("refs/remotes/renamed/master", git3_reference_name(ref));
	git3_oid_fmt(idstr, git3_reference_target(ref));
	cl_assert_equal_s("be3563ae3f795b2b4353bcce3a527ad0a4f7f644", idstr);
	git3_reference_free(ref);

	cl_git_fail_with(GIT3_ITEROVER, git3_branch_next(&ref, &btype, iter));
	git3_branch_iterator_free(iter);
}

void test_network_remote_rename__nonexistent_returns_enotfound(void)
{
	git3_strarray problems = {0};

	int err = git3_remote_rename(&problems, _repo, "nonexistent", "renamed");

	cl_assert_equal_i(GIT3_ENOTFOUND, err);
}

void test_network_remote_rename__symref_head(void)
{
	int error;
	git3_reference *ref;
	git3_branch_t btype;
	git3_branch_iterator *iter;
	git3_strarray problems = {0};
	char idstr[GIT3_OID_SHA1_HEXSIZE + 1] = {0};
	git3_vector refs;

	cl_git_pass(git3_reference_symbolic_create(&ref, _repo, "refs/remotes/test/HEAD", "refs/remotes/test/master", 0, NULL));
	git3_reference_free(ref);

	cl_git_pass(git3_remote_rename(&problems, _repo, _remote_name, "renamed"));
	cl_assert_equal_i(0, problems.count);
	git3_strarray_dispose(&problems);

	cl_git_pass(git3_vector_init(&refs, 2, git3_reference__cmp_cb));
	cl_git_pass(git3_branch_iterator_new(&iter, _repo, GIT3_BRANCH_REMOTE));

	while ((error = git3_branch_next(&ref, &btype, iter)) == 0) {
		cl_git_pass(git3_vector_insert(&refs, ref));
	}
	cl_assert_equal_i(GIT3_ITEROVER, error);
	git3_vector_sort(&refs);

	cl_assert_equal_i(2, refs.length);

	ref = git3_vector_get(&refs, 0);
	cl_assert_equal_s("refs/remotes/renamed/HEAD", git3_reference_name(ref));
	cl_assert_equal_s("refs/remotes/renamed/master", git3_reference_symbolic_target(ref));
	git3_reference_free(ref);

	ref = git3_vector_get(&refs, 1);
	cl_assert_equal_s("refs/remotes/renamed/master", git3_reference_name(ref));
	git3_oid_fmt(idstr, git3_reference_target(ref));
	cl_assert_equal_s("be3563ae3f795b2b4353bcce3a527ad0a4f7f644", idstr);
	git3_reference_free(ref);

	git3_vector_dispose(&refs);

	cl_git_fail_with(GIT3_ITEROVER, git3_branch_next(&ref, &btype, iter));
	git3_branch_iterator_free(iter);
}
