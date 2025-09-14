#include "clar_libgit3.h"
#include "index.h"
#include "git3/sys/index.h"
#include "git3/repository.h"
#include "../reset/reset_helpers.h"

static git3_repository *repo;
static git3_index *repo_index;

#define TEST_REPO_PATH "mergedrepo"
#define TEST_INDEX_PATH TEST_REPO_PATH "/.git/index"

/* Fixture setup and teardown */
void test_index_names__initialize(void)
{
	repo = cl_git_sandbox_init("mergedrepo");
	git3_repository_index(&repo_index, repo);
}

void test_index_names__cleanup(void)
{
	git3_index_free(repo_index);
	repo_index = NULL;

	cl_git_sandbox_cleanup();
}

static void index_add_conflicts(void)
{
	git3_index_entry entry = {{0}};
	const char *paths[][3] = {
		{ "ancestor", "ours", "theirs" },
		{ "ancestor2", "ours2", "theirs2" },
		{ "ancestor3", "ours3", "theirs3" } };
	const char **conflict;
	size_t i;

	for (i = 0; i < ARRAY_SIZE(paths); i++) {
		conflict = paths[i];

		/* ancestor */
		entry.path = conflict[0];
		entry.mode = GIT3_FILEMODE_BLOB;
		GIT3_INDEX_ENTRY_STAGE_SET(&entry, GIT3_INDEX_STAGE_ANCESTOR);
		git3_oid_from_string(&entry.id, "1f85ca51b8e0aac893a621b61a9c2661d6aa6d81", GIT3_OID_SHA1);
		cl_git_pass(git3_index_add(repo_index, &entry));

		/* ours */
		entry.path = conflict[1];
		entry.mode = GIT3_FILEMODE_BLOB;
		GIT3_INDEX_ENTRY_STAGE_SET(&entry, GIT3_INDEX_STAGE_OURS);
		git3_oid_from_string(&entry.id, "1f85ca51b8e0aac893a621b61a9c2661d6aa6d81", GIT3_OID_SHA1);
		cl_git_pass(git3_index_add(repo_index, &entry));

		/* theirs */
		entry.path = conflict[2];
		entry.mode = GIT3_FILEMODE_BLOB;
		GIT3_INDEX_ENTRY_STAGE_SET(&entry, GIT3_INDEX_STAGE_THEIRS);
		git3_oid_from_string(&entry.id, "1f85ca51b8e0aac893a621b61a9c2661d6aa6d81", GIT3_OID_SHA1);
		cl_git_pass(git3_index_add(repo_index, &entry));
	}
}

void test_index_names__add(void)
{
	const git3_index_name_entry *conflict_name;

	index_add_conflicts();
	cl_git_pass(git3_index_name_add(repo_index, "ancestor", "ours", "theirs"));
	cl_git_pass(git3_index_name_add(repo_index, "ancestor2", "ours2", NULL));
	cl_git_pass(git3_index_name_add(repo_index, "ancestor3", NULL, "theirs3"));

	cl_assert(git3_index_name_entrycount(repo_index) == 3);

	conflict_name = git3_index_name_get_byindex(repo_index, 0);
	cl_assert(strcmp(conflict_name->ancestor, "ancestor") == 0);
	cl_assert(strcmp(conflict_name->ours, "ours") == 0);
	cl_assert(strcmp(conflict_name->theirs, "theirs") == 0);

	conflict_name = git3_index_name_get_byindex(repo_index, 1);
	cl_assert(strcmp(conflict_name->ancestor, "ancestor2") == 0);
	cl_assert(strcmp(conflict_name->ours, "ours2") == 0);
	cl_assert(conflict_name->theirs == NULL);

	conflict_name = git3_index_name_get_byindex(repo_index, 2);
	cl_assert(strcmp(conflict_name->ancestor, "ancestor3") == 0);
	cl_assert(conflict_name->ours == NULL);
	cl_assert(strcmp(conflict_name->theirs, "theirs3") == 0);

	cl_git_pass(git3_index_write(repo_index));
}

void test_index_names__roundtrip(void)
{
	const git3_index_name_entry *conflict_name;

	cl_git_pass(git3_index_name_add(repo_index, "ancestor", "ours", "theirs"));
	cl_git_pass(git3_index_name_add(repo_index, "ancestor2", "ours2", NULL));
	cl_git_pass(git3_index_name_add(repo_index, "ancestor3", NULL, "theirs3"));

	cl_git_pass(git3_index_write(repo_index));
	git3_index_clear(repo_index);
	cl_assert(git3_index_name_entrycount(repo_index) == 0);

	cl_git_pass(git3_index_read(repo_index, true));
	cl_assert(git3_index_name_entrycount(repo_index) == 3);

	conflict_name = git3_index_name_get_byindex(repo_index, 0);
	cl_assert(strcmp(conflict_name->ancestor, "ancestor") == 0);
	cl_assert(strcmp(conflict_name->ours, "ours") == 0);
	cl_assert(strcmp(conflict_name->theirs, "theirs") == 0);

	conflict_name = git3_index_name_get_byindex(repo_index, 1);
	cl_assert(strcmp(conflict_name->ancestor, "ancestor2") == 0);
	cl_assert(strcmp(conflict_name->ours, "ours2") == 0);
	cl_assert(conflict_name->theirs == NULL);

	conflict_name = git3_index_name_get_byindex(repo_index, 2);
	cl_assert(strcmp(conflict_name->ancestor, "ancestor3") == 0);
	cl_assert(conflict_name->ours == NULL);
	cl_assert(strcmp(conflict_name->theirs, "theirs3") == 0);
}

void test_index_names__cleaned_on_reset_hard(void)
{
	git3_object *target;

	cl_git_pass(git3_revparse_single(&target, repo, "3a34580"));

	test_index_names__add();
	cl_git_pass(git3_reset(repo, target, GIT3_RESET_HARD, NULL));
	cl_assert(git3_index_name_entrycount(repo_index) == 0);

	git3_object_free(target);
}

void test_index_names__cleaned_on_reset_mixed(void)
{
	git3_object *target;

	cl_git_pass(git3_revparse_single(&target, repo, "3a34580"));

	test_index_names__add();
	cl_git_pass(git3_reset(repo, target, GIT3_RESET_MIXED, NULL));
	cl_assert(git3_index_name_entrycount(repo_index) == 0);

	git3_object_free(target);
}

void test_index_names__cleaned_on_checkout_tree(void)
{
	git3_oid oid;
	git3_object *obj;
	git3_checkout_options opts = GIT3_CHECKOUT_OPTIONS_INIT;

	opts.checkout_strategy = GIT3_CHECKOUT_FORCE | GIT3_CHECKOUT_UPDATE_ONLY;

	test_index_names__add();
	cl_git_pass(git3_reference_name_to_id(&oid, repo, "refs/heads/master"));
	cl_git_pass(git3_object_lookup(&obj, repo, &oid, GIT3_OBJECT_ANY));
	cl_git_pass(git3_checkout_tree(repo, obj, &opts));
	cl_assert_equal_sz(0, git3_index_name_entrycount(repo_index));

	git3_object_free(obj);
}

void test_index_names__cleaned_on_checkout_head(void)
{
	git3_checkout_options opts = GIT3_CHECKOUT_OPTIONS_INIT;

	opts.checkout_strategy = GIT3_CHECKOUT_FORCE | GIT3_CHECKOUT_UPDATE_ONLY;

	test_index_names__add();
	cl_git_pass(git3_checkout_head(repo, &opts));
	cl_assert_equal_sz(0, git3_index_name_entrycount(repo_index));
}

void test_index_names__retained_on_checkout_index(void)
{
	git3_checkout_options opts = GIT3_CHECKOUT_OPTIONS_INIT;

	opts.checkout_strategy = GIT3_CHECKOUT_FORCE | GIT3_CHECKOUT_UPDATE_ONLY;

	test_index_names__add();
	cl_git_pass(git3_checkout_index(repo, repo_index, &opts));
	cl_assert(git3_index_name_entrycount(repo_index) > 0);
}
