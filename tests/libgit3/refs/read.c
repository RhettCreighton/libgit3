#include "clar_libgit3.h"

#include "repository.h"
#include "git3/reflog.h"
#include "reflog.h"
#include "ref_helpers.h"

static const char *loose_tag_ref_name = "refs/tags/e90810b";
static const char *non_existing_tag_ref_name = "refs/tags/i-do-not-exist";
static const char *head_tracker_sym_ref_name = "HEAD_TRACKER";
static const char *current_head_target = "refs/heads/master";
static const char *current_master_tip = "a65fedf39aefe402d3bb6e24df4d4f5fe4547750";
static const char *packed_head_name = "refs/heads/packed";
static const char *packed_test_head_name = "refs/heads/packed-test";

static git3_repository *g_repo;

void test_refs_read__initialize(void)
{
	cl_git_pass(git3_repository_open(&g_repo, cl_fixture("testrepo.git")));
}

void test_refs_read__cleanup(void)
{
	git3_repository_free(g_repo);
	g_repo = NULL;
}

void test_refs_read__loose_tag(void)
{
	/* lookup a loose tag reference */
	git3_reference *reference;
	git3_object *object;
	git3_str ref_name_from_tag_name = GIT3_STR_INIT;

	cl_git_pass(git3_reference_lookup(&reference, g_repo, loose_tag_ref_name));
	cl_assert(git3_reference_type(reference) & GIT3_REFERENCE_DIRECT);
	cl_assert(reference_is_packed(reference) == 0);
	cl_assert_equal_s(reference->name, loose_tag_ref_name);

	cl_git_pass(git3_object_lookup(&object, g_repo, git3_reference_target(reference), GIT3_OBJECT_ANY));
	cl_assert(object != NULL);
	cl_assert(git3_object_type(object) == GIT3_OBJECT_TAG);

	/* Ensure the name of the tag matches the name of the reference */
	cl_git_pass(git3_str_joinpath(&ref_name_from_tag_name, GIT3_REFS_TAGS_DIR, git3_tag_name((git3_tag *)object)));
	cl_assert_equal_s(ref_name_from_tag_name.ptr, loose_tag_ref_name);
	git3_str_dispose(&ref_name_from_tag_name);

	git3_object_free(object);

	git3_reference_free(reference);
}

void test_refs_read__nonexisting_tag(void)
{
	/* lookup a loose tag reference that doesn't exist */
	git3_reference *reference;

	cl_git_fail(git3_reference_lookup(&reference, g_repo, non_existing_tag_ref_name));

	git3_reference_free(reference);
}


void test_refs_read__symbolic(void)
{
	/* lookup a symbolic reference */
	git3_reference *reference, *resolved_ref;
	git3_object *object;
	git3_oid id;

	cl_git_pass(git3_reference_lookup(&reference, g_repo, GIT3_HEAD_FILE));
	cl_assert(git3_reference_type(reference) & GIT3_REFERENCE_SYMBOLIC);
	cl_assert(reference_is_packed(reference) == 0);
	cl_assert_equal_s(reference->name, GIT3_HEAD_FILE);

	cl_git_pass(git3_reference_resolve(&resolved_ref, reference));
	cl_assert(git3_reference_type(resolved_ref) == GIT3_REFERENCE_DIRECT);

	cl_git_pass(git3_object_lookup(&object, g_repo, git3_reference_target(resolved_ref), GIT3_OBJECT_ANY));
	cl_assert(object != NULL);
	cl_assert(git3_object_type(object) == GIT3_OBJECT_COMMIT);

	git3_oid_from_string(&id, current_master_tip, GIT3_OID_SHA1);
	cl_assert_equal_oid(&id, git3_object_id(object));

	git3_object_free(object);

	git3_reference_free(reference);
	git3_reference_free(resolved_ref);
}

void test_refs_read__nested_symbolic(void)
{
	/* lookup a nested symbolic reference */
	git3_reference *reference, *resolved_ref;
	git3_object *object;
	git3_oid id;

	cl_git_pass(git3_reference_lookup(&reference, g_repo, head_tracker_sym_ref_name));
	cl_assert(git3_reference_type(reference) & GIT3_REFERENCE_SYMBOLIC);
	cl_assert(reference_is_packed(reference) == 0);
	cl_assert_equal_s(reference->name, head_tracker_sym_ref_name);

	cl_git_pass(git3_reference_resolve(&resolved_ref, reference));
	cl_assert(git3_reference_type(resolved_ref) == GIT3_REFERENCE_DIRECT);

	cl_git_pass(git3_object_lookup(&object, g_repo, git3_reference_target(resolved_ref), GIT3_OBJECT_ANY));
	cl_assert(object != NULL);
	cl_assert(git3_object_type(object) == GIT3_OBJECT_COMMIT);

	git3_oid_from_string(&id, current_master_tip, GIT3_OID_SHA1);
	cl_assert_equal_oid(&id, git3_object_id(object));

	git3_object_free(object);

	git3_reference_free(reference);
	git3_reference_free(resolved_ref);
}

void test_refs_read__head_then_master(void)
{
	/* lookup the HEAD and resolve the master branch */
	git3_reference *reference, *resolved_ref, *comp_base_ref;

	cl_git_pass(git3_reference_lookup(&reference, g_repo, head_tracker_sym_ref_name));
	cl_git_pass(git3_reference_resolve(&comp_base_ref, reference));
	git3_reference_free(reference);

	cl_git_pass(git3_reference_lookup(&reference, g_repo, GIT3_HEAD_FILE));
	cl_git_pass(git3_reference_resolve(&resolved_ref, reference));
	cl_assert_equal_oid(git3_reference_target(comp_base_ref), git3_reference_target(resolved_ref));
	git3_reference_free(reference);
	git3_reference_free(resolved_ref);

	cl_git_pass(git3_reference_lookup(&reference, g_repo, current_head_target));
	cl_git_pass(git3_reference_resolve(&resolved_ref, reference));
	cl_assert_equal_oid(git3_reference_target(comp_base_ref), git3_reference_target(resolved_ref));
	git3_reference_free(reference);
	git3_reference_free(resolved_ref);

	git3_reference_free(comp_base_ref);
}

void test_refs_read__master_then_head(void)
{
	/* lookup the master branch and then the HEAD */
	git3_reference *reference, *master_ref, *resolved_ref;

	cl_git_pass(git3_reference_lookup(&master_ref, g_repo, current_head_target));
	cl_git_pass(git3_reference_lookup(&reference, g_repo, GIT3_HEAD_FILE));

	cl_git_pass(git3_reference_resolve(&resolved_ref, reference));
	cl_assert_equal_oid(git3_reference_target(master_ref), git3_reference_target(resolved_ref));

	git3_reference_free(reference);
	git3_reference_free(resolved_ref);
	git3_reference_free(master_ref);
}


void test_refs_read__packed(void)
{
	/* lookup a packed reference */
	git3_reference *reference;
	git3_object *object;

	cl_git_pass(git3_reference_lookup(&reference, g_repo, packed_head_name));
	cl_assert(git3_reference_type(reference) & GIT3_REFERENCE_DIRECT);
	cl_assert(reference_is_packed(reference));
	cl_assert_equal_s(reference->name, packed_head_name);

	cl_git_pass(git3_object_lookup(&object, g_repo, git3_reference_target(reference), GIT3_OBJECT_ANY));
	cl_assert(object != NULL);
	cl_assert(git3_object_type(object) == GIT3_OBJECT_COMMIT);

	git3_object_free(object);

	git3_reference_free(reference);
}

void test_refs_read__loose_first(void)
{
	/* assure that a loose reference is looked up before a packed reference */
	git3_reference *reference;

	cl_git_pass(git3_reference_lookup(&reference, g_repo, packed_head_name));
	git3_reference_free(reference);
	cl_git_pass(git3_reference_lookup(&reference, g_repo, packed_test_head_name));
	cl_assert(git3_reference_type(reference) & GIT3_REFERENCE_DIRECT);
	cl_assert(reference_is_packed(reference) == 0);
	cl_assert_equal_s(reference->name, packed_test_head_name);

	git3_reference_free(reference);
}

void test_refs_read__chomped(void)
{
	git3_reference *test, *chomped;

	cl_git_pass(git3_reference_lookup(&test, g_repo, "refs/heads/test"));
	cl_git_pass(git3_reference_lookup(&chomped, g_repo, "refs/heads/chomped"));
	cl_assert_equal_oid(git3_reference_target(test), git3_reference_target(chomped));

	git3_reference_free(test);
	git3_reference_free(chomped);
}

void test_refs_read__trailing(void)
{
	git3_reference *test, *trailing;

	cl_git_pass(git3_reference_lookup(&test, g_repo, "refs/heads/test"));
	cl_git_pass(git3_reference_lookup(&trailing, g_repo, "refs/heads/trailing"));
	cl_assert_equal_oid(git3_reference_target(test), git3_reference_target(trailing));
	git3_reference_free(trailing);
	cl_git_pass(git3_reference_lookup(&trailing, g_repo, "FETCH_HEAD"));

	git3_reference_free(test);
	git3_reference_free(trailing);
}

void test_refs_read__unfound_return_ENOTFOUND(void)
{
	git3_reference *reference;
	git3_oid id;

	cl_assert_equal_i(GIT3_ENOTFOUND,
		git3_reference_lookup(&reference, g_repo, "TEST_MASTER"));
	cl_assert_equal_i(GIT3_ENOTFOUND,
		git3_reference_lookup(&reference, g_repo, "refs/test/master"));
	cl_assert_equal_i(GIT3_ENOTFOUND,
		git3_reference_lookup(&reference, g_repo, "refs/tags/test/master"));
	cl_assert_equal_i(GIT3_ENOTFOUND,
		git3_reference_lookup(&reference, g_repo, "refs/tags/test/farther/master"));

	cl_assert_equal_i(GIT3_ENOTFOUND,
		git3_reference_name_to_id(&id, g_repo, "refs/tags/test/farther/master"));
}

static void assert_is_branch(const char *name, bool expected_branchness)
{
	git3_reference *reference;
	cl_git_pass(git3_reference_lookup(&reference, g_repo, name));
	cl_assert_equal_i(expected_branchness, git3_reference_is_branch(reference));
	git3_reference_free(reference);
}

void test_refs_read__can_determine_if_a_reference_is_a_local_branch(void)
{
	assert_is_branch("refs/heads/master", true);
	assert_is_branch("refs/heads/packed", true);
	assert_is_branch("refs/remotes/test/master", false);
	assert_is_branch("refs/tags/e90810b", false);
}

static void assert_is_tag(const char *name, bool expected_tagness)
{
	git3_reference *reference;
	cl_git_pass(git3_reference_lookup(&reference, g_repo, name));
	cl_assert_equal_i(expected_tagness, git3_reference_is_tag(reference));
	git3_reference_free(reference);
}

void test_refs_read__can_determine_if_a_reference_is_a_tag(void)
{
	assert_is_tag("refs/tags/e90810b", true);
	assert_is_tag("refs/tags/test", true);
	assert_is_tag("refs/heads/packed", false);
	assert_is_tag("refs/remotes/test/master", false);
}

static void assert_is_note(const char *name, bool expected_noteness)
{
	git3_reference *reference;
	cl_git_pass(git3_reference_lookup(&reference, g_repo, name));
	cl_assert_equal_i(expected_noteness, git3_reference_is_note(reference));
	git3_reference_free(reference);
}

void test_refs_read__can_determine_if_a_reference_is_a_note(void)
{
	assert_is_note("refs/notes/fanout", true);
	assert_is_note("refs/heads/packed", false);
	assert_is_note("refs/remotes/test/master", false);
}

void test_refs_read__invalid_name_returns_EINVALIDSPEC(void)
{
	git3_reference *reference;
	git3_oid id;

	cl_assert_equal_i(GIT3_EINVALIDSPEC,
		git3_reference_lookup(&reference, g_repo, "refs/heads/Inv@{id"));

	cl_assert_equal_i(GIT3_EINVALIDSPEC,
		git3_reference_name_to_id(&id, g_repo, "refs/heads/Inv@{id"));
}
