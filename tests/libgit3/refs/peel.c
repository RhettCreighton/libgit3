#include "clar_libgit3.h"

static git3_repository *g_repo;
static git3_repository *g_peel_repo;

void test_refs_peel__initialize(void)
{
	cl_git_pass(git3_repository_open(&g_repo, cl_fixture("testrepo.git")));
	cl_git_pass(git3_repository_open(&g_peel_repo, cl_fixture("peeled.git")));
}

void test_refs_peel__cleanup(void)
{
	git3_repository_free(g_repo);
	g_repo = NULL;
	git3_repository_free(g_peel_repo);
	g_peel_repo = NULL;
}

static void assert_peel_generic(
	git3_repository *repo,
	const char *ref_name,
	git3_object_t requested_type,
	const char* expected_sha,
	git3_object_t expected_type)
{
	git3_oid expected_oid;
	git3_reference *ref;
	git3_object *peeled;

	cl_git_pass(git3_reference_lookup(&ref, repo, ref_name));

	cl_git_pass(git3_reference_peel(&peeled, ref, requested_type));

	cl_git_pass(git3_oid_from_string(&expected_oid, expected_sha, GIT3_OID_SHA1));
	cl_assert_equal_oid(&expected_oid, git3_object_id(peeled));

	cl_assert_equal_i(expected_type, git3_object_type(peeled));

	git3_object_free(peeled);
	git3_reference_free(ref);
}

static void assert_peel(
	const char *ref_name,
	git3_object_t requested_type,
	const char* expected_sha,
	git3_object_t expected_type)
{
	assert_peel_generic(g_repo, ref_name, requested_type,
			    expected_sha, expected_type);
}

static void assert_peel_error(int error, const char *ref_name, git3_object_t requested_type)
{
	git3_reference *ref;
	git3_object *peeled;

	cl_git_pass(git3_reference_lookup(&ref, g_repo, ref_name));

	cl_assert_equal_i(error, git3_reference_peel(&peeled, ref, requested_type));

	git3_reference_free(ref);
}

void test_refs_peel__can_peel_a_tag(void)
{
	assert_peel("refs/tags/test", GIT3_OBJECT_TAG,
		"b25fa35b38051e4ae45d4222e795f9df2e43f1d1", GIT3_OBJECT_TAG);
	assert_peel("refs/tags/test", GIT3_OBJECT_COMMIT,
		"e90810b8df3e80c413d903f631643c716887138d", GIT3_OBJECT_COMMIT);
	assert_peel("refs/tags/test", GIT3_OBJECT_TREE,
		"53fc32d17276939fc79ed05badaef2db09990016", GIT3_OBJECT_TREE);
	assert_peel("refs/tags/point_to_blob", GIT3_OBJECT_BLOB,
		"1385f264afb75a56a5bec74243be9b367ba4ca08", GIT3_OBJECT_BLOB);
}

void test_refs_peel__can_peel_a_branch(void)
{
	assert_peel("refs/heads/master", GIT3_OBJECT_COMMIT,
		"a65fedf39aefe402d3bb6e24df4d4f5fe4547750", GIT3_OBJECT_COMMIT);
	assert_peel("refs/heads/master", GIT3_OBJECT_TREE,
		"944c0f6e4dfa41595e6eb3ceecdb14f50fe18162", GIT3_OBJECT_TREE);
}

void test_refs_peel__can_peel_a_symbolic_reference(void)
{
	assert_peel("HEAD", GIT3_OBJECT_COMMIT,
		"a65fedf39aefe402d3bb6e24df4d4f5fe4547750", GIT3_OBJECT_COMMIT);
	assert_peel("HEAD", GIT3_OBJECT_TREE,
		"944c0f6e4dfa41595e6eb3ceecdb14f50fe18162", GIT3_OBJECT_TREE);
}

void test_refs_peel__cannot_peel_into_a_non_existing_target(void)
{
	assert_peel_error(GIT3_EINVALIDSPEC, "refs/tags/point_to_blob", GIT3_OBJECT_TAG);
}

void test_refs_peel__can_peel_into_any_non_tag_object(void)
{
	assert_peel("refs/heads/master", GIT3_OBJECT_ANY,
		"a65fedf39aefe402d3bb6e24df4d4f5fe4547750", GIT3_OBJECT_COMMIT);
	assert_peel("refs/tags/point_to_blob", GIT3_OBJECT_ANY,
		"1385f264afb75a56a5bec74243be9b367ba4ca08", GIT3_OBJECT_BLOB);
	assert_peel("refs/tags/test", GIT3_OBJECT_ANY,
		"e90810b8df3e80c413d903f631643c716887138d", GIT3_OBJECT_COMMIT);
}

void test_refs_peel__can_peel_fully_peeled_packed_refs(void)
{
	assert_peel_generic(g_peel_repo,
			    "refs/tags/tag-inside-tags", GIT3_OBJECT_ANY,
			    "0df1a5865c8abfc09f1f2182e6a31be550e99f07",
			    GIT3_OBJECT_COMMIT);
	assert_peel_generic(g_peel_repo,
			    "refs/foo/tag-outside-tags", GIT3_OBJECT_ANY,
			    "0df1a5865c8abfc09f1f2182e6a31be550e99f07",
			    GIT3_OBJECT_COMMIT);
}

void test_refs_peel__can_peel_fully_peeled_tag_to_tag(void)
{
	assert_peel_generic(g_peel_repo,
			    "refs/tags/tag-inside-tags", GIT3_OBJECT_TAG,
			    "c2596aa0151888587ec5c0187f261e63412d9e11",
			    GIT3_OBJECT_TAG);
	assert_peel_generic(g_peel_repo,
			    "refs/foo/tag-outside-tags", GIT3_OBJECT_TAG,
			    "c2596aa0151888587ec5c0187f261e63412d9e11",
			    GIT3_OBJECT_TAG);
}
