#include "clar_libgit3.h"

#include "futils.h"
#include "grafts.h"

static git3_repository *g_repo;

void test_grafts_basic__initialize(void)
{
	g_repo = cl_git_sandbox_init("grafted.git");
}

void test_grafts_basic__cleanup(void)
{
	cl_git_sandbox_cleanup();
}

void test_grafts_basic__graft_add(void)
{
	git3_array_oid_t parents = GIT3_ARRAY_INIT;
	git3_oid oid_src, *oid1;
	git3_commit_graft *graft;
	git3_grafts *grafts;

	cl_git_pass(git3_grafts_new(&grafts, GIT3_OID_SHA1));

	cl_assert(oid1 = git3_array_alloc(parents));
	cl_git_pass(git3_oid_from_string(&oid_src, "2f3053cbff8a4ca2f0666de364ddb734a28a31a9", GIT3_OID_SHA1));
	git3_oid_cpy(oid1, &oid_src);

	git3_oid_from_string(&oid_src, "f503807ffa920e407a600cfaee96b7152259acc7", GIT3_OID_SHA1);
	cl_git_pass(git3_grafts_add(grafts, &oid_src, parents));
	git3_array_clear(parents);

	cl_assert_equal_i(1, git3_grafts_size(grafts));
	cl_git_pass(git3_grafts_get(&graft, grafts, &oid_src));
	cl_assert_equal_s("f503807ffa920e407a600cfaee96b7152259acc7", git3_oid_tostr_s(&graft->oid));
	cl_assert_equal_i(1, git3_array_size(graft->parents));
	cl_assert_equal_s("2f3053cbff8a4ca2f0666de364ddb734a28a31a9", git3_oid_tostr_s(git3_array_get(graft->parents, 0)));

	git3_grafts_free(grafts);
}

void test_grafts_basic__grafted_revwalk(void)
{
	git3_revwalk *w;
	git3_oid oids[10];
	size_t i = 0;
	git3_commit *commit;

	cl_git_pass(git3_revwalk_new(&w, g_repo));
	cl_git_pass(git3_revwalk_push_ref(w, "refs/heads/branch"));

	cl_git_pass(git3_revwalk_next(&oids[i++], w));
	cl_assert_equal_s(git3_oid_tostr_s(&oids[0]), "8a00e91619098618be97c0d2ceabb05a2c58edd9");
	cl_git_pass(git3_revwalk_next(&oids[i++], w));
	cl_assert_equal_s(git3_oid_tostr_s(&oids[1]), "f503807ffa920e407a600cfaee96b7152259acc7");
	cl_git_pass(git3_revwalk_next(&oids[i++], w));
	cl_assert_equal_s(git3_oid_tostr_s(&oids[2]), "2f3053cbff8a4ca2f0666de364ddb734a28a31a9");

	cl_git_fail_with(GIT3_ITEROVER, git3_revwalk_next(&oids[i++], w));

	cl_git_pass(git3_commit_lookup(&commit, g_repo, &oids[0]));

	cl_assert_equal_i(1, git3_commit_parentcount(commit));

	git3_commit_free(commit);
	git3_revwalk_free(w);
}

void test_grafts_basic__grafted_objects(void)
{
	git3_oid oid;
	git3_commit *commit;

	cl_git_pass(git3_oid_from_string(&oid, "f503807ffa920e407a600cfaee96b7152259acc7", GIT3_OID_SHA1));
	cl_git_pass(git3_commit_lookup(&commit, g_repo, &oid));
	cl_assert_equal_i(1, git3_commit_parentcount(commit));
	git3_commit_free(commit);

	cl_git_pass(git3_oid_from_string(&oid, "0512adebd3782157f0d5c9b22b043f87b4aaff9e", GIT3_OID_SHA1));
	cl_git_pass(git3_commit_lookup(&commit, g_repo, &oid));
	cl_assert_equal_i(1, git3_commit_parentcount(commit));
	git3_commit_free(commit);

	cl_git_pass(git3_oid_from_string(&oid, "66cc22a015f6ca75b34c82d28f78ba663876bade", GIT3_OID_SHA1));
	cl_git_pass(git3_commit_lookup(&commit, g_repo, &oid));
	cl_assert_equal_i(4, git3_commit_parentcount(commit));
	git3_commit_free(commit);
}

void test_grafts_basic__grafted_merge_revwalk(void)
{
	git3_revwalk *w;
	git3_oid oids[10];
	size_t i = 0;

	cl_git_pass(git3_revwalk_new(&w, g_repo));
	cl_git_pass(git3_revwalk_push_ref(w, "refs/heads/bottom"));

	cl_git_pass(git3_revwalk_next(&oids[i++], w));
	cl_assert_equal_s(git3_oid_tostr_s(&oids[i - 1]), "66cc22a015f6ca75b34c82d28f78ba663876bade");
	cl_git_pass(git3_revwalk_next(&oids[i++], w));
	cl_assert_equal_s(git3_oid_tostr_s(&oids[i - 1]), "e414f42f4e6bc6934563a2349a8600f0ab68618e");
	cl_git_pass(git3_revwalk_next(&oids[i++], w));
	cl_assert_equal_s(git3_oid_tostr_s(&oids[i - 1]), "8a00e91619098618be97c0d2ceabb05a2c58edd9");
	cl_git_pass(git3_revwalk_next(&oids[i++], w));
	cl_assert_equal_s(git3_oid_tostr_s(&oids[i - 1]), "1c18e80a276611bb9b146590616bbc5aebdf2945");
	cl_git_pass(git3_revwalk_next(&oids[i++], w));
	cl_assert_equal_s(git3_oid_tostr_s(&oids[i - 1]), "d7224d49d6d5aff6ade596ed74f4bcd4f77b29e2");
	cl_git_pass(git3_revwalk_next(&oids[i++], w));
	cl_assert_equal_s(git3_oid_tostr_s(&oids[i - 1]), "0512adebd3782157f0d5c9b22b043f87b4aaff9e");
	cl_git_pass(git3_revwalk_next(&oids[i++], w));
	cl_assert_equal_s(git3_oid_tostr_s(&oids[i - 1]), "f503807ffa920e407a600cfaee96b7152259acc7");
	cl_git_pass(git3_revwalk_next(&oids[i++], w));
	cl_assert_equal_s(git3_oid_tostr_s(&oids[i - 1]), "2f3053cbff8a4ca2f0666de364ddb734a28a31a9");

	cl_git_fail_with(GIT3_ITEROVER, git3_revwalk_next(&oids[i++], w));

	git3_revwalk_free(w);
}
