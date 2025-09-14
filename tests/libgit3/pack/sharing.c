#include "clar_libgit3.h"
#include <git3.h>
#include "mwindow.h"
#include "pack.h"
#include "hashmap.h"

extern git3_mwindow_packmap git3_mwindow__pack_cache;

void test_pack_sharing__open_two_repos(void)
{
	git3_repository *repo1, *repo2;
	git3_object *obj1, *obj2;
	git3_oid id;
	struct git3_pack_file *pack;
	git3_hashmap_iter_t iter = GIT3_HASHMAP_ITER_INIT;

	cl_git_pass(git3_repository_open(&repo1, cl_fixture("testrepo.git")));
	cl_git_pass(git3_repository_open(&repo2, cl_fixture("testrepo.git")));

	git3_oid_from_string(&id, "a65fedf39aefe402d3bb6e24df4d4f5fe4547750", GIT3_OID_SHA1);

	cl_git_pass(git3_object_lookup(&obj1, repo1, &id, GIT3_OBJECT_ANY));
	cl_git_pass(git3_object_lookup(&obj2, repo2, &id, GIT3_OBJECT_ANY));

	while (git3_mwindow_packmap_iterate(&iter, NULL, &pack, &git3_mwindow__pack_cache) == 0)
		cl_assert_equal_i(2, pack->refcount.val);

	cl_assert_equal_i(3, git3_mwindow_packmap_size(&git3_mwindow__pack_cache));

	git3_object_free(obj1);
	git3_object_free(obj2);
	git3_repository_free(repo1);
	git3_repository_free(repo2);

	/* we don't want to keep the packs open after the repos go away */
	cl_assert_equal_i(0, git3_mwindow_packmap_size(&git3_mwindow__pack_cache));
}
