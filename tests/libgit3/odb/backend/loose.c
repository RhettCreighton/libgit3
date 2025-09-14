#include "clar_libgit3.h"
#include "repository.h"
#include "odb.h"
#include "backend_helpers.h"
#include "git3/sys/mempack.h"

static git3_repository *_repo;
static git3_odb *_odb;

void test_odb_backend_loose__initialize(void)
{
	git3_odb_backend *backend;

	cl_fixture_sandbox("testrepo.git");

#ifdef GIT3_EXPERIMENTAL_SHA256
	cl_git_pass(git3_odb_backend_loose(&backend, "testrepo.git/objects", NULL));
#else
	cl_git_pass(git3_odb_backend_loose(&backend, "testrepo.git/objects", 0, 0, 0, 0));
#endif

	cl_git_pass(git3_odb_new(&_odb));
	cl_git_pass(git3_odb_add_backend(_odb, backend, 10));
	cl_git_pass(git3_repository_wrap_odb(&_repo, _odb));
}

void test_odb_backend_loose__cleanup(void)
{
	git3_odb_free(_odb);
	git3_repository_free(_repo);

	cl_fixture_cleanup("testrepo.git");
}

void test_odb_backend_loose__read_from_odb(void)
{
	git3_oid oid;
	git3_odb_object *obj;

	cl_git_pass(git3_oid_from_string(&oid, "1385f264afb75a56a5bec74243be9b367ba4ca08", GIT3_OID_SHA1));
	cl_git_pass(git3_odb_read(&obj, _odb, &oid));
	git3_odb_object_free(obj);

	cl_git_pass(git3_oid_from_string(&oid, "fd093bff70906175335656e6ce6ae05783708765", GIT3_OID_SHA1));
	cl_git_pass(git3_odb_read(&obj, _odb, &oid));
	git3_odb_object_free(obj);
}

void test_odb_backend_loose__read_from_repo(void)
{
	git3_oid oid;
	git3_blob *blob;
	git3_tree *tree;

	cl_git_pass(git3_oid_from_string(&oid, "1385f264afb75a56a5bec74243be9b367ba4ca08", GIT3_OID_SHA1));
	cl_git_pass(git3_blob_lookup(&blob, _repo, &oid));
	git3_blob_free(blob);

	cl_git_pass(git3_oid_from_string(&oid, "fd093bff70906175335656e6ce6ae05783708765", GIT3_OID_SHA1));
	cl_git_pass(git3_tree_lookup(&tree, _repo, &oid));
	git3_tree_free(tree);
}
