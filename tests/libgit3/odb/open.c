#include "clar_libgit3.h"
#include "odb.h"

void test_odb_open__initialize(void)
{
	cl_fixture_sandbox("testrepo.git");
}

void test_odb_open__cleanup(void)
{
	cl_fixture_cleanup("testrepo.git");
}

void test_odb_open__exists(void)
{
	git3_odb *odb;
	git3_oid one, two;
	git3_odb_options opts = GIT3_ODB_OPTIONS_INIT;

	cl_git_pass(git3_odb_open_ext(&odb, "testrepo.git/objects", &opts));

#ifdef GIT3_EXPERIMENTAL_SHA256
	cl_git_pass(git3_oid_from_string(&one, "1385f264afb75a56a5bec74243be9b367ba4ca08", GIT3_OID_SHA1));
	cl_git_pass(git3_oid_from_string(&two, "00112233445566778899aabbccddeeff00112233", GIT3_OID_SHA1));
#else
	cl_git_pass(git3_oid_fromstr(&one, "1385f264afb75a56a5bec74243be9b367ba4ca08"));
	cl_git_pass(git3_oid_fromstr(&two, "00112233445566778899aabbccddeeff00112233"));
#endif

	cl_assert(git3_odb_exists(odb, &one));
	cl_assert(!git3_odb_exists(odb, &two));

	git3_odb_free(odb);
}
