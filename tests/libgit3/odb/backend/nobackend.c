#include "clar_libgit3.h"
#include "repository.h"
#include "odb.h"
#include "git3/sys/repository.h"

static git3_repository *_repo;

void test_odb_backend_nobackend__initialize(void)
{
	git3_config *config;
	git3_odb *odb;
	git3_refdb *refdb;

	git3_repository_new_options repo_opts = GIT3_REPOSITORY_NEW_OPTIONS_INIT;
	git3_odb_options odb_opts = GIT3_ODB_OPTIONS_INIT;

	repo_opts.oid_type = GIT3_OID_SHA1;
	odb_opts.oid_type = GIT3_OID_SHA1;

	cl_git_pass(git3_repository_new_ext(&_repo, &repo_opts));
	cl_git_pass(git3_config_new(&config));
	cl_git_pass(git3_odb_new_ext(&odb, &odb_opts));
	cl_git_pass(git3_refdb_new(&refdb, _repo));

	git3_repository_set_config(_repo, config);
	git3_repository_set_odb(_repo, odb);
	git3_repository_set_refdb(_repo, refdb);

	/* The set increases the refcount and we don't want them anymore */
	git3_config_free(config);
	git3_odb_free(odb);
	git3_refdb_free(refdb);
}

void test_odb_backend_nobackend__cleanup(void)
{
	git3_repository_free(_repo);
}

void test_odb_backend_nobackend__write_fails_gracefully(void)
{
	git3_oid id;
	git3_odb *odb;
	const git3_error *err;

	git3_repository_odb(&odb, _repo);
	cl_git_fail(git3_odb_write(&id, odb, "Hello world!\n", 13, GIT3_OBJECT_BLOB));

	err = git3_error_last();
	cl_assert_equal_s(err->message, "cannot write object - unsupported in the loaded odb backends");

	git3_odb_free(odb);
}
