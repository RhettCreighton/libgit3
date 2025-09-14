#include "clar_libgit3.h"
#include "git3/sys/odb_backend.h"
#include "odb.h"

typedef struct {
	git3_odb_backend base;
	size_t position;
} fake_backend;

static void odb_backend_free(git3_odb_backend *odb)
{
	git3__free(odb);
}

static git3_odb_backend *new_backend(size_t position)
{
	fake_backend *b;

	b = git3__calloc(1, sizeof(fake_backend));
	if (b == NULL)
		return NULL;

	b->base.free = odb_backend_free;
	b->base.version = GIT3_ODB_BACKEND_VERSION;
	b->position = position;
	return (git3_odb_backend *)b;
}

static void check_backend_sorting(git3_odb *odb)
{
	size_t i, max_i = git3_odb_num_backends(odb);
	fake_backend *internal;

	for (i = 0; i < max_i; ++i) {
		cl_git_pass(git3_odb_get_backend((git3_odb_backend **)&internal, odb, i));
		cl_assert(internal != NULL);
		cl_assert_equal_sz(i, internal->position);
	}
}

static git3_odb *_odb;

void test_odb_sorting__initialize(void)
{
	cl_git_pass(git3_odb_new(&_odb));
}

void test_odb_sorting__cleanup(void)
{
	git3_odb_free(_odb);
	_odb = NULL;

	cl_git_pass(git3_libgit3_opts(GIT3_OPT_SET_ODB_LOOSE_PRIORITY,
	                             GIT3_ODB_DEFAULT_LOOSE_PRIORITY));
	cl_git_pass(git3_libgit3_opts(GIT3_OPT_SET_ODB_PACKED_PRIORITY,
	                             GIT3_ODB_DEFAULT_PACKED_PRIORITY));
}

void test_odb_sorting__basic_backends_sorting(void)
{
	cl_git_pass(git3_odb_add_backend(_odb, new_backend(0), 5));
	cl_git_pass(git3_odb_add_backend(_odb, new_backend(2), 3));
	cl_git_pass(git3_odb_add_backend(_odb, new_backend(1), 4));
	cl_git_pass(git3_odb_add_backend(_odb, new_backend(3), 1));

	check_backend_sorting(_odb);
}

void test_odb_sorting__alternate_backends_sorting(void)
{
	cl_git_pass(git3_odb_add_backend(_odb, new_backend(1), 5));
	cl_git_pass(git3_odb_add_backend(_odb, new_backend(5), 3));
	cl_git_pass(git3_odb_add_backend(_odb, new_backend(3), 4));
	cl_git_pass(git3_odb_add_backend(_odb, new_backend(7), 1));
	cl_git_pass(git3_odb_add_alternate(_odb, new_backend(0), 5));
	cl_git_pass(git3_odb_add_alternate(_odb, new_backend(4), 3));
	cl_git_pass(git3_odb_add_alternate(_odb, new_backend(2), 4));
	cl_git_pass(git3_odb_add_alternate(_odb, new_backend(6), 1));

	check_backend_sorting(_odb);
}

void test_odb_sorting__override_default_backend_priority(void)
{
	git3_odb *new_odb;
	git3_odb_backend *loose, *packed, *backend;

	cl_git_pass(git3_libgit3_opts(GIT3_OPT_SET_ODB_LOOSE_PRIORITY, 5));
	cl_git_pass(git3_libgit3_opts(GIT3_OPT_SET_ODB_PACKED_PRIORITY, 3));
	git3_odb_backend_pack(&packed, "./testrepo.git/objects"
#ifdef GIT3_EXPERIMENTAL_SHA256
		, NULL
#endif
	);
	git3_odb__backend_loose(&loose, "./testrepo.git/objects", NULL);

	cl_git_pass(git3_odb_open(&new_odb, cl_fixture("testrepo.git/objects")));
	cl_assert_equal_sz(2, git3_odb_num_backends(new_odb));

	cl_git_pass(git3_odb_get_backend(&backend, new_odb, 0));
	cl_assert_equal_p(loose->read, backend->read);

	cl_git_pass(git3_odb_get_backend(&backend, new_odb, 1));
	cl_assert_equal_p(packed->read, backend->read);

	git3_odb_free(new_odb);
	loose->free(loose);
	packed->free(packed);
}
