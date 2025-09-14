#include "clar_libgit3.h"
#include "repository.h"

static git3_repository *g_repo;
static size_t cache_limit;
static int object_type;

void test_object_cache__initialize_cache_no_blobs(void)
{
	g_repo = NULL;
	object_type = GIT3_OBJECT_BLOB;
	cache_limit = 0;
}

void test_object_cache__initialize_cache_tiny_blobs(void)
{
	g_repo = NULL;
	object_type = GIT3_OBJECT_BLOB;
	cache_limit = 10;
}

void test_object_cache__initialize_cache_all_blobs(void)
{
	g_repo = NULL;
	object_type = GIT3_OBJECT_BLOB;
	cache_limit = 32767;
}

void test_object_cache__initialize_cache_no_trees(void)
{
	g_repo = NULL;
	object_type = GIT3_OBJECT_TREE;
	cache_limit = 0;
}

void test_object_cache__cleanup(void)
{
	git3_repository_free(g_repo);
	g_repo = NULL;

	git3_libgit3_opts(GIT3_OPT_SET_CACHE_OBJECT_LIMIT, (int)GIT3_OBJECT_BLOB, (size_t)0);
	git3_libgit3_opts(GIT3_OPT_SET_CACHE_OBJECT_LIMIT, (int)GIT3_OBJECT_TREE, (size_t)4096);
	git3_libgit3_opts(GIT3_OPT_SET_CACHE_OBJECT_LIMIT, (int)GIT3_OBJECT_COMMIT, (size_t)4096);
}

static struct {
	git3_object_t type;
	const char *sha;
	size_t size;
} g_data[] = {
	/* HEAD */
	{ GIT3_OBJECT_BLOB, "a8233120f6ad708f843d861ce2b7228ec4e3dec6", 10 }, /* README */
	{ GIT3_OBJECT_BLOB, "3697d64be941a53d4ae8f6a271e4e3fa56b022cc",  8 }, /* branch_file.txt */
	{ GIT3_OBJECT_BLOB, "a71586c1dfe8a71c6cbf6c129f404c5642ff31bd", 12 }, /* new.txt */

	/* refs/heads/subtrees */
	{ GIT3_OBJECT_BLOB, "1385f264afb75a56a5bec74243be9b367ba4ca08",  4 }, /* README */
	{ GIT3_OBJECT_TREE, "f1425cef211cc08caa31e7b545ffb232acb098c3", 90 }, /* ab */
	{ GIT3_OBJECT_BLOB, "d6c93164c249c8000205dd4ec5cbca1b516d487f",  6 }, /* ab/4.txt */
	{ GIT3_OBJECT_TREE, "9a03079b8a8ee85a0bee58bf9be3da8b62414ed4", 33 }, /* ab/c */
	{ GIT3_OBJECT_BLOB, "270b8ea76056d5cad83af921837702d3e3c2924d",  6 }, /* ab/c/3.txt */
	{ GIT3_OBJECT_TREE, "b6361fc6a97178d8fc8639fdeed71c775ab52593", 63 }, /* ab/de */
	{ GIT3_OBJECT_BLOB, "e7b4ad382349ff96dd8199000580b9b1e2042eb0",  6 }, /* ab/de/2.txt */
	{ GIT3_OBJECT_TREE, "3259a6bd5b57fb9c1281bb7ed3167b50f224cb54", 33 }, /* ab/de/fgh */
	{ GIT3_OBJECT_BLOB, "1f67fc4386b2d171e0d21be1c447e12660561f9b",  6 }, /* ab/de/fgh/1.txt */
	{ GIT3_OBJECT_BLOB, "45b983be36b73c0788dc9cbcb76cbb80fc7bb057",  3 }, /* branch_file.txt */
	{ GIT3_OBJECT_BLOB, "fa49b077972391ad58037050f2a75f74e3671e92",  9 }, /* new.txt */

	/* refs/heads/chomped */
	{ GIT3_OBJECT_BLOB, "0266163a49e280c4f5ed1e08facd36a2bd716bcf", 51 }, /* readme.txt */

	{ 0, NULL, 0 },
	{ 0, NULL, 0 }
};

void test_object_cache__cache_counts(void)
{
	int i, start, nonmatching = 0;
	git3_oid oid;
	git3_odb_object *odb_obj;
	git3_object *obj;
	git3_odb *odb;

	git3_libgit3_opts(GIT3_OPT_SET_CACHE_OBJECT_LIMIT, object_type, cache_limit);

	cl_git_pass(git3_repository_open(&g_repo, cl_fixture("testrepo.git")));
	cl_git_pass(git3_repository_odb(&odb, g_repo));

	start = (int)git3_cache_size(&g_repo->objects);

	for (i = 0; g_data[i].sha != NULL; ++i) {
		int count = (int)git3_cache_size(&g_repo->objects);

		cl_git_pass(git3_oid_from_string(&oid, g_data[i].sha, GIT3_OID_SHA1));

		/* alternate between loading raw and parsed objects */
		if ((i & 1) == 0) {
			cl_git_pass(git3_odb_read(&odb_obj, odb, &oid));
			cl_assert(g_data[i].type == git3_odb_object_type(odb_obj));
			git3_odb_object_free(odb_obj);
		} else {
			cl_git_pass(git3_object_lookup(&obj, g_repo, &oid, GIT3_OBJECT_ANY));
			cl_assert(g_data[i].type == git3_object_type(obj));
			git3_object_free(obj);
		}

		if ((g_data[i].type == object_type && g_data[i].size >= cache_limit) ||
		    (g_data[i].type != object_type && g_data[i].type == GIT3_OBJECT_BLOB))
			cl_assert_equal_i(count, (int)git3_cache_size(&g_repo->objects));
		else {
			cl_assert_equal_i(count + 1, (int)git3_cache_size(&g_repo->objects));
			nonmatching++;
		}
	}

	cl_assert_equal_i(nonmatching, (int)git3_cache_size(&g_repo->objects) - start);

	for (i = 0; g_data[i].sha != NULL; ++i) {
		int count = (int)git3_cache_size(&g_repo->objects);

		cl_git_pass(git3_oid_from_string(&oid, g_data[i].sha, GIT3_OID_SHA1));
		cl_git_pass(git3_object_lookup(&obj, g_repo, &oid, GIT3_OBJECT_ANY));
		cl_assert(g_data[i].type == git3_object_type(obj));
		git3_object_free(obj);

		cl_assert_equal_i(count, (int)git3_cache_size(&g_repo->objects));
	}

	git3_odb_free(odb);
}

static void *cache_parsed(void *arg)
{
	int i;
	git3_oid oid;
	git3_object *obj;

	for (i = ((int *)arg)[1]; g_data[i].sha != NULL; i += 2) {
		cl_git_pass(git3_oid_from_string(&oid, g_data[i].sha, GIT3_OID_SHA1));
		cl_git_pass(git3_object_lookup(&obj, g_repo, &oid, GIT3_OBJECT_ANY));
		cl_assert(g_data[i].type == git3_object_type(obj));
		git3_object_free(obj);
	}

	for (i = 0; i < ((int *)arg)[1]; i += 2) {
		cl_git_pass(git3_oid_from_string(&oid, g_data[i].sha, GIT3_OID_SHA1));
		cl_git_pass(git3_object_lookup(&obj, g_repo, &oid, GIT3_OBJECT_ANY));
		cl_assert(g_data[i].type == git3_object_type(obj));
		git3_object_free(obj);
	}

	return arg;
}

static void *cache_raw(void *arg)
{
	int i;
	git3_oid oid;
	git3_odb *odb;
	git3_odb_object *odb_obj;

	cl_git_pass(git3_repository_odb(&odb, g_repo));

	for (i = ((int *)arg)[1]; g_data[i].sha != NULL; i += 2) {
		cl_git_pass(git3_oid_from_string(&oid, g_data[i].sha, GIT3_OID_SHA1));
		cl_git_pass(git3_odb_read(&odb_obj, odb, &oid));
		cl_assert(g_data[i].type == git3_odb_object_type(odb_obj));
		git3_odb_object_free(odb_obj);
	}

	for (i = 0; i < ((int *)arg)[1]; i += 2) {
		cl_git_pass(git3_oid_from_string(&oid, g_data[i].sha, GIT3_OID_SHA1));
		cl_git_pass(git3_odb_read(&odb_obj, odb, &oid));
		cl_assert(g_data[i].type == git3_odb_object_type(odb_obj));
		git3_odb_object_free(odb_obj);
	}

	git3_odb_free(odb);

	return arg;
}

#define REPEAT 20
#define THREADCOUNT 50

void test_object_cache__threadmania(void)
{
	int try, th, max_i;
	void *data;
	void *(*fn)(void *);

#ifdef GIT3_THREADS
	git3_thread t[THREADCOUNT];
#endif

	for (max_i = 0; g_data[max_i].sha != NULL; ++max_i)
		/* count up */;

	for (try = 0; try < REPEAT; ++try) {

		cl_git_pass(git3_repository_open(&g_repo, cl_fixture("testrepo.git")));

		for (th = 0; th < THREADCOUNT; ++th) {
			data = git3__malloc(2 * sizeof(int));

			((int *)data)[0] = th;
			((int *)data)[1] = th % max_i;

			fn = (th & 1) ? cache_parsed : cache_raw;

#ifdef GIT3_THREADS
			cl_git_pass(git3_thread_create(&t[th], fn, data));
#else
			cl_assert(fn(data) == data);
			git3__free(data);
#endif
		}

#ifdef GIT3_THREADS
		for (th = 0; th < THREADCOUNT; ++th) {
			cl_git_pass(git3_thread_join(&t[th], &data));
			cl_assert_equal_i(th, ((int *)data)[0]);
			git3__free(data);
		}
#endif

		git3_repository_free(g_repo);
		g_repo = NULL;
	}
}

static void *cache_quick(void *arg)
{
	git3_oid oid;
	git3_object *obj;

	cl_git_pass(git3_oid_from_string(&oid, g_data[4].sha, GIT3_OID_SHA1));
	cl_git_pass(git3_object_lookup(&obj, g_repo, &oid, GIT3_OBJECT_ANY));
	cl_assert(g_data[4].type == git3_object_type(obj));
	git3_object_free(obj);

	return arg;
}

void test_object_cache__fast_thread_rush(void)
{
	int try, th, data[THREADCOUNT];
#ifdef GIT3_THREADS
	git3_thread t[THREADCOUNT];
#endif

	for (try = 0; try < REPEAT; ++try) {
		cl_git_pass(git3_repository_open(&g_repo, cl_fixture("testrepo.git")));

		for (th = 0; th < THREADCOUNT; ++th) {
			data[th] = th;
#ifdef GIT3_THREADS
			cl_git_pass(
				git3_thread_create(&t[th], cache_quick, &data[th]));
#else
			cl_assert(cache_quick(&data[th]) == &data[th]);
#endif
		}

#ifdef GIT3_THREADS
		for (th = 0; th < THREADCOUNT; ++th) {
			void *rval;
			cl_git_pass(git3_thread_join(&t[th], &rval));
			cl_assert_equal_i(th, *((int *)rval));
		}
#endif

		git3_repository_free(g_repo);
		g_repo = NULL;
	}
}
