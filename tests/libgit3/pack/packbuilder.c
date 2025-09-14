#include "clar_libgit3.h"
#include "futils.h"
#include "pack.h"
#include "hash.h"
#include "iterator.h"
#include "vector.h"
#include "posix.h"
#include "hash.h"

static git3_repository *_repo;
static git3_revwalk *_revwalker;
static git3_packbuilder *_packbuilder;
static git3_indexer *_indexer;
static git3_vector _commits;
static int _commits_is_initialized;
static git3_indexer_progress _stats;

extern bool git3_disable_pack_keep_file_checks;

void test_pack_packbuilder__initialize(void)
{
	_repo = cl_git_sandbox_init("testrepo.git");
	cl_git_pass(p_chdir("testrepo.git"));
	cl_git_pass(git3_revwalk_new(&_revwalker, _repo));
	cl_git_pass(git3_packbuilder_new(&_packbuilder, _repo));
	cl_git_pass(git3_vector_init(&_commits, 0, NULL));
	_commits_is_initialized = 1;
	memset(&_stats, 0, sizeof(_stats));
	p_fsync__cnt = 0;
}

void test_pack_packbuilder__cleanup(void)
{
	git3_oid *o;
	unsigned int i;

	cl_git_pass(git3_libgit3_opts(GIT3_OPT_ENABLE_FSYNC_GITDIR, 0));
	cl_git_pass(git3_libgit3_opts(GIT3_OPT_DISABLE_PACK_KEEP_FILE_CHECKS, false));

	if (_commits_is_initialized) {
		_commits_is_initialized = 0;
		git3_vector_foreach(&_commits, i, o) {
			git3__free(o);
		}
		git3_vector_dispose(&_commits);
	}

	git3_packbuilder_free(_packbuilder);
	_packbuilder = NULL;

	git3_revwalk_free(_revwalker);
	_revwalker = NULL;

	git3_indexer_free(_indexer);
	_indexer = NULL;

	cl_git_pass(p_chdir(".."));
	cl_git_sandbox_cleanup();
	_repo = NULL;
}

static void seed_packbuilder(void)
{
	git3_oid oid, *o;
	unsigned int i;

	git3_revwalk_sorting(_revwalker, GIT3_SORT_TIME);
	cl_git_pass(git3_revwalk_push_ref(_revwalker, "HEAD"));

	while (git3_revwalk_next(&oid, _revwalker) == 0) {
		o = git3__malloc(sizeof(git3_oid));
		cl_assert(o != NULL);
		git3_oid_cpy(o, &oid);
		cl_git_pass(git3_vector_insert(&_commits, o));
	}

	git3_vector_foreach(&_commits, i, o) {
		cl_git_pass(git3_packbuilder_insert(_packbuilder, o, NULL));
	}

	git3_vector_foreach(&_commits, i, o) {
		git3_object *obj;
		cl_git_pass(git3_object_lookup(&obj, _repo, o, GIT3_OBJECT_COMMIT));
		cl_git_pass(git3_packbuilder_insert_tree(_packbuilder,
					git3_commit_tree_id((git3_commit *)obj)));
		git3_object_free(obj);
	}
}

static int feed_indexer(void *ptr, size_t len, void *payload)
{
	git3_indexer_progress *stats = (git3_indexer_progress *)payload;

	return git3_indexer_append(_indexer, ptr, len, stats);
}

void test_pack_packbuilder__create_pack(void)
{
	git3_indexer_progress stats;
	git3_str buf = GIT3_STR_INIT, path = GIT3_STR_INIT;

	seed_packbuilder();

#ifdef GIT3_EXPERIMENTAL_SHA256
	cl_git_pass(git3_indexer_new(&_indexer, ".", NULL));
#else
	cl_git_pass(git3_indexer_new(&_indexer, ".", 0, NULL, NULL));
#endif

	cl_git_pass(git3_packbuilder_foreach(_packbuilder, feed_indexer, &stats));
	cl_git_pass(git3_indexer_commit(_indexer, &stats));

	git3_str_printf(&path, "pack-%s.pack", git3_indexer_name(_indexer));
	cl_assert(git3_fs_path_exists(path.ptr));

	cl_git_pass(git3_futils_readbuffer(&buf, git3_str_cstr(&path)));
	cl_assert(buf.size > 256);

	git3_str_dispose(&path);
	git3_str_dispose(&buf);
}

void test_pack_packbuilder__get_name(void)
{
	seed_packbuilder();

	cl_git_pass(git3_packbuilder_write(_packbuilder, ".", 0, NULL, NULL));
	cl_assert(git3_packbuilder_name(_packbuilder) != NULL);
}

static void get_packfile_path(git3_str *out, git3_packbuilder *pb)
{
	git3_str_puts(out, "pack-");
	git3_str_puts(out, git3_packbuilder_name(pb));
	git3_str_puts(out, ".pack");
}

static void get_index_path(git3_str *out, git3_packbuilder *pb)
{
	git3_str_puts(out, "pack-");
	git3_str_puts(out, git3_packbuilder_name(pb));
	git3_str_puts(out, ".idx");
}

void test_pack_packbuilder__write_default_path(void)
{
	git3_str idx = GIT3_STR_INIT, pack = GIT3_STR_INIT;

	seed_packbuilder();

	cl_git_pass(git3_packbuilder_write(_packbuilder, NULL, 0, NULL, NULL));

	git3_str_puts(&idx, "objects/pack/");
	get_index_path(&idx, _packbuilder);

	git3_str_puts(&pack, "objects/pack/");
	get_packfile_path(&pack, _packbuilder);

	cl_assert(git3_fs_path_exists(idx.ptr));
	cl_assert(git3_fs_path_exists(pack.ptr));

	git3_str_dispose(&idx);
	git3_str_dispose(&pack);
}

static void test_write_pack_permission(mode_t given, mode_t expected)
{
	struct stat statbuf;
	mode_t mask, os_mask;
	git3_str idx = GIT3_STR_INIT, pack = GIT3_STR_INIT;

	seed_packbuilder();

	cl_git_pass(git3_packbuilder_write(_packbuilder, ".", given, NULL, NULL));

	/* Windows does not return group/user bits from stat,
	* files are never executable.
	*/
#ifdef GIT3_WIN32
	os_mask = 0600;
#else
	os_mask = 0777;
#endif

	mask = p_umask(0);
	p_umask(mask);

	get_index_path(&idx, _packbuilder);
	get_packfile_path(&pack, _packbuilder);

	cl_git_pass(p_stat(idx.ptr, &statbuf));
	cl_assert_equal_i(statbuf.st_mode & os_mask, (expected & ~mask) & os_mask);

	cl_git_pass(p_stat(pack.ptr, &statbuf));
	cl_assert_equal_i(statbuf.st_mode & os_mask, (expected & ~mask) & os_mask);

	git3_str_dispose(&idx);
	git3_str_dispose(&pack);
}

void test_pack_packbuilder__permissions_standard(void)
{
	test_write_pack_permission(0, GIT3_PACK_FILE_MODE);
}

void test_pack_packbuilder__permissions_readonly(void)
{
	test_write_pack_permission(0444, 0444);
}

void test_pack_packbuilder__permissions_readwrite(void)
{
	test_write_pack_permission(0666, 0666);
}

void test_pack_packbuilder__does_not_fsync_by_default(void)
{
	seed_packbuilder();
	cl_git_pass(git3_packbuilder_write(_packbuilder, ".", 0666, NULL, NULL));
	cl_assert_equal_sz(0, p_fsync__cnt);
}

/* We fsync the packfile and index.  On non-Windows, we also fsync
 * the parent directories.
 */
#ifdef GIT3_WIN32
static int expected_fsyncs = 2;
#else
static int expected_fsyncs = 4;
#endif

void test_pack_packbuilder__fsync_global_setting(void)
{
	cl_git_pass(git3_libgit3_opts(GIT3_OPT_ENABLE_FSYNC_GITDIR, 1));
	p_fsync__cnt = 0;
	seed_packbuilder();
	cl_git_pass(git3_packbuilder_write(_packbuilder, ".", 0666, NULL, NULL));
	cl_assert_equal_sz(expected_fsyncs, p_fsync__cnt);
}

void test_pack_packbuilder__fsync_repo_setting(void)
{
	cl_repo_set_bool(_repo, "core.fsyncObjectFiles", true);
	p_fsync__cnt = 0;
	seed_packbuilder();
	cl_git_pass(git3_packbuilder_write(_packbuilder, ".", 0666, NULL, NULL));
	cl_assert_equal_sz(expected_fsyncs, p_fsync__cnt);
}

static int foreach_cb(void *buf, size_t len, void *payload)
{
	git3_indexer *idx = (git3_indexer *) payload;
	cl_git_pass(git3_indexer_append(idx, buf, len, &_stats));
	return 0;
}

void test_pack_packbuilder__foreach(void)
{
	git3_indexer *idx;

	seed_packbuilder();

#ifdef GIT3_EXPERIMENTAL_SHA256
	cl_git_pass(git3_indexer_new(&idx, ".", NULL));
#else
	cl_git_pass(git3_indexer_new(&idx, ".", 0, NULL, NULL));
#endif

	cl_git_pass(git3_packbuilder_foreach(_packbuilder, foreach_cb, idx));
	cl_git_pass(git3_indexer_commit(idx, &_stats));
	git3_indexer_free(idx);
}

static int foreach_cancel_cb(void *buf, size_t len, void *payload)
{
	git3_indexer *idx = (git3_indexer *)payload;
	cl_git_pass(git3_indexer_append(idx, buf, len, &_stats));
	return (_stats.total_objects > 2) ? -1111 : 0;
}

void test_pack_packbuilder__foreach_with_cancel(void)
{
	git3_indexer *idx;

	seed_packbuilder();

#ifdef GIT3_EXPERIMENTAL_SHA256
	cl_git_pass(git3_indexer_new(&idx, ".", NULL));
#else
	cl_git_pass(git3_indexer_new(&idx, ".", 0, NULL, NULL));
#endif

	cl_git_fail_with(
		git3_packbuilder_foreach(_packbuilder, foreach_cancel_cb, idx), -1111);
	git3_indexer_free(idx);
}

void test_pack_packbuilder__keep_file_check(void)
{
	assert(!git3_disable_pack_keep_file_checks);
	cl_git_pass(git3_libgit3_opts(GIT3_OPT_DISABLE_PACK_KEEP_FILE_CHECKS, true));
	assert(git3_disable_pack_keep_file_checks);
}
