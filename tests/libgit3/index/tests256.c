#include "clar_libgit3.h"
#include "index.h"

#ifdef GIT3_EXPERIMENTAL_SHA256

static const size_t index_entry_count = 4344;
#define TEST_INDEX_PATH cl_fixture("git-sha256.index")

static git3_repository_init_options repo_init_opts =
	GIT3_REPOSITORY_INIT_OPTIONS_INIT;

/* Suite data */
struct test_entry {
   size_t index;
   char path[128];
   off64_t file_size;
   git3_time_t mtime;
};

static struct test_entry test_entries[] = {
   { 892,  "Makefile",    120084, 0x642c3a6e },
   { 1542, "git.c",        27432, 0x642c3a6e },
   { 1737, "perl/Git.pm",  48084, 0x642c3a6e },
   { 1961, "t/Makefile",    4711, 0x642c3a6e },
   { 4343, "zlib.c",        6271, 0x642c3a6f }
};

/* Helpers */
static void copy_file(const char *src, const char *dst)
{
	git3_str source_buf = GIT3_STR_INIT;
	git3_file dst_fd;

	cl_git_pass(git3_futils_readbuffer(&source_buf, src));

	dst_fd = git3_futils_creat_withpath(dst, 0777, 0666); /* -V536 */
	if (dst_fd < 0)
		goto cleanup;

	cl_git_pass(p_write(dst_fd, source_buf.ptr, source_buf.size));

cleanup:
	git3_str_dispose(&source_buf);
	p_close(dst_fd);
}

static void files_are_equal(const char *a, const char *b)
{
	git3_str buf_a = GIT3_STR_INIT;
	git3_str buf_b = GIT3_STR_INIT;

	if (git3_futils_readbuffer(&buf_a, a) < 0)
		cl_assert(0);

	if (git3_futils_readbuffer(&buf_b, b) < 0) {
		git3_str_dispose(&buf_a);
		cl_assert(0);
	}

	cl_assert_equal_sz(buf_a.size, buf_b.size);
	cl_assert(!memcmp(buf_a.ptr, buf_b.ptr, buf_a.size));

	git3_str_dispose(&buf_a);
	git3_str_dispose(&buf_b);
}

#endif

/* Fixture setup and teardown */
void test_index_tests256__initialize(void)
{
#ifdef GIT3_EXPERIMENTAL_SHA256
	repo_init_opts.flags |= GIT3_REPOSITORY_INIT_MKPATH;
	repo_init_opts.oid_type = GIT3_OID_SHA256;
#endif
}

void test_index_tests256__cleanup(void)
{
#ifdef GIT3_EXPERIMENTAL_SHA256
	cl_git_pass(git3_libgit3_opts(GIT3_OPT_ENABLE_UNSAVED_INDEX_SAFETY, 0));
#endif
}

void test_index_tests256__empty_index(void)
{
#ifdef GIT3_EXPERIMENTAL_SHA256
   git3_index *index;
   git3_index_options index_opts = GIT3_INDEX_OPTIONS_INIT;

   index_opts.oid_type = GIT3_OID_SHA256;

   cl_git_pass(git3_index_open_ext(&index, "in-memory-index", &index_opts));
   cl_assert(index->on_disk == 0);

   cl_assert(git3_index_entrycount(index) == 0);
   cl_assert(git3_vector_is_sorted(&index->entries));

   git3_index_free(index);
#endif
}

void test_index_tests256__default_test_index(void)
{
#ifdef GIT3_EXPERIMENTAL_SHA256
   git3_index *index;
   unsigned int i;
   git3_index_entry **entries;
   git3_index_options index_opts = GIT3_INDEX_OPTIONS_INIT;

   index_opts.oid_type = GIT3_OID_SHA256;

   cl_git_pass(git3_index_open_ext(&index, TEST_INDEX_PATH, &index_opts));
   cl_assert(index->on_disk);

   cl_assert_equal_sz(git3_index_entrycount(index), index_entry_count);
   cl_assert(git3_vector_is_sorted(&index->entries));

   entries = (git3_index_entry **)index->entries.contents;

   for (i = 0; i < ARRAY_SIZE(test_entries); ++i) {
		git3_index_entry *e = entries[test_entries[i].index];

		cl_assert_equal_s(e->path, test_entries[i].path);
		cl_assert_equal_i(e->mtime.seconds, test_entries[i].mtime);
		cl_assert_equal_i(e->file_size, test_entries[i].file_size);
   }

   git3_index_free(index);
#endif
}

void test_index_tests256__find_in_existing(void)
{
#ifdef GIT3_EXPERIMENTAL_SHA256
   git3_index *index;
   unsigned int i;
   git3_index_options index_opts = GIT3_INDEX_OPTIONS_INIT;

   index_opts.oid_type = GIT3_OID_SHA256;

   cl_git_pass(git3_index_open_ext(&index, TEST_INDEX_PATH, &index_opts));

   for (i = 0; i < ARRAY_SIZE(test_entries); ++i) {
		size_t idx;

		cl_assert(!git3_index_find(&idx, index, test_entries[i].path));
		cl_assert(idx == test_entries[i].index);
   }

   git3_index_free(index);
#endif
}

void test_index_tests256__find_in_empty(void)
{
#ifdef GIT3_EXPERIMENTAL_SHA256
   git3_index *index;
   unsigned int i;
   git3_index_options index_opts = GIT3_INDEX_OPTIONS_INIT;

   index_opts.oid_type = GIT3_OID_SHA256;

   cl_git_pass(git3_index_open_ext(&index, "fake-index", &index_opts));

   for (i = 0; i < ARRAY_SIZE(test_entries); ++i) {
		cl_assert(GIT3_ENOTFOUND == git3_index_find(NULL, index, test_entries[i].path));
   }

   git3_index_free(index);
#endif
}

void test_index_tests256__find_prefix(void)
{
#ifdef GIT3_EXPERIMENTAL_SHA256
   git3_index *index;
   const git3_index_entry *entry;
   size_t pos;
   git3_index_options index_opts = GIT3_INDEX_OPTIONS_INIT;

   index_opts.oid_type = GIT3_OID_SHA256;

   cl_git_pass(git3_index_open_ext(&index, TEST_INDEX_PATH, &index_opts));

   cl_git_pass(git3_index_find_prefix(&pos, index, "Documentation"));
   entry = git3_index_get_byindex(index, pos);
   cl_assert(git3__strcmp(entry->path, "Documentation/.gitattributes") == 0);

   cl_git_pass(git3_index_find_prefix(&pos, index, "contrib/RE"));
   entry = git3_index_get_byindex(index, pos);
   cl_assert(git3__strcmp(entry->path, "contrib/README") == 0);

   cl_assert(GIT3_ENOTFOUND == git3_index_find_prefix(NULL, index, "blah"));

   git3_index_free(index);
#endif
}

void test_index_tests256__write(void)
{
#ifdef GIT3_EXPERIMENTAL_SHA256
   git3_index *index;
   git3_index_options index_opts = GIT3_INDEX_OPTIONS_INIT;

   index_opts.oid_type = GIT3_OID_SHA256;

   copy_file(TEST_INDEX_PATH, "index_rewrite");

   cl_git_pass(git3_index_open_ext(&index, "index_rewrite", &index_opts));
   cl_assert(index->on_disk);

   cl_git_pass(git3_index_write(index));
   files_are_equal(TEST_INDEX_PATH, "index_rewrite");

   git3_index_free(index);

   p_unlink("index_rewrite");
#endif
}

void test_index_tests256__sort1(void)
{
#ifdef GIT3_EXPERIMENTAL_SHA256
   /* sort the entries in an empty index */
   git3_index *index;
   git3_index_options index_opts = GIT3_INDEX_OPTIONS_INIT;

   index_opts.oid_type = GIT3_OID_SHA256;

   cl_git_pass(git3_index_open_ext(&index, "fake-index", &index_opts));

   /* FIXME: this test is slightly dumb */
   cl_assert(git3_vector_is_sorted(&index->entries));

   git3_index_free(index);
#endif
}

#ifdef GIT3_EXPERIMENTAL_SHA256
static void cleanup_myrepo(void *opaque)
{
	GIT3_UNUSED(opaque);
	cl_fixture_cleanup("myrepo");
}
#endif

void test_index_tests256__add(void)
{
#ifdef GIT3_EXPERIMENTAL_SHA256
	git3_index *index;
	git3_filebuf file = GIT3_FILEBUF_INIT;
	git3_repository *repo;
	const git3_index_entry *entry;
	git3_oid id1;

	cl_set_cleanup(&cleanup_myrepo, NULL);

	/* Initialize a new repository */
	cl_git_pass(git3_repository_init_ext(&repo, "./myrepo", &repo_init_opts));

	/* Ensure we're the only guy in the room */
	cl_git_pass(git3_repository_index(&index, repo));
	cl_assert(git3_index_entrycount(index) == 0);

	/* Create a new file in the working directory */
	cl_git_pass(git3_futils_mkpath2file("myrepo/test.txt", 0777));
	cl_git_pass(git3_filebuf_open(&file, "myrepo/test.txt", 0, 0666));
	cl_git_pass(git3_filebuf_write(&file, "hey there\n", 10));
	cl_git_pass(git3_filebuf_commit(&file));

	/* Store the expected hash of the file/blob
	 * This has been generated by executing the following
	 * $ echo "hey there" | git hash-object --stdin
	 */
	cl_git_pass(git3_oid_from_string(&id1, "aea29dc305d40e362df25c3fdeed5502fd56b182af01b7740d297a24459333c5", GIT3_OID_SHA256));

	/* Add the new file to the index */
	cl_git_pass(git3_index_add_bypath(index, "test.txt"));

	/* Wow... it worked! */
	cl_assert(git3_index_entrycount(index) == 1);
	entry = git3_index_get_byindex(index, 0);

	/* And the built-in hashing mechanism worked as expected */
	cl_assert_equal_oid(&id1, &entry->id);

	/* Test access by path instead of index */
	cl_assert((entry = git3_index_get_bypath(index, "test.txt", 0)) != NULL);
	cl_assert_equal_oid(&id1, &entry->id);

	git3_index_free(index);
	git3_repository_free(repo);
#endif
}

void test_index_tests256__add_frombuffer(void)
{
#ifdef GIT3_EXPERIMENTAL_SHA256
	git3_index *index;
	git3_repository *repo;
        git3_index_entry entry;
	const git3_index_entry *returned_entry;

	git3_oid id1;
	git3_blob *blob;

	const char *content = "hey there\n";

	cl_set_cleanup(&cleanup_myrepo, NULL);

	/* Initialize a new repository */
	cl_git_pass(git3_repository_init_ext(&repo, "./myrepo", &repo_init_opts));

	/* Ensure we're the only guy in the room */
	cl_git_pass(git3_repository_index(&index, repo));
	cl_assert(git3_index_entrycount(index) == 0);

	/* Store the expected hash of the file/blob
	 * This has been generated by executing the following
	 * $ echo "hey there" | git hash-object --stdin
	 */
	cl_git_pass(git3_oid_from_string(&id1, "aea29dc305d40e362df25c3fdeed5502fd56b182af01b7740d297a24459333c5", GIT3_OID_SHA256));

	/* Add the new file to the index */
	memset(&entry, 0x0, sizeof(git3_index_entry));
	entry.mode = GIT3_FILEMODE_BLOB;
	entry.path = "test.txt";
	cl_git_pass(git3_index_add_from_buffer(index, &entry,
		content, strlen(content)));

	/* Wow... it worked! */
	cl_assert(git3_index_entrycount(index) == 1);
	returned_entry = git3_index_get_byindex(index, 0);

	/* And the built-in hashing mechanism worked as expected */
	cl_assert_equal_oid(&id1, &returned_entry->id);
	/* And mode is the one asked */
	cl_assert_equal_i(GIT3_FILEMODE_BLOB, returned_entry->mode);

	/* Test access by path instead of index */
	cl_assert((returned_entry = git3_index_get_bypath(index, "test.txt", 0)) != NULL);
	cl_assert_equal_oid(&id1, &returned_entry->id);

	/* Test the blob is in the repository */
	cl_git_pass(git3_blob_lookup(&blob, repo, &id1));
	cl_assert_equal_s(
		content, git3_blob_rawcontent(blob));
	git3_blob_free(blob);

	git3_index_free(index);
	git3_repository_free(repo);
#endif
}

void test_index_tests256__dirty_and_clean(void)
{
#ifdef GIT3_EXPERIMENTAL_SHA256
	git3_repository *repo;
	git3_index *index;
	git3_index_entry entry = {{0}};

	/* Index is not dirty after opening */
	cl_git_pass(git3_repository_init_ext(&repo, "./myrepo", &repo_init_opts));
	cl_git_pass(git3_repository_index(&index, repo));

	cl_assert(git3_index_entrycount(index) == 0);
	cl_assert(!git3_index_is_dirty(index));

	/* Index is dirty after adding an entry */
	entry.mode = GIT3_FILEMODE_BLOB;
	entry.path = "test.txt";
	cl_git_pass(git3_index_add_from_buffer(index, &entry, "Hi.\n", 4));
	cl_assert(git3_index_entrycount(index) == 1);
	cl_assert(git3_index_is_dirty(index));

	/* Index is not dirty after write */
	cl_git_pass(git3_index_write(index));
	cl_assert(!git3_index_is_dirty(index));

	/* Index is dirty after removing an entry */
	cl_git_pass(git3_index_remove_bypath(index, "test.txt"));
	cl_assert(git3_index_entrycount(index) == 0);
	cl_assert(git3_index_is_dirty(index));

	/* Index is not dirty after write */
	cl_git_pass(git3_index_write(index));
	cl_assert(!git3_index_is_dirty(index));

	/* Index remains not dirty after read */
	cl_git_pass(git3_index_read(index, 0));
	cl_assert(!git3_index_is_dirty(index));

	/* Index is dirty when we do an unforced read with dirty content */
	cl_git_pass(git3_index_add_from_buffer(index, &entry, "Hi.\n", 4));
	cl_assert(git3_index_entrycount(index) == 1);
	cl_assert(git3_index_is_dirty(index));

	cl_git_pass(git3_index_read(index, 0));
	cl_assert(git3_index_is_dirty(index));

	/* Index is clean when we force a read with dirty content */
	cl_git_pass(git3_index_read(index, 1));
	cl_assert(!git3_index_is_dirty(index));

	git3_index_free(index);
	git3_repository_free(repo);
#endif
}

void test_index_tests256__dirty_fails_optionally(void)
{
#ifdef GIT3_EXPERIMENTAL_SHA256
	git3_repository *repo;
	git3_index *index;
	git3_index_entry entry = {{0}};

	/* Index is not dirty after opening */
	repo = cl_git_sandbox_init("testrepo");
	cl_git_pass(git3_repository_index(&index, repo));

	/* Index is dirty after adding an entry */
	entry.mode = GIT3_FILEMODE_BLOB;
	entry.path = "test.txt";
	cl_git_pass(git3_index_add_from_buffer(index, &entry, "Hi.\n", 4));
	cl_assert(git3_index_is_dirty(index));

	cl_git_pass(git3_checkout_head(repo, NULL));

	/* Index is dirty (again) after adding an entry */
	entry.mode = GIT3_FILEMODE_BLOB;
	entry.path = "test.txt";
	cl_git_pass(git3_index_add_from_buffer(index, &entry, "Hi.\n", 4));
	cl_assert(git3_index_is_dirty(index));

	cl_git_pass(git3_libgit3_opts(GIT3_OPT_ENABLE_UNSAVED_INDEX_SAFETY, 1));
	cl_git_fail_with(GIT3_EINDEXDIRTY, git3_checkout_head(repo, NULL));

	git3_index_free(index);
	cl_git_sandbox_cleanup();
#endif
}

void test_index_tests256__add_frombuffer_reset_entry(void)
{
#ifdef GIT3_EXPERIMENTAL_SHA256
	git3_index *index;
	git3_repository *repo;
        git3_index_entry entry;
	const git3_index_entry *returned_entry;
	git3_filebuf file = GIT3_FILEBUF_INIT;

	git3_oid id1;
	git3_blob *blob;
	const char *old_content = "here\n";
	const char *content = "hey there\n";

	cl_set_cleanup(&cleanup_myrepo, NULL);

	/* Initialize a new repository */
	cl_git_pass(git3_repository_init_ext(&repo, "./myrepo", &repo_init_opts));
	cl_git_pass(git3_repository_index(&index, repo));
	cl_git_pass(git3_futils_mkpath2file("myrepo/test.txt", 0777));
	cl_git_pass(git3_filebuf_open(&file, "myrepo/test.txt", 0, 0666));
	cl_git_pass(git3_filebuf_write(&file, old_content, strlen(old_content)));
	cl_git_pass(git3_filebuf_commit(&file));

	/* Store the expected hash of the file/blob
	 * This has been generated by executing the following
	 * $ echo "hey there" | git hash-object --stdin
	 */
	cl_git_pass(git3_oid_from_string(&id1, "aea29dc305d40e362df25c3fdeed5502fd56b182af01b7740d297a24459333c5", GIT3_OID_SHA256));

	cl_git_pass(git3_index_add_bypath(index, "test.txt"));

	/* Add the new file to the index */
	memset(&entry, 0x0, sizeof(git3_index_entry));
	entry.mode = GIT3_FILEMODE_BLOB;
	entry.path = "test.txt";
	cl_git_pass(git3_index_add_from_buffer(index, &entry,
		content, strlen(content)));

	/* Wow... it worked! */
	cl_assert(git3_index_entrycount(index) == 1);
	returned_entry = git3_index_get_byindex(index, 0);

	/* And the built-in hashing mechanism worked as expected */
	cl_assert_equal_oid(&id1, &returned_entry->id);
	/* And mode is the one asked */
	cl_assert_equal_i(GIT3_FILEMODE_BLOB, returned_entry->mode);

	/* Test access by path instead of index */
	cl_assert((returned_entry = git3_index_get_bypath(index, "test.txt", 0)) != NULL);
	cl_assert_equal_oid(&id1, &returned_entry->id);
	cl_assert_equal_i(0, returned_entry->dev);
	cl_assert_equal_i(0, returned_entry->ino);
	cl_assert_equal_i(0, returned_entry->uid);
	cl_assert_equal_i(0, returned_entry->uid);
	cl_assert_equal_i(10, returned_entry->file_size);

            /* Test the blob is in the repository */
	cl_git_pass(git3_blob_lookup(&blob, repo, &id1));
	cl_assert_equal_s(content, git3_blob_rawcontent(blob));
	git3_blob_free(blob);

	git3_index_free(index);
	git3_repository_free(repo);
#endif
}

void test_index_tests256__add_bypath_to_a_bare_repository_returns_EBAREPO(void)
{
#ifdef GIT3_EXPERIMENTAL_SHA256
	git3_repository *bare_repo;
	git3_index *index;

	cl_git_pass(git3_repository_open(&bare_repo, cl_fixture("testrepo.git")));
	cl_git_pass(git3_repository_index(&index, bare_repo));

	cl_assert_equal_i(GIT3_EBAREREPO, git3_index_add_bypath(index, "test.txt"));

	git3_index_free(index);
	git3_repository_free(bare_repo);
#endif
}

#ifdef GIT3_EXPERIMENTAL_SHA256
static void assert_add_bypath_fails(git3_repository *repo, const char *fn)
{
	git3_index *index;
	git3_str path = GIT3_STR_INIT;

	cl_git_pass(git3_repository_index(&index, repo));
	cl_assert(git3_index_entrycount(index) == 0);

	git3_str_joinpath(&path, "./invalid", fn);

	cl_git_mkfile(path.ptr, NULL);
	cl_git_fail(git3_index_add_bypath(index, fn));
	cl_must_pass(p_unlink(path.ptr));

	cl_assert(git3_index_entrycount(index) == 0);

	git3_str_dispose(&path);
	git3_index_free(index);
}
#endif

/* Test that writing an invalid filename fails */
void test_index_tests256__cannot_add_invalid_filename(void)
{
#ifdef GIT3_EXPERIMENTAL_SHA256
	git3_repository *repo;

	cl_must_pass(p_mkdir("invalid", 0700));
	cl_git_pass(git3_repository_init_ext(&repo, "./invalid", &repo_init_opts));
	cl_must_pass(p_mkdir("./invalid/subdir", 0777));

	/* cl_git_mkfile() needs the dir to exist */
	if (!git3_fs_path_exists("./invalid/.GIT"))
		cl_must_pass(p_mkdir("./invalid/.GIT", 0777));
	if (!git3_fs_path_exists("./invalid/.GiT"))
		cl_must_pass(p_mkdir("./invalid/.GiT", 0777));

	assert_add_bypath_fails(repo, ".git/hello");
	assert_add_bypath_fails(repo, ".GIT/hello");
	assert_add_bypath_fails(repo, ".GiT/hello");
	assert_add_bypath_fails(repo, "./.git/hello");
	assert_add_bypath_fails(repo, "./foo");
	assert_add_bypath_fails(repo, "./bar");
	assert_add_bypath_fails(repo, "subdir/../bar");

	git3_repository_free(repo);

	cl_fixture_cleanup("invalid");
#endif
}

#ifdef GIT3_EXPERIMENTAL_SHA256
static void assert_add_fails(git3_repository *repo, const char *fn)
{
	git3_index *index;
	git3_str path = GIT3_STR_INIT;
	git3_index_entry entry = {{0}};

	cl_git_pass(git3_repository_index(&index, repo));
	cl_assert(git3_index_entrycount(index) == 0);

	entry.path = fn;
	entry.mode = GIT3_FILEMODE_BLOB;
	cl_git_pass(git3_oid_from_string(&entry.id, "aea29dc305d40e362df25c3fdeed5502fd56b182af01b7740d297a24459333c5", GIT3_OID_SHA256));

	cl_git_fail(git3_index_add(index, &entry));

	cl_assert(git3_index_entrycount(index) == 0);

	git3_str_dispose(&path);
	git3_index_free(index);
}
#endif

/*
 * Test that writing an invalid filename fails on filesystem
 * specific protected names
 */
void test_index_tests256__cannot_add_protected_invalid_filename(void)
{
#ifdef GIT3_EXPERIMENTAL_SHA256
	git3_repository *repo;
	git3_index *index;

	cl_must_pass(p_mkdir("invalid", 0700));

	cl_git_pass(git3_repository_init(&repo, "./invalid", 0));

	/* add a file to the repository so we can reference it later */
	cl_git_pass(git3_repository_index(&index, repo));
	cl_git_mkfile("invalid/dummy.txt", "");
	cl_git_pass(git3_index_add_bypath(index, "dummy.txt"));
	cl_must_pass(p_unlink("invalid/dummy.txt"));
	cl_git_pass(git3_index_remove_bypath(index, "dummy.txt"));
	git3_index_free(index);

	cl_repo_set_bool(repo, "core.protectHFS", true);
	cl_repo_set_bool(repo, "core.protectNTFS", true);

	assert_add_fails(repo, ".git./hello");
	assert_add_fails(repo, ".git\xe2\x80\xad/hello");
	assert_add_fails(repo, "git~1/hello");
	assert_add_fails(repo, ".git\xe2\x81\xaf/hello");
	assert_add_fails(repo, ".git::$INDEX_ALLOCATION/dummy-file");

	git3_repository_free(repo);

	cl_fixture_cleanup("invalid");
#endif
}

#ifdef GIT3_EXPERIMENTAL_SHA256
static void replace_char(char *str, char in, char out)
{
	char *c = str;

	while (*c++)
		if (*c == in)
			*c = out;
}

static void assert_write_fails(git3_repository *repo, const char *fn_orig)
{
	git3_index *index;
	git3_oid expected;
	const git3_index_entry *entry;
	git3_str path = GIT3_STR_INIT;
	char *fn;

	cl_git_pass(git3_repository_index(&index, repo));
	cl_assert(git3_index_entrycount(index) == 0);

	/*
	 * Sneak a valid path into the index, we'll update it
	 * to an invalid path when we try to write the index.
	 */
	fn = git3__strdup(fn_orig);
	replace_char(fn, '/', '_');
	replace_char(fn, ':', '!');

	git3_str_joinpath(&path, "./invalid", fn);

	cl_git_mkfile(path.ptr, NULL);

	cl_git_pass(git3_index_add_bypath(index, fn));

	cl_assert(entry = git3_index_get_bypath(index, fn, 0));

	/* kids, don't try this at home */
	replace_char((char *)entry->path, '_', '/');
	replace_char((char *)entry->path, '!', ':');

	/* write-tree */
	cl_git_fail(git3_index_write_tree(&expected, index));

	p_unlink(path.ptr);

	cl_git_pass(git3_index_remove_all(index, NULL, NULL, NULL));
	git3_str_dispose(&path);
	git3_index_free(index);
	git3__free(fn);
}
#endif

void test_index_tests256__write_tree_invalid_unowned_index(void)
{
#ifdef GIT3_EXPERIMENTAL_SHA256
	git3_index *idx;
	git3_repository *repo;
	git3_index_entry entry = {{0}};
	git3_oid tree_id;
	git3_index_options index_opts = GIT3_INDEX_OPTIONS_INIT;

	index_opts.oid_type = GIT3_OID_SHA256;

	cl_git_pass(git3_index_new_ext(&idx, &index_opts));

	/* TODO: this one is failing */
	cl_git_pass(git3_oid_from_string(&entry.id, "a8c2e0a89a9cbab77c732b6bc39b51a783e3a318a847f46cba7614cac9814291", GIT3_OID_SHA256));
	entry.path = "foo";
	entry.mode = GIT3_FILEMODE_BLOB;
	cl_git_pass(git3_index_add(idx, &entry));

	cl_git_pass(git3_repository_init_ext(&repo, "./invalid-id", &repo_init_opts));

	cl_git_fail(git3_index_write_tree_to(&tree_id, idx, repo));

	git3_index_free(idx);
	git3_repository_free(repo);

	cl_fixture_cleanup("invalid-id");
#endif
}

/* Test that writing an invalid filename fails */
void test_index_tests256__write_invalid_filename(void)
{
#ifdef GIT3_EXPERIMENTAL_SHA256
	git3_repository *repo;

	p_mkdir("invalid", 0700);

	cl_git_pass(git3_repository_init(&repo, "./invalid", 0));

	assert_write_fails(repo, ".git/hello");
	assert_write_fails(repo, ".GIT/hello");
	assert_write_fails(repo, ".GiT/hello");
	assert_write_fails(repo, "./.git/hello");
	assert_write_fails(repo, "./foo");
	assert_write_fails(repo, "./bar");
	assert_write_fails(repo, "foo/../bar");

	git3_repository_free(repo);

	cl_fixture_cleanup("invalid");
#endif
}

void test_index_tests256__honors_protect_filesystems(void)
{
#ifdef GIT3_EXPERIMENTAL_SHA256
	git3_repository *repo;

	p_mkdir("invalid", 0700);

	cl_git_pass(git3_repository_init(&repo, "./invalid", 0));

	cl_repo_set_bool(repo, "core.protectHFS", true);
	cl_repo_set_bool(repo, "core.protectNTFS", true);

	assert_write_fails(repo, ".git./hello");
	assert_write_fails(repo, ".git\xe2\x80\xad/hello");
	assert_write_fails(repo, "git~1/hello");
	assert_write_fails(repo, ".git\xe2\x81\xaf/hello");
	assert_write_fails(repo, ".git::$INDEX_ALLOCATION/dummy-file");

	git3_repository_free(repo);

	cl_fixture_cleanup("invalid");
#endif
}

void test_index_tests256__protectntfs_on_by_default(void)
{
#ifdef GIT3_EXPERIMENTAL_SHA256
	git3_repository *repo;

	p_mkdir("invalid", 0700);

	cl_git_pass(git3_repository_init(&repo, "./invalid", 0));
	assert_write_fails(repo, ".git./hello");
	assert_write_fails(repo, "git~1/hello");

	git3_repository_free(repo);

	cl_fixture_cleanup("invalid");
#endif
}

void test_index_tests256__can_disable_protectntfs(void)
{
#ifdef GIT3_EXPERIMENTAL_SHA256
	git3_repository *repo;
	git3_index *index;

	cl_must_pass(p_mkdir("valid", 0700));
	cl_git_rewritefile("valid/git~1", "steal the shortname");

	cl_git_pass(git3_repository_init(&repo, "./valid", 0));
	cl_git_pass(git3_repository_index(&index, repo));
	cl_repo_set_bool(repo, "core.protectNTFS", false);

	cl_git_pass(git3_index_add_bypath(index, "git~1"));

	git3_index_free(index);
	git3_repository_free(repo);

	cl_fixture_cleanup("valid");
#endif
}

void test_index_tests256__remove_entry(void)
{
#ifdef GIT3_EXPERIMENTAL_SHA256
	git3_repository *repo;
	git3_index *index;

	p_mkdir("index_test", 0770);

	cl_git_pass(git3_repository_init(&repo, "index_test", 0));
	cl_git_pass(git3_repository_index(&index, repo));
	cl_assert(git3_index_entrycount(index) == 0);

	cl_git_mkfile("index_test/hello", NULL);
	cl_git_pass(git3_index_add_bypath(index, "hello"));
	cl_git_pass(git3_index_write(index));

	cl_git_pass(git3_index_read(index, true)); /* reload */
	cl_assert(git3_index_entrycount(index) == 1);
	cl_assert(git3_index_get_bypath(index, "hello", 0) != NULL);

	cl_git_pass(git3_index_remove(index, "hello", 0));
	cl_git_pass(git3_index_write(index));

	cl_git_pass(git3_index_read(index, true)); /* reload */
	cl_assert(git3_index_entrycount(index) == 0);
	cl_assert(git3_index_get_bypath(index, "hello", 0) == NULL);

	git3_index_free(index);
	git3_repository_free(repo);
	cl_fixture_cleanup("index_test");
#endif
}

void test_index_tests256__remove_directory(void)
{
#ifdef GIT3_EXPERIMENTAL_SHA256
	git3_repository *repo;
	git3_index *index;

	p_mkdir("index_test", 0770);

	cl_git_pass(git3_repository_init(&repo, "index_test", 0));
	cl_git_pass(git3_repository_index(&index, repo));
	cl_assert_equal_i(0, (int)git3_index_entrycount(index));

	p_mkdir("index_test/a", 0770);
	cl_git_mkfile("index_test/a/1.txt", NULL);
	cl_git_mkfile("index_test/a/2.txt", NULL);
	cl_git_mkfile("index_test/a/3.txt", NULL);
	cl_git_mkfile("index_test/b.txt", NULL);

	cl_git_pass(git3_index_add_bypath(index, "a/1.txt"));
	cl_git_pass(git3_index_add_bypath(index, "a/2.txt"));
	cl_git_pass(git3_index_add_bypath(index, "a/3.txt"));
	cl_git_pass(git3_index_add_bypath(index, "b.txt"));
	cl_git_pass(git3_index_write(index));

	cl_git_pass(git3_index_read(index, true)); /* reload */
	cl_assert_equal_i(4, (int)git3_index_entrycount(index));
	cl_assert(git3_index_get_bypath(index, "a/1.txt", 0) != NULL);
	cl_assert(git3_index_get_bypath(index, "a/2.txt", 0) != NULL);
	cl_assert(git3_index_get_bypath(index, "b.txt", 0) != NULL);

	cl_git_pass(git3_index_remove(index, "a/1.txt", 0));
	cl_git_pass(git3_index_write(index));

	cl_git_pass(git3_index_read(index, true)); /* reload */
	cl_assert_equal_i(3, (int)git3_index_entrycount(index));
	cl_assert(git3_index_get_bypath(index, "a/1.txt", 0) == NULL);
	cl_assert(git3_index_get_bypath(index, "a/2.txt", 0) != NULL);
	cl_assert(git3_index_get_bypath(index, "b.txt", 0) != NULL);

	cl_git_pass(git3_index_remove_directory(index, "a", 0));
	cl_git_pass(git3_index_write(index));

	cl_git_pass(git3_index_read(index, true)); /* reload */
	cl_assert_equal_i(1, (int)git3_index_entrycount(index));
	cl_assert(git3_index_get_bypath(index, "a/1.txt", 0) == NULL);
	cl_assert(git3_index_get_bypath(index, "a/2.txt", 0) == NULL);
	cl_assert(git3_index_get_bypath(index, "b.txt", 0) != NULL);

	git3_index_free(index);
	git3_repository_free(repo);
	cl_fixture_cleanup("index_test");
#endif
}

void test_index_tests256__preserves_case(void)
{
#ifdef GIT3_EXPERIMENTAL_SHA256
	git3_repository *repo;
	git3_index *index;
	const git3_index_entry *entry;
	int index_caps;

	cl_set_cleanup(&cleanup_myrepo, NULL);

	cl_git_pass(git3_repository_init_ext(&repo, "./myrepo", &repo_init_opts));
	cl_git_pass(git3_repository_index(&index, repo));

	index_caps = git3_index_caps(index);

	cl_git_rewritefile("myrepo/test.txt", "hey there\n");
	cl_git_pass(git3_index_add_bypath(index, "test.txt"));

	cl_git_pass(p_rename("myrepo/test.txt", "myrepo/TEST.txt"));
	cl_git_rewritefile("myrepo/TEST.txt", "hello again\n");
	cl_git_pass(git3_index_add_bypath(index, "TEST.txt"));

	if (index_caps & GIT3_INDEX_CAPABILITY_IGNORE_CASE)
		cl_assert_equal_i(1, (int)git3_index_entrycount(index));
	else
		cl_assert_equal_i(2, (int)git3_index_entrycount(index));

	/* Test access by path instead of index */
	cl_assert((entry = git3_index_get_bypath(index, "test.txt", 0)) != NULL);
	/* The path should *not* have changed without an explicit remove */
	cl_assert(git3__strcmp(entry->path, "test.txt") == 0);

	cl_assert((entry = git3_index_get_bypath(index, "TEST.txt", 0)) != NULL);
	if (index_caps & GIT3_INDEX_CAPABILITY_IGNORE_CASE)
		/* The path should *not* have changed without an explicit remove */
		cl_assert(git3__strcmp(entry->path, "test.txt") == 0);
	else
		cl_assert(git3__strcmp(entry->path, "TEST.txt") == 0);

	git3_index_free(index);
	git3_repository_free(repo);
#endif
}

void test_index_tests256__elocked(void)
{
#ifdef GIT3_EXPERIMENTAL_SHA256
	git3_repository *repo;
	git3_index *index;
	git3_filebuf file = GIT3_FILEBUF_INIT;
	const git3_error *err;
	int error;

	cl_set_cleanup(&cleanup_myrepo, NULL);

	cl_git_pass(git3_repository_init_ext(&repo, "./myrepo", &repo_init_opts));
	cl_git_pass(git3_repository_index(&index, repo));

	/* Lock the index file so we fail to lock it */
	cl_git_pass(git3_filebuf_open(&file, index->index_file_path, 0, 0666));
	error = git3_index_write(index);
	cl_assert_equal_i(GIT3_ELOCKED, error);

	err = git3_error_last();
	cl_assert_equal_i(err->klass, GIT3_ERROR_INDEX);

	git3_filebuf_cleanup(&file);
	git3_index_free(index);
	git3_repository_free(repo);
#endif
}

void test_index_tests256__reload_from_disk(void)
{
#ifdef GIT3_EXPERIMENTAL_SHA256
	git3_repository *repo;
	git3_index *read_index;
	git3_index *write_index;
	git3_index_options index_opts = GIT3_INDEX_OPTIONS_INIT;

	index_opts.oid_type = GIT3_OID_SHA256;

	cl_set_cleanup(&cleanup_myrepo, NULL);

	cl_git_pass(git3_futils_mkdir("./myrepo", 0777, GIT3_MKDIR_PATH));
	cl_git_mkfile("./myrepo/a.txt", "a\n");
	cl_git_mkfile("./myrepo/b.txt", "b\n");

	cl_git_pass(git3_repository_init_ext(&repo, "./myrepo", &repo_init_opts));
	cl_git_pass(git3_repository_index(&write_index, repo));
	cl_assert_equal_i(false, write_index->on_disk);

	cl_git_pass(git3_index_open_ext(&read_index, write_index->index_file_path, &index_opts));
	cl_assert_equal_i(false, read_index->on_disk);

	/* Stage two new files against the write_index */
	cl_git_pass(git3_index_add_bypath(write_index, "a.txt"));
	cl_git_pass(git3_index_add_bypath(write_index, "b.txt"));

	cl_assert_equal_sz(2, git3_index_entrycount(write_index));

	/* Persist the index changes to disk */
	cl_git_pass(git3_index_write(write_index));
	cl_assert_equal_i(true, write_index->on_disk);

	/* Sync the changes back into the read_index */
	cl_assert_equal_sz(0, git3_index_entrycount(read_index));

	cl_git_pass(git3_index_read(read_index, true));
	cl_assert_equal_i(true, read_index->on_disk);

	cl_assert_equal_sz(2, git3_index_entrycount(read_index));

	/* Remove the index file from the filesystem */
	cl_git_pass(p_unlink(write_index->index_file_path));

	/* Sync the changes back into the read_index */
	cl_git_pass(git3_index_read(read_index, true));
	cl_assert_equal_i(false, read_index->on_disk);
	cl_assert_equal_sz(0, git3_index_entrycount(read_index));

	git3_index_free(read_index);
	git3_index_free(write_index);
	git3_repository_free(repo);
#endif
}

void test_index_tests256__reload_while_ignoring_case(void)
{
#ifdef GIT3_EXPERIMENTAL_SHA256
	git3_index *index;
	unsigned int caps;
	git3_index_options index_opts = GIT3_INDEX_OPTIONS_INIT;

	index_opts.oid_type = GIT3_OID_SHA256;

	cl_git_pass(git3_index_open_ext(&index, TEST_INDEX_PATH, &index_opts));
	cl_git_pass(git3_vector_verify_sorted(&index->entries));

	caps = git3_index_caps(index);
	cl_git_pass(git3_index_set_caps(index, caps &= ~GIT3_INDEX_CAPABILITY_IGNORE_CASE));
	cl_git_pass(git3_index_read(index, true));
	cl_git_pass(git3_vector_verify_sorted(&index->entries));
	cl_assert(git3_index_get_bypath(index, "contrib/README", 0));
	cl_assert_equal_p(NULL, git3_index_get_bypath(index, "CONTRIB/readme", 0));

	cl_git_pass(git3_index_set_caps(index, caps | GIT3_INDEX_CAPABILITY_IGNORE_CASE));
	cl_git_pass(git3_index_read(index, true));
	cl_git_pass(git3_vector_verify_sorted(&index->entries));
	cl_assert(git3_index_get_bypath(index, "contrib/README", 0));
	cl_assert(git3_index_get_bypath(index, "CONTRIB/readme", 0));

	git3_index_free(index);
#endif
}

void test_index_tests256__change_icase_on_instance(void)
{
#ifdef GIT3_EXPERIMENTAL_SHA256
	git3_index *index;
	unsigned int caps;
	const git3_index_entry *e;
	git3_index_options index_opts = GIT3_INDEX_OPTIONS_INIT;

	index_opts.oid_type = GIT3_OID_SHA256;

	cl_git_pass(git3_index_open_ext(&index, TEST_INDEX_PATH, &index_opts));
	cl_git_pass(git3_vector_verify_sorted(&index->entries));

	caps = git3_index_caps(index);
	cl_git_pass(git3_index_set_caps(index, caps &= ~GIT3_INDEX_CAPABILITY_IGNORE_CASE));
	cl_assert_equal_i(false, index->ignore_case);
	cl_git_pass(git3_vector_verify_sorted(&index->entries));
	cl_assert(e = git3_index_get_bypath(index, "contrib/README", 0));
	cl_assert_equal_p(NULL, e = git3_index_get_bypath(index, "CONTRIB/readme", 0));
	cl_assert(e = git3_index_get_bypath(index, "config.h", 0));
	cl_assert_equal_p(NULL, e = git3_index_get_bypath(index, "CONFIG.H", 0));

	cl_git_pass(git3_index_set_caps(index, caps | GIT3_INDEX_CAPABILITY_IGNORE_CASE));
	cl_assert_equal_i(true, index->ignore_case);
	cl_git_pass(git3_vector_verify_sorted(&index->entries));
	cl_assert(e = git3_index_get_bypath(index, "config.h", 0));
	cl_assert_equal_s("config.h", e->path);
	cl_assert(e = git3_index_get_bypath(index, "CONFIG.H", 0));
	cl_assert_equal_s("config.h", e->path);

	git3_index_free(index);
#endif
}

void test_index_tests256__can_lock_index(void)
{
#ifdef GIT3_EXPERIMENTAL_SHA256
	git3_repository *repo;
	git3_index *index;
	git3_indexwriter one = GIT3_INDEXWRITER_INIT,
		two = GIT3_INDEXWRITER_INIT;

	repo = cl_git_sandbox_init("testrepo.git");

	cl_git_pass(git3_repository_index(&index, repo));
	cl_git_pass(git3_indexwriter_init(&one, index));

	cl_git_fail_with(GIT3_ELOCKED, git3_indexwriter_init(&two, index));
	cl_git_fail_with(GIT3_ELOCKED, git3_index_write(index));

	cl_git_pass(git3_indexwriter_commit(&one));

	cl_git_pass(git3_index_write(index));

	git3_indexwriter_cleanup(&one);
	git3_indexwriter_cleanup(&two);
	git3_index_free(index);
	cl_git_sandbox_cleanup();
#endif
}

void test_index_tests256__can_iterate(void)
{
#ifdef GIT3_EXPERIMENTAL_SHA256
	git3_index *index;
	git3_index_iterator *iterator;
	const git3_index_entry *entry;
	size_t i, iterator_idx = 0, found = 0;
	int ret;
	git3_index_options index_opts = GIT3_INDEX_OPTIONS_INIT;

	index_opts.oid_type = GIT3_OID_SHA256;

	cl_git_pass(git3_index_open_ext(&index, TEST_INDEX_PATH, &index_opts));
	cl_git_pass(git3_index_iterator_new(&iterator, index));

	cl_assert(git3_vector_is_sorted(&iterator->snap));

	for (i = 0; i < ARRAY_SIZE(test_entries); i++) {
		/* Advance iterator to next test entry index */
		do {
			ret = git3_index_iterator_next(&entry, iterator);

			if (ret == GIT3_ITEROVER)
				cl_fail("iterator did not contain all test entries");

			cl_git_pass(ret);
		} while (iterator_idx++ < test_entries[i].index);

		cl_assert_equal_s(entry->path, test_entries[i].path);
		cl_assert_equal_i(entry->mtime.seconds, test_entries[i].mtime);
		cl_assert_equal_i(entry->file_size, test_entries[i].file_size);
		found++;
	}

	while ((ret = git3_index_iterator_next(&entry, iterator)) == 0)
		;

	if (ret != GIT3_ITEROVER)
		cl_git_fail(ret);

	cl_assert_equal_i(found, ARRAY_SIZE(test_entries));

	git3_index_iterator_free(iterator);
	git3_index_free(index);
#endif
}

void test_index_tests256__can_modify_while_iterating(void)
{
#ifdef GIT3_EXPERIMENTAL_SHA256
	git3_index *index;
	git3_index_iterator *iterator;
	const git3_index_entry *entry;
	git3_index_entry new_entry = {{0}};
	size_t expected = 0, seen = 0;
	int ret;
	git3_index_options index_opts = GIT3_INDEX_OPTIONS_INIT;

	index_opts.oid_type = GIT3_OID_SHA256;

	cl_git_pass(git3_index_open_ext(&index, TEST_INDEX_PATH, &index_opts));
	cl_git_pass(git3_index_iterator_new(&iterator, index));

	expected = git3_index_entrycount(index);
	cl_assert(git3_vector_is_sorted(&iterator->snap));

	/*
	 * After we've counted the entries, add a new one and change another;
	 * ensure that our iterator is backed by a snapshot and thus returns
	 * the number of entries from when the iterator was created.
	 */
	cl_git_pass(git3_oid_from_string(&new_entry.id, "8312e0a89a9cbab77c732b6bc39b51a783e3a318a847f46cba7614cac9814291", GIT3_OID_SHA256));
	new_entry.path = "newfile";
	new_entry.mode = GIT3_FILEMODE_BLOB;
	cl_git_pass(git3_index_add(index, &new_entry));

	cl_git_pass(git3_oid_from_string(&new_entry.id, "4141414141414141414141414141414141414141414141414141414141414141", GIT3_OID_SHA256));
	new_entry.path = "Makefile";
	new_entry.mode = GIT3_FILEMODE_BLOB;
	cl_git_pass(git3_index_add(index, &new_entry));

	while (true) {
		ret = git3_index_iterator_next(&entry, iterator);

		if (ret == GIT3_ITEROVER)
			break;

		seen++;
	}

	cl_assert_equal_i(expected, seen);

	git3_index_iterator_free(iterator);
	git3_index_free(index);
#endif
}
