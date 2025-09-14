#include "clar_libgit3.h"
#include "futils.h"
#include "stash_helpers.h"

static git3_repository *repo;
static git3_signature *signature;
static git3_oid stash_tip_oid;

/*
 * Friendly reminder, in order to ease the reading of the following tests:
 *
 * "stash"		points to the worktree commit
 * "stash^1"	points to the base commit (HEAD when the stash was created)
 * "stash^2"	points to the index commit
 * "stash^3"	points to the untracked commit
 */

void test_stash_save__initialize(void)
{
	cl_git_pass(git3_repository_init(&repo, "stash", 0));
	cl_git_pass(git3_signature_new(&signature, "nulltoken", "emeric.fermas@gmail.com", 1323847743, 60)); /* Wed Dec 14 08:29:03 2011 +0100 */

	setup_stash(repo, signature);
}

void test_stash_save__cleanup(void)
{
	git3_signature_free(signature);
	signature = NULL;

	git3_repository_free(repo);
	repo = NULL;

	cl_git_pass(git3_futils_rmdir_r("stash", NULL, GIT3_RMDIR_REMOVE_FILES));
	cl_fixture_cleanup("sorry-it-is-a-non-bare-only-party");
}

static void assert_object_oid(const char* revision, const char* expected_oid, git3_object_t type)
{
	int result;
	git3_object *obj;

	result = git3_revparse_single(&obj, repo, revision);

	if (!expected_oid) {
		cl_assert_equal_i(GIT3_ENOTFOUND, result);
		return;
	} else
		cl_assert_equal_i(0, result);

	cl_git_pass(git3_oid_streq(git3_object_id(obj), expected_oid));
	cl_assert_equal_i(type, git3_object_type(obj));
	git3_object_free(obj);
}

static void assert_blob_oid(const char* revision, const char* expected_oid)
{
	assert_object_oid(revision, expected_oid, GIT3_OBJECT_BLOB);
}

void test_stash_save__does_not_keep_index_by_default(void)
{
/*
$ git stash

$ git show refs/stash:what
see you later

$ git show refs/stash:how
not so small and

$ git show refs/stash:who
funky world

$ git show refs/stash:when
fatal: Path 'when' exists on disk, but not in 'stash'.

$ git show refs/stash^2:what
goodbye

$ git show refs/stash^2:how
not so small and

$ git show refs/stash^2:who
world

$ git show refs/stash^2:when
fatal: Path 'when' exists on disk, but not in 'stash^2'.

$ git status --short
?? when

*/
	unsigned int status;

	cl_git_pass(git3_stash_save(&stash_tip_oid, repo, signature, NULL, GIT3_STASH_DEFAULT));
	cl_git_pass(git3_status_file(&status, repo, "when"));

	assert_blob_oid("refs/stash:what", "bc99dc98b3eba0e9157e94769cd4d49cb49de449");	/* see you later */
	assert_blob_oid("refs/stash:how", "e6d64adb2c7f3eb8feb493b556cc8070dca379a3");	/* not so small and */
	assert_blob_oid("refs/stash:who", "a0400d4954659306a976567af43125a0b1aa8595");	/* funky world */
	assert_blob_oid("refs/stash:when", NULL);
	assert_blob_oid("refs/stash:why", "88c2533e21f098b89c91a431d8075cbdbe422a51"); /* would anybody use stash? */
	assert_blob_oid("refs/stash:where", "e3d6434ec12eb76af8dfa843a64ba6ab91014a0b"); /* .... */
	assert_blob_oid("refs/stash:.gitignore", "ac4d88de61733173d9959e4b77c69b9f17a00980");
	assert_blob_oid("refs/stash:just.ignore", NULL);

	assert_blob_oid("refs/stash^2:what", "dd7e1c6f0fefe118f0b63d9f10908c460aa317a6");	/* goodbye */
	assert_blob_oid("refs/stash^2:how", "e6d64adb2c7f3eb8feb493b556cc8070dca379a3");	/* not so small and */
	assert_blob_oid("refs/stash^2:who", "cc628ccd10742baea8241c5924df992b5c019f71");	/* world */
	assert_blob_oid("refs/stash^2:when", NULL);
	assert_blob_oid("refs/stash^2:why", "88c2533e21f098b89c91a431d8075cbdbe422a51"); /* would anybody use stash? */
	assert_blob_oid("refs/stash^2:where", "e08f7fbb9a42a0c5367cf8b349f1f08c3d56bd72"); /* ???? */
	assert_blob_oid("refs/stash^2:.gitignore", "ac4d88de61733173d9959e4b77c69b9f17a00980");
	assert_blob_oid("refs/stash^2:just.ignore", NULL);

	assert_blob_oid("refs/stash^3", NULL);

	cl_assert_equal_i(GIT3_STATUS_WT_NEW, status);
}

void test_stash_save__can_keep_index(void)
{
	cl_git_pass(git3_stash_save(&stash_tip_oid, repo, signature, NULL, GIT3_STASH_KEEP_INDEX));

	assert_status(repo, "what", GIT3_STATUS_INDEX_MODIFIED);
	assert_status(repo, "how", GIT3_STATUS_INDEX_MODIFIED);
	assert_status(repo, "who", GIT3_STATUS_CURRENT);
	assert_status(repo, "when", GIT3_STATUS_WT_NEW);
	assert_status(repo, "just.ignore", GIT3_STATUS_IGNORED);
}

void test_stash_save__can_keep_all(void)
{
	cl_git_pass(git3_stash_save(&stash_tip_oid, repo, signature, NULL, GIT3_STASH_KEEP_ALL));
	
	assert_status(repo, "what", GIT3_STATUS_WT_MODIFIED | GIT3_STATUS_INDEX_MODIFIED);
	assert_status(repo, "how", GIT3_STATUS_INDEX_MODIFIED);
	assert_status(repo, "who", GIT3_STATUS_WT_MODIFIED);
	assert_status(repo, "when", GIT3_STATUS_WT_NEW);
	assert_status(repo, "why", GIT3_STATUS_INDEX_NEW);
	assert_status(repo, "where", GIT3_STATUS_WT_MODIFIED | GIT3_STATUS_INDEX_NEW);
	assert_status(repo, "just.ignore", GIT3_STATUS_IGNORED);
}

static void assert_commit_message_contains(const char *revision, const char *fragment)
{
	git3_commit *commit;

	cl_git_pass(git3_revparse_single((git3_object**)&commit, repo, revision));

	cl_assert(strstr(git3_commit_message(commit), fragment) != NULL);

	git3_commit_free(commit);
}

void test_stash_save__can_include_untracked_files(void)
{
	cl_git_pass(git3_stash_save(&stash_tip_oid, repo, signature, NULL, GIT3_STASH_INCLUDE_UNTRACKED));

	assert_commit_message_contains("refs/stash^3", "untracked files on master: ");

	assert_blob_oid("refs/stash^3:what", NULL);
	assert_blob_oid("refs/stash^3:how", NULL);
	assert_blob_oid("refs/stash^3:who", NULL);
	assert_blob_oid("refs/stash^3:when", "b6ed15e81e2593d7bb6265eb4a991d29dc3e628b");
	assert_blob_oid("refs/stash^3:just.ignore", NULL);
}

void test_stash_save__untracked_skips_ignored(void)
{
	cl_git_append2file("stash/.gitignore", "bundle/vendor/\n");
	cl_must_pass(p_mkdir("stash/bundle", 0777));
	cl_must_pass(p_mkdir("stash/bundle/vendor", 0777));
	cl_git_mkfile("stash/bundle/vendor/blah", "contents\n");

	cl_assert(git3_fs_path_exists("stash/when")); /* untracked */
	cl_assert(git3_fs_path_exists("stash/just.ignore")); /* ignored */
	cl_assert(git3_fs_path_exists("stash/bundle/vendor/blah")); /* ignored */

	cl_git_pass(git3_stash_save(
		&stash_tip_oid, repo, signature, NULL, GIT3_STASH_INCLUDE_UNTRACKED));

	cl_assert(!git3_fs_path_exists("stash/when"));
	cl_assert(git3_fs_path_exists("stash/bundle/vendor/blah"));
	cl_assert(git3_fs_path_exists("stash/just.ignore"));
}

void test_stash_save__can_include_untracked_and_ignored_files(void)
{
	cl_git_pass(git3_stash_save(&stash_tip_oid, repo, signature, NULL, GIT3_STASH_INCLUDE_UNTRACKED | GIT3_STASH_INCLUDE_IGNORED));

	assert_commit_message_contains("refs/stash^3", "untracked files on master: ");

	assert_blob_oid("refs/stash^3:what", NULL);
	assert_blob_oid("refs/stash^3:how", NULL);
	assert_blob_oid("refs/stash^3:who", NULL);
	assert_blob_oid("refs/stash^3:when", "b6ed15e81e2593d7bb6265eb4a991d29dc3e628b");
	assert_blob_oid("refs/stash^3:just.ignore", "78925fb1236b98b37a35e9723033e627f97aa88b");

	cl_assert(!git3_fs_path_exists("stash/just.ignore"));
}

/*
 * Note: this test was flaky prior to fixing #4101 -- run it several
 * times to get a failure.  The issues is that whether the fast
 * (stat-only) codepath is used inside stash's diff operation depends
 * on whether files are "racily clean", and there doesn't seem to be
 * an easy way to force the exact required state.
 */
void test_stash_save__untracked_regression(void)
{
	git3_checkout_options opts = GIT3_CHECKOUT_OPTIONS_INIT;
	const char *paths[] = {"what", "where", "how", "why"};
	git3_reference *head;
	git3_commit *head_commit;
	git3_str untracked_dir;

	const char* workdir = git3_repository_workdir(repo);

	git3_str_init(&untracked_dir, 0);
	git3_str_printf(&untracked_dir, "%sz", workdir);

	cl_assert(!p_mkdir(untracked_dir.ptr, 0777));

	cl_git_pass(git3_repository_head(&head, repo));

	cl_git_pass(git3_reference_peel((git3_object **)&head_commit, head, GIT3_OBJECT_COMMIT));

	opts.checkout_strategy = GIT3_CHECKOUT_FORCE;

	opts.paths.strings = (char **)paths;
	opts.paths.count = 4;

	cl_git_pass(git3_checkout_tree(repo, (git3_object*)head_commit, &opts));

	cl_git_pass(git3_stash_save(&stash_tip_oid, repo, signature, NULL, GIT3_STASH_DEFAULT));

	assert_commit_message_contains("refs/stash", "WIP on master");

	git3_reference_free(head);
	git3_commit_free(head_commit);
	git3_str_dispose(&untracked_dir);
}

#define MESSAGE "Look Ma! I'm on TV!"
void test_stash_save__can_accept_a_message(void)
{
	cl_git_pass(git3_stash_save(&stash_tip_oid, repo, signature, MESSAGE, GIT3_STASH_DEFAULT));

	assert_commit_message_contains("refs/stash^2", "index on master: ");
	assert_commit_message_contains("refs/stash", "On master: " MESSAGE);
}

void test_stash_save__cannot_stash_against_an_unborn_branch(void)
{
	git3_reference *head;

	cl_git_pass(git3_reference_symbolic_create(&head, repo, "HEAD", "refs/heads/unborn", 1, NULL));

	cl_assert_equal_i(GIT3_EUNBORNBRANCH,
		git3_stash_save(&stash_tip_oid, repo, signature, NULL, GIT3_STASH_DEFAULT));

	git3_reference_free(head);
}

void test_stash_save__cannot_stash_against_a_bare_repository(void)
{
	git3_repository *local;

	cl_git_pass(git3_repository_init(&local, "sorry-it-is-a-non-bare-only-party", 1));

	cl_assert_equal_i(GIT3_EBAREREPO,
		git3_stash_save(&stash_tip_oid, local, signature, NULL, GIT3_STASH_DEFAULT));

	git3_repository_free(local);
}

void test_stash_save__can_stash_against_a_detached_head(void)
{
	git3_repository_detach_head(repo);

	cl_git_pass(git3_stash_save(&stash_tip_oid, repo, signature, NULL, GIT3_STASH_DEFAULT));

	assert_commit_message_contains("refs/stash^2", "index on (no branch): ");
	assert_commit_message_contains("refs/stash", "WIP on (no branch): ");
}

void test_stash_save__stashing_updates_the_reflog(void)
{
	assert_object_oid("refs/stash@{0}", NULL, GIT3_OBJECT_COMMIT);

	cl_git_pass(git3_stash_save(&stash_tip_oid, repo, signature, NULL, GIT3_STASH_DEFAULT));

	assert_object_oid("refs/stash@{0}", git3_oid_tostr_s(&stash_tip_oid), GIT3_OBJECT_COMMIT);
	assert_object_oid("refs/stash@{1}", NULL, GIT3_OBJECT_COMMIT);
}

void test_stash_save__multiline_message(void)
{
	const char *msg = "This\n\nis a multiline message\n";
	const git3_reflog_entry *entry;
	git3_reflog *reflog;

	assert_object_oid("refs/stash@{0}", NULL, GIT3_OBJECT_COMMIT);

	cl_git_pass(git3_stash_save(&stash_tip_oid, repo, signature, msg, GIT3_STASH_DEFAULT));

	cl_git_pass(git3_reflog_read(&reflog, repo, "refs/stash"));
	cl_assert(entry = git3_reflog_entry_byindex(reflog, 0));
	cl_assert_equal_s(git3_reflog_entry_message(entry), "On master: This  is a multiline message");

	assert_object_oid("refs/stash@{0}", git3_oid_tostr_s(&stash_tip_oid), GIT3_OBJECT_COMMIT);
	assert_commit_message_contains("refs/stash@{0}", msg);

	git3_reflog_free(reflog);
}

void test_stash_save__cannot_stash_when_there_are_no_local_change(void)
{
	git3_index *index;
	git3_oid stash_tip_oid;

	cl_git_pass(git3_repository_index(&index, repo));

	/*
	 * 'what', 'where' and 'who' are being committed.
	 * 'when' remains untracked.
	 */
	cl_git_pass(git3_index_add_bypath(index, "what"));
	cl_git_pass(git3_index_add_bypath(index, "where"));
	cl_git_pass(git3_index_add_bypath(index, "who"));

	cl_repo_commit_from_index(NULL, repo, signature, 0, "Initial commit");
	git3_index_free(index);

	cl_assert_equal_i(GIT3_ENOTFOUND,
		git3_stash_save(&stash_tip_oid, repo, signature, NULL, GIT3_STASH_DEFAULT));

	p_unlink("stash/when");
	cl_assert_equal_i(GIT3_ENOTFOUND,
		git3_stash_save(&stash_tip_oid, repo, signature, NULL, GIT3_STASH_INCLUDE_UNTRACKED));
}

void test_stash_save__can_stage_normal_then_stage_untracked(void)
{
	/*
	 * $ git ls-tree stash@{1}^0
	 * 100644 blob ac4d88de61733173d9959e4b77c69b9f17a00980    .gitignore
	 * 100644 blob e6d64adb2c7f3eb8feb493b556cc8070dca379a3    how
	 * 100644 blob bc99dc98b3eba0e9157e94769cd4d49cb49de449    what
	 * 100644 blob a0400d4954659306a976567af43125a0b1aa8595    who
	 *
	 * $ git ls-tree stash@{1}^1
	 * 100644 blob ac4d88de61733173d9959e4b77c69b9f17a00980    .gitignore
	 * 100644 blob ac790413e2d7a26c3767e78c57bb28716686eebc    how
	 * 100644 blob ce013625030ba8dba906f756967f9e9ca394464a    what
	 * 100644 blob cc628ccd10742baea8241c5924df992b5c019f71    who
	 *
	 * $ git ls-tree stash@{1}^2
	 * 100644 blob ac4d88de61733173d9959e4b77c69b9f17a00980    .gitignore
	 * 100644 blob e6d64adb2c7f3eb8feb493b556cc8070dca379a3    how
	 * 100644 blob dd7e1c6f0fefe118f0b63d9f10908c460aa317a6    what
	 * 100644 blob cc628ccd10742baea8241c5924df992b5c019f71    who
	 *
	 * $ git ls-tree stash@{1}^3
	 * fatal: Not a valid object name stash@{1}^3
	 *
	 * $ git ls-tree stash@{0}^0
	 * 100644 blob ac4d88de61733173d9959e4b77c69b9f17a00980    .gitignore
	 * 100644 blob ac790413e2d7a26c3767e78c57bb28716686eebc    how
	 * 100644 blob ce013625030ba8dba906f756967f9e9ca394464a    what
	 * 100644 blob cc628ccd10742baea8241c5924df992b5c019f71    who
	 *
	 * $ git ls-tree stash@{0}^1
	 * 100644 blob ac4d88de61733173d9959e4b77c69b9f17a00980    .gitignore
	 * 100644 blob ac790413e2d7a26c3767e78c57bb28716686eebc    how
	 * 100644 blob ce013625030ba8dba906f756967f9e9ca394464a    what
	 * 100644 blob cc628ccd10742baea8241c5924df992b5c019f71    who
	 *
	 * $ git ls-tree stash@{0}^2
	 * 100644 blob ac4d88de61733173d9959e4b77c69b9f17a00980    .gitignore
	 * 100644 blob ac790413e2d7a26c3767e78c57bb28716686eebc    how
	 * 100644 blob ce013625030ba8dba906f756967f9e9ca394464a    what
	 * 100644 blob cc628ccd10742baea8241c5924df992b5c019f71    who
	 *
	 * $ git ls-tree stash@{0}^3
	 * 100644 blob b6ed15e81e2593d7bb6265eb4a991d29dc3e628b    when
	*/

	assert_status(repo, "what", GIT3_STATUS_WT_MODIFIED | GIT3_STATUS_INDEX_MODIFIED);
	assert_status(repo, "how", GIT3_STATUS_INDEX_MODIFIED);
	assert_status(repo, "who", GIT3_STATUS_WT_MODIFIED);
	assert_status(repo, "when", GIT3_STATUS_WT_NEW);
	assert_status(repo, "just.ignore", GIT3_STATUS_IGNORED);

	cl_git_pass(git3_stash_save(&stash_tip_oid, repo, signature, NULL, GIT3_STASH_DEFAULT));
	assert_status(repo, "what", GIT3_STATUS_CURRENT);
	assert_status(repo, "how", GIT3_STATUS_CURRENT);
	assert_status(repo, "who", GIT3_STATUS_CURRENT);
	assert_status(repo, "when", GIT3_STATUS_WT_NEW);
	assert_status(repo, "just.ignore", GIT3_STATUS_IGNORED);

	cl_git_pass(git3_stash_save(&stash_tip_oid, repo, signature, NULL, GIT3_STASH_INCLUDE_UNTRACKED));
	assert_status(repo, "what", GIT3_STATUS_CURRENT);
	assert_status(repo, "how", GIT3_STATUS_CURRENT);
	assert_status(repo, "who", GIT3_STATUS_CURRENT);
	assert_status(repo, "when", GIT3_ENOTFOUND);
	assert_status(repo, "just.ignore", GIT3_STATUS_IGNORED);


	assert_blob_oid("stash@{1}^0:what", "bc99dc98b3eba0e9157e94769cd4d49cb49de449");	/* see you later */
	assert_blob_oid("stash@{1}^0:how", "e6d64adb2c7f3eb8feb493b556cc8070dca379a3");		/* not so small and */
	assert_blob_oid("stash@{1}^0:who", "a0400d4954659306a976567af43125a0b1aa8595");		/* funky world */
	assert_blob_oid("stash@{1}^0:when", NULL);

	assert_blob_oid("stash@{1}^2:what", "dd7e1c6f0fefe118f0b63d9f10908c460aa317a6");	/* goodbye */
	assert_blob_oid("stash@{1}^2:how", "e6d64adb2c7f3eb8feb493b556cc8070dca379a3");		/* not so small and */
	assert_blob_oid("stash@{1}^2:who", "cc628ccd10742baea8241c5924df992b5c019f71");		/* world */
	assert_blob_oid("stash@{1}^2:when", NULL);

	assert_object_oid("stash@{1}^3", NULL, GIT3_OBJECT_COMMIT);

	assert_blob_oid("stash@{0}^0:what", "ce013625030ba8dba906f756967f9e9ca394464a");	/* hello */
	assert_blob_oid("stash@{0}^0:how", "ac790413e2d7a26c3767e78c57bb28716686eebc");		/* small */
	assert_blob_oid("stash@{0}^0:who", "cc628ccd10742baea8241c5924df992b5c019f71");		/* world */
	assert_blob_oid("stash@{0}^0:when", NULL);

	assert_blob_oid("stash@{0}^2:what", "ce013625030ba8dba906f756967f9e9ca394464a");	/* hello */
	assert_blob_oid("stash@{0}^2:how", "ac790413e2d7a26c3767e78c57bb28716686eebc");		/* small */
	assert_blob_oid("stash@{0}^2:who", "cc628ccd10742baea8241c5924df992b5c019f71");		/* world */
	assert_blob_oid("stash@{0}^2:when", NULL);

	assert_blob_oid("stash@{0}^3:when", "b6ed15e81e2593d7bb6265eb4a991d29dc3e628b");	/* now */
}

#define EMPTY_TREE "4b825dc642cb6eb9a060e54bf8d69288fbee4904"

void test_stash_save__including_untracked_without_any_untracked_file_creates_an_empty_tree(void)
{
	cl_must_pass(p_unlink("stash/when"));

	assert_status(repo, "what", GIT3_STATUS_WT_MODIFIED | GIT3_STATUS_INDEX_MODIFIED);
	assert_status(repo, "how", GIT3_STATUS_INDEX_MODIFIED);
	assert_status(repo, "who", GIT3_STATUS_WT_MODIFIED);
	assert_status(repo, "when", GIT3_ENOTFOUND);
	assert_status(repo, "just.ignore", GIT3_STATUS_IGNORED);

	cl_git_pass(git3_stash_save(&stash_tip_oid, repo, signature, NULL, GIT3_STASH_INCLUDE_UNTRACKED));

	assert_object_oid("stash^3^{tree}", EMPTY_TREE, GIT3_OBJECT_TREE);
}

void test_stash_save__ignored_directory(void)
{
	cl_git_pass(p_mkdir("stash/ignored_directory", 0777));
	cl_git_pass(p_mkdir("stash/ignored_directory/sub", 0777));
	cl_git_mkfile("stash/ignored_directory/sub/some_file", "stuff");

	assert_status(repo, "ignored_directory/sub/some_file", GIT3_STATUS_WT_NEW);
	cl_git_pass(git3_ignore_add_rule(repo, "ignored_directory/"));
	assert_status(repo, "ignored_directory/sub/some_file", GIT3_STATUS_IGNORED);

	cl_git_pass(git3_stash_save(&stash_tip_oid, repo, signature, NULL, GIT3_STASH_INCLUDE_UNTRACKED | GIT3_STASH_INCLUDE_IGNORED));

	cl_assert(!git3_fs_path_exists("stash/ignored_directory/sub/some_file"));
	cl_assert(!git3_fs_path_exists("stash/ignored_directory/sub"));
	cl_assert(!git3_fs_path_exists("stash/ignored_directory"));
}

void test_stash_save__skip_submodules(void)
{
	git3_repository *untracked_repo;
	cl_git_pass(git3_repository_init(&untracked_repo, "stash/untracked_repo", false));
	cl_git_mkfile("stash/untracked_repo/content", "stuff");
	git3_repository_free(untracked_repo);

	assert_status(repo, "untracked_repo/", GIT3_STATUS_WT_NEW);

	cl_git_pass(git3_stash_save(
		&stash_tip_oid, repo, signature, NULL, GIT3_STASH_INCLUDE_UNTRACKED));

	assert_status(repo, "untracked_repo/", GIT3_STATUS_WT_NEW);
}

void test_stash_save__deleted_in_index_modified_in_workdir(void)
{
	git3_index *index;

	git3_repository_index(&index, repo);

	cl_git_pass(git3_index_remove_bypath(index, "who"));
	cl_git_pass(git3_index_write(index));

	assert_status(repo, "who", GIT3_STATUS_WT_NEW | GIT3_STATUS_INDEX_DELETED);

	cl_git_pass(git3_stash_save(&stash_tip_oid, repo, signature, NULL, GIT3_STASH_DEFAULT));

	assert_blob_oid("stash@{0}^0:who", "a0400d4954659306a976567af43125a0b1aa8595");
	assert_blob_oid("stash@{0}^2:who", NULL);

	git3_index_free(index);
}

void test_stash_save__option_paths(void)
{
	git3_stash_save_options options = GIT3_STASH_SAVE_OPTIONS_INIT;
	char *paths[2] = { "who", "where" };

	options.paths = (git3_strarray){
		paths,
		2
	};
	options.stasher = signature;
	
	cl_git_pass(git3_stash_save_with_opts(&stash_tip_oid, repo, &options));

	assert_blob_oid("refs/stash:who", "a0400d4954659306a976567af43125a0b1aa8595");
	assert_blob_oid("refs/stash:where", "e3d6434ec12eb76af8dfa843a64ba6ab91014a0b");

	assert_blob_oid("refs/stash:what", "ce013625030ba8dba906f756967f9e9ca394464a");
	assert_blob_oid("refs/stash:how", "ac790413e2d7a26c3767e78c57bb28716686eebc");
	assert_blob_oid("refs/stash:when", NULL);
	assert_blob_oid("refs/stash:why", NULL);
	assert_blob_oid("refs/stash:.gitignore", "ac4d88de61733173d9959e4b77c69b9f17a00980");
	assert_blob_oid("refs/stash:just.ignore", NULL);
}
