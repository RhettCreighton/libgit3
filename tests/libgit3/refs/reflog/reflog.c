#include "clar_libgit3.h"

#include "futils.h"
#include "git3/reflog.h"
#include "reflog.h"

static const char *new_ref = "refs/heads/test-reflog";
static const char *current_master_tip = "a65fedf39aefe402d3bb6e24df4d4f5fe4547750";
#define commit_msg "commit: bla bla"

static git3_repository *g_repo;


/* helpers */
static void assert_signature(const git3_signature *expected, const git3_signature *actual)
{
	cl_assert(actual);
	cl_assert_equal_s(expected->name, actual->name);
	cl_assert_equal_s(expected->email, actual->email);
	cl_assert(expected->when.offset == actual->when.offset);
	cl_assert(expected->when.time == actual->when.time);
}


/* Fixture setup and teardown */
void test_refs_reflog_reflog__initialize(void)
{
	g_repo = cl_git_sandbox_init("testrepo.git");
}

void test_refs_reflog_reflog__cleanup(void)
{
	cl_git_sandbox_cleanup();
}

static void assert_appends(const git3_signature *committer, const git3_oid *oid)
{
	git3_repository *repo2;
	git3_reference *lookedup_ref;
	git3_reflog *reflog;
	const git3_reflog_entry *entry;

	/* Reopen a new instance of the repository */
	cl_git_pass(git3_repository_open(&repo2, "testrepo.git"));

	/* Lookup the previously created branch */
	cl_git_pass(git3_reference_lookup(&lookedup_ref, repo2, new_ref));

	/* Read and parse the reflog for this branch */
	cl_git_pass(git3_reflog_read(&reflog, repo2, new_ref));
	cl_assert_equal_i(3, (int)git3_reflog_entrycount(reflog));

	/* The first one was the creation of the branch */
	entry = git3_reflog_entry_byindex(reflog, 2);
	cl_assert(git3_oid_streq(&entry->oid_old, GIT3_OID_SHA1_HEXZERO) == 0);

	entry = git3_reflog_entry_byindex(reflog, 1);
	assert_signature(committer, entry->committer);
	cl_assert(git3_oid_cmp(oid, &entry->oid_old) == 0);
	cl_assert(git3_oid_cmp(oid, &entry->oid_cur) == 0);
	cl_assert(entry->msg == NULL);

	entry = git3_reflog_entry_byindex(reflog, 0);
	assert_signature(committer, entry->committer);
	cl_assert(git3_oid_cmp(oid, &entry->oid_cur) == 0);
	cl_assert_equal_s(commit_msg, entry->msg);

	git3_reflog_free(reflog);
	git3_repository_free(repo2);

	git3_reference_free(lookedup_ref);
}

void test_refs_reflog_reflog__append_then_read(void)
{
	/* write a reflog for a given reference and ensure it can be read back */
	git3_reference *ref;
	git3_oid oid;
	git3_signature *committer;
	git3_reflog *reflog;

	/* Create a new branch pointing at the HEAD */
	git3_oid_from_string(&oid, current_master_tip, GIT3_OID_SHA1);
	cl_git_pass(git3_reference_create(&ref, g_repo, new_ref, &oid, 0, NULL));
	git3_reference_free(ref);

	cl_git_pass(git3_signature_now(&committer, "foo", "foo@bar"));

	cl_git_pass(git3_reflog_read(&reflog, g_repo, new_ref));
	cl_git_pass(git3_reflog_append(reflog, &oid, committer, NULL));
	cl_git_pass(git3_reflog_append(reflog, &oid, committer, commit_msg "\n"));
	cl_git_pass(git3_reflog_write(reflog));

	assert_appends(committer, &oid);

	git3_reflog_free(reflog);
	git3_signature_free(committer);
}

void test_refs_reflog_reflog__renaming_the_reference_moves_the_reflog(void)
{
	git3_reference *master, *new_master;
	git3_str master_log_path = GIT3_STR_INIT, moved_log_path = GIT3_STR_INIT;

	git3_str_joinpath(&master_log_path, git3_repository_path(g_repo), GIT3_REFLOG_DIR);
	git3_str_puts(&moved_log_path, git3_str_cstr(&master_log_path));
	git3_str_joinpath(&master_log_path, git3_str_cstr(&master_log_path), "refs/heads/master");
	git3_str_joinpath(&moved_log_path, git3_str_cstr(&moved_log_path), "refs/moved");

	cl_assert_equal_i(true, git3_fs_path_isfile(git3_str_cstr(&master_log_path)));
	cl_assert_equal_i(false, git3_fs_path_isfile(git3_str_cstr(&moved_log_path)));

	cl_git_pass(git3_reference_lookup(&master, g_repo, "refs/heads/master"));
	cl_git_pass(git3_reference_rename(&new_master, master, "refs/moved", 0, NULL));
	git3_reference_free(master);

	cl_assert_equal_i(false, git3_fs_path_isfile(git3_str_cstr(&master_log_path)));
	cl_assert_equal_i(true, git3_fs_path_isfile(git3_str_cstr(&moved_log_path)));

	git3_reference_free(new_master);
	git3_str_dispose(&moved_log_path);
	git3_str_dispose(&master_log_path);
}

void test_refs_reflog_reflog__deleting_the_reference_deletes_the_reflog(void)
{
	git3_reference *master;
	git3_str master_log_path = GIT3_STR_INIT;

	git3_str_joinpath(&master_log_path, git3_repository_path(g_repo), GIT3_REFLOG_DIR);
	git3_str_joinpath(&master_log_path, git3_str_cstr(&master_log_path), "refs/heads/master");

	cl_assert_equal_i(true, git3_fs_path_isfile(git3_str_cstr(&master_log_path)));

	cl_git_pass(git3_reference_lookup(&master, g_repo, "refs/heads/master"));
	cl_git_pass(git3_reference_delete(master));
	git3_reference_free(master);

	cl_assert_equal_i(false, git3_fs_path_isfile(git3_str_cstr(&master_log_path)));
	git3_str_dispose(&master_log_path);
}

void test_refs_reflog_reflog__removes_empty_reflog_dir(void)
{
	git3_reference *ref;
	git3_str log_path = GIT3_STR_INIT;
	git3_oid id;

	/* Create a new branch pointing at the HEAD */
	git3_oid_from_string(&id, current_master_tip, GIT3_OID_SHA1);
	cl_git_pass(git3_reference_create(&ref, g_repo, "refs/heads/new-dir/new-head", &id, 0, NULL));

	git3_str_joinpath(&log_path, git3_repository_path(g_repo), GIT3_REFLOG_DIR);
	git3_str_joinpath(&log_path, git3_str_cstr(&log_path), "refs/heads/new-dir/new-head");

	cl_assert_equal_i(true, git3_fs_path_isfile(git3_str_cstr(&log_path)));

	cl_git_pass(git3_reference_delete(ref));
	git3_reference_free(ref);

	/* new ref creation should succeed since new-dir is empty */
	git3_oid_from_string(&id, current_master_tip, GIT3_OID_SHA1);
	cl_git_pass(git3_reference_create(&ref, g_repo, "refs/heads/new-dir", &id, 0, NULL));
	git3_reference_free(ref);

	git3_str_dispose(&log_path);
}

void test_refs_reflog_reflog__fails_gracefully_on_nonempty_reflog_dir(void)
{
	git3_reference *ref;
	git3_str log_path = GIT3_STR_INIT;
	git3_oid id;

	/* Create a new branch pointing at the HEAD */
	git3_oid_from_string(&id, current_master_tip, GIT3_OID_SHA1);
	cl_git_pass(git3_reference_create(&ref, g_repo, "refs/heads/new-dir/new-head", &id, 0, NULL));
	git3_reference_free(ref);

	git3_str_joinpath(&log_path, git3_repository_path(g_repo), GIT3_REFLOG_DIR);
	git3_str_joinpath(&log_path, git3_str_cstr(&log_path), "refs/heads/new-dir/new-head");

	cl_assert_equal_i(true, git3_fs_path_isfile(git3_str_cstr(&log_path)));

	/* delete the ref manually, leave the reflog */
	cl_must_pass(p_unlink("testrepo.git/refs/heads/new-dir/new-head"));

	/* new ref creation should fail since new-dir contains reflogs still */
	git3_oid_from_string(&id, current_master_tip, GIT3_OID_SHA1);
	cl_git_fail_with(GIT3_EDIRECTORY, git3_reference_create(&ref, g_repo, "refs/heads/new-dir", &id, 0, NULL));
	git3_reference_free(ref);

	git3_str_dispose(&log_path);
}

static void assert_has_reflog(bool expected_result, const char *name)
{
	cl_assert_equal_i(expected_result, git3_reference_has_log(g_repo, name));
}

void test_refs_reflog_reflog__reference_has_reflog(void)
{
	assert_has_reflog(true, "HEAD");
	assert_has_reflog(true, "refs/heads/master");
	assert_has_reflog(false, "refs/heads/subtrees");
}

void test_refs_reflog_reflog__reading_the_reflog_from_a_reference_with_no_log_returns_an_empty_one(void)
{
	git3_reflog *reflog;
	const char *refname = "refs/heads/subtrees";
	git3_str subtrees_log_path = GIT3_STR_INIT;

	git3_str_join_n(&subtrees_log_path, '/', 3, git3_repository_path(g_repo), GIT3_REFLOG_DIR, refname);
	cl_assert_equal_i(false, git3_fs_path_isfile(git3_str_cstr(&subtrees_log_path)));

	cl_git_pass(git3_reflog_read(&reflog, g_repo, refname));

	cl_assert_equal_i(0, (int)git3_reflog_entrycount(reflog));

	git3_reflog_free(reflog);
	git3_str_dispose(&subtrees_log_path);
}

void test_refs_reflog_reflog__reading_a_reflog_with_invalid_format_succeeds(void)
{
	git3_reflog *reflog;
	const char *refname = "refs/heads/newline";
	const char *refmessage =
		"Reflog*message with a newline and enough content after it to pass the GIT3_REFLOG_SIZE_MIN check inside reflog_parse.";
	const git3_reflog_entry *entry;
	git3_reference *ref;
	git3_oid id;
	git3_str logpath = GIT3_STR_INIT, logcontents = GIT3_STR_INIT;
	char *star;

	/* Create a new branch. */
	cl_git_pass(git3_oid_from_string(&id, current_master_tip, GIT3_OID_SHA1));
	cl_git_pass(git3_reference_create(&ref, g_repo, refname, &id, 1, refmessage));

	/*
	 * Corrupt the branch reflog by introducing a newline inside the reflog message.
	 * We do this by replacing '*' with '\n'
	 */
	cl_git_pass(git3_str_join_n(&logpath, '/', 3, git3_repository_path(g_repo), GIT3_REFLOG_DIR, refname));
	cl_git_pass(git3_futils_readbuffer(&logcontents, git3_str_cstr(&logpath)));
	cl_assert((star = strchr(git3_str_cstr(&logcontents), '*')) != NULL);
	*star = '\n';
	cl_git_rewritefile(git3_str_cstr(&logpath), git3_str_cstr(&logcontents));

	/*
	 * Confirm that the file was rewritten successfully
	 * and now contains a '\n' in the expected location
	 */
	cl_git_pass(git3_futils_readbuffer(&logcontents, git3_str_cstr(&logpath)));
	cl_assert(strstr(git3_str_cstr(&logcontents), "Reflog\nmessage") != NULL);

	cl_git_pass(git3_reflog_read(&reflog, g_repo, refname));
	cl_assert(entry = git3_reflog_entry_byindex(reflog, 0));
	cl_assert_equal_s(git3_reflog_entry_message(entry), "Reflog");

	git3_reference_free(ref);
	git3_reflog_free(reflog);
	git3_str_dispose(&logpath);
	git3_str_dispose(&logcontents);
}

void test_refs_reflog_reflog__cannot_write_a_moved_reflog(void)
{
	git3_reference *master, *new_master;
	git3_str master_log_path = GIT3_STR_INIT, moved_log_path = GIT3_STR_INIT;
	git3_reflog *reflog;

	cl_git_pass(git3_reference_lookup(&master, g_repo, "refs/heads/master"));
	cl_git_pass(git3_reflog_read(&reflog, g_repo, "refs/heads/master"));

	cl_git_pass(git3_reflog_write(reflog));

	cl_git_pass(git3_reference_rename(&new_master, master, "refs/moved", 0, NULL));
	git3_reference_free(master);

	cl_git_fail(git3_reflog_write(reflog));

	git3_reflog_free(reflog);
	git3_reference_free(new_master);
	git3_str_dispose(&moved_log_path);
	git3_str_dispose(&master_log_path);
}

void test_refs_reflog_reflog__renaming_with_an_invalid_name_returns_EINVALIDSPEC(void)
{
	cl_assert_equal_i(GIT3_EINVALIDSPEC,
			  git3_reflog_rename(g_repo, "refs/heads/master", "refs/heads/Inv@{id"));
}

void test_refs_reflog_reflog__write_only_std_locations(void)
{
	git3_reference *ref;
	git3_oid id;

	git3_oid_from_string(&id, current_master_tip, GIT3_OID_SHA1);

	cl_git_pass(git3_reference_create(&ref, g_repo, "refs/heads/foo", &id, 1, NULL));
	git3_reference_free(ref);
	cl_git_pass(git3_reference_create(&ref, g_repo, "refs/tags/foo", &id, 1, NULL));
	git3_reference_free(ref);
	cl_git_pass(git3_reference_create(&ref, g_repo, "refs/notes/foo", &id, 1, NULL));
	git3_reference_free(ref);

	assert_has_reflog(true, "refs/heads/foo");
	assert_has_reflog(false, "refs/tags/foo");
	assert_has_reflog(true, "refs/notes/foo");

}

void test_refs_reflog_reflog__write_when_explicitly_active(void)
{
	git3_reference *ref;
	git3_oid id;

	git3_oid_from_string(&id, current_master_tip, GIT3_OID_SHA1);
	git3_reference_ensure_log(g_repo, "refs/tags/foo");

	cl_git_pass(git3_reference_create(&ref, g_repo, "refs/tags/foo", &id, 1, NULL));
	git3_reference_free(ref);
	assert_has_reflog(true, "refs/tags/foo");
}

void test_refs_reflog_reflog__append_to_HEAD_when_changing_current_branch(void)
{
	size_t nlogs, nlogs_after;
	git3_reference *ref;
	git3_reflog *log;
	git3_oid id;

	cl_git_pass(git3_reflog_read(&log, g_repo, "HEAD"));
	nlogs = git3_reflog_entrycount(log);
	git3_reflog_free(log);

	/* Move it back */
	git3_oid_from_string(&id, "be3563ae3f795b2b4353bcce3a527ad0a4f7f644", GIT3_OID_SHA1);
	cl_git_pass(git3_reference_create(&ref, g_repo, "refs/heads/master", &id, 1, NULL));
	git3_reference_free(ref);

	cl_git_pass(git3_reflog_read(&log, g_repo, "HEAD"));
	nlogs_after = git3_reflog_entrycount(log);
	git3_reflog_free(log);

	cl_assert_equal_i(nlogs_after, nlogs + 1);
}

void test_refs_reflog_reflog__do_not_append_when_no_update(void)
{
	size_t nlogs, nlogs_after;
	git3_reference *ref, *ref2;
	git3_reflog *log;

	cl_git_pass(git3_reflog_read(&log, g_repo, "HEAD"));
	nlogs = git3_reflog_entrycount(log);
	git3_reflog_free(log);

	cl_git_pass(git3_reference_lookup(&ref, g_repo, "refs/heads/master"));
	cl_git_pass(git3_reference_create(&ref2, g_repo, "refs/heads/master",
					 git3_reference_target(ref), 1, NULL));

	git3_reference_free(ref);
	git3_reference_free(ref2);

	cl_git_pass(git3_reflog_read(&log, g_repo, "HEAD"));
	nlogs_after = git3_reflog_entrycount(log);
	git3_reflog_free(log);

	cl_assert_equal_i(nlogs_after, nlogs);
}

static void assert_no_reflog_update(void)
{
	size_t nlogs, nlogs_after;
	size_t nlogs_master, nlogs_master_after;
	git3_reference *ref;
	git3_reflog *log;
	git3_oid id;

	cl_git_pass(git3_reflog_read(&log, g_repo, "HEAD"));
	nlogs = git3_reflog_entrycount(log);
	git3_reflog_free(log);

	cl_git_pass(git3_reflog_read(&log, g_repo, "refs/heads/master"));
	nlogs_master = git3_reflog_entrycount(log);
	git3_reflog_free(log);

	/* Move it back */
	git3_oid_from_string(&id, "be3563ae3f795b2b4353bcce3a527ad0a4f7f644", GIT3_OID_SHA1);
	cl_git_pass(git3_reference_create(&ref, g_repo, "refs/heads/master", &id, 1, NULL));
	git3_reference_free(ref);

	cl_git_pass(git3_reflog_read(&log, g_repo, "HEAD"));
	nlogs_after = git3_reflog_entrycount(log);
	git3_reflog_free(log);

	cl_assert_equal_i(nlogs_after, nlogs);

	cl_git_pass(git3_reflog_read(&log, g_repo, "refs/heads/master"));
	nlogs_master_after = git3_reflog_entrycount(log);
	git3_reflog_free(log);

	cl_assert_equal_i(nlogs_after, nlogs);
	cl_assert_equal_i(nlogs_master_after, nlogs_master);

}

void test_refs_reflog_reflog__logallrefupdates_bare_set_false(void)
{
	git3_config *config;

	cl_git_pass(git3_repository_config(&config, g_repo));
	cl_git_pass(git3_config_set_bool(config, "core.logallrefupdates", false));
	git3_config_free(config);

	assert_no_reflog_update();
}

void test_refs_reflog_reflog__logallrefupdates_bare_set_always(void)
{
	git3_config *config;
	git3_reference *ref;
	git3_reflog *log;
	git3_oid id;

	cl_git_pass(git3_repository_config(&config, g_repo));
	cl_git_pass(git3_config_set_string(config, "core.logallrefupdates", "always"));
	git3_config_free(config);

	git3_oid_from_string(&id, "be3563ae3f795b2b4353bcce3a527ad0a4f7f644", GIT3_OID_SHA1);
	cl_git_pass(git3_reference_create(&ref, g_repo, "refs/bork", &id, 1, "message"));

	cl_git_pass(git3_reflog_read(&log, g_repo, "refs/bork"));
	cl_assert_equal_i(1, git3_reflog_entrycount(log));
	cl_assert_equal_s("message", git3_reflog_entry_byindex(log, 0)->msg);

	git3_reflog_free(log);
	git3_reference_free(ref);
}

void test_refs_reflog_reflog__logallrefupdates_bare_unset(void)
{
	git3_config *config;

	cl_git_pass(git3_repository_config(&config, g_repo));
	cl_git_pass(git3_config_delete_entry(config, "core.logallrefupdates"));
	git3_config_free(config);

	assert_no_reflog_update();
}

void test_refs_reflog_reflog__logallrefupdates_nonbare_set_false(void)
{
	git3_config *config;

	cl_git_sandbox_cleanup();
	g_repo = cl_git_sandbox_init("testrepo");


	cl_git_pass(git3_repository_config(&config, g_repo));
	cl_git_pass(git3_config_set_bool(config, "core.logallrefupdates", false));
	git3_config_free(config);

	assert_no_reflog_update();
}
