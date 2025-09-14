#include "clar_libgit3.h"

#include "notes.h"

static git3_repository *_repo;
static git3_note *_note;
static git3_signature *_sig;
static git3_config *_cfg;

void test_notes_notesref__initialize(void)
{
	cl_fixture_sandbox("testrepo.git");
	cl_git_pass(git3_repository_open(&_repo, "testrepo.git"));
}

void test_notes_notesref__cleanup(void)
{
	git3_note_free(_note);
	_note = NULL;

	git3_signature_free(_sig);
	_sig = NULL;

	git3_config_free(_cfg);
	_cfg = NULL;

	git3_repository_free(_repo);
	_repo = NULL;

	cl_fixture_cleanup("testrepo.git");
}

void test_notes_notesref__config_corenotesref(void)
{
	git3_oid oid, note_oid;
	git3_buf default_ref = GIT3_BUF_INIT;

	cl_git_pass(git3_signature_now(&_sig, "alice", "alice@example.com"));
	cl_git_pass(git3_oid_from_string(&oid, "8496071c1b46c854b31185ea97743be6a8774479", GIT3_OID_SHA1));

	cl_git_pass(git3_repository_config(&_cfg, _repo));

	cl_git_pass(git3_config_set_string(_cfg, "core.notesRef", "refs/notes/mydefaultnotesref"));

	cl_git_pass(git3_note_create(&note_oid, _repo, NULL, _sig, _sig, &oid, "test123test\n", 0));

	cl_git_pass(git3_note_read(&_note, _repo, NULL, &oid));
	cl_assert_equal_s("test123test\n", git3_note_message(_note));
	cl_assert_equal_oid(git3_note_id(_note), &note_oid);

	git3_note_free(_note);

	cl_git_pass(git3_note_read(&_note, _repo, "refs/notes/mydefaultnotesref", &oid));
	cl_assert_equal_s("test123test\n", git3_note_message(_note));
	cl_assert_equal_oid(git3_note_id(_note), &note_oid);

	cl_git_pass(git3_note_default_ref(&default_ref, _repo));
	cl_assert_equal_s("refs/notes/mydefaultnotesref", default_ref.ptr);
	git3_buf_dispose(&default_ref);

	cl_git_pass(git3_config_delete_entry(_cfg, "core.notesRef"));

	cl_git_pass(git3_note_default_ref(&default_ref, _repo));
	cl_assert_equal_s(GIT3_NOTES_DEFAULT_REF, default_ref.ptr);

	git3_buf_dispose(&default_ref);
}
