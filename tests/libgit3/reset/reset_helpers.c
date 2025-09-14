#include "clar_libgit3.h"
#include "reset_helpers.h"

void reflog_check(git3_repository *repo, const char *refname,
		size_t exp_count, const char *exp_email, const char *exp_msg)
{
	git3_reflog *log;
	const git3_reflog_entry *entry;

	GIT3_UNUSED(exp_email);

	cl_git_pass(git3_reflog_read(&log, repo, refname));
	cl_assert_equal_i(exp_count, git3_reflog_entrycount(log));
	entry = git3_reflog_entry_byindex(log, 0);

	if (exp_msg)
		cl_assert_equal_s(exp_msg, git3_reflog_entry_message(entry));

	git3_reflog_free(log);
}
