#include "clar_libgit3.h"

#include "repository.h"
#include "reflog.h"
#include "reflog_helpers.h"

int reflog_entry_tostr(git3_str *out, const git3_reflog_entry *entry)
{
	char old_oid[GIT3_OID_SHA1_HEXSIZE], new_oid[GIT3_OID_SHA1_HEXSIZE];

	assert(out && entry);

	git3_oid_tostr((char *)&old_oid, GIT3_OID_SHA1_HEXSIZE, git3_reflog_entry_id_old(entry));
	git3_oid_tostr((char *)&new_oid, GIT3_OID_SHA1_HEXSIZE, git3_reflog_entry_id_new(entry));

	return git3_str_printf(out, "%s %s %s %s", old_oid, new_oid, "somesig", git3_reflog_entry_message(entry));
}

size_t reflog_entrycount(git3_repository *repo, const char *name)
{
	git3_reflog *log;
	size_t ret;

	cl_git_pass(git3_reflog_read(&log, repo, name));
	ret = git3_reflog_entrycount(log);
	git3_reflog_free(log);

	return ret;
}

void cl_reflog_check_entry_(git3_repository *repo, const char *reflog, size_t idx,
	const char *old_spec, const char *new_spec,
	const char *email, const char *message,
	const char *file, const char *func, int line)
{
	git3_reflog *log;
	const git3_reflog_entry *entry;
	git3_str result = GIT3_STR_INIT;

	cl_git_pass(git3_reflog_read(&log, repo, reflog));
	entry = git3_reflog_entry_byindex(log, idx);
	if (entry == NULL)
		clar__fail(file, func, line, "Reflog has no such entry", NULL, 1);

	if (old_spec) {
		git3_object *obj = NULL;
		if (git3_revparse_single(&obj, repo, old_spec) == GIT3_OK) {
			if (git3_oid_cmp(git3_object_id(obj), git3_reflog_entry_id_old(entry)) != 0) {
				git3_object__write_oid_header(&result, "\tOld OID: \"", git3_object_id(obj));
				git3_object__write_oid_header(&result, "\" != \"", git3_reflog_entry_id_old(entry));
				git3_str_puts(&result, "\"\n");
			}
			git3_object_free(obj);
		} else {
			git3_oid *oid = git3__calloc(1, sizeof(*oid));
			git3_oid_from_string(oid, old_spec, GIT3_OID_SHA1);
			if (git3_oid_cmp(oid, git3_reflog_entry_id_old(entry)) != 0) {
				git3_object__write_oid_header(&result, "\tOld OID: \"", oid);
				git3_object__write_oid_header(&result, "\" != \"", git3_reflog_entry_id_old(entry));
				git3_str_puts(&result, "\"\n");
			}
			git3__free(oid);
		}
	}
	if (new_spec) {
		git3_object *obj = NULL;
		if (git3_revparse_single(&obj, repo, new_spec) == GIT3_OK) {
			if (git3_oid_cmp(git3_object_id(obj), git3_reflog_entry_id_new(entry)) != 0) {
				git3_object__write_oid_header(&result, "\tNew OID: \"", git3_object_id(obj));
				git3_object__write_oid_header(&result, "\" != \"", git3_reflog_entry_id_new(entry));
				git3_str_puts(&result, "\"\n");
			}
			git3_object_free(obj);
		} else {
			git3_oid *oid = git3__calloc(1, sizeof(*oid));
			git3_oid_from_string(oid, new_spec, GIT3_OID_SHA1);
			if (git3_oid_cmp(oid, git3_reflog_entry_id_new(entry)) != 0) {
				git3_object__write_oid_header(&result, "\tNew OID: \"", oid);
				git3_object__write_oid_header(&result, "\" != \"", git3_reflog_entry_id_new(entry));
				git3_str_puts(&result, "\"\n");
			}
			git3__free(oid);
		}
	}

	if (email && strcmp(email, git3_reflog_entry_committer(entry)->email) != 0)
		git3_str_printf(&result, "\tEmail: \"%s\" != \"%s\"\n", email, git3_reflog_entry_committer(entry)->email);

	if (message) {
		const char *entry_msg = git3_reflog_entry_message(entry);
		if (entry_msg == NULL) entry_msg = "";

		if (entry_msg && strcmp(message, entry_msg) != 0)
			git3_str_printf(&result, "\tMessage: \"%s\" != \"%s\"\n", message, entry_msg);
	}
	if (git3_str_len(&result) != 0)
		clar__fail(file, func, line, "Reflog entry mismatch", git3_str_cstr(&result), 1);

	git3_str_dispose(&result);
	git3_reflog_free(log);
}

void reflog_print(git3_repository *repo, const char *reflog_name)
{
	git3_reflog *reflog;
	size_t idx;
	git3_str out = GIT3_STR_INIT;

	git3_reflog_read(&reflog, repo, reflog_name);

	for (idx = 0; idx < git3_reflog_entrycount(reflog); idx++) {
		const git3_reflog_entry *entry = git3_reflog_entry_byindex(reflog, idx);
		reflog_entry_tostr(&out, entry);
		git3_str_putc(&out, '\n');
	}

	fprintf(stderr, "%s", git3_str_cstr(&out));
	git3_str_dispose(&out);
	git3_reflog_free(reflog);
}
