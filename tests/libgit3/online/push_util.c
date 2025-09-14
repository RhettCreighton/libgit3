#include "clar_libgit3.h"
#include "vector.h"
#include "push_util.h"

void updated_tip_free(updated_tip *t)
{
	git3__free(t->name);
	git3__free(t);
}

static void push_status_free(push_status *s)
{
	git3__free(s->ref);
	git3__free(s->msg);
	git3__free(s);
}

void record_callbacks_data_clear(record_callbacks_data *data)
{
	size_t i;
	updated_tip *tip;
	push_status *status;

	git3_vector_foreach(&data->updated_tips, i, tip)
		updated_tip_free(tip);

	git3_vector_dispose(&data->updated_tips);

	git3_vector_foreach(&data->statuses, i, status)
		push_status_free(status);

	git3_vector_dispose(&data->statuses);

	data->pack_progress_calls = 0;
	data->transfer_progress_calls = 0;
}

int record_update_refs_cb(const char *refname, const git3_oid *a, const git3_oid *b, git3_refspec *spec, void *data)
{
	updated_tip *t;
	record_callbacks_data *record_data = (record_callbacks_data *)data;

	GIT3_UNUSED(spec);

	cl_assert(t = git3__calloc(1, sizeof(*t)));

	cl_assert(t->name = git3__strdup(refname));
	git3_oid_cpy(&t->old_oid, a);
	git3_oid_cpy(&t->new_oid, b);

	git3_vector_insert(&record_data->updated_tips, t);

	return 0;
}

int create_deletion_refspecs(git3_vector *out, const git3_remote_head **heads, size_t heads_len)
{
	git3_str del_spec = GIT3_STR_INIT;
	int valid;
	size_t i;

	for (i = 0; i < heads_len; i++) {
		const git3_remote_head *head = heads[i];
		/* Ignore malformed ref names (which also saves us from tag^{} */
		cl_git_pass(git3_reference_name_is_valid(&valid, head->name));
		if (!valid)
			return 0;

		/* Create a refspec that deletes a branch in the remote */
		if (strcmp(head->name, "refs/heads/master")) {
			cl_git_pass(git3_str_putc(&del_spec, ':'));
			cl_git_pass(git3_str_puts(&del_spec, head->name));
			cl_git_pass(git3_vector_insert(out, git3_str_detach(&del_spec)));
		}
	}

	return 0;
}

int record_ref_cb(git3_remote_head *head, void *payload)
{
	git3_vector *refs = (git3_vector *) payload;
	return git3_vector_insert(refs, head);
}

void verify_remote_refs(const git3_remote_head *actual_refs[], size_t actual_refs_len, const expected_ref expected_refs[], size_t expected_refs_len)
{
	size_t i, j = 0;
	git3_str msg = GIT3_STR_INIT;
	const git3_remote_head *actual;
	char *oid_str;
	bool master_present = false;

	/* We don't care whether "master" is present on the other end or not */
	for (i = 0; i < actual_refs_len; i++) {
		actual = actual_refs[i];
		if (!strcmp(actual->name, "refs/heads/master")) {
			master_present = true;
			break;
		}
	}

	if (expected_refs_len + (master_present ? 1 : 0) != actual_refs_len)
		goto failed;

	for (i = 0; i < actual_refs_len; i++) {
		actual = actual_refs[i];
		if (master_present && !strcmp(actual->name, "refs/heads/master"))
			continue;

		if (strcmp(expected_refs[j].name, actual->name) ||
			git3_oid_cmp(expected_refs[j].oid, &actual->oid))
			goto failed;

		j++;
	}

	return;

failed:
	git3_str_puts(&msg, "Expected and actual refs differ:\nEXPECTED:\n");

	for(i = 0; i < expected_refs_len; i++) {
		oid_str = git3_oid_tostr_s(expected_refs[i].oid);
		cl_git_pass(git3_str_printf(&msg, "%s = %s\n", expected_refs[i].name, oid_str));
	}

	git3_str_puts(&msg, "\nACTUAL:\n");
	for (i = 0; i < actual_refs_len; i++) {
		actual = actual_refs[i];
		if (master_present && !strcmp(actual->name, "refs/heads/master"))
			continue;

		oid_str = git3_oid_tostr_s(&actual->oid);
		cl_git_pass(git3_str_printf(&msg, "%s = %s\n", actual->name, oid_str));
	}

	cl_fail(git3_str_cstr(&msg));

	git3_str_dispose(&msg);
}
