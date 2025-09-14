/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "commit.h"

#include "git3/common.h"
#include "git3/object.h"
#include "git3/repository.h"
#include "git3/signature.h"
#include "git3/mailmap.h"
#include "git3/sys/commit.h"

#include "buf.h"
#include "odb.h"
#include "commit.h"
#include "signature.h"
#include "refs.h"
#include "object.h"
#include "array.h"
#include "oidarray.h"
#include "grafts.h"

void git3_commit__free(void *_commit)
{
	git3_commit *commit = _commit;

	git3_array_clear(commit->parent_ids);

	git3_signature_free(commit->author);
	git3_signature_free(commit->committer);

	git3__free(commit->raw_header);
	git3__free(commit->raw_message);
	git3__free(commit->message_encoding);
	git3__free(commit->summary);
	git3__free(commit->body);

	git3__free(commit);
}

static int git3_commit__create_buffer_internal(
	git3_str *out,
	const git3_signature *author,
	const git3_signature *committer,
	const char *message_encoding,
	const char *message,
	const git3_oid *tree,
	git3_array_oid_t *parents)
{
	size_t i = 0;
	const git3_oid *parent;

	GIT3_ASSERT_ARG(out);
	GIT3_ASSERT_ARG(tree);

	if (git3_object__write_oid_header(out, "tree ", tree) < 0)
		goto on_error;

	for (i = 0; i < git3_array_size(*parents); i++) {
		parent = git3_array_get(*parents, i);
		if (git3_object__write_oid_header(out, "parent ", parent) < 0)
			goto on_error;
	}

	git3_signature__writebuf(out, "author ", author);
	git3_signature__writebuf(out, "committer ", committer);

	if (message_encoding != NULL)
		git3_str_printf(out, "encoding %s\n", message_encoding);

	git3_str_putc(out, '\n');

	if (git3_str_puts(out, message) < 0)
		goto on_error;

	return 0;

on_error:
	git3_str_dispose(out);
	return -1;
}

static int validate_tree_and_parents(git3_array_oid_t *parents, git3_repository *repo, const git3_oid *tree,
	git3_commit_parent_callback parent_cb, void *parent_payload,
	const git3_oid *current_id, bool validate)
{
	size_t i;
	int error;
	git3_oid *parent_cpy;
	const git3_oid *parent;

	if (validate && !git3_object__is_valid(repo, tree, GIT3_OBJECT_TREE))
		return -1;

	i = 0;
	while ((parent = parent_cb(i, parent_payload)) != NULL) {
		if (validate && !git3_object__is_valid(repo, parent, GIT3_OBJECT_COMMIT)) {
			error = -1;
			goto on_error;
		}

		parent_cpy = git3_array_alloc(*parents);
		GIT3_ERROR_CHECK_ALLOC(parent_cpy);

		git3_oid_cpy(parent_cpy, parent);
		i++;
	}

	if (current_id && (parents->size == 0 || git3_oid_cmp(current_id, git3_array_get(*parents, 0)))) {
		git3_error_set(GIT3_ERROR_OBJECT, "failed to create commit: current tip is not the first parent");
		error = GIT3_EMODIFIED;
		goto on_error;
	}

	return 0;

on_error:
	git3_array_clear(*parents);
	return error;
}

static int git3_commit__create_internal(
	git3_oid *id,
	git3_repository *repo,
	const char *update_ref,
	const git3_signature *author,
	const git3_signature *committer,
	const char *message_encoding,
	const char *message,
	const git3_oid *tree,
	git3_commit_parent_callback parent_cb,
	void *parent_payload,
	bool validate)
{
	int error;
	git3_odb *odb;
	git3_reference *ref = NULL;
	git3_str buf = GIT3_STR_INIT;
	const git3_oid *current_id = NULL;
	git3_array_oid_t parents = GIT3_ARRAY_INIT;

	if (update_ref) {
		error = git3_reference_lookup_resolved(&ref, repo, update_ref, 10);
		if (error < 0 && error != GIT3_ENOTFOUND)
			return error;
	}
	git3_error_clear();

	if (ref)
		current_id = git3_reference_target(ref);

	if ((error = validate_tree_and_parents(&parents, repo, tree, parent_cb, parent_payload, current_id, validate)) < 0)
		goto cleanup;

	error = git3_commit__create_buffer_internal(&buf, author, committer,
		message_encoding, message, tree,
		&parents);

	if (error < 0)
		goto cleanup;

	if (git3_repository_odb__weakptr(&odb, repo) < 0)
		goto cleanup;

	if (git3_odb__freshen(odb, tree) < 0)
		goto cleanup;

	if (git3_odb_write(id, odb, buf.ptr, buf.size, GIT3_OBJECT_COMMIT) < 0)
		goto cleanup;


	if (update_ref != NULL) {
		error = git3_reference__update_for_commit(
			repo, ref, update_ref, id, "commit");
		goto cleanup;
	}

cleanup:
	git3_array_clear(parents);
	git3_reference_free(ref);
	git3_str_dispose(&buf);
	return error;
}

int git3_commit_create_from_callback(
	git3_oid *id,
	git3_repository *repo,
	const char *update_ref,
	const git3_signature *author,
	const git3_signature *committer,
	const char *message_encoding,
	const char *message,
	const git3_oid *tree,
	git3_commit_parent_callback parent_cb,
	void *parent_payload)
{
	return git3_commit__create_internal(
		id, repo, update_ref, author, committer, message_encoding, message,
		tree, parent_cb, parent_payload, true);
}

typedef struct {
	size_t total;
	va_list args;
} commit_parent_varargs;

static const git3_oid *commit_parent_from_varargs(size_t curr, void *payload)
{
	commit_parent_varargs *data = payload;
	const git3_commit *commit;
	if (curr >= data->total)
		return NULL;
	commit = va_arg(data->args, const git3_commit *);
	return commit ? git3_commit_id(commit) : NULL;
}

int git3_commit_create_v(
	git3_oid *id,
	git3_repository *repo,
	const char *update_ref,
	const git3_signature *author,
	const git3_signature *committer,
	const char *message_encoding,
	const char *message,
	const git3_tree *tree,
	size_t parent_count,
	...)
{
	int error = 0;
	commit_parent_varargs data;

	GIT3_ASSERT_ARG(tree);
	GIT3_ASSERT_ARG(git3_tree_owner(tree) == repo);

	data.total = parent_count;
	va_start(data.args, parent_count);

	error = git3_commit__create_internal(
		id, repo, update_ref, author, committer,
		message_encoding, message, git3_tree_id(tree),
		commit_parent_from_varargs, &data, false);

	va_end(data.args);
	return error;
}

typedef struct {
	size_t total;
	const git3_oid **parents;
} commit_parent_oids;

static const git3_oid *commit_parent_from_ids(size_t curr, void *payload)
{
	commit_parent_oids *data = payload;
	return (curr < data->total) ? data->parents[curr] : NULL;
}

int git3_commit_create_from_ids(
	git3_oid *id,
	git3_repository *repo,
	const char *update_ref,
	const git3_signature *author,
	const git3_signature *committer,
	const char *message_encoding,
	const char *message,
	const git3_oid *tree,
	size_t parent_count,
	const git3_oid *parents[])
{
	commit_parent_oids data = { parent_count, parents };

	return git3_commit__create_internal(
		id, repo, update_ref, author, committer,
		message_encoding, message, tree,
		commit_parent_from_ids, &data, true);
}

typedef struct {
	size_t total;
	const git3_commit **parents;
	git3_repository *repo;
} commit_parent_data;

static const git3_oid *commit_parent_from_array(size_t curr, void *payload)
{
	commit_parent_data *data = payload;
	const git3_commit *commit;
	if (curr >= data->total)
		return NULL;
	commit = data->parents[curr];
	if (git3_commit_owner(commit) != data->repo)
		return NULL;
	return git3_commit_id(commit);
}

int git3_commit_create(
	git3_oid *id,
	git3_repository *repo,
	const char *update_ref,
	const git3_signature *author,
	const git3_signature *committer,
	const char *message_encoding,
	const char *message,
	const git3_tree *tree,
	size_t parent_count,
	const git3_commit *parents[])
{
	commit_parent_data data = { parent_count, parents, repo };

	GIT3_ASSERT_ARG(tree);
	GIT3_ASSERT_ARG(git3_tree_owner(tree) == repo);

	return git3_commit__create_internal(
		id, repo, update_ref, author, committer,
		message_encoding, message, git3_tree_id(tree),
		commit_parent_from_array, &data, false);
}

static const git3_oid *commit_parent_for_amend(size_t curr, void *payload)
{
	const git3_commit *commit_to_amend = payload;
	if (curr >= git3_array_size(commit_to_amend->parent_ids))
		return NULL;
	return git3_array_get(commit_to_amend->parent_ids, curr);
}

int git3_commit_amend(
	git3_oid *id,
	const git3_commit *commit_to_amend,
	const char *update_ref,
	const git3_signature *author,
	const git3_signature *committer,
	const char *message_encoding,
	const char *message,
	const git3_tree *tree)
{
	git3_repository *repo;
	git3_oid tree_id;
	git3_reference *ref;
	int error;

	GIT3_ASSERT_ARG(id);
	GIT3_ASSERT_ARG(commit_to_amend);

	repo = git3_commit_owner(commit_to_amend);

	if (!author)
		author = git3_commit_author(commit_to_amend);
	if (!committer)
		committer = git3_commit_committer(commit_to_amend);
	if (!message_encoding)
		message_encoding = git3_commit_message_encoding(commit_to_amend);
	if (!message)
		message = git3_commit_message(commit_to_amend);

	if (!tree) {
		git3_tree *old_tree;
		GIT3_ERROR_CHECK_ERROR( git3_commit_tree(&old_tree, commit_to_amend) );
		git3_oid_cpy(&tree_id, git3_tree_id(old_tree));
		git3_tree_free(old_tree);
	} else {
		GIT3_ASSERT_ARG(git3_tree_owner(tree) == repo);
		git3_oid_cpy(&tree_id, git3_tree_id(tree));
	}

	if (update_ref) {
		if ((error = git3_reference_lookup_resolved(&ref, repo, update_ref, 5)) < 0)
			return error;

		if (git3_oid_cmp(git3_commit_id(commit_to_amend), git3_reference_target(ref))) {
			git3_reference_free(ref);
			git3_error_set(GIT3_ERROR_REFERENCE, "commit to amend is not the tip of the given branch");
			return -1;
		}
	}

	error = git3_commit__create_internal(
		id, repo, NULL, author, committer, message_encoding, message,
		&tree_id, commit_parent_for_amend, (void *)commit_to_amend, false);

	if (!error && update_ref) {
		error = git3_reference__update_for_commit(
			repo, ref, NULL, id, "commit");
		git3_reference_free(ref);
	}

	return error;
}

static int commit_parse(
	git3_commit *commit,
	const char *data,
	size_t size,
	git3_commit__parse_options *opts)
{
	const char *buffer_start = data, *buffer;
	const char *buffer_end = buffer_start + size;
	git3_oid parent_id;
	size_t header_len;
	git3_signature dummy_sig;
	int error;

	GIT3_ASSERT_ARG(commit);
	GIT3_ASSERT_ARG(data);
	GIT3_ASSERT_ARG(opts);

	buffer = buffer_start;

	/* Allocate for one, which will allow not to realloc 90% of the time  */
	git3_array_init_to_size(commit->parent_ids, 1);
	GIT3_ERROR_CHECK_ARRAY(commit->parent_ids);

	/* The tree is always the first field */
	if (!(opts->flags & GIT3_COMMIT_PARSE_QUICK)) {
		if (git3_object__parse_oid_header(&commit->tree_id,
				&buffer, buffer_end, "tree ",
				opts->oid_type) < 0)
			goto bad_buffer;
	} else {
		size_t tree_len = strlen("tree ") + git3_oid_hexsize(opts->oid_type) + 1;

		if (buffer + tree_len > buffer_end)
			goto bad_buffer;
		buffer += tree_len;
	}

	while (git3_object__parse_oid_header(&parent_id,
			&buffer, buffer_end, "parent ",
			opts->oid_type) == 0) {
		git3_oid *new_id = git3_array_alloc(commit->parent_ids);
		GIT3_ERROR_CHECK_ALLOC(new_id);

		git3_oid_cpy(new_id, &parent_id);
	}

	if (!opts || !(opts->flags & GIT3_COMMIT_PARSE_QUICK)) {
		commit->author = git3__malloc(sizeof(git3_signature));
		GIT3_ERROR_CHECK_ALLOC(commit->author);

		if ((error = git3_signature__parse(commit->author, &buffer, buffer_end, "author ", '\n')) < 0)
			return error;
	}

	/* Some tools create multiple author fields, ignore the extra ones */
	while (!git3__prefixncmp(buffer, buffer_end - buffer, "author ")) {
		if ((error = git3_signature__parse(&dummy_sig, &buffer, buffer_end, "author ", '\n')) < 0)
			return error;

		git3__free(dummy_sig.name);
		git3__free(dummy_sig.email);
	}

	/* Always parse the committer; we need the commit time */
	commit->committer = git3__malloc(sizeof(git3_signature));
	GIT3_ERROR_CHECK_ALLOC(commit->committer);

	if ((error = git3_signature__parse(commit->committer, &buffer, buffer_end, "committer ", '\n')) < 0)
		return error;

	if (opts && opts->flags & GIT3_COMMIT_PARSE_QUICK)
		return 0;

	/* Parse add'l header entries */
	while (buffer < buffer_end) {
		const char *eoln = buffer;
		if (buffer[-1] == '\n' && buffer[0] == '\n')
			break;

		while (eoln < buffer_end && *eoln != '\n')
			++eoln;

		if (git3__prefixncmp(buffer, buffer_end - buffer, "encoding ") == 0) {
			buffer += strlen("encoding ");

			commit->message_encoding = git3__strndup(buffer, eoln - buffer);
			GIT3_ERROR_CHECK_ALLOC(commit->message_encoding);
		}

		if (eoln < buffer_end && *eoln == '\n')
			++eoln;
		buffer = eoln;
	}

	header_len = buffer - buffer_start;
	commit->raw_header = git3__strndup(buffer_start, header_len);
	GIT3_ERROR_CHECK_ALLOC(commit->raw_header);

	/* point "buffer" to data after header, +1 for the final LF */
	buffer = buffer_start + header_len + 1;

	/* extract commit message */
	if (buffer <= buffer_end)
		commit->raw_message = git3__strndup(buffer, buffer_end - buffer);
	else
		commit->raw_message = git3__strdup("");
	GIT3_ERROR_CHECK_ALLOC(commit->raw_message);

	return 0;

bad_buffer:
	git3_error_set(GIT3_ERROR_OBJECT, "failed to parse bad commit object");
	return GIT3_EINVALID;
}

int git3_commit__parse(
	void *commit,
	git3_odb_object *odb_obj,
	git3_oid_t oid_type)
{
	git3_commit__parse_options parse_options = {0};
	parse_options.oid_type = oid_type;

	return git3_commit__parse_ext(commit, odb_obj, &parse_options);
}

int git3_commit__parse_raw(
	void *commit,
	const char *data,
	size_t size,
	git3_oid_t oid_type)
{
	git3_commit__parse_options parse_options = {0};
	parse_options.oid_type = oid_type;

	return commit_parse(commit, data, size, &parse_options);
}

static int assign_commit_parents_from_graft(git3_commit *commit, git3_commit_graft *graft) {
	size_t idx;
	git3_oid *oid;

	git3_array_clear(commit->parent_ids);
	git3_array_init_to_size(commit->parent_ids, git3_array_size(graft->parents));
	git3_array_foreach(graft->parents, idx, oid) {
		git3_oid *id = git3_array_alloc(commit->parent_ids);
		GIT3_ERROR_CHECK_ALLOC(id);

		git3_oid_cpy(id, oid);
	}

	return 0;
}

int git3_commit__parse_ext(
	git3_commit *commit,
	git3_odb_object *odb_obj,
	git3_commit__parse_options *parse_opts)
{
	git3_repository *repo = git3_object_owner((git3_object *)commit);
	git3_commit_graft *graft;
	int error;

	if ((error = commit_parse(commit, git3_odb_object_data(odb_obj),
				  git3_odb_object_size(odb_obj), parse_opts)) < 0)
		return error;

	/* Perform necessary grafts */
	if (git3_grafts_get(&graft, repo->grafts, git3_odb_object_id(odb_obj)) != 0 &&
		git3_grafts_get(&graft, repo->shallow_grafts, git3_odb_object_id(odb_obj)) != 0)
		return 0;

	return assign_commit_parents_from_graft(commit, graft);
}

#define GIT3_COMMIT_GETTER(_rvalue, _name, _return, _invalid) \
	_rvalue git3_commit_##_name(const git3_commit *commit) \
	{\
		GIT3_ASSERT_ARG_WITH_RETVAL(commit, _invalid); \
		return _return; \
	}

GIT3_COMMIT_GETTER(const git3_signature *, author, commit->author, NULL)
GIT3_COMMIT_GETTER(const git3_signature *, committer, commit->committer, NULL)
GIT3_COMMIT_GETTER(const char *, message_raw, commit->raw_message, NULL)
GIT3_COMMIT_GETTER(const char *, message_encoding, commit->message_encoding, NULL)
GIT3_COMMIT_GETTER(const char *, raw_header, commit->raw_header, NULL)
GIT3_COMMIT_GETTER(git3_time_t, time, commit->committer->when.time, INT64_MIN)
GIT3_COMMIT_GETTER(int, time_offset, commit->committer->when.offset, -1)
GIT3_COMMIT_GETTER(unsigned int, parentcount, (unsigned int)git3_array_size(commit->parent_ids), 0)
GIT3_COMMIT_GETTER(const git3_oid *, tree_id, &commit->tree_id, NULL)

const char *git3_commit_message(const git3_commit *commit)
{
	const char *message;

	GIT3_ASSERT_ARG_WITH_RETVAL(commit, NULL);

	message = commit->raw_message;

	/* trim leading newlines from raw message */
	while (*message && *message == '\n')
		++message;

	return message;
}

const char *git3_commit_summary(git3_commit *commit)
{
	git3_str summary = GIT3_STR_INIT;
	const char *msg, *space, *next;
	bool space_contains_newline = false;

	GIT3_ASSERT_ARG_WITH_RETVAL(commit, NULL);

	if (!commit->summary) {
		for (msg = git3_commit_message(commit), space = NULL; *msg; ++msg) {
			char next_character = msg[0];
			/* stop processing at the end of the first paragraph */
			if (next_character == '\n') {
				if (!msg[1])
					break;
				if (msg[1] == '\n')
					break;
				/* stop processing if next line contains only whitespace */
				next = msg + 1;
				while (*next && git3__isspace_nonlf(*next)) {
					++next;
				}
				if (!*next || *next == '\n')
					break;
			}
			/* record the beginning of contiguous whitespace runs */
			if (git3__isspace(next_character)) {
				if(space == NULL) {
					space = msg;
					space_contains_newline = false;
				}
				space_contains_newline |= next_character == '\n';
			}
			/* the next character is non-space */
			else {
				/* process any recorded whitespace */
				if (space) {
					if(space_contains_newline)
						git3_str_putc(&summary, ' '); /* if the space contains a newline, collapse to ' ' */
					else
						git3_str_put(&summary, space, (msg - space)); /* otherwise copy it */
					space = NULL;
				}
				/* copy the next character */
				git3_str_putc(&summary, next_character);
			}
		}

		commit->summary = git3_str_detach(&summary);
		if (!commit->summary)
			commit->summary = git3__strdup("");
	}

	return commit->summary;
}

const char *git3_commit_body(git3_commit *commit)
{
	const char *msg, *end;

	GIT3_ASSERT_ARG_WITH_RETVAL(commit, NULL);

	if (!commit->body) {
		/* search for end of summary */
		for (msg = git3_commit_message(commit); *msg; ++msg)
			if (msg[0] == '\n' && (!msg[1] || msg[1] == '\n'))
				break;

		/* trim leading and trailing whitespace */
		for (; *msg; ++msg)
			if (!git3__isspace(*msg))
				break;
		for (end = msg + strlen(msg) - 1; msg <= end; --end)
			if (!git3__isspace(*end))
				break;

		if (*msg)
			commit->body = git3__strndup(msg, end - msg + 1);
	}

	return commit->body;
}

int git3_commit_tree(git3_tree **tree_out, const git3_commit *commit)
{
	GIT3_ASSERT_ARG(commit);
	return git3_tree_lookup(tree_out, commit->object.repo, &commit->tree_id);
}

const git3_oid *git3_commit_parent_id(
	const git3_commit *commit, unsigned int n)
{
	GIT3_ASSERT_ARG_WITH_RETVAL(commit, NULL);

	return git3_array_get(commit->parent_ids, n);
}

int git3_commit_parent(
	git3_commit **parent, const git3_commit *commit, unsigned int n)
{
	const git3_oid *parent_id;
	GIT3_ASSERT_ARG(commit);

	parent_id = git3_commit_parent_id(commit, n);
	if (parent_id == NULL) {
		git3_error_set(GIT3_ERROR_INVALID, "parent %u does not exist", n);
		return GIT3_ENOTFOUND;
	}

	return git3_commit_lookup(parent, commit->object.repo, parent_id);
}

int git3_commit_nth_gen_ancestor(
	git3_commit **ancestor,
	const git3_commit *commit,
	unsigned int n)
{
	git3_commit *current, *parent = NULL;
	int error;

	GIT3_ASSERT_ARG(ancestor);
	GIT3_ASSERT_ARG(commit);

	if (git3_commit_dup(&current, (git3_commit *)commit) < 0)
		return -1;

	if (n == 0) {
		*ancestor = current;
		return 0;
	}

	while (n--) {
		error = git3_commit_parent(&parent, current, 0);

		git3_commit_free(current);

		if (error < 0)
			return error;

		current = parent;
	}

	*ancestor = parent;
	return 0;
}

int git3_commit_header_field(
	git3_buf *out,
	const git3_commit *commit,
	const char *field)
{
	GIT3_BUF_WRAP_PRIVATE(out, git3_commit__header_field, commit, field);
}

int git3_commit__header_field(
	git3_str *out,
	const git3_commit *commit,
	const char *field)
{
	const char *eol, *buf = commit->raw_header;

	git3_str_clear(out);

	while ((eol = strchr(buf, '\n'))) {
		/* We can skip continuations here */
		if (buf[0] == ' ') {
			buf = eol + 1;
			continue;
		}

		/* Skip until we find the field we're after */
		if (git3__prefixcmp(buf, field)) {
			buf = eol + 1;
			continue;
		}

		buf += strlen(field);
		/* Check that we're not matching a prefix but the field itself */
		if (buf[0] != ' ') {
			buf = eol + 1;
			continue;
		}

		buf++; /* skip the SP */

		git3_str_put(out, buf, eol - buf);
		if (git3_str_oom(out))
			goto oom;

		/* If the next line starts with SP, it's multi-line, we must continue */
		while (eol[1] == ' ') {
			git3_str_putc(out, '\n');
			buf = eol + 2;
			eol = strchr(buf, '\n');
			if (!eol)
				goto malformed;

			git3_str_put(out, buf, eol - buf);
		}

		if (git3_str_oom(out))
			goto oom;

		return 0;
	}

	git3_error_set(GIT3_ERROR_OBJECT, "no such field '%s'", field);
	return GIT3_ENOTFOUND;

malformed:
	git3_error_set(GIT3_ERROR_OBJECT, "malformed header");
	return -1;
oom:
	git3_error_set_oom();
	return -1;
}

int git3_commit_extract_signature(
	git3_buf *signature_out,
	git3_buf *signed_data_out,
	git3_repository *repo,
	git3_oid *commit_id,
	const char *field)
{
	git3_str signature = GIT3_STR_INIT, signed_data = GIT3_STR_INIT;
	int error;

	if ((error = git3_buf_tostr(&signature, signature_out)) < 0 ||
	    (error = git3_buf_tostr(&signed_data, signed_data_out)) < 0 ||
	    (error = git3_commit__extract_signature(&signature, &signed_data, repo, commit_id, field)) < 0 ||
	    (error = git3_buf_fromstr(signature_out, &signature)) < 0 ||
	    (error = git3_buf_fromstr(signed_data_out, &signed_data)) < 0)
		goto done;

done:
	git3_str_dispose(&signature);
	git3_str_dispose(&signed_data);
	return error;
}

int git3_commit__extract_signature(
	git3_str *signature,
	git3_str *signed_data,
	git3_repository *repo,
	git3_oid *commit_id,
	const char *field)
{
	git3_odb_object *obj;
	git3_odb *odb;
	const char *buf;
	const char *h, *eol;
	int error;

	git3_str_clear(signature);
	git3_str_clear(signed_data);

	if (!field)
		field = "gpgsig";

	if ((error = git3_repository_odb__weakptr(&odb, repo)) < 0)
		return error;

	if ((error = git3_odb_read(&obj, odb, commit_id)) < 0)
		return error;

	if (obj->cached.type != GIT3_OBJECT_COMMIT) {
		git3_error_set(GIT3_ERROR_INVALID, "the requested type does not match the type in the ODB");
		error = GIT3_ENOTFOUND;
		goto cleanup;
	}

	buf = git3_odb_object_data(obj);

	while ((h = strchr(buf, '\n')) && h[1] != '\0') {
		h++;
		if (git3__prefixcmp(buf, field)) {
			if (git3_str_put(signed_data, buf, h - buf) < 0)
				return -1;

			buf = h;
			continue;
		}

		h = buf;
		h += strlen(field);
		eol = strchr(h, '\n');
		if (h[0] != ' ') {
			buf = h;
			continue;
		}
		if (!eol)
			goto malformed;

		h++; /* skip the SP */

		git3_str_put(signature, h, eol - h);
		if (git3_str_oom(signature))
			goto oom;

		/* If the next line starts with SP, it's multi-line, we must continue */
		while (eol[1] == ' ') {
			git3_str_putc(signature, '\n');
			h = eol + 2;
			eol = strchr(h, '\n');
			if (!eol)
				goto malformed;

			git3_str_put(signature, h, eol - h);
		}

		if (git3_str_oom(signature))
			goto oom;

		error = git3_str_puts(signed_data, eol+1);
		git3_odb_object_free(obj);
		return error;
	}

	git3_error_set(GIT3_ERROR_OBJECT, "this commit is not signed");
	error = GIT3_ENOTFOUND;
	goto cleanup;

malformed:
	git3_error_set(GIT3_ERROR_OBJECT, "malformed header");
	error = -1;
	goto cleanup;
oom:
	git3_error_set_oom();
	error = -1;
	goto cleanup;

cleanup:
	git3_odb_object_free(obj);
	git3_str_clear(signature);
	git3_str_clear(signed_data);
	return error;
}

int git3_commit_create_buffer(
	git3_buf *out,
	git3_repository *repo,
	const git3_signature *author,
	const git3_signature *committer,
	const char *message_encoding,
	const char *message,
	const git3_tree *tree,
	size_t parent_count,
	const git3_commit *parents[])
{
	GIT3_BUF_WRAP_PRIVATE(out, git3_commit__create_buffer, repo,
	                     author, committer, message_encoding, message,
	                     tree, parent_count, parents);
}

int git3_commit__create_buffer(
	git3_str *out,
	git3_repository *repo,
	const git3_signature *author,
	const git3_signature *committer,
	const char *message_encoding,
	const char *message,
	const git3_tree *tree,
	size_t parent_count,
	const git3_commit *parents[])
{
	int error;
	commit_parent_data data = { parent_count, parents, repo };
	git3_array_oid_t parents_arr = GIT3_ARRAY_INIT;
	const git3_oid *tree_id;

	GIT3_ASSERT_ARG(tree);
	GIT3_ASSERT_ARG(git3_tree_owner(tree) == repo);

	tree_id = git3_tree_id(tree);

	if ((error = validate_tree_and_parents(&parents_arr, repo, tree_id, commit_parent_from_array, &data, NULL, true)) < 0)
		return error;

	error = git3_commit__create_buffer_internal(
		out, author, committer,
		message_encoding, message, tree_id,
		&parents_arr);

	git3_array_clear(parents_arr);
	return error;
}

/**
 * Append to 'out' properly marking continuations when there's a newline in 'content'
 */
static int format_header_field(git3_str *out, const char *field, const char *content)
{
	const char *lf;

	GIT3_ASSERT_ARG(out);
	GIT3_ASSERT_ARG(field);
	GIT3_ASSERT_ARG(content);

	git3_str_puts(out, field);
	git3_str_putc(out, ' ');

	while ((lf = strchr(content, '\n')) != NULL) {
		git3_str_put(out, content, lf - content);
		git3_str_puts(out, "\n ");
		content = lf + 1;
	}

	git3_str_puts(out, content);
	git3_str_putc(out, '\n');

	return git3_str_oom(out) ? -1 : 0;
}

static const git3_oid *commit_parent_from_commit(size_t n, void *payload)
{
	const git3_commit *commit = (const git3_commit *) payload;

	return git3_array_get(commit->parent_ids, n);

}

int git3_commit_create_with_signature(
	git3_oid *out,
	git3_repository *repo,
	const char *commit_content,
	const char *signature,
	const char *signature_field)
{
	git3_odb *odb;
	int error = 0;
	const char *field;
	const char *header_end;
	git3_str commit = GIT3_STR_INIT;
	git3_commit *parsed;
	git3_array_oid_t parents = GIT3_ARRAY_INIT;
	git3_commit__parse_options parse_opts = {0};

	parse_opts.oid_type = repo->oid_type;

	/* The first step is to verify that all the tree and parents exist */
	parsed = git3__calloc(1, sizeof(git3_commit));
	GIT3_ERROR_CHECK_ALLOC(parsed);
	if (commit_parse(parsed, commit_content, strlen(commit_content), &parse_opts) < 0) {
		error = -1;
		goto cleanup;
	}

	if ((error = validate_tree_and_parents(&parents, repo, &parsed->tree_id, commit_parent_from_commit, parsed, NULL, true)) < 0)
		goto cleanup;

	git3_array_clear(parents);

	/* Then we start appending by identifying the end of the commit header */
	header_end = strstr(commit_content, "\n\n");
	if (!header_end) {
		git3_error_set(GIT3_ERROR_INVALID, "malformed commit contents");
		error = -1;
		goto cleanup;
	}

	/* The header ends after the first LF */
	header_end++;
	git3_str_put(&commit, commit_content, header_end - commit_content);

	if (signature != NULL) {
		field = signature_field ? signature_field : "gpgsig";

		if ((error = format_header_field(&commit, field, signature)) < 0)
			goto cleanup;
	}

	git3_str_puts(&commit, header_end);

	if (git3_str_oom(&commit))
		return -1;

	if ((error = git3_repository_odb__weakptr(&odb, repo)) < 0)
		goto cleanup;

	if ((error = git3_odb_write(out, odb, commit.ptr, commit.size, GIT3_OBJECT_COMMIT)) < 0)
		goto cleanup;

cleanup:
	git3_commit__free(parsed);
	git3_str_dispose(&commit);
	return error;
}

int git3_commit_create_from_stage(
	git3_oid *out,
	git3_repository *repo,
	const char *message,
	const git3_commit_create_options *given_opts)
{
	git3_commit_create_options opts = GIT3_COMMIT_CREATE_OPTIONS_INIT;
	git3_signature *default_signature = NULL;
	const git3_signature *author, *committer;
	git3_index *index = NULL;
	git3_diff *diff = NULL;
	git3_oid tree_id;
	git3_tree *head_tree = NULL, *tree = NULL;
	git3_commitarray parents = { 0 };
	int error = -1;

	GIT3_ASSERT_ARG(out && repo);

	if (given_opts)
		memcpy(&opts, given_opts, sizeof(git3_commit_create_options));

	author = opts.author;
	committer = opts.committer;

	if (!author || !committer) {
		if (git3_signature_default(&default_signature, repo) < 0)
			goto done;

		if (!author)
			author = default_signature;

		if (!committer)
			committer = default_signature;
	}

	if (git3_repository_index(&index, repo) < 0)
		goto done;

	if (!opts.allow_empty_commit) {
		error = git3_repository_head_tree(&head_tree, repo);

		if (error && error != GIT3_EUNBORNBRANCH)
			goto done;

		error = -1;

		if (git3_diff_tree_to_index(&diff, repo, head_tree, index, NULL) < 0)
			goto done;

		if (git3_diff_num_deltas(diff) == 0) {
			git3_error_set(GIT3_ERROR_REPOSITORY,
				"no changes are staged for commit");
			error = GIT3_EUNCHANGED;
			goto done;
		}
	}

	if (git3_index_write_tree(&tree_id, index) < 0 ||
	    git3_tree_lookup(&tree, repo, &tree_id) < 0 ||
	    git3_repository_commit_parents(&parents, repo) < 0)
		goto done;

	error = git3_commit_create(out, repo, "HEAD", author, committer,
			opts.message_encoding, message,
			tree, parents.count,
			(const git3_commit **)parents.commits);

done:
	git3_commitarray_dispose(&parents);
	git3_signature_free(default_signature);
	git3_tree_free(tree);
	git3_tree_free(head_tree);
	git3_diff_free(diff);
	git3_index_free(index);
	return error;
}

int git3_commit_committer_with_mailmap(
	git3_signature **out, const git3_commit *commit, const git3_mailmap *mailmap)
{
	return git3_mailmap_resolve_signature(out, mailmap, commit->committer);
}

int git3_commit_author_with_mailmap(
	git3_signature **out, const git3_commit *commit, const git3_mailmap *mailmap)
{
	return git3_mailmap_resolve_signature(out, mailmap, commit->author);
}

void git3_commitarray_dispose(git3_commitarray *array)
{
	size_t i;

	if (array == NULL)
		return;

	for (i = 0; i < array->count; i++)
		git3_commit_free(array->commits[i]);

	git3__free((git3_commit **)array->commits);

	memset(array, 0, sizeof(*array));
}
