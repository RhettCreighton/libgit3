/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "common.h"

#include "str.h"
#include "tree.h"
#include "refdb.h"
#include "regexp.h"
#include "date.h"

#include "git3.h"

static int maybe_sha_or_abbrev(
	git3_object **out,
	git3_repository *repo,
	const char *spec,
	size_t speclen)
{
	git3_oid oid;

	if (git3_oid_from_prefix(&oid, spec, speclen, repo->oid_type) < 0)
		return GIT3_ENOTFOUND;

	return git3_object_lookup_prefix(out, repo, &oid, speclen, GIT3_OBJECT_ANY);
}

static int maybe_sha(
	git3_object **out,
	git3_repository *repo,
	const char *spec)
{
	size_t speclen = strlen(spec);

	if (speclen != git3_oid_hexsize(repo->oid_type))
		return GIT3_ENOTFOUND;

	return maybe_sha_or_abbrev(out, repo, spec, speclen);
}

static int maybe_abbrev(git3_object **out, git3_repository *repo, const char *spec)
{
	size_t speclen = strlen(spec);

	return maybe_sha_or_abbrev(out, repo, spec, speclen);
}

static int build_regex(git3_regexp *regex, const char *pattern)
{
	int error;

	if (*pattern == '\0') {
		git3_error_set(GIT3_ERROR_REGEX, "empty pattern");
		return GIT3_EINVALIDSPEC;
	}

	error = git3_regexp_compile(regex, pattern, 0);
	if (!error)
		return 0;

	git3_regexp_dispose(regex);

	return error;
}

static int maybe_describe(git3_object**out, git3_repository *repo, const char *spec)
{
	const char *substr;
	int error;
	git3_regexp regex;

	substr = strstr(spec, "-g");

	if (substr == NULL)
		return GIT3_ENOTFOUND;

	if (build_regex(&regex, ".+-[0-9]+-g[0-9a-fA-F]+") < 0)
		return -1;

	error = git3_regexp_match(&regex, spec);
	git3_regexp_dispose(&regex);

	if (error)
		return GIT3_ENOTFOUND;

	return maybe_abbrev(out, repo, substr+2);
}

static int revparse_lookup_object(
	git3_object **object_out,
	git3_reference **reference_out,
	git3_repository *repo,
	const char *spec)
{
	int error;
	git3_reference *ref;

	if ((error = maybe_sha(object_out, repo, spec)) != GIT3_ENOTFOUND)
		return error;

	error = git3_reference_dwim(&ref, repo, spec);
	if (!error) {

		error = git3_object_lookup(
			object_out, repo, git3_reference_target(ref), GIT3_OBJECT_ANY);

		if (!error)
			*reference_out = ref;

		return error;
	}

	if (error != GIT3_ENOTFOUND)
		return error;

	if ((strlen(spec) < git3_oid_hexsize(repo->oid_type)) &&
	    ((error = maybe_abbrev(object_out, repo, spec)) != GIT3_ENOTFOUND))
			return error;

	if ((error = maybe_describe(object_out, repo, spec)) != GIT3_ENOTFOUND)
		return error;

	git3_error_set(GIT3_ERROR_REFERENCE, "revspec '%s' not found", spec);
	return GIT3_ENOTFOUND;
}

static int try_parse_numeric(int *n, const char *curly_braces_content)
{
	int32_t content;
	const char *end_ptr;

	if (git3__strntol32(&content, curly_braces_content, strlen(curly_braces_content),
			   &end_ptr, 10) < 0)
		return -1;

	if (*end_ptr != '\0')
		return -1;

	*n = (int)content;
	return 0;
}

static int retrieve_previously_checked_out_branch_or_revision(git3_object **out, git3_reference **base_ref, git3_repository *repo, const char *identifier, size_t position)
{
	git3_reference *ref = NULL;
	git3_reflog *reflog = NULL;
	git3_regexp preg;
	int error = -1;
	size_t i, numentries, cur;
	const git3_reflog_entry *entry;
	const char *msg;
	git3_str buf = GIT3_STR_INIT;

	cur = position;

	if (*identifier != '\0' || *base_ref != NULL)
		return GIT3_EINVALIDSPEC;

	if (build_regex(&preg, "checkout: moving from (.*) to .*") < 0)
		return -1;

	if (git3_reference_lookup(&ref, repo, GIT3_HEAD_FILE) < 0)
		goto cleanup;

	if (git3_reflog_read(&reflog, repo, GIT3_HEAD_FILE) < 0)
		goto cleanup;

	numentries  = git3_reflog_entrycount(reflog);

	for (i = 0; i < numentries; i++) {
		git3_regmatch regexmatches[2];

		entry = git3_reflog_entry_byindex(reflog, i);
		msg = git3_reflog_entry_message(entry);
		if (!msg)
			continue;

		if (git3_regexp_search(&preg, msg, 2, regexmatches) < 0)
			continue;

		cur--;

		if (cur > 0)
			continue;

		if ((git3_str_put(&buf, msg+regexmatches[1].start, regexmatches[1].end - regexmatches[1].start)) < 0)
			goto cleanup;

		if ((error = git3_reference_dwim(base_ref, repo, git3_str_cstr(&buf))) == 0)
			goto cleanup;

		if (error < 0 && error != GIT3_ENOTFOUND)
			goto cleanup;

		error = maybe_abbrev(out, repo, git3_str_cstr(&buf));

		goto cleanup;
	}

	error = GIT3_ENOTFOUND;

cleanup:
	git3_reference_free(ref);
	git3_str_dispose(&buf);
	git3_regexp_dispose(&preg);
	git3_reflog_free(reflog);
	return error;
}

static int retrieve_oid_from_reflog(git3_oid *oid, git3_reference *ref, size_t identifier)
{
	git3_reflog *reflog;
	size_t numentries;
	const git3_reflog_entry *entry = NULL;
	bool search_by_pos = (identifier <= 100000000);

	if (git3_reflog_read(&reflog, git3_reference_owner(ref), git3_reference_name(ref)) < 0)
		return -1;

	numentries = git3_reflog_entrycount(reflog);

	if (search_by_pos) {
		if (numentries < identifier + 1)
			goto notfound;

		entry = git3_reflog_entry_byindex(reflog, identifier);
		git3_oid_cpy(oid, git3_reflog_entry_id_new(entry));
	} else {
		size_t i;
		git3_time commit_time;

		for (i = 0; i < numentries; i++) {
			entry = git3_reflog_entry_byindex(reflog, i);
			commit_time = git3_reflog_entry_committer(entry)->when;

			if (commit_time.time > (git3_time_t)identifier)
				continue;

			git3_oid_cpy(oid, git3_reflog_entry_id_new(entry));
			break;
		}

		if (i == numentries) {
			if (entry == NULL)
				goto notfound;

			/*
			 * TODO: emit a warning (log for 'branch' only goes back to ...)
			 */
			git3_oid_cpy(oid, git3_reflog_entry_id_new(entry));
		}
	}

	git3_reflog_free(reflog);
	return 0;

notfound:
	git3_error_set(
		GIT3_ERROR_REFERENCE,
		"reflog for '%s' has only %"PRIuZ" entries, asked for %"PRIuZ,
		git3_reference_name(ref), numentries, identifier);

	git3_reflog_free(reflog);
	return GIT3_ENOTFOUND;
}

static int retrieve_revobject_from_reflog(git3_object **out, git3_reference **base_ref, git3_repository *repo, const char *identifier, size_t position)
{
	git3_reference *ref;
	git3_oid oid;
	int error = -1;

	if (*base_ref == NULL) {
		/*
		 * When HEAD@{n} is specified, do not use dwim, which would resolve the
		 * reference (to the current branch that HEAD is pointing to).
		 */
		if (position > 0 && strcmp(identifier, GIT3_HEAD_FILE) == 0)
			error = git3_reference_lookup(&ref, repo, GIT3_HEAD_FILE);
		else
			error = git3_reference_dwim(&ref, repo, identifier);

		if (error < 0)
			return error;
	} else {
		ref = *base_ref;
		*base_ref = NULL;
	}

	if (position == 0) {
		error = git3_object_lookup(out, repo, git3_reference_target(ref), GIT3_OBJECT_ANY);
		goto cleanup;
	}

	if ((error = retrieve_oid_from_reflog(&oid, ref, position)) < 0)
		goto cleanup;

	error = git3_object_lookup(out, repo, &oid, GIT3_OBJECT_ANY);

cleanup:
	git3_reference_free(ref);
	return error;
}

static int retrieve_remote_tracking_reference(git3_reference **base_ref, const char *identifier, git3_repository *repo)
{
	git3_reference *tracking, *ref;
	int error = -1;

	if (*base_ref == NULL) {
		if ((error = git3_reference_dwim(&ref, repo, identifier)) < 0)
			return error;
	} else {
		ref = *base_ref;
		*base_ref = NULL;
	}

	if (!git3_reference_is_branch(ref)) {
		error = GIT3_EINVALIDSPEC;
		goto cleanup;
	}

	if ((error = git3_branch_upstream(&tracking, ref)) < 0)
		goto cleanup;

	*base_ref = tracking;

cleanup:
	git3_reference_free(ref);
	return error;
}

static int handle_at_syntax(git3_object **out, git3_reference **ref, const char *spec, size_t identifier_len, git3_repository *repo, const char *curly_braces_content)
{
	bool is_numeric;
	int parsed = 0, error = -1;
	git3_str identifier = GIT3_STR_INIT;
	git3_time_t timestamp;

	GIT3_ASSERT(*out == NULL);

	if (git3_str_put(&identifier, spec, identifier_len) < 0)
		return -1;

	is_numeric = !try_parse_numeric(&parsed, curly_braces_content);

	if (*curly_braces_content == '-' && (!is_numeric || parsed == 0)) {
		error = GIT3_EINVALIDSPEC;
		goto cleanup;
	}

	if (is_numeric) {
		if (parsed < 0)
			error = retrieve_previously_checked_out_branch_or_revision(out, ref, repo, git3_str_cstr(&identifier), -parsed);
		else
			error = retrieve_revobject_from_reflog(out, ref, repo, git3_str_cstr(&identifier), parsed);

		goto cleanup;
	}

	if (!strcmp(curly_braces_content, "u") || !strcmp(curly_braces_content, "upstream")) {
		error = retrieve_remote_tracking_reference(ref, git3_str_cstr(&identifier), repo);

		goto cleanup;
	}

	if (git3_date_parse(&timestamp, curly_braces_content) < 0) {
		error = GIT3_EINVALIDSPEC;
		goto cleanup;
	}

	error = retrieve_revobject_from_reflog(out, ref, repo, git3_str_cstr(&identifier), (size_t)timestamp);

cleanup:
	git3_str_dispose(&identifier);
	return error;
}

static git3_object_t parse_obj_type(const char *str)
{
	if (!strcmp(str, "commit"))
		return GIT3_OBJECT_COMMIT;

	if (!strcmp(str, "tree"))
		return GIT3_OBJECT_TREE;

	if (!strcmp(str, "blob"))
		return GIT3_OBJECT_BLOB;

	if (!strcmp(str, "tag"))
		return GIT3_OBJECT_TAG;

	return GIT3_OBJECT_INVALID;
}

static int dereference_to_non_tag(git3_object **out, git3_object *obj)
{
	if (git3_object_type(obj) == GIT3_OBJECT_TAG)
		return git3_tag_peel(out, (git3_tag *)obj);

	return git3_object_dup(out, obj);
}

static int handle_caret_parent_syntax(git3_object **out, git3_object *obj, int n)
{
	git3_object *temp_commit = NULL;
	int error;

	if ((error = git3_object_peel(&temp_commit, obj, GIT3_OBJECT_COMMIT)) < 0)
		return (error == GIT3_EAMBIGUOUS || error == GIT3_ENOTFOUND) ?
			GIT3_EINVALIDSPEC : error;

	if (n == 0) {
		*out = temp_commit;
		return 0;
	}

	error = git3_commit_parent((git3_commit **)out, (git3_commit*)temp_commit, n - 1);

	git3_object_free(temp_commit);
	return error;
}

static int handle_linear_syntax(git3_object **out, git3_object *obj, int n)
{
	git3_object *temp_commit = NULL;
	int error;

	if ((error = git3_object_peel(&temp_commit, obj, GIT3_OBJECT_COMMIT)) < 0)
		return (error == GIT3_EAMBIGUOUS || error == GIT3_ENOTFOUND) ?
			GIT3_EINVALIDSPEC : error;

	error = git3_commit_nth_gen_ancestor((git3_commit **)out, (git3_commit*)temp_commit, n);

	git3_object_free(temp_commit);
	return error;
}

static int handle_colon_syntax(
	git3_object **out,
	git3_object *obj,
	const char *path)
{
	git3_object *tree;
	int error = -1;
	git3_tree_entry *entry = NULL;

	if ((error = git3_object_peel(&tree, obj, GIT3_OBJECT_TREE)) < 0)
		return error == GIT3_ENOTFOUND ? GIT3_EINVALIDSPEC : error;

	if (*path == '\0') {
		*out = tree;
		return 0;
	}

	/*
	 * TODO: Handle the relative path syntax
	 * (:./relative/path and :../relative/path)
	 */
	if ((error = git3_tree_entry_bypath(&entry, (git3_tree *)tree, path)) < 0)
		goto cleanup;

	error = git3_tree_entry_to_object(out, git3_object_owner(tree), entry);

cleanup:
	git3_tree_entry_free(entry);
	git3_object_free(tree);

	return error;
}

static int walk_and_search(git3_object **out, git3_revwalk *walk, git3_regexp *regex)
{
	int error;
	git3_oid oid;
	git3_object *obj;

	while (!(error = git3_revwalk_next(&oid, walk))) {

		error = git3_object_lookup(&obj, git3_revwalk_repository(walk), &oid, GIT3_OBJECT_COMMIT);
		if ((error < 0) && (error != GIT3_ENOTFOUND))
			return -1;

		if (!git3_regexp_match(regex, git3_commit_message((git3_commit*)obj))) {
			*out = obj;
			return 0;
		}

		git3_object_free(obj);
	}

	if (error < 0 && error == GIT3_ITEROVER)
		error = GIT3_ENOTFOUND;

	return error;
}

static int handle_grep_syntax(git3_object **out, git3_repository *repo, const git3_oid *spec_oid, const char *pattern)
{
	git3_regexp preg;
	git3_revwalk *walk = NULL;
	int error;

	if ((error = build_regex(&preg, pattern)) < 0)
		return error;

	if ((error = git3_revwalk_new(&walk, repo)) < 0)
		goto cleanup;

	git3_revwalk_sorting(walk, GIT3_SORT_TIME);

	if (spec_oid == NULL) {
		if ((error = git3_revwalk_push_glob(walk, "refs/*")) < 0)
			goto cleanup;
	} else if ((error = git3_revwalk_push(walk, spec_oid)) < 0)
			goto cleanup;

	error = walk_and_search(out, walk, &preg);

cleanup:
	git3_regexp_dispose(&preg);
	git3_revwalk_free(walk);

	return error;
}

static int handle_caret_curly_syntax(git3_object **out, git3_object *obj, const char *curly_braces_content)
{
	git3_object_t expected_type;

	if (*curly_braces_content == '\0')
		return dereference_to_non_tag(out, obj);

	if (*curly_braces_content == '/')
		return handle_grep_syntax(out, git3_object_owner(obj), git3_object_id(obj), curly_braces_content + 1);

	expected_type = parse_obj_type(curly_braces_content);

	if (expected_type == GIT3_OBJECT_INVALID)
		return GIT3_EINVALIDSPEC;

	return git3_object_peel(out, obj, expected_type);
}

static int extract_curly_braces_content(git3_str *buf, const char *spec, size_t *pos)
{
	git3_str_clear(buf);

	GIT3_ASSERT_ARG(spec[*pos] == '^' || spec[*pos] == '@');

	(*pos)++;

	if (spec[*pos] == '\0' || spec[*pos] != '{')
		return GIT3_EINVALIDSPEC;

	(*pos)++;

	while (spec[*pos] != '}') {
		if (spec[*pos] == '\0')
			return GIT3_EINVALIDSPEC;

		if (git3_str_putc(buf, spec[(*pos)++]) < 0)
			return -1;
	}

	(*pos)++;

	return 0;
}

static int extract_path(git3_str *buf, const char *spec, size_t *pos)
{
	git3_str_clear(buf);

	GIT3_ASSERT_ARG(spec[*pos] == ':');

	(*pos)++;

	if (git3_str_puts(buf, spec + *pos) < 0)
		return -1;

	*pos += git3_str_len(buf);

	return 0;
}

static int extract_how_many(int *n, const char *spec, size_t *pos)
{
	const char *end_ptr;
	int parsed, accumulated;
	char kind = spec[*pos];

	GIT3_ASSERT_ARG(spec[*pos] == '^' || spec[*pos] == '~');

	accumulated = 0;

	do {
		do {
			(*pos)++;
			accumulated++;
		} while (spec[(*pos)] == kind && kind == '~');

		if (git3__isdigit(spec[*pos])) {
			if (git3__strntol32(&parsed, spec + *pos, strlen(spec + *pos), &end_ptr, 10) < 0)
				return GIT3_EINVALIDSPEC;

			accumulated += (parsed - 1);
			*pos = end_ptr - spec;
		}

	} while (spec[(*pos)] == kind && kind == '~');

	*n = accumulated;

	return 0;
}

static int object_from_reference(git3_object **object, git3_reference *reference)
{
	git3_reference *resolved = NULL;
	int error;

	if (git3_reference_resolve(&resolved, reference) < 0)
		return -1;

	error = git3_object_lookup(object, reference->db->repo, git3_reference_target(resolved), GIT3_OBJECT_ANY);
	git3_reference_free(resolved);

	return error;
}

static int ensure_base_rev_loaded(git3_object **object, git3_reference **reference, const char *spec, size_t identifier_len, git3_repository *repo, bool allow_empty_identifier)
{
	int error;
	git3_str identifier = GIT3_STR_INIT;

	if (*object != NULL)
		return 0;

	if (*reference != NULL)
		return object_from_reference(object, *reference);

	if (!allow_empty_identifier && identifier_len == 0)
		return GIT3_EINVALIDSPEC;

	if (git3_str_put(&identifier, spec, identifier_len) < 0)
		return -1;

	error = revparse_lookup_object(object, reference, repo, git3_str_cstr(&identifier));
	git3_str_dispose(&identifier);

	return error;
}

static int ensure_base_rev_is_not_known_yet(git3_object *object)
{
	if (object == NULL)
		return 0;

	return GIT3_EINVALIDSPEC;
}

static bool any_left_hand_identifier(git3_object *object, git3_reference *reference, size_t identifier_len)
{
	if (object != NULL)
		return true;

	if (reference != NULL)
		return true;

	if (identifier_len > 0)
		return true;

	return false;
}

static int ensure_left_hand_identifier_is_not_known_yet(git3_object *object, git3_reference *reference)
{
	if (!ensure_base_rev_is_not_known_yet(object) && reference == NULL)
		return 0;

	return GIT3_EINVALIDSPEC;
}

static int revparse(
	git3_object **object_out,
	git3_reference **reference_out,
	size_t *identifier_len_out,
	git3_repository *repo,
	const char *spec)
{
	size_t pos = 0, identifier_len = 0;
	int error = -1, n;
	git3_str buf = GIT3_STR_INIT;

	git3_reference *reference = NULL;
	git3_object *base_rev = NULL;

	bool should_return_reference = true;
	bool parsed = false;

	GIT3_ASSERT_ARG(object_out);
	GIT3_ASSERT_ARG(reference_out);
	GIT3_ASSERT_ARG(repo);
	GIT3_ASSERT_ARG(spec);

	*object_out = NULL;
	*reference_out = NULL;

	while (!parsed && spec[pos]) {
		switch (spec[pos]) {
		case '^':
			should_return_reference = false;

			if ((error = ensure_base_rev_loaded(&base_rev, &reference, spec, identifier_len, repo, false)) < 0)
				goto cleanup;

			if (spec[pos+1] == '{') {
				git3_object *temp_object = NULL;

				if ((error = extract_curly_braces_content(&buf, spec, &pos)) < 0)
					goto cleanup;

				if ((error = handle_caret_curly_syntax(&temp_object, base_rev, git3_str_cstr(&buf))) < 0)
					goto cleanup;

				git3_object_free(base_rev);
				base_rev = temp_object;
			} else {
				git3_object *temp_object = NULL;

				if ((error = extract_how_many(&n, spec, &pos)) < 0)
					goto cleanup;

				if ((error = handle_caret_parent_syntax(&temp_object, base_rev, n)) < 0)
					goto cleanup;

				git3_object_free(base_rev);
				base_rev = temp_object;
			}
			break;

		case '~':
		{
			git3_object *temp_object = NULL;

			should_return_reference = false;

			if ((error = extract_how_many(&n, spec, &pos)) < 0)
				goto cleanup;

			if ((error = ensure_base_rev_loaded(&base_rev, &reference, spec, identifier_len, repo, false)) < 0)
				goto cleanup;

			if ((error = handle_linear_syntax(&temp_object, base_rev, n)) < 0)
				goto cleanup;

			git3_object_free(base_rev);
			base_rev = temp_object;
			break;
		}

		case ':':
		{
			git3_object *temp_object = NULL;

			should_return_reference = false;

			if ((error = extract_path(&buf, spec, &pos)) < 0)
				goto cleanup;

			if (any_left_hand_identifier(base_rev, reference, identifier_len)) {
				if ((error = ensure_base_rev_loaded(&base_rev, &reference, spec, identifier_len, repo, true)) < 0)
					goto cleanup;

				if ((error = handle_colon_syntax(&temp_object, base_rev, git3_str_cstr(&buf))) < 0)
					goto cleanup;
			} else {
				if (*git3_str_cstr(&buf) == '/') {
					if ((error = handle_grep_syntax(&temp_object, repo, NULL, git3_str_cstr(&buf) + 1)) < 0)
						goto cleanup;
				} else {

					/*
					 * TODO: support merge-stage path lookup (":2:Makefile")
					 * and plain index blob lookup (:i-am/a/blob)
					 */
					git3_error_set(GIT3_ERROR_INVALID, "unimplemented");
					error = GIT3_ERROR;
					goto cleanup;
				}
			}

			git3_object_free(base_rev);
			base_rev = temp_object;
			break;
		}

		case '@':
			if (spec[pos+1] == '{') {
				git3_object *temp_object = NULL;

				if ((error = extract_curly_braces_content(&buf, spec, &pos)) < 0)
					goto cleanup;

				if ((error = ensure_base_rev_is_not_known_yet(base_rev)) < 0)
					goto cleanup;

				if ((error = handle_at_syntax(&temp_object, &reference, spec, identifier_len, repo, git3_str_cstr(&buf))) < 0)
					goto cleanup;

				if (temp_object != NULL)
					base_rev = temp_object;
				break;
			} else if (spec[pos + 1] == '\0' && !pos) {
				spec = "HEAD";
				identifier_len = 4;
				parsed = true;
				break;
			}
			/* fall through */

		default:
			if ((error = ensure_left_hand_identifier_is_not_known_yet(base_rev, reference)) < 0)
				goto cleanup;

			pos++;
			identifier_len++;
		}
	}

	if ((error = ensure_base_rev_loaded(&base_rev, &reference, spec, identifier_len, repo, false)) < 0)
		goto cleanup;

	if (!should_return_reference) {
		git3_reference_free(reference);
		reference = NULL;
	}

	*object_out = base_rev;
	*reference_out = reference;
	*identifier_len_out = identifier_len;
	error = 0;

cleanup:
	if (error) {
		if (error == GIT3_EINVALIDSPEC)
			git3_error_set(GIT3_ERROR_INVALID,
				"failed to parse revision specifier - Invalid pattern '%s'", spec);

		git3_object_free(base_rev);
		git3_reference_free(reference);
	}

	git3_str_dispose(&buf);
	return error;
}

int git3_revparse_ext(
	git3_object **object_out,
	git3_reference **reference_out,
	git3_repository *repo,
	const char *spec)
{
	int error;
	size_t identifier_len;
	git3_object *obj = NULL;
	git3_reference *ref = NULL;

	if ((error = revparse(&obj, &ref, &identifier_len, repo, spec)) < 0)
		goto cleanup;

	*object_out = obj;
	*reference_out = ref;
	GIT3_UNUSED(identifier_len);

	return 0;

cleanup:
	git3_object_free(obj);
	git3_reference_free(ref);
	return error;
}

int git3_revparse_single(git3_object **out, git3_repository *repo, const char *spec)
{
	int error;
	git3_object *obj = NULL;
	git3_reference *ref = NULL;

	*out = NULL;

	if ((error = git3_revparse_ext(&obj, &ref, repo, spec)) < 0)
		goto cleanup;

	git3_reference_free(ref);

	*out = obj;

	return 0;

cleanup:
	git3_object_free(obj);
	git3_reference_free(ref);
	return error;
}

int git3_revparse(
	git3_revspec *revspec,
	git3_repository *repo,
	const char *spec)
{
	const char *dotdot;
	int error = 0;

	GIT3_ASSERT_ARG(revspec);
	GIT3_ASSERT_ARG(repo);
	GIT3_ASSERT_ARG(spec);

	memset(revspec, 0x0, sizeof(*revspec));

	if ((dotdot = strstr(spec, "..")) != NULL) {
		char *lstr;
		const char *rstr;
		revspec->flags = GIT3_REVSPEC_RANGE;

		/*
		 * Following git.git, don't allow '..' because it makes command line
		 * arguments which can be either paths or revisions ambiguous when the
		 * path is almost certainly intended. The empty range '...' is still
		 * allowed.
		 */
		if (!git3__strcmp(spec, "..")) {
			git3_error_set(GIT3_ERROR_INVALID, "invalid pattern '..'");
			return GIT3_EINVALIDSPEC;
		}

		lstr = git3__substrdup(spec, dotdot - spec);
		rstr = dotdot + 2;
		if (dotdot[2] == '.') {
			revspec->flags |= GIT3_REVSPEC_MERGE_BASE;
			rstr++;
		}

		error = git3_revparse_single(
			&revspec->from,
			repo,
			*lstr == '\0' ? "HEAD" : lstr);

		if (!error) {
			error = git3_revparse_single(
				&revspec->to,
				repo,
				*rstr == '\0' ? "HEAD" : rstr);
		}

		git3__free((void*)lstr);
	} else {
		revspec->flags = GIT3_REVSPEC_SINGLE;
		error = git3_revparse_single(&revspec->from, repo, spec);
	}

	return error;
}
