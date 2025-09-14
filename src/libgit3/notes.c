/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "notes.h"

#include "buf.h"
#include "refs.h"
#include "config.h"
#include "iterator.h"
#include "signature.h"
#include "blob.h"

static int note_error_notfound(void)
{
	git3_error_set(GIT3_ERROR_INVALID, "note could not be found");
	return GIT3_ENOTFOUND;
}

static int find_subtree_in_current_level(
	git3_tree **out,
	git3_repository *repo,
	git3_tree *parent,
	const char *annotated_object_sha,
	int fanout)
{
	size_t i;
	const git3_tree_entry *entry;

	*out = NULL;

	if (parent == NULL)
		return note_error_notfound();

	for (i = 0; i < git3_tree_entrycount(parent); i++) {
		entry = git3_tree_entry_byindex(parent, i);

		if (!git3__ishex(git3_tree_entry_name(entry)))
			continue;

		if (S_ISDIR(git3_tree_entry_filemode(entry))
			&& strlen(git3_tree_entry_name(entry)) == 2
			&& !strncmp(git3_tree_entry_name(entry), annotated_object_sha + fanout, 2))
			return git3_tree_lookup(out, repo, git3_tree_entry_id(entry));

		/* Not a DIR, so do we have an already existing blob? */
		if (!strcmp(git3_tree_entry_name(entry), annotated_object_sha + fanout))
			return GIT3_EEXISTS;
	}

	return note_error_notfound();
}

static int find_subtree_r(git3_tree **out, git3_tree *root,
			git3_repository *repo, const char *target, int *fanout)
{
	int error;
	git3_tree *subtree = NULL;

	*out = NULL;

	error = find_subtree_in_current_level(&subtree, repo, root, target, *fanout);
	if (error == GIT3_EEXISTS)
		return git3_tree_lookup(out, repo, git3_tree_id(root));

	if (error < 0)
		return error;

	*fanout += 2;
	error = find_subtree_r(out, subtree, repo, target, fanout);
	git3_tree_free(subtree);

	return error;
}

static int find_blob(git3_oid *blob, git3_tree *tree, const char *target)
{
	size_t i;
	const git3_tree_entry *entry;

	for (i=0; i<git3_tree_entrycount(tree); i++) {
		entry = git3_tree_entry_byindex(tree, i);

		if (!strcmp(git3_tree_entry_name(entry), target)) {
			/* found matching note object - return */

			git3_oid_cpy(blob, git3_tree_entry_id(entry));
			return 0;
		}
	}

	return note_error_notfound();
}

static int tree_write(
	git3_tree **out,
	git3_repository *repo,
	git3_tree *source_tree,
	const git3_oid *object_oid,
	const char *treeentry_name,
	unsigned int attributes)
{
	int error;
	git3_treebuilder *tb = NULL;
	const git3_tree_entry *entry;
	git3_oid tree_oid;

	if ((error = git3_treebuilder_new(&tb, repo, source_tree)) < 0)
		goto cleanup;

	if (object_oid) {
		if ((error = git3_treebuilder_insert(
				&entry, tb, treeentry_name, object_oid, attributes)) < 0)
			goto cleanup;
	} else {
		if ((error = git3_treebuilder_remove(tb, treeentry_name)) < 0)
			goto cleanup;
	}

	if ((error = git3_treebuilder_write(&tree_oid, tb)) < 0)
		goto cleanup;

	error = git3_tree_lookup(out, repo, &tree_oid);

cleanup:
	git3_treebuilder_free(tb);
	return error;
}

static int manipulate_note_in_tree_r(
	git3_tree **out,
	git3_repository *repo,
	git3_tree *parent,
	git3_oid *note_oid,
	const char *annotated_object_sha,
	int fanout,
	int (*note_exists_cb)(
		git3_tree **out,
		git3_repository *repo,
		git3_tree *parent,
		git3_oid *note_oid,
		const char *annotated_object_sha,
		int fanout,
		int current_error),
	int (*note_notfound_cb)(
		git3_tree **out,
		git3_repository *repo,
		git3_tree *parent,
		git3_oid *note_oid,
		const char *annotated_object_sha,
		int fanout,
		int current_error))
{
	int error;
	git3_tree *subtree = NULL, *new = NULL;
	char subtree_name[3];

	error = find_subtree_in_current_level(
		&subtree, repo, parent, annotated_object_sha, fanout);

	if (error == GIT3_EEXISTS) {
		error = note_exists_cb(
			out, repo, parent, note_oid, annotated_object_sha, fanout, error);
		goto cleanup;
	}

	if (error == GIT3_ENOTFOUND) {
		error = note_notfound_cb(
			out, repo, parent, note_oid, annotated_object_sha, fanout, error);
		goto cleanup;
	}

	if (error < 0)
		goto cleanup;

	/* An existing fanout has been found, let's dig deeper */
	error = manipulate_note_in_tree_r(
		&new, repo, subtree, note_oid, annotated_object_sha,
		fanout + 2, note_exists_cb, note_notfound_cb);

	if (error < 0)
		goto cleanup;

	strncpy(subtree_name, annotated_object_sha + fanout, 2);
	subtree_name[2] = '\0';

	error = tree_write(out, repo, parent, git3_tree_id(new),
			   subtree_name, GIT3_FILEMODE_TREE);


cleanup:
	git3_tree_free(new);
	git3_tree_free(subtree);
	return error;
}

static int remove_note_in_tree_eexists_cb(
	git3_tree **out,
	git3_repository *repo,
	git3_tree *parent,
	git3_oid *note_oid,
	const char *annotated_object_sha,
	int fanout,
	int current_error)
{
	GIT3_UNUSED(note_oid);
	GIT3_UNUSED(current_error);

	return tree_write(out, repo, parent, NULL, annotated_object_sha + fanout, 0);
}

static int remove_note_in_tree_enotfound_cb(
	git3_tree **out,
	git3_repository *repo,
	git3_tree *parent,
	git3_oid *note_oid,
	const char *annotated_object_sha,
	int fanout,
	int current_error)
{
	GIT3_UNUSED(out);
	GIT3_UNUSED(repo);
	GIT3_UNUSED(parent);
	GIT3_UNUSED(note_oid);
	GIT3_UNUSED(fanout);

	git3_error_set(GIT3_ERROR_REPOSITORY, "object '%s' has no note", annotated_object_sha);
	return current_error;
}

static int insert_note_in_tree_eexists_cb(git3_tree **out,
	git3_repository *repo,
	git3_tree *parent,
	git3_oid *note_oid,
	const char *annotated_object_sha,
	int fanout,
	int current_error)
{
	GIT3_UNUSED(out);
	GIT3_UNUSED(repo);
	GIT3_UNUSED(parent);
	GIT3_UNUSED(note_oid);
	GIT3_UNUSED(fanout);

	git3_error_set(GIT3_ERROR_REPOSITORY, "note for '%s' exists already", annotated_object_sha);
	return current_error;
}

static int insert_note_in_tree_enotfound_cb(git3_tree **out,
	git3_repository *repo,
	git3_tree *parent,
	git3_oid *note_oid,
	const char *annotated_object_sha,
	int fanout,
	int current_error)
{
	GIT3_UNUSED(current_error);

	/* No existing fanout at this level, insert in place */
	return tree_write(
		out,
		repo,
		parent,
		note_oid,
		annotated_object_sha + fanout,
		GIT3_FILEMODE_BLOB);
}

static int note_write(
	git3_oid *notes_commit_out,
	git3_oid *notes_blob_out,
	git3_repository *repo,
	const git3_signature *author,
	const git3_signature *committer,
	const char *notes_ref,
	const char *note,
	git3_tree *commit_tree,
	const char *target,
	git3_commit **parents,
	int allow_note_overwrite)
{
	int error;
	git3_oid oid;
	git3_tree *tree = NULL;

	/* TODO: should we apply filters? */
	/* create note object */
	if ((error = git3_blob_create_from_buffer(&oid, repo, note, strlen(note))) < 0)
		goto cleanup;

	if ((error = manipulate_note_in_tree_r(
		&tree, repo, commit_tree, &oid, target, 0,
		allow_note_overwrite ? insert_note_in_tree_enotfound_cb : insert_note_in_tree_eexists_cb,
		insert_note_in_tree_enotfound_cb)) < 0)
		goto cleanup;

	if (notes_blob_out)
		git3_oid_cpy(notes_blob_out, &oid);


	error = git3_commit_create(&oid, repo, notes_ref, author, committer,
				  NULL, GIT3_NOTES_DEFAULT_MSG_ADD,
				  tree, *parents == NULL ? 0 : 1, (const git3_commit **) parents);

	if (notes_commit_out)
		git3_oid_cpy(notes_commit_out, &oid);

cleanup:
	git3_tree_free(tree);
	return error;
}

static int note_new(
	git3_note **out,
	git3_oid *note_oid,
	git3_commit *commit,
	git3_blob *blob)
{
	git3_note *note = NULL;
	git3_object_size_t blobsize;

	note = git3__malloc(sizeof(git3_note));
	GIT3_ERROR_CHECK_ALLOC(note);

	git3_oid_cpy(&note->id, note_oid);

	if (git3_signature_dup(&note->author, git3_commit_author(commit)) < 0 ||
		git3_signature_dup(&note->committer, git3_commit_committer(commit)) < 0)
		return -1;

	blobsize = git3_blob_rawsize(blob);
	GIT3_ERROR_CHECK_BLOBSIZE(blobsize);

	note->message = git3__strndup(git3_blob_rawcontent(blob), (size_t)blobsize);
	GIT3_ERROR_CHECK_ALLOC(note->message);

	*out = note;
	return 0;
}

static int note_lookup(
	git3_note **out,
	git3_repository *repo,
	git3_commit *commit,
	git3_tree *tree,
	const char *target)
{
	int error, fanout = 0;
	git3_oid oid;
	git3_blob *blob = NULL;
	git3_note *note = NULL;
	git3_tree *subtree = NULL;

	if ((error = find_subtree_r(&subtree, tree, repo, target, &fanout)) < 0)
		goto cleanup;

	if ((error = find_blob(&oid, subtree, target + fanout)) < 0)
		goto cleanup;

	if ((error = git3_blob_lookup(&blob, repo, &oid)) < 0)
		goto cleanup;

	if ((error = note_new(&note, &oid, commit, blob)) < 0)
		goto cleanup;

	*out = note;

cleanup:
	git3_tree_free(subtree);
	git3_blob_free(blob);
	return error;
}

static int note_remove(
		git3_oid *notes_commit_out,
		git3_repository *repo,
		const git3_signature *author, const git3_signature *committer,
		const char *notes_ref, git3_tree *tree,
		const char *target, git3_commit **parents)
{
	int error;
	git3_tree *tree_after_removal = NULL;
	git3_oid oid;

	if ((error = manipulate_note_in_tree_r(
		&tree_after_removal, repo, tree, NULL, target, 0,
		remove_note_in_tree_eexists_cb, remove_note_in_tree_enotfound_cb)) < 0)
		goto cleanup;

	error = git3_commit_create(&oid, repo, notes_ref, author, committer,
	  NULL, GIT3_NOTES_DEFAULT_MSG_RM,
	  tree_after_removal,
	  *parents == NULL ? 0 : 1,
	  (const git3_commit **) parents);

	if (error < 0)
		goto cleanup;

	if (notes_commit_out)
		git3_oid_cpy(notes_commit_out, &oid);

cleanup:
	git3_tree_free(tree_after_removal);
	return error;
}

static int note_get_default_ref(git3_str *out, git3_repository *repo)
{
	git3_config *cfg;
	int error;

	if ((error = git3_repository_config__weakptr(&cfg, repo)) < 0)
		return error;

	error = git3_config__get_string_buf(out, cfg, "core.notesref");

	if (error == GIT3_ENOTFOUND)
		error = git3_str_puts(out, GIT3_NOTES_DEFAULT_REF);

	return error;
}

static int normalize_namespace(git3_str *out, git3_repository *repo, const char *notes_ref)
{
	if (notes_ref)
		return git3_str_puts(out, notes_ref);

	return note_get_default_ref(out, repo);
}

static int retrieve_note_commit(
	git3_commit **commit_out,
	git3_str *notes_ref_out,
	git3_repository *repo,
	const char *notes_ref)
{
	int error;
	git3_oid oid;

	if ((error = normalize_namespace(notes_ref_out, repo, notes_ref)) < 0)
		return error;

	if ((error = git3_reference_name_to_id(&oid, repo, notes_ref_out->ptr)) < 0)
		return error;

	if (git3_commit_lookup(commit_out, repo, &oid) < 0)
		return error;

	return 0;
}

int git3_note_commit_read(
	git3_note **out,
	git3_repository *repo,
	git3_commit *notes_commit,
	const git3_oid *oid)
{
	int error;
	git3_tree *tree = NULL;
	char target[GIT3_OID_MAX_HEXSIZE + 1];

	git3_oid_tostr(target, sizeof(target), oid);

	if ((error = git3_commit_tree(&tree, notes_commit)) < 0)
		goto cleanup;

	error = note_lookup(out, repo, notes_commit, tree, target);

cleanup:
	git3_tree_free(tree);
	return error;
}

int git3_note_read(git3_note **out, git3_repository *repo,
		  const char *notes_ref_in, const git3_oid *oid)
{
	int error;
	git3_str notes_ref = GIT3_STR_INIT;
	git3_commit *commit = NULL;

	error = retrieve_note_commit(&commit, &notes_ref, repo, notes_ref_in);

	if (error < 0)
		goto cleanup;

	error = git3_note_commit_read(out, repo, commit, oid);

cleanup:
	git3_str_dispose(&notes_ref);
	git3_commit_free(commit);
	return error;
}

int git3_note_commit_create(
	git3_oid *notes_commit_out,
	git3_oid *notes_blob_out,
	git3_repository *repo,
	git3_commit *parent,
	const git3_signature *author,
	const git3_signature *committer,
	const git3_oid *oid,
	const char *note,
	int allow_note_overwrite)
{
	int error;
	git3_tree *tree = NULL;
	char target[GIT3_OID_MAX_HEXSIZE + 1];

	git3_oid_tostr(target, sizeof(target), oid);

	if (parent != NULL && (error = git3_commit_tree(&tree, parent)) < 0)
		goto cleanup;

	error = note_write(notes_commit_out, notes_blob_out, repo, author,
			committer, NULL, note, tree, target, &parent, allow_note_overwrite);

	if (error < 0)
		goto cleanup;

cleanup:
	git3_tree_free(tree);
	return error;
}

int git3_note_create(
	git3_oid *out,
	git3_repository *repo,
	const char *notes_ref_in,
	const git3_signature *author,
	const git3_signature *committer,
	const git3_oid *oid,
	const char *note,
	int allow_note_overwrite)
{
	int error;
	git3_str notes_ref = GIT3_STR_INIT;
	git3_commit *existing_notes_commit = NULL;
	git3_reference *ref = NULL;
	git3_oid notes_blob_oid, notes_commit_oid;

	error = retrieve_note_commit(&existing_notes_commit, &notes_ref,
			repo, notes_ref_in);

	if (error < 0 && error != GIT3_ENOTFOUND)
		goto cleanup;

	error = git3_note_commit_create(&notes_commit_oid,
			&notes_blob_oid,
			repo, existing_notes_commit, author,
			committer, oid, note,
			allow_note_overwrite);
	if (error < 0)
		goto cleanup;

	error = git3_reference_create(&ref, repo, notes_ref.ptr,
				&notes_commit_oid, 1, NULL);

	if (out != NULL)
		git3_oid_cpy(out, &notes_blob_oid);

cleanup:
	git3_str_dispose(&notes_ref);
	git3_commit_free(existing_notes_commit);
	git3_reference_free(ref);
	return error;
}

int git3_note_commit_remove(
		git3_oid *notes_commit_out,
		git3_repository *repo,
		git3_commit *notes_commit,
		const git3_signature *author,
		const git3_signature *committer,
		const git3_oid *oid)
{
	int error;
	git3_tree *tree = NULL;
	char target[GIT3_OID_MAX_HEXSIZE + 1];

	git3_oid_tostr(target, sizeof(target), oid);

	if ((error = git3_commit_tree(&tree, notes_commit)) < 0)
		goto cleanup;

	error = note_remove(notes_commit_out,
		repo, author, committer, NULL, tree, target, &notes_commit);

cleanup:
	git3_tree_free(tree);
	return error;
}

int git3_note_remove(git3_repository *repo, const char *notes_ref_in,
		const git3_signature *author, const git3_signature *committer,
		const git3_oid *oid)
{
	int error;
	git3_str notes_ref_target = GIT3_STR_INIT;
	git3_commit *existing_notes_commit = NULL;
	git3_oid new_notes_commit;
	git3_reference *notes_ref = NULL;

	error = retrieve_note_commit(&existing_notes_commit, &notes_ref_target,
			repo, notes_ref_in);

	if (error < 0)
		goto cleanup;

	error = git3_note_commit_remove(&new_notes_commit, repo,
			existing_notes_commit, author, committer, oid);
	if (error < 0)
		goto cleanup;

	error = git3_reference_create(&notes_ref, repo, notes_ref_target.ptr,
			&new_notes_commit, 1, NULL);

cleanup:
	git3_str_dispose(&notes_ref_target);
	git3_reference_free(notes_ref);
	git3_commit_free(existing_notes_commit);
	return error;
}

int git3_note_default_ref(git3_buf *out, git3_repository *repo)
{
	GIT3_BUF_WRAP_PRIVATE(out, note_get_default_ref, repo);
}

const git3_signature *git3_note_committer(const git3_note *note)
{
	GIT3_ASSERT_ARG_WITH_RETVAL(note, NULL);
	return note->committer;
}

const git3_signature *git3_note_author(const git3_note *note)
{
	GIT3_ASSERT_ARG_WITH_RETVAL(note, NULL);
	return note->author;
}

const char *git3_note_message(const git3_note *note)
{
	GIT3_ASSERT_ARG_WITH_RETVAL(note, NULL);
	return note->message;
}

const git3_oid *git3_note_id(const git3_note *note)
{
	GIT3_ASSERT_ARG_WITH_RETVAL(note, NULL);
	return &note->id;
}

void git3_note_free(git3_note *note)
{
	if (note == NULL)
		return;

	git3_signature_free(note->committer);
	git3_signature_free(note->author);
	git3__free(note->message);
	git3__free(note);
}

static int process_entry_path(
	git3_oid *annotated_object_id,
	git3_note_iterator *it,
	const char *entry_path)
{
	int error = 0;
	size_t i = 0, j = 0, len;
	git3_str buf = GIT3_STR_INIT;

	if ((error = git3_str_puts(&buf, entry_path)) < 0)
		goto cleanup;

	len = git3_str_len(&buf);

	while (i < len) {
		if (buf.ptr[i] == '/') {
			i++;
			continue;
		}

		if (git3__fromhex(buf.ptr[i]) < 0) {
			/* This is not a note entry */
			goto cleanup;
		}

		if (i != j)
			buf.ptr[j] = buf.ptr[i];

		i++;
		j++;
	}

	buf.ptr[j] = '\0';
	buf.size = j;

	if (j != git3_oid_hexsize(it->repo->oid_type)) {
		/* This is not a note entry */
		goto cleanup;
	}

	error = git3_oid_from_string(annotated_object_id, buf.ptr, it->repo->oid_type);

cleanup:
	git3_str_dispose(&buf);
	return error;
}

int git3_note_foreach(
	git3_repository *repo,
	const char *notes_ref,
	git3_note_foreach_cb note_cb,
	void *payload)
{
	int error;
	git3_note_iterator *iter = NULL;
	git3_oid note_id, annotated_id;

	if ((error = git3_note_iterator_new(&iter, repo, notes_ref)) < 0)
		return error;

	while (!(error = git3_note_next(&note_id, &annotated_id, iter))) {
		if ((error = note_cb(&note_id, &annotated_id, payload)) != 0) {
			git3_error_set_after_callback(error);
			break;
		}
	}

	if (error == GIT3_ITEROVER)
		error = 0;

	git3_note_iterator_free(iter);
	return error;
}

void git3_note_iterator_free(git3_note_iterator *it)
{
	if (it == NULL)
		return;

	git3_iterator_free(it);
}

int git3_note_commit_iterator_new(
	git3_note_iterator **it,
	git3_commit *notes_commit)
{
	int error;
	git3_tree *tree;

	if ((error = git3_commit_tree(&tree, notes_commit)) < 0)
		goto cleanup;

	if ((error = git3_iterator_for_tree(it, tree, NULL)) < 0)
		git3_iterator_free(*it);

cleanup:
	git3_tree_free(tree);

	return error;
}

int git3_note_iterator_new(
	git3_note_iterator **it,
	git3_repository *repo,
	const char *notes_ref_in)
{
	int error;
	git3_commit *commit = NULL;
	git3_str notes_ref = GIT3_STR_INIT;

	error = retrieve_note_commit(&commit, &notes_ref, repo, notes_ref_in);
	if (error < 0)
		goto cleanup;

	error = git3_note_commit_iterator_new(it, commit);

cleanup:
	git3_str_dispose(&notes_ref);
	git3_commit_free(commit);

	return error;
}

int git3_note_next(
	git3_oid *note_id,
	git3_oid *annotated_id,
	git3_note_iterator *it)
{
	int error;
	const git3_index_entry *item;

	if ((error = git3_iterator_current(&item, it)) < 0)
		return error;

	git3_oid_cpy(note_id, &item->id);

	if ((error = process_entry_path(annotated_id, it, item->path)) < 0)
		return error;

	if ((error = git3_iterator_advance(NULL, it)) < 0 && error != GIT3_ITEROVER)
		return error;

	return 0;
}
