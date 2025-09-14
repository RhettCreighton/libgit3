/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_git_note_h__
#define INCLUDE_git_note_h__

#include "oid.h"

/**
 * @file git3/notes.h
 * @brief Notes are metadata attached to an object
 * @defgroup git3_note Git notes management routines
 * @ingroup Git
 * @{
 */
GIT3_BEGIN_DECL

/**
 * Callback for git3_note_foreach.
 *
 * @param blob_id object id of the blob containing the message
 * @param annotated_object_id the id of the object being annotated
 * @param payload user-specified data to the foreach function
 * @return 0 on success, or a negative number on failure
 */
typedef int GIT3_CALLBACK(git3_note_foreach_cb)(
	const git3_oid *blob_id,
	const git3_oid *annotated_object_id,
	void *payload);

/**
 * note iterator
 */
typedef struct git3_iterator git3_note_iterator;

/**
 * Creates a new iterator for notes
 *
 * The iterator must be freed manually by the user.
 *
 * @param out pointer to the iterator
 * @param repo repository where to look up the note
 * @param notes_ref canonical name of the reference to use (optional); defaults to
 *                  "refs/notes/commits"
 *
 * @return 0 or an error code
 */
GIT3_EXTERN(int) git3_note_iterator_new(
	git3_note_iterator **out,
	git3_repository *repo,
	const char *notes_ref);

/**
 * Creates a new iterator for notes from a commit
 *
 * The iterator must be freed manually by the user.
 *
 * @param out pointer to the iterator
 * @param notes_commit a pointer to the notes commit object
 *
 * @return 0 or an error code
 */
GIT3_EXTERN(int) git3_note_commit_iterator_new(
	git3_note_iterator **out,
	git3_commit *notes_commit);

/**
 * Frees an git3_note_iterator
 *
 * @param it pointer to the iterator
 */
GIT3_EXTERN(void) git3_note_iterator_free(git3_note_iterator *it);

/**
 * Return the current item (note_id and annotated_id) and advance the iterator
 * internally to the next value
 *
 * @param note_id id of blob containing the message
 * @param annotated_id id of the git object being annotated
 * @param it pointer to the iterator
 *
 * @return 0 (no error), GIT3_ITEROVER (iteration is done) or an error code
 *         (negative value)
 */
GIT3_EXTERN(int) git3_note_next(
	git3_oid *note_id,
	git3_oid *annotated_id,
	git3_note_iterator *it);


/**
 * Read the note for an object
 *
 * The note must be freed manually by the user.
 *
 * @param out pointer to the read note; NULL in case of error
 * @param repo repository where to look up the note
 * @param notes_ref canonical name of the reference to use (optional); defaults to
 *                  "refs/notes/commits"
 * @param oid OID of the git object to read the note from
 *
 * @return 0 or an error code
 */
GIT3_EXTERN(int) git3_note_read(
	git3_note **out,
	git3_repository *repo,
	const char *notes_ref,
	const git3_oid *oid);


/**
 * Read the note for an object from a note commit
 *
 * The note must be freed manually by the user.
 *
 * @param out pointer to the read note; NULL in case of error
 * @param repo repository where to look up the note
 * @param notes_commit a pointer to the notes commit object
 * @param oid OID of the git object to read the note from
 *
 * @return 0 or an error code
 */
GIT3_EXTERN(int) git3_note_commit_read(
	git3_note **out,
	git3_repository *repo,
	git3_commit *notes_commit,
	const git3_oid *oid);

/**
 * Get the note author
 *
 * @param note the note
 * @return the author
 */
GIT3_EXTERN(const git3_signature *) git3_note_author(const git3_note *note);

/**
 * Get the note committer
 *
 * @param note the note
 * @return the committer
 */
GIT3_EXTERN(const git3_signature *) git3_note_committer(const git3_note *note);


/**
 * Get the note message
 *
 * @param note the note
 * @return the note message
 */
GIT3_EXTERN(const char *) git3_note_message(const git3_note *note);


/**
 * Get the note object's id
 *
 * @param note the note
 * @return the note object's id
 */
GIT3_EXTERN(const git3_oid *) git3_note_id(const git3_note *note);

/**
 * Add a note for an object
 *
 * @param out pointer to store the OID (optional); NULL in case of error
 * @param repo repository where to store the note
 * @param notes_ref canonical name of the reference to use (optional);
 *					defaults to "refs/notes/commits"
 * @param author signature of the notes commit author
 * @param committer signature of the notes commit committer
 * @param oid OID of the git object to decorate
 * @param note Content of the note to add for object oid
 * @param force Overwrite existing note
 *
 * @return 0 or an error code
 */
GIT3_EXTERN(int) git3_note_create(
	git3_oid *out,
	git3_repository *repo,
	const char *notes_ref,
	const git3_signature *author,
	const git3_signature *committer,
	const git3_oid *oid,
	const char *note,
	int force);

/**
 * Add a note for an object from a commit
 *
 * This function will create a notes commit for a given object,
 * the commit is a dangling commit, no reference is created.
 *
 * @param notes_commit_out pointer to store the commit (optional);
 *					NULL in case of error
 * @param notes_blob_out a point to the id of a note blob (optional)
 * @param repo repository where the note will live
 * @param parent Pointer to parent note
 *					or NULL if this shall start a new notes tree
 * @param author signature of the notes commit author
 * @param committer signature of the notes commit committer
 * @param oid OID of the git object to decorate
 * @param note Content of the note to add for object oid
 * @param allow_note_overwrite Overwrite existing note
 *
 * @return 0 or an error code
 */
GIT3_EXTERN(int) git3_note_commit_create(
	git3_oid *notes_commit_out,
	git3_oid *notes_blob_out,
	git3_repository *repo,
	git3_commit *parent,
	const git3_signature *author,
	const git3_signature *committer,
	const git3_oid *oid,
	const char *note,
	int allow_note_overwrite);

/**
 * Remove the note for an object
 *
 * @param repo repository where the note lives
 * @param notes_ref canonical name of the reference to use (optional);
 *					defaults to "refs/notes/commits"
 * @param author signature of the notes commit author
 * @param committer signature of the notes commit committer
 * @param oid OID of the git object to remove the note from
 *
 * @return 0 or an error code
 */
GIT3_EXTERN(int) git3_note_remove(
	git3_repository *repo,
	const char *notes_ref,
	const git3_signature *author,
	const git3_signature *committer,
	const git3_oid *oid);

/**
 * Remove the note for an object
 *
 * @param notes_commit_out pointer to store the new notes commit (optional);
 *					NULL in case of error.
 *					When removing a note a new tree containing all notes
 *					sans the note to be removed is created and a new commit
 *					pointing to that tree is also created.
 *					In the case where the resulting tree is an empty tree
 *					a new commit pointing to this empty tree will be returned.
 * @param repo repository where the note lives
 * @param notes_commit a pointer to the notes commit object
 * @param author signature of the notes commit author
 * @param committer signature of the notes commit committer
 * @param oid OID of the git object to remove the note from
 *
 * @return 0 or an error code
 */
GIT3_EXTERN(int) git3_note_commit_remove(
		git3_oid *notes_commit_out,
		git3_repository *repo,
		git3_commit *notes_commit,
		const git3_signature *author,
		const git3_signature *committer,
		const git3_oid *oid);

/**
 * Free a git3_note object
 *
 * @param note git3_note object
 */
GIT3_EXTERN(void) git3_note_free(git3_note *note);

/**
 * Get the default notes reference for a repository
 *
 * @param out buffer in which to store the name of the default notes reference
 * @param repo The Git repository
 *
 * @return 0 or an error code
 */
GIT3_EXTERN(int) git3_note_default_ref(git3_buf *out, git3_repository *repo);

/**
 * Loop over all the notes within a specified namespace
 * and issue a callback for each one.
 *
 * @param repo Repository where to find the notes.
 *
 * @param notes_ref Reference to read from (optional); defaults to
 *        "refs/notes/commits".
 *
 * @param note_cb Callback to invoke per found annotation.  Return non-zero
 *        to stop looping.
 *
 * @param payload Extra parameter to callback function.
 *
 * @return 0 on success, non-zero callback return value, or error code
 */
GIT3_EXTERN(int) git3_note_foreach(
	git3_repository *repo,
	const char *notes_ref,
	git3_note_foreach_cb note_cb,
	void *payload);

/** @} */
GIT3_END_DECL

#endif
