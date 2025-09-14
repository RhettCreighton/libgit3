/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "tag.h"

#include "commit.h"
#include "signature.h"
#include "wildmatch.h"
#include "git3/object.h"
#include "git3/repository.h"
#include "git3/signature.h"
#include "git3/odb_backend.h"

void git3_tag__free(void *_tag)
{
	git3_tag *tag = _tag;
	git3_signature_free(tag->tagger);
	git3__free(tag->message);
	git3__free(tag->tag_name);
	git3__free(tag);
}

int git3_tag_target(git3_object **target, const git3_tag *t)
{
	GIT3_ASSERT_ARG(t);
	return git3_object_lookup(target, t->object.repo, &t->target, t->type);
}

const git3_oid *git3_tag_target_id(const git3_tag *t)
{
	GIT3_ASSERT_ARG_WITH_RETVAL(t, NULL);
	return &t->target;
}

git3_object_t git3_tag_target_type(const git3_tag *t)
{
	GIT3_ASSERT_ARG_WITH_RETVAL(t, GIT3_OBJECT_INVALID);
	return t->type;
}

const char *git3_tag_name(const git3_tag *t)
{
	GIT3_ASSERT_ARG_WITH_RETVAL(t, NULL);
	return t->tag_name;
}

const git3_signature *git3_tag_tagger(const git3_tag *t)
{
	return t->tagger;
}

const char *git3_tag_message(const git3_tag *t)
{
	GIT3_ASSERT_ARG_WITH_RETVAL(t, NULL);
	return t->message;
}

static int tag_error(const char *str)
{
	git3_error_set(GIT3_ERROR_TAG, "failed to parse tag: %s", str);
	return GIT3_EINVALID;
}

static int tag_parse(
	git3_tag *tag,
	const char *buffer,
	const char *buffer_end,
	git3_oid_t oid_type)
{
	static const char *tag_types[] = {
		NULL, "commit\n", "tree\n", "blob\n", "tag\n"
	};
	size_t text_len, alloc_len;
	const char *search;
	unsigned int i;
	int error;

	if (git3_object__parse_oid_header(&tag->target,
			&buffer, buffer_end, "object ", oid_type) < 0)
		return tag_error("object field invalid");

	if (buffer + 5 >= buffer_end)
		return tag_error("object too short");

	if (memcmp(buffer, "type ", 5) != 0)
		return tag_error("type field not found");
	buffer += 5;

	tag->type = GIT3_OBJECT_INVALID;

	for (i = 1; i < ARRAY_SIZE(tag_types); ++i) {
		size_t type_length = strlen(tag_types[i]);

		if (buffer + type_length >= buffer_end)
			return tag_error("object too short");

		if (memcmp(buffer, tag_types[i], type_length) == 0) {
			tag->type = i;
			buffer += type_length;
			break;
		}
	}

	if (tag->type == GIT3_OBJECT_INVALID)
		return tag_error("invalid object type");

	if (buffer + 4 >= buffer_end)
		return tag_error("object too short");

	if (memcmp(buffer, "tag ", 4) != 0)
		return tag_error("tag field not found");

	buffer += 4;

	search = memchr(buffer, '\n', buffer_end - buffer);
	if (search == NULL)
		return tag_error("object too short");

	text_len = search - buffer;

	GIT3_ERROR_CHECK_ALLOC_ADD(&alloc_len, text_len, 1);
	tag->tag_name = git3__malloc(alloc_len);
	GIT3_ERROR_CHECK_ALLOC(tag->tag_name);

	memcpy(tag->tag_name, buffer, text_len);
	tag->tag_name[text_len] = '\0';

	buffer = search + 1;

	tag->tagger = NULL;
	if (buffer < buffer_end && *buffer != '\n') {
		tag->tagger = git3__malloc(sizeof(git3_signature));
		GIT3_ERROR_CHECK_ALLOC(tag->tagger);

		if ((error = git3_signature__parse(tag->tagger, &buffer, buffer_end, "tagger ", '\n')) < 0)
			return error;
	}

	tag->message = NULL;
	if (buffer < buffer_end) {
		/* If we're not at the end of the header, search for it */
		if(*buffer != '\n') {
			search = git3__memmem(buffer, buffer_end - buffer,
					     "\n\n", 2);
			if (search)
				buffer = search + 1;
			else
				return tag_error("tag contains no message");
		}

		text_len = buffer_end - ++buffer;

		GIT3_ERROR_CHECK_ALLOC_ADD(&alloc_len, text_len, 1);
		tag->message = git3__malloc(alloc_len);
		GIT3_ERROR_CHECK_ALLOC(tag->message);

		memcpy(tag->message, buffer, text_len);
		tag->message[text_len] = '\0';
	}

	return 0;
}

int git3_tag__parse_raw(
	void *_tag,
	const char *data,
	size_t size,
	git3_oid_t oid_type)
{
	return tag_parse(_tag, data, data + size, oid_type);
}

int git3_tag__parse(
	void *_tag,
	git3_odb_object *odb_obj,
	git3_oid_t oid_type)
{
	git3_tag *tag = _tag;
	const char *buffer = git3_odb_object_data(odb_obj);
	const char *buffer_end = buffer + git3_odb_object_size(odb_obj);

	return tag_parse(tag, buffer, buffer_end, oid_type);
}

static int retrieve_tag_reference(
	git3_reference **tag_reference_out,
	git3_str *ref_name_out,
	git3_repository *repo,
	const char *tag_name)
{
	git3_reference *tag_ref;
	int error;

	*tag_reference_out = NULL;

	if (git3_str_joinpath(ref_name_out, GIT3_REFS_TAGS_DIR, tag_name) < 0)
		return -1;

	error = git3_reference_lookup(&tag_ref, repo, ref_name_out->ptr);
	if (error < 0)
		return error; /* Be it not foundo or corrupted */

	*tag_reference_out = tag_ref;

	return 0;
}

static int retrieve_tag_reference_oid(
	git3_oid *oid,
	git3_str *ref_name_out,
	git3_repository *repo,
	const char *tag_name)
{
	if (git3_str_joinpath(ref_name_out, GIT3_REFS_TAGS_DIR, tag_name) < 0)
		return -1;

	return git3_reference_name_to_id(oid, repo, ref_name_out->ptr);
}

static int write_tag_annotation(
		git3_oid *oid,
		git3_repository *repo,
		const char *tag_name,
		const git3_object *target,
		const git3_signature *tagger,
		const char *message)
{
	git3_str tag = GIT3_STR_INIT;
	git3_odb *odb;

	if (git3_object__write_oid_header(&tag, "object ", git3_object_id(target)) < 0)
		goto on_error;

	git3_str_printf(&tag, "type %s\n", git3_object_type2string(git3_object_type(target)));
	git3_str_printf(&tag, "tag %s\n", tag_name);
	git3_signature__writebuf(&tag, "tagger ", tagger);
	git3_str_putc(&tag, '\n');

	if (git3_str_puts(&tag, message) < 0)
		goto on_error;

	if (git3_repository_odb__weakptr(&odb, repo) < 0)
		goto on_error;

	if (git3_odb_write(oid, odb, tag.ptr, tag.size, GIT3_OBJECT_TAG) < 0)
		goto on_error;

	git3_str_dispose(&tag);
	return 0;

on_error:
	git3_str_dispose(&tag);
	git3_error_set(GIT3_ERROR_OBJECT, "failed to create tag annotation");
	return -1;
}

static bool tag_name_is_valid(const char *tag_name)
{
	/*
	 * Discourage tag name starting with dash,
	 * https://github.com/git/git/commit/4f0accd638b8d2
	 * and refuse to use HEAD as a tagname,
	 * https://github.com/git/git/commit/bbd445d5efd415
	 */
	return tag_name[0] != '-' && git3__strcmp(tag_name, "HEAD");
}

static int git3_tag_create__internal(
		git3_oid *oid,
		git3_repository *repo,
		const char *tag_name,
		const git3_object *target,
		const git3_signature *tagger,
		const char *message,
		int allow_ref_overwrite,
		int create_tag_annotation)
{
	git3_reference *new_ref = NULL;
	git3_str ref_name = GIT3_STR_INIT;

	int error;

	GIT3_ASSERT_ARG(repo);
	GIT3_ASSERT_ARG(tag_name);
	GIT3_ASSERT_ARG(target);
	GIT3_ASSERT_ARG(!create_tag_annotation || (tagger && message));

	if (git3_object_owner(target) != repo) {
		git3_error_set(GIT3_ERROR_INVALID, "the given target does not belong to this repository");
		return -1;
	}

	if (!tag_name_is_valid(tag_name)) {
		git3_error_set(GIT3_ERROR_TAG, "'%s' is not a valid tag name", tag_name);
		return -1;
	}

	error = retrieve_tag_reference_oid(oid, &ref_name, repo, tag_name);
	if (error < 0 && error != GIT3_ENOTFOUND)
		goto cleanup;

	/** Ensure the tag name doesn't conflict with an already existing
	 *	reference unless overwriting has explicitly been requested **/
	if (error == 0 && !allow_ref_overwrite) {
		git3_str_dispose(&ref_name);
		git3_error_set(GIT3_ERROR_TAG, "tag already exists");
		return GIT3_EEXISTS;
	}

	if (create_tag_annotation) {
		if (write_tag_annotation(oid, repo, tag_name, target, tagger, message) < 0) {
			git3_str_dispose(&ref_name);
			return -1;
		}
	} else
		git3_oid_cpy(oid, git3_object_id(target));

	error = git3_reference_create(&new_ref, repo, ref_name.ptr, oid, allow_ref_overwrite, NULL);

cleanup:
	git3_reference_free(new_ref);
	git3_str_dispose(&ref_name);
	return error;
}

int git3_tag_create(
	git3_oid *oid,
	git3_repository *repo,
	const char *tag_name,
	const git3_object *target,
	const git3_signature *tagger,
	const char *message,
	int allow_ref_overwrite)
{
	return git3_tag_create__internal(oid, repo, tag_name, target, tagger, message, allow_ref_overwrite, 1);
}

int git3_tag_annotation_create(
	git3_oid *oid,
	git3_repository *repo,
	const char *tag_name,
	const git3_object *target,
	const git3_signature *tagger,
	const char *message)
{
	GIT3_ASSERT_ARG(oid);
	GIT3_ASSERT_ARG(repo);
	GIT3_ASSERT_ARG(tag_name);
	GIT3_ASSERT_ARG(target);
	GIT3_ASSERT_ARG(tagger);
	GIT3_ASSERT_ARG(message);

	return write_tag_annotation(oid, repo, tag_name, target, tagger, message);
}

int git3_tag_create_lightweight(
	git3_oid *oid,
	git3_repository *repo,
	const char *tag_name,
	const git3_object *target,
	int allow_ref_overwrite)
{
	return git3_tag_create__internal(oid, repo, tag_name, target, NULL, NULL, allow_ref_overwrite, 0);
}

int git3_tag_create_from_buffer(git3_oid *oid, git3_repository *repo, const char *buffer, int allow_ref_overwrite)
{
	git3_tag tag;
	int error;
	git3_odb *odb;
	git3_odb_stream *stream;
	git3_odb_object *target_obj;

	git3_reference *new_ref = NULL;
	git3_str ref_name = GIT3_STR_INIT;

	GIT3_ASSERT_ARG(oid);
	GIT3_ASSERT_ARG(buffer);

	memset(&tag, 0, sizeof(tag));

	if (git3_repository_odb__weakptr(&odb, repo) < 0)
		return -1;

	/* validate the buffer */
	if (tag_parse(&tag, buffer, buffer + strlen(buffer), repo->oid_type) < 0)
		return -1;

	/* validate the target */
	if (git3_odb_read(&target_obj, odb, &tag.target) < 0)
		goto on_error;

	if (tag.type != target_obj->cached.type) {
		git3_error_set(GIT3_ERROR_TAG, "the type for the given target is invalid");
		goto on_error;
	}

	error = retrieve_tag_reference_oid(oid, &ref_name, repo, tag.tag_name);
	if (error < 0 && error != GIT3_ENOTFOUND)
		goto on_error;

	/* We don't need these objects after this */
	git3_signature_free(tag.tagger);
	git3__free(tag.tag_name);
	git3__free(tag.message);
	git3_odb_object_free(target_obj);

	/** Ensure the tag name doesn't conflict with an already existing
	 *	reference unless overwriting has explicitly been requested **/
	if (error == 0 && !allow_ref_overwrite) {
		git3_str_dispose(&ref_name);
		git3_error_set(GIT3_ERROR_TAG, "tag already exists");
		return GIT3_EEXISTS;
	}

	/* write the buffer */
	if ((error = git3_odb_open_wstream(
			&stream, odb, strlen(buffer), GIT3_OBJECT_TAG)) < 0) {
		git3_str_dispose(&ref_name);
		return error;
	}

	if (!(error = git3_odb_stream_write(stream, buffer, strlen(buffer))))
		error = git3_odb_stream_finalize_write(oid, stream);

	git3_odb_stream_free(stream);

	if (error < 0) {
		git3_str_dispose(&ref_name);
		return error;
	}

	error = git3_reference_create(
		&new_ref, repo, ref_name.ptr, oid, allow_ref_overwrite, NULL);

	git3_reference_free(new_ref);
	git3_str_dispose(&ref_name);

	return error;

on_error:
	git3_signature_free(tag.tagger);
	git3__free(tag.tag_name);
	git3__free(tag.message);
	git3_odb_object_free(target_obj);
	return -1;
}

int git3_tag_delete(git3_repository *repo, const char *tag_name)
{
	git3_reference *tag_ref;
	git3_str ref_name = GIT3_STR_INIT;
	int error;

	error = retrieve_tag_reference(&tag_ref, &ref_name, repo, tag_name);

	git3_str_dispose(&ref_name);

	if (error < 0)
		return error;

	error = git3_reference_delete(tag_ref);

	git3_reference_free(tag_ref);

	return error;
}

typedef struct {
	git3_repository *repo;
	git3_tag_foreach_cb cb;
	void *cb_data;
} tag_cb_data;

static int tags_cb(const char *ref, void *data)
{
	int error;
	git3_oid oid;
	tag_cb_data *d = (tag_cb_data *)data;

	if (git3__prefixcmp(ref, GIT3_REFS_TAGS_DIR) != 0)
		return 0; /* no tag */

	if (!(error = git3_reference_name_to_id(&oid, d->repo, ref))) {
		if ((error = d->cb(ref, &oid, d->cb_data)) != 0)
			git3_error_set_after_callback_function(error, "git3_tag_foreach");
	}

	return error;
}

int git3_tag_foreach(git3_repository *repo, git3_tag_foreach_cb cb, void *cb_data)
{
	tag_cb_data data;

	GIT3_ASSERT_ARG(repo);
	GIT3_ASSERT_ARG(cb);

	data.cb = cb;
	data.cb_data = cb_data;
	data.repo = repo;

	return git3_reference_foreach_name(repo, &tags_cb, &data);
}

typedef struct {
	git3_vector *taglist;
	const char *pattern;
} tag_filter_data;

#define GIT3_REFS_TAGS_DIR_LEN strlen(GIT3_REFS_TAGS_DIR)

static int tag_list_cb(const char *tag_name, git3_oid *oid, void *data)
{
	tag_filter_data *filter = (tag_filter_data *)data;
	GIT3_UNUSED(oid);

	if (!*filter->pattern ||
	    wildmatch(filter->pattern, tag_name + GIT3_REFS_TAGS_DIR_LEN, 0) == 0)
	{
		char *matched = git3__strdup(tag_name + GIT3_REFS_TAGS_DIR_LEN);
		GIT3_ERROR_CHECK_ALLOC(matched);

		return git3_vector_insert(filter->taglist, matched);
	}

	return 0;
}

int git3_tag_list_match(git3_strarray *tag_names, const char *pattern, git3_repository *repo)
{
	int error;
	tag_filter_data filter;
	git3_vector taglist;

	GIT3_ASSERT_ARG(tag_names);
	GIT3_ASSERT_ARG(repo);
	GIT3_ASSERT_ARG(pattern);

	if ((error = git3_vector_init(&taglist, 8, NULL)) < 0)
		return error;

	filter.taglist = &taglist;
	filter.pattern = pattern;

	error = git3_tag_foreach(repo, &tag_list_cb, (void *)&filter);

	if (error < 0)
		git3_vector_dispose(&taglist);

	tag_names->strings =
		(char **)git3_vector_detach(&tag_names->count, NULL, &taglist);

	return 0;
}

int git3_tag_list(git3_strarray *tag_names, git3_repository *repo)
{
	return git3_tag_list_match(tag_names, "", repo);
}

int git3_tag_peel(git3_object **tag_target, const git3_tag *tag)
{
	return git3_object_peel(tag_target, (const git3_object *)tag, GIT3_OBJECT_ANY);
}

int git3_tag_name_is_valid(int *valid, const char *name)
{
	git3_str ref_name = GIT3_STR_INIT;
	int error = 0;

	GIT3_ASSERT(valid);

	*valid = 0;

	if (!name || !tag_name_is_valid(name))
		goto done;

	if ((error = git3_str_puts(&ref_name, GIT3_REFS_TAGS_DIR)) < 0 ||
	    (error = git3_str_puts(&ref_name, name)) < 0)
		goto done;

	error = git3_reference_name_is_valid(valid, ref_name.ptr);

done:
	git3_str_dispose(&ref_name);
	return error;
}

/* Deprecated Functions */

#ifndef GIT3_DEPRECATE_HARD
int git3_tag_create_frombuffer(git3_oid *oid, git3_repository *repo, const char *buffer, int allow_ref_overwrite)
{
	return git3_tag_create_from_buffer(oid, repo, buffer, allow_ref_overwrite);
}
#endif
