/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "common.h"

#include "git3/attr.h"
#include "git3/blob.h"
#include "git3/index.h"
#include "git3/sys/filter.h"

#include "buf.h"
#include "futils.h"
#include "hash.h"
#include "filter.h"
#include "repository.h"

typedef enum {
	GIT3_CRLF_UNDEFINED,
	GIT3_CRLF_BINARY,
	GIT3_CRLF_TEXT,
	GIT3_CRLF_TEXT_INPUT,
	GIT3_CRLF_TEXT_CRLF,
	GIT3_CRLF_AUTO,
	GIT3_CRLF_AUTO_INPUT,
	GIT3_CRLF_AUTO_CRLF
} git3_crlf_t;

struct crlf_attrs {
	int attr_action; /* the .gitattributes setting */
	int crlf_action; /* the core.autocrlf setting */

	int auto_crlf;
	int safe_crlf;
	int core_eol;
};

struct crlf_filter {
	git3_filter f;
};

static git3_crlf_t check_crlf(const char *value)
{
	if (GIT3_ATTR_IS_TRUE(value))
		return GIT3_CRLF_TEXT;
	else if (GIT3_ATTR_IS_FALSE(value))
		return GIT3_CRLF_BINARY;
	else if (GIT3_ATTR_IS_UNSPECIFIED(value))
		;
	else if (strcmp(value, "input") == 0)
		return GIT3_CRLF_TEXT_INPUT;
	else if (strcmp(value, "auto") == 0)
		return GIT3_CRLF_AUTO;

	return GIT3_CRLF_UNDEFINED;
}

static git3_configmap_value check_eol(const char *value)
{
	if (GIT3_ATTR_IS_UNSPECIFIED(value))
		;
	else if (strcmp(value, "lf") == 0)
		return GIT3_EOL_LF;
	else if (strcmp(value, "crlf") == 0)
		return GIT3_EOL_CRLF;

	return GIT3_EOL_UNSET;
}

static int has_cr_in_index(const git3_filter_source *src)
{
	git3_repository *repo = git3_filter_source_repo(src);
	const char *path = git3_filter_source_path(src);
	git3_index *index;
	const git3_index_entry *entry;
	git3_blob *blob;
	const void *blobcontent;
	git3_object_size_t blobsize;
	bool found_cr;

	if (!path)
		return false;

	if (git3_repository_index__weakptr(&index, repo) < 0) {
		git3_error_clear();
		return false;
	}

	if (!(entry = git3_index_get_bypath(index, path, 0)) &&
		!(entry = git3_index_get_bypath(index, path, 1)))
		return false;

	if (!S_ISREG(entry->mode)) /* don't crlf filter non-blobs */
		return true;

	if (git3_blob_lookup(&blob, repo, &entry->id) < 0)
		return false;

	blobcontent = git3_blob_rawcontent(blob);
	blobsize    = git3_blob_rawsize(blob);
	if (!git3__is_sizet(blobsize))
		blobsize = (size_t)-1;

	found_cr = (blobcontent != NULL &&
		blobsize > 0 &&
		memchr(blobcontent, '\r', (size_t)blobsize) != NULL);

	git3_blob_free(blob);
	return found_cr;
}

static int text_eol_is_crlf(struct crlf_attrs *ca)
{
	if (ca->auto_crlf == GIT3_AUTO_CRLF_TRUE)
		return 1;
	else if (ca->auto_crlf == GIT3_AUTO_CRLF_INPUT)
		return 0;

	if (ca->core_eol == GIT3_EOL_CRLF)
		return 1;
	if (ca->core_eol == GIT3_EOL_UNSET && GIT3_EOL_NATIVE == GIT3_EOL_CRLF)
		return 1;

	return 0;
}

static git3_configmap_value output_eol(struct crlf_attrs *ca)
{
	switch (ca->crlf_action) {
	case GIT3_CRLF_BINARY:
		return GIT3_EOL_UNSET;
	case GIT3_CRLF_TEXT_CRLF:
		return GIT3_EOL_CRLF;
	case GIT3_CRLF_TEXT_INPUT:
		return GIT3_EOL_LF;
	case GIT3_CRLF_UNDEFINED:
	case GIT3_CRLF_AUTO_CRLF:
		return GIT3_EOL_CRLF;
	case GIT3_CRLF_AUTO_INPUT:
		return GIT3_EOL_LF;
	case GIT3_CRLF_TEXT:
	case GIT3_CRLF_AUTO:
		return text_eol_is_crlf(ca) ? GIT3_EOL_CRLF : GIT3_EOL_LF;
	}

	/* TODO: warn when available */
	return ca->core_eol;
}

GIT3_INLINE(int) check_safecrlf(
	struct crlf_attrs *ca,
	const git3_filter_source *src,
	git3_str_text_stats *stats)
{
	const char *filename = git3_filter_source_path(src);

	if (!ca->safe_crlf)
		return 0;

	if (output_eol(ca) == GIT3_EOL_LF) {
		/*
		 * CRLFs would not be restored by checkout:
		 * check if we'd remove CRLFs
		 */
		if (stats->crlf) {
			if (ca->safe_crlf == GIT3_SAFE_CRLF_WARN) {
				/* TODO: issue a warning when available */
			} else {
				if (filename && *filename)
					git3_error_set(
						GIT3_ERROR_FILTER, "CRLF would be replaced by LF in '%s'",
						filename);
				else
					git3_error_set(
						GIT3_ERROR_FILTER, "CRLF would be replaced by LF");

				return -1;
			}
		}
	} else if (output_eol(ca) == GIT3_EOL_CRLF) {
		/*
		 * CRLFs would be added by checkout:
		 * check if we have "naked" LFs
		 */
		if (stats->crlf != stats->lf) {
			if (ca->safe_crlf == GIT3_SAFE_CRLF_WARN) {
				/* TODO: issue a warning when available */
			} else {
				if (filename && *filename)
					git3_error_set(
						GIT3_ERROR_FILTER, "LF would be replaced by CRLF in '%s'",
						filename);
				else
					git3_error_set(
						GIT3_ERROR_FILTER, "LF would be replaced by CRLF");

				return -1;
			}
		}
	}

	return 0;
}

static int crlf_apply_to_odb(
	struct crlf_attrs *ca,
	git3_str *to,
	const git3_str *from,
	const git3_filter_source *src)
{
	git3_str_text_stats stats;
	bool is_binary;
	int error;

	/* Binary attribute? Empty file? Nothing to do */
	if (ca->crlf_action == GIT3_CRLF_BINARY || from->size == 0)
		return GIT3_PASSTHROUGH;

	is_binary = git3_str_gather_text_stats(&stats, from, false);

	/* Heuristics to see if we can skip the conversion.
	 * Straight from Core Git.
	 */
	if (ca->crlf_action == GIT3_CRLF_AUTO ||
		ca->crlf_action == GIT3_CRLF_AUTO_INPUT ||
		ca->crlf_action == GIT3_CRLF_AUTO_CRLF) {

		if (is_binary)
			return GIT3_PASSTHROUGH;

		/*
		 * If the file in the index has any CR in it, do not convert.
		 * This is the new safer autocrlf handling.
		 */
		if (has_cr_in_index(src))
			return GIT3_PASSTHROUGH;
	}

	if ((error = check_safecrlf(ca, src, &stats)) < 0)
		return error;

	/* If there are no CR characters to filter out, then just pass */
	if (!stats.crlf)
		return GIT3_PASSTHROUGH;

	/* Actually drop the carriage returns */
	return git3_str_crlf_to_lf(to, from);
}

static int crlf_apply_to_workdir(
	struct crlf_attrs *ca,
	git3_str *to,
	const git3_str *from)
{
	git3_str_text_stats stats;
	bool is_binary;

	/* Empty file? Nothing to do. */
	if (git3_str_len(from) == 0 || output_eol(ca) != GIT3_EOL_CRLF)
		return GIT3_PASSTHROUGH;

	is_binary = git3_str_gather_text_stats(&stats, from, false);

	/* If there are no LFs, or all LFs are part of a CRLF, nothing to do */
	if (stats.lf == 0 || stats.lf == stats.crlf)
		return GIT3_PASSTHROUGH;

	if (ca->crlf_action == GIT3_CRLF_AUTO ||
		ca->crlf_action == GIT3_CRLF_AUTO_INPUT ||
		ca->crlf_action == GIT3_CRLF_AUTO_CRLF) {

		/* If we have any existing CR or CRLF line endings, do nothing */
		if (stats.cr > 0)
			return GIT3_PASSTHROUGH;

		/* Don't filter binary files */
		if (is_binary)
			return GIT3_PASSTHROUGH;
	}

	return git3_str_lf_to_crlf(to, from);
}

static int convert_attrs(
	struct crlf_attrs *ca,
	const char **attr_values,
	const git3_filter_source *src)
{
	int error;

	memset(ca, 0, sizeof(struct crlf_attrs));

	if ((error = git3_repository__configmap_lookup(&ca->auto_crlf,
		 git3_filter_source_repo(src), GIT3_CONFIGMAP_AUTO_CRLF)) < 0 ||
		(error = git3_repository__configmap_lookup(&ca->safe_crlf,
		 git3_filter_source_repo(src), GIT3_CONFIGMAP_SAFE_CRLF)) < 0 ||
		(error = git3_repository__configmap_lookup(&ca->core_eol,
		 git3_filter_source_repo(src), GIT3_CONFIGMAP_EOL)) < 0)
		return error;

	/* downgrade FAIL to WARN if ALLOW_UNSAFE option is used */
	if ((git3_filter_source_flags(src) & GIT3_FILTER_ALLOW_UNSAFE) &&
		ca->safe_crlf == GIT3_SAFE_CRLF_FAIL)
		ca->safe_crlf = GIT3_SAFE_CRLF_WARN;

	if (attr_values) {
		/* load the text attribute */
		ca->crlf_action = check_crlf(attr_values[2]); /* text */

		if (ca->crlf_action == GIT3_CRLF_UNDEFINED)
			ca->crlf_action = check_crlf(attr_values[0]); /* crlf */

		if (ca->crlf_action != GIT3_CRLF_BINARY) {
			/* load the eol attribute */
			int eol_attr = check_eol(attr_values[1]);

			if (ca->crlf_action == GIT3_CRLF_AUTO && eol_attr == GIT3_EOL_LF)
				ca->crlf_action = GIT3_CRLF_AUTO_INPUT;
			else if (ca->crlf_action == GIT3_CRLF_AUTO && eol_attr == GIT3_EOL_CRLF)
				ca->crlf_action = GIT3_CRLF_AUTO_CRLF;
			else if (eol_attr == GIT3_EOL_LF)
				ca->crlf_action = GIT3_CRLF_TEXT_INPUT;
			else if (eol_attr == GIT3_EOL_CRLF)
				ca->crlf_action = GIT3_CRLF_TEXT_CRLF;
		}

		ca->attr_action = ca->crlf_action;
	} else {
		ca->crlf_action = GIT3_CRLF_UNDEFINED;
	}

	if (ca->crlf_action == GIT3_CRLF_TEXT)
		ca->crlf_action = text_eol_is_crlf(ca) ? GIT3_CRLF_TEXT_CRLF : GIT3_CRLF_TEXT_INPUT;
	if (ca->crlf_action == GIT3_CRLF_UNDEFINED && ca->auto_crlf == GIT3_AUTO_CRLF_FALSE)
		ca->crlf_action = GIT3_CRLF_BINARY;
	if (ca->crlf_action == GIT3_CRLF_UNDEFINED && ca->auto_crlf == GIT3_AUTO_CRLF_TRUE)
		ca->crlf_action = GIT3_CRLF_AUTO_CRLF;
	if (ca->crlf_action == GIT3_CRLF_UNDEFINED && ca->auto_crlf == GIT3_AUTO_CRLF_INPUT)
		ca->crlf_action = GIT3_CRLF_AUTO_INPUT;

	return 0;
}

static int crlf_check(
	git3_filter *self,
	void **payload, /* points to NULL ptr on entry, may be set */
	const git3_filter_source *src,
	const char **attr_values)
{
	struct crlf_attrs ca;

	GIT3_UNUSED(self);

	convert_attrs(&ca, attr_values, src);

	if (ca.crlf_action == GIT3_CRLF_BINARY)
		return GIT3_PASSTHROUGH;

	*payload = git3__malloc(sizeof(ca));
	GIT3_ERROR_CHECK_ALLOC(*payload);
	memcpy(*payload, &ca, sizeof(ca));

	return 0;
}

static int crlf_apply(
	git3_filter *self,
	void **payload, /* may be read and/or set */
	git3_str *to,
	const git3_str *from,
	const git3_filter_source *src)
{
	int error = 0;

	/* initialize payload in case `check` was bypassed */
	if (!*payload) {
		if ((error = crlf_check(self, payload, src, NULL)) < 0)
			return error;
	}

	if (git3_filter_source_mode(src) == GIT3_FILTER_SMUDGE)
		error = crlf_apply_to_workdir(*payload, to, from);
	else
		error = crlf_apply_to_odb(*payload, to, from, src);

	return error;
}

static int crlf_stream(
	git3_writestream **out,
	git3_filter *self,
	void **payload,
	const git3_filter_source *src,
	git3_writestream *next)
{
	return git3_filter_buffered_stream_new(out,
		self, crlf_apply, NULL, payload, src, next);
}

static void crlf_cleanup(
	git3_filter *self,
	void       *payload)
{
	GIT3_UNUSED(self);
	git3__free(payload);
}

git3_filter *git3_crlf_filter_new(void)
{
	struct crlf_filter *f = git3__calloc(1, sizeof(struct crlf_filter));
	if (f == NULL)
		return NULL;

	f->f.version = GIT3_FILTER_VERSION;
	f->f.attributes = "crlf eol text";
	f->f.initialize = NULL;
	f->f.shutdown = git3_filter_free;
	f->f.check    = crlf_check;
	f->f.stream   = crlf_stream;
	f->f.cleanup  = crlf_cleanup;

	return (git3_filter *)f;
}
