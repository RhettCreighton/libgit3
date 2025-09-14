/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "refspec.h"

#include "buf.h"
#include "refs.h"
#include "util.h"
#include "vector.h"
#include "wildmatch.h"

int git3_refspec__parse(git3_refspec *refspec, const char *input, bool is_fetch)
{
	/* Ported from https://github.com/git/git/blob/f06d47e7e0d9db709ee204ed13a8a7486149f494/remote.c#L518-636 */

	size_t llen;
	int is_glob = 0;
	const char *lhs, *rhs;
	int valid = 0;
	unsigned int flags;
	bool is_neg_refspec = false;

	GIT3_ASSERT_ARG(refspec);
	GIT3_ASSERT_ARG(input);

	memset(refspec, 0x0, sizeof(git3_refspec));
	refspec->push = !is_fetch;

	lhs = input;
	if (*lhs == '+') {
		refspec->force = 1;
		lhs++;
	}
	if (*lhs == '^') {
		is_neg_refspec = true;
	}

	rhs = strrchr(lhs, ':');

	/*
	 * Before going on, special case ":" (or "+:") as a refspec
	 * for matching refs.
	 */
	if (!is_fetch && rhs == lhs && rhs[1] == '\0') {
		refspec->matching = 1;
		refspec->string = git3__strdup(input);
		GIT3_ERROR_CHECK_ALLOC(refspec->string);
		refspec->src = git3__strdup("");
		GIT3_ERROR_CHECK_ALLOC(refspec->src);
		refspec->dst = git3__strdup("");
		GIT3_ERROR_CHECK_ALLOC(refspec->dst);
		return 0;
	}

	if (rhs) {
		size_t rlen = strlen(++rhs);
		if (rlen || !is_fetch) {
			is_glob = (1 <= rlen && strchr(rhs, '*'));
			refspec->dst = git3__strndup(rhs, rlen);
		}
	}

	llen = (rhs ? (size_t)(rhs - lhs - 1) : strlen(lhs));
	if (1 <= llen && memchr(lhs, '*', llen)) {
		/*
		 * If the lefthand side contains a glob, then one of the following must be
		 * true, otherwise the spec is invalid
		 *   1) the rhs exists and also contains a glob
		 *   2) it is a negative refspec (i.e. no rhs)
		 *   3) the rhs doesn't exist and we're fetching
		 */
		if ((rhs && !is_glob) || (rhs && is_neg_refspec) || (!rhs && is_fetch && !is_neg_refspec))
			goto invalid;
		is_glob = 1;
	} else if (rhs && is_glob)
		goto invalid;

	refspec->pattern = is_glob;
	refspec->src = git3__strndup(lhs, llen);
	flags = GIT3_REFERENCE_FORMAT_ALLOW_ONELEVEL |
		GIT3_REFERENCE_FORMAT_REFSPEC_SHORTHAND |
		(is_glob ? GIT3_REFERENCE_FORMAT_REFSPEC_PATTERN : 0);

	if (is_fetch) {
		/*
		 * LHS
		 * - empty is allowed; it means HEAD.
		 * - otherwise it must be a valid looking ref.
		 */
		if (!*refspec->src)
			; /* empty is ok */
		else if (git3_reference__name_is_valid(&valid, refspec->src, flags) < 0)
			goto on_error;
		else if (!valid)
			goto invalid;

		/*
		 * RHS
		 * - missing is ok, and is same as empty.
		 * - empty is ok; it means not to store.
		 * - otherwise it must be a valid looking ref.
		 */
		if (!refspec->dst)
			; /* ok */
		else if (!*refspec->dst)
			; /* ok */
		else if (git3_reference__name_is_valid(&valid, refspec->dst, flags) < 0)
			goto on_error;
		else if (!valid)
			goto invalid;
	} else {
		/*
		 * LHS
		 * - empty is allowed; it means delete.
		 * - when wildcarded, it must be a valid looking ref.
		 * - otherwise, it must be an extended SHA-1, but
		 *   there is no existing way to validate this.
		 */
		if (!*refspec->src)
			; /* empty is ok */
		else if (is_glob) {
			if (git3_reference__name_is_valid(&valid, refspec->src, flags) < 0)
				goto on_error;
			else if (!valid)
				goto invalid;
		}
		else {
			; /* anything goes, for now */
		}

		/*
		 * RHS
		 * - missing is allowed, but LHS then must be a
		 *   valid looking ref.
		 * - empty is not allowed.
		 * - otherwise it must be a valid looking ref.
		 */
		if (!refspec->dst) {
			if (git3_reference__name_is_valid(&valid, refspec->src, flags) < 0)
				goto on_error;
			else if (!valid)
				goto invalid;
		} else if (!*refspec->dst) {
			goto invalid;
		} else {
			if (git3_reference__name_is_valid(&valid, refspec->dst, flags) < 0)
				goto on_error;
			else if (!valid)
				goto invalid;
		}

		/* if the RHS is empty, then it's a copy of the LHS */
		if (!refspec->dst) {
			refspec->dst = git3__strdup(refspec->src);
			GIT3_ERROR_CHECK_ALLOC(refspec->dst);
		}
	}

	refspec->string = git3__strdup(input);
	GIT3_ERROR_CHECK_ALLOC(refspec->string);

	return 0;

invalid:
	git3_error_set(GIT3_ERROR_INVALID,
	              "'%s' is not a valid refspec.", input);
	git3_refspec__dispose(refspec);
	return GIT3_EINVALIDSPEC;

on_error:
	git3_refspec__dispose(refspec);
	return -1;
}

void git3_refspec__dispose(git3_refspec *refspec)
{
	if (refspec == NULL)
		return;

	git3__free(refspec->src);
	git3__free(refspec->dst);
	git3__free(refspec->string);

	memset(refspec, 0x0, sizeof(git3_refspec));
}

int git3_refspec_parse(git3_refspec **out_refspec, const char *input, int is_fetch)
{
	git3_refspec *refspec;
	GIT3_ASSERT_ARG(out_refspec);
	GIT3_ASSERT_ARG(input);

	*out_refspec = NULL;

	refspec = git3__malloc(sizeof(git3_refspec));
	GIT3_ERROR_CHECK_ALLOC(refspec);

	if (git3_refspec__parse(refspec, input, !!is_fetch) != 0) {
		git3__free(refspec);
		return -1;
	}

	*out_refspec = refspec;
	return 0;
}

void git3_refspec_free(git3_refspec *refspec)
{
	git3_refspec__dispose(refspec);
	git3__free(refspec);
}

const char *git3_refspec_src(const git3_refspec *refspec)
{
	return refspec == NULL ? NULL : refspec->src;
}

const char *git3_refspec_dst(const git3_refspec *refspec)
{
	return refspec == NULL ? NULL : refspec->dst;
}

const char *git3_refspec_string(const git3_refspec *refspec)
{
	return refspec == NULL ? NULL : refspec->string;
}

int git3_refspec_force(const git3_refspec *refspec)
{
	GIT3_ASSERT_ARG(refspec);

	return refspec->force;
}

int git3_refspec_src_matches_negative(const git3_refspec *refspec, const char *refname)
{
	if (refspec == NULL || refspec->src == NULL || !git3_refspec_is_negative(refspec))
		return false;

	return (wildmatch(refspec->src + 1, refname, 0) == 0);
}

int git3_refspec_src_matches(const git3_refspec *refspec, const char *refname)
{
	if (refspec == NULL || refspec->src == NULL)
		return false;

	return (wildmatch(refspec->src, refname, 0) == 0);
}

int git3_refspec_dst_matches(const git3_refspec *refspec, const char *refname)
{
	if (refspec == NULL || refspec->dst == NULL)
		return false;

	return (wildmatch(refspec->dst, refname, 0) == 0);
}

static int refspec_transform(
	git3_str *out, const char *from, const char *to, const char *name)
{
	const char *from_star, *to_star;
	size_t replacement_len, star_offset;

	git3_str_clear(out);

	/*
	 * There are two parts to each side of a refspec, the bit
	 * before the star and the bit after it. The star can be in
	 * the middle of the pattern, so we need to look at each bit
	 * individually.
	 */
	from_star = strchr(from, '*');
	to_star = strchr(to, '*');

	GIT3_ASSERT(from_star && to_star);

	/* star offset, both in 'from' and in 'name' */
	star_offset = from_star - from;

	/* the first half is copied over */
	git3_str_put(out, to, to_star - to);

	/*
	 * Copy over the name, but exclude the trailing part in "from" starting
	 * after the glob
	 */
	replacement_len = strlen(name + star_offset) - strlen(from_star + 1);
	git3_str_put(out, name + star_offset, replacement_len);

	return git3_str_puts(out, to_star + 1);
}

int git3_refspec_transform(git3_buf *out, const git3_refspec *spec, const char *name)
{
	GIT3_BUF_WRAP_PRIVATE(out, git3_refspec__transform, spec, name);
}

int git3_refspec__transform(git3_str *out, const git3_refspec *spec, const char *name)
{
	GIT3_ASSERT_ARG(out);
	GIT3_ASSERT_ARG(spec);
	GIT3_ASSERT_ARG(name);

	if (!git3_refspec_src_matches(spec, name)) {
		git3_error_set(GIT3_ERROR_INVALID, "ref '%s' doesn't match the source", name);
		return -1;
	}

	if (!spec->pattern)
		return git3_str_puts(out, spec->dst ? spec->dst : "");

	return refspec_transform(out, spec->src, spec->dst, name);
}

int git3_refspec_rtransform(git3_buf *out, const git3_refspec *spec, const char *name)
{
	GIT3_BUF_WRAP_PRIVATE(out, git3_refspec__rtransform, spec, name);
}

int git3_refspec__rtransform(git3_str *out, const git3_refspec *spec, const char *name)
{
	GIT3_ASSERT_ARG(out);
	GIT3_ASSERT_ARG(spec);
	GIT3_ASSERT_ARG(name);

	if (!git3_refspec_dst_matches(spec, name)) {
		git3_error_set(GIT3_ERROR_INVALID, "ref '%s' doesn't match the destination", name);
		return -1;
	}

	if (!spec->pattern)
		return git3_str_puts(out, spec->src);

	return refspec_transform(out, spec->dst, spec->src, name);
}

int git3_refspec__serialize(git3_str *out, const git3_refspec *refspec)
{
	if (refspec->force)
		git3_str_putc(out, '+');

	git3_str_printf(out, "%s:%s",
		refspec->src != NULL ? refspec->src : "",
		refspec->dst != NULL ? refspec->dst : "");

	return git3_str_oom(out) == false;
}

int git3_refspec_is_wildcard(const git3_refspec *spec)
{
	GIT3_ASSERT_ARG(spec);
	GIT3_ASSERT_ARG(spec->src);

	return (spec->src[strlen(spec->src) - 1] == '*');
}

int git3_refspec_is_negative(const git3_refspec *spec)
{
	GIT3_ASSERT_ARG(spec);
	GIT3_ASSERT_ARG(spec->src);

	return (spec->src[0] == '^' && spec->dst == NULL);
}

git3_direction git3_refspec_direction(const git3_refspec *spec)
{
	GIT3_ASSERT_ARG(spec);

	return spec->push;
}

int git3_refspec__dwim_one(git3_vector *out, git3_refspec *spec, git3_vector *refs)
{
	git3_str buf = GIT3_STR_INIT;
	size_t j, pos;
	git3_remote_head key;
	git3_refspec *cur;

	const char *formatters[] = {
		GIT3_REFS_DIR "%s",
		GIT3_REFS_TAGS_DIR "%s",
		GIT3_REFS_HEADS_DIR "%s",
		NULL
	};

	GIT3_ASSERT_ARG(out);
	GIT3_ASSERT_ARG(spec);
	GIT3_ASSERT_ARG(refs);

	cur = git3__calloc(1, sizeof(git3_refspec));
	GIT3_ERROR_CHECK_ALLOC(cur);

	cur->force = spec->force;
	cur->push = spec->push;
	cur->pattern = spec->pattern;
	cur->matching = spec->matching;
	cur->string = git3__strdup(spec->string);

	/* shorthand on the lhs */
	if (git3__prefixcmp(spec->src, GIT3_REFS_DIR)) {
		for (j = 0; formatters[j]; j++) {
			git3_str_clear(&buf);
			git3_str_printf(&buf, formatters[j], spec->src);
			GIT3_ERROR_CHECK_ALLOC_STR(&buf);

			key.name = (char *) git3_str_cstr(&buf);
			if (!git3_vector_search(&pos, refs, &key)) {
				/* we found something to match the shorthand, set src to that */
				cur->src = git3_str_detach(&buf);
			}
		}
	}

	/* No shorthands found, copy over the name */
	if (cur->src == NULL && spec->src != NULL) {
		cur->src = git3__strdup(spec->src);
		GIT3_ERROR_CHECK_ALLOC(cur->src);
	}

	if (spec->dst && git3__prefixcmp(spec->dst, GIT3_REFS_DIR)) {
		/* if it starts with "remotes" then we just prepend "refs/" */
		if (!git3__prefixcmp(spec->dst, "remotes/")) {
			git3_str_puts(&buf, GIT3_REFS_DIR);
		} else {
			git3_str_puts(&buf, GIT3_REFS_HEADS_DIR);
		}

		git3_str_puts(&buf, spec->dst);
		GIT3_ERROR_CHECK_ALLOC_STR(&buf);

		cur->dst = git3_str_detach(&buf);
	}

	git3_str_dispose(&buf);

	if (cur->dst == NULL && spec->dst != NULL) {
		cur->dst = git3__strdup(spec->dst);
		GIT3_ERROR_CHECK_ALLOC(cur->dst);
	}

	return git3_vector_insert(out, cur);
}
