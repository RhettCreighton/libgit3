/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_refspec_h__
#define INCLUDE_refspec_h__

#include "common.h"

#include "git3/refspec.h"
#include "str.h"
#include "vector.h"

struct git3_refspec {
	char *string;
	char *src;
	char *dst;
	unsigned int force :1,
		push : 1,
		pattern :1,
		matching :1;
};

#define GIT3_REFSPEC_TAGS "refs/tags/*:refs/tags/*"

int git3_refspec__transform(git3_str *out, const git3_refspec *spec, const char *name);
int git3_refspec__rtransform(git3_str *out, const git3_refspec *spec, const char *name);

int git3_refspec__parse(
	struct git3_refspec *refspec,
	const char *str,
	bool is_fetch);

void git3_refspec__dispose(git3_refspec *refspec);

int git3_refspec__serialize(git3_str *out, const git3_refspec *refspec);

/**
 * Determines if a refspec is a wildcard refspec.
 *
 * @param spec the refspec
 * @return 1 if the refspec is a wildcard, 0 otherwise
 */
int git3_refspec_is_wildcard(const git3_refspec *spec);

/**
 * Determines if a refspec is a negative refspec.
 *
 * @param spec the refspec
 * @return 1 if the refspec is a negative, 0 otherwise
 */
int git3_refspec_is_negative(const git3_refspec *spec);

/**
 * DWIM `spec` with `refs` existing on the remote, append the dwim'ed
 * result in `out`.
 */
int git3_refspec__dwim_one(git3_vector *out, git3_refspec *spec, git3_vector *refs);

#endif
