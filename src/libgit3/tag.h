/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_tag_h__
#define INCLUDE_tag_h__

#include "common.h"

#include "git3/tag.h"
#include "repository.h"
#include "odb.h"

struct git3_tag {
	git3_object object;

	git3_oid target;
	git3_object_t type;

	char *tag_name;
	git3_signature *tagger;
	char *message;
};

void git3_tag__free(void *tag);
int git3_tag__parse(void *tag, git3_odb_object *obj, git3_oid_t oid_type);
int git3_tag__parse_raw(void *tag, const char *data, size_t size, git3_oid_t oid_type);

#endif
