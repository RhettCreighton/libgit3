/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_diff_driver_h__
#define INCLUDE_diff_driver_h__

#include "common.h"

#include "attr_file.h"
#include "str.h"
#include "hashmap.h"

typedef struct git3_diff_driver git3_diff_driver;
typedef struct git3_diff_driver_registry git3_diff_driver_registry;

git3_diff_driver_registry *git3_diff_driver_registry_new(void);
void git3_diff_driver_registry_free(git3_diff_driver_registry *);

int git3_diff_driver_lookup(git3_diff_driver **, git3_repository *,
	git3_attr_session *attrsession, const char *);
void git3_diff_driver_free(git3_diff_driver *);

/* diff option flags to force off and on for this driver */
void git3_diff_driver_update_options(uint32_t *option_flags, git3_diff_driver *);

/* returns -1 meaning "unknown", 0 meaning not binary, 1 meaning binary */
int git3_diff_driver_content_is_binary(
	git3_diff_driver *, const char *content, size_t content_len);

typedef long (*git3_diff_find_context_fn)(
	const char *, long, char *, long, void *);

typedef int (*git3_diff_find_context_line)(
	git3_diff_driver *, git3_str *);

typedef struct {
	git3_diff_driver *driver;
	git3_diff_find_context_line match_line;
	git3_str line;
} git3_diff_find_context_payload;

void git3_diff_find_context_init(
	git3_diff_find_context_fn *findfn_out,
	git3_diff_find_context_payload *payload_out,
	git3_diff_driver *driver);

void git3_diff_find_context_clear(git3_diff_find_context_payload *);

#endif
