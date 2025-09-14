/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_mailmap_h__
#define INCLUDE_mailmap_h__

#include "git3/mailmap.h"
#include "vector.h"

/*
 * A mailmap is stored as a sorted vector of 'git3_mailmap_entry's. These entries
 * are sorted first by 'replace_email', and then by 'replace_name'. NULL
 * replace_names are ordered first.
 *
 * Looking up a name and email in the mailmap is done with a binary search.
 */
struct git3_mailmap {
	git3_vector entries;
};

/* Single entry parsed from a mailmap */
typedef struct git3_mailmap_entry {
	char *real_name; /**< the real name (may be NULL) */
	char *real_email; /**< the real email (may be NULL) */
	char *replace_name; /**< the name to replace (may be NULL) */
	char *replace_email; /**< the email to replace */
} git3_mailmap_entry;

const git3_mailmap_entry *git3_mailmap_entry_lookup(
	const git3_mailmap *mm, const char *name, const char *email);

#endif
