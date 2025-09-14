/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_note_h__
#define INCLUDE_note_h__

#include "common.h"

#include "git3/oid.h"
#include "git3/types.h"

#define GIT3_NOTES_DEFAULT_REF "refs/notes/commits"

#define GIT3_NOTES_DEFAULT_MSG_ADD \
	"Notes added by 'git3_note_create' from libgit3"

#define GIT3_NOTES_DEFAULT_MSG_RM \
	"Notes removed by 'git3_note_remove' from libgit3"

struct git3_note {
	git3_oid id;

	git3_signature *author;
	git3_signature *committer;

	char *message;
};

#endif
