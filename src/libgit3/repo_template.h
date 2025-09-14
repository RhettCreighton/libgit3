/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_repo_template_h__
#define INCLUDE_repo_template_h__

#define GIT3_OBJECTS_INFO_DIR GIT3_OBJECTS_DIR "info/"
#define GIT3_OBJECTS_PACK_DIR GIT3_OBJECTS_DIR "pack/"

#define GIT3_HOOKS_DIR "hooks/"
#define GIT3_HOOKS_DIR_MODE 0777

#define GIT3_HOOKS_README_FILE GIT3_HOOKS_DIR "README.sample"
#define GIT3_HOOKS_README_MODE 0777
#define GIT3_HOOKS_README_CONTENT \
"#!/bin/sh\n"\
"#\n"\
"# Place appropriately named executable hook scripts into this directory\n"\
"# to intercept various actions that git takes.  See `git help hooks` for\n"\
"# more information.\n"

#define GIT3_INFO_DIR "info/"
#define GIT3_INFO_DIR_MODE 0777

#define GIT3_INFO_EXCLUDE_FILE GIT3_INFO_DIR "exclude"
#define GIT3_INFO_EXCLUDE_MODE 0666
#define GIT3_INFO_EXCLUDE_CONTENT \
"# File patterns to ignore; see `git help ignore` for more information.\n"\
"# Lines that start with '#' are comments.\n"

#define GIT3_DESC_FILE "description"
#define GIT3_DESC_MODE 0666
#define GIT3_DESC_CONTENT \
"Unnamed repository; edit this file 'description' to name the repository.\n"

typedef struct {
	const char *path;
	mode_t mode;
	const char *content;
} repo_template_item;

static repo_template_item repo_template[] = {
	{ GIT3_OBJECTS_INFO_DIR, GIT3_OBJECT_DIR_MODE, NULL }, /* '/objects/info/' */
	{ GIT3_OBJECTS_PACK_DIR, GIT3_OBJECT_DIR_MODE, NULL }, /* '/objects/pack/' */
	{ GIT3_REFS_HEADS_DIR, GIT3_REFS_DIR_MODE, NULL },     /* '/refs/heads/' */
	{ GIT3_REFS_TAGS_DIR, GIT3_REFS_DIR_MODE, NULL },      /* '/refs/tags/' */
	{ GIT3_HOOKS_DIR, GIT3_HOOKS_DIR_MODE, NULL },         /* '/hooks/' */
	{ GIT3_INFO_DIR, GIT3_INFO_DIR_MODE, NULL },           /* '/info/' */
	{ GIT3_DESC_FILE, GIT3_DESC_MODE, GIT3_DESC_CONTENT },
	{ GIT3_HOOKS_README_FILE, GIT3_HOOKS_README_MODE, GIT3_HOOKS_README_CONTENT },
	{ GIT3_INFO_EXCLUDE_FILE, GIT3_INFO_EXCLUDE_MODE, GIT3_INFO_EXCLUDE_CONTENT },
	{ NULL, 0, NULL }
};

#endif
