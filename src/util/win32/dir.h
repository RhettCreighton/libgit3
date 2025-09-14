/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_win32_dir_h__
#define INCLUDE_win32_dir_h__

#include "git3_util.h"

#include "w32_util.h"

struct git3__dirent {
	int d_ino;
	git3_win32_utf8_path d_name;
};

typedef struct {
	HANDLE h;
	WIN32_FIND_DATAW f;
	struct git3__dirent entry;
	int first;
	char dir[GIT3_FLEX_ARRAY];
} git3__DIR;

extern git3__DIR *git3__opendir(const char *);
extern struct git3__dirent *git3__readdir(git3__DIR *);
extern int git3__readdir_ext(
	git3__DIR *, struct git3__dirent *, struct git3__dirent **, int *);
extern void git3__rewinddir(git3__DIR *);
extern int git3__closedir(git3__DIR *);

# ifndef GIT3__WIN32_NO_WRAP_DIR
#	define dirent git3__dirent
#	define DIR git3__DIR
#	define opendir	git3__opendir
#	define readdir	git3__readdir
#   define readdir_r(d,e,r) git3__readdir_ext((d),(e),(r),NULL)
#	define rewinddir git3__rewinddir
#	define closedir git3__closedir
# endif

#endif
