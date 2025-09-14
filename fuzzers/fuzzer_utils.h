/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#ifndef INCLUDE_fuzzer_utils_h__
#define INCLUDE_fuzzer_utils_h__

extern void fuzzer_git_abort(const char *op);
extern git3_repository *fuzzer_repo_init(void);

#endif
