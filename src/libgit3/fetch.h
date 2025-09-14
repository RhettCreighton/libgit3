/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_fetch_h__
#define INCLUDE_fetch_h__

#include "common.h"

#include "git3/remote.h"

int git3_fetch_negotiate(git3_remote *remote, const git3_fetch_options *opts);

int git3_fetch_download_pack(git3_remote *remote);

int git3_fetch_setup_walk(git3_revwalk **out, git3_repository *repo);

#endif
