/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_indexer_h__
#define INCLUDE_indexer_h__

#include "common.h"

#include "git3/indexer.h"

extern void git3_indexer__set_fsync(git3_indexer *idx, int do_fsync);

#endif
