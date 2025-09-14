/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_status_h__
#define INCLUDE_status_h__

#include "common.h"

#include "diff.h"
#include "git3/status.h"
#include "git3/diff.h"

struct git3_status_list {
	git3_status_options opts;

	git3_diff *head2idx;
	git3_diff *idx2wd;

	git3_vector paired;
};

#endif
