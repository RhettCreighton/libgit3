/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_diff_xdiff_h__
#define INCLUDE_diff_xdiff_h__

#include "common.h"

#include "diff.h"
#include "xdiff.h"
#include "patch_generate.h"

/* xdiff cannot cope with large files.  these files should not be passed to
 * xdiff.  callers should treat these large files as binary.
 */
#define GIT3_XDIFF_MAX_SIZE (INT64_C(1024) * 1024 * 1023)

/* A git3_xdiff_output is a git3_patch_generate_output with extra fields
 * necessary to use libxdiff.  Calling git3_xdiff_init() will set the diff_cb
 * field of the output to use xdiff to generate the diffs.
 */
typedef struct {
	git3_patch_generated_output output;

	xdemitconf_t config;
	xpparam_t    params;
	xdemitcb_t   callback;
} git3_xdiff_output;

void git3_xdiff_init(git3_xdiff_output *xo, const git3_diff_options *opts);

#endif
