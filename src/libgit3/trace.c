/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "trace.h"

#include "str.h"
#include "runtime.h"
#include "git3/trace.h"

struct git3_trace_data git3_trace__data = {0};

int git3_trace_set(git3_trace_level_t level, git3_trace_cb callback)
{
	GIT3_ASSERT_ARG(level == 0 || callback != NULL);

	git3_trace__data.level = level;
	git3_trace__data.callback = callback;
	GIT3_MEMORY_BARRIER;

	return 0;
}
