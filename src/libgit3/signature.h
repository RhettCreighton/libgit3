/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_signature_h__
#define INCLUDE_signature_h__

#include "common.h"

#include "git3/common.h"
#include "git3/signature.h"
#include "repository.h"
#include <time.h>

int git3_signature__parse(git3_signature *sig, const char **buffer_out, const char *buffer_end, const char *header, char ender);
void git3_signature__writebuf(git3_str *buf, const char *header, const git3_signature *sig);
bool git3_signature__equal(const git3_signature *one, const git3_signature *two);
int git3_signature__pdup(git3_signature **dest, const git3_signature *source, git3_pool *pool);

#endif
