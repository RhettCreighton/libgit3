/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_checkout_h__
#define INCLUDE_checkout_h__

#include "common.h"

#include "git3/checkout.h"
#include "iterator.h"

/**
 * Update the working directory to match the target iterator.  The
 * expected baseline value can be passed in via the checkout options
 * or else will default to the HEAD commit.
 */
extern int git3_checkout_iterator(
	git3_iterator *target,
	git3_index *index,
	const git3_checkout_options *opts);

#endif
