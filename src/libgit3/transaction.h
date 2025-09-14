/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_transaction_h__
#define INCLUDE_transaction_h__

#include "common.h"

int git3_transaction_config_new(
	git3_transaction **out,
	git3_config *cfg,
	void *data);

#endif
