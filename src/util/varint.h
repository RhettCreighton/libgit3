/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_varint_h__
#define INCLUDE_varint_h__

#include "git3_util.h"

#include <stdint.h>

extern int git3_encode_varint(unsigned char *, size_t, uintmax_t);
extern uintmax_t git3_decode_varint(const unsigned char *, size_t *);

#endif
