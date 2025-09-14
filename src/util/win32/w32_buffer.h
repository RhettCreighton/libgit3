/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_win32_w32_buffer_h__
#define INCLUDE_win32_w32_buffer_h__

#include "git3_util.h"
#include "str.h"

/**
 * Convert a wide character string to UTF-8 and append the results to the
 * buffer.
 */
int git3_str_put_w(git3_str *buf, const wchar_t *string_w, size_t len_w);

#endif
