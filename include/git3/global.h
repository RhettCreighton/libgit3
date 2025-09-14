/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_git_global_h__
#define INCLUDE_git_global_h__

#include "common.h"

/**
 * @file git3/global.h
 * @brief libgit3 library initializer and shutdown functionality
 * @ingroup Git
 * @{
 */
GIT3_BEGIN_DECL

/**
 * Init the global state
 *
 * This function must be called before any other libgit3 function in
 * order to set up global state and threading.
 *
 * This function may be called multiple times - it will return the number
 * of times the initialization has been called (including this one) that have
 * not subsequently been shutdown.
 *
 * @return the number of initializations of the library, or an error code.
 */
GIT3_EXTERN(int) git3_libgit3_init(void);

/**
 * Shutdown the global state
 *
 * Clean up the global state and threading context after calling it as
 * many times as `git3_libgit3_init()` was called - it will return the
 * number of remainining initializations that have not been shutdown
 * (after this one).
 *
 * @return the number of remaining initializations of the library, or an
 * error code.
 */
GIT3_EXTERN(int) git3_libgit3_shutdown(void);

/** @} */
GIT3_END_DECL

#endif

