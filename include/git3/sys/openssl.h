/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_git_openssl_h__
#define INCLUDE_git_openssl_h__

#include "git3/common.h"

/**
 * @file git3/sys/openssl.h
 * @brief Custom OpenSSL functionality
 * @defgroup git3_openssl Custom OpenSSL functionality
 * @{
 */
GIT3_BEGIN_DECL

/**
 * Initialize the OpenSSL locks
 *
 * OpenSSL requires the application to determine how it performs
 * locking.
 *
 * This is a last-resort convenience function which libgit3 provides for
 * allocating and initializing the locks as well as setting the
 * locking function to use the system's native locking functions.
 *
 * The locking function will be cleared and the memory will be freed
 * when you call git3_threads_sutdown().
 *
 * If your programming language has an OpenSSL package/bindings, it
 * likely sets up locking. You should very strongly prefer that over
 * this function.
 *
 * @return 0 on success, -1 if there are errors or if libgit3 was not
 * built with OpenSSL and threading support.
 */
GIT3_EXTERN(int) git3_openssl_set_locking(void);

/** @} */
GIT3_END_DECL

#endif
