/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_git_transport_h__
#define INCLUDE_git_transport_h__

#include "indexer.h"
#include "net.h"
#include "types.h"
#include "cert.h"
#include "credential.h"

/**
 * @file git3/transport.h
 * @brief Transports are the low-level mechanism to connect to a remote server
 * @defgroup git3_transport Transports are the low-level mechanism to connect to a remote server
 * @ingroup Git
 * @{
 */
GIT3_BEGIN_DECL

/**
 * Callback for messages received by the transport.
 *
 * Return a negative value to cancel the network operation.
 *
 * @param str The message from the transport
 * @param len The length of the message
 * @param payload Payload provided by the caller
 * @return 0 on success or an error code
 */
typedef int GIT3_CALLBACK(git3_transport_message_cb)(const char *str, int len, void *payload);

/**
 * Signature of a function which creates a transport.
 *
 * @param out the transport generate
 * @param owner the owner for the transport
 * @param param the param to the transport creation
 * @return 0 on success or an error code
 */
typedef int GIT3_CALLBACK(git3_transport_cb)(git3_transport **out, git3_remote *owner, void *param);

/** @} */
GIT3_END_DECL

#endif
