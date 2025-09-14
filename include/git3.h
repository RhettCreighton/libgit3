/*
 * git3.h - Main header for libgit3 (Git with SHA3-256)
 *
 * libgit3 is a fork of libgit3 that uses SHA3-256 instead of SHA1
 * for quantum resistance and improved security.
 *
 * Copyright (C) 2025 QED Systems
 * Copyright (C) the libgit3 contributors
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#ifndef INCLUDE_git3_h__
#define INCLUDE_git3_h__

/* Include all git3 headers */
#include "git3/common.h"
#include "git3/oid.h"
#include "git3/repository.h"
#include "git3/odb.h"
#include "git3/object.h"
#include "git3/blob.h"
#include "git3/commit.h"
#include "git3/tree.h"
#include "git3/tag.h"
#include "git3/index.h"
#include "git3/config.h"
#include "git3/remote.h"
#include "git3/clone.h"
#include "git3/checkout.h"
#include "git3/merge.h"
#include "git3/diff.h"
#include "git3/patch.h"
#include "git3/pathspec.h"
#include "git3/status.h"
#include "git3/submodule.h"
#include "git3/refs.h"
#include "git3/refspec.h"
#include "git3/net.h"
#include "git3/transport.h"
#include "git3/pack.h"
#include "git3/stash.h"
#include "git3/signature.h"
#include "git3/rebase.h"
#include "git3/graph.h"
#include "git3/reflog.h"
#include "git3/revparse.h"
#include "git3/revwalk.h"
#include "git3/notes.h"
#include "git3/reset.h"
#include "git3/message.h"
#include "git3/oidarray.h"
#include "git3/sys/index.h"
#include "git3/sys/odb_backend.h"
#include "git3/sys/refdb_backend.h"
#include "git3/sys/repository.h"
#include "git3/sys/stream.h"
#include "git3/filter.h"
#include "git3/transaction.h"
#include "git3/describe.h"
#include "git3/attr.h"
#include "git3/ignore.h"
#include "git3/branch.h"
#include "git3/worktree.h"
#include "git3/strarray.h"
#include "git3/proxy.h"
#include "git3/trace.h"
#include "git3/email.h"
#include "git3/revert.h"
#include "git3/cherrypick.h"
#include "git3/apply.h"
#include "git3/cred_helpers.h"
#include "git3/mailmap.h"
#include "git3/types.h"
#include "git3/version.h"
#include "git3/errors.h"
#include "git3/cert.h"
#include "git3/credential.h"
#include "git3/credential_helpers.h"
#include "git3/deprecated.h"
#include "git3/experimental.h"

/* Git3-specific definitions */
#define GIT3_VERSION "1.0.0"
#define GIT3_DEFAULT_OID_TYPE GIT3_OID_SHA3_256

/* Ensure SHA3-256 is the default everywhere */
#ifdef GIT3_OID_DEFAULT
#undef GIT3_OID_DEFAULT
#endif
#define GIT3_OID_DEFAULT GIT3_OID_SHA3_256

/* Git3 is libgit3 with SHA3-256 as the default hash */
/* All git3_ functions work as git3_ functions */

/* Verify that SHA3-256 is being used */
static inline int git3_verify_sha3(void) {
    return (GIT3_OID_DEFAULT == GIT3_OID_SHA3_256) ? 0 : -1;
}

/* Get git3 version string */
static inline const char* git3_version(void) {
    return "libgit3 " GIT3_VERSION " (SHA3-256)";
}

#endif /* INCLUDE_git3_h__ */