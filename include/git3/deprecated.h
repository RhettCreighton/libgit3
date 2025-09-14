/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_git_deprecated_h__
#define INCLUDE_git_deprecated_h__

#include "attr.h"
#include "config.h"
#include "common.h"
#include "blame.h"
#include "buffer.h"
#include "checkout.h"
#include "cherrypick.h"
#include "clone.h"
#include "describe.h"
#include "diff.h"
#include "errors.h"
#include "filter.h"
#include "index.h"
#include "indexer.h"
#include "merge.h"
#include "object.h"
#include "proxy.h"
#include "refs.h"
#include "rebase.h"
#include "remote.h"
#include "trace.h"
#include "repository.h"
#include "revert.h"
#include "revparse.h"
#include "stash.h"
#include "status.h"
#include "submodule.h"
#include "worktree.h"
#include "credential.h"
#include "credential_helpers.h"

/*
 * Users can avoid deprecated functions by defining `GIT3_DEPRECATE_HARD`.
 */
#ifndef GIT3_DEPRECATE_HARD

/*
 * The credential structures are now opaque by default, and their
 * definition has moved into the `sys/credential.h` header; include
 * them here for backward compatibility.
 */
#include "sys/credential.h"

/**
 * @file git3/deprecated.h
 * @brief Deprecated functions and values
 * @ingroup Git
 * @{
 */
GIT3_BEGIN_DECL

/** @name Deprecated Attribute Constants
 *
 * These enumeration values are retained for backward compatibility.
 * The newer versions of these functions should be preferred in all
 * new code.
 *
 * There is no plan to remove these backward compatibility values at
 * this time.
 */
/**@{*/

/** @deprecated use GIT3_ATTR_VALUE_UNSPECIFIED */
#define GIT3_ATTR_UNSPECIFIED_T GIT3_ATTR_VALUE_UNSPECIFIED
/** @deprecated use GIT3_ATTR_VALUE_TRUE */
#define GIT3_ATTR_TRUE_T GIT3_ATTR_VALUE_TRUE
/** @deprecated use GIT3_ATTR_VALUE_FALSE */
#define GIT3_ATTR_FALSE_T GIT3_ATTR_VALUE_FALSE
/** @deprecated use GIT3_ATTR_VALUE_STRING */
#define GIT3_ATTR_VALUE_T GIT3_ATTR_VALUE_STRING

/** @deprecated use GIT3_ATTR_IS_TRUE */
#define GIT3_ATTR_TRUE(attr) GIT3_ATTR_IS_TRUE(attr)
/** @deprecated use GIT3_ATTR_IS_FALSE */
#define GIT3_ATTR_FALSE(attr) GIT3_ATTR_IS_FALSE(attr)
/** @deprecated use GIT3_ATTR_IS_UNSPECIFIED */
#define GIT3_ATTR_UNSPECIFIED(attr) GIT3_ATTR_IS_UNSPECIFIED(attr)

/** @deprecated use git3_attr_value_t */
typedef git3_attr_value_t git3_attr_t;

/**@}*/

/** @name Deprecated Blob Functions and Constants
 *
 * These functions and enumeration values are retained for backward
 * compatibility.  The newer versions of these functions and values
 * should be preferred in all new code.
 *
 * There is no plan to remove these backward compatibility values at
 * this time.
 */
/**@{*/

/** @deprecated use GIT3_BLOB_FILTER_ATTRIBUTES_FROM_HEAD */
#define GIT3_BLOB_FILTER_ATTTRIBUTES_FROM_HEAD GIT3_BLOB_FILTER_ATTRIBUTES_FROM_HEAD

GIT3_EXTERN(int) git3_blob_create_fromworkdir(git3_oid *id, git3_repository *repo, const char *relative_path);
GIT3_EXTERN(int) git3_blob_create_fromdisk(git3_oid *id, git3_repository *repo, const char *path);
GIT3_EXTERN(int) git3_blob_create_fromstream(
	git3_writestream **out,
	git3_repository *repo,
	const char *hintpath);
GIT3_EXTERN(int) git3_blob_create_fromstream_commit(
	git3_oid *out,
	git3_writestream *stream);
GIT3_EXTERN(int) git3_blob_create_frombuffer(
	git3_oid *id, git3_repository *repo, const void *buffer, size_t len);

/** Deprecated in favor of `git3_blob_filter`.
 *
 * @deprecated Use git3_blob_filter
 * @see git3_blob_filter
 */
GIT3_EXTERN(int) git3_blob_filtered_content(
	git3_buf *out,
	git3_blob *blob,
	const char *as_path,
	int check_for_binary_data);

/**@}*/

/** @name Deprecated Filter Functions
 *
 * These functions are retained for backward compatibility.  The
 * newer versions of these functions should be preferred in all
 * new code.
 *
 * There is no plan to remove these backward compatibility values at
 * this time.
 */
/**@{*/

/** Deprecated in favor of `git3_filter_list_stream_buffer`.
 *
 * @deprecated Use git3_filter_list_stream_buffer
 * @see Use git3_filter_list_stream_buffer
 */
GIT3_EXTERN(int) git3_filter_list_stream_data(
	git3_filter_list *filters,
	git3_buf *data,
	git3_writestream *target);

/** Deprecated in favor of `git3_filter_list_apply_to_buffer`.
 *
 * @deprecated Use git3_filter_list_apply_to_buffer
 * @see Use git3_filter_list_apply_to_buffer
 */
GIT3_EXTERN(int) git3_filter_list_apply_to_data(
	git3_buf *out,
	git3_filter_list *filters,
	git3_buf *in);

/**@}*/

/** @name Deprecated Tree Functions
 *
 * These functions are retained for backward compatibility.  The
 * newer versions of these functions and values should be preferred
 * in all new code.
 *
 * There is no plan to remove these backward compatibility values at
 * this time.
 */
/**@{*/

/**
 * Write the contents of the tree builder as a tree object.
 * This is an alias of `git3_treebuilder_write` and is preserved
 * for backward compatibility.
 *
 * This function is deprecated, but there is no plan to remove this
 * function at this time.
 *
 * @deprecated Use git3_treebuilder_write
 * @see git3_treebuilder_write
 */
GIT3_EXTERN(int) git3_treebuilder_write_with_buffer(
	git3_oid *oid, git3_treebuilder *bld, git3_buf *tree);

/**@}*/

/** @name Deprecated Buffer Functions
 *
 * These functions and enumeration values are retained for backward
 * compatibility.  The newer versions of these functions should be
 * preferred in all new code.
 *
 * There is no plan to remove these backward compatibility values at
 * this time.
 */
/**@{*/

/**
 * Static initializer for git3_buf from static buffer
 */
#define GIT3_BUF_INIT_CONST(STR,LEN) { (char *)(STR), 0, (size_t)(LEN) }

/**
 * Resize the buffer allocation to make more space.
 *
 * This will attempt to grow the buffer to accommodate the target size.
 *
 * If the buffer refers to memory that was not allocated by libgit3 (i.e.
 * the `asize` field is zero), then `ptr` will be replaced with a newly
 * allocated block of data.  Be careful so that memory allocated by the
 * caller is not lost.  As a special variant, if you pass `target_size` as
 * 0 and the memory is not allocated by libgit3, this will allocate a new
 * buffer of size `size` and copy the external data into it.
 *
 * Currently, this will never shrink a buffer, only expand it.
 *
 * If the allocation fails, this will return an error and the buffer will be
 * marked as invalid for future operations, invaliding the contents.
 *
 * @param buffer The buffer to be resized; may or may not be allocated yet
 * @param target_size The desired available size
 * @return 0 on success, -1 on allocation failure
 */
GIT3_EXTERN(int) git3_buf_grow(git3_buf *buffer, size_t target_size);

/**
 * Set buffer to a copy of some raw data.
 *
 * @param buffer The buffer to set
 * @param data The data to copy into the buffer
 * @param datalen The length of the data to copy into the buffer
 * @return 0 on success, -1 on allocation failure
 */
GIT3_EXTERN(int) git3_buf_set(
	git3_buf *buffer, const void *data, size_t datalen);

/**
* Check quickly if buffer looks like it contains binary data
*
* @param buf Buffer to check
* @return 1 if buffer looks like non-text data
*/
GIT3_EXTERN(int) git3_buf_is_binary(const git3_buf *buf);

/**
* Check quickly if buffer contains a NUL byte
*
* @param buf Buffer to check
* @return 1 if buffer contains a NUL byte
*/
GIT3_EXTERN(int) git3_buf_contains_nul(const git3_buf *buf);

/**
 * Free the memory referred to by the git3_buf.  This is an alias of
 * `git3_buf_dispose` and is preserved for backward compatibility.
 *
 * This function is deprecated, but there is no plan to remove this
 * function at this time.
 *
 * @deprecated Use git3_buf_dispose
 * @see git3_buf_dispose
 */
GIT3_EXTERN(void) git3_buf_free(git3_buf *buffer);

/**@}*/

/** @name Deprecated Commit Definitions
 */
/**@{*/

/**
 * Provide a commit signature during commit creation.
 *
 * Callers should instead define a `git3_commit_create_cb` that
 * generates a commit buffer using `git3_commit_create_buffer`, sign
 * that buffer and call `git3_commit_create_with_signature`.
 *
 * @deprecated use a `git3_commit_create_cb` instead
 */
typedef int (*git3_commit_signing_cb)(
	git3_buf *signature,
	git3_buf *signature_field,
	const char *commit_content,
	void *payload);

/**@}*/

/** @name Deprecated Config Functions and Constants
 */
/**@{*/

/** @deprecated use GIT3_CONFIGMAP_FALSE */
#define GIT3_CVAR_FALSE  GIT3_CONFIGMAP_FALSE
/** @deprecated use GIT3_CONFIGMAP_TRUE */
#define GIT3_CVAR_TRUE   GIT3_CONFIGMAP_TRUE
/** @deprecated use GIT3_CONFIGMAP_INT32 */
#define GIT3_CVAR_INT32  GIT3_CONFIGMAP_INT32
/** @deprecated use GIT3_CONFIGMAP_STRING */
#define GIT3_CVAR_STRING GIT3_CONFIGMAP_STRING

/** @deprecated use git3_cvar_map */
typedef git3_configmap git3_cvar_map;

/**@}*/

/** @name Deprecated Diff Functions and Constants
 *
 * These functions and enumeration values are retained for backward
 * compatibility.  The newer versions of these functions and values
 * should be preferred in all new code.
 *
 * There is no plan to remove these backward compatibility values at
 * this time.
 */
/**@{*/

/**
 * Formatting options for diff e-mail generation
 */
typedef enum {
	/** Normal patch, the default */
	GIT3_DIFF_FORMAT_EMAIL_NONE = 0,

	/** Don't insert "[PATCH]" in the subject header*/
	GIT3_DIFF_FORMAT_EMAIL_EXCLUDE_SUBJECT_PATCH_MARKER = (1 << 0)
} git3_diff_format_email_flags_t;

/**
 * Options for controlling the formatting of the generated e-mail.
 *
 * @deprecated use `git3_email_create_options`
 */
typedef struct {
	unsigned int version;

	/** see `git3_diff_format_email_flags_t` above */
	uint32_t flags;

	/** This patch number */
	size_t patch_no;

	/** Total number of patches in this series */
	size_t total_patches;

	/** id to use for the commit */
	const git3_oid *id;

	/** Summary of the change */
	const char *summary;

	/** Commit message's body */
	const char *body;

	/** Author of the change */
	const git3_signature *author;
} git3_diff_format_email_options;

/** @deprecated use `git3_email_create_options` */
#define GIT3_DIFF_FORMAT_EMAIL_OPTIONS_VERSION 1
/** @deprecated use `git3_email_create_options` */
#define GIT3_DIFF_FORMAT_EMAIL_OPTIONS_INIT {GIT3_DIFF_FORMAT_EMAIL_OPTIONS_VERSION, 0, 1, 1, NULL, NULL, NULL, NULL}

/**
 * Create an e-mail ready patch from a diff.
 *
 * @deprecated git3_email_create_from_diff
 * @see git3_email_create_from_diff
 */
GIT3_EXTERN(int) git3_diff_format_email(
	git3_buf *out,
	git3_diff *diff,
	const git3_diff_format_email_options *opts);

/**
 * Create an e-mail ready patch for a commit.
 *
 * @deprecated git3_email_create_from_commit
 * @see git3_email_create_from_commit
 */
GIT3_EXTERN(int) git3_diff_commit_as_email(
	git3_buf *out,
	git3_repository *repo,
	git3_commit *commit,
	size_t patch_no,
	size_t total_patches,
	uint32_t flags,
	const git3_diff_options *diff_opts);

/**
 * Initialize git3_diff_format_email_options structure
 *
 * Initializes a `git3_diff_format_email_options` with default values. Equivalent
 * to creating an instance with GIT3_DIFF_FORMAT_EMAIL_OPTIONS_INIT.
 *
 * @param opts The `git3_blame_options` struct to initialize.
 * @param version The struct version; pass `GIT3_DIFF_FORMAT_EMAIL_OPTIONS_VERSION`.
 * @return Zero on success; -1 on failure.
 */
GIT3_EXTERN(int) git3_diff_format_email_options_init(
	git3_diff_format_email_options *opts,
	unsigned int version);

/**@}*/

/** @name Deprecated Error Functions and Constants
 *
 * These functions and enumeration values are retained for backward
 * compatibility.  The newer versions of these functions and values
 * should be preferred in all new code.
 *
 * There is no plan to remove these backward compatibility values at
 * this time.
 */
/**@{*/

/** @deprecated use `GIT3_ERROR_NONE` */
#define GITERR_NONE GIT3_ERROR_NONE
/** @deprecated use `GIT3_ERROR_NOMEMORY` */
#define GITERR_NOMEMORY GIT3_ERROR_NOMEMORY
/** @deprecated use `GIT3_ERROR_OS` */
#define GITERR_OS GIT3_ERROR_OS
/** @deprecated use `GIT3_ERROR_INVALID` */
#define GITERR_INVALID GIT3_ERROR_INVALID
/** @deprecated use `GIT3_ERROR_REFERENCE` */
#define GITERR_REFERENCE GIT3_ERROR_REFERENCE
/** @deprecated use `GIT3_ERROR_ZLIB` */
#define GITERR_ZLIB GIT3_ERROR_ZLIB
/** @deprecated use `GIT3_ERROR_REPOSITORY` */
#define GITERR_REPOSITORY GIT3_ERROR_REPOSITORY
/** @deprecated use `GIT3_ERROR_CONFIG` */
#define GITERR_CONFIG GIT3_ERROR_CONFIG
/** @deprecated use `GIT3_ERROR_REGEX` */
#define GITERR_REGEX GIT3_ERROR_REGEX
/** @deprecated use `GIT3_ERROR_ODB` */
#define GITERR_ODB GIT3_ERROR_ODB
/** @deprecated use `GIT3_ERROR_INDEX` */
#define GITERR_INDEX GIT3_ERROR_INDEX
/** @deprecated use `GIT3_ERROR_OBJECT` */
#define GITERR_OBJECT GIT3_ERROR_OBJECT
/** @deprecated use `GIT3_ERROR_NET` */
#define GITERR_NET GIT3_ERROR_NET
/** @deprecated use `GIT3_ERROR_TAG` */
#define GITERR_TAG GIT3_ERROR_TAG
/** @deprecated use `GIT3_ERROR_TREE` */
#define GITERR_TREE GIT3_ERROR_TREE
/** @deprecated use `GIT3_ERROR_INDEXER` */
#define GITERR_INDEXER GIT3_ERROR_INDEXER
/** @deprecated use `GIT3_ERROR_SSL` */
#define GITERR_SSL GIT3_ERROR_SSL
/** @deprecated use `GIT3_ERROR_SUBMODULE` */
#define GITERR_SUBMODULE GIT3_ERROR_SUBMODULE
/** @deprecated use `GIT3_ERROR_THREAD` */
#define GITERR_THREAD GIT3_ERROR_THREAD
/** @deprecated use `GIT3_ERROR_STASH` */
#define GITERR_STASH GIT3_ERROR_STASH
/** @deprecated use `GIT3_ERROR_CHECKOUT` */
#define GITERR_CHECKOUT GIT3_ERROR_CHECKOUT
/** @deprecated use `GIT3_ERROR_FETCHHEAD` */
#define GITERR_FETCHHEAD GIT3_ERROR_FETCHHEAD
/** @deprecated use `GIT3_ERROR_MERGE` */
#define GITERR_MERGE GIT3_ERROR_MERGE
/** @deprecated use `GIT3_ERROR_SSH` */
#define GITERR_SSH GIT3_ERROR_SSH
/** @deprecated use `GIT3_ERROR_FILTER` */
#define GITERR_FILTER GIT3_ERROR_FILTER
/** @deprecated use `GIT3_ERROR_REVERT` */
#define GITERR_REVERT GIT3_ERROR_REVERT
/** @deprecated use `GIT3_ERROR_CALLBACK` */
#define GITERR_CALLBACK GIT3_ERROR_CALLBACK
/** @deprecated use `GIT3_ERROR_CHERRYPICK` */
#define GITERR_CHERRYPICK GIT3_ERROR_CHERRYPICK
/** @deprecated use `GIT3_ERROR_DESCRIBE` */
#define GITERR_DESCRIBE GIT3_ERROR_DESCRIBE
/** @deprecated use `GIT3_ERROR_REBASE` */
#define GITERR_REBASE GIT3_ERROR_REBASE
/** @deprecated use `GIT3_ERROR_FILESYSTEM` */
#define GITERR_FILESYSTEM GIT3_ERROR_FILESYSTEM
/** @deprecated use `GIT3_ERROR_PATCH` */
#define GITERR_PATCH GIT3_ERROR_PATCH
/** @deprecated use `GIT3_ERROR_WORKTREE` */
#define GITERR_WORKTREE GIT3_ERROR_WORKTREE
/** @deprecated use `GIT3_ERROR_SHA1` */
#define GITERR_SHA1 GIT3_ERROR_SHA1
/** @deprecated use `GIT3_ERROR_SHA` */
#define GIT3_ERROR_SHA1 GIT3_ERROR_SHA

/**
 * Return the last `git3_error` object that was generated for the
 * current thread.  This is an alias of `git3_error_last` and is
 * preserved for backward compatibility.
 *
 * This function is deprecated, but there is no plan to remove this
 * function at this time.
 *
 * @deprecated Use git3_error_last
 * @see git3_error_last
 */
GIT3_EXTERN(const git3_error *) giterr_last(void);

/**
 * Clear the last error.  This is an alias of `git3_error_last` and is
 * preserved for backward compatibility.
 *
 * This function is deprecated, but there is no plan to remove this
 * function at this time.
 *
 * @deprecated Use git3_error_clear
 * @see git3_error_clear
 */
GIT3_EXTERN(void) giterr_clear(void);

/**
 * Sets the error message to the given string.  This is an alias of
 * `git3_error_set_str` and is preserved for backward compatibility.
 *
 * This function is deprecated, but there is no plan to remove this
 * function at this time.
 *
 * @deprecated Use git3_error_set_str
 * @see git3_error_set_str
 */
GIT3_EXTERN(void) giterr_set_str(int error_class, const char *string);

/**
 * Indicates that an out-of-memory situation occurred.  This is an alias
 * of `git3_error_set_oom` and is preserved for backward compatibility.
 *
 * This function is deprecated, but there is no plan to remove this
 * function at this time.
 *
 * @deprecated Use git3_error_set_oom
 * @see git3_error_set_oom
 */
GIT3_EXTERN(void) giterr_set_oom(void);

/**@}*/

/** @name Deprecated Index Functions and Constants
 *
 * These functions and enumeration values are retained for backward
 * compatibility.  The newer versions of these values should be
 * preferred in all new code.
 *
 * There is no plan to remove these backward compatibility values at
 * this time.
 */
/**@{*/

/* The git3_idxentry_extended_flag_t enum */
/** @deprecated use `GIT3_INDEX_ENTRY_NAMEMASK` */
#define GIT3_IDXENTRY_NAMEMASK          GIT3_INDEX_ENTRY_NAMEMASK
/** @deprecated use `GIT3_INDEX_ENTRY_STAGEMASK` */
#define GIT3_IDXENTRY_STAGEMASK         GIT3_INDEX_ENTRY_STAGEMASK
/** @deprecated use `GIT3_INDEX_ENTRY_STAGESHIFT` */
#define GIT3_IDXENTRY_STAGESHIFT        GIT3_INDEX_ENTRY_STAGESHIFT

/* The git3_indxentry_flag_t enum */
/** @deprecated use `GIT3_INDEX_ENTRY_EXTENDED` */
#define GIT3_IDXENTRY_EXTENDED          GIT3_INDEX_ENTRY_EXTENDED
/** @deprecated use `GIT3_INDEX_ENTRY_VALID` */
#define GIT3_IDXENTRY_VALID             GIT3_INDEX_ENTRY_VALID

/** @deprecated use `GIT3_INDEX_ENTRY_STAGE` */
#define GIT3_IDXENTRY_STAGE(E)          GIT3_INDEX_ENTRY_STAGE(E)
/** @deprecated use `GIT3_INDEX_ENTRY_STAGE_SET` */
#define GIT3_IDXENTRY_STAGE_SET(E,S)    GIT3_INDEX_ENTRY_STAGE_SET(E,S)

/* The git3_idxentry_extended_flag_t enum */
/** @deprecated use `GIT3_INDEX_ENTRY_INTENT_TO_ADD` */
#define GIT3_IDXENTRY_INTENT_TO_ADD     GIT3_INDEX_ENTRY_INTENT_TO_ADD
/** @deprecated use `GIT3_INDEX_ENTRY_SKIP_WORKTREE` */
#define GIT3_IDXENTRY_SKIP_WORKTREE     GIT3_INDEX_ENTRY_SKIP_WORKTREE
/** @deprecated use `GIT3_INDEX_ENTRY_INTENT_TO_ADD | GIT3_INDEX_ENTRY_SKIP_WORKTREE` */
#define GIT3_IDXENTRY_EXTENDED_FLAGS    (GIT3_INDEX_ENTRY_INTENT_TO_ADD | GIT3_INDEX_ENTRY_SKIP_WORKTREE)
/** @deprecated this value is not public */
#define GIT3_IDXENTRY_EXTENDED2         (1 << 15)
/** @deprecated this value is not public */
#define GIT3_IDXENTRY_UPDATE            (1 << 0)
/** @deprecated this value is not public */
#define GIT3_IDXENTRY_REMOVE            (1 << 1)
/** @deprecated this value is not public */
#define GIT3_IDXENTRY_UPTODATE          (1 << 2)
/** @deprecated this value is not public */
#define GIT3_IDXENTRY_ADDED             (1 << 3)
/** @deprecated this value is not public */
#define GIT3_IDXENTRY_HASHED            (1 << 4)
/** @deprecated this value is not public */
#define GIT3_IDXENTRY_UNHASHED          (1 << 5)
/** @deprecated this value is not public */
#define GIT3_IDXENTRY_WT_REMOVE         (1 << 6)
/** @deprecated this value is not public */
#define GIT3_IDXENTRY_CONFLICTED        (1 << 7)
/** @deprecated this value is not public */
#define GIT3_IDXENTRY_UNPACKED          (1 << 8)
/** @deprecated this value is not public */
#define GIT3_IDXENTRY_NEW_SKIP_WORKTREE (1 << 9)

/* The git3_index_capability_t enum */
/** @deprecated use `GIT3_INDEX_CAPABILITY_IGNORE_CASE` */
#define GIT3_INDEXCAP_IGNORE_CASE       GIT3_INDEX_CAPABILITY_IGNORE_CASE
/** @deprecated use `GIT3_INDEX_CAPABILITY_NO_FILEMODE` */
#define GIT3_INDEXCAP_NO_FILEMODE       GIT3_INDEX_CAPABILITY_NO_FILEMODE
/** @deprecated use `GIT3_INDEX_CAPABILITY_NO_SYMLINKS` */
#define GIT3_INDEXCAP_NO_SYMLINKS       GIT3_INDEX_CAPABILITY_NO_SYMLINKS
/** @deprecated use `GIT3_INDEX_CAPABILITY_FROM_OWNER` */
#define GIT3_INDEXCAP_FROM_OWNER        GIT3_INDEX_CAPABILITY_FROM_OWNER

GIT3_EXTERN(int) git3_index_add_frombuffer(
	git3_index *index,
	const git3_index_entry *entry,
	const void *buffer, size_t len);

/**@}*/

/** @name Deprecated Object Constants
 *
 * These enumeration values are retained for backward compatibility.  The
 * newer versions of these values should be preferred in all new code.
 *
 * There is no plan to remove these backward compatibility values at
 * this time.
 */
/**@{*/

/** @deprecate use `git3_object_t` */
#define git3_otype git3_object_t

/** @deprecate use `GIT3_OBJECT_ANY` */
#define GIT3_OBJ_ANY GIT3_OBJECT_ANY
/** @deprecate use `GIT3_OBJECT_INVALID` */
#define GIT3_OBJ_BAD GIT3_OBJECT_INVALID
/** @deprecated this value is not public */
#define GIT3_OBJ__EXT1 0
/** @deprecate use `GIT3_OBJECT_COMMIT` */
#define GIT3_OBJ_COMMIT GIT3_OBJECT_COMMIT
/** @deprecate use `GIT3_OBJECT_TREE` */
#define GIT3_OBJ_TREE GIT3_OBJECT_TREE
/** @deprecate use `GIT3_OBJECT_BLOB` */
#define GIT3_OBJ_BLOB GIT3_OBJECT_BLOB
/** @deprecate use `GIT3_OBJECT_TAG` */
#define GIT3_OBJ_TAG GIT3_OBJECT_TAG
/** @deprecated this value is not public */
#define GIT3_OBJ__EXT2 5
/** @deprecate use `GIT3_OBJECT_OFS_DELTA` */
#define GIT3_OBJ_OFS_DELTA GIT3_OBJECT_OFS_DELTA
/** @deprecate use `GIT3_OBJECT_REF_DELTA` */
#define GIT3_OBJ_REF_DELTA GIT3_OBJECT_REF_DELTA

/**
 * Get the size in bytes for the structure which
 * acts as an in-memory representation of any given
 * object type.
 *
 * For all the core types, this would the equivalent
 * of calling `sizeof(git3_commit)` if the core types
 * were not opaque on the external API.
 *
 * @param type object type to get its size
 * @return size in bytes of the object
 */
GIT3_EXTERN(size_t) git3_object__size(git3_object_t type);

/**
 * Determine if the given git3_object_t is a valid object type.
 *
 * @deprecated use `git3_object_type_is_valid`
 *
 * @param type object type to test.
 * @return 1 if the type represents a valid object type, 0 otherwise
 */
GIT3_EXTERN(int) git3_object_typeisloose(git3_object_t type);

/**@}*/

/** @name Deprecated Remote Functions
 *
 * These functions are retained for backward compatibility.  The newer
 * versions of these functions should be preferred in all new code.
 *
 * There is no plan to remove these backward compatibility functions at
 * this time.
 */
/**@{*/

/**
 * Ensure the remote name is well-formed.
 *
 * @deprecated Use git3_remote_name_is_valid
 * @param remote_name name to be checked.
 * @return 1 if the reference name is acceptable; 0 if it isn't
 */
GIT3_EXTERN(int) git3_remote_is_valid_name(const char *remote_name);

/**@}*/

/** @name Deprecated Reference Functions and Constants
 *
 * These functions and enumeration values are retained for backward
 * compatibility.  The newer versions of these values should be
 * preferred in all new code.
 *
 * There is no plan to remove these backward compatibility values at
 * this time.
 */
/**@{*/

 /** Basic type of any Git reference. */
/** @deprecate use `git3_reference_t` */
#define git3_ref_t git3_reference_t
/** @deprecate use `git3_reference_format_t` */
#define git3_reference_normalize_t git3_reference_format_t

/** @deprecate use `GIT3_REFERENCE_INVALID` */
#define GIT3_REF_INVALID GIT3_REFERENCE_INVALID
/** @deprecate use `GIT3_REFERENCE_DIRECT` */
#define GIT3_REF_OID GIT3_REFERENCE_DIRECT
/** @deprecate use `GIT3_REFERENCE_SYMBOLIC` */
#define GIT3_REF_SYMBOLIC GIT3_REFERENCE_SYMBOLIC
/** @deprecate use `GIT3_REFERENCE_ALL` */
#define GIT3_REF_LISTALL GIT3_REFERENCE_ALL

/** @deprecate use `GIT3_REFERENCE_FORMAT_NORMAL` */
#define GIT3_REF_FORMAT_NORMAL GIT3_REFERENCE_FORMAT_NORMAL
/** @deprecate use `GIT3_REFERENCE_FORMAT_ALLOW_ONELEVEL` */
#define GIT3_REF_FORMAT_ALLOW_ONELEVEL GIT3_REFERENCE_FORMAT_ALLOW_ONELEVEL
/** @deprecate use `GIT3_REFERENCE_FORMAT_REFSPEC_PATTERN` */
#define GIT3_REF_FORMAT_REFSPEC_PATTERN GIT3_REFERENCE_FORMAT_REFSPEC_PATTERN
/** @deprecate use `GIT3_REFERENCE_FORMAT_REFSPEC_SHORTHAND` */
#define GIT3_REF_FORMAT_REFSPEC_SHORTHAND GIT3_REFERENCE_FORMAT_REFSPEC_SHORTHAND

/**
 * Ensure the reference name is well-formed.
 *
 * Valid reference names must follow one of two patterns:
 *
 * 1. Top-level names must contain only capital letters and underscores,
 *    and must begin and end with a letter. (e.g. "HEAD", "ORIG_HEAD").
 * 2. Names prefixed with "refs/" can be almost anything.  You must avoid
 *    the characters '~', '^', ':', '\\', '?', '[', and '*', and the
 *    sequences ".." and "@{" which have special meaning to revparse.
 *
 * @deprecated Use git3_reference_name_is_valid
 * @param refname name to be checked.
 * @return 1 if the reference name is acceptable; 0 if it isn't
 */
GIT3_EXTERN(int) git3_reference_is_valid_name(const char *refname);

GIT3_EXTERN(int) git3_tag_create_frombuffer(
	git3_oid *oid,
	git3_repository *repo,
	const char *buffer,
	int force);

/**@}*/

/** @name Deprecated Repository Constants
 *
 * These enumeration values are retained for backward compatibility.
 */

/**
 * @deprecated This option is deprecated; it is now implied when
 * a separate working directory is specified to `git3_repository_init`.
 */
#define GIT3_REPOSITORY_INIT_NO_DOTGIT3_DIR 0

/** @name Deprecated Revspec Constants
 *
 * These enumeration values are retained for backward compatibility.
 * The newer versions of these values should be preferred in all new
 * code.
 *
 * There is no plan to remove these backward compatibility values at
 * this time.
 */
/**@{*/

typedef git3_revspec_t git3_revparse_mode_t;

/** @deprecated use `GIT3_REVSPEC_SINGLE` */
#define GIT3_REVPARSE_SINGLE GIT3_REVSPEC_SINGLE
/** @deprecated use `GIT3_REVSPEC_RANGE` */
#define GIT3_REVPARSE_RANGE GIT3_REVSPEC_RANGE
/** @deprecated use `GIT3_REVSPEC_MERGE_BASE` */
#define GIT3_REVPARSE_MERGE_BASE GIT3_REVSPEC_MERGE_BASE

/**@}*/

/** @name Deprecated Credential Types
 *
 * These types are retained for backward compatibility.  The newer
 * versions of these values should be preferred in all new code.
 *
 * There is no plan to remove these backward compatibility values at
 * this time.
 */
/**@{*/

typedef git3_credential git3_cred;
typedef git3_credential_userpass_plaintext git3_cred_userpass_plaintext;
typedef git3_credential_username git3_cred_username;
typedef git3_credential_default git3_cred_default;
typedef git3_credential_ssh_key git3_cred_ssh_key;
typedef git3_credential_ssh_interactive git3_cred_ssh_interactive;
typedef git3_credential_ssh_custom git3_cred_ssh_custom;

typedef git3_credential_acquire_cb git3_cred_acquire_cb;
typedef git3_credential_sign_cb git3_cred_sign_callback;
typedef git3_credential_sign_cb git3_cred_sign_cb;
typedef git3_credential_ssh_interactive_cb git3_cred_ssh_interactive_callback;
typedef git3_credential_ssh_interactive_cb git3_cred_ssh_interactive_cb;

/** @deprecated use `git3_credential_t` */
#define git3_credtype_t git3_credential_t

/** @deprecated use `GIT3_CREDENTIAL_USERPASS_PLAINTEXT` */
#define GIT3_CREDTYPE_USERPASS_PLAINTEXT GIT3_CREDENTIAL_USERPASS_PLAINTEXT
/** @deprecated use `GIT3_CREDENTIAL_SSH_KEY` */
#define GIT3_CREDTYPE_SSH_KEY GIT3_CREDENTIAL_SSH_KEY
/** @deprecated use `GIT3_CREDENTIAL_SSH_CUSTOM` */
#define GIT3_CREDTYPE_SSH_CUSTOM GIT3_CREDENTIAL_SSH_CUSTOM
/** @deprecated use `GIT3_CREDENTIAL_DEFAULT` */
#define GIT3_CREDTYPE_DEFAULT GIT3_CREDENTIAL_DEFAULT
/** @deprecated use `GIT3_CREDENTIAL_SSH_INTERACTIVE` */
#define GIT3_CREDTYPE_SSH_INTERACTIVE GIT3_CREDENTIAL_SSH_INTERACTIVE
/** @deprecated use `GIT3_CREDENTIAL_USERNAME` */
#define GIT3_CREDTYPE_USERNAME GIT3_CREDENTIAL_USERNAME
/** @deprecated use `GIT3_CREDENTIAL_SSH_MEMORY` */
#define GIT3_CREDTYPE_SSH_MEMORY GIT3_CREDENTIAL_SSH_MEMORY

GIT3_EXTERN(void) git3_cred_free(git3_credential *cred);
GIT3_EXTERN(int) git3_cred_has_username(git3_credential *cred);
GIT3_EXTERN(const char *) git3_cred_get_username(git3_credential *cred);
GIT3_EXTERN(int) git3_cred_userpass_plaintext_new(
	git3_credential **out,
	const char *username,
	const char *password);
GIT3_EXTERN(int) git3_cred_default_new(git3_credential **out);
GIT3_EXTERN(int) git3_cred_username_new(git3_credential **out, const char *username);
GIT3_EXTERN(int) git3_cred_ssh_key_new(
	git3_credential **out,
	const char *username,
	const char *publickey,
	const char *privatekey,
	const char *passphrase);
GIT3_EXTERN(int) git3_cred_ssh_key_memory_new(
	git3_credential **out,
	const char *username,
	const char *publickey,
	const char *privatekey,
	const char *passphrase);
GIT3_EXTERN(int) git3_cred_ssh_interactive_new(
	git3_credential **out,
	const char *username,
	git3_credential_ssh_interactive_cb prompt_callback,
	void *payload);
GIT3_EXTERN(int) git3_cred_ssh_key_from_agent(
	git3_credential **out,
	const char *username);
GIT3_EXTERN(int) git3_cred_ssh_custom_new(
	git3_credential **out,
	const char *username,
	const char *publickey,
	size_t publickey_len,
	git3_credential_sign_cb sign_callback,
	void *payload);

/* Deprecated Credential Helper Types */

typedef git3_credential_userpass_payload git3_cred_userpass_payload;

GIT3_EXTERN(int) git3_cred_userpass(
	git3_credential **out,
	const char *url,
	const char *user_from_url,
	unsigned int allowed_types,
	void *payload);

/**@}*/

/** @name Deprecated Trace Callback Types
 *
 * These types are retained for backward compatibility.  The newer
 * versions of these values should be preferred in all new code.
 *
 * There is no plan to remove these backward compatibility values at
 * this time.
 */
/**@{*/

typedef git3_trace_cb git3_trace_callback;

/**@}*/

/** @name Deprecated Object ID Types
 *
 * These types are retained for backward compatibility.  The newer
 * versions of these values should be preferred in all new code.
 *
 * There is no plan to remove these backward compatibility values at
 * this time.
 */
/**@{*/

/** Deprecated OID "raw size" definition - now uses SHA3-256 */
# define GIT3_OID_RAWSZ    GIT3_OID_SHA3_256_SIZE
/** Deprecated OID "hex size" definition - now uses SHA3-256 */
# define GIT3_OID_HEXSZ    GIT3_OID_SHA3_256_HEXSIZE
/** Deprecated OID "hex zero" definition - now uses SHA3-256 */
# define GIT3_OID_HEX_ZERO GIT3_OID_SHA3_256_HEXZERO

GIT3_EXTERN(int) git3_oid_iszero(const git3_oid *id);

/**@}*/

/** @name Deprecated OID Array Functions
 *
 * These types are retained for backward compatibility.  The newer
 * versions of these values should be preferred in all new code.
 *
 * There is no plan to remove these backward compatibility values at
 * this time.
 */
/**@{*/

/**
 * Free the memory referred to by the git3_oidarray.  This is an alias of
 * `git3_oidarray_dispose` and is preserved for backward compatibility.
 *
 * This function is deprecated, but there is no plan to remove this
 * function at this time.
 *
 * @deprecated Use git3_oidarray_dispose
 * @see git3_oidarray_dispose
 */
GIT3_EXTERN(void) git3_oidarray_free(git3_oidarray *array);

/**@}*/

/** @name Deprecated Transfer Progress Types
 *
 * These types are retained for backward compatibility.  The newer
 * versions of these values should be preferred in all new code.
 *
 * There is no plan to remove these backward compatibility values at
 * this time.
 */
/**@{*/

/**
 * This structure is used to provide callers information about the
 * progress of indexing a packfile.
 *
 * This type is deprecated, but there is no plan to remove this
 * type definition at this time.
 */
typedef git3_indexer_progress git3_transfer_progress;

/**
 * Type definition for progress callbacks during indexing.
 *
 * This type is deprecated, but there is no plan to remove this
 * type definition at this time.
 */
typedef git3_indexer_progress_cb git3_transfer_progress_cb;

/**
 * Type definition for push transfer progress callbacks.
 *
 * This type is deprecated, but there is no plan to remove this
 * type definition at this time.
 */
typedef git3_push_transfer_progress_cb git3_push_transfer_progress;

 /** The type of a remote completion event */
#define git3_remote_completion_type git3_remote_completion_t

/**
 * Callback for listing the remote heads
 */
typedef int GIT3_CALLBACK(git3_headlist_cb)(git3_remote_head *rhead, void *payload);

/**@}*/

/** @name Deprecated String Array Functions
 *
 * These types are retained for backward compatibility.  The newer
 * versions of these values should be preferred in all new code.
 *
 * There is no plan to remove these backward compatibility values at
 * this time.
 */
/**@{*/

/**
 * Copy a string array object from source to target.
 *
 * This function is deprecated, but there is no plan to remove this
 * function at this time.
 *
 * @param tgt target
 * @param src source
 * @return 0 on success, < 0 on allocation failure
 */
GIT3_EXTERN(int) git3_strarray_copy(git3_strarray *tgt, const git3_strarray *src);

/**
 * Free the memory referred to by the git3_strarray.  This is an alias of
 * `git3_strarray_dispose` and is preserved for backward compatibility.
 *
 * This function is deprecated, but there is no plan to remove this
 * function at this time.
 *
 * @deprecated Use git3_strarray_dispose
 * @see git3_strarray_dispose
 */
GIT3_EXTERN(void) git3_strarray_free(git3_strarray *array);

/**@}*/

/** @name Deprecated Version Constants
 *
 * These constants are retained for backward compatibility.  The newer
 * versions of these constants should be preferred in all new code.
 *
 * There is no plan to remove these backward compatibility constants at
 * this time.
 */
/**@{*/

#define LIBGIT3_VER_MAJOR      LIBGIT3_VERSION_MAJOR
#define LIBGIT3_VER_MINOR      LIBGIT3_VERSION_MINOR
#define LIBGIT3_VER_REVISION   LIBGIT3_VERSION_REVISION
#define LIBGIT3_VER_PATCH      LIBGIT3_VERSION_PATCH
#define LIBGIT3_VER_PRERELEASE LIBGIT3_VERSION_PRERELEASE

/**@}*/

/** @name Deprecated Options Initialization Functions
 *
 * These functions are retained for backward compatibility.  The newer
 * versions of these functions should be preferred in all new code.
 *
 * There is no plan to remove these backward compatibility functions at
 * this time.
 */
/**@{*/

GIT3_EXTERN(int) git3_blame_init_options(git3_blame_options *opts, unsigned int version);
GIT3_EXTERN(int) git3_checkout_init_options(git3_checkout_options *opts, unsigned int version);
GIT3_EXTERN(int) git3_cherrypick_init_options(git3_cherrypick_options *opts, unsigned int version);
GIT3_EXTERN(int) git3_clone_init_options(git3_clone_options *opts, unsigned int version);
GIT3_EXTERN(int) git3_describe_init_options(git3_describe_options *opts, unsigned int version);
GIT3_EXTERN(int) git3_describe_init_format_options(git3_describe_format_options *opts, unsigned int version);
GIT3_EXTERN(int) git3_diff_init_options(git3_diff_options *opts, unsigned int version);
GIT3_EXTERN(int) git3_diff_find_init_options(git3_diff_find_options *opts, unsigned int version);
GIT3_EXTERN(int) git3_diff_format_email_init_options(git3_diff_format_email_options *opts, unsigned int version);
GIT3_EXTERN(int) git3_diff_patchid_init_options(git3_diff_patchid_options *opts, unsigned int version);
GIT3_EXTERN(int) git3_fetch_init_options(git3_fetch_options *opts, unsigned int version);
GIT3_EXTERN(int) git3_indexer_init_options(git3_indexer_options *opts, unsigned int version);
GIT3_EXTERN(int) git3_merge_init_options(git3_merge_options *opts, unsigned int version);
GIT3_EXTERN(int) git3_merge_file_init_input(git3_merge_file_input *input, unsigned int version);
GIT3_EXTERN(int) git3_merge_file_init_options(git3_merge_file_options *opts, unsigned int version);
GIT3_EXTERN(int) git3_proxy_init_options(git3_proxy_options *opts, unsigned int version);
GIT3_EXTERN(int) git3_push_init_options(git3_push_options *opts, unsigned int version);
GIT3_EXTERN(int) git3_rebase_init_options(git3_rebase_options *opts, unsigned int version);
GIT3_EXTERN(int) git3_remote_create_init_options(git3_remote_create_options *opts, unsigned int version);
GIT3_EXTERN(int) git3_repository_init_init_options(git3_repository_init_options *opts, unsigned int version);
GIT3_EXTERN(int) git3_revert_init_options(git3_revert_options *opts, unsigned int version);
GIT3_EXTERN(int) git3_stash_apply_init_options(git3_stash_apply_options *opts, unsigned int version);
GIT3_EXTERN(int) git3_status_init_options(git3_status_options *opts, unsigned int version);
GIT3_EXTERN(int) git3_submodule_update_init_options(git3_submodule_update_options *opts, unsigned int version);
GIT3_EXTERN(int) git3_worktree_add_init_options(git3_worktree_add_options *opts, unsigned int version);
GIT3_EXTERN(int) git3_worktree_prune_init_options(git3_worktree_prune_options *opts, unsigned int version);

/**@}*/

/** @} */
GIT3_END_DECL

#endif

#endif
