/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_git_oid_h__
#define INCLUDE_git_oid_h__

#include "common.h"
#include "experimental.h"

/**
 * @file git3/oid.h
 * @brief Object IDs
 * @defgroup git3_oid Git object id routines
 * @ingroup Git
 * @{
 */
GIT3_BEGIN_DECL

/** The type of object id. */
typedef enum {
	GIT3_OID_SHA1 = 1,  /**< SHA1 (deprecated, not used in git3) */
	GIT3_OID_SHA3_256 = 2 /**< SHA3-256 (used by git3) */
} git3_oid_t;

/*
 * SHA3-256 is the only supported object ID type for git3.
 */

/** SHA3-256 is libgit3's default oid type for git3 compatibility. */
#define GIT3_OID_DEFAULT         GIT3_OID_SHA3_256

/** Size (in bytes) of a raw/binary sha1 oid (deprecated) */
#define GIT3_OID_SHA1_SIZE       20
/** Size (in bytes) of a hex formatted sha1 oid (deprecated) */
#define GIT3_OID_SHA1_HEXSIZE   (GIT3_OID_SHA1_SIZE * 2)

/** Size (in bytes) of a raw/binary sha3-256 oid */
#define GIT3_OID_SHA3_256_SIZE     32
/** Size (in bytes) of a hex formatted sha3-256 oid */
#define GIT3_OID_SHA3_256_HEXSIZE (GIT3_OID_SHA3_256_SIZE * 2)

/**
 * The binary representation of the null sha1 object ID (deprecated).
 */
# define GIT3_OID_SHA1_ZERO   { GIT3_OID_SHA1, { 0 } }

/**
 * The string representation of the null sha1 object ID (deprecated).
 */
#define GIT3_OID_SHA1_HEXZERO   "0000000000000000000000000000000000000000"

/**
 * The binary representation of the null sha3-256 object ID.
 */
# define GIT3_OID_SHA3_256_ZERO { GIT3_OID_SHA3_256, { 0 } }

/**
 * The string representation of the null sha3-256 object ID.
 */
#define GIT3_OID_SHA3_256_HEXZERO "0000000000000000000000000000000000000000000000000000000000000000"

/* SHA256 definitions kept for backwards compatibility but aliased to SHA3-256 */
# define GIT3_OID_SHA256_SIZE     GIT3_OID_SHA3_256_SIZE
# define GIT3_OID_SHA256_HEXSIZE  GIT3_OID_SHA3_256_HEXSIZE
# define GIT3_OID_SHA256_ZERO     GIT3_OID_SHA3_256_ZERO
# define GIT3_OID_SHA256_HEXZERO  GIT3_OID_SHA3_256_HEXZERO
# define GIT3_OID_SHA256          GIT3_OID_SHA3_256

/** Maximum possible object ID size in raw format */
# define GIT3_OID_MAX_SIZE        GIT3_OID_SHA3_256_SIZE

/** Maximum possible object ID size in hex format */
# define GIT3_OID_MAX_HEXSIZE     GIT3_OID_SHA3_256_HEXSIZE

/** Minimum length (in number of hex characters,
 * i.e. packets of 4 bits) of an oid prefix */
#define GIT3_OID_MINPREFIXLEN 4

/** Unique identity of any object (commit, tree, blob, tag). */
typedef struct git3_oid {
	/** type of object id */
	unsigned char type;

	/** raw binary formatted id */
	unsigned char id[GIT3_OID_MAX_SIZE];
} git3_oid;

/**
 * Parse a NUL terminated hex formatted object id string into a `git3_oid`.
 *
 * The given string must be NUL terminated, and must be the hex size of
 * the given object ID type - 40 characters for SHA1, 64 characters for
 * SHA3-256.
 *
 * To parse an incomplete object ID (an object ID prefix), or a sequence
 * of characters that is not NUL terminated, use `git3_oid_from_prefix`.
 *
 * @param out oid structure the result is written into.
 * @param str input hex string
 * @param type object id type
 * @return 0 or an error code
 */
GIT3_EXTERN(int) git3_oid_from_string(
	git3_oid *out,
	const char *str,
	git3_oid_t type);

/**
 * Parse the given number of characters out of a hex formatted object id
 * string into a `git3_oid`.
 *
 * The given length can be between 0 and the hex size for the given object ID
 * type - 40 characters for SHA1, 64 characters for SHA3-256. The remainder of
 * the `git3_oid` will be set to zeros.
 *
 * @param out oid structure the result is written into.
 * @param str input hex prefix
 * @param type object id type
 * @return 0 or an error code
 */
GIT3_EXTERN(int) git3_oid_from_prefix(
	git3_oid *out,
	const char *str,
	size_t len,
	git3_oid_t type);

/**
 * Parse a raw object id into a `git3_oid`.
 *
 * The appropriate number of bytes for the given object ID type will
 * be read from the byte array - 20 bytes for SHA1, 32 bytes for SHA3-256.
 *
 * @param out oid structure the result is written into.
 * @param raw raw object ID bytes
 * @param type object id type
 * @return 0 or an error code
 */
GIT3_EXTERN(int) git3_oid_from_raw(
	git3_oid *out,
	const unsigned char *raw,
	git3_oid_t type);

/**
 * Parse a hex formatted object id into a git3_oid.
 *
 * The appropriate number of bytes for the given object ID type will
 * be read from the string - 40 bytes for SHA1, 64 bytes for SHA3-256.
 * The given string need not be NUL terminated.
 *
 * @param out oid structure the result is written into.
 * @param str input hex string; must be pointing at the start of
 *		the hex sequence and have at least the number of bytes
 *		needed for an oid encoded in hex (40 bytes for sha1,
 *		256 bytes for sha256).
 * @return 0 or an error code
 */
GIT3_EXTERN(int) git3_oid_fromstr(git3_oid *out, const char *str);

/**
 * Parse a hex formatted NUL-terminated string into a git3_oid.
 *
 * @param out oid structure the result is written into.
 * @param str input hex string; must be null-terminated.
 * @return 0 or an error code
 */
GIT3_EXTERN(int) git3_oid_fromstrp(git3_oid *out, const char *str);

/**
 * Parse N characters of a hex formatted object id into a git3_oid.
 *
 * If N is odd, the last byte's high nibble will be read in and the
 * low nibble set to zero.
 *
 * @param out oid structure the result is written into.
 * @param str input hex string of at least size `length`
 * @param length length of the input string
 * @return 0 or an error code
 */
GIT3_EXTERN(int) git3_oid_fromstrn(git3_oid *out, const char *str, size_t length);

/**
 * Copy an already raw oid into a git3_oid structure.
 *
 * @param out oid structure the result is written into.
 * @param raw the raw input bytes to be copied.
 * @return 0 on success or error code
 */
GIT3_EXTERN(int) git3_oid_fromraw(git3_oid *out, const unsigned char *raw);

/**
 * Format a git3_oid into a hex string.
 *
 * @param out output hex string; must be pointing at the start of
 *		the hex sequence and have at least the number of bytes
 *		needed for an oid encoded in hex (40 bytes for SHA1,
 *		64 bytes for SHA3-256). Only the oid digits are written;
 *		a '\\0' terminator must be added by the caller if it is
 *		required.
 * @param id oid structure to format.
 * @return 0 on success or error code
 */
GIT3_EXTERN(int) git3_oid_fmt(char *out, const git3_oid *id);

/**
 * Format a git3_oid into a partial hex string.
 *
 * @param out output hex string; you say how many bytes to write.
 *		If the number of bytes is > GIT3_OID_SHA1_HEXSIZE, extra bytes
 *		will be zeroed; if not, a '\0' terminator is NOT added.
 * @param n number of characters to write into out string
 * @param id oid structure to format.
 * @return 0 on success or error code
 */
GIT3_EXTERN(int) git3_oid_nfmt(char *out, size_t n, const git3_oid *id);

/**
 * Format a git3_oid into a loose-object path string.
 *
 * The resulting string is "aa/...", where "aa" is the first two
 * hex digits of the oid and "..." is the remaining 38 digits.
 *
 * @param out output hex string; must be pointing at the start of
 *		the hex sequence and have at least the number of bytes
 *		needed for an oid encoded in hex (41 bytes for SHA1,
 *		65 bytes for SHA3-256). Only the oid digits are written;
 *		a '\\0' terminator must be added by the caller if it
 *		is required.
 * @param id oid structure to format.
 * @return 0 on success, non-zero callback return value, or error code
 */
GIT3_EXTERN(int) git3_oid_pathfmt(char *out, const git3_oid *id);

/**
 * Format a git3_oid into a statically allocated c-string.
 *
 * The c-string is owned by the library and should not be freed
 * by the user. If libgit3 is built with thread support, the string
 * will be stored in TLS (i.e. one buffer per thread) to allow for
 * concurrent calls of the function.
 *
 * @param oid The oid structure to format
 * @return the c-string or NULL on failure
 */
GIT3_EXTERN(char *) git3_oid_tostr_s(const git3_oid *oid);

/**
 * Format a git3_oid into a buffer as a hex format c-string.
 *
 * If the buffer is smaller than the size of a hex-formatted oid string
 * plus an additional byte (GIT3_OID_SHA1_HEXSIZE + 1 for SHA1 or
 * GIT3_OID_SHA3_256_HEXSIZE + 1 for SHA3-256), then the resulting
 * oid c-string will be truncated to n-1 characters (but will still be
 * NUL-byte terminated).
 *
 * If there are any input parameter errors (out == NULL, n == 0, oid ==
 * NULL), then a pointer to an empty string is returned, so that the
 * return value can always be printed.
 *
 * @param out the buffer into which the oid string is output.
 * @param n the size of the out buffer.
 * @param id the oid structure to format.
 * @return the out buffer pointer, assuming no input parameter
 *			errors, otherwise a pointer to an empty string.
 */
GIT3_EXTERN(char *) git3_oid_tostr(char *out, size_t n, const git3_oid *id);

/**
 * Copy an oid from one structure to another.
 *
 * @param out oid structure the result is written into.
 * @param src oid structure to copy from.
 * @return 0 on success or error code
 */
GIT3_EXTERN(int) git3_oid_cpy(git3_oid *out, const git3_oid *src);

/**
 * Compare two oid structures.
 *
 * @param a first oid structure.
 * @param b second oid structure.
 * @return <0, 0, >0 if a < b, a == b, a > b.
 */
GIT3_EXTERN(int) git3_oid_cmp(const git3_oid *a, const git3_oid *b);

/**
 * Compare two oid structures for equality
 *
 * @param a first oid structure.
 * @param b second oid structure.
 * @return true if equal, false otherwise
 */
GIT3_EXTERN(int) git3_oid_equal(const git3_oid *a, const git3_oid *b);

/**
 * Compare the first 'len' hexadecimal characters (packets of 4 bits)
 * of two oid structures.
 *
 * @param a first oid structure.
 * @param b second oid structure.
 * @param len the number of hex chars to compare
 * @return 0 in case of a match
 */
GIT3_EXTERN(int) git3_oid_ncmp(const git3_oid *a, const git3_oid *b, size_t len);

/**
 * Check if an oid equals an hex formatted object id.
 *
 * @param id oid structure.
 * @param str input hex string of an object id.
 * @return 0 in case of a match, -1 otherwise.
 */
GIT3_EXTERN(int) git3_oid_streq(const git3_oid *id, const char *str);

/**
 * Compare an oid to an hex formatted object id.
 *
 * @param id oid structure.
 * @param str input hex string of an object id.
 * @return -1 if str is not valid, <0 if id sorts before str,
 *         0 if id matches str, >0 if id sorts after str.
 */
GIT3_EXTERN(int) git3_oid_strcmp(const git3_oid *id, const char *str);

/**
 * Check is an oid is all zeros.
 *
 * @param id the object ID to check
 * @return 1 if all zeros, 0 otherwise.
 */
GIT3_EXTERN(int) git3_oid_is_zero(const git3_oid *id);

/**
 * OID Shortener object
 */
typedef struct git3_oid_shorten git3_oid_shorten;

/**
 * Create a new OID shortener.
 *
 * The OID shortener is used to process a list of OIDs
 * in text form and return the shortest length that would
 * uniquely identify all of them.
 *
 * E.g. look at the result of `git log --abbrev`.
 *
 * @param min_length The minimal length for all identifiers,
 *		which will be used even if shorter OIDs would still
 *		be unique.
 *	@return a `git3_oid_shorten` instance, NULL if OOM
 */
GIT3_EXTERN(git3_oid_shorten *) git3_oid_shorten_new(size_t min_length);

/**
 * Add a new OID to set of shortened OIDs and calculate
 * the minimal length to uniquely identify all the OIDs in
 * the set.
 *
 * The OID is expected to be a 40-char hexadecimal string.
 * The OID is owned by the user and will not be modified
 * or freed.
 *
 * For performance reasons, there is a hard-limit of how many
 * OIDs can be added to a single set (around ~32000, assuming
 * a mostly randomized distribution), which should be enough
 * for any kind of program, and keeps the algorithm fast and
 * memory-efficient.
 *
 * Attempting to add more than those OIDs will result in a
 * GIT3_ERROR_INVALID error
 *
 * @param os a `git3_oid_shorten` instance
 * @param text_id an OID in text form
 * @return the minimal length to uniquely identify all OIDs
 *		added so far to the set; or an error code (<0) if an
 *		error occurs.
 */
GIT3_EXTERN(int) git3_oid_shorten_add(git3_oid_shorten *os, const char *text_id);

/**
 * Free an OID shortener instance
 *
 * @param os a `git3_oid_shorten` instance
 */
GIT3_EXTERN(void) git3_oid_shorten_free(git3_oid_shorten *os);

/** @} */
GIT3_END_DECL

#endif
