/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_git_cert_h__
#define INCLUDE_git_cert_h__

#include "common.h"
#include "types.h"

/**
 * @file git3/cert.h
 * @brief TLS and SSH certificate handling
 * @defgroup git3_cert Certificate objects
 * @ingroup Git
 * @{
 */
GIT3_BEGIN_DECL

/**
 * Type of host certificate structure that is passed to the check callback
 */
typedef enum git3_cert_t {
	/**
	 * No information about the certificate is available. This may
	 * happen when using curl.
	 */
	GIT3_CERT_NONE,
	/**
	 * The `data` argument to the callback will be a pointer to
	 * the DER-encoded data.
	 */
	GIT3_CERT_X509,
	/**
	 * The `data` argument to the callback will be a pointer to a
	 * `git3_cert_hostkey` structure.
	 */
	GIT3_CERT_HOSTKEY_LIBSSH2,
	/**
	 * The `data` argument to the callback will be a pointer to a
	 * `git3_strarray` with `name:content` strings containing
	 * information about the certificate. This is used when using
	 * curl.
	 */
	GIT3_CERT_STRARRAY
} git3_cert_t;

/**
 * Parent type for `git3_cert_hostkey` and `git3_cert_x509`.
 */
struct git3_cert {
	/**
	 * Type of certificate. A `GIT3_CERT_` value.
	 */
	git3_cert_t cert_type;
};

/**
 * Callback for the user's custom certificate checks.
 *
 * @param cert The host certificate
 * @param valid Whether the libgit3 checks (OpenSSL or WinHTTP) think
 * this certificate is valid
 * @param host Hostname of the host libgit3 connected to
 * @param payload Payload provided by the caller
 * @return 0 to proceed with the connection, < 0 to fail the connection
 *         or > 0 to indicate that the callback refused to act and that
 *         the existing validity determination should be honored
 */
typedef int GIT3_CALLBACK(git3_transport_certificate_check_cb)(git3_cert *cert, int valid, const char *host, void *payload);

/**
 * Type of SSH host fingerprint
 */
typedef enum {
	/** MD5 is available */
	GIT3_CERT_SSH_MD5 = (1 << 0),
	/** SHA-1 is available */
	GIT3_CERT_SSH_SHA1 = (1 << 1),
	/** SHA-256 is available */
	GIT3_CERT_SSH_SHA256 = (1 << 2),
	/** Raw hostkey is available */
	GIT3_CERT_SSH_RAW = (1 << 3)
} git3_cert_ssh_t;

typedef enum {
	/** The raw key is of an unknown type. */
	GIT3_CERT_SSH_RAW_TYPE_UNKNOWN = 0,
	/** The raw key is an RSA key. */
	GIT3_CERT_SSH_RAW_TYPE_RSA = 1,
	/** The raw key is a DSS key. */
	GIT3_CERT_SSH_RAW_TYPE_DSS = 2,
	/** The raw key is a ECDSA 256 key. */
	GIT3_CERT_SSH_RAW_TYPE_KEY_ECDSA_256 = 3,
	/** The raw key is a ECDSA 384 key. */
	GIT3_CERT_SSH_RAW_TYPE_KEY_ECDSA_384 = 4,
	/** The raw key is a ECDSA 521 key. */
	GIT3_CERT_SSH_RAW_TYPE_KEY_ECDSA_521 = 5,
	/** The raw key is a ED25519 key. */
	GIT3_CERT_SSH_RAW_TYPE_KEY_ED25519 = 6
} git3_cert_ssh_raw_type_t;

/**
 * Hostkey information taken from libssh2
 */
typedef struct {
	git3_cert parent; /**< The parent cert */

	/**
	 * A bitmask containing the available fields.
	 */
	git3_cert_ssh_t type;

	/**
	 * Hostkey hash. If `type` has `GIT3_CERT_SSH_MD5` set, this will
	 * have the MD5 hash of the hostkey.
	 */
	unsigned char hash_md5[16];

	/**
	 * Hostkey hash. If `type` has `GIT3_CERT_SSH_SHA1` set, this will
	 * have the SHA-1 hash of the hostkey.
	 */
	unsigned char hash_sha1[20];

	/**
	 * Hostkey hash. If `type` has `GIT3_CERT_SSH_SHA256` set, this will
	 * have the SHA-256 hash of the hostkey.
	 */
	unsigned char hash_sha256[32];

	/**
	 * Raw hostkey type. If `type` has `GIT3_CERT_SSH_RAW` set, this will
	 * have the type of the raw hostkey.
	 */
	git3_cert_ssh_raw_type_t raw_type;

	/**
	 * Pointer to the raw hostkey. If `type` has `GIT3_CERT_SSH_RAW` set,
	 * this will have the raw contents of the hostkey.
	 */
	const char *hostkey;

	/**
	 * Raw hostkey length. If `type` has `GIT3_CERT_SSH_RAW` set, this will
	 * have the length of the raw contents of the hostkey.
	 */
	size_t hostkey_len;
} git3_cert_hostkey;

/**
 * X.509 certificate information
 */
typedef struct {
	git3_cert parent; /**< The parent cert */

	/**
	 * Pointer to the X.509 certificate data
	 */
	void *data;

	/**
	 * Length of the memory block pointed to by `data`.
	 */
	size_t len;
} git3_cert_x509;

/** @} */
GIT3_END_DECL

#endif
