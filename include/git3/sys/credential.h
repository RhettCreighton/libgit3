/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_sys_git_credential_h__
#define INCLUDE_sys_git_credential_h__

#include "git3/common.h"
#include "git3/credential.h"

/**
 * @file git3/sys/credential.h
 * @brief Low-level credentials implementation
 * @defgroup git3_credential Low-level credentials implementation
 * @ingroup Git
 * @{
 */
GIT3_BEGIN_DECL

/**
 * The base structure for all credential types
 */
struct git3_credential {
	git3_credential_t credtype; /**< A type of credential */

	/** The deallocator for this type of credentials */
	void GIT3_CALLBACK(free)(git3_credential *cred);
};

/** A plaintext username and password */
struct git3_credential_userpass_plaintext {
	git3_credential parent; /**< The parent credential */
	char *username;        /**< The username to authenticate as */
	char *password;        /**< The password to use */
};

/** Username-only credential information */
struct git3_credential_username {
	git3_credential parent; /**< The parent credential */
	char username[1];      /**< The username to authenticate as */
};

/**
 * A ssh key from disk
 */
struct git3_credential_ssh_key {
	git3_credential parent; /**< The parent credential */
	char *username;        /**< The username to authenticate as */
	char *publickey;       /**< The path to a public key */
	char *privatekey;      /**< The path to a private key */
	char *passphrase;      /**< Passphrase to decrypt the private key */
};

/**
 * Keyboard-interactive based ssh authentication
 */
struct git3_credential_ssh_interactive {
	git3_credential parent; /**< The parent credential */
	char *username;        /**< The username to authenticate as */

	/**
	 * Callback used for authentication.
	 */
	git3_credential_ssh_interactive_cb prompt_callback;

	void *payload;         /**< Payload passed to prompt_callback */
};

/**
 * A key with a custom signature function
 */
struct git3_credential_ssh_custom {
	git3_credential parent; /**< The parent credential */
	char *username;        /**< The username to authenticate as */
	char *publickey;       /**< The public key data */
	size_t publickey_len;  /**< Length of the public key */

	/**
	 * Callback used to sign the data.
	 */
	git3_credential_sign_cb sign_callback;

	void *payload;         /**< Payload passed to prompt_callback */
};

/** @} */
GIT3_END_DECL

#endif
