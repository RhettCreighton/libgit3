/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "common.h"

#include "git3/credential.h"
#include "git3/sys/credential.h"
#include "git3/credential_helpers.h"

static int git3_credential_ssh_key_type_new(
	git3_credential **cred,
	const char *username,
	const char *publickey,
	const char *privatekey,
	const char *passphrase,
	git3_credential_t credtype);

int git3_credential_has_username(git3_credential *cred)
{
	if (cred->credtype == GIT3_CREDENTIAL_DEFAULT)
		return 0;

	return 1;
}

const char *git3_credential_get_username(git3_credential *cred)
{
	switch (cred->credtype) {
	case GIT3_CREDENTIAL_USERNAME:
	{
		git3_credential_username *c = (git3_credential_username *) cred;
		return c->username;
	}
	case GIT3_CREDENTIAL_USERPASS_PLAINTEXT:
	{
		git3_credential_userpass_plaintext *c = (git3_credential_userpass_plaintext *) cred;
		return c->username;
	}
	case GIT3_CREDENTIAL_SSH_KEY:
	case GIT3_CREDENTIAL_SSH_MEMORY:
	{
		git3_credential_ssh_key *c = (git3_credential_ssh_key *) cred;
		return c->username;
	}
	case GIT3_CREDENTIAL_SSH_CUSTOM:
	{
		git3_credential_ssh_custom *c = (git3_credential_ssh_custom *) cred;
		return c->username;
	}
	case GIT3_CREDENTIAL_SSH_INTERACTIVE:
	{
		git3_credential_ssh_interactive *c = (git3_credential_ssh_interactive *) cred;
		return c->username;
	}

	default:
		return NULL;
	}
}

static void plaintext_free(struct git3_credential *cred)
{
	git3_credential_userpass_plaintext *c = (git3_credential_userpass_plaintext *)cred;

	git3__free(c->username);

	/* Zero the memory which previously held the password */
	if (c->password) {
		size_t pass_len = strlen(c->password);
		git3__memzero(c->password, pass_len);
		git3__free(c->password);
	}

	git3__free(c);
}

int git3_credential_userpass_plaintext_new(
	git3_credential **cred,
	const char *username,
	const char *password)
{
	git3_credential_userpass_plaintext *c;

	GIT3_ASSERT_ARG(cred);
	GIT3_ASSERT_ARG(username);
	GIT3_ASSERT_ARG(password);

	c = git3__malloc(sizeof(git3_credential_userpass_plaintext));
	GIT3_ERROR_CHECK_ALLOC(c);

	c->parent.credtype = GIT3_CREDENTIAL_USERPASS_PLAINTEXT;
	c->parent.free = plaintext_free;
	c->username = git3__strdup(username);

	if (!c->username) {
		git3__free(c);
		return -1;
	}

	c->password = git3__strdup(password);

	if (!c->password) {
		git3__free(c->username);
		git3__free(c);
		return -1;
	}

	*cred = &c->parent;
	return 0;
}

static void ssh_key_free(struct git3_credential *cred)
{
	git3_credential_ssh_key *c =
		(git3_credential_ssh_key *)cred;

	git3__free(c->username);

	if (c->privatekey) {
		/* Zero the memory which previously held the private key */
		size_t key_len = strlen(c->privatekey);
		git3__memzero(c->privatekey, key_len);
		git3__free(c->privatekey);
	}

	if (c->passphrase) {
		/* Zero the memory which previously held the passphrase */
		size_t pass_len = strlen(c->passphrase);
		git3__memzero(c->passphrase, pass_len);
		git3__free(c->passphrase);
	}

	if (c->publickey) {
		/* Zero the memory which previously held the public key */
		size_t key_len = strlen(c->publickey);
		git3__memzero(c->publickey, key_len);
		git3__free(c->publickey);
	}

	git3__free(c);
}

static void ssh_interactive_free(struct git3_credential *cred)
{
	git3_credential_ssh_interactive *c = (git3_credential_ssh_interactive *)cred;

	git3__free(c->username);

	git3__free(c);
}

static void ssh_custom_free(struct git3_credential *cred)
{
	git3_credential_ssh_custom *c = (git3_credential_ssh_custom *)cred;

	git3__free(c->username);

	if (c->publickey) {
		/* Zero the memory which previously held the publickey */
		size_t key_len = strlen(c->publickey);
		git3__memzero(c->publickey, key_len);
		git3__free(c->publickey);
	}

	git3__free(c);
}

static void default_free(struct git3_credential *cred)
{
	git3_credential_default *c = (git3_credential_default *)cred;

	git3__free(c);
}

static void username_free(struct git3_credential *cred)
{
	git3__free(cred);
}

int git3_credential_ssh_key_new(
	git3_credential **cred,
	const char *username,
	const char *publickey,
	const char *privatekey,
	const char *passphrase)
{
	return git3_credential_ssh_key_type_new(
		cred,
		username,
		publickey,
		privatekey,
		passphrase,
		GIT3_CREDENTIAL_SSH_KEY);
}

int git3_credential_ssh_key_memory_new(
	git3_credential **cred,
	const char *username,
	const char *publickey,
	const char *privatekey,
	const char *passphrase)
{
#ifdef GIT3_SSH_LIBSSH2_MEMORY_CREDENTIALS
	return git3_credential_ssh_key_type_new(
		cred,
		username,
		publickey,
		privatekey,
		passphrase,
		GIT3_CREDENTIAL_SSH_MEMORY);
#else
	GIT3_UNUSED(cred);
	GIT3_UNUSED(username);
	GIT3_UNUSED(publickey);
	GIT3_UNUSED(privatekey);
	GIT3_UNUSED(passphrase);

	git3_error_set(GIT3_ERROR_INVALID,
		"this version of libgit3 was not built with ssh memory credentials.");
	return -1;
#endif
}

static int git3_credential_ssh_key_type_new(
	git3_credential **cred,
	const char *username,
	const char *publickey,
	const char *privatekey,
	const char *passphrase,
	git3_credential_t credtype)
{
	git3_credential_ssh_key *c;

	GIT3_ASSERT_ARG(username);
	GIT3_ASSERT_ARG(cred);
	GIT3_ASSERT_ARG(privatekey);

	c = git3__calloc(1, sizeof(git3_credential_ssh_key));
	GIT3_ERROR_CHECK_ALLOC(c);

	c->parent.credtype = credtype;
	c->parent.free = ssh_key_free;

	c->username = git3__strdup(username);
	GIT3_ERROR_CHECK_ALLOC(c->username);

	c->privatekey = git3__strdup(privatekey);
	GIT3_ERROR_CHECK_ALLOC(c->privatekey);

	if (publickey) {
		c->publickey = git3__strdup(publickey);
		GIT3_ERROR_CHECK_ALLOC(c->publickey);
	}

	if (passphrase) {
		c->passphrase = git3__strdup(passphrase);
		GIT3_ERROR_CHECK_ALLOC(c->passphrase);
	}

	*cred = &c->parent;
	return 0;
}

int git3_credential_ssh_interactive_new(
	git3_credential **out,
	const char *username,
	git3_credential_ssh_interactive_cb prompt_callback,
	void *payload)
{
	git3_credential_ssh_interactive *c;

	GIT3_ASSERT_ARG(out);
	GIT3_ASSERT_ARG(username);
	GIT3_ASSERT_ARG(prompt_callback);

	c = git3__calloc(1, sizeof(git3_credential_ssh_interactive));
	GIT3_ERROR_CHECK_ALLOC(c);

	c->parent.credtype = GIT3_CREDENTIAL_SSH_INTERACTIVE;
	c->parent.free = ssh_interactive_free;

	c->username = git3__strdup(username);
	GIT3_ERROR_CHECK_ALLOC(c->username);

	c->prompt_callback = prompt_callback;
	c->payload = payload;

	*out = &c->parent;
	return 0;
}

int git3_credential_ssh_key_from_agent(git3_credential **cred, const char *username) {
	git3_credential_ssh_key *c;

	GIT3_ASSERT_ARG(username);
	GIT3_ASSERT_ARG(cred);

	c = git3__calloc(1, sizeof(git3_credential_ssh_key));
	GIT3_ERROR_CHECK_ALLOC(c);

	c->parent.credtype = GIT3_CREDENTIAL_SSH_KEY;
	c->parent.free = ssh_key_free;

	c->username = git3__strdup(username);
	GIT3_ERROR_CHECK_ALLOC(c->username);

	c->privatekey = NULL;

	*cred = &c->parent;
	return 0;
}

int git3_credential_ssh_custom_new(
	git3_credential **cred,
	const char *username,
	const char *publickey,
	size_t publickey_len,
	git3_credential_sign_cb sign_callback,
	void *payload)
{
	git3_credential_ssh_custom *c;

	GIT3_ASSERT_ARG(username);
	GIT3_ASSERT_ARG(cred);

	c = git3__calloc(1, sizeof(git3_credential_ssh_custom));
	GIT3_ERROR_CHECK_ALLOC(c);

	c->parent.credtype = GIT3_CREDENTIAL_SSH_CUSTOM;
	c->parent.free = ssh_custom_free;

	c->username = git3__strdup(username);
	GIT3_ERROR_CHECK_ALLOC(c->username);

	if (publickey_len > 0) {
		c->publickey = git3__malloc(publickey_len);
		GIT3_ERROR_CHECK_ALLOC(c->publickey);

		memcpy(c->publickey, publickey, publickey_len);
	}

	c->publickey_len = publickey_len;
	c->sign_callback = sign_callback;
	c->payload = payload;

	*cred = &c->parent;
	return 0;
}

int git3_credential_default_new(git3_credential **cred)
{
	git3_credential_default *c;

	GIT3_ASSERT_ARG(cred);

	c = git3__calloc(1, sizeof(git3_credential_default));
	GIT3_ERROR_CHECK_ALLOC(c);

	c->credtype = GIT3_CREDENTIAL_DEFAULT;
	c->free = default_free;

	*cred = c;
	return 0;
}

int git3_credential_username_new(git3_credential **cred, const char *username)
{
	git3_credential_username *c;
	size_t len, allocsize;

	GIT3_ASSERT_ARG(cred);

	len = strlen(username);

	GIT3_ERROR_CHECK_ALLOC_ADD(&allocsize, sizeof(git3_credential_username), len);
	GIT3_ERROR_CHECK_ALLOC_ADD(&allocsize, allocsize, 1);
	c = git3__malloc(allocsize);
	GIT3_ERROR_CHECK_ALLOC(c);

	c->parent.credtype = GIT3_CREDENTIAL_USERNAME;
	c->parent.free = username_free;
	memcpy(c->username, username, len + 1);

	*cred = (git3_credential *) c;
	return 0;
}

void git3_credential_free(git3_credential *cred)
{
	if (!cred)
		return;

	cred->free(cred);
}

/* Deprecated credential functions */

#ifndef GIT3_DEPRECATE_HARD
int git3_cred_has_username(git3_credential *cred)
{
	return git3_credential_has_username(cred);
}

const char *git3_cred_get_username(git3_credential *cred)
{
	return git3_credential_get_username(cred);
}

int git3_cred_userpass_plaintext_new(
	git3_credential **out,
	const char *username,
	const char *password)
{
	return git3_credential_userpass_plaintext_new(out,username, password);
}

int git3_cred_default_new(git3_credential **out)
{
	return git3_credential_default_new(out);
}

int git3_cred_username_new(git3_credential **out, const char *username)
{
	return git3_credential_username_new(out, username);
}

int git3_cred_ssh_key_new(
	git3_credential **out,
	const char *username,
	const char *publickey,
	const char *privatekey,
	const char *passphrase)
{
	return git3_credential_ssh_key_new(out, username,
		publickey, privatekey, passphrase);
}

int git3_cred_ssh_key_memory_new(
	git3_credential **out,
	const char *username,
	const char *publickey,
	const char *privatekey,
	const char *passphrase)
{
	return git3_credential_ssh_key_memory_new(out, username,
		publickey, privatekey, passphrase);
}

int git3_cred_ssh_interactive_new(
	git3_credential **out,
	const char *username,
	git3_credential_ssh_interactive_cb prompt_callback,
	void *payload)
{
	return git3_credential_ssh_interactive_new(out, username,
		prompt_callback, payload);
}

int git3_cred_ssh_key_from_agent(
	git3_credential **out,
	const char *username)
{
	return git3_credential_ssh_key_from_agent(out, username);
}

int git3_cred_ssh_custom_new(
	git3_credential **out,
	const char *username,
	const char *publickey,
	size_t publickey_len,
	git3_credential_sign_cb sign_callback,
	void *payload)
{
	return git3_credential_ssh_custom_new(out, username,
		publickey, publickey_len, sign_callback, payload);
}

void git3_cred_free(git3_credential *cred)
{
	git3_credential_free(cred);
}
#endif
