/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "common.h"

#include "git3/credential_helpers.h"

int git3_credential_userpass(
		git3_credential **cred,
		const char *url,
		const char *user_from_url,
		unsigned int allowed_types,
		void *payload)
{
	git3_credential_userpass_payload *userpass = (git3_credential_userpass_payload*)payload;
	const char *effective_username = NULL;

	GIT3_UNUSED(url);

	if (!userpass || !userpass->password) return -1;

	/* Username resolution: a username can be passed with the URL, the
	 * credentials payload, or both. Here's what we do.  Note that if we get
	 * this far, we know that any password the url may contain has already
	 * failed at least once, so we ignore it.
	 *
	 * |  Payload    |   URL    |   Used    |
	 * +-------------+----------+-----------+
	 * |    yes      |   no     |  payload  |
	 * |    yes      |   yes    |  payload  |
	 * |    no       |   yes    |  url      |
	 * |    no       |   no     |  FAIL     |
	 */
	if (userpass->username)
		effective_username = userpass->username;
	else if (user_from_url)
		effective_username = user_from_url;
	else
		return -1;

	if (GIT3_CREDENTIAL_USERNAME & allowed_types)
		return git3_credential_username_new(cred, effective_username);

	if ((GIT3_CREDENTIAL_USERPASS_PLAINTEXT & allowed_types) == 0 ||
			git3_credential_userpass_plaintext_new(cred, effective_username, userpass->password) < 0)
		return -1;

	return 0;
}

/* Deprecated credential functions */

#ifndef GIT3_DEPRECATE_HARD
int git3_cred_userpass(
	git3_credential **out,
	const char *url,
	const char *user_from_url,
	unsigned int allowed_types,
	void *payload)
{
	return git3_credential_userpass(out, url, user_from_url,
		allowed_types, payload);
}
#endif
