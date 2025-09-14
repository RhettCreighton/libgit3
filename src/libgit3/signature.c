/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "signature.h"

#include "repository.h"
#include "git3/common.h"
#include "posix.h"
#include "date.h"

void git3_signature_free(git3_signature *sig)
{
	if (sig == NULL)
		return;

	git3__free(sig->name);
	sig->name = NULL;
	git3__free(sig->email);
	sig->email = NULL;
	git3__free(sig);
}

static int signature_parse_error(const char *msg)
{
	git3_error_set(GIT3_ERROR_INVALID, "failed to parse signature - %s", msg);
	return GIT3_EINVALID;
}

static int signature_error(const char *msg)
{
	git3_error_set(GIT3_ERROR_INVALID, "failed to parse signature - %s", msg);
	return -1;
}

static bool contains_angle_brackets(const char *input)
{
	return strchr(input, '<') != NULL || strchr(input, '>') != NULL;
}

static bool is_crud(unsigned char c)
{
	return  c <= 32  ||
		c == ',' ||
		c == ':' ||
		c == ';' ||
		c == '<' ||
		c == '>' ||
		c == '"' ||
		c == '\\' ||
		c == '\'';
}

static char *extract_trimmed(const char *ptr, size_t len)
{
	while (len && is_crud((unsigned char)ptr[0])) {
		ptr++; len--;
	}

	while (len && is_crud((unsigned char)ptr[len - 1])) {
		len--;
	}

	return git3__substrdup(ptr, len);
}

int git3_signature_new(git3_signature **sig_out, const char *name, const char *email, git3_time_t time, int offset)
{
	git3_signature *p = NULL;

	GIT3_ASSERT_ARG(name);
	GIT3_ASSERT_ARG(email);

	*sig_out = NULL;

	if (contains_angle_brackets(name) ||
		contains_angle_brackets(email)) {
		return signature_error(
			"Neither `name` nor `email` should contain angle brackets chars.");
	}

	p = git3__calloc(1, sizeof(git3_signature));
	GIT3_ERROR_CHECK_ALLOC(p);

	p->name = extract_trimmed(name, strlen(name));
	GIT3_ERROR_CHECK_ALLOC(p->name);
	p->email = extract_trimmed(email, strlen(email));
	GIT3_ERROR_CHECK_ALLOC(p->email);

	if (p->name[0] == '\0' || p->email[0] == '\0') {
		git3_signature_free(p);
		return signature_error("Signature cannot have an empty name or email");
	}

	p->when.time = time;
	p->when.offset = offset;
	p->when.sign = (offset < 0) ? '-' : '+';

	*sig_out = p;
	return 0;
}

int git3_signature_dup(git3_signature **dest, const git3_signature *source)
{
	git3_signature *signature;

	if (source == NULL)
		return 0;

	signature = git3__calloc(1, sizeof(git3_signature));
	GIT3_ERROR_CHECK_ALLOC(signature);

	signature->name = git3__strdup(source->name);
	GIT3_ERROR_CHECK_ALLOC(signature->name);

	signature->email = git3__strdup(source->email);
	GIT3_ERROR_CHECK_ALLOC(signature->email);

	signature->when.time = source->when.time;
	signature->when.offset = source->when.offset;
	signature->when.sign = source->when.sign;

	*dest = signature;

	return 0;
}

int git3_signature__pdup(git3_signature **dest, const git3_signature *source, git3_pool *pool)
{
	git3_signature *signature;

	if (source == NULL)
		return 0;

	signature = git3_pool_mallocz(pool, sizeof(git3_signature));
	GIT3_ERROR_CHECK_ALLOC(signature);

	signature->name = git3_pool_strdup(pool, source->name);
	GIT3_ERROR_CHECK_ALLOC(signature->name);

	signature->email = git3_pool_strdup(pool, source->email);
	GIT3_ERROR_CHECK_ALLOC(signature->email);

	signature->when.time = source->when.time;
	signature->when.offset = source->when.offset;
	signature->when.sign = source->when.sign;

	*dest = signature;

	return 0;
}

static void current_time(time_t *now_out, int *offset_out)
{
	time_t offset;
	struct tm _utc, *utc_tm;

	/*
	 * Get the current time as seconds since the epoch and
	 * transform that into a tm struct containing the time at
	 * UTC. Give that to mktime which considers it a local time
	 * (tm_isdst = -1 asks it to take DST into account) and gives
	 * us that time as seconds since the epoch. The difference
	 * between its return value and 'now' is our offset to UTC.
	 */
	time(now_out);
	utc_tm = p_gmtime_r(now_out, &_utc);
	utc_tm->tm_isdst = -1;
	offset = (time_t)difftime(*now_out, mktime(utc_tm));
	offset /= 60;

	*offset_out = (int)offset;
}

int git3_signature_now(
	git3_signature **sig_out,
	const char *name,
	const char *email)
{
	time_t now;
	int offset;

	current_time(&now, &offset);

	return git3_signature_new(sig_out, name, email, now, offset);
}

int git3_signature_default(git3_signature **out, git3_repository *repo)
{
	int error;
	git3_config *cfg;
	const char *user_name, *user_email;

	if ((error = git3_repository_config_snapshot(&cfg, repo)) < 0)
		return error;

	if (!(error = git3_config_get_string(&user_name, cfg, "user.name")) &&
		!(error = git3_config_get_string(&user_email, cfg, "user.email")))
		error = git3_signature_now(out, user_name, user_email);

	git3_config_free(cfg);
	return error;
}

static int user_from_env(
	git3_signature **out,
	git3_repository *repo,
	const char *name_env_var,
	const char *email_env_var,
	const char *date_env_var,
	time_t default_time,
	int default_offset)
{
	int error;
	git3_config *cfg;
	const char *name, *email, *date;
	git3_time_t timestamp;
	int offset;
	git3_str name_env = GIT3_STR_INIT;
	git3_str email_env = GIT3_STR_INIT;
	git3_str date_env = GIT3_STR_INIT;

	if ((error = git3_repository_config_snapshot(&cfg, repo)) < 0)
		return error;

	/* Check if the environment variable for the name is set */
	if (!(git3__getenv(&name_env, name_env_var))) {
		name = git3_str_cstr(&name_env);
	} else {
		/* or else read the configuration value. */
		if ((error = git3_config_get_string(&name, cfg, "user.name")) < 0)
			goto done;
	}

	/* Check if the environment variable for the email is set. */
	if (!(git3__getenv(&email_env, email_env_var))) {
		email = git3_str_cstr(&email_env);
	} else {
		if ((error = git3_config_get_string(&email, cfg, "user.email")) == GIT3_ENOTFOUND) {
			git3_error *last_error;

			git3_error_save(&last_error);

			if ((error = git3__getenv(&email_env, "EMAIL")) < 0) {
				git3_error_restore(last_error);
				error = GIT3_ENOTFOUND;
				goto done;
			}

			email = git3_str_cstr(&email_env);
			git3_error_free(last_error);
		} else if (error < 0) {
			goto done;
		}
	}

	/* Check if the environment variable for the timestamp is set */
	if (!(git3__getenv(&date_env, date_env_var))) {
		date = git3_str_cstr(&date_env);

		if ((error = git3_date_offset_parse(&timestamp, &offset, date)) < 0)
			goto done;
	} else {
		timestamp = default_time;
		offset = default_offset;
	}

	error = git3_signature_new(out, name, email, timestamp, offset);

done:
	git3_config_free(cfg);
	git3_str_dispose(&name_env);
	git3_str_dispose(&email_env);
	git3_str_dispose(&date_env);
	return error;
}

int git3_signature_default_from_env(
	git3_signature **author_out,
	git3_signature **committer_out,
	git3_repository *repo)
{
	git3_signature *author = NULL, *committer = NULL;
	time_t now;
	int offset;
	int error;

	GIT3_ASSERT_ARG(author_out || committer_out);
	GIT3_ASSERT_ARG(repo);

	current_time(&now, &offset);

	if (author_out &&
	    (error = user_from_env(&author, repo, "GIT3_AUTHOR_NAME",
			"GIT3_AUTHOR_EMAIL", "GIT3_AUTHOR_DATE",
			now, offset)) < 0)
		goto on_error;

	if (committer_out &&
	    (error = user_from_env(&committer, repo, "GIT3_COMMITTER_NAME",
			"GIT3_COMMITTER_EMAIL", "GIT3_COMMITTER_DATE",
			now, offset)) < 0)
		goto on_error;

	if (author_out)
		*author_out = author;

	if (committer_out)
		*committer_out = committer;

	return 0;

on_error:
	git3__free(author);
	git3__free(committer);
	return error;
}

int git3_signature__parse(git3_signature *sig, const char **buffer_out,
		const char *buffer_end, const char *header, char ender)
{
	const char *buffer = *buffer_out;
	const char *email_start, *email_end;

	memset(sig, 0, sizeof(git3_signature));

	if (ender &&
		(buffer_end = memchr(buffer, ender, buffer_end - buffer)) == NULL)
		return signature_parse_error("no newline given");

	if (header) {
		const size_t header_len = strlen(header);

		if (buffer + header_len >= buffer_end || memcmp(buffer, header, header_len) != 0)
			return signature_parse_error("expected prefix doesn't match actual");

		buffer += header_len;
	}

	email_start = git3__memrchr(buffer, '<', buffer_end - buffer);
	email_end = git3__memrchr(buffer, '>', buffer_end - buffer);

	if (!email_start || !email_end || email_end <= email_start)
		return signature_parse_error("malformed e-mail");

	email_start += 1;
	sig->name = extract_trimmed(buffer, email_start - buffer - 1);
	sig->email = extract_trimmed(email_start, email_end - email_start);

	/* Do we even have a time at the end of the signature? */
	if (email_end + 2 < buffer_end) {
		const char *time_start = email_end + 2;
		const char *time_end;

		if (git3__strntol64(&sig->when.time, time_start,
				   buffer_end - time_start, &time_end, 10) < 0) {
			git3__free(sig->name);
			git3__free(sig->email);
			sig->name = sig->email = NULL;
			return signature_parse_error("invalid Unix timestamp");
		}

		/* do we have a timezone? */
		if (time_end + 1 < buffer_end) {
			int offset, hours, mins;
			const char *tz_start, *tz_end;

			tz_start = time_end + 1;

			if ((tz_start[0] != '-' && tz_start[0] != '+') ||
			    git3__strntol32(&offset, tz_start + 1,
					   buffer_end - tz_start - 1, &tz_end, 10) < 0) {
				/* malformed timezone, just assume it's zero */
				offset = 0;
			}

			hours = offset / 100;
			mins = offset % 100;

			/*
			 * only store timezone if it's not overflowing;
			 * see http://www.worldtimezone.com/faq.html
			 */
			if (hours <= 14 && mins <= 59) {
				sig->when.offset = (hours * 60) + mins;
				sig->when.sign = tz_start[0];
				if (tz_start[0] == '-')
					sig->when.offset = -sig->when.offset;
			}
		}
	}

	*buffer_out = buffer_end + 1;
	return 0;
}

int git3_signature_from_buffer(git3_signature **out, const char *buf)
{
	git3_signature *sig;
	const char *buf_end;
	int error;

	GIT3_ASSERT_ARG(out);
	GIT3_ASSERT_ARG(buf);

	*out = NULL;

	sig = git3__calloc(1, sizeof(git3_signature));
	GIT3_ERROR_CHECK_ALLOC(sig);

	buf_end = buf + strlen(buf);
	error = git3_signature__parse(sig, &buf, buf_end, NULL, '\0');

	if (error)
		git3__free(sig);
	else
		*out = sig;

	return error;
}

void git3_signature__writebuf(git3_str *buf, const char *header, const git3_signature *sig)
{
	int offset, hours, mins;
	char sign;

	offset = sig->when.offset;
	sign = (sig->when.offset < 0 || sig->when.sign == '-') ? '-' : '+';

	if (offset < 0)
		offset = -offset;

	hours = offset / 60;
	mins = offset % 60;

	git3_str_printf(buf, "%s%s <%s> %u %c%02d%02d\n",
			header ? header : "", sig->name, sig->email,
			(unsigned)sig->when.time, sign, hours, mins);
}

bool git3_signature__equal(const git3_signature *one, const git3_signature *two)
{
	GIT3_ASSERT_ARG(one);
	GIT3_ASSERT_ARG(two);

	return
		git3__strcmp(one->name, two->name) == 0 &&
		git3__strcmp(one->email, two->email) == 0 &&
		one->when.time == two->when.time &&
		one->when.offset == two->when.offset &&
		one->when.sign == two->when.sign;
}

