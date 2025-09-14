/*
 * Utilities library for libgit3 examples
 *
 * Written by the libgit3 contributors
 *
 * To the extent possible under law, the author(s) have dedicated all copyright
 * and related and neighboring rights to this software to the public domain
 * worldwide. This software is distributed without any warranty.
 *
 * You should have received a copy of the CC0 Public Domain Dedication along
 * with this software. If not, see
 * <http://creativecommons.org/publicdomain/zero/1.0/>.
 */


#include "common.h"

#ifndef _WIN32
# include <unistd.h>
#endif
#include <errno.h>

void check_lg2(int error, const char *message, const char *extra)
{
	const git3_error *lg2err;
	const char *lg2msg = "", *lg2spacer = "";

	if (!error)
		return;

	if ((lg2err = git3_error_last()) != NULL && lg2err->message != NULL) {
		lg2msg = lg2err->message;
		lg2spacer = " - ";
	}

	if (extra)
		fprintf(stderr, "%s '%s' [%d]%s%s\n",
			message, extra, error, lg2spacer, lg2msg);
	else
		fprintf(stderr, "%s [%d]%s%s\n",
			message, error, lg2spacer, lg2msg);

	exit(1);
}

void fatal(const char *message, const char *extra)
{
	if (extra)
		fprintf(stderr, "%s %s\n", message, extra);
	else
		fprintf(stderr, "%s\n", message);

	exit(1);
}

int diff_output(
	const git3_diff_delta *d,
	const git3_diff_hunk *h,
	const git3_diff_line *l,
	void *p)
{
	FILE *fp = (FILE*)p;

	(void)d; (void)h;

	if (!fp)
		fp = stdout;

	if (l->origin == GIT3_DIFF_LINE_CONTEXT ||
		l->origin == GIT3_DIFF_LINE_ADDITION ||
		l->origin == GIT3_DIFF_LINE_DELETION)
		fputc(l->origin, fp);

	fwrite(l->content, 1, l->content_len, fp);

	return 0;
}

void treeish_to_tree(
	git3_tree **out, git3_repository *repo, const char *treeish)
{
	git3_object *obj = NULL;

	check_lg2(
		git3_revparse_single(&obj, repo, treeish),
		"looking up object", treeish);

	check_lg2(
		git3_object_peel((git3_object **)out, obj, GIT3_OBJECT_TREE),
		"resolving object to tree", treeish);

	git3_object_free(obj);
}

void *xrealloc(void *oldp, size_t newsz)
{
	void *p = realloc(oldp, newsz);
	if (p == NULL) {
		fprintf(stderr, "Cannot allocate memory, exiting.\n");
		exit(1);
	}
	return p;
}

int resolve_refish(git3_annotated_commit **commit, git3_repository *repo, const char *refish)
{
	git3_reference *ref;
	git3_object *obj;
	int err = 0;

	assert(commit != NULL);

	err = git3_reference_dwim(&ref, repo, refish);
	if (err == GIT3_OK) {
		git3_annotated_commit_from_ref(commit, repo, ref);
		git3_reference_free(ref);
		return 0;
	}

	err = git3_revparse_single(&obj, repo, refish);
	if (err == GIT3_OK) {
		err = git3_annotated_commit_lookup(commit, repo, git3_object_id(obj));
		git3_object_free(obj);
	}

	return err;
}

static int readline(char **out)
{
	int c, error = 0, length = 0, allocated = 0;
	char *line = NULL;

	errno = 0;

	while ((c = getchar()) != EOF) {
		if (length == allocated) {
			allocated += 16;

			if ((line = realloc(line, allocated)) == NULL) {
				error = -1;
				goto error;
			}
		}

		if (c == '\n')
			break;

		line[length++] = c;
	}

	if (errno != 0) {
		error = -1;
		goto error;
	}

	line[length] = '\0';
	*out = line;
	line = NULL;
	error = length;
error:
	free(line);
	return error;
}

static int ask(char **out, const char *prompt, char optional)
{
	printf("%s ", prompt);
	fflush(stdout);

	if (!readline(out) && !optional) {
		fprintf(stderr, "Could not read response: %s", strerror(errno));
		return -1;
	}

	return 0;
}

int cred_acquire_cb(git3_credential **out,
		const char *url,
		const char *username_from_url,
		unsigned int allowed_types,
		void *payload)
{
	char *username = NULL, *password = NULL, *privkey = NULL, *pubkey = NULL;
	int error = 1;

	UNUSED(url);
	UNUSED(payload);

	if (username_from_url) {
		if ((username = strdup(username_from_url)) == NULL)
			goto out;
	} else if ((error = ask(&username, "Username:", 0)) < 0) {
		goto out;
	}

	if (allowed_types & GIT3_CREDENTIAL_SSH_KEY) {
		int n;

		if ((error = ask(&privkey, "SSH Key:", 0)) < 0 ||
		    (error = ask(&password, "Password:", 1)) < 0)
			goto out;

		if ((n = snprintf(NULL, 0, "%s.pub", privkey)) < 0 ||
		    (pubkey = malloc(n + 1)) == NULL ||
		    (n = snprintf(pubkey, n + 1, "%s.pub", privkey)) < 0)
			goto out;

		error = git3_credential_ssh_key_new(out, username, pubkey, privkey, password);
	} else if (allowed_types & GIT3_CREDENTIAL_USERPASS_PLAINTEXT) {
		if ((error = ask(&password, "Password:", 1)) < 0)
			goto out;

		error = git3_credential_userpass_plaintext_new(out, username, password);
	} else if (allowed_types & GIT3_CREDENTIAL_USERNAME) {
		error = git3_credential_username_new(out, username);
	}

out:
	free(username);
	free(password);
	free(privkey);
	free(pubkey);
	return error;
}

char *read_file(const char *path)
{
	ssize_t total = 0;
	char *buf = NULL;
	struct stat st;
	int fd = -1;

	if ((fd = open(path, O_RDONLY)) < 0 || fstat(fd, &st) < 0)
		goto out;

	if ((buf = malloc(st.st_size + 1)) == NULL)
		goto out;

	while (total < st.st_size) {
		ssize_t bytes = read(fd, buf + total, st.st_size - total);
		if (bytes <= 0) {
			if (errno == EAGAIN || errno == EINTR)
				 continue;
			free(buf);
			buf = NULL;
			goto out;
		}
		total += bytes;
	}

	buf[total] = '\0';

out:
	if (fd >= 0)
		close(fd);
	return buf;
}

