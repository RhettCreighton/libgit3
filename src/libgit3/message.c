/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "buf.h"

#include "git3/message.h"

static size_t line_length_without_trailing_spaces(const char *line, size_t len)
{
	while (len) {
		unsigned char c = line[len - 1];
		if (!git3__isspace(c))
			break;
		len--;
	}

	return len;
}

/* Greatly inspired from git.git "stripspace" */
/* see https://github.com/git/git/blob/497215d8811ac7b8955693ceaad0899ecd894ed2/builtin/stripspace.c#L4-67 */
static int git3_message__prettify(
	git3_str *message_out,
	const char *message,
	int strip_comments,
	char comment_char)
{
	const size_t message_len = strlen(message);

	int consecutive_empty_lines = 0;
	size_t i, line_length, rtrimmed_line_length;
	char *next_newline;

	for (i = 0; i < strlen(message); i += line_length) {
		next_newline = memchr(message + i, '\n', message_len - i);

		if (next_newline != NULL) {
			line_length = next_newline - (message + i) + 1;
		} else {
			line_length = message_len - i;
		}

		if (strip_comments && line_length && message[i] == comment_char)
			continue;

		rtrimmed_line_length = line_length_without_trailing_spaces(message + i, line_length);

		if (!rtrimmed_line_length) {
			consecutive_empty_lines++;
			continue;
		}

		if (consecutive_empty_lines > 0 && message_out->size > 0)
			git3_str_putc(message_out, '\n');

		consecutive_empty_lines = 0;
		git3_str_put(message_out, message + i, rtrimmed_line_length);
		git3_str_putc(message_out, '\n');
	}

	return git3_str_oom(message_out) ? -1 : 0;
}

int git3_message_prettify(
	git3_buf *message_out,
	const char *message,
	int strip_comments,
	char comment_char)
{
	GIT3_BUF_WRAP_PRIVATE(message_out, git3_message__prettify, message, strip_comments, comment_char);
}
