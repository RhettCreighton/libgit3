/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "common.h"
#include "str.h"

#define is_switch_or_value(spec) \
	((spec)->type == CLI_OPT_TYPE_SWITCH || \
	 (spec)->type == CLI_OPT_TYPE_VALUE)

static int print_spec_args(git3_str *out, const cli_opt_spec *spec)
{
	GIT3_ASSERT(!is_switch_or_value(spec));

	if (spec->type == CLI_OPT_TYPE_ARG)
		return git3_str_printf(out, "<%s>", spec->value_name);
	if (spec->type == CLI_OPT_TYPE_ARGS)
		return git3_str_printf(out, "<%s>...", spec->value_name);
	if (spec->type == CLI_OPT_TYPE_LITERAL)
		return git3_str_printf(out, "--");

	GIT3_ASSERT(!"unknown option spec type");
	return -1;
}

GIT3_INLINE(int) print_spec_alias(git3_str *out, const cli_opt_spec *spec)
{
	GIT3_ASSERT(is_switch_or_value(spec) && spec->alias);

	if (spec->type == CLI_OPT_TYPE_VALUE &&
	    !(spec->usage & CLI_OPT_USAGE_VALUE_OPTIONAL))
		return git3_str_printf(out, "-%c <%s>", spec->alias, spec->value_name);
	else if (spec->type == CLI_OPT_TYPE_VALUE)
		return git3_str_printf(out, "-%c [<%s>]", spec->alias, spec->value_name);
	else
		return git3_str_printf(out, "-%c", spec->alias);
}

GIT3_INLINE(int) print_spec_name(git3_str *out, const cli_opt_spec *spec)
{
	GIT3_ASSERT(is_switch_or_value(spec) && spec->name);

	if (spec->type == CLI_OPT_TYPE_VALUE &&
	    !(spec->usage & CLI_OPT_USAGE_VALUE_OPTIONAL))
		return git3_str_printf(out, "--%s=<%s>", spec->name, spec->value_name);
	else if (spec->type == CLI_OPT_TYPE_VALUE)
		return git3_str_printf(out, "--%s[=<%s>]", spec->name, spec->value_name);
	else
		return git3_str_printf(out, "--%s", spec->name);
}

GIT3_INLINE(int) print_spec_full(git3_str *out, const cli_opt_spec *spec)
{
	int error = 0;

	if (is_switch_or_value(spec)) {
		if (spec->alias)
			error |= print_spec_alias(out, spec);

		if (spec->alias && spec->name)
			error |= git3_str_printf(out, ", ");

		if (spec->name)
			error |= print_spec_name(out, spec);
	} else {
		error |= print_spec_args(out, spec);
	}

	return error;
}

GIT3_INLINE(int) print_spec(git3_str *out, const cli_opt_spec *spec)
{
	if (is_switch_or_value(spec)) {
		if (spec->alias && !(spec->usage & CLI_OPT_USAGE_SHOW_LONG))
			return print_spec_alias(out, spec);
		else
			return print_spec_name(out, spec);
	}

	return print_spec_args(out, spec);
}

/*
 * This is similar to adopt's function, but modified to understand
 * that we have a command ("git") and a "subcommand" ("checkout").
 * It also understands a terminal's line length and wrap appropriately,
 * using a `git3_str` for storage.
 */
int cli_opt_usage_fprint(
	FILE *file,
	const char *command,
	const char *subcommand,
	const cli_opt_spec specs[],
	unsigned int print_flags)
{
	git3_str usage = GIT3_BUF_INIT, opt = GIT3_BUF_INIT;
	const cli_opt_spec *spec;
	size_t i, prefixlen, linelen;
	bool choice = false, next_choice = false, optional = false;
	int error;

	/* TODO: query actual console width. */
	int console_width = 78;

	if ((error = git3_str_printf(&usage, "usage: %s", command)) < 0)
		goto done;

	if (subcommand &&
	    (error = git3_str_printf(&usage, " %s", subcommand)) < 0)
		goto done;

	linelen = git3_str_len(&usage);
	prefixlen = linelen + 1;

	for (spec = specs; spec->type; ++spec) {
		if (!choice)
			optional = !(spec->usage & CLI_OPT_USAGE_REQUIRED);

		next_choice = !!((spec + 1)->usage & CLI_OPT_USAGE_CHOICE);

		if ((spec->usage & CLI_OPT_USAGE_HIDDEN) &&
		    !(print_flags & CLI_OPT_USAGE_SHOW_HIDDEN))
			continue;

		if (choice)
			git3_str_putc(&opt, '|');
		else
			git3_str_clear(&opt);

		if (optional && !choice)
			git3_str_putc(&opt, '[');
		if (!optional && !choice && next_choice)
			git3_str_putc(&opt, '(');

		if ((error = print_spec(&opt, spec)) < 0)
			goto done;

		if (!optional && choice && !next_choice)
			git3_str_putc(&opt, ')');
		else if (optional && !next_choice)
			git3_str_putc(&opt, ']');

		if ((choice = next_choice))
			continue;

		if (git3_str_oom(&opt)) {
			error = -1;
			goto done;
		}

		if (linelen > prefixlen &&
		    console_width > 0 &&
		    linelen + git3_str_len(&opt) + 1 > (size_t)console_width) {
			git3_str_putc(&usage, '\n');

			for (i = 0; i < prefixlen; i++)
				git3_str_putc(&usage, ' ');

			linelen = prefixlen;
		}

		git3_str_putc(&usage, ' ');
		linelen += git3_str_len(&opt) + 1;

		git3_str_puts(&usage, git3_str_cstr(&opt));

		if (git3_str_oom(&usage)) {
			error = -1;
			goto done;
		}
	}

	error = fprintf(file, "%s\n", git3_str_cstr(&usage));

done:
	error = (error < 0) ? -1 : 0;

	git3_str_dispose(&usage);
	git3_str_dispose(&opt);
	return error;
}

int cli_opt_usage_error(
	const char *subcommand,
	const cli_opt_spec specs[],
	const cli_opt *invalid_opt)
{
	cli_opt_status_fprint(stderr, PROGRAM_NAME, invalid_opt);
	cli_opt_usage_fprint(stderr, PROGRAM_NAME, subcommand, specs, 0);
	return CLI_EXIT_USAGE;
}

int cli_opt_help_fprint(
	FILE *file,
	const cli_opt_spec specs[])
{
	git3_str help = GIT3_BUF_INIT;
	const cli_opt_spec *spec;
	bool required;
	int error = 0;

	/* Display required arguments first */
	for (spec = specs; spec->type; ++spec) {
		if ((spec->usage & CLI_OPT_USAGE_HIDDEN) ||
		    (spec->type == CLI_OPT_TYPE_LITERAL))
			continue;

		required = ((spec->usage & CLI_OPT_USAGE_REQUIRED) ||
		    ((spec->usage & CLI_OPT_USAGE_CHOICE) && required));

		if (!required)
			continue;

		git3_str_printf(&help, "    ");

		if ((error = print_spec_full(&help, spec)) < 0)
			goto done;

		git3_str_printf(&help, "\n");

		if (spec->help)
			git3_str_printf(&help, "        %s\n", spec->help);
	}

	/* Display the remaining arguments */
	for (spec = specs; spec->type; ++spec) {
		if ((spec->usage & CLI_OPT_USAGE_HIDDEN) ||
		    (spec->type == CLI_OPT_TYPE_LITERAL))
			continue;

		required = ((spec->usage & CLI_OPT_USAGE_REQUIRED) ||
		    ((spec->usage & CLI_OPT_USAGE_CHOICE) && required));

		if (required)
			continue;

		git3_str_printf(&help, "    ");

		if ((error = print_spec_full(&help, spec)) < 0)
			goto done;

		git3_str_printf(&help, "\n");

		if (spec->help)
			git3_str_printf(&help, "        %s\n", spec->help);
	}

	if (git3_str_oom(&help) ||
	    p_write(fileno(file), help.ptr, help.size) < 0)
		error = -1;

done:
	error = (error < 0) ? -1 : 0;

	git3_str_dispose(&help);
	return error;
}

