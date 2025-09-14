/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "diff_driver.h"

#include "git3/attr.h"

#include "common.h"
#include "diff.h"
#include "map.h"
#include "config.h"
#include "regexp.h"
#include "repository.h"
#include "userdiff.h"

typedef enum {
	DIFF_DRIVER_AUTO = 0,
	DIFF_DRIVER_BINARY = 1,
	DIFF_DRIVER_TEXT = 2,
	DIFF_DRIVER_PATTERNLIST = 3
} git3_diff_driver_t;

typedef struct {
	git3_regexp re;
	int flags;
} git3_diff_driver_pattern;

enum {
	REG_NEGATE = (1 << 15) /* get out of the way of existing flags */
};

/* data for finding function context for a given file type */
struct git3_diff_driver {
	git3_diff_driver_t type;
	uint32_t binary_flags;
	uint32_t other_flags;
	git3_array_t(git3_diff_driver_pattern) fn_patterns;
	git3_regexp  word_pattern;
	char name[GIT3_FLEX_ARRAY];
};

GIT3_HASHMAP_STR_SETUP(git3_diff_driver_map, git3_diff_driver *);

struct git3_diff_driver_registry {
	git3_diff_driver_map map;
};

#define FORCE_DIFFABLE (GIT3_DIFF_FORCE_TEXT | GIT3_DIFF_FORCE_BINARY)

static git3_diff_driver diff_driver_auto =   { DIFF_DRIVER_AUTO,   0, 0 };
static git3_diff_driver diff_driver_binary = { DIFF_DRIVER_BINARY, GIT3_DIFF_FORCE_BINARY, 0 };
static git3_diff_driver diff_driver_text =   { DIFF_DRIVER_TEXT,   GIT3_DIFF_FORCE_TEXT, 0 };

git3_diff_driver_registry *git3_diff_driver_registry_new(void)
{
	return git3__calloc(1, sizeof(git3_diff_driver_registry));
}

void git3_diff_driver_registry_free(git3_diff_driver_registry *reg)
{
	git3_diff_driver *drv;
	git3_hashmap_iter_t iter = 0;

	if (!reg)
		return;

	while (git3_diff_driver_map_iterate(&iter, NULL, &drv, &reg->map) == 0)
		git3_diff_driver_free(drv);

	git3_diff_driver_map_dispose(&reg->map);
	git3__free(reg);
}

static int diff_driver_add_patterns(
	git3_diff_driver *drv, const char *regex_str, int regex_flags)
{
	int error = 0;
	const char *scan, *end;
	git3_diff_driver_pattern *pat = NULL;
	git3_str buf = GIT3_STR_INIT;

	for (scan = regex_str; scan; scan = end) {
		/* get pattern to fill in */
		if ((pat = git3_array_alloc(drv->fn_patterns)) == NULL) {
			return -1;
		}

		pat->flags = regex_flags;
		if (*scan == '!') {
			pat->flags |= REG_NEGATE;
			++scan;
		}

		if ((end = strchr(scan, '\n')) != NULL) {
			error = git3_str_set(&buf, scan, end - scan);
			end++;
		} else {
			error = git3_str_sets(&buf, scan);
		}
		if (error < 0)
			break;

		if ((error = git3_regexp_compile(&pat->re, buf.ptr, regex_flags)) != 0) {
			/*
			 * TODO: issue a warning
			 */
		}
	}

	if (error && pat != NULL)
		(void)git3_array_pop(drv->fn_patterns); /* release last item */
	git3_str_dispose(&buf);

	/* We want to ignore bad patterns, so return success regardless */
	return 0;
}

static int diff_driver_xfuncname(const git3_config_entry *entry, void *payload)
{
	return diff_driver_add_patterns(payload, entry->value, 0);
}

static int diff_driver_funcname(const git3_config_entry *entry, void *payload)
{
	return diff_driver_add_patterns(payload, entry->value, 0);
}

static git3_diff_driver_registry *git3_repository_driver_registry(
	git3_repository *repo)
{
	git3_diff_driver_registry *reg = git3_atomic_load(repo->diff_drivers), *newreg;
	if (reg)
		return reg;

	newreg = git3_diff_driver_registry_new();
	if (!newreg) {
		git3_error_set(GIT3_ERROR_REPOSITORY, "unable to create diff driver registry");
		return newreg;
	}
	reg = git3_atomic_compare_and_swap(&repo->diff_drivers, NULL, newreg);
	if (!reg) {
		reg = newreg;
	} else {
		/* if we race, free losing allocation */
		git3_diff_driver_registry_free(newreg);
	}
	return reg;
}

static int diff_driver_alloc(
	git3_diff_driver **out, size_t *namelen_out, const char *name)
{
	git3_diff_driver *driver;
	size_t driverlen = sizeof(git3_diff_driver),
		namelen = strlen(name),
		alloclen;

	GIT3_ERROR_CHECK_ALLOC_ADD(&alloclen, driverlen, namelen);
	GIT3_ERROR_CHECK_ALLOC_ADD(&alloclen, alloclen, 1);

	driver = git3__calloc(1, alloclen);
	GIT3_ERROR_CHECK_ALLOC(driver);

	memcpy(driver->name, name, namelen);

	*out = driver;

	if (namelen_out)
		*namelen_out = namelen;

	return 0;
}

static int git3_diff_driver_builtin(
	git3_diff_driver **out,
	git3_diff_driver_registry *reg,
	const char *driver_name)
{
	git3_diff_driver_definition *ddef = NULL;
	git3_diff_driver *drv = NULL;
	int error = 0;
	size_t idx;

	for (idx = 0; idx < ARRAY_SIZE(builtin_defs); ++idx) {
		if (!strcasecmp(driver_name, builtin_defs[idx].name)) {
			ddef = &builtin_defs[idx];
			break;
		}
	}
	if (!ddef)
		goto done;

	if ((error = diff_driver_alloc(&drv, NULL, ddef->name)) < 0)
		goto done;

	drv->type = DIFF_DRIVER_PATTERNLIST;

	if (ddef->fns &&
		(error = diff_driver_add_patterns(
			drv, ddef->fns, ddef->flags)) < 0)
		goto done;

	if (ddef->words &&
	    (error = git3_regexp_compile(&drv->word_pattern, ddef->words, ddef->flags)) < 0)
		goto done;

	if ((error = git3_diff_driver_map_put(&reg->map, drv->name, drv)) < 0)
		goto done;

done:
	if (error && drv)
		git3_diff_driver_free(drv);
	else
		*out = drv;

	return error;
}

static int git3_diff_driver_load(
	git3_diff_driver **out, git3_repository *repo, const char *driver_name)
{
	int error = 0;
	git3_diff_driver_registry *reg;
	git3_diff_driver *drv;
	size_t namelen;
	git3_config *cfg = NULL;
	git3_str name = GIT3_STR_INIT;
	git3_config_entry *ce = NULL;
	bool found_driver = false;

	if ((reg = git3_repository_driver_registry(repo)) == NULL)
		return -1;

	if (git3_diff_driver_map_get(&drv, &reg->map, driver_name) == 0) {
		*out = drv;
		return 0;
	}

	if ((error = diff_driver_alloc(&drv, &namelen, driver_name)) < 0)
		goto done;

	drv->type = DIFF_DRIVER_AUTO;

	/* if you can't read config for repo, just use default driver */
	if (git3_repository_config_snapshot(&cfg, repo) < 0) {
		git3_error_clear();
		goto done;
	}

	if ((error = git3_str_printf(&name, "diff.%s.binary", driver_name)) < 0)
		goto done;

	switch (git3_config__get_bool_force(cfg, name.ptr, -1)) {
	case true:
		/* if diff.<driver>.binary is true, just return the binary driver */
		*out = &diff_driver_binary;
		goto done;
	case false:
		/* if diff.<driver>.binary is false, force binary checks off */
		/* but still may have custom function context patterns, etc. */
		drv->binary_flags = GIT3_DIFF_FORCE_TEXT;
		found_driver = true;
		break;
	default:
		/* diff.<driver>.binary unspecified or "auto", so just continue */
		break;
	}

	/* TODO: warn if diff.<name>.command or diff.<name>.textconv are set */

	git3_str_truncate(&name, namelen + strlen("diff.."));
	if ((error = git3_str_PUTS(&name, "xfuncname")) < 0)
		goto done;

	if ((error = git3_config_get_multivar_foreach(
			cfg, name.ptr, NULL, diff_driver_xfuncname, drv)) < 0) {
		if (error != GIT3_ENOTFOUND)
			goto done;
		git3_error_clear(); /* no diff.<driver>.xfuncname, so just continue */
	}

	git3_str_truncate(&name, namelen + strlen("diff.."));
	if ((error = git3_str_PUTS(&name, "funcname")) < 0)
		goto done;

	if ((error = git3_config_get_multivar_foreach(
			cfg, name.ptr, NULL, diff_driver_funcname, drv)) < 0) {
		if (error != GIT3_ENOTFOUND)
			goto done;
		git3_error_clear(); /* no diff.<driver>.funcname, so just continue */
	}

	/* if we found any patterns, set driver type to use correct callback */
	if (git3_array_size(drv->fn_patterns) > 0) {
		drv->type = DIFF_DRIVER_PATTERNLIST;
		found_driver = true;
	}

	git3_str_truncate(&name, namelen + strlen("diff.."));
	if ((error = git3_str_PUTS(&name, "wordregex")) < 0)
		goto done;

	if ((error = git3_config__lookup_entry(&ce, cfg, name.ptr, false)) < 0)
		goto done;
	if (!ce || !ce->value)
		/* no diff.<driver>.wordregex, so just continue */;
	else if (!(error = git3_regexp_compile(&drv->word_pattern, ce->value, 0)))
		found_driver = true;
	else {
		/* TODO: warn about bad regex instead of failure */
		goto done;
	}

	/* TODO: look up diff.<driver>.algorithm to turn on minimal / patience
	 * diff in drv->other_flags
	 */

	/* if no driver config found at all, fall back on AUTO driver */
	if (!found_driver)
		goto done;

	/* store driver in registry */
	if ((error = git3_diff_driver_map_put(&reg->map, drv->name, drv)) < 0)
		goto done;

	*out = drv;

done:
	git3_config_entry_free(ce);
	git3_str_dispose(&name);
	git3_config_free(cfg);

	if (!*out) {
		int error2 = git3_diff_driver_builtin(out, reg, driver_name);
		if (!error)
			error = error2;
	}

	if (drv && drv != *out)
		git3_diff_driver_free(drv);

	return error;
}

int git3_diff_driver_lookup(
	git3_diff_driver **out, git3_repository *repo,
	git3_attr_session *attrsession, const char *path)
{
	int error = 0;
	const char *values[1], *attrs[] = { "diff" };

	GIT3_ASSERT_ARG(out);
	*out = NULL;

	if (!repo || !path || !strlen(path))
		/* just use the auto value */;
	else if ((error = git3_attr_get_many_with_session(values, repo,
			attrsession, 0, path, 1, attrs)) < 0)
		/* return error below */;

	else if (GIT3_ATTR_IS_UNSPECIFIED(values[0]))
		/* just use the auto value */;
	else if (GIT3_ATTR_IS_FALSE(values[0]))
		*out = &diff_driver_binary;
	else if (GIT3_ATTR_IS_TRUE(values[0]))
		*out = &diff_driver_text;

	/* otherwise look for driver information in config and build driver */
	else if ((error = git3_diff_driver_load(out, repo, values[0])) < 0) {
		if (error == GIT3_ENOTFOUND) {
			error = 0;
			git3_error_clear();
		}
	}

	if (!*out)
		*out = &diff_driver_auto;

	return error;
}

void git3_diff_driver_free(git3_diff_driver *driver)
{
	git3_diff_driver_pattern *pat;

	if (!driver)
		return;

	while ((pat = git3_array_pop(driver->fn_patterns)) != NULL)
		git3_regexp_dispose(&pat->re);
	git3_array_clear(driver->fn_patterns);

	git3_regexp_dispose(&driver->word_pattern);

	git3__free(driver);
}

void git3_diff_driver_update_options(
	uint32_t *option_flags, git3_diff_driver *driver)
{
	if ((*option_flags & FORCE_DIFFABLE) == 0)
		*option_flags |= driver->binary_flags;

	*option_flags |= driver->other_flags;
}

int git3_diff_driver_content_is_binary(
	git3_diff_driver *driver, const char *content, size_t content_len)
{
	git3_str search = GIT3_STR_INIT;

	GIT3_UNUSED(driver);

	git3_str_attach_notowned(&search, content,
		min(content_len, GIT3_FILTER_BYTES_TO_CHECK_NUL));

	/* TODO: provide encoding / binary detection callbacks that can
	 * be UTF-8 aware, etc.  For now, instead of trying to be smart,
	 * let's just use the simple NUL-byte detection that core git uses.
	 */

	/* previously was: if (git3_str_is_binary(&search)) */
	if (git3_str_contains_nul(&search))
		return 1;

	return 0;
}

static int diff_context_line__simple(
	git3_diff_driver *driver, git3_str *line)
{
	char firstch = line->ptr[0];
	GIT3_UNUSED(driver);
	return (git3__isalpha(firstch) || firstch == '_' || firstch == '$');
}

static int diff_context_line__pattern_match(
	git3_diff_driver *driver, git3_str *line)
{
	size_t i, maxi = git3_array_size(driver->fn_patterns);
	git3_regmatch pmatch[2];

	for (i = 0; i < maxi; ++i) {
		git3_diff_driver_pattern *pat = git3_array_get(driver->fn_patterns, i);

		if (!git3_regexp_search(&pat->re, line->ptr, 2, pmatch)) {
			if (pat->flags & REG_NEGATE)
				return false;

			/* use pmatch data to trim line data */
			i = (pmatch[1].start >= 0) ? 1 : 0;
			git3_str_consume(line, git3_str_cstr(line) + pmatch[i].start);
			git3_str_truncate(line, pmatch[i].end - pmatch[i].start);
			git3_str_rtrim(line);

			return true;
		}
	}

	return false;
}

static long diff_context_find(
	const char *line,
	long line_len,
	char *out,
	long out_size,
	void *payload)
{
	git3_diff_find_context_payload *ctxt = payload;

	if (git3_str_set(&ctxt->line, line, (size_t)line_len) < 0)
		return -1;
	git3_str_rtrim(&ctxt->line);

	if (!ctxt->line.size)
		return -1;

	if (!ctxt->match_line || !ctxt->match_line(ctxt->driver, &ctxt->line))
		return -1;

	if (out_size > (long)ctxt->line.size)
		out_size = (long)ctxt->line.size;
	memcpy(out, ctxt->line.ptr, (size_t)out_size);

	return out_size;
}

void git3_diff_find_context_init(
	git3_diff_find_context_fn *findfn_out,
	git3_diff_find_context_payload *payload_out,
	git3_diff_driver *driver)
{
	*findfn_out = driver ? diff_context_find : NULL;

	memset(payload_out, 0, sizeof(*payload_out));
	if (driver) {
		payload_out->driver = driver;
		payload_out->match_line = (driver->type == DIFF_DRIVER_PATTERNLIST) ?
			diff_context_line__pattern_match : diff_context_line__simple;
		git3_str_init(&payload_out->line, 0);
	}
}

void git3_diff_find_context_clear(git3_diff_find_context_payload *payload)
{
	if (payload) {
		git3_str_dispose(&payload->line);
		payload->driver = NULL;
	}
}
