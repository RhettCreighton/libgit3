/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "common.h"

#include "futils.h"
#include "repository.h"
#include "config.h"
#include "git3/config.h"
#include "vector.h"
#include "filter.h"

struct map_data {
	const char *name;
	git3_configmap *maps;
	size_t map_count;
	int default_value;
};

/*
 *	core.eol
 *		Sets the line ending type to use in the working directory for
 *	files that have the text property set. Alternatives are lf, crlf
 *	and native, which uses the platform's native line ending. The default
 *	value is native. See gitattributes(5) for more information on
 *	end-of-line conversion.
 */
static git3_configmap _configmap_eol[] = {
	{GIT3_CONFIGMAP_FALSE, NULL, GIT3_EOL_UNSET},
	{GIT3_CONFIGMAP_STRING, "lf", GIT3_EOL_LF},
	{GIT3_CONFIGMAP_STRING, "crlf", GIT3_EOL_CRLF},
	{GIT3_CONFIGMAP_STRING, "native", GIT3_EOL_NATIVE}
};

/*
 *	core.autocrlf
 *		Setting this variable to "true" is almost the same as setting
 *	the text attribute to "auto" on all files except that text files are
 *	not guaranteed to be normalized: files that contain CRLF in the
 *	repository will not be touched. Use this setting if you want to have
 *	CRLF line endings in your working directory even though the repository
 *	does not have normalized line endings. This variable can be set to input,
 *	in which case no output conversion is performed.
 */
static git3_configmap _configmap_autocrlf[] = {
	{GIT3_CONFIGMAP_FALSE, NULL, GIT3_AUTO_CRLF_FALSE},
	{GIT3_CONFIGMAP_TRUE, NULL, GIT3_AUTO_CRLF_TRUE},
	{GIT3_CONFIGMAP_STRING, "input", GIT3_AUTO_CRLF_INPUT}
};

static git3_configmap _configmap_safecrlf[] = {
	{GIT3_CONFIGMAP_FALSE, NULL, GIT3_SAFE_CRLF_FALSE},
	{GIT3_CONFIGMAP_TRUE, NULL, GIT3_SAFE_CRLF_FAIL},
	{GIT3_CONFIGMAP_STRING, "warn", GIT3_SAFE_CRLF_WARN}
};

static git3_configmap _configmap_logallrefupdates[] = {
	{GIT3_CONFIGMAP_FALSE, NULL, GIT3_LOGALLREFUPDATES_FALSE},
	{GIT3_CONFIGMAP_TRUE, NULL, GIT3_LOGALLREFUPDATES_TRUE},
	{GIT3_CONFIGMAP_STRING, "always", GIT3_LOGALLREFUPDATES_ALWAYS},
};

static git3_configmap _configmap_abbrev[] = {
	{GIT3_CONFIGMAP_INT32, NULL, 0},
	{GIT3_CONFIGMAP_FALSE, NULL, GIT3_ABBREV_FALSE},
	{GIT3_CONFIGMAP_STRING, "auto", GIT3_ABBREV_DEFAULT}
};

static struct map_data _configmaps[] = {
	{"core.autocrlf", _configmap_autocrlf, ARRAY_SIZE(_configmap_autocrlf), GIT3_AUTO_CRLF_DEFAULT},
	{"core.eol", _configmap_eol, ARRAY_SIZE(_configmap_eol), GIT3_EOL_DEFAULT},
	{"core.symlinks", NULL, 0, GIT3_SYMLINKS_DEFAULT },
	{"core.ignorecase", NULL, 0, GIT3_IGNORECASE_DEFAULT },
	{"core.filemode", NULL, 0, GIT3_FILEMODE_DEFAULT },
	{"core.ignorestat", NULL, 0, GIT3_IGNORESTAT_DEFAULT },
	{"core.trustctime", NULL, 0, GIT3_TRUSTCTIME_DEFAULT },
	{"core.abbrev", _configmap_abbrev, ARRAY_SIZE(_configmap_abbrev), GIT3_ABBREV_DEFAULT },
	{"core.precomposeunicode", NULL, 0, GIT3_PRECOMPOSE_DEFAULT },
	{"core.safecrlf", _configmap_safecrlf, ARRAY_SIZE(_configmap_safecrlf), GIT3_SAFE_CRLF_DEFAULT},
	{"core.logallrefupdates", _configmap_logallrefupdates, ARRAY_SIZE(_configmap_logallrefupdates), GIT3_LOGALLREFUPDATES_DEFAULT},
	{"core.protecthfs", NULL, 0, GIT3_PROTECTHFS_DEFAULT },
	{"core.protectntfs", NULL, 0, GIT3_PROTECTNTFS_DEFAULT },
	{"core.fsyncobjectfiles", NULL, 0, GIT3_FSYNCOBJECTFILES_DEFAULT },
	{"core.longpaths", NULL, 0, GIT3_LONGPATHS_DEFAULT },
};

int git3_config__configmap_lookup(int *out, git3_config *config, git3_configmap_item item)
{
	int error = 0;
	struct map_data *data = &_configmaps[(int)item];
	git3_config_entry *entry;

	if ((error = git3_config__lookup_entry(&entry, config, data->name, false)) < 0)
		return error;

	if (!entry)
		*out = data->default_value;
	else if (data->maps)
		error = git3_config_lookup_map_value(
			out, data->maps, data->map_count, entry->value);
	else
		error = git3_config_parse_bool(out, entry->value);

	git3_config_entry_free(entry);
	return error;
}

int git3_repository__configmap_lookup(int *out, git3_repository *repo, git3_configmap_item item)
{
	intptr_t value = (intptr_t)git3_atomic_load(repo->configmap_cache[(int)item]);

	*out = (int)value;

	if (value == GIT3_CONFIGMAP_NOT_CACHED) {
		git3_config *config;
		intptr_t oldval = value;
		int error;

		if ((error = git3_repository_config__weakptr(&config, repo)) < 0 ||
			(error = git3_config__configmap_lookup(out, config, item)) < 0)
			return error;

		value = *out;
		git3_atomic_compare_and_swap(&repo->configmap_cache[(int)item], (void *)oldval, (void *)value);
	}

	return 0;
}

void git3_repository__configmap_lookup_cache_clear(git3_repository *repo)
{
	int i;

	for (i = 0; i < GIT3_CONFIGMAP_CACHE_MAX; ++i)
		repo->configmap_cache[i] = GIT3_CONFIGMAP_NOT_CACHED;
}

