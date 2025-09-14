/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "config.h"

#include "git3/config.h"
#include "git3/sys/config.h"

#include "array.h"
#include "str.h"
#include "config_backend.h"
#include "config_list.h"
#include "config_parse.h"
#include "filebuf.h"
#include "regexp.h"
#include "sysdir.h"
#include "wildmatch.h"
#include "hash.h"

/* Max depth for [include] directives */
#define MAX_INCLUDE_DEPTH 10

#define CONFIG_FILE_TYPE "file"

typedef struct config_file {
	git3_futils_filestamp stamp;
	unsigned char checksum[GIT3_HASH_SHA256_SIZE];
	char *path;
	git3_array_t(struct config_file) includes;
} config_file;

typedef struct {
	git3_config_backend parent;
	git3_mutex values_mutex;
	git3_config_list *config_list;
	const git3_repository *repo;
	git3_config_level_t level;

	git3_array_t(git3_config_parser) readers;

	bool locked;
	git3_filebuf locked_buf;
	git3_str locked_content;

	config_file file;
} config_file_backend;

typedef struct {
	const git3_repository *repo;
	config_file *file;
	git3_config_list *config_list;
	git3_config_level_t level;
	unsigned int depth;
} config_file_parse_data;

static int config_file_read(git3_config_list *config_list, const git3_repository *repo, config_file *file, git3_config_level_t level, int depth);
static int config_file_read_buffer(git3_config_list *config_list, const git3_repository *repo, config_file *file, git3_config_level_t level, int depth, const char *buf, size_t buflen);
static int config_file_write(config_file_backend *cfg, const char *orig_key, const char *key, const git3_regexp *preg, const char *value);
static char *escape_value(const char *ptr);

/**
 * Take the current values map from the backend and increase its
 * refcount. This is its own function to make sure we use the mutex to
 * avoid the map pointer from changing under us.
 */
static int config_file_take_list(git3_config_list **out, config_file_backend *b)
{
	int error;

	if ((error = git3_mutex_lock(&b->values_mutex)) < 0) {
		git3_error_set(GIT3_ERROR_OS, "failed to lock config backend");
		return error;
	}

	git3_config_list_incref(b->config_list);
	*out = b->config_list;

	git3_mutex_unlock(&b->values_mutex);

	return 0;
}

static void config_file_clear(config_file *file)
{
	config_file *include;
	uint32_t i;

	if (file == NULL)
		return;

	git3_array_foreach(file->includes, i, include) {
		config_file_clear(include);
	}
	git3_array_clear(file->includes);

	git3__free(file->path);
}

static int config_file_open(git3_config_backend *cfg, git3_config_level_t level, const git3_repository *repo)
{
	config_file_backend *b = GIT3_CONTAINER_OF(cfg, config_file_backend, parent);
	int res;

	b->level = level;
	b->repo = repo;

	if ((res = git3_config_list_new(&b->config_list)) < 0)
		return res;

	if (!git3_fs_path_exists(b->file.path))
		return 0;

	/*
	 * git silently ignores configuration files that are not
	 * readable.  We emulate that behavior.  This is particularly
	 * important for sandboxed applications on macOS where the
	 * git configuration files may not be readable.
	 */
	if (p_access(b->file.path, R_OK) < 0)
		return GIT3_ENOTFOUND;

	if (res < 0 || (res = config_file_read(b->config_list, repo, &b->file, level, 0)) < 0) {
		git3_config_list_free(b->config_list);
		b->config_list = NULL;
	}

	return res;
}

static int config_file_is_modified(int *modified, config_file *file)
{
	config_file *include;
	git3_str buf = GIT3_STR_INIT;
	unsigned char checksum[GIT3_HASH_SHA256_SIZE];
	uint32_t i;
	int error = 0;

	*modified = 0;

	if (!git3_futils_filestamp_check(&file->stamp, file->path))
		goto check_includes;

	if ((error = git3_futils_readbuffer(&buf, file->path)) < 0)
		goto out;

	if ((error = git3_hash_buf(checksum, buf.ptr, buf.size, GIT3_HASH_ALGORITHM_SHA256)) < 0)
		goto out;

	if (memcmp(checksum, file->checksum, GIT3_HASH_SHA256_SIZE) != 0) {
		*modified = 1;
		goto out;
	}

check_includes:
	git3_array_foreach(file->includes, i, include) {
		if ((error = config_file_is_modified(modified, include)) < 0 || *modified)
			goto out;
	}

out:
	git3_str_dispose(&buf);

	return error;
}

static void config_file_clear_includes(config_file_backend *cfg)
{
	config_file *include;
	uint32_t i;

	git3_array_foreach(cfg->file.includes, i, include)
		config_file_clear(include);
	git3_array_clear(cfg->file.includes);
}

static int config_file_set_entries(git3_config_backend *cfg, git3_config_list *config_list)
{
	config_file_backend *b = GIT3_CONTAINER_OF(cfg, config_file_backend, parent);
	git3_config_list *old = NULL;
	int error;

	if (b->parent.readonly) {
		git3_error_set(GIT3_ERROR_CONFIG, "this backend is read-only");
		return -1;
	}

	if ((error = git3_mutex_lock(&b->values_mutex)) < 0) {
		git3_error_set(GIT3_ERROR_OS, "failed to lock config backend");
		goto out;
	}

	old = b->config_list;
	b->config_list = config_list;

	git3_mutex_unlock(&b->values_mutex);

out:
	git3_config_list_free(old);
	return error;
}

static int config_file_refresh_from_buffer(git3_config_backend *cfg, const char *buf, size_t buflen)
{
	config_file_backend *b = GIT3_CONTAINER_OF(cfg, config_file_backend, parent);
	git3_config_list *config_list = NULL;
	int error;

	config_file_clear_includes(b);

	if ((error = git3_config_list_new(&config_list)) < 0 ||
	    (error = config_file_read_buffer(config_list, b->repo, &b->file,
					     b->level, 0, buf, buflen)) < 0 ||
	    (error = config_file_set_entries(cfg, config_list)) < 0)
		goto out;

	config_list = NULL;
out:
	git3_config_list_free(config_list);
	return error;
}

static int config_file_refresh(git3_config_backend *cfg)
{
	config_file_backend *b = GIT3_CONTAINER_OF(cfg, config_file_backend, parent);
	git3_config_list *config_list = NULL;
	int error, modified;

	if (cfg->readonly)
		return 0;

	if ((error = config_file_is_modified(&modified, &b->file)) < 0 && error != GIT3_ENOTFOUND)
		goto out;

	if (!modified)
		return 0;

	config_file_clear_includes(b);

	if ((error = git3_config_list_new(&config_list)) < 0 ||
	    (error = config_file_read(config_list, b->repo, &b->file, b->level, 0)) < 0 ||
	    (error = config_file_set_entries(cfg, config_list)) < 0)
		goto out;

	config_list = NULL;
out:
	git3_config_list_free(config_list);

	return (error == GIT3_ENOTFOUND) ? 0 : error;
}

static void config_file_free(git3_config_backend *_backend)
{
	config_file_backend *backend = GIT3_CONTAINER_OF(_backend, config_file_backend, parent);

	if (backend == NULL)
		return;

	config_file_clear(&backend->file);
	git3_config_list_free(backend->config_list);
	git3_mutex_free(&backend->values_mutex);
	git3__free(backend);
}

static int config_file_iterator(
	git3_config_iterator **iter,
	struct git3_config_backend *backend)
{
	config_file_backend *b = GIT3_CONTAINER_OF(backend, config_file_backend, parent);
	git3_config_list *dupped = NULL, *config_list = NULL;
	int error;

	if ((error = config_file_refresh(backend)) < 0 ||
	    (error = config_file_take_list(&config_list, b)) < 0 ||
	    (error = git3_config_list_dup(&dupped, config_list)) < 0 ||
	    (error = git3_config_list_iterator_new(iter, dupped)) < 0)
		goto out;

out:
	/* Let iterator delete duplicated config_list when it's done */
	git3_config_list_free(config_list);
	git3_config_list_free(dupped);
	return error;
}

static int config_file_snapshot(git3_config_backend **out, git3_config_backend *backend)
{
	return git3_config_backend_snapshot(out, backend);
}

static int config_file_set(git3_config_backend *cfg, const char *name, const char *value)
{
	config_file_backend *b = GIT3_CONTAINER_OF(cfg, config_file_backend, parent);
	git3_config_list *config_list;
	git3_config_list_entry *existing;
	char *key, *esc_value = NULL;
	int error;

	if ((error = git3_config__normalize_name(name, &key)) < 0)
		return error;

	if ((error = config_file_take_list(&config_list, b)) < 0)
		return error;

	/* Check whether we'd be modifying an included or multivar key */
	if ((error = git3_config_list_get_unique(&existing, config_list, key)) < 0) {
		if (error != GIT3_ENOTFOUND)
			goto out;
		error = 0;
	} else if ((!existing->base.entry.value && !value) ||
		   (existing->base.entry.value && value && !strcmp(existing->base.entry.value, value))) {
		/* don't update if old and new values already match */
		error = 0;
		goto out;
	}

	/* No early returns due to sanity checks, let's write it out and refresh */
	if (value) {
		esc_value = escape_value(value);
		GIT3_ERROR_CHECK_ALLOC(esc_value);
	}

	if ((error = config_file_write(b, name, key, NULL, esc_value)) < 0)
		goto out;

out:
	git3_config_list_free(config_list);
	git3__free(esc_value);
	git3__free(key);
	return error;
}

/*
 * Internal function that actually gets the value in string form
 */
static int config_file_get(
	git3_config_backend *cfg,
	const char *key,
	git3_config_backend_entry **out)
{
	config_file_backend *h = GIT3_CONTAINER_OF(cfg, config_file_backend, parent);
	git3_config_list *config_list = NULL;
	git3_config_list_entry *entry;
	int error = 0;

	if (!h->parent.readonly && ((error = config_file_refresh(cfg)) < 0))
		return error;

	if ((error = config_file_take_list(&config_list, h)) < 0)
		return error;

	if ((error = (git3_config_list_get(&entry, config_list, key))) < 0) {
		git3_config_list_free(config_list);
		return error;
	}

	*out = &entry->base;

	return 0;
}

static int config_file_set_multivar(
	git3_config_backend *cfg, const char *name, const char *regexp, const char *value)
{
	config_file_backend *b = GIT3_CONTAINER_OF(cfg, config_file_backend, parent);
	git3_regexp preg;
	int result;
	char *key;

	GIT3_ASSERT_ARG(regexp);

	if ((result = git3_config__normalize_name(name, &key)) < 0)
		return result;

	if ((result = git3_regexp_compile(&preg, regexp, 0)) < 0)
		goto out;

	/* If we do have it, set call config_file_write() and reload */
	if ((result = config_file_write(b, name, key, &preg, value)) < 0)
		goto out;

out:
	git3__free(key);
	git3_regexp_dispose(&preg);

	return result;
}

static int config_file_delete(git3_config_backend *cfg, const char *name)
{
	config_file_backend *b = GIT3_CONTAINER_OF(cfg, config_file_backend, parent);
	git3_config_list *config_list = NULL;
	git3_config_list_entry *entry;
	char *key = NULL;
	int error;

	if ((error = git3_config__normalize_name(name, &key)) < 0)
		goto out;

	if ((error = config_file_take_list(&config_list, b)) < 0)
		goto out;

	/* Check whether we'd be modifying an included or multivar key */
	if ((error = git3_config_list_get_unique(&entry, config_list, key)) < 0) {
		if (error == GIT3_ENOTFOUND)
			git3_error_set(GIT3_ERROR_CONFIG, "could not find key '%s' to delete", name);
		goto out;
	}

	if ((error = config_file_write(b, name, entry->base.entry.name, NULL, NULL)) < 0)
		goto out;

out:
	git3_config_list_free(config_list);
	git3__free(key);
	return error;
}

static int config_file_delete_multivar(git3_config_backend *cfg, const char *name, const char *regexp)
{
	config_file_backend *b = GIT3_CONTAINER_OF(cfg, config_file_backend, parent);
	git3_config_list *config_list = NULL;
	git3_config_list_entry *entry = NULL;
	git3_regexp preg = GIT3_REGEX_INIT;
	char *key = NULL;
	int result;

	if ((result = git3_config__normalize_name(name, &key)) < 0)
		goto out;

	if ((result = config_file_take_list(&config_list, b)) < 0)
		goto out;

	if ((result = git3_config_list_get(&entry, config_list, key)) < 0) {
		if (result == GIT3_ENOTFOUND)
			git3_error_set(GIT3_ERROR_CONFIG, "could not find key '%s' to delete", name);
		goto out;
	}

	if ((result = git3_regexp_compile(&preg, regexp, 0)) < 0)
		goto out;

	if ((result = config_file_write(b, name, key, &preg, NULL)) < 0)
		goto out;

out:
	git3_config_list_free(config_list);
	git3__free(key);
	git3_regexp_dispose(&preg);
	return result;
}

static int config_file_lock(git3_config_backend *_cfg)
{
	config_file_backend *cfg = GIT3_CONTAINER_OF(_cfg, config_file_backend, parent);
	int error;

	if ((error = git3_filebuf_open(&cfg->locked_buf, cfg->file.path, 0, GIT3_CONFIG_FILE_MODE)) < 0)
		return error;

	error = git3_futils_readbuffer(&cfg->locked_content, cfg->file.path);
	if (error < 0 && error != GIT3_ENOTFOUND) {
		git3_filebuf_cleanup(&cfg->locked_buf);
		return error;
	}

	cfg->locked = true;
	return 0;

}

static int config_file_unlock(git3_config_backend *_cfg, int success)
{
	config_file_backend *cfg = GIT3_CONTAINER_OF(_cfg, config_file_backend, parent);
	int error = 0;

	if (success) {
		git3_filebuf_write(&cfg->locked_buf, cfg->locked_content.ptr, cfg->locked_content.size);
		error = git3_filebuf_commit(&cfg->locked_buf);
	}

	git3_filebuf_cleanup(&cfg->locked_buf);
	git3_str_dispose(&cfg->locked_content);
	cfg->locked = false;

	return error;
}

int git3_config_backend_from_file(git3_config_backend **out, const char *path)
{
	config_file_backend *backend;

	backend = git3__calloc(1, sizeof(config_file_backend));
	GIT3_ERROR_CHECK_ALLOC(backend);

	backend->parent.version = GIT3_CONFIG_BACKEND_VERSION;
	git3_mutex_init(&backend->values_mutex);

	backend->file.path = git3__strdup(path);
	GIT3_ERROR_CHECK_ALLOC(backend->file.path);
	git3_array_init(backend->file.includes);

	backend->parent.open = config_file_open;
	backend->parent.get = config_file_get;
	backend->parent.set = config_file_set;
	backend->parent.set_multivar = config_file_set_multivar;
	backend->parent.del = config_file_delete;
	backend->parent.del_multivar = config_file_delete_multivar;
	backend->parent.iterator = config_file_iterator;
	backend->parent.snapshot = config_file_snapshot;
	backend->parent.lock = config_file_lock;
	backend->parent.unlock = config_file_unlock;
	backend->parent.free = config_file_free;

	*out = (git3_config_backend *)backend;

	return 0;
}

static int included_path(git3_str *out, const char *dir, const char *path)
{
	/* From the user's home */
	if (path[0] == '~' && path[1] == '/')
		return git3_sysdir_expand_homedir_file(out, &path[1]);

	return git3_fs_path_join_unrooted(out, path, dir, NULL);
}

/* Escape the values to write them to the file */
static char *escape_value(const char *ptr)
{
	git3_str buf;
	size_t len;
	const char *esc;

	GIT3_ASSERT_ARG_WITH_RETVAL(ptr, NULL);

	len = strlen(ptr);
	if (!len)
		return git3__calloc(1, sizeof(char));

	if (git3_str_init(&buf, len) < 0)
		return NULL;

	while (*ptr != '\0') {
		if ((esc = strchr(git3_config_escaped, *ptr)) != NULL) {
			git3_str_putc(&buf, '\\');
			git3_str_putc(&buf, git3_config_escapes[esc - git3_config_escaped]);
		} else {
			git3_str_putc(&buf, *ptr);
		}
		ptr++;
	}

	if (git3_str_oom(&buf))
		return NULL;

	return git3_str_detach(&buf);
}

static int parse_include(config_file_parse_data *parse_data, const char *file)
{
	config_file *include;
	git3_str path = GIT3_STR_INIT;
	char *dir;
	int result;

	if (!file)
		return 0;

	if ((result = git3_fs_path_dirname_r(&path, parse_data->file->path)) < 0)
		return result;

	dir = git3_str_detach(&path);
	result = included_path(&path, dir, file);
	git3__free(dir);

	if (result < 0)
		return result;

	include = git3_array_alloc(parse_data->file->includes);
	GIT3_ERROR_CHECK_ALLOC(include);
	memset(include, 0, sizeof(*include));
	git3_array_init(include->includes);
	include->path = git3_str_detach(&path);

	result = config_file_read(parse_data->config_list, parse_data->repo, include,
				  parse_data->level, parse_data->depth+1);

	if (result == GIT3_ENOTFOUND) {
		git3_error_clear();
		result = 0;
	}

	return result;
}

static int do_match_gitdir(
	int *matches,
	const git3_repository *repo,
	const char *cfg_file,
	const char *condition,
	bool case_insensitive)
{
	git3_str pattern = GIT3_STR_INIT, gitdir = GIT3_STR_INIT;
	int error;

	if (condition[0] == '.' && git3_fs_path_is_dirsep(condition[1])) {
		git3_fs_path_dirname_r(&pattern, cfg_file);
		git3_str_joinpath(&pattern, pattern.ptr, condition + 2);
	} else if (condition[0] == '~' && git3_fs_path_is_dirsep(condition[1]))
		git3_sysdir_expand_homedir_file(&pattern, condition + 1);
	else if (!git3_fs_path_is_absolute(condition))
		git3_str_joinpath(&pattern, "**", condition);
	else
		git3_str_sets(&pattern, condition);

	if (git3_fs_path_is_dirsep(condition[strlen(condition) - 1]))
		git3_str_puts(&pattern, "**");

	if (git3_str_oom(&pattern)) {
		error = -1;
		goto out;
	}

	if ((error = git3_repository__item_path(&gitdir, repo, GIT3_REPOSITORY_ITEM_GITDIR)) < 0)
		goto out;

	if (git3_fs_path_is_dirsep(gitdir.ptr[gitdir.size - 1]))
		git3_str_truncate(&gitdir, gitdir.size - 1);

	*matches = wildmatch(pattern.ptr, gitdir.ptr,
			     WM_PATHNAME | (case_insensitive ? WM_CASEFOLD : 0)) == WM_MATCH;
out:
	git3_str_dispose(&pattern);
	git3_str_dispose(&gitdir);
	return error;
}

static int conditional_match_gitdir(
	int *matches,
	const git3_repository *repo,
	const char *cfg_file,
	const char *value)
{
	return do_match_gitdir(matches, repo, cfg_file, value, false);
}

static int conditional_match_gitdir_i(
	int *matches,
	const git3_repository *repo,
	const char *cfg_file,
	const char *value)
{
	return do_match_gitdir(matches, repo, cfg_file, value, true);
}

static int conditional_match_onbranch(
	int *matches,
	const git3_repository *repo,
	const char *cfg_file,
	const char *condition)
{
	git3_str reference = GIT3_STR_INIT, buf = GIT3_STR_INIT;
	int error;

	GIT3_UNUSED(cfg_file);

	/*
	 * NOTE: you cannot use `git3_repository_head` here. Looking up the
	 * HEAD reference will create the ODB, which causes us to read the
	 * repo's config for keys like core.precomposeUnicode. As we're
	 * just parsing the config right now, though, this would result in
	 * an endless recursion.
	 */

	if ((error = git3_str_joinpath(&buf, git3_repository_path(repo), GIT3_HEAD_FILE)) < 0 ||
	    (error = git3_futils_readbuffer(&reference, buf.ptr)) < 0)
		goto out;
	git3_str_rtrim(&reference);

	if (git3__strncmp(reference.ptr, GIT3_SYMREF, strlen(GIT3_SYMREF)))
		goto out;
	git3_str_consume(&reference, reference.ptr + strlen(GIT3_SYMREF));

	if (git3__strncmp(reference.ptr, GIT3_REFS_HEADS_DIR, strlen(GIT3_REFS_HEADS_DIR)))
		goto out;
	git3_str_consume(&reference, reference.ptr + strlen(GIT3_REFS_HEADS_DIR));

	/*
	 * If the condition ends with a '/', then we should treat it as if
	 * it had '**' appended.
	 */
	if ((error = git3_str_sets(&buf, condition)) < 0)
		goto out;
	if (git3_fs_path_is_dirsep(condition[strlen(condition) - 1]) &&
	    (error = git3_str_puts(&buf, "**")) < 0)
		goto out;

	*matches = wildmatch(buf.ptr, reference.ptr, WM_PATHNAME) == WM_MATCH;
out:
	git3_str_dispose(&reference);
	git3_str_dispose(&buf);

	return error;

}

static const struct {
	const char *prefix;
	int (*matches)(int *matches, const git3_repository *repo, const char *cfg, const char *value);
} conditions[] = {
	{ "gitdir:", conditional_match_gitdir },
	{ "gitdir/i:", conditional_match_gitdir_i },
	{ "onbranch:", conditional_match_onbranch }
};

static int parse_conditional_include(config_file_parse_data *parse_data, const char *section, const char *file)
{
	char *condition;
	size_t section_len, i;
	int error = 0, matches;

	if (!parse_data->repo || !file)
		return 0;

	section_len = strlen(section);

	/*
	 * We checked that the string starts with `includeIf.` and ends
	 * in `.path` to get here.  Make sure it consists of more.
	 */
	if (section_len < CONST_STRLEN("includeIf.") + CONST_STRLEN(".path"))
		return 0;

	condition = git3__substrdup(section + CONST_STRLEN("includeIf."),
		section_len - CONST_STRLEN("includeIf.") - CONST_STRLEN(".path"));

	GIT3_ERROR_CHECK_ALLOC(condition);

	for (i = 0; i < ARRAY_SIZE(conditions); i++) {
		if (git3__prefixcmp(condition, conditions[i].prefix))
			continue;

		if ((error = conditions[i].matches(&matches,
						   parse_data->repo,
						   parse_data->file->path,
						   condition + strlen(conditions[i].prefix))) < 0)
			break;

		if (matches)
			error = parse_include(parse_data, file);

		break;
	}

	git3__free(condition);
	return error;
}

static int read_on_variable(
	git3_config_parser *reader,
	const char *current_section,
	const char *var_name,
	const char *var_value,
	const char *line,
	size_t line_len,
	void *data)
{
	config_file_parse_data *parse_data = (config_file_parse_data *)data;
	git3_str buf = GIT3_STR_INIT;
	git3_config_list_entry *entry;
	const char *c;
	int result = 0;

	GIT3_UNUSED(reader);
	GIT3_UNUSED(line);
	GIT3_UNUSED(line_len);

	if (current_section) {
		/* TODO: Once warnings lang, we should likely warn
		 * here. Git appears to warn in most cases if it sees
		 * un-namespaced config options.
		 */
		git3_str_puts(&buf, current_section);
		git3_str_putc(&buf, '.');
	}

	for (c = var_name; *c; c++)
		git3_str_putc(&buf, git3__tolower(*c));

	if (git3_str_oom(&buf))
		return -1;

	entry = git3__calloc(1, sizeof(git3_config_list_entry));
	GIT3_ERROR_CHECK_ALLOC(entry);

	entry->base.entry.name = git3_str_detach(&buf);
	GIT3_ERROR_CHECK_ALLOC(entry->base.entry.name);

	if (var_value) {
		entry->base.entry.value = git3__strdup(var_value);
		GIT3_ERROR_CHECK_ALLOC(entry->base.entry.value);
	}

	entry->base.entry.backend_type = git3_config_list_add_string(parse_data->config_list, CONFIG_FILE_TYPE);
	GIT3_ERROR_CHECK_ALLOC(entry->base.entry.backend_type);

	entry->base.entry.origin_path = git3_config_list_add_string(parse_data->config_list, parse_data->file->path);
	GIT3_ERROR_CHECK_ALLOC(entry->base.entry.origin_path);

	entry->base.entry.level = parse_data->level;
	entry->base.entry.include_depth = parse_data->depth;
	entry->base.free = git3_config_list_entry_free;
	entry->config_list = parse_data->config_list;

	if ((result = git3_config_list_append(parse_data->config_list, entry)) < 0)
		return result;

	result = 0;

	/* Add or append the new config option */
	if (!git3__strcmp(entry->base.entry.name, "include.path"))
		result = parse_include(parse_data, entry->base.entry.value);
	else if (!git3__prefixcmp(entry->base.entry.name, "includeif.") &&
	         !git3__suffixcmp(entry->base.entry.name, ".path"))
		result = parse_conditional_include(parse_data, entry->base.entry.name, entry->base.entry.value);

	return result;
}

static int config_file_read_buffer(
	git3_config_list *config_list,
	const git3_repository *repo,
	config_file *file,
	git3_config_level_t level,
	int depth,
	const char *buf,
	size_t buflen)
{
	config_file_parse_data parse_data;
	git3_config_parser reader;
	int error;

	if (depth >= MAX_INCLUDE_DEPTH) {
		git3_error_set(GIT3_ERROR_CONFIG, "maximum config include depth reached");
		return -1;
	}

	/* Initialize the reading position */
	reader.path = file->path;
	git3_parse_ctx_init(&reader.ctx, buf, buflen);

	/* If the file is empty, there's nothing for us to do */
	if (!reader.ctx.content || *reader.ctx.content == '\0') {
		error = 0;
		goto out;
	}

	parse_data.repo = repo;
	parse_data.file = file;
	parse_data.config_list = config_list;
	parse_data.level = level;
	parse_data.depth = depth;

	error = git3_config_parse(&reader, NULL, read_on_variable, NULL, NULL, &parse_data);

out:
	return error;
}

static int config_file_read(
	git3_config_list *config_list,
	const git3_repository *repo,
	config_file *file,
	git3_config_level_t level,
	int depth)
{
	git3_str contents = GIT3_STR_INIT;
	struct stat st;
	int error;

	if (p_stat(file->path, &st) < 0) {
		error = git3_fs_path_set_error(errno, file->path, "stat");
		goto out;
	}

	if ((error = git3_futils_readbuffer(&contents, file->path)) < 0)
		goto out;

	git3_futils_filestamp_set_from_stat(&file->stamp, &st);
	if ((error = git3_hash_buf(file->checksum, contents.ptr, contents.size, GIT3_HASH_ALGORITHM_SHA256)) < 0)
		goto out;

	if ((error = config_file_read_buffer(config_list, repo, file, level, depth,
					     contents.ptr, contents.size)) < 0)
		goto out;

out:
	git3_str_dispose(&contents);
	return error;
}

static int write_section(git3_str *fbuf, const char *key)
{
	int result;
	const char *dot;
	git3_str buf = GIT3_STR_INIT;

	/* All of this just for [section "subsection"] */
	dot = strchr(key, '.');
	git3_str_putc(&buf, '[');
	if (dot == NULL) {
		git3_str_puts(&buf, key);
	} else {
		char *escaped;
		git3_str_put(&buf, key, dot - key);
		escaped = escape_value(dot + 1);
		GIT3_ERROR_CHECK_ALLOC(escaped);
		git3_str_printf(&buf, " \"%s\"", escaped);
		git3__free(escaped);
	}
	git3_str_puts(&buf, "]\n");

	if (git3_str_oom(&buf))
		return -1;

	result = git3_str_put(fbuf, git3_str_cstr(&buf), buf.size);
	git3_str_dispose(&buf);

	return result;
}

static const char *quotes_for_value(const char *value)
{
	const char *ptr;

	if (value[0] == ' ' || value[0] == '\0')
		return "\"";

	for (ptr = value; *ptr; ++ptr) {
		if (*ptr == ';' || *ptr == '#')
			return "\"";
	}

	if (ptr[-1] == ' ')
		return "\"";

	return "";
}

struct write_data {
	git3_str *buf;
	git3_str buffered_comment;
	unsigned int in_section : 1,
		preg_replaced : 1;
	const char *orig_section;
	const char *section;
	const char *orig_name;
	const char *name;
	const git3_regexp *preg;
	const char *value;
};

static int write_line_to(git3_str *buf, const char *line, size_t line_len)
{
	int result = git3_str_put(buf, line, line_len);

	if (!result && line_len && line[line_len-1] != '\n')
		result = git3_str_printf(buf, "\n");

	return result;
}

static int write_line(struct write_data *write_data, const char *line, size_t line_len)
{
	return write_line_to(write_data->buf, line, line_len);
}

static int write_value(struct write_data *write_data)
{
	const char *q;
	int result;

	q = quotes_for_value(write_data->value);
	result = git3_str_printf(write_data->buf,
		"\t%s = %s%s%s\n", write_data->orig_name, q, write_data->value, q);

	/* If we are updating a single name/value, we're done.  Setting `value`
	 * to `NULL` will prevent us from trying to write it again later (in
	 * `write_on_section`) if we see the same section repeated.
	 */
	if (!write_data->preg)
		write_data->value = NULL;

	return result;
}

static int write_on_section(
	git3_config_parser *reader,
	const char *current_section,
	const char *line,
	size_t line_len,
	void *data)
{
	struct write_data *write_data = (struct write_data *)data;
	int result = 0;

	GIT3_UNUSED(reader);

	/* If we were previously in the correct section (but aren't anymore)
	 * and haven't written our value (for a simple name/value set, not
	 * a multivar), then append it to the end of the section before writing
	 * the new one.
	 */
	if (write_data->in_section && !write_data->preg && write_data->value)
		result = write_value(write_data);

	write_data->in_section = strcmp(current_section, write_data->section) == 0;

	/*
	 * If there were comments just before this section, dump them as well.
	 */
	if (!result) {
		result = git3_str_put(write_data->buf, write_data->buffered_comment.ptr, write_data->buffered_comment.size);
		git3_str_clear(&write_data->buffered_comment);
	}

	if (!result)
		result = write_line(write_data, line, line_len);

	return result;
}

static int write_on_variable(
	git3_config_parser *reader,
	const char *current_section,
	const char *var_name,
	const char *var_value,
	const char *line,
	size_t line_len,
	void *data)
{
	struct write_data *write_data = (struct write_data *)data;
	bool has_matched = false;
	int error;

	GIT3_UNUSED(reader);
	GIT3_UNUSED(current_section);

	/*
	 * If there were comments just before this variable, let's dump them as well.
	 */
	if ((error = git3_str_put(write_data->buf, write_data->buffered_comment.ptr, write_data->buffered_comment.size)) < 0)
		return error;

	git3_str_clear(&write_data->buffered_comment);

	/* See if we are to update this name/value pair; first examine name */
	if (write_data->in_section &&
		strcasecmp(write_data->name, var_name) == 0)
		has_matched = true;

	/* If we have a regex to match the value, see if it matches */
	if (has_matched && write_data->preg != NULL)
		has_matched = (git3_regexp_match(write_data->preg, var_value) == 0);

	/* If this isn't the name/value we're looking for, simply dump the
	 * existing data back out and continue on.
	 */
	if (!has_matched)
		return write_line(write_data, line, line_len);

	write_data->preg_replaced = 1;

	/* If value is NULL, we are deleting this value; write nothing. */
	if (!write_data->value)
		return 0;

	return write_value(write_data);
}

static int write_on_comment(git3_config_parser *reader, const char *line, size_t line_len, void *data)
{
	struct write_data *write_data;

	GIT3_UNUSED(reader);

	write_data = (struct write_data *)data;
	return write_line_to(&write_data->buffered_comment, line, line_len);
}

static int write_on_eof(
	git3_config_parser *reader, const char *current_section, void *data)
{
	struct write_data *write_data = (struct write_data *)data;
	int result = 0;

	GIT3_UNUSED(reader);

	/*
	 * If we've buffered comments when reaching EOF, make sure to dump them.
	 */
	if ((result = git3_str_put(write_data->buf, write_data->buffered_comment.ptr, write_data->buffered_comment.size)) < 0)
		return result;

	/* If we are at the EOF and have not written our value (again, for a
	 * simple name/value set, not a multivar) then we have never seen the
	 * section in question and should create a new section and write the
	 * value.
	 */
	if ((!write_data->preg || !write_data->preg_replaced) && write_data->value) {
		/* write the section header unless we're already in it */
		if (!current_section || strcmp(current_section, write_data->section))
			result = write_section(write_data->buf, write_data->orig_section);

		if (!result)
			result = write_value(write_data);
	}

	return result;
}

/*
 * This is pretty much the parsing, except we write out anything we don't have
 */
static int config_file_write(
	config_file_backend *cfg,
	const char *orig_key,
	const char *key,
	const git3_regexp *preg,
	const char *value)

{
	char *orig_section = NULL, *section = NULL, *orig_name, *name, *ldot;
	git3_str buf = GIT3_STR_INIT, contents = GIT3_STR_INIT;
	git3_config_parser parser = GIT3_CONFIG_PARSER_INIT;
	git3_filebuf file = GIT3_FILEBUF_INIT;
	struct write_data write_data;
	int error;

	memset(&write_data, 0, sizeof(write_data));

	if (cfg->locked) {
		error = git3_str_puts(&contents, git3_str_cstr(&cfg->locked_content) == NULL ? "" : git3_str_cstr(&cfg->locked_content));
	} else {
		if ((error = git3_filebuf_open(&file, cfg->file.path,
				GIT3_FILEBUF_HASH_SHA256,
				GIT3_CONFIG_FILE_MODE)) < 0)
			goto done;

		/* We need to read in our own config file */
		error = git3_futils_readbuffer(&contents, cfg->file.path);
	}
	if (error < 0 && error != GIT3_ENOTFOUND)
		goto done;

	if ((git3_config_parser_init(&parser, cfg->file.path, contents.ptr, contents.size)) < 0)
		goto done;

	ldot = strrchr(key, '.');
	name = ldot + 1;
	section = git3__strndup(key, ldot - key);
	GIT3_ERROR_CHECK_ALLOC(section);

	ldot = strrchr(orig_key, '.');
	orig_name = ldot + 1;
	orig_section = git3__strndup(orig_key, ldot - orig_key);
	GIT3_ERROR_CHECK_ALLOC(orig_section);

	write_data.buf = &buf;
	write_data.orig_section = orig_section;
	write_data.section = section;
	write_data.orig_name = orig_name;
	write_data.name = name;
	write_data.preg = preg;
	write_data.value = value;

	if ((error = git3_config_parse(&parser, write_on_section, write_on_variable,
				      write_on_comment, write_on_eof, &write_data)) < 0)
		goto done;

	if (cfg->locked) {
		size_t len = buf.asize;
		/* Update our copy with the modified contents */
		git3_str_dispose(&cfg->locked_content);
		git3_str_attach(&cfg->locked_content, git3_str_detach(&buf), len);
	} else {
		git3_filebuf_write(&file, git3_str_cstr(&buf), git3_str_len(&buf));

		if ((error = git3_filebuf_commit(&file)) < 0)
			goto done;

		if ((error = config_file_refresh_from_buffer(&cfg->parent, buf.ptr, buf.size)) < 0)
			goto done;
	}

done:
	git3__free(section);
	git3__free(orig_section);
	git3_str_dispose(&write_data.buffered_comment);
	git3_str_dispose(&buf);
	git3_str_dispose(&contents);
	git3_filebuf_cleanup(&file);
	git3_config_parser_dispose(&parser);

	return error;
}
