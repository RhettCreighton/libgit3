/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "config_backend.h"

#include "config.h"
#include "config_list.h"

typedef struct {
	git3_config_backend parent;
	git3_mutex values_mutex;
	git3_config_list *config_list;
	git3_config_backend *source;
} config_snapshot_backend;

static int config_error_readonly(void)
{
	git3_error_set(GIT3_ERROR_CONFIG, "this backend is read-only");
	return -1;
}

static int config_snapshot_iterator(
	git3_config_iterator **iter,
	struct git3_config_backend *backend)
{
	config_snapshot_backend *b = GIT3_CONTAINER_OF(backend, config_snapshot_backend, parent);
	git3_config_list *config_list = NULL;
	int error;

	if ((error = git3_config_list_dup(&config_list, b->config_list)) < 0 ||
	    (error = git3_config_list_iterator_new(iter, config_list)) < 0)
		goto out;

out:
	/* Let iterator delete duplicated config_list when it's done */
	git3_config_list_free(config_list);
	return error;
}

static int config_snapshot_get(
	git3_config_backend *cfg,
	const char *key,
	git3_config_backend_entry **out)
{
	config_snapshot_backend *b = GIT3_CONTAINER_OF(cfg, config_snapshot_backend, parent);
	git3_config_list *config_list = NULL;
	git3_config_list_entry *entry;
	int error = 0;

	if (git3_mutex_lock(&b->values_mutex) < 0) {
	    git3_error_set(GIT3_ERROR_OS, "failed to lock config backend");
	    return -1;
	}

	config_list = b->config_list;
	git3_config_list_incref(config_list);
	git3_mutex_unlock(&b->values_mutex);

	if ((error = (git3_config_list_get(&entry, config_list, key))) < 0) {
		git3_config_list_free(config_list);
		return error;
	}

	*out = &entry->base;
	return 0;
}

static int config_snapshot_set(git3_config_backend *cfg, const char *name, const char *value)
{
	GIT3_UNUSED(cfg);
	GIT3_UNUSED(name);
	GIT3_UNUSED(value);

	return config_error_readonly();
}

static int config_snapshot_set_multivar(
	git3_config_backend *cfg, const char *name, const char *regexp, const char *value)
{
	GIT3_UNUSED(cfg);
	GIT3_UNUSED(name);
	GIT3_UNUSED(regexp);
	GIT3_UNUSED(value);

	return config_error_readonly();
}

static int config_snapshot_delete_multivar(git3_config_backend *cfg, const char *name, const char *regexp)
{
	GIT3_UNUSED(cfg);
	GIT3_UNUSED(name);
	GIT3_UNUSED(regexp);

	return config_error_readonly();
}

static int config_snapshot_delete(git3_config_backend *cfg, const char *name)
{
	GIT3_UNUSED(cfg);
	GIT3_UNUSED(name);

	return config_error_readonly();
}

static int config_snapshot_lock(git3_config_backend *_cfg)
{
	GIT3_UNUSED(_cfg);

	return config_error_readonly();
}

static int config_snapshot_unlock(git3_config_backend *_cfg, int success)
{
	GIT3_UNUSED(_cfg);
	GIT3_UNUSED(success);

	return config_error_readonly();
}

static void config_snapshot_free(git3_config_backend *_backend)
{
	config_snapshot_backend *backend = GIT3_CONTAINER_OF(_backend, config_snapshot_backend, parent);

	if (backend == NULL)
		return;

	git3_config_list_free(backend->config_list);
	git3_mutex_free(&backend->values_mutex);
	git3__free(backend);
}

static int config_snapshot_open(git3_config_backend *cfg, git3_config_level_t level, const git3_repository *repo)
{
	config_snapshot_backend *b = GIT3_CONTAINER_OF(cfg, config_snapshot_backend, parent);
	git3_config_list *config_list = NULL;
	git3_config_iterator *it = NULL;
	git3_config_entry *entry;
	int error;

	/* We're just copying data, don't care about the level or repo*/
	GIT3_UNUSED(level);
	GIT3_UNUSED(repo);

	if ((error = git3_config_list_new(&config_list)) < 0 ||
	    (error = b->source->iterator(&it, b->source)) < 0)
		goto out;

	while ((error = git3_config_next(&entry, it)) == 0)
		if ((error = git3_config_list_dup_entry(config_list, entry)) < 0)
			goto out;

	if (error < 0) {
		if (error != GIT3_ITEROVER)
			goto out;
		error = 0;
	}

	b->config_list = config_list;

out:
	git3_config_iterator_free(it);
	if (error)
		git3_config_list_free(config_list);
	return error;
}

int git3_config_backend_snapshot(git3_config_backend **out, git3_config_backend *source)
{
	config_snapshot_backend *backend;

	backend = git3__calloc(1, sizeof(config_snapshot_backend));
	GIT3_ERROR_CHECK_ALLOC(backend);

	backend->parent.version = GIT3_CONFIG_BACKEND_VERSION;
	git3_mutex_init(&backend->values_mutex);

	backend->source = source;

	backend->parent.readonly = 1;
	backend->parent.version = GIT3_CONFIG_BACKEND_VERSION;
	backend->parent.open = config_snapshot_open;
	backend->parent.get = config_snapshot_get;
	backend->parent.set = config_snapshot_set;
	backend->parent.set_multivar = config_snapshot_set_multivar;
	backend->parent.snapshot = git3_config_backend_snapshot;
	backend->parent.del = config_snapshot_delete;
	backend->parent.del_multivar = config_snapshot_delete_multivar;
	backend->parent.iterator = config_snapshot_iterator;
	backend->parent.lock = config_snapshot_lock;
	backend->parent.unlock = config_snapshot_unlock;
	backend->parent.free = config_snapshot_free;

	*out = &backend->parent;

	return 0;
}
