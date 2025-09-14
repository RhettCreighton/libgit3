/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_config_file_h__
#define INCLUDE_config_file_h__

#include "common.h"

#include "git3/sys/config.h"
#include "git3/config.h"

/**
 * Create a configuration file backend for ondisk files
 *
 * These are the normal `.gitconfig` files that Core Git
 * processes. Note that you first have to add this file to a
 * configuration object before you can query it for configuration
 * variables.
 *
 * @param out the new backend
 * @param path where the config file is located
 */
extern int git3_config_backend_from_file(git3_config_backend **out, const char *path);

/**
 * Create a readonly configuration file backend from another backend
 *
 * This copies the complete contents of the source backend to the
 * new backend. The new backend will be completely read-only and
 * cannot be modified.
 *
 * @param out the new snapshotted backend
 * @param source the backend to copy
 */
extern int git3_config_backend_snapshot(git3_config_backend **out, git3_config_backend *source);

GIT3_INLINE(int) git3_config_backend_open(git3_config_backend *cfg, unsigned int level, const git3_repository *repo)
{
	return cfg->open(cfg, level, repo);
}

GIT3_INLINE(void) git3_config_backend_free(git3_config_backend *cfg)
{
	if (cfg)
		cfg->free(cfg);
}

GIT3_INLINE(int) git3_config_backend_get_string(
	git3_config_entry **out, git3_config_backend *cfg, const char *name)
{
	git3_config_backend_entry *be;
	int error;

	if ((error = cfg->get(cfg, name, &be)) < 0)
		return error;

	*out = &be->entry;
	return 0;
}

GIT3_INLINE(int) git3_config_backend_set_string(
	git3_config_backend *cfg, const char *name, const char *value)
{
	return cfg->set(cfg, name, value);
}

GIT3_INLINE(int) git3_config_backend_delete(
	git3_config_backend *cfg, const char *name)
{
	return cfg->del(cfg, name);
}

GIT3_INLINE(int) git3_config_backend_foreach(
	git3_config_backend *cfg,
	int (*fn)(const git3_config_entry *entry, void *data),
	void *data)
{
	return git3_config_backend_foreach_match(cfg, NULL, fn, data);
}

GIT3_INLINE(int) git3_config_backend_lock(git3_config_backend *cfg)
{
	return cfg->lock(cfg);
}

GIT3_INLINE(int) git3_config_backend_unlock(git3_config_backend *cfg, int success)
{
	return cfg->unlock(cfg, success);
}

#endif
