/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "settings.h"

#include <git3.h>
#include "alloc.h"
#include "buf.h"
#include "cache.h"
#include "common.h"
#include "filter.h"
#include "grafts.h"
#include "hash.h"
#include "index.h"
#include "merge_driver.h"
#include "pool.h"
#include "mwindow.h"
#include "object.h"
#include "odb.h"
#include "rand.h"
#include "refs.h"
#include "runtime.h"
#include "sysdir.h"
#include "thread.h"
#include "git3/global.h"
#include "streams/registry.h"
#include "streams/mbedtls.h"
#include "streams/openssl.h"
#include "streams/socket.h"
#include "transports/smart.h"
#include "transports/http.h"
#include "transports/ssh_libssh2.h"

#ifdef GIT3_WIN32
# include "win32/w32_leakcheck.h"
#endif

/* Declarations for tuneable settings */
extern size_t git3_mwindow__window_size;
extern size_t git3_mwindow__mapped_limit;
extern size_t git3_mwindow__file_limit;
extern size_t git3_indexer__max_objects;
extern bool git3_disable_pack_keep_file_checks;
extern int git3_odb__packed_priority;
extern int git3_odb__loose_priority;
extern int git3_socket_stream__connect_timeout;
extern int git3_socket_stream__timeout;

char *git3__user_agent;
char *git3__user_agent_product;
char *git3__ssl_ciphers;

static void settings_global_shutdown(void)
{
	git3__free(git3__user_agent);
	git3__free(git3__user_agent_product);

	git3__free(git3__ssl_ciphers);
	git3_repository__free_extensions();
}

int git3_settings_global_init(void)
{
	return git3_runtime_shutdown_register(settings_global_shutdown);
}

static int config_level_to_sysdir(int *out, int config_level)
{
	switch (config_level) {
	case GIT3_CONFIG_LEVEL_SYSTEM:
		*out = GIT3_SYSDIR_SYSTEM;
		return 0;
	case GIT3_CONFIG_LEVEL_XDG:
		*out = GIT3_SYSDIR_XDG;
		return 0;
	case GIT3_CONFIG_LEVEL_GLOBAL:
		*out = GIT3_SYSDIR_GLOBAL;
		return 0;
	case GIT3_CONFIG_LEVEL_PROGRAMDATA:
		*out = GIT3_SYSDIR_PROGRAMDATA;
		return 0;
	default:
		break;
	}

	git3_error_set(
		GIT3_ERROR_INVALID, "invalid config path selector %d", config_level);
	return -1;
}

const char *git3_settings__user_agent_product(void)
{
	return git3__user_agent_product ? git3__user_agent_product :
		"git/2.0";
}

const char *git3_settings__user_agent(void)
{
	return git3__user_agent ? git3__user_agent :
		"libgit3 " LIBGIT3_VERSION;
}

int git3_libgit3_opts(int key, ...)
{
	int error = 0;
	va_list ap;

	va_start(ap, key);

	switch (key) {
	case GIT3_OPT_SET_MWINDOW_SIZE:
		git3_mwindow__window_size = va_arg(ap, size_t);
		break;

	case GIT3_OPT_GET_MWINDOW_SIZE:
		*(va_arg(ap, size_t *)) = git3_mwindow__window_size;
		break;

	case GIT3_OPT_SET_MWINDOW_MAPPED_LIMIT:
		git3_mwindow__mapped_limit = va_arg(ap, size_t);
		break;

	case GIT3_OPT_GET_MWINDOW_MAPPED_LIMIT:
		*(va_arg(ap, size_t *)) = git3_mwindow__mapped_limit;
		break;

	case GIT3_OPT_SET_MWINDOW_FILE_LIMIT:
		git3_mwindow__file_limit = va_arg(ap, size_t);
		break;

	case GIT3_OPT_GET_MWINDOW_FILE_LIMIT:
		*(va_arg(ap, size_t *)) = git3_mwindow__file_limit;
		break;

	case GIT3_OPT_GET_SEARCH_PATH:
		{
			int sysdir = va_arg(ap, int);
			git3_buf *out = va_arg(ap, git3_buf *);
			git3_str str = GIT3_STR_INIT;
			const git3_str *tmp;
			int level;

			if ((error = git3_buf_tostr(&str, out)) < 0 ||
			    (error = config_level_to_sysdir(&level, sysdir)) < 0 ||
			    (error = git3_sysdir_get(&tmp, level)) < 0 ||
			    (error = git3_str_put(&str, tmp->ptr, tmp->size)) < 0)
				break;

			error = git3_buf_fromstr(out, &str);
		}
		break;

	case GIT3_OPT_SET_SEARCH_PATH:
		{
			int level;

			if ((error = config_level_to_sysdir(&level, va_arg(ap, int))) >= 0)
				error = git3_sysdir_set(level, va_arg(ap, const char *));
		}
		break;

	case GIT3_OPT_SET_CACHE_OBJECT_LIMIT:
		{
			git3_object_t type = (git3_object_t)va_arg(ap, int);
			size_t size = va_arg(ap, size_t);
			error = git3_cache_set_max_object_size(type, size);
			break;
		}

	case GIT3_OPT_SET_CACHE_MAX_SIZE:
		git3_cache__max_storage = va_arg(ap, ssize_t);
		break;

	case GIT3_OPT_ENABLE_CACHING:
		git3_cache__enabled = (va_arg(ap, int) != 0);
		break;

	case GIT3_OPT_GET_CACHED_MEMORY:
		*(va_arg(ap, ssize_t *)) = git3_cache__current_storage.val;
		*(va_arg(ap, ssize_t *)) = git3_cache__max_storage;
		break;

	case GIT3_OPT_GET_TEMPLATE_PATH:
		{
			git3_buf *out = va_arg(ap, git3_buf *);
			git3_str str = GIT3_STR_INIT;
			const git3_str *tmp;

			if ((error = git3_buf_tostr(&str, out)) < 0 ||
			    (error = git3_sysdir_get(&tmp, GIT3_SYSDIR_TEMPLATE)) < 0 ||
			    (error = git3_str_put(&str, tmp->ptr, tmp->size)) < 0)
				break;

			error = git3_buf_fromstr(out, &str);
		}
		break;

	case GIT3_OPT_SET_TEMPLATE_PATH:
		error = git3_sysdir_set(GIT3_SYSDIR_TEMPLATE, va_arg(ap, const char *));
		break;

	case GIT3_OPT_SET_SSL_CERT_LOCATIONS:
#if defined(GIT3_HTTPS_OPENSSL) || defined(GIT3_HTTPS_OPENSSL_DYNAMIC)
		{
			const char *file = va_arg(ap, const char *);
			const char *path = va_arg(ap, const char *);
			error = git3_openssl__set_cert_location(file, path);
		}
#elif defined(GIT3_HTTPS_MBEDTLS)
		{
			const char *file = va_arg(ap, const char *);
			const char *path = va_arg(ap, const char *);
			error = git3_mbedtls__set_cert_location(file, path);
		}
#else
		git3_error_set(GIT3_ERROR_SSL, "TLS backend doesn't support certificate locations");
		error = -1;
#endif
		break;

	case GIT3_OPT_ADD_SSL_X509_CERT:
#if defined(GIT3_HTTPS_OPENSSL) || defined(GIT3_HTTPS_OPENSSL_DYNAMIC)
		{
			X509 *cert = va_arg(ap, X509 *);
			error = git3_openssl__add_x509_cert(cert);
		}
#else
		git3_error_set(GIT3_ERROR_SSL, "TLS backend doesn't support adding of the raw certs");
		error = -1;
#endif
		break;

	case GIT3_OPT_SET_USER_AGENT:
		{
			const char *new_agent = va_arg(ap, const char *);

			git3__free(git3__user_agent);

			if (new_agent) {
				git3__user_agent= git3__strdup(new_agent);

				if (!git3__user_agent)
					error = -1;
			} else {
				git3__user_agent = NULL;
			}
		}
		break;

	case GIT3_OPT_GET_USER_AGENT:
		{
			git3_buf *out = va_arg(ap, git3_buf *);
			git3_str str = GIT3_STR_INIT;

			if ((error = git3_buf_tostr(&str, out)) < 0 ||
			    (error = git3_str_puts(&str, git3_settings__user_agent())) < 0)
				break;

			error = git3_buf_fromstr(out, &str);
		}
		break;

	case GIT3_OPT_SET_USER_AGENT_PRODUCT:
		{
			const char *new_agent = va_arg(ap, const char *);

			git3__free(git3__user_agent_product);

			if (new_agent) {
				git3__user_agent_product = git3__strdup(new_agent);

				if (!git3__user_agent_product)
					error = -1;
			} else {
				git3__user_agent_product = NULL;
			}
		}
		break;

	case GIT3_OPT_GET_USER_AGENT_PRODUCT:
		{
			git3_buf *out = va_arg(ap, git3_buf *);
			git3_str str = GIT3_STR_INIT;

			if ((error = git3_buf_tostr(&str, out)) < 0 ||
			    (error = git3_str_puts(&str, git3_settings__user_agent_product())) < 0)
				break;

			error = git3_buf_fromstr(out, &str);
		}
		break;

	case GIT3_OPT_ENABLE_STRICT_OBJECT_CREATION:
		git3_object__strict_input_validation = (va_arg(ap, int) != 0);
		break;

	case GIT3_OPT_ENABLE_STRICT_SYMBOLIC_REF_CREATION:
		git3_reference__enable_symbolic_ref_target_validation = (va_arg(ap, int) != 0);
		break;

	case GIT3_OPT_SET_SSL_CIPHERS:
#if defined(GIT3_HTTPS_OPENSSL) || \
    defined(GIT3_HTTPS_OPENSSL_DYNAMIC) || \
    defined(GIT3_HTTPS_MBEDTLS)
		{
			git3__free(git3__ssl_ciphers);
			git3__ssl_ciphers = git3__strdup(va_arg(ap, const char *));
			if (!git3__ssl_ciphers) {
				git3_error_set_oom();
				error = -1;
			}
		}
#else
		git3_error_set(GIT3_ERROR_SSL, "TLS backend doesn't support custom ciphers");
		error = -1;
#endif
		break;

	case GIT3_OPT_ENABLE_OFS_DELTA:
		git3_smart__ofs_delta_enabled = (va_arg(ap, int) != 0);
		break;

	case GIT3_OPT_ENABLE_FSYNC_GITDIR:
		git3_repository__fsync_gitdir = (va_arg(ap, int) != 0);
		break;

	case GIT3_OPT_GET_WINDOWS_SHAREMODE:
#ifdef GIT3_WIN32
		*(va_arg(ap, unsigned long *)) = git3_win32__createfile_sharemode;
#endif
		break;

	case GIT3_OPT_SET_WINDOWS_SHAREMODE:
#ifdef GIT3_WIN32
		git3_win32__createfile_sharemode = va_arg(ap, unsigned long);
#endif
		break;

	case GIT3_OPT_ENABLE_STRICT_HASH_VERIFICATION:
		git3_odb__strict_hash_verification = (va_arg(ap, int) != 0);
		break;

	case GIT3_OPT_SET_ALLOCATOR:
		error = git3_allocator_setup(va_arg(ap, git3_allocator *));
		break;

	case GIT3_OPT_ENABLE_UNSAVED_INDEX_SAFETY:
		git3_index__enforce_unsaved_safety = (va_arg(ap, int) != 0);
		break;

	case GIT3_OPT_SET_PACK_MAX_OBJECTS:
		git3_indexer__max_objects = va_arg(ap, size_t);
		break;

	case GIT3_OPT_GET_PACK_MAX_OBJECTS:
		*(va_arg(ap, size_t *)) = git3_indexer__max_objects;
		break;

	case GIT3_OPT_DISABLE_PACK_KEEP_FILE_CHECKS:
		git3_disable_pack_keep_file_checks = (va_arg(ap, int) != 0);
		break;

	case GIT3_OPT_ENABLE_HTTP_EXPECT_CONTINUE:
		git3_http__expect_continue = (va_arg(ap, int) != 0);
		break;

	case GIT3_OPT_SET_ODB_PACKED_PRIORITY:
		git3_odb__packed_priority = va_arg(ap, int);
		break;

	case GIT3_OPT_SET_ODB_LOOSE_PRIORITY:
		git3_odb__loose_priority = va_arg(ap, int);
		break;

	case GIT3_OPT_SET_EXTENSIONS:
		{
			const char **extensions = va_arg(ap, const char **);
			size_t len = va_arg(ap, size_t);
			error = git3_repository__set_extensions(extensions, len);
		}
		break;

	case GIT3_OPT_GET_EXTENSIONS:
		{
			git3_strarray *out = va_arg(ap, git3_strarray *);
			char **extensions;
			size_t len;

			if ((error = git3_repository__extensions(&extensions, &len)) < 0)
				break;

			out->strings = extensions;
			out->count = len;
		}
		break;

	case GIT3_OPT_GET_OWNER_VALIDATION:
		*(va_arg(ap, int *)) = git3_repository__validate_ownership;
		break;

	case GIT3_OPT_SET_OWNER_VALIDATION:
		git3_repository__validate_ownership = (va_arg(ap, int) != 0);
		break;

	case GIT3_OPT_GET_HOMEDIR:
		{
			git3_buf *out = va_arg(ap, git3_buf *);
			git3_str str = GIT3_STR_INIT;
			const git3_str *tmp;

			if ((error = git3_buf_tostr(&str, out)) < 0 ||
			    (error = git3_sysdir_get(&tmp, GIT3_SYSDIR_HOME)) < 0 ||
			    (error = git3_str_put(&str, tmp->ptr, tmp->size)) < 0)
				break;

			error = git3_buf_fromstr(out, &str);
		}
		break;

	case GIT3_OPT_SET_HOMEDIR:
		error = git3_sysdir_set(GIT3_SYSDIR_HOME, va_arg(ap, const char *));
		break;

	case GIT3_OPT_GET_SERVER_CONNECT_TIMEOUT:
		*(va_arg(ap, int *)) = git3_socket_stream__connect_timeout;
		break;

	case GIT3_OPT_SET_SERVER_CONNECT_TIMEOUT:
		{
			int timeout = va_arg(ap, int);

			if (timeout < 0) {
				git3_error_set(GIT3_ERROR_INVALID, "invalid connect timeout");
				error = -1;
			} else {
				git3_socket_stream__connect_timeout = timeout;
			}
		}
		break;

	case GIT3_OPT_GET_SERVER_TIMEOUT:
		*(va_arg(ap, int *)) = git3_socket_stream__timeout;
		break;

	case GIT3_OPT_SET_SERVER_TIMEOUT:
		{
			int timeout = va_arg(ap, int);

			if (timeout < 0) {
				git3_error_set(GIT3_ERROR_INVALID, "invalid timeout");
				error = -1;
			} else {
				git3_socket_stream__timeout = timeout;
			}
		}
		break;

	default:
		git3_error_set(GIT3_ERROR_INVALID, "invalid option key");
		error = -1;
	}

	va_end(ap);

	return error;
}

const char *git3_libgit3_buildinfo(git3_buildinfo_t key)
{
	switch (key) {

#ifdef GIT3_BUILD_CPU
	case GIT3_BUILDINFO_CPU:
		return GIT3_BUILD_CPU;
		break;
#endif

#ifdef GIT3_BUILD_COMMIT
	case GIT3_BUILDINFO_COMMIT:
		return GIT3_BUILD_COMMIT;
		break;
#endif

	default:
		break;
	}

	return NULL;
}
