/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "sysdir.h"

#include "runtime.h"
#include "str.h"
#include "fs_path.h"
#include <ctype.h>
#if GIT3_WIN32
# include "fs_path.h"
# include "win32/path_w32.h"
# include "win32/utf-conv.h"
#else
# include <unistd.h>
# include <pwd.h>
#endif

#ifdef GIT3_WIN32
# define REG_GITFORWINDOWS_KEY       L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Git_is1"
# define REG_GITFORWINDOWS_KEY_WOW64 L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Git_is1"

static int expand_win32_path(git3_win32_path dest, const wchar_t *src)
{
	DWORD len = ExpandEnvironmentStringsW(src, dest, GIT3_WIN_PATH_UTF16);

	if (!len || len > GIT3_WIN_PATH_UTF16)
		return -1;

	return 0;
}

static int win32_path_to_utf8(git3_str *dest, const wchar_t *src)
{
	git3_win32_utf8_path utf8_path;

	if (git3_win32_path_to_utf8(utf8_path, src) < 0) {
		git3_error_set(GIT3_ERROR_OS, "unable to convert path to UTF-8");
		return -1;
	}

	/* Convert backslashes to forward slashes */
	git3_fs_path_mkposix(utf8_path);

	return git3_str_sets(dest, utf8_path);
}

static git3_win32_path mock_registry;
static bool mock_registry_set;

extern int git3_win32__set_registry_system_dir(const wchar_t *mock_sysdir)
{
	if (!mock_sysdir) {
		mock_registry[0] = L'\0';
		mock_registry_set = false;
	} else {
		size_t len = wcslen(mock_sysdir);

		if (len > GIT3_WIN_PATH_MAX) {
			git3_error_set(GIT3_ERROR_INVALID, "mock path too long");
			return -1;
		}

		wcscpy(mock_registry, mock_sysdir);
		mock_registry_set = true;
	}

	return 0;
}

static int lookup_registry_key(
	git3_win32_path out,
	const HKEY hive,
	const wchar_t* key,
	const wchar_t *value)
{
	HKEY hkey;
	DWORD type, size;
	int error = GIT3_ENOTFOUND;

	/*
	 * Registry data may not be NUL terminated, provide room to do
	 * it ourselves.
	 */
	size = (DWORD)((sizeof(git3_win32_path) - 1) * sizeof(wchar_t));

	if (RegOpenKeyExW(hive, key, 0, KEY_READ, &hkey) != 0)
		return GIT3_ENOTFOUND;

	if (RegQueryValueExW(hkey, value, NULL, &type, (LPBYTE)out, &size) == 0 &&
	    type == REG_SZ &&
	    size > 0 &&
	    size < sizeof(git3_win32_path)) {
		size_t wsize = size / sizeof(wchar_t);
		size_t len = wsize - 1;

		if (out[wsize - 1] != L'\0') {
			len = wsize;
			out[wsize] = L'\0';
		}

		if (out[len - 1] == L'\\')
			out[len - 1] = L'\0';

		if (_waccess(out, F_OK) == 0)
			error = 0;
	}

	RegCloseKey(hkey);
	return error;
}

static int find_sysdir_in_registry(git3_win32_path out)
{
	if (mock_registry_set) {
		if (mock_registry[0] == L'\0')
			return GIT3_ENOTFOUND;

		wcscpy(out, mock_registry);
		return 0;
	}

	if (lookup_registry_key(out, HKEY_CURRENT_USER, REG_GITFORWINDOWS_KEY, L"InstallLocation") == 0 ||
	    lookup_registry_key(out, HKEY_CURRENT_USER, REG_GITFORWINDOWS_KEY_WOW64, L"InstallLocation") == 0 ||
	    lookup_registry_key(out, HKEY_LOCAL_MACHINE, REG_GITFORWINDOWS_KEY, L"InstallLocation") == 0 ||
	    lookup_registry_key(out, HKEY_LOCAL_MACHINE, REG_GITFORWINDOWS_KEY_WOW64, L"InstallLocation") == 0)
		return 0;

    return GIT3_ENOTFOUND;
}

static int find_sysdir_in_path(git3_win32_path out)
{
	size_t out_len;

	if (git3_win32_path_find_executable(out, L"git.exe") < 0 &&
	    git3_win32_path_find_executable(out, L"git.cmd") < 0)
		return GIT3_ENOTFOUND;

	out_len = wcslen(out);

	/* Trim the file name */
	if (out_len <= CONST_STRLEN(L"git.exe"))
		return GIT3_ENOTFOUND;

	out_len -= CONST_STRLEN(L"git.exe");

	if (out_len && out[out_len - 1] == L'\\')
		out_len--;

	/*
	 * Git for Windows usually places the command in a 'bin' or
	 * 'cmd' directory, trim that.
	 */
	if (out_len >= CONST_STRLEN(L"\\bin") &&
	    wcsncmp(&out[out_len - CONST_STRLEN(L"\\bin")], L"\\bin", CONST_STRLEN(L"\\bin")) == 0)
		out_len -= CONST_STRLEN(L"\\bin");
	else if (out_len >= CONST_STRLEN(L"\\cmd") &&
	         wcsncmp(&out[out_len - CONST_STRLEN(L"\\cmd")], L"\\cmd", CONST_STRLEN(L"\\cmd")) == 0)
		out_len -= CONST_STRLEN(L"\\cmd");

	if (!out_len)
		return GIT3_ENOTFOUND;

	out[out_len] = L'\0';
	return 0;
}

static int find_win32_dirs(
    git3_str *out,
    const wchar_t* tmpl[])
{
	git3_win32_path path16;
	git3_str buf = GIT3_STR_INIT;

	git3_str_clear(out);

	for (; *tmpl != NULL; tmpl++) {
		if (!expand_win32_path(path16, *tmpl) &&
		    path16[0] != L'%' &&
		    !_waccess(path16, F_OK)) {
			win32_path_to_utf8(&buf, path16);

			if (buf.size)
				git3_str_join(out, GIT3_PATH_LIST_SEPARATOR, out->ptr, buf.ptr);
		}
	}

	git3_str_dispose(&buf);

	return (git3_str_oom(out) ? -1 : 0);
}

static int append_subdir(git3_str *out, git3_str *path, const char *subdir)
{
	static const char* architecture_roots[] = {
		"",
		"mingw64",
		"mingw32",
		NULL
	};
	const char **root;
	size_t orig_path_len = path->size;

	for (root = architecture_roots; *root; root++) {
		if ((*root[0] && git3_str_joinpath(path, path->ptr, *root) < 0) ||
		    git3_str_joinpath(path, path->ptr, subdir) < 0)
			return -1;

		if (git3_fs_path_exists(path->ptr) &&
		    git3_str_join(out, GIT3_PATH_LIST_SEPARATOR, out->ptr, path->ptr) < 0)
			return -1;

		git3_str_truncate(path, orig_path_len);
	}

	return 0;
}

int git3_win32__find_system_dirs(git3_str *out, const char *subdir)
{
	git3_win32_path pathdir, regdir;
	git3_str path8 = GIT3_STR_INIT;
	bool has_pathdir, has_regdir;
	int error;

	has_pathdir = (find_sysdir_in_path(pathdir) == 0);
	has_regdir = (find_sysdir_in_registry(regdir) == 0);

	if (!has_pathdir && !has_regdir)
		return 0;

	/*
	 * Usually the git in the path is the same git in the registry,
	 * in this case there's no need to duplicate the paths.
	 */
	if (has_pathdir && has_regdir && wcscmp(pathdir, regdir) == 0)
		has_regdir = false;

	if (has_pathdir) {
		if ((error = win32_path_to_utf8(&path8, pathdir)) < 0 ||
		    (error = append_subdir(out, &path8, subdir)) < 0)
			goto done;
	}

	if (has_regdir) {
		if ((error = win32_path_to_utf8(&path8, regdir)) < 0 ||
		    (error = append_subdir(out, &path8, subdir)) < 0)
			goto done;
	}

done:
    git3_str_dispose(&path8);
    return error;
}
#endif /* WIN32 */

static int git3_sysdir_guess_programdata_dirs(git3_str *out)
{
#ifdef GIT3_WIN32
	static const wchar_t *programdata_tmpls[2] = {
		L"%PROGRAMDATA%\\Git",
		NULL,
	};

	return find_win32_dirs(out, programdata_tmpls);
#else
	git3_str_clear(out);
	return 0;
#endif
}

static int git3_sysdir_guess_system_dirs(git3_str *out)
{
#ifdef GIT3_WIN32
	return git3_win32__find_system_dirs(out, "etc");
#else
	return git3_str_sets(out, "/etc");
#endif
}

#ifndef GIT3_WIN32
static int get_passwd_home(git3_str *out, uid_t uid)
{
	struct passwd pwd, *pwdptr;
	char *buf = NULL;
	long buflen;
	int error;

	GIT3_ASSERT_ARG(out);

	if ((buflen = sysconf(_SC_GETPW_R_SIZE_MAX)) == -1)
		buflen = 1024;

	do {
		buf = git3__realloc(buf, buflen);
		error = getpwuid_r(uid, &pwd, buf, buflen, &pwdptr);
		buflen *= 2;
	} while (error == ERANGE && buflen <= 8192);

	if (error) {
		git3_error_set(GIT3_ERROR_OS, "failed to get passwd entry");
		goto out;
	}

	if (!pwdptr) {
		git3_error_set(GIT3_ERROR_OS, "no passwd entry found for user");
		goto out;
	}

	if ((error = git3_str_puts(out, pwdptr->pw_dir)) < 0)
		goto out;

out:
	git3__free(buf);
	return error;
}
#endif

static int git3_sysdir_guess_home_dirs(git3_str *out)
{
#ifdef GIT3_WIN32
	static const wchar_t *global_tmpls[4] = {
		L"%HOME%\\",
		L"%HOMEDRIVE%%HOMEPATH%\\",
		L"%USERPROFILE%\\",
		NULL,
	};

	return find_win32_dirs(out, global_tmpls);
#else
	int error;
	uid_t uid, euid;
	const char *sandbox_id;

	uid = getuid();
	euid = geteuid();

	/**
	 * If APP_SANDBOX_CONTAINER_ID is set, we are running in a
	 * sandboxed environment on macOS.
	 */
	sandbox_id = getenv("APP_SANDBOX_CONTAINER_ID");

	/*
	 * In case we are running setuid, use the configuration
	 * of the effective user.
	 *
	 * If we are running in a sandboxed environment on macOS,
	 * we have to get the HOME dir from the password entry file.
	 */
	if (!sandbox_id && uid == euid)
	    error = git3__getenv(out, "HOME");
	else
	    error = get_passwd_home(out, euid);

	if (error == GIT3_ENOTFOUND) {
		git3_error_clear();
		error = 0;
	}

	return error;
#endif
}

static int git3_sysdir_guess_global_dirs(git3_str *out)
{
	return git3_sysdir_guess_home_dirs(out);
}

static int git3_sysdir_guess_xdg_dirs(git3_str *out)
{
#ifdef GIT3_WIN32
	static const wchar_t *global_tmpls[7] = {
		L"%XDG_CONFIG_HOME%\\git",
		L"%APPDATA%\\git",
		L"%LOCALAPPDATA%\\git",
		L"%HOME%\\.config\\git",
		L"%HOMEDRIVE%%HOMEPATH%\\.config\\git",
		L"%USERPROFILE%\\.config\\git",
		NULL,
	};

	return find_win32_dirs(out, global_tmpls);
#else
	git3_str env = GIT3_STR_INIT;
	int error;
	uid_t uid, euid;

	uid = getuid();
	euid = geteuid();

	/*
	 * In case we are running setuid, only look up passwd
	 * directory of the effective user.
	 */
	if (uid == euid) {
		if ((error = git3__getenv(&env, "XDG_CONFIG_HOME")) == 0)
			error = git3_str_joinpath(out, env.ptr, "git");

		if (error == GIT3_ENOTFOUND && (error = git3__getenv(&env, "HOME")) == 0)
			error = git3_str_joinpath(out, env.ptr, ".config/git");
	} else {
		if ((error = get_passwd_home(&env, euid)) == 0)
			error = git3_str_joinpath(out, env.ptr, ".config/git");
	}

	if (error == GIT3_ENOTFOUND) {
		git3_error_clear();
		error = 0;
	}

	git3_str_dispose(&env);
	return error;
#endif
}

static int git3_sysdir_guess_template_dirs(git3_str *out)
{
#ifdef GIT3_WIN32
	return git3_win32__find_system_dirs(out, "share/git-core/templates");
#else
	return git3_str_sets(out, "/usr/share/git-core/templates");
#endif
}

struct git3_sysdir__dir {
	git3_str buf;
	int (*guess)(git3_str *out);
};

static struct git3_sysdir__dir git3_sysdir__dirs[] = {
	{ GIT3_STR_INIT, git3_sysdir_guess_system_dirs },
	{ GIT3_STR_INIT, git3_sysdir_guess_global_dirs },
	{ GIT3_STR_INIT, git3_sysdir_guess_xdg_dirs },
	{ GIT3_STR_INIT, git3_sysdir_guess_programdata_dirs },
	{ GIT3_STR_INIT, git3_sysdir_guess_template_dirs },
	{ GIT3_STR_INIT, git3_sysdir_guess_home_dirs }
};

static void git3_sysdir_global_shutdown(void)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(git3_sysdir__dirs); ++i)
		git3_str_dispose(&git3_sysdir__dirs[i].buf);
}

int git3_sysdir_global_init(void)
{
	size_t i;
	int error = 0;

	for (i = 0; !error && i < ARRAY_SIZE(git3_sysdir__dirs); i++)
		error = git3_sysdir__dirs[i].guess(&git3_sysdir__dirs[i].buf);

	if (error)
		return error;

	return git3_runtime_shutdown_register(git3_sysdir_global_shutdown);
}

int git3_sysdir_reset(void)
{
	size_t i;
	int error = 0;

	for (i = 0; !error && i < ARRAY_SIZE(git3_sysdir__dirs); ++i) {
		git3_str_dispose(&git3_sysdir__dirs[i].buf);
		error = git3_sysdir__dirs[i].guess(&git3_sysdir__dirs[i].buf);
	}

	return error;
}

static int git3_sysdir_check_selector(git3_sysdir_t which)
{
	if (which < ARRAY_SIZE(git3_sysdir__dirs))
		return 0;

	git3_error_set(GIT3_ERROR_INVALID, "config directory selector out of range");
	return -1;
}


int git3_sysdir_get(const git3_str **out, git3_sysdir_t which)
{
	GIT3_ASSERT_ARG(out);

	*out = NULL;

	GIT3_ERROR_CHECK_ERROR(git3_sysdir_check_selector(which));

	*out = &git3_sysdir__dirs[which].buf;
	return 0;
}

#define PATH_MAGIC "$PATH"

int git3_sysdir_set(git3_sysdir_t which, const char *search_path)
{
	const char *expand_path = NULL;
	git3_str merge = GIT3_STR_INIT;

	GIT3_ERROR_CHECK_ERROR(git3_sysdir_check_selector(which));

	if (search_path != NULL)
		expand_path = strstr(search_path, PATH_MAGIC);

	/* reset the default if this path has been cleared */
	if (!search_path)
		git3_sysdir__dirs[which].guess(&git3_sysdir__dirs[which].buf);

	/* if $PATH is not referenced, then just set the path */
	if (!expand_path) {
		if (search_path)
			git3_str_sets(&git3_sysdir__dirs[which].buf, search_path);

		goto done;
	}

	/* otherwise set to join(before $PATH, old value, after $PATH) */
	if (expand_path > search_path)
		git3_str_set(&merge, search_path, expand_path - search_path);

	if (git3_str_len(&git3_sysdir__dirs[which].buf))
		git3_str_join(&merge, GIT3_PATH_LIST_SEPARATOR,
			merge.ptr, git3_sysdir__dirs[which].buf.ptr);

	expand_path += strlen(PATH_MAGIC);
	if (*expand_path)
		git3_str_join(&merge, GIT3_PATH_LIST_SEPARATOR, merge.ptr, expand_path);

	git3_str_swap(&git3_sysdir__dirs[which].buf, &merge);
	git3_str_dispose(&merge);

done:
	if (git3_str_oom(&git3_sysdir__dirs[which].buf))
		return -1;

	return 0;
}

static int git3_sysdir_find_in_dirlist(
	git3_str *path,
	const char *name,
	git3_sysdir_t which,
	const char *label)
{
	size_t len;
	const char *scan, *next = NULL;
	const git3_str *syspath;

	GIT3_ERROR_CHECK_ERROR(git3_sysdir_get(&syspath, which));
	if (!syspath || !git3_str_len(syspath))
		goto done;

	for (scan = git3_str_cstr(syspath); scan; scan = next) {
		/* find unescaped separator or end of string */
		for (next = scan; *next; ++next) {
			if (*next == GIT3_PATH_LIST_SEPARATOR &&
				(next <= scan || next[-1] != '\\'))
				break;
		}

		len = (size_t)(next - scan);
		next = (*next ? next + 1 : NULL);
		if (!len)
			continue;

		GIT3_ERROR_CHECK_ERROR(git3_str_set(path, scan, len));
		if (name)
			GIT3_ERROR_CHECK_ERROR(git3_str_joinpath(path, path->ptr, name));

		if (git3_fs_path_exists(path->ptr))
			return 0;
	}

done:
	if (name)
		git3_error_set(GIT3_ERROR_OS, "the %s file '%s' doesn't exist", label, name);
	else
		git3_error_set(GIT3_ERROR_OS, "the %s directory doesn't exist", label);
	git3_str_dispose(path);
	return GIT3_ENOTFOUND;
}

int git3_sysdir_find_system_file(git3_str *path, const char *filename)
{
	return git3_sysdir_find_in_dirlist(
		path, filename, GIT3_SYSDIR_SYSTEM, "system");
}

int git3_sysdir_find_global_file(git3_str *path, const char *filename)
{
	return git3_sysdir_find_in_dirlist(
		path, filename, GIT3_SYSDIR_GLOBAL, "global");
}

int git3_sysdir_find_xdg_file(git3_str *path, const char *filename)
{
	return git3_sysdir_find_in_dirlist(
		path, filename, GIT3_SYSDIR_XDG, "global/xdg");
}

int git3_sysdir_find_programdata_file(git3_str *path, const char *filename)
{
	return git3_sysdir_find_in_dirlist(
		path, filename, GIT3_SYSDIR_PROGRAMDATA, "ProgramData");
}

int git3_sysdir_find_template_dir(git3_str *path)
{
	return git3_sysdir_find_in_dirlist(
		path, NULL, GIT3_SYSDIR_TEMPLATE, "template");
}

int git3_sysdir_find_homedir(git3_str *path)
{
	return git3_sysdir_find_in_dirlist(
		path, NULL, GIT3_SYSDIR_HOME, "home directory");
}

int git3_sysdir_expand_global_file(git3_str *path, const char *filename)
{
	int error;

	if ((error = git3_sysdir_find_global_file(path, NULL)) == 0) {
		if (filename)
			error = git3_str_joinpath(path, path->ptr, filename);
	}

	return error;
}

int git3_sysdir_expand_homedir_file(git3_str *path, const char *filename)
{
	int error;

	if ((error = git3_sysdir_find_homedir(path)) == 0) {
		if (filename)
			error = git3_str_joinpath(path, path->ptr, filename);
	}

	return error;
}
