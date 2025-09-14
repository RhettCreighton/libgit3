/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_ctype_compat_h__
#define INCLUDE_ctype_compat_h__

/*
 * The Microsoft C runtime (MSVCRT) may take a heavy lock on the
 * locale in order to figure out how the `ctype` functions work.
 * This is deeply slow. Provide our own to avoid that.
 */

#ifdef GIT3_WIN32

GIT3_INLINE(int) git3__tolower(int c)
{
	return (c >= 'A' && c <= 'Z') ? (c + 32) : c;
}

GIT3_INLINE(int) git3__toupper(int c)
{
	return (c >= 'a' && c <= 'z') ? (c - 32) : c;
}

GIT3_INLINE(bool) git3__isalpha(int c)
{
	return ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'));
}

GIT3_INLINE(bool) git3__isdigit(int c)
{
	return (c >= '0' && c <= '9');
}

GIT3_INLINE(bool) git3__isalnum(int c)
{
	return git3__isalpha(c) || git3__isdigit(c);
}

GIT3_INLINE(bool) git3__isspace(int c)
{
	return (c == ' ' || c == '\t' || c == '\n' || c == '\f' || c == '\r' || c == '\v');
}

GIT3_INLINE(bool) git3__isxdigit(int c)
{
	return ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'));
}

GIT3_INLINE(bool) git3__isprint(int c)
{
	return (c >= ' ' && c <= '~');
}

#else
# define git3__tolower(a) tolower((unsigned char)(a))
# define git3__toupper(a) toupper((unsigned char)(a))

# define git3__isalpha(a)  (!!isalpha((unsigned char)(a)))
# define git3__isdigit(a)  (!!isdigit((unsigned char)(a)))
# define git3__isalnum(a)  (!!isalnum((unsigned char)(a)))
# define git3__isspace(a)  (!!isspace((unsigned char)(a)))
# define git3__isxdigit(a) (!!isxdigit((unsigned char)(a)))
# define git3__isprint(a)  (!!isprint((unsigned char)(a)))
#endif

#endif
