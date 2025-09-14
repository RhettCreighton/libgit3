/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#ifndef INCLUDE_win32_thread_h__
#define INCLUDE_win32_thread_h__

#include "git3_util.h"

#if defined (_MSC_VER)
#	define GIT3_RESTRICT __restrict
#else
#	define GIT3_RESTRICT __restrict__
#endif

typedef struct {
	HANDLE thread;
	void *(*proc)(void *);
	void *param;
	void *result;
} git3_thread;

typedef CRITICAL_SECTION git3_mutex;
typedef HANDLE git3_cond;

typedef struct { void *Ptr; } GIT3_SRWLOCK;

typedef struct {
	union {
		GIT3_SRWLOCK srwl;
		CRITICAL_SECTION csec;
	} native;
} git3_rwlock;

int git3_threads_global_init(void);

int git3_thread_create(git3_thread *GIT3_RESTRICT,
	void *(*) (void *),
	void *GIT3_RESTRICT);
int git3_thread_join(git3_thread *, void **);
size_t git3_thread_currentid(void);
void git3_thread_exit(void *);

int git3_mutex_init(git3_mutex *GIT3_RESTRICT mutex);
int git3_mutex_free(git3_mutex *);
int git3_mutex_lock(git3_mutex *);
int git3_mutex_unlock(git3_mutex *);

int git3_cond_init(git3_cond *);
int git3_cond_free(git3_cond *);
int git3_cond_wait(git3_cond *, git3_mutex *);
int git3_cond_signal(git3_cond *);

int git3_rwlock_init(git3_rwlock *GIT3_RESTRICT lock);
int git3_rwlock_rdlock(git3_rwlock *);
int git3_rwlock_rdunlock(git3_rwlock *);
int git3_rwlock_wrlock(git3_rwlock *);
int git3_rwlock_wrunlock(git3_rwlock *);
int git3_rwlock_free(git3_rwlock *);

#endif
