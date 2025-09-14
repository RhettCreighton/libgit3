/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#ifndef INCLUDE_unix_pthread_h__
#define INCLUDE_unix_pthread_h__

typedef struct {
	pthread_t thread;
} git3_thread;

GIT3_INLINE(int) git3_threads_global_init(void) { return 0; }

#define git3_thread_create(git3_thread_ptr, start_routine, arg) \
	pthread_create(&(git3_thread_ptr)->thread, NULL, start_routine, arg)
#define git3_thread_join(git3_thread_ptr, status) \
	pthread_join((git3_thread_ptr)->thread, status)
#define git3_thread_currentid() ((size_t)(pthread_self()))
#define git3_thread_exit(retval) pthread_exit(retval)

/* Git Mutex */
#define git3_mutex pthread_mutex_t
#define git3_mutex_init(a)	pthread_mutex_init(a, NULL)
#define git3_mutex_lock(a)	pthread_mutex_lock(a)
#define git3_mutex_unlock(a)     pthread_mutex_unlock(a)
#define git3_mutex_free(a)	pthread_mutex_destroy(a)

/* Git condition vars */
#define git3_cond pthread_cond_t
#define git3_cond_init(c)	pthread_cond_init(c, NULL)
#define git3_cond_free(c) 	pthread_cond_destroy(c)
#define git3_cond_wait(c, l)	pthread_cond_wait(c, l)
#define git3_cond_signal(c)	pthread_cond_signal(c)
#define git3_cond_broadcast(c)	pthread_cond_broadcast(c)

/* Pthread (-ish) rwlock
 *
 * This differs from normal pthreads rwlocks in two ways:
 * 1. Separate APIs for releasing read locks and write locks (as
 *    opposed to the pure POSIX API which only has one unlock fn)
 * 2. You should not use recursive read locks (i.e. grabbing a read
 *    lock in a thread that already holds a read lock) because the
 *    Windows implementation doesn't support it
 */
#define git3_rwlock              pthread_rwlock_t
#define git3_rwlock_init(a)	pthread_rwlock_init(a, NULL)
#define git3_rwlock_rdlock(a)	pthread_rwlock_rdlock(a)
#define git3_rwlock_rdunlock(a)	pthread_rwlock_unlock(a)
#define git3_rwlock_wrlock(a)	pthread_rwlock_wrlock(a)
#define git3_rwlock_wrunlock(a)	pthread_rwlock_unlock(a)
#define git3_rwlock_free(a)	pthread_rwlock_destroy(a)
#define GIT3_RWLOCK_STATIC_INIT	PTHREAD_RWLOCK_INITIALIZER

#endif
