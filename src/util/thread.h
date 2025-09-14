/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_thread_h__
#define INCLUDE_thread_h__

#if defined(GIT3_THREADS)

#if defined(__clang__)

# if (__clang_major__ < 3 || (__clang_major__ == 3 && __clang_minor__ < 1))
#  error Atomic primitives do not exist on this version of clang; configure libgit3 with -DUSE_THREADS=OFF
# else
#  define GIT3_BUILTIN_ATOMIC
# endif

#elif defined(__GNUC__)

# if (__GNUC__ < 4 || (__GNUC__ == 4 && __GNUC_MINOR__ < 1))
#  error Atomic primitives do not exist on this version of gcc; configure libgit3 with -DUSE_THREADS=OFF
# elif (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 7))
#  define GIT3_BUILTIN_ATOMIC
# else
#  define GIT3_BUILTIN_SYNC
# endif

#endif

#endif /* GIT3_THREADS */

/* Common operations even if threading has been disabled */
typedef struct {
#if defined(GIT3_WIN32)
	volatile long val;
#else
	volatile int val;
#endif
} git3_atomic32;

#ifdef GIT3_ARCH_64

typedef struct {
#if defined(GIT3_WIN32)
	volatile __int64 val;
#else
	volatile int64_t val;
#endif
} git3_atomic64;

typedef git3_atomic64 git3_atomic_ssize;

#define git3_atomic_ssize_set git3_atomic64_set
#define git3_atomic_ssize_add git3_atomic64_add
#define git3_atomic_ssize_get git3_atomic64_get

#else

typedef git3_atomic32 git3_atomic_ssize;

#define git3_atomic_ssize_set git3_atomic32_set
#define git3_atomic_ssize_add git3_atomic32_add
#define git3_atomic_ssize_get git3_atomic32_get

#endif

#ifdef GIT3_THREADS

#ifdef GIT3_WIN32
#   include "win32/thread.h"
#else
#   include "unix/pthread.h"
#endif

/*
 * Atomically sets the contents of *a to be val.
 */
GIT3_INLINE(void) git3_atomic32_set(git3_atomic32 *a, int val)
{
#if defined(GIT3_WIN32)
	InterlockedExchange(&a->val, (LONG)val);
#elif defined(GIT3_BUILTIN_ATOMIC)
	__atomic_store_n(&a->val, val, __ATOMIC_SEQ_CST);
#elif defined(GIT3_BUILTIN_SYNC)
	__sync_lock_test_and_set(&a->val, val);
#else
#	error "Unsupported architecture for atomic operations"
#endif
}

/*
 * Atomically increments the contents of *a by 1, and stores the result back into *a.
 * @return the result of the operation.
 */
GIT3_INLINE(int) git3_atomic32_inc(git3_atomic32 *a)
{
#if defined(GIT3_WIN32)
	return InterlockedIncrement(&a->val);
#elif defined(GIT3_BUILTIN_ATOMIC)
	return __atomic_add_fetch(&a->val, 1, __ATOMIC_SEQ_CST);
#elif defined(GIT3_BUILTIN_SYNC)
	return __sync_add_and_fetch(&a->val, 1);
#else
#	error "Unsupported architecture for atomic operations"
#endif
}

/*
 * Atomically adds the contents of *a and addend, and stores the result back into *a.
 * @return the result of the operation.
 */
GIT3_INLINE(int) git3_atomic32_add(git3_atomic32 *a, int32_t addend)
{
#if defined(GIT3_WIN32)
	return InterlockedAdd(&a->val, addend);
#elif defined(GIT3_BUILTIN_ATOMIC)
	return __atomic_add_fetch(&a->val, addend, __ATOMIC_SEQ_CST);
#elif defined(GIT3_BUILTIN_SYNC)
	return __sync_add_and_fetch(&a->val, addend);
#else
#	error "Unsupported architecture for atomic operations"
#endif
}

/*
 * Atomically decrements the contents of *a by 1, and stores the result back into *a.
 * @return the result of the operation.
 */
GIT3_INLINE(int) git3_atomic32_dec(git3_atomic32 *a)
{
#if defined(GIT3_WIN32)
	return InterlockedDecrement(&a->val);
#elif defined(GIT3_BUILTIN_ATOMIC)
	return __atomic_sub_fetch(&a->val, 1, __ATOMIC_SEQ_CST);
#elif defined(GIT3_BUILTIN_SYNC)
	return __sync_sub_and_fetch(&a->val, 1);
#else
#	error "Unsupported architecture for atomic operations"
#endif
}

/*
 * Atomically gets the contents of *a.
 * @return the contents of *a.
 */
GIT3_INLINE(int) git3_atomic32_get(git3_atomic32 *a)
{
#if defined(GIT3_WIN32)
	return (int)InterlockedCompareExchange(&a->val, 0, 0);
#elif defined(GIT3_BUILTIN_ATOMIC)
	return __atomic_load_n(&a->val, __ATOMIC_SEQ_CST);
#elif defined(GIT3_BUILTIN_SYNC)
	return __sync_val_compare_and_swap(&a->val, 0, 0);
#else
#	error "Unsupported architecture for atomic operations"
#endif
}

GIT3_INLINE(void *) git3_atomic__compare_and_swap(
	void * volatile *ptr, void *oldval, void *newval)
{
#if defined(GIT3_WIN32)
	return InterlockedCompareExchangePointer((volatile PVOID *)ptr, newval, oldval);
#elif defined(GIT3_BUILTIN_ATOMIC)
	void *foundval = oldval;
	__atomic_compare_exchange(ptr, &foundval, &newval, false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
	return foundval;
#elif defined(GIT3_BUILTIN_SYNC)
	return __sync_val_compare_and_swap(ptr, oldval, newval);
#else
#	error "Unsupported architecture for atomic operations"
#endif
}

GIT3_INLINE(volatile void *) git3_atomic__swap(
	void * volatile *ptr, void *newval)
{
#if defined(GIT3_WIN32)
	return InterlockedExchangePointer(ptr, newval);
#elif defined(GIT3_BUILTIN_ATOMIC)
	void * foundval = NULL;
	__atomic_exchange(ptr, &newval, &foundval, __ATOMIC_SEQ_CST);
	return foundval;
#elif defined(GIT3_BUILTIN_SYNC)
	return (volatile void *)__sync_lock_test_and_set(ptr, newval);
#else
#	error "Unsupported architecture for atomic operations"
#endif
}

GIT3_INLINE(volatile void *) git3_atomic__load(void * volatile *ptr)
{
#if defined(GIT3_WIN32)
	void *newval = NULL, *oldval = NULL;
	return (volatile void *)InterlockedCompareExchangePointer((volatile PVOID *)ptr, newval, oldval);
#elif defined(GIT3_BUILTIN_ATOMIC)
	return (volatile void *)__atomic_load_n(ptr, __ATOMIC_SEQ_CST);
#elif defined(GIT3_BUILTIN_SYNC)
	return (volatile void *)__sync_val_compare_and_swap(ptr, 0, 0);
#else
#	error "Unsupported architecture for atomic operations"
#endif
}

#ifdef GIT3_ARCH_64

/*
 * Atomically adds the contents of *a and addend, and stores the result back into *a.
 * @return the result of the operation.
 */
GIT3_INLINE(int64_t) git3_atomic64_add(git3_atomic64 *a, int64_t addend)
{
#if defined(GIT3_WIN32)
	return InterlockedAdd64(&a->val, addend);
#elif defined(GIT3_BUILTIN_ATOMIC)
	return __atomic_add_fetch(&a->val, addend, __ATOMIC_SEQ_CST);
#elif defined(GIT3_BUILTIN_SYNC)
	return __sync_add_and_fetch(&a->val, addend);
#else
#	error "Unsupported architecture for atomic operations"
#endif
}

/*
 * Atomically sets the contents of *a to be val.
 */
GIT3_INLINE(void) git3_atomic64_set(git3_atomic64 *a, int64_t val)
{
#if defined(GIT3_WIN32)
	InterlockedExchange64(&a->val, val);
#elif defined(GIT3_BUILTIN_ATOMIC)
	__atomic_store_n(&a->val, val, __ATOMIC_SEQ_CST);
#elif defined(GIT3_BUILTIN_SYNC)
	__sync_lock_test_and_set(&a->val, val);
#else
#	error "Unsupported architecture for atomic operations"
#endif
}

/*
 * Atomically gets the contents of *a.
 * @return the contents of *a.
 */
GIT3_INLINE(int64_t) git3_atomic64_get(git3_atomic64 *a)
{
#if defined(GIT3_WIN32)
	return (int64_t)InterlockedCompareExchange64(&a->val, 0, 0);
#elif defined(GIT3_BUILTIN_ATOMIC)
	return __atomic_load_n(&a->val, __ATOMIC_SEQ_CST);
#elif defined(GIT3_BUILTIN_SYNC)
	return __sync_val_compare_and_swap(&a->val, 0, 0);
#else
#	error "Unsupported architecture for atomic operations"
#endif
}

#endif

#else

#define git3_threads_global_init	git3__noop

#define git3_thread unsigned int
#define git3_thread_create(t, s, a) git3__noop(t, s, a)
#define git3_thread_join(i, s)	git3__noop_args(i, s)

/* Pthreads Mutex */
#define git3_mutex unsigned int
#define git3_mutex_init(a)	git3__noop_args(a)
#define git3_mutex_init(a)	git3__noop_args(a)
#define git3_mutex_lock(a)	git3__noop_args(a)
#define git3_mutex_unlock(a)	git3__noop_args(a)
#define git3_mutex_free(a)	git3__noop_args(a)

/* Pthreads condition vars */
#define git3_cond unsigned int
#define git3_cond_init(c)	git3__noop_args(c)
#define git3_cond_free(c)	git3__noop_args(c)
#define git3_cond_wait(c, l)	git3__noop_args(c, l)
#define git3_cond_signal(c)	git3__noop_args(c)
#define git3_cond_broadcast(c)	git3__noop_args(c)

/* Pthreads rwlock */
#define git3_rwlock unsigned int
#define git3_rwlock_init(a)	git3__noop_args(a)
#define git3_rwlock_rdlock(a)	git3__noop_args(a)
#define git3_rwlock_rdunlock(a)	git3__noop_args(a)
#define git3_rwlock_wrlock(a)	git3__noop_args(a)
#define git3_rwlock_wrunlock(a)	git3__noop_args(a)
#define git3_rwlock_free(a)	git3__noop_args(a)

#define GIT3_RWLOCK_STATIC_INIT	0


GIT3_INLINE(void) git3_atomic32_set(git3_atomic32 *a, int val)
{
	a->val = val;
}

GIT3_INLINE(int) git3_atomic32_inc(git3_atomic32 *a)
{
	return ++a->val;
}

GIT3_INLINE(int) git3_atomic32_add(git3_atomic32 *a, int32_t addend)
{
	a->val += addend;
	return a->val;
}

GIT3_INLINE(int) git3_atomic32_dec(git3_atomic32 *a)
{
	return --a->val;
}

GIT3_INLINE(int) git3_atomic32_get(git3_atomic32 *a)
{
	return (int)a->val;
}

GIT3_INLINE(void *) git3_atomic__compare_and_swap(
	void * volatile *ptr, void *oldval, void *newval)
{
	void *foundval = *ptr;
	if (foundval == oldval)
		*ptr = newval;
	return foundval;
}

GIT3_INLINE(volatile void *) git3_atomic__swap(
	void * volatile *ptr, void *newval)
{
	volatile void *old = *ptr;
	*ptr = newval;
	return old;
}

GIT3_INLINE(volatile void *) git3_atomic__load(void * volatile *ptr)
{
	return *ptr;
}

#ifdef GIT3_ARCH_64

GIT3_INLINE(int64_t) git3_atomic64_add(git3_atomic64 *a, int64_t addend)
{
	a->val += addend;
	return a->val;
}

GIT3_INLINE(void) git3_atomic64_set(git3_atomic64 *a, int64_t val)
{
	a->val = val;
}

GIT3_INLINE(int64_t) git3_atomic64_get(git3_atomic64 *a)
{
	return (int64_t)a->val;
}

#endif

#endif

/*
 * Atomically replace the contents of *ptr (if they are equal to oldval) with
 * newval. ptr must point to a pointer or a value that is the same size as a
 * pointer. This is semantically compatible with:
 *
 *   #define git3_atomic_compare_and_swap(ptr, oldval, newval) \
 *   ({                                                       \
 *       void *foundval = *ptr;                               \
 *       if (foundval == oldval)                              \
 *           *ptr = newval;                                   \
 *       foundval;                                            \
 *   })
 *
 * @return the original contents of *ptr.
 */
#define git3_atomic_compare_and_swap(ptr, oldval, newval) \
	git3_atomic__compare_and_swap((void * volatile *)ptr, oldval, newval)

/*
 * Atomically replace the contents of v with newval. v must be the same size as
 * a pointer. This is semantically compatible with:
 *
 *   #define git3_atomic_swap(v, newval) \
 *   ({                                 \
 *       volatile void *old = v;        \
 *       v = newval;                    \
 *       old;                           \
 *   })
 *
 * @return the original contents of v.
 */
#define git3_atomic_swap(v, newval) \
	(void *)git3_atomic__swap((void * volatile *)&(v), newval)

/*
 * Atomically reads the contents of v. v must be the same size as a pointer.
 * This is semantically compatible with:
 *
 *   #define git3_atomic_load(v) v
 *
 * @return the contents of v.
 */
#define git3_atomic_load(v) \
	(void *)git3_atomic__load((void * volatile *)&(v))

#if defined(GIT3_THREADS)

# if defined(GIT3_WIN32)
#  define GIT3_MEMORY_BARRIER MemoryBarrier()
# elif defined(GIT3_BUILTIN_ATOMIC)
#  define GIT3_MEMORY_BARRIER __atomic_thread_fence(__ATOMIC_SEQ_CST)
# elif defined(GIT3_BUILTIN_SYNC)
#  define GIT3_MEMORY_BARRIER __sync_synchronize()
# endif

#else

# define GIT3_MEMORY_BARRIER /* noop */

#endif

/* Thread-local data */

#if !defined(GIT3_THREADS)
# define git3_tlsdata_key int
#elif defined(GIT3_WIN32)
# define git3_tlsdata_key DWORD
#elif defined(_POSIX_THREADS)
# define git3_tlsdata_key pthread_key_t
#else
# error unknown threading model
#endif

/**
 * Create a thread-local data key.  The destroy function will be
 * called upon thread exit.  On some platforms, it may be called
 * when all threads have deleted their keys.
 *
 * Note that the tlsdata functions do not set an error message on
 * failure; this is because the error handling in libgit3 is itself
 * handled by thread-local data storage.
 *
 * @param key the tlsdata key
 * @param destroy_fn function pointer called upon thread exit
 * @return 0 on success, non-zero on failure
 */
int git3_tlsdata_init(git3_tlsdata_key *key, void (GIT3_SYSTEM_CALL *destroy_fn)(void *));

/**
 * Set a the thread-local value for the given key.
 *
 * @param key the tlsdata key to store data on
 * @param value the pointer to store
 * @return 0 on success, non-zero on failure
 */
int git3_tlsdata_set(git3_tlsdata_key key, void *value);

/**
 * Get the thread-local value for the given key.
 *
 * @param key the tlsdata key to retrieve the value of
 * @return the pointer stored with git3_tlsdata_set
 */
void *git3_tlsdata_get(git3_tlsdata_key key);

/**
 * Delete the given thread-local key.
 *
 * @param key the tlsdata key to dispose
 * @return 0 on success, non-zero on failure
 */
int git3_tlsdata_dispose(git3_tlsdata_key key);

#endif
