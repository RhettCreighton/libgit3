/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_sys_git_filter_h__
#define INCLUDE_sys_git_filter_h__

#include "git3/filter.h"

/**
 * @file git3/sys/filter.h
 * @brief Custom filter backends and plugins
 * @defgroup git3_backend Custom filter backends and plugins
 * @ingroup Git
 * @{
 */
GIT3_BEGIN_DECL

/**
 * Look up a filter by name
 *
 * @param name The name of the filter
 * @return Pointer to the filter object or NULL if not found
 */
GIT3_EXTERN(git3_filter *) git3_filter_lookup(const char *name);

/** The "crlf" filter */
#define GIT3_FILTER_CRLF  "crlf"

/** The "ident" filter */
#define GIT3_FILTER_IDENT "ident"

/**
 * This is priority that the internal CRLF filter will be registered with
 */
#define GIT3_FILTER_CRLF_PRIORITY 0

/**
 * This is priority that the internal ident filter will be registered with
 */
#define GIT3_FILTER_IDENT_PRIORITY 100

/**
 * This is priority to use with a custom filter to imitate a core Git
 * filter driver, so that it will be run last on checkout and first on
 * checkin.  You do not have to use this, but it helps compatibility.
 */
#define GIT3_FILTER_DRIVER_PRIORITY 200

/**
 * Create a new empty filter list
 *
 * Normally you won't use this because `git3_filter_list_load` will create
 * the filter list for you, but you can use this in combination with the
 * `git3_filter_lookup` and `git3_filter_list_push` functions to assemble
 * your own chains of filters.
 *
 * @param out the filter list
 * @param repo the repository to use for configuration
 * @param mode the filter mode (direction)
 * @param options the options
 * @return 0 on success or an error code
 */
GIT3_EXTERN(int) git3_filter_list_new(
	git3_filter_list **out,
	git3_repository *repo,
	git3_filter_mode_t mode,
	uint32_t options);

/**
 * Add a filter to a filter list with the given payload.
 *
 * Normally you won't have to do this because the filter list is created
 * by calling the "check" function on registered filters when the filter
 * attributes are set, but this does allow more direct manipulation of
 * filter lists when desired.
 *
 * Note that normally the "check" function can set up a payload for the
 * filter.  Using this function, you can either pass in a payload if you
 * know the expected payload format, or you can pass NULL.  Some filters
 * may fail with a NULL payload.  Good luck!
 *
 * @param fl the filter list
 * @param filter the filter to push
 * @param payload the payload for the filter
 * @return 0 on success or an error code
 */
GIT3_EXTERN(int) git3_filter_list_push(
	git3_filter_list *fl, git3_filter *filter, void *payload);

/**
 * Look up how many filters are in the list
 *
 * We will attempt to apply all of these filters to any data passed in,
 * but note that the filter apply action still has the option of skipping
 * data that is passed in (for example, the CRLF filter will skip data
 * that appears to be binary).
 *
 * @param fl A filter list
 * @return The number of filters in the list
 */
GIT3_EXTERN(size_t) git3_filter_list_length(const git3_filter_list *fl);

/**
 * A filter source represents a file/blob to be processed
 */
typedef struct git3_filter_source git3_filter_source;

/**
 * Get the repository that the source data is coming from.
 *
 * @param src the filter source
 * @return the repository for the filter information
 */
GIT3_EXTERN(git3_repository *) git3_filter_source_repo(const git3_filter_source *src);

/**
 * Get the path that the source data is coming from.
 *
 * @param src the filter source
 * @return the path that is being filtered
 */
GIT3_EXTERN(const char *) git3_filter_source_path(const git3_filter_source *src);

/**
 * Get the file mode of the source file
 * If the mode is unknown, this will return 0
 *
 * @param src the filter source
 * @return the file mode for the file being filtered
 */
GIT3_EXTERN(uint16_t) git3_filter_source_filemode(const git3_filter_source *src);

/**
 * Get the OID of the source
 * If the OID is unknown (often the case with GIT3_FILTER_CLEAN) then
 * this will return NULL.
 *
 * @param src the filter source
 * @return the object id of the file being filtered
 */
GIT3_EXTERN(const git3_oid *) git3_filter_source_id(const git3_filter_source *src);

/**
 * Get the git3_filter_mode_t to be used
 *
 * @param src the filter source
 * @return the mode (direction) of the filter
 */
GIT3_EXTERN(git3_filter_mode_t) git3_filter_source_mode(const git3_filter_source *src);

/**
 * Get the combination git3_filter_flag_t options to be applied
 *
 * @param src the filter source
 * @return the flags of the filter
 */
GIT3_EXTERN(uint32_t) git3_filter_source_flags(const git3_filter_source *src);

/**
 * Initialize callback on filter
 *
 * Specified as `filter.initialize`, this is an optional callback invoked
 * before a filter is first used.  It will be called once at most.
 *
 * If non-NULL, the filter's `initialize` callback will be invoked right
 * before the first use of the filter, so you can defer expensive
 * initialization operations (in case libgit3 is being used in a way that
 * doesn't need the filter).
 *
 * @param self the filter to initialize
 * @return 0 on success, negative number on failure
 */
typedef int GIT3_CALLBACK(git3_filter_init_fn)(git3_filter *self);

/**
 * Shutdown callback on filter
 *
 * Specified as `filter.shutdown`, this is an optional callback invoked
 * when the filter is unregistered or when libgit3 is shutting down.  It
 * will be called once at most and should release resources as needed.
 * This may be called even if the `initialize` callback was not made.
 *
 * Typically this function will free the `git3_filter` object itself.
 *
 * @param self the filter to shutdown
 */
typedef void GIT3_CALLBACK(git3_filter_shutdown_fn)(git3_filter *self);

/**
 * Callback to decide if a given source needs this filter
 *
 * Specified as `filter.check`, this is an optional callback that checks
 * if filtering is needed for a given source.
 *
 * It should return 0 if the filter should be applied (i.e. success),
 * GIT3_PASSTHROUGH if the filter should not be applied, or an error code
 * to fail out of the filter processing pipeline and return to the caller.
 *
 * The `attr_values` will be set to the values of any attributes given in
 * the filter definition.  See `git3_filter` below for more detail.
 *
 * The `payload` will be a pointer to a reference payload for the filter.
 * This will start as NULL, but `check` can assign to this pointer for
 * later use by the `stream` callback.  Note that the value should be heap
 * allocated (not stack), so that it doesn't go away before the `stream`
 * callback can use it.  If a filter allocates and assigns a value to the
 * `payload`, it will need a `cleanup` callback to free the payload.
 *
 * @param self the filter check
 * @param payload a data for future filter functions
 * @param src the filter source
 * @param attr_values the attribute values
 * @return 0 on success or a negative value on error
 */
typedef int GIT3_CALLBACK(git3_filter_check_fn)(
	git3_filter              *self,
	void                   **payload, /* NULL on entry, may be set */
	const git3_filter_source *src,
	const char             **attr_values);

#ifndef GIT3_DEPRECATE_HARD
/**
 * Callback to actually perform the data filtering
 *
 * Specified as `filter.apply`, this is the callback that actually filters
 * data.  If it successfully writes the output, it should return 0.  Like
 * `check`, it can return GIT3_PASSTHROUGH to indicate that the filter
 * doesn't want to run.  Other error codes will stop filter processing and
 * return to the caller.
 *
 * The `payload` value will refer to any payload that was set by the
 * `check` callback.  It may be read from or written to as needed.
 *
 * @param self the filter check
 * @param payload a data for future filter functions
 * @param to the input buffer
 * @param from the output buffer
 * @param src the filter source
 * @return 0 on success or a negative value on error
 * @deprecated use git3_filter_stream_fn
 */
typedef int GIT3_CALLBACK(git3_filter_apply_fn)(
	git3_filter              *self,
	void                   **payload, /* may be read and/or set */
	git3_buf                 *to,
	const git3_buf           *from,
	const git3_filter_source *src);
#endif

/**
 * Callback to perform the data filtering.
 *
 * Specified as `filter.stream`, this is a callback that filters data
 * in a streaming manner.  This function will provide a
 * `git3_writestream` that will the original data will be written to;
 * with that data, the `git3_writestream` will then perform the filter
 * translation and stream the filtered data out to the `next` location.
 *
 * @param out the write stream
 * @param self the filter
 * @param payload a data for future filter functions
 * @param src the filter source
 * @param next the output stream
 * @return 0 on success or a negative value on error
 */
typedef int GIT3_CALLBACK(git3_filter_stream_fn)(
	git3_writestream        **out,
	git3_filter              *self,
	void                   **payload,
	const git3_filter_source *src,
	git3_writestream         *next);

/**
 * Callback to clean up after filtering has been applied
 *
 * Specified as `filter.cleanup`, this is an optional callback invoked
 * after the filter has been applied.  If the `check`, `apply`, or
 * `stream` callbacks allocated a `payload` to keep per-source filter
 * state, use this callback to free that payload and release resources
 * as required.
 *
 * @param self the filter
 * @param payload a data for future filter functions
 */
typedef void GIT3_CALLBACK(git3_filter_cleanup_fn)(
	git3_filter              *self,
	void                    *payload);

/**
 * Filter structure used to register custom filters.
 *
 * To associate extra data with a filter, allocate extra data and put the
 * `git3_filter` struct at the start of your data buffer, then cast the
 * `self` pointer to your larger structure when your callback is invoked.
 */
struct git3_filter {
	/** The `version` field should be set to `GIT3_FILTER_VERSION`. */
	unsigned int           version;

 	/**
	 * A whitespace-separated list of attribute names to check for this
	 * filter (e.g. "eol crlf text").  If the attribute name is bare, it
	 * will be simply loaded and passed to the `check` callback.  If it
	 * has a value (i.e. "name=value"), the attribute must match that
	 * value for the filter to be applied.  The value may be a wildcard
	 * (eg, "name=*"), in which case the filter will be invoked for any
	 * value for the given attribute name.  See the attribute parameter
	 * of the `check` callback for the attribute value that was specified.
	 */
	const char            *attributes;

	/** Called when the filter is first used for any file. */
	git3_filter_init_fn     initialize;

	/** Called when the filter is removed or unregistered from the system. */
	git3_filter_shutdown_fn shutdown;

	/**
	 * Called to determine whether the filter should be invoked for a
	 * given file.  If this function returns `GIT3_PASSTHROUGH` then the
	 * `stream` or `apply` functions will not be invoked and the
	 * contents will be passed through unmodified.
	 */
	git3_filter_check_fn    check;

#ifdef GIT3_DEPRECATE_HARD
	void *reserved;
#else
	/**
	 * Provided for backward compatibility; this will apply the
	 * filter to the given contents in a `git3_buf`.  Callers should
	 * provide a `stream` function instead.
	 */
	git3_filter_apply_fn    apply;
#endif

	/**
	 * Called to apply the filter, this function will provide a
	 * `git3_writestream` that will the original data will be
	 * written to; with that data, the `git3_writestream` will then
	 * perform the filter translation and stream the filtered data
	 * out to the `next` location.
	 */
	git3_filter_stream_fn   stream;

	/** Called when the system is done filtering for a file. */
	git3_filter_cleanup_fn  cleanup;
};

/** Current version for the `git3_filter_options` structure */
#define GIT3_FILTER_VERSION 1

/** Static constructor for `git3_filter_options` */
#define GIT3_FILTER_INIT {GIT3_FILTER_VERSION}

/**
 * Initializes a `git3_filter` with default values. Equivalent to
 * creating an instance with GIT3_FILTER_INIT.
 *
 * @param filter the `git3_filter` struct to initialize.
 * @param version Version the struct; pass `GIT3_FILTER_VERSION`
 * @return 0 on success; -1 on failure.
 */
GIT3_EXTERN(int) git3_filter_init(git3_filter *filter, unsigned int version);

/**
 * Register a filter under a given name with a given priority.
 *
 * As mentioned elsewhere, the initialize callback will not be invoked
 * immediately.  It is deferred until the filter is used in some way.
 *
 * A filter's attribute checks and `check` and `stream` (or `apply`)
 * callbacks will be issued in order of `priority` on smudge (to
 * workdir), and in reverse order of `priority` on clean (to odb).
 *
 * Two filters are preregistered with libgit3:
 * - GIT3_FILTER_CRLF with priority 0
 * - GIT3_FILTER_IDENT with priority 100
 *
 * Currently the filter registry is not thread safe, so any registering or
 * deregistering of filters must be done outside of any possible usage of
 * the filters (i.e. during application setup or shutdown).
 *
 * @param name A name by which the filter can be referenced.  Attempting
 * 			to register with an in-use name will return GIT3_EEXISTS.
 * @param filter The filter definition.  This pointer will be stored as is
 * 			by libgit3 so it must be a durable allocation (either static
 * 			or on the heap).
 * @param priority The priority for filter application
 * @return 0 on successful registry, error code <0 on failure
 */
GIT3_EXTERN(int) git3_filter_register(
	const char *name, git3_filter *filter, int priority);

/**
 * Remove the filter with the given name
 *
 * Attempting to remove the builtin libgit3 filters is not permitted and
 * will return an error.
 *
 * Currently the filter registry is not thread safe, so any registering or
 * deregistering of filters must be done outside of any possible usage of
 * the filters (i.e. during application setup or shutdown).
 *
 * @param name The name under which the filter was registered
 * @return 0 on success, error code <0 on failure
 */
GIT3_EXTERN(int) git3_filter_unregister(const char *name);

/** @} */
GIT3_END_DECL

#endif
