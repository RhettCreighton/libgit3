#include "clar_libgit3.h"
#include <git3/sys/commit_graph.h>
#include <git3/sys/config.h>
#include <git3/sys/filter.h>
#include <git3/sys/odb_backend.h>
#include <git3/sys/refdb_backend.h>
#include <git3/sys/transport.h>

#define STRINGIFY(s) #s

/* Checks two conditions for the specified structure:
 *     1. That the initializers for the latest version produces the same
 *        in-memory representation.
 *     2. That the function-based initializer supports all versions from 1...n,
 *        where n is the latest version (often represented by GIT3_*_VERSION).
 *
 * Parameters:
 *     structname: The name of the structure to test, e.g. git3_blame_options.
 *     structver: The latest version of the specified structure.
 *     macroinit: The macro that initializes the latest version of the structure.
 *     funcinitname: The function that initializes the structure. Must have the
 *                   signature "int (structname* instance, int version)".
 */
#define CHECK_MACRO_FUNC_INIT_EQUAL(structname, structver, macroinit, funcinitname) \
do { \
	structname structname##_macro_latest = macroinit; \
	structname structname##_func_latest; \
	int structname##_curr_ver = structver - 1; \
	memset(&structname##_func_latest, 0, sizeof(structname##_func_latest)); \
	cl_git_pass(funcinitname(&structname##_func_latest, structver)); \
	options_cmp(&structname##_macro_latest, &structname##_func_latest, \
		sizeof(structname), STRINGIFY(structname)); \
	\
	while (structname##_curr_ver > 0) \
	{ \
		structname macro; \
		cl_git_pass(funcinitname(&macro, structname##_curr_ver)); \
		structname##_curr_ver--; \
	}\
} while(0)

static void options_cmp(void *one, void *two, size_t size, const char *name)
{
	size_t i;

	for (i = 0; i < size; i++) {
		if (((char *)one)[i] != ((char *)two)[i]) {
			char desc[1024];

			p_snprintf(desc, 1024, "Difference in %s at byte %" PRIuZ ": macro=%u / func=%u",
				name, i, ((char *)one)[i], ((char *)two)[i]);
			clar__fail(__FILE__, __func__, __LINE__,
				"Difference between macro and function options initializer",
				desc, 0);
			return;
		}
	}
}

void test_core_structinit__compare(void)
{
	/* These tests assume that they can memcmp() two structures that were
	 * initialized with the same static initializer.  Eg,
	 * git3_blame_options = GIT3_BLAME_OPTIONS_INIT;
	 *
	 * This assumption fails when there is padding between structure members,
	 * which is not guaranteed to be initialized to anything sane at all.
	 *
	 * Assume most compilers, in a debug build, will clear that memory for
	 * us or set it to sentinel markers.  Etc.
	 */
#if !defined(DEBUG) && !defined(_DEBUG)
	clar__skip();
#endif

	/* apply */
	CHECK_MACRO_FUNC_INIT_EQUAL( \
		git3_apply_options, GIT3_APPLY_OPTIONS_VERSION, \
		GIT3_APPLY_OPTIONS_INIT, git3_apply_options_init);

	/* blame */
	CHECK_MACRO_FUNC_INIT_EQUAL( \
		git3_blame_options, GIT3_BLAME_OPTIONS_VERSION, \
		GIT3_BLAME_OPTIONS_INIT, git3_blame_options_init);

	/* blob_filter_options */
	CHECK_MACRO_FUNC_INIT_EQUAL( \
		git3_blob_filter_options, GIT3_BLOB_FILTER_OPTIONS_VERSION, \
		GIT3_BLOB_FILTER_OPTIONS_INIT, git3_blob_filter_options_init);

	/* checkout */
	CHECK_MACRO_FUNC_INIT_EQUAL( \
		git3_checkout_options, GIT3_CHECKOUT_OPTIONS_VERSION, \
		GIT3_CHECKOUT_OPTIONS_INIT, git3_checkout_options_init);

	/* clone */
	CHECK_MACRO_FUNC_INIT_EQUAL( \
		git3_clone_options, GIT3_CLONE_OPTIONS_VERSION, \
		GIT3_CLONE_OPTIONS_INIT, git3_clone_options_init);

	/* commit_graph_writer */
	CHECK_MACRO_FUNC_INIT_EQUAL( \
		git3_commit_graph_writer_options, \
		GIT3_COMMIT_GRAPH_WRITER_OPTIONS_VERSION, \
		GIT3_COMMIT_GRAPH_WRITER_OPTIONS_INIT, \
		git3_commit_graph_writer_options_init);

	/* diff */
	CHECK_MACRO_FUNC_INIT_EQUAL( \
		git3_diff_options, GIT3_DIFF_OPTIONS_VERSION, \
		GIT3_DIFF_OPTIONS_INIT, git3_diff_options_init);

	/* diff_find */
	CHECK_MACRO_FUNC_INIT_EQUAL( \
		git3_diff_find_options, GIT3_DIFF_FIND_OPTIONS_VERSION, \
		GIT3_DIFF_FIND_OPTIONS_INIT, git3_diff_find_options_init);

	/* filter */
	CHECK_MACRO_FUNC_INIT_EQUAL( \
		git3_filter, GIT3_FILTER_VERSION, \
		GIT3_FILTER_INIT, git3_filter_init);

	/* merge_file_input */
	CHECK_MACRO_FUNC_INIT_EQUAL( \
		git3_merge_file_input, GIT3_MERGE_FILE_INPUT_VERSION, \
		GIT3_MERGE_FILE_INPUT_INIT, git3_merge_file_input_init);

	/* merge_file */
	CHECK_MACRO_FUNC_INIT_EQUAL( \
		git3_merge_file_options, GIT3_MERGE_FILE_OPTIONS_VERSION, \
		GIT3_MERGE_FILE_OPTIONS_INIT, git3_merge_file_options_init);

	/* merge_tree */
	CHECK_MACRO_FUNC_INIT_EQUAL( \
		git3_merge_options, GIT3_MERGE_OPTIONS_VERSION, \
		GIT3_MERGE_OPTIONS_INIT, git3_merge_options_init);

	/* push */
	CHECK_MACRO_FUNC_INIT_EQUAL( \
		git3_push_options, GIT3_PUSH_OPTIONS_VERSION, \
		GIT3_PUSH_OPTIONS_INIT, git3_push_options_init);

	/* remote */
	CHECK_MACRO_FUNC_INIT_EQUAL( \
		git3_remote_callbacks, GIT3_REMOTE_CALLBACKS_VERSION, \
		GIT3_REMOTE_CALLBACKS_INIT, git3_remote_init_callbacks);

	/* repository_init */
	CHECK_MACRO_FUNC_INIT_EQUAL( \
		git3_repository_init_options, GIT3_REPOSITORY_INIT_OPTIONS_VERSION, \
		GIT3_REPOSITORY_INIT_OPTIONS_INIT, git3_repository_init_options_init);

	/* revert */
	CHECK_MACRO_FUNC_INIT_EQUAL( \
		git3_revert_options, GIT3_REVERT_OPTIONS_VERSION, \
		GIT3_REVERT_OPTIONS_INIT, git3_revert_options_init);

	/* stash apply */
	CHECK_MACRO_FUNC_INIT_EQUAL( \
		git3_stash_apply_options, GIT3_STASH_APPLY_OPTIONS_VERSION, \
		GIT3_STASH_APPLY_OPTIONS_INIT, git3_stash_apply_options_init);

	/* stash save */
	CHECK_MACRO_FUNC_INIT_EQUAL( \
		git3_stash_save_options, GIT3_STASH_SAVE_OPTIONS_VERSION, \
		GIT3_STASH_SAVE_OPTIONS_INIT, git3_stash_save_options_init);

	/* status */
	CHECK_MACRO_FUNC_INIT_EQUAL( \
		git3_status_options, GIT3_STATUS_OPTIONS_VERSION, \
		GIT3_STATUS_OPTIONS_INIT, git3_status_options_init);

	/* transport */
	CHECK_MACRO_FUNC_INIT_EQUAL( \
		git3_transport, GIT3_TRANSPORT_VERSION, \
		GIT3_TRANSPORT_INIT, git3_transport_init);

	/* config_backend */
	CHECK_MACRO_FUNC_INIT_EQUAL( \
		git3_config_backend, GIT3_CONFIG_BACKEND_VERSION, \
		GIT3_CONFIG_BACKEND_INIT, git3_config_init_backend);

	/* odb_backend */
	CHECK_MACRO_FUNC_INIT_EQUAL( \
		git3_odb_backend, GIT3_ODB_BACKEND_VERSION, \
		GIT3_ODB_BACKEND_INIT, git3_odb_init_backend);

	/* refdb_backend */
	CHECK_MACRO_FUNC_INIT_EQUAL( \
		git3_refdb_backend, GIT3_REFDB_BACKEND_VERSION, \
		GIT3_REFDB_BACKEND_INIT, git3_refdb_init_backend);

	/* submodule update */
	CHECK_MACRO_FUNC_INIT_EQUAL( \
		git3_submodule_update_options, GIT3_SUBMODULE_UPDATE_OPTIONS_VERSION, \
		GIT3_SUBMODULE_UPDATE_OPTIONS_INIT, git3_submodule_update_options_init);

	/* submodule update */
	CHECK_MACRO_FUNC_INIT_EQUAL( \
		git3_proxy_options, GIT3_PROXY_OPTIONS_VERSION, \
		GIT3_PROXY_OPTIONS_INIT, git3_proxy_options_init);

	CHECK_MACRO_FUNC_INIT_EQUAL( \
		git3_diff_patchid_options, GIT3_DIFF_PATCHID_OPTIONS_VERSION, \
		GIT3_DIFF_PATCHID_OPTIONS_INIT, git3_diff_patchid_options_init);
}
