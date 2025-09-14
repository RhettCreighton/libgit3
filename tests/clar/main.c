#include "clar_libgit3.h"
#include "clar_libgit3_trace.h"

#ifdef GIT3_DEBUG_LEAKCHECK_WIN32
# include "win32/w32_leakcheck.h"
#endif

#ifdef _WIN32
int __cdecl main(int argc, char *argv[])
#else
int main(int argc, char *argv[])
#endif
{
	int res;
	char *at_exit_cmd;

	clar_test_init(argc, argv);

	res = git3_libgit3_init();
	if (res < 0) {
		const git3_error *err = git3_error_last();
		const char *msg = err ? err->message : "unknown failure";
		fprintf(stderr, "failed to init libgit3: %s\n", msg);
		return res;
	}

	cl_global_trace_register();
	cl_sandbox_set_homedir(getenv("CLAR_HOMEDIR"));
	cl_sandbox_set_search_path_defaults();
	cl_sandbox_disable_ownership_validation();

	/* Run the test suite */
	res = clar_test_run();

	clar_test_shutdown();

	cl_global_trace_disable();
	git3_libgit3_shutdown();

#ifdef GIT3_DEBUG_LEAKCHECK_WIN32
	if (git3_win32_leakcheck_has_leaks())
		res = res || 1;
#endif

	at_exit_cmd = getenv("CLAR_AT_EXIT");
	if (at_exit_cmd != NULL) {
		int at_exit = system(at_exit_cmd);
		return res || at_exit;
	}

	return res;
}
