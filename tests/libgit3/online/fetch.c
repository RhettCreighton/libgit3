#include "clar_libgit3.h"
#include "futils.h"

static git3_repository *_repo;
static int counter;

static char *_remote_proxy_scheme = NULL;
static char *_remote_proxy_host = NULL;
static char *_remote_proxy_user = NULL;
static char *_remote_proxy_pass = NULL;
static char *_remote_redirect_initial = NULL;
static char *_remote_redirect_subsequent = NULL;

void test_online_fetch__initialize(void)
{
	cl_git_pass(git3_repository_init(&_repo, "./fetch", 0));

	_remote_proxy_scheme = cl_getenv("GITTEST_REMOTE_PROXY_SCHEME");
	_remote_proxy_host = cl_getenv("GITTEST_REMOTE_PROXY_HOST");
	_remote_proxy_user = cl_getenv("GITTEST_REMOTE_PROXY_USER");
	_remote_proxy_pass = cl_getenv("GITTEST_REMOTE_PROXY_PASS");
	_remote_redirect_initial = cl_getenv("GITTEST_REMOTE_REDIRECT_INITIAL");
	_remote_redirect_subsequent = cl_getenv("GITTEST_REMOTE_REDIRECT_SUBSEQUENT");
}

void test_online_fetch__cleanup(void)
{
	git3_repository_free(_repo);
	_repo = NULL;

	cl_fixture_cleanup("./fetch");
	cl_fixture_cleanup("./redirected");

	git3__free(_remote_proxy_scheme);
	git3__free(_remote_proxy_host);
	git3__free(_remote_proxy_user);
	git3__free(_remote_proxy_pass);
	git3__free(_remote_redirect_initial);
	git3__free(_remote_redirect_subsequent);
}

static int update_refs(const char *refname, const git3_oid *a, const git3_oid *b, git3_refspec *spec, void *data)
{
	GIT3_UNUSED(refname);
	GIT3_UNUSED(a);
	GIT3_UNUSED(b);
	GIT3_UNUSED(spec);
	GIT3_UNUSED(data);

	++counter;

	return 0;
}

static int progress(const git3_indexer_progress *stats, void *payload)
{
	size_t *bytes_received = (size_t *)payload;
	*bytes_received = stats->received_bytes;
	return 0;
}

static void do_fetch(const char *url, git3_remote_autotag_option_t flag, int n)
{
	git3_remote *remote;
	git3_fetch_options options = GIT3_FETCH_OPTIONS_INIT;
	size_t bytes_received = 0;

	options.callbacks.transfer_progress = progress;
	options.callbacks.update_refs = update_refs;
	options.callbacks.payload = &bytes_received;
	options.download_tags = flag;
	counter = 0;

	cl_git_pass(git3_remote_create(&remote, _repo, "test", url));
	cl_git_pass(git3_remote_fetch(remote, NULL, &options, NULL));
	cl_assert_equal_i(counter, n);
	cl_assert(bytes_received > 0);

	git3_remote_free(remote);
}

void test_online_fetch__default_http(void)
{
	do_fetch("http://github.com/libgit3/TestGitRepository.git", GIT3_REMOTE_DOWNLOAD_TAGS_AUTO, 6);
}

void test_online_fetch__default_https(void)
{
	do_fetch("https://github.com/libgit3/TestGitRepository.git", GIT3_REMOTE_DOWNLOAD_TAGS_AUTO, 6);
}

void test_online_fetch__no_tags_git(void)
{
	do_fetch("https://github.com/libgit3/TestGitRepository.git", GIT3_REMOTE_DOWNLOAD_TAGS_NONE, 3);
}

void test_online_fetch__no_tags_http(void)
{
	do_fetch("http://github.com/libgit3/TestGitRepository.git", GIT3_REMOTE_DOWNLOAD_TAGS_NONE, 3);
}

void test_online_fetch__fetch_twice(void)
{
	git3_remote *remote;
	cl_git_pass(git3_remote_create(&remote, _repo, "test", "https://github.com/libgit3/TestGitRepository.git"));
	cl_git_pass(git3_remote_connect(remote, GIT3_DIRECTION_FETCH, NULL, NULL, NULL));
	cl_git_pass(git3_remote_download(remote, NULL, NULL));
    	git3_remote_disconnect(remote);

	git3_remote_connect(remote, GIT3_DIRECTION_FETCH, NULL, NULL, NULL);
	cl_git_pass(git3_remote_download(remote, NULL, NULL));
	git3_remote_disconnect(remote);

	git3_remote_free(remote);
}

void test_online_fetch__fetch_with_empty_http_proxy(void)
{
	git3_remote *remote;
	git3_config *config;
	git3_fetch_options opts = GIT3_FETCH_OPTIONS_INIT;

	opts.proxy_opts.type = GIT3_PROXY_AUTO;

	cl_git_pass(git3_repository_config(&config, _repo));
	cl_git_pass(git3_config_set_string(config, "http.proxy", ""));

	cl_git_pass(git3_remote_create(&remote, _repo, "test",
		"https://github.com/libgit3/TestGitRepository"));
	cl_git_pass(git3_remote_fetch(remote, NULL, &opts, NULL));

	git3_remote_disconnect(remote);
	git3_remote_free(remote);
	git3_config_free(config);
}

static int transferProgressCallback(const git3_indexer_progress *stats, void *payload)
{
	bool *invoked = (bool *)payload;

	GIT3_UNUSED(stats);
	*invoked = true;
	return 0;
}

void test_online_fetch__doesnt_retrieve_a_pack_when_the_repository_is_up_to_date(void)
{
	git3_repository *_repository;
	bool invoked = false;
	git3_remote *remote;
	git3_fetch_options options = GIT3_FETCH_OPTIONS_INIT;
	git3_clone_options opts = GIT3_CLONE_OPTIONS_INIT;
	opts.bare = true;

	counter = 0;

	cl_git_pass(git3_clone(&_repository, "https://github.com/libgit3/TestGitRepository.git",
				"./fetch/lg2", &opts));
	git3_repository_free(_repository);

	cl_git_pass(git3_repository_open(&_repository, "./fetch/lg2"));

	cl_git_pass(git3_remote_lookup(&remote, _repository, "origin"));
	cl_git_pass(git3_remote_connect(remote, GIT3_DIRECTION_FETCH, NULL, NULL, NULL));

	cl_assert_equal_i(false, invoked);

	options.callbacks.transfer_progress = &transferProgressCallback;
	options.callbacks.payload = &invoked;
	options.callbacks.update_refs = update_refs;
	cl_git_pass(git3_remote_download(remote, NULL, &options));

	cl_assert_equal_i(false, invoked);

	cl_git_pass(git3_remote_update_tips(remote, &options.callbacks, GIT3_REMOTE_UPDATE_FETCHHEAD, options.download_tags, NULL));
	cl_assert_equal_i(0, counter);

	git3_remote_disconnect(remote);

	git3_remote_free(remote);
	git3_repository_free(_repository);
}

void test_online_fetch__report_unchanged_tips(void)
{
	git3_repository *_repository;
	bool invoked = false;
	git3_remote *remote;
	git3_fetch_options options = GIT3_FETCH_OPTIONS_INIT;
	git3_clone_options opts = GIT3_CLONE_OPTIONS_INIT;
	opts.bare = true;

	counter = 0;

	cl_git_pass(git3_clone(&_repository, "https://github.com/libgit3/TestGitRepository.git",
				"./fetch/lg2", &opts));
	git3_repository_free(_repository);

	cl_git_pass(git3_repository_open(&_repository, "./fetch/lg2"));

	cl_git_pass(git3_remote_lookup(&remote, _repository, "origin"));
	cl_git_pass(git3_remote_connect(remote, GIT3_DIRECTION_FETCH, NULL, NULL, NULL));

	cl_assert_equal_i(false, invoked);

	options.callbacks.transfer_progress = &transferProgressCallback;
	options.callbacks.payload = &invoked;
	options.callbacks.update_refs = update_refs;
	cl_git_pass(git3_remote_download(remote, NULL, &options));

	cl_assert_equal_i(false, invoked);

	cl_git_pass(git3_remote_update_tips(remote, &options.callbacks, GIT3_REMOTE_UPDATE_REPORT_UNCHANGED, options.download_tags, NULL));
	cl_assert(counter > 0);

	git3_remote_disconnect(remote);

	git3_remote_free(remote);
	git3_repository_free(_repository);
}

static int cancel_at_half(const git3_indexer_progress *stats, void *payload)
{
	GIT3_UNUSED(payload);

	if (stats->received_objects > (stats->total_objects/2))
		return -4321;
	return 0;
}

void test_online_fetch__can_cancel(void)
{
	git3_remote *remote;
	size_t bytes_received = 0;
	git3_fetch_options options = GIT3_FETCH_OPTIONS_INIT;

	cl_git_pass(git3_remote_create(&remote, _repo, "test",
				"http://github.com/libgit3/TestGitRepository.git"));

	options.callbacks.transfer_progress = cancel_at_half;
	options.callbacks.payload = &bytes_received;

	cl_git_pass(git3_remote_connect(remote, GIT3_DIRECTION_FETCH, NULL, NULL, NULL));
	cl_git_fail_with(git3_remote_download(remote, NULL, &options), -4321);
	git3_remote_disconnect(remote);
	git3_remote_free(remote);
}

void test_online_fetch__ls_disconnected(void)
{
	const git3_remote_head **refs;
	size_t refs_len_before, refs_len_after;
	git3_remote *remote;

	cl_git_pass(git3_remote_create(&remote, _repo, "test",
				"http://github.com/libgit3/TestGitRepository.git"));
	cl_git_pass(git3_remote_connect(remote, GIT3_DIRECTION_FETCH, NULL, NULL, NULL));
	cl_git_pass(git3_remote_ls(&refs, &refs_len_before, remote));
	git3_remote_disconnect(remote);
	cl_git_pass(git3_remote_ls(&refs, &refs_len_after, remote));

	cl_assert_equal_i(refs_len_before, refs_len_after);

	git3_remote_free(remote);
}

void test_online_fetch__remote_symrefs(void)
{
	const git3_remote_head **refs;
	size_t refs_len;
	git3_remote *remote;

	cl_git_pass(git3_remote_create(&remote, _repo, "test",
				"http://github.com/libgit3/TestGitRepository.git"));
	cl_git_pass(git3_remote_connect(remote, GIT3_DIRECTION_FETCH, NULL, NULL, NULL));
	git3_remote_disconnect(remote);
	cl_git_pass(git3_remote_ls(&refs, &refs_len, remote));

	cl_assert_equal_s("HEAD", refs[0]->name);
	cl_assert_equal_s("refs/heads/master", refs[0]->symref_target);

	git3_remote_free(remote);
}

void test_online_fetch__twice(void)
{
	git3_remote *remote;

	cl_git_pass(git3_remote_create(&remote, _repo, "test", "http://github.com/libgit3/TestGitRepository.git"));
	cl_git_pass(git3_remote_fetch(remote, NULL, NULL, NULL));
	cl_git_pass(git3_remote_fetch(remote, NULL, NULL, NULL));

	git3_remote_free(remote);
}

void test_online_fetch__proxy(void)
{
    git3_remote *remote;
    git3_str url = GIT3_STR_INIT;
    git3_fetch_options fetch_opts;

    if (!_remote_proxy_host || !_remote_proxy_user || !_remote_proxy_pass)
        cl_skip();

    cl_git_pass(git3_str_printf(&url, "%s://%s:%s@%s/",
        _remote_proxy_scheme ? _remote_proxy_scheme : "http",
        _remote_proxy_user, _remote_proxy_pass, _remote_proxy_host));

    cl_git_pass(git3_fetch_options_init(&fetch_opts, GIT3_FETCH_OPTIONS_VERSION));
    fetch_opts.proxy_opts.type = GIT3_PROXY_SPECIFIED;
    fetch_opts.proxy_opts.url = url.ptr;

    cl_git_pass(git3_remote_create(&remote, _repo, "test", "https://github.com/libgit3/TestGitRepository.git"));
    cl_git_pass(git3_remote_connect(remote, GIT3_DIRECTION_FETCH, NULL, &fetch_opts.proxy_opts, NULL));
    cl_git_pass(git3_remote_fetch(remote, NULL, &fetch_opts, NULL));

    git3_remote_free(remote);
    git3_str_dispose(&url);
}

static int do_redirected_fetch(const char *url, const char *name, const char *config)
{
	git3_repository *repo;
	git3_remote *remote;
	int error;

	cl_git_pass(git3_repository_init(&repo, "./redirected", 0));
	cl_fixture_cleanup(name);

	if (config)
		cl_repo_set_string(repo, "http.followRedirects", config);

	cl_git_pass(git3_remote_create(&remote, repo, name, url));
	error = git3_remote_fetch(remote, NULL, NULL, NULL);

	git3_remote_free(remote);
	git3_repository_free(repo);

	cl_fixture_cleanup("./redirected");

	return error;
}

void test_online_fetch__redirect_config(void)
{
	if (!_remote_redirect_initial || !_remote_redirect_subsequent)
		cl_skip();

	/* config defaults */
	cl_git_pass(do_redirected_fetch(_remote_redirect_initial, "initial", NULL));
	cl_git_fail(do_redirected_fetch(_remote_redirect_subsequent, "subsequent", NULL));

	/* redirect=initial */
	cl_git_pass(do_redirected_fetch(_remote_redirect_initial, "initial", "initial"));
	cl_git_fail(do_redirected_fetch(_remote_redirect_subsequent, "subsequent", "initial"));

	/* redirect=false */
	cl_git_fail(do_redirected_fetch(_remote_redirect_initial, "initial", "false"));
	cl_git_fail(do_redirected_fetch(_remote_redirect_subsequent, "subsequent", "false"));
}

void test_online_fetch__reachable_commit(void)
{
	git3_remote *remote;
	git3_strarray refspecs;
	git3_object *obj;
	git3_oid expected_id;
	git3_str fetchhead = GIT3_STR_INIT;
	char *refspec = "+2c349335b7f797072cf729c4f3bb0914ecb6dec9:refs/success";

	refspecs.strings = &refspec;
	refspecs.count = 1;

	git3_oid_from_string(&expected_id, "2c349335b7f797072cf729c4f3bb0914ecb6dec9", GIT3_OID_SHA1);

	cl_git_pass(git3_remote_create(&remote, _repo, "test",
		"https://github.com/libgit3/TestGitRepository"));
	cl_git_pass(git3_remote_fetch(remote, &refspecs, NULL, NULL));

	cl_git_pass(git3_revparse_single(&obj, _repo, "refs/success"));
	cl_assert_equal_oid(&expected_id, git3_object_id(obj));

	cl_git_pass(git3_futils_readbuffer(&fetchhead, "./fetch/.git/FETCH_HEAD"));
	cl_assert_equal_s(fetchhead.ptr,
		"2c349335b7f797072cf729c4f3bb0914ecb6dec9\t\t'2c349335b7f797072cf729c4f3bb0914ecb6dec9' of https://github.com/libgit3/TestGitRepository\n");

	git3_str_dispose(&fetchhead);
	git3_object_free(obj);
	git3_remote_free(remote);
}

void test_online_fetch__reachable_commit_without_destination(void)
{
	git3_remote *remote;
	git3_strarray refspecs;
	git3_object *obj;
	git3_oid expected_id;
	git3_str fetchhead = GIT3_STR_INIT;
	char *refspec = "2c349335b7f797072cf729c4f3bb0914ecb6dec9";

	refspecs.strings = &refspec;
	refspecs.count = 1;

	git3_oid_from_string(&expected_id, "2c349335b7f797072cf729c4f3bb0914ecb6dec9", GIT3_OID_SHA1);

	cl_git_pass(git3_remote_create(&remote, _repo, "test",
		"https://github.com/libgit3/TestGitRepository"));
	cl_git_pass(git3_remote_fetch(remote, &refspecs, NULL, NULL));

	cl_git_fail_with(GIT3_ENOTFOUND, git3_revparse_single(&obj, _repo, "refs/success"));

	cl_git_pass(git3_futils_readbuffer(&fetchhead, "./fetch/.git/FETCH_HEAD"));
	cl_assert_equal_s(fetchhead.ptr,
		"2c349335b7f797072cf729c4f3bb0914ecb6dec9\t\t'2c349335b7f797072cf729c4f3bb0914ecb6dec9' of https://github.com/libgit3/TestGitRepository\n");

	git3_str_dispose(&fetchhead);
	git3_object_free(obj);
	git3_remote_free(remote);
}
