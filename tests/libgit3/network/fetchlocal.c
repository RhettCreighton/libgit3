#include "clar_libgit3.h"

#include "path.h"
#include "remote.h"

static const char* tagger_name = "Vicent Marti";
static const char* tagger_email = "vicent@github.com";
static const char* tagger_message = "This is my tag.\n\nThere are many tags, but this one is mine\n";

static int transfer_cb(const git3_indexer_progress *stats, void *payload)
{
	int *callcount = (int*)payload;
	GIT3_UNUSED(stats);
	(*callcount)++;
	return 0;
}

static void cleanup_local_repo(void *path)
{
	cl_fixture_cleanup((char *)path);
}

void test_network_fetchlocal__cleanup(void)
{
	cl_git_sandbox_cleanup();
}

void test_network_fetchlocal__complete(void)
{
	git3_repository *repo;
	git3_remote *origin;
	int callcount = 0;
	git3_strarray refnames = {0};

	const char *url = cl_git_fixture_url("testrepo.git");
	git3_fetch_options options = GIT3_FETCH_OPTIONS_INIT;

	options.callbacks.transfer_progress = transfer_cb;
	options.callbacks.payload = &callcount;

	cl_set_cleanup(&cleanup_local_repo, "foo");
	cl_git_pass(git3_repository_init(&repo, "foo", true));

	cl_git_pass(git3_remote_create(&origin, repo, GIT3_REMOTE_ORIGIN, url));
	cl_git_pass(git3_remote_fetch(origin, NULL, &options, NULL));

	cl_git_pass(git3_reference_list(&refnames, repo));
	cl_assert_equal_i(20, (int)refnames.count);
	cl_assert(callcount > 0);

	git3_strarray_dispose(&refnames);
	git3_remote_free(origin);
	git3_repository_free(repo);
}

void test_network_fetchlocal__prune(void)
{
	git3_repository *repo;
	git3_remote *origin;
	int callcount = 0;
	git3_strarray refnames = {0};
	git3_reference *ref;
	git3_repository *remote_repo = cl_git_sandbox_init("testrepo.git");
	const char *url = cl_git_path_url(git3_repository_path(remote_repo));
	git3_fetch_options options = GIT3_FETCH_OPTIONS_INIT;

	options.callbacks.transfer_progress = transfer_cb;
	options.callbacks.payload = &callcount;

	cl_set_cleanup(&cleanup_local_repo, "foo");
	cl_git_pass(git3_repository_init(&repo, "foo", true));

	cl_git_pass(git3_remote_create(&origin, repo, GIT3_REMOTE_ORIGIN, url));
	cl_git_pass(git3_remote_fetch(origin, NULL, &options, NULL));

	cl_git_pass(git3_reference_list(&refnames, repo));
	cl_assert_equal_i(20, (int)refnames.count);
	cl_assert(callcount > 0);
	git3_strarray_dispose(&refnames);
	git3_remote_free(origin);

	cl_git_pass(git3_reference_lookup(&ref, remote_repo, "refs/heads/br2"));
	cl_git_pass(git3_reference_delete(ref));
	git3_reference_free(ref);

	cl_git_pass(git3_remote_lookup(&origin, repo, GIT3_REMOTE_ORIGIN));
	cl_git_pass(git3_remote_fetch(origin, NULL, &options, NULL));
	cl_git_pass(git3_remote_prune(origin, &options.callbacks));

	cl_git_pass(git3_reference_list(&refnames, repo));
	cl_assert_equal_i(19, (int)refnames.count);
	git3_strarray_dispose(&refnames);
	git3_remote_free(origin);

	cl_git_pass(git3_reference_lookup(&ref, remote_repo, "refs/heads/packed"));
	cl_git_pass(git3_reference_delete(ref));
	git3_reference_free(ref);

	cl_git_pass(git3_remote_lookup(&origin, repo, GIT3_REMOTE_ORIGIN));
	cl_git_pass(git3_remote_fetch(origin, NULL, &options, NULL));
	cl_git_pass(git3_remote_prune(origin, &options.callbacks));

	cl_git_pass(git3_reference_list(&refnames, repo));
	cl_assert_equal_i(18, (int)refnames.count);
	git3_strarray_dispose(&refnames);
	git3_remote_free(origin);

	git3_repository_free(repo);
}

static int update_refs_fail_on_call(const char *ref, const git3_oid *old, const git3_oid *new, git3_refspec *refspec, void *data)
{
	GIT3_UNUSED(ref);
	GIT3_UNUSED(old);
	GIT3_UNUSED(new);
	GIT3_UNUSED(refspec);
	GIT3_UNUSED(data);

	cl_fail("update refs called");
	return 0;
}

static void assert_ref_exists(git3_repository *repo, const char *name)
{
	git3_reference *ref;

	cl_git_pass(git3_reference_lookup(&ref, repo, name));
	git3_reference_free(ref);
}

void test_network_fetchlocal__prune_overlapping(void)
{
	git3_repository *repo;
	git3_remote *origin;
	int callcount = 0;
	git3_strarray refnames = {0};
	git3_reference *ref;
	git3_config *config;
	git3_oid target;

	git3_repository *remote_repo = cl_git_sandbox_init("testrepo.git");
	const char *url = cl_git_path_url(git3_repository_path(remote_repo));

	git3_fetch_options options = GIT3_FETCH_OPTIONS_INIT;
	options.callbacks.transfer_progress = transfer_cb;
	options.callbacks.payload = &callcount;

	cl_git_pass(git3_reference_lookup(&ref, remote_repo, "refs/heads/master"));
	git3_oid_cpy(&target, git3_reference_target(ref));
	git3_reference_free(ref);
	cl_git_pass(git3_reference_create(&ref, remote_repo, "refs/pull/42/head", &target, 1, NULL));
	git3_reference_free(ref);

	cl_set_cleanup(&cleanup_local_repo, "foo");
	cl_git_pass(git3_repository_init(&repo, "foo", true));

	cl_git_pass(git3_remote_create(&origin, repo, GIT3_REMOTE_ORIGIN, url));

	cl_git_pass(git3_repository_config(&config, repo));
	cl_git_pass(git3_config_set_bool(config, "remote.origin.prune", true));
	cl_git_pass(git3_config_set_multivar(config, "remote.origin.fetch", "^$", "refs/pull/*/head:refs/remotes/origin/pr/*"));

	git3_remote_free(origin);
	cl_git_pass(git3_remote_lookup(&origin, repo, GIT3_REMOTE_ORIGIN));
	cl_git_pass(git3_remote_fetch(origin, NULL, &options, NULL));

	assert_ref_exists(repo, "refs/remotes/origin/master");
	assert_ref_exists(repo, "refs/remotes/origin/pr/42");
	cl_git_pass(git3_reference_list(&refnames, repo));
	cl_assert_equal_i(21, (int)refnames.count);
	git3_strarray_dispose(&refnames);

	cl_git_pass(git3_config_delete_multivar(config, "remote.origin.fetch", "refs"));
	cl_git_pass(git3_config_set_multivar(config, "remote.origin.fetch", "^$", "refs/pull/*/head:refs/remotes/origin/pr/*"));
	cl_git_pass(git3_config_set_multivar(config, "remote.origin.fetch", "^$", "refs/heads/*:refs/remotes/origin/*"));

	git3_remote_free(origin);
	cl_git_pass(git3_remote_lookup(&origin, repo, GIT3_REMOTE_ORIGIN));
	options.callbacks.update_refs = update_refs_fail_on_call;
	cl_git_pass(git3_remote_fetch(origin, NULL, &options, NULL));

	assert_ref_exists(repo, "refs/remotes/origin/master");
	assert_ref_exists(repo, "refs/remotes/origin/pr/42");
	cl_git_pass(git3_reference_list(&refnames, repo));
	cl_assert_equal_i(21, (int)refnames.count);
	git3_strarray_dispose(&refnames);

	cl_git_pass(git3_config_delete_multivar(config, "remote.origin.fetch", "refs"));
	cl_git_pass(git3_config_set_multivar(config, "remote.origin.fetch", "^$", "refs/heads/*:refs/remotes/origin/*"));
	cl_git_pass(git3_config_set_multivar(config, "remote.origin.fetch", "^$", "refs/pull/*/head:refs/remotes/origin/pr/*"));

	git3_remote_free(origin);
	cl_git_pass(git3_remote_lookup(&origin, repo, GIT3_REMOTE_ORIGIN));
	options.callbacks.update_refs = update_refs_fail_on_call;
	cl_git_pass(git3_remote_fetch(origin, NULL, &options, NULL));

	git3_config_free(config);
	git3_strarray_dispose(&refnames);
	git3_remote_free(origin);
	git3_repository_free(repo);
}

void test_network_fetchlocal__fetchprune(void)
{
	git3_repository *repo;
	git3_remote *origin;
	int callcount = 0;
	git3_strarray refnames = {0};
	git3_reference *ref;
	git3_config *config;
	git3_repository *remote_repo = cl_git_sandbox_init("testrepo.git");
	const char *url = cl_git_path_url(git3_repository_path(remote_repo));
	git3_fetch_options options = GIT3_FETCH_OPTIONS_INIT;

	options.callbacks.transfer_progress = transfer_cb;
	options.callbacks.payload = &callcount;

	cl_set_cleanup(&cleanup_local_repo, "foo");
	cl_git_pass(git3_repository_init(&repo, "foo", true));

	cl_git_pass(git3_remote_create(&origin, repo, GIT3_REMOTE_ORIGIN, url));
	cl_git_pass(git3_remote_fetch(origin, NULL, &options, NULL));

	cl_git_pass(git3_reference_list(&refnames, repo));
	cl_assert_equal_i(20, (int)refnames.count);
	cl_assert(callcount > 0);
	git3_strarray_dispose(&refnames);
	git3_remote_free(origin);

	cl_git_pass(git3_reference_lookup(&ref, remote_repo, "refs/heads/br2"));
	cl_git_pass(git3_reference_delete(ref));
	git3_reference_free(ref);

	cl_git_pass(git3_remote_lookup(&origin, repo, GIT3_REMOTE_ORIGIN));
	cl_git_pass(git3_remote_fetch(origin, NULL, &options, NULL));
	cl_git_pass(git3_remote_prune(origin, &options.callbacks));

	cl_git_pass(git3_reference_list(&refnames, repo));
	cl_assert_equal_i(19, (int)refnames.count);
	git3_strarray_dispose(&refnames);
	git3_remote_free(origin);

	cl_git_pass(git3_reference_lookup(&ref, remote_repo, "refs/heads/packed"));
	cl_git_pass(git3_reference_delete(ref));
	git3_reference_free(ref);

	cl_git_pass(git3_repository_config(&config, repo));
	cl_git_pass(git3_config_set_bool(config, "remote.origin.prune", 1));
	git3_config_free(config);
	cl_git_pass(git3_remote_lookup(&origin, repo, GIT3_REMOTE_ORIGIN));
	cl_assert_equal_i(1, git3_remote_prune_refs(origin));
	cl_git_pass(git3_remote_fetch(origin, NULL, &options, NULL));

	cl_git_pass(git3_reference_list(&refnames, repo));
	cl_assert_equal_i(18, (int)refnames.count);
	git3_strarray_dispose(&refnames);
	git3_remote_free(origin);

	git3_repository_free(repo);
}

void test_network_fetchlocal__prune_tag(void)
{
	git3_repository *repo;
	git3_remote *origin;
	int callcount = 0;
	git3_reference *ref;
	git3_config *config;
	git3_oid tag_id;
	git3_signature *tagger;
	git3_object *obj;

	git3_repository *remote_repo = cl_git_sandbox_init("testrepo.git");
	const char *url = cl_git_path_url(git3_repository_path(remote_repo));
	git3_fetch_options options = GIT3_FETCH_OPTIONS_INIT;

	options.callbacks.transfer_progress = transfer_cb;
	options.callbacks.payload = &callcount;

	cl_set_cleanup(&cleanup_local_repo, "foo");
	cl_git_pass(git3_repository_init(&repo, "foo", true));

	cl_git_pass(git3_remote_create(&origin, repo, GIT3_REMOTE_ORIGIN, url));
	cl_git_pass(git3_remote_fetch(origin, NULL, &options, NULL));
	git3_remote_free(origin);

	cl_git_pass(git3_revparse_single(&obj, repo, "origin/master"));

	cl_git_pass(git3_reference_create(&ref, repo, "refs/remotes/origin/fake-remote", git3_object_id(obj), 1, NULL));
	git3_reference_free(ref);

	/* create signature */
	cl_git_pass(git3_signature_new(&tagger, tagger_name, tagger_email, 123456789, 60));

	cl_git_pass(
		git3_tag_create(&tag_id, repo,
		  "some-tag", obj, tagger, tagger_message, 0)
	);
	git3_signature_free(tagger);

	cl_git_pass(git3_repository_config(&config, repo));
	cl_git_pass(git3_config_set_bool(config, "remote.origin.prune", 1));
	git3_config_free(config);
	cl_git_pass(git3_remote_lookup(&origin, repo, GIT3_REMOTE_ORIGIN));
	cl_assert_equal_i(1, git3_remote_prune_refs(origin));
	cl_git_pass(git3_remote_fetch(origin, NULL, &options, NULL));

	assert_ref_exists(repo, "refs/tags/some-tag");
	cl_git_fail_with(GIT3_ENOTFOUND, git3_reference_lookup(&ref, repo, "refs/remotes/origin/fake-remote"));

	git3_object_free(obj);
	git3_remote_free(origin);

	git3_repository_free(repo);
}

void test_network_fetchlocal__partial(void)
{
	git3_repository *repo = cl_git_sandbox_init("partial-testrepo");
	git3_remote *origin;
	int callcount = 0;
	git3_strarray refnames = {0};
	const char *url;
	git3_fetch_options options = GIT3_FETCH_OPTIONS_INIT;

	options.callbacks.transfer_progress = transfer_cb;
	options.callbacks.payload = &callcount;

	cl_git_pass(git3_reference_list(&refnames, repo));
	cl_assert_equal_i(1, (int)refnames.count);

	url = cl_git_fixture_url("testrepo.git");
	cl_git_pass(git3_remote_create(&origin, repo, GIT3_REMOTE_ORIGIN, url));
	cl_git_pass(git3_remote_fetch(origin, NULL, &options, NULL));

	git3_strarray_dispose(&refnames);

	cl_git_pass(git3_reference_list(&refnames, repo));
	cl_assert_equal_i(21, (int)refnames.count); /* 18 remote + 1 local */
	cl_assert(callcount > 0);

	git3_strarray_dispose(&refnames);
	git3_remote_free(origin);
}

static int remote_mirror_cb(git3_remote **out, git3_repository *repo,
			    const char *name, const char *url, void *payload)
{
	int error;
	git3_remote *remote;

	GIT3_UNUSED(payload);

	if ((error = git3_remote_create_with_fetchspec(&remote, repo, name, url, "+refs/*:refs/*")) < 0)
		return error;

	*out = remote;
	return 0;
}

void test_network_fetchlocal__clone_into_mirror(void)
{
	git3_clone_options opts = GIT3_CLONE_OPTIONS_INIT;
	git3_repository *repo;
	git3_reference *ref;

	opts.bare = true;
	opts.remote_cb = remote_mirror_cb;
	cl_git_pass(git3_clone(&repo, cl_git_fixture_url("testrepo.git"), "./foo.git", &opts));

	cl_git_pass(git3_reference_lookup(&ref, repo, "HEAD"));
	cl_assert_equal_i(GIT3_REFERENCE_SYMBOLIC, git3_reference_type(ref));
	cl_assert_equal_s("refs/heads/master", git3_reference_symbolic_target(ref));

	git3_reference_free(ref);
	cl_git_pass(git3_reference_lookup(&ref, repo, "refs/remotes/test/master"));

	git3_reference_free(ref);
	git3_repository_free(repo);
	cl_fixture_cleanup("./foo.git");
}

void test_network_fetchlocal__all_refs(void)
{
	git3_repository *repo;
	git3_remote *remote;
	git3_reference *ref;
	char *allrefs = "+refs/*:refs/*";
	git3_strarray refspecs = {
		&allrefs,
		1,
	};

	cl_git_pass(git3_repository_init(&repo, "./foo.git", true));
	cl_git_pass(git3_remote_create_anonymous(&remote, repo, cl_git_fixture_url("testrepo.git")));
	cl_git_pass(git3_remote_fetch(remote, &refspecs, NULL, NULL));

	cl_git_pass(git3_reference_lookup(&ref, repo, "refs/remotes/test/master"));
	git3_reference_free(ref);

	cl_git_pass(git3_reference_lookup(&ref, repo, "refs/tags/test"));
	git3_reference_free(ref);

	git3_remote_free(remote);
	git3_repository_free(repo);
	cl_fixture_cleanup("./foo.git");
}

void test_network_fetchlocal__multi_remotes(void)
{
	git3_repository *repo = cl_git_sandbox_init("testrepo.git");
	git3_remote *test, *test2;
	git3_strarray refnames = {0};
	git3_fetch_options options = GIT3_FETCH_OPTIONS_INIT;

	options.callbacks.transfer_progress = transfer_cb;
	cl_git_pass(git3_remote_set_url(repo, "test", cl_git_fixture_url("testrepo.git")));
	cl_git_pass(git3_remote_lookup(&test, repo, "test"));
	cl_git_pass(git3_remote_fetch(test, NULL, &options, NULL));

	cl_git_pass(git3_reference_list(&refnames, repo));
	cl_assert_equal_i(35, (int)refnames.count);
	git3_strarray_dispose(&refnames);

	cl_git_pass(git3_remote_set_url(repo, "test_with_pushurl", cl_git_fixture_url("testrepo.git")));
	cl_git_pass(git3_remote_lookup(&test2, repo, "test_with_pushurl"));
	cl_git_pass(git3_remote_fetch(test2, NULL, &options, NULL));

	cl_git_pass(git3_reference_list(&refnames, repo));
	cl_assert_equal_i(48, (int)refnames.count);

	git3_strarray_dispose(&refnames);
	git3_remote_free(test);
	git3_remote_free(test2);
}

static int sideband_cb(const char *str, int len, void *payload)
{
	int *count = (int *) payload;

	GIT3_UNUSED(str);
	GIT3_UNUSED(len);

	(*count)++;
	return 0;
}

void test_network_fetchlocal__call_progress(void)
{
	git3_repository *repo;
	git3_remote *remote;
	git3_fetch_options options = GIT3_FETCH_OPTIONS_INIT;
	int callcount = 0;

	cl_git_pass(git3_repository_init(&repo, "foo.git", true));
	cl_set_cleanup(cleanup_local_repo, "foo.git");

	cl_git_pass(git3_remote_create_with_fetchspec(&remote, repo, "origin", cl_git_fixture_url("testrepo.git"), "+refs/heads/*:refs/heads/*"));

	options.callbacks.sideband_progress = sideband_cb;
	options.callbacks.payload = &callcount;

	cl_git_pass(git3_remote_fetch(remote, NULL, &options, NULL));
	cl_assert(callcount != 0);

	git3_remote_free(remote);
	git3_repository_free(repo);
}

void test_network_fetchlocal__prune_load_remote_prune_config(void)
{
	git3_repository *repo;
	git3_remote *origin;
	git3_config *config;
	git3_repository *remote_repo = cl_git_sandbox_init("testrepo.git");
	const char *url = cl_git_path_url(git3_repository_path(remote_repo));

	cl_set_cleanup(&cleanup_local_repo, "foo");
	cl_git_pass(git3_repository_init(&repo, "foo", true));

	cl_git_pass(git3_repository_config(&config, repo));
	cl_git_pass(git3_config_set_bool(config, "remote.origin.prune", 1));

	cl_git_pass(git3_remote_create(&origin, repo, GIT3_REMOTE_ORIGIN, url));
	cl_assert_equal_i(1, git3_remote_prune_refs(origin));

	git3_config_free(config);
	git3_remote_free(origin);
	git3_repository_free(repo);
}

void test_network_fetchlocal__prune_load_fetch_prune_config(void)
{
	git3_repository *repo;
	git3_remote *origin;
	git3_config *config;
	git3_repository *remote_repo = cl_git_sandbox_init("testrepo.git");
	const char *url = cl_git_path_url(git3_repository_path(remote_repo));

	cl_set_cleanup(&cleanup_local_repo, "foo");
	cl_git_pass(git3_repository_init(&repo, "foo", true));

	cl_git_pass(git3_repository_config(&config, repo));
	cl_git_pass(git3_config_set_bool(config, "fetch.prune", 1));

	cl_git_pass(git3_remote_create(&origin, repo, GIT3_REMOTE_ORIGIN, url));
	cl_assert_equal_i(1, git3_remote_prune_refs(origin));

	git3_config_free(config);
	git3_remote_free(origin);
	git3_repository_free(repo);
}

static int update_refs_error(const char *ref, const git3_oid *old, const git3_oid *new, git3_refspec *refspec, void *data)
{
	int *callcount = (int *) data;

	GIT3_UNUSED(ref);
	GIT3_UNUSED(old);
	GIT3_UNUSED(new);
	GIT3_UNUSED(refspec);

	(*callcount)++;

	return -1;
}

void test_network_fetchlocal__update_refs_error_is_propagated(void)
{
	git3_repository *repo;
	git3_reference_iterator *iterator;
	git3_reference *ref;
	git3_remote *remote;
	git3_fetch_options options = GIT3_FETCH_OPTIONS_INIT;
	int callcount = 0;

	cl_git_pass(git3_repository_init(&repo, "foo.git", true));
	cl_set_cleanup(cleanup_local_repo, "foo.git");

	cl_git_pass(git3_remote_create_with_fetchspec(&remote, repo, "origin", cl_git_fixture_url("testrepo.git"), "+refs/heads/*:refs/remotes/update-tips/*"));

	options.callbacks.update_refs = update_refs_error;
	options.callbacks.payload = &callcount;

	cl_git_fail(git3_remote_fetch(remote, NULL, &options, NULL));
	cl_assert_equal_i(1, callcount);

	cl_git_pass(git3_reference_iterator_glob_new(&iterator, repo, "refs/remotes/update-tips/**/"));
	cl_assert_equal_i(GIT3_ITEROVER, git3_reference_next(&ref, iterator));

	git3_reference_iterator_free(iterator);
	git3_remote_free(remote);
	git3_repository_free(repo);
}

#ifndef GIT3_DEPRECATE_HARD
static int update_tips(const char *ref, const git3_oid *old, const git3_oid *new, void *data)
{
	int *called = (int *) data;

	GIT3_UNUSED(ref);
	GIT3_UNUSED(old);
	GIT3_UNUSED(new);

	(*called) += 1;

	return 0;
}

static int update_refs(const char *ref, const git3_oid *old, const git3_oid *new, git3_refspec *spec, void *data)
{
	int *called = (int *) data;

	GIT3_UNUSED(ref);
	GIT3_UNUSED(old);
	GIT3_UNUSED(new);
	GIT3_UNUSED(spec);

	(*called) += 0x10000;

	return 0;
}
#endif

void test_network_fetchlocal__update_tips_backcompat(void)
{
#ifndef GIT3_DEPRECATE_HARD
	git3_repository *repo;
	git3_remote *remote;
	git3_fetch_options options = GIT3_FETCH_OPTIONS_INIT;
	int callcount = 0;

	cl_git_pass(git3_repository_init(&repo, "foo.git", true));
	cl_set_cleanup(cleanup_local_repo, "foo.git");

	cl_git_pass(git3_remote_create_with_fetchspec(&remote, repo, "origin", cl_git_fixture_url("testrepo.git"), "+refs/heads/*:refs/remotes/update-tips/*"));

	options.callbacks.update_tips = update_tips;
	options.callbacks.payload = &callcount;

	cl_git_pass(git3_remote_fetch(remote, NULL, &options, NULL));
	cl_assert_equal_i(0, (callcount & 0xffff0000));
	cl_assert((callcount & 0x0000ffff) > 0);

	git3_remote_free(remote);
	git3_repository_free(repo);
#endif
}

void test_network_fetchlocal__update_refs_is_preferred(void)
{
#ifndef GIT3_DEPRECATE_HARD
	git3_repository *repo;
	git3_remote *remote;
	git3_fetch_options options = GIT3_FETCH_OPTIONS_INIT;
	int callcount = 0;

	cl_git_pass(git3_repository_init(&repo, "foo.git", true));
	cl_set_cleanup(cleanup_local_repo, "foo.git");

	cl_git_pass(git3_remote_create_with_fetchspec(&remote, repo, "origin", cl_git_fixture_url("testrepo.git"), "+refs/heads/*:refs/remotes/update-tips/*"));

	options.callbacks.update_tips = update_tips;
	options.callbacks.update_refs = update_refs;
	options.callbacks.payload = &callcount;

	cl_git_pass(git3_remote_fetch(remote, NULL, &options, NULL));
	cl_assert_equal_i(0, (callcount & 0x0000ffff));
	cl_assert((callcount & 0xffff0000) > 0);

	git3_remote_free(remote);
	git3_repository_free(repo);
#endif
}
