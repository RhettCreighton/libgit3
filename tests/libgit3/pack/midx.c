#include "clar_libgit3.h"

#include <git3.h>
#include <git3/sys/midx.h>

#include "futils.h"
#include "midx.h"

void test_pack_midx__parse(void)
{
	git3_repository *repo;
	struct git3_midx_file *idx;
	struct git3_midx_entry e;
	git3_oid id;
	git3_str midx_path = GIT3_STR_INIT;

	cl_git_pass(git3_repository_open(&repo, cl_fixture("testrepo.git")));
	cl_git_pass(git3_str_joinpath(&midx_path, git3_repository_path(repo), "objects/pack/multi-pack-index"));
	cl_git_pass(git3_midx_open(&idx, git3_str_cstr(&midx_path), GIT3_OID_SHA1));
	cl_assert_equal_i(git3_midx_needs_refresh(idx, git3_str_cstr(&midx_path)), 0);

	cl_git_pass(git3_oid_from_string(&id, "5001298e0c09ad9c34e4249bc5801c75e9754fa5", GIT3_OID_SHA1));
	cl_git_pass(git3_midx_entry_find(&e, idx, &id, GIT3_OID_SHA1_HEXSIZE));
	cl_assert_equal_oid(&e.sha1, &id);
	cl_assert_equal_s(
			(const char *)git3_vector_get(&idx->packfile_names, e.pack_index),
			"pack-d7c6adf9f61318f041845b01440d09aa7a91e1b5.idx");

	git3_midx_free(idx);
	git3_repository_free(repo);
	git3_str_dispose(&midx_path);
}

void test_pack_midx__lookup(void)
{
	git3_repository *repo;
	git3_commit *commit;
	git3_oid id;

	cl_git_pass(git3_repository_open(&repo, cl_fixture("testrepo.git")));

	cl_git_pass(git3_oid_from_string(&id, "5001298e0c09ad9c34e4249bc5801c75e9754fa5", GIT3_OID_SHA1));
	cl_git_pass(git3_commit_lookup_prefix(&commit, repo, &id, GIT3_OID_SHA1_HEXSIZE));
	cl_assert_equal_s(git3_commit_message(commit), "packed commit one\n");

	git3_commit_free(commit);
	git3_repository_free(repo);
}

void test_pack_midx__writer(void)
{
	git3_repository *repo;
	git3_midx_writer *w = NULL;
	git3_buf midx = GIT3_BUF_INIT;
	git3_str expected_midx = GIT3_STR_INIT, path = GIT3_STR_INIT;

	cl_git_pass(git3_repository_open(&repo, cl_fixture("testrepo.git")));

	cl_git_pass(git3_str_joinpath(&path, git3_repository_path(repo), "objects/pack"));

#ifdef GIT3_EXPERIMENTAL_SHA256
	cl_git_pass(git3_midx_writer_new(&w, git3_str_cstr(&path), NULL));
#else
	cl_git_pass(git3_midx_writer_new(&w, git3_str_cstr(&path)));
#endif

	cl_git_pass(git3_midx_writer_add(w, "pack-d7c6adf9f61318f041845b01440d09aa7a91e1b5.idx"));
	cl_git_pass(git3_midx_writer_add(w, "pack-d85f5d483273108c9d8dd0e4728ccf0b2982423a.idx"));
	cl_git_pass(git3_midx_writer_add(w, "pack-a81e489679b7d3418f9ab594bda8ceb37dd4c695.idx"));

	cl_git_pass(git3_midx_writer_dump(&midx, w));
	cl_git_pass(git3_str_joinpath(&path, git3_repository_path(repo), "objects/pack/multi-pack-index"));
	cl_git_pass(git3_futils_readbuffer(&expected_midx, git3_str_cstr(&path)));

	cl_assert_equal_i(midx.size, git3_str_len(&expected_midx));
	cl_assert_equal_strn(midx.ptr, git3_str_cstr(&expected_midx), midx.size);

	git3_buf_dispose(&midx);
	git3_str_dispose(&expected_midx);
	git3_str_dispose(&path);
	git3_midx_writer_free(w);
	git3_repository_free(repo);
}

void test_pack_midx__odb_create(void)
{
	git3_repository *repo;
	git3_odb *odb;
	git3_clone_options opts = GIT3_CLONE_OPTIONS_INIT;
	git3_str midx = GIT3_STR_INIT, expected_midx = GIT3_STR_INIT, midx_path = GIT3_STR_INIT;
	struct stat st;

	opts.bare = true;
	opts.local = GIT3_CLONE_LOCAL;
	cl_git_pass(git3_clone(&repo, cl_fixture("testrepo/.gitted"), "./clone.git", &opts));
	cl_git_pass(git3_str_joinpath(&midx_path, git3_repository_path(repo), "objects/pack/multi-pack-index"));
	cl_git_fail(p_stat(git3_str_cstr(&midx_path), &st));

	cl_git_pass(git3_repository_odb(&odb, repo));
	cl_git_pass(git3_odb_write_multi_pack_index(odb));
	git3_odb_free(odb);

	cl_git_pass(p_stat(git3_str_cstr(&midx_path), &st));

	cl_git_pass(git3_futils_readbuffer(&expected_midx, cl_fixture("testrepo.git/objects/pack/multi-pack-index")));
	cl_git_pass(git3_futils_readbuffer(&midx, git3_str_cstr(&midx_path)));
	cl_assert_equal_i(git3_str_len(&midx), git3_str_len(&expected_midx));
	cl_assert_equal_strn(git3_str_cstr(&midx), git3_str_cstr(&expected_midx), git3_str_len(&midx));

	git3_repository_free(repo);
	git3_str_dispose(&midx);
	git3_str_dispose(&midx_path);
	git3_str_dispose(&expected_midx);

	cl_git_pass(git3_futils_rmdir_r("./clone.git", NULL, GIT3_RMDIR_REMOVE_FILES));
}
