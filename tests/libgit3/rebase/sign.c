#include "clar_libgit3.h"
#include "git3/rebase.h"

static git3_repository *repo;
static git3_signature *signature;

/* Fixture setup and teardown */
void test_rebase_sign__initialize(void)
{
	repo = cl_git_sandbox_init("rebase");
	cl_git_pass(git3_signature_new(&signature, "Rebaser",
		"rebaser@rebaser.rb", 1405694510, 0));
}

void test_rebase_sign__cleanup(void)
{
	git3_signature_free(signature);
	cl_git_sandbox_cleanup();
}

static int create_cb_passthrough(
	git3_oid *out,
	const git3_signature *author,
	const git3_signature *committer,
	const char *message_encoding,
	const char *message,
	const git3_tree *tree,
	size_t parent_count,
	const git3_commit *parents[],
	void *payload)
{
	GIT3_UNUSED(out);
	GIT3_UNUSED(author);
	GIT3_UNUSED(committer);
	GIT3_UNUSED(message_encoding);
	GIT3_UNUSED(message);
	GIT3_UNUSED(tree);
	GIT3_UNUSED(parent_count);
	GIT3_UNUSED(parents);
	GIT3_UNUSED(payload);

	return GIT3_PASSTHROUGH;
}

/* git checkout gravy ; git rebase --merge veal */
void test_rebase_sign__passthrough_create_cb(void)
{
	git3_rebase *rebase;
	git3_reference *branch_ref, *upstream_ref;
	git3_annotated_commit *branch_head, *upstream_head;
	git3_rebase_operation *rebase_operation;
	git3_oid commit_id, expected_id;
	git3_rebase_options rebase_opts = GIT3_REBASE_OPTIONS_INIT;
	git3_commit *commit;
	const char *expected_commit_raw_header = "tree cd99b26250099fc38d30bfaed7797a7275ed3366\n\
parent f87d14a4a236582a0278a916340a793714256864\n\
author Edward Thomson <ethomson@edwardthomson.com> 1405625055 -0400\n\
committer Rebaser <rebaser@rebaser.rb> 1405694510 +0000\n";

	rebase_opts.commit_create_cb = create_cb_passthrough;

	cl_git_pass(git3_reference_lookup(&branch_ref, repo, "refs/heads/gravy"));
	cl_git_pass(git3_reference_lookup(&upstream_ref, repo, "refs/heads/veal"));

	cl_git_pass(git3_annotated_commit_from_ref(&branch_head, repo, branch_ref));
	cl_git_pass(git3_annotated_commit_from_ref(&upstream_head, repo, upstream_ref));

	cl_git_pass(git3_rebase_init(&rebase, repo, branch_head, upstream_head, NULL, &rebase_opts));

	cl_git_pass(git3_rebase_next(&rebase_operation, rebase));
	cl_git_pass(git3_rebase_commit(&commit_id, rebase, NULL, signature, NULL, NULL));

	git3_oid_from_string(&expected_id, "129183968a65abd6c52da35bff43325001bfc630", GIT3_OID_SHA1);
	cl_assert_equal_oid(&expected_id, &commit_id);

	cl_git_pass(git3_commit_lookup(&commit, repo, &commit_id));
	cl_assert_equal_s(expected_commit_raw_header, git3_commit_raw_header(commit));

	cl_git_fail_with(GIT3_ITEROVER, git3_rebase_next(&rebase_operation, rebase));

	git3_reference_free(branch_ref);
	git3_reference_free(upstream_ref);
	git3_annotated_commit_free(branch_head);
	git3_annotated_commit_free(upstream_head);
	git3_commit_free(commit);
	git3_rebase_free(rebase);
}

static int create_cb_signed_gpg(
	git3_oid *out,
	const git3_signature *author,
	const git3_signature *committer,
	const char *message_encoding,
	const char *message,
	const git3_tree *tree,
	size_t parent_count,
	const git3_commit *parents[],
	void *payload)
{
	git3_buf commit_content = GIT3_BUF_INIT;
	const char *gpg_signature = "-----BEGIN PGP SIGNATURE-----\n\
\n\
iQIzBAEBCgAdFiEEgVlDEfSlmKn0fvGgK++h5T2/ctIFAlwZcrAACgkQK++h5T2/\n\
ctIPVhAA42RyZhMdKl5Bm0KtQco2scsukIg2y7tjSwhti91zDu3HQgpusjjo0fQx\n\
ZzB+OrmlvQ9CDcGpZ0THIzXD8GRJoDMPqdrvZVrBWkGcHvw7/YPA8skzsjkauJ8W\n\
7lzF5LCuHSS6OUmPT/+5hEHPin5PB3zhfszyC+Q7aujnIuPJMrKiMnUa+w1HWifM\n\
km49OOygQ9S6NQoVuEQede22+c76DlDL7yFghGoo1f0sKCE/9LW6SEnwI/bWv9eo\n\
nom5vOPrvQeJiYCQk+2DyWo8RdSxINtY+G9bPE4RXm+6ZgcXECPm9TYDIWpL36fC\n\
jvtGLs98woWFElOziBMp5Tb630GMcSI+q5ivHfJ3WS5NKLYLHBNK4iSFN0/dgAnB\n\
dj6GcKXKWnIBWn6ZM4o40pcM5KSRUUCLtA0ZmjJH4c4zx3X5fUxd+enwkf3e9VZO\n\
fNKC/+xfq6NfoPUPK9+UnchHpJaJw7RG5tZS+sWCz2xpQ1y3/o49xImNyM3wnpvB\n\
cRAZabqIHpZa9/DIUkELOtCzln6niqkjRgg3M/YCCNznwV+0RNgz87VtyTPerdef\n\
xrqn0+ROMF6ebVqIs6PPtuPkxnAJu7TMKXVB5rFnAewS24e6cIGFzeIA7810py3l\n\
cttVRsdOoego+fiy08eFE+aJIeYiINRGhqOBTsuqG4jIdpdKxPE=\n\
=KbsY\n\
-----END PGP SIGNATURE-----";

	git3_repository *repo = (git3_repository *)payload;
	int error;

	if ((error = git3_commit_create_buffer(&commit_content,
		repo, author, committer, message_encoding, message,
		tree, parent_count, parents)) < 0)
		goto done;

	error = git3_commit_create_with_signature(out, repo,
		commit_content.ptr,
		gpg_signature,
		NULL);

done:
	git3_buf_dispose(&commit_content);
	return error;
}

/* git checkout gravy ; git rebase --merge veal */
void test_rebase_sign__create_gpg_signed(void)
{
	git3_rebase *rebase;
	git3_reference *branch_ref, *upstream_ref;
	git3_annotated_commit *branch_head, *upstream_head;
	git3_rebase_operation *rebase_operation;
	git3_oid commit_id, expected_id;
	git3_rebase_options rebase_opts = GIT3_REBASE_OPTIONS_INIT;
	git3_commit *commit;
	const char *expected_commit_raw_header = "tree cd99b26250099fc38d30bfaed7797a7275ed3366\n\
parent f87d14a4a236582a0278a916340a793714256864\n\
author Edward Thomson <ethomson@edwardthomson.com> 1405625055 -0400\n\
committer Rebaser <rebaser@rebaser.rb> 1405694510 +0000\n\
gpgsig -----BEGIN PGP SIGNATURE-----\n\
 \n\
 iQIzBAEBCgAdFiEEgVlDEfSlmKn0fvGgK++h5T2/ctIFAlwZcrAACgkQK++h5T2/\n\
 ctIPVhAA42RyZhMdKl5Bm0KtQco2scsukIg2y7tjSwhti91zDu3HQgpusjjo0fQx\n\
 ZzB+OrmlvQ9CDcGpZ0THIzXD8GRJoDMPqdrvZVrBWkGcHvw7/YPA8skzsjkauJ8W\n\
 7lzF5LCuHSS6OUmPT/+5hEHPin5PB3zhfszyC+Q7aujnIuPJMrKiMnUa+w1HWifM\n\
 km49OOygQ9S6NQoVuEQede22+c76DlDL7yFghGoo1f0sKCE/9LW6SEnwI/bWv9eo\n\
 nom5vOPrvQeJiYCQk+2DyWo8RdSxINtY+G9bPE4RXm+6ZgcXECPm9TYDIWpL36fC\n\
 jvtGLs98woWFElOziBMp5Tb630GMcSI+q5ivHfJ3WS5NKLYLHBNK4iSFN0/dgAnB\n\
 dj6GcKXKWnIBWn6ZM4o40pcM5KSRUUCLtA0ZmjJH4c4zx3X5fUxd+enwkf3e9VZO\n\
 fNKC/+xfq6NfoPUPK9+UnchHpJaJw7RG5tZS+sWCz2xpQ1y3/o49xImNyM3wnpvB\n\
 cRAZabqIHpZa9/DIUkELOtCzln6niqkjRgg3M/YCCNznwV+0RNgz87VtyTPerdef\n\
 xrqn0+ROMF6ebVqIs6PPtuPkxnAJu7TMKXVB5rFnAewS24e6cIGFzeIA7810py3l\n\
 cttVRsdOoego+fiy08eFE+aJIeYiINRGhqOBTsuqG4jIdpdKxPE=\n\
 =KbsY\n\
 -----END PGP SIGNATURE-----\n";

	rebase_opts.commit_create_cb = create_cb_signed_gpg;
	rebase_opts.payload = repo;

	cl_git_pass(git3_reference_lookup(&branch_ref, repo, "refs/heads/gravy"));
	cl_git_pass(git3_reference_lookup(&upstream_ref, repo, "refs/heads/veal"));

	cl_git_pass(git3_annotated_commit_from_ref(&branch_head, repo, branch_ref));
	cl_git_pass(git3_annotated_commit_from_ref(&upstream_head, repo, upstream_ref));

	cl_git_pass(git3_rebase_init(&rebase, repo, branch_head, upstream_head, NULL, &rebase_opts));

	cl_git_pass(git3_rebase_next(&rebase_operation, rebase));
	cl_git_pass(git3_rebase_commit(&commit_id, rebase, NULL, signature, NULL, NULL));

	git3_oid_from_string(&expected_id, "bf78348e45c8286f52b760f1db15cb6da030f2ef", GIT3_OID_SHA1);
	cl_assert_equal_oid(&expected_id, &commit_id);

	cl_git_pass(git3_commit_lookup(&commit, repo, &commit_id));
	cl_assert_equal_s(expected_commit_raw_header, git3_commit_raw_header(commit));

	cl_git_fail_with(GIT3_ITEROVER, git3_rebase_next(&rebase_operation, rebase));

	git3_reference_free(branch_ref);
	git3_reference_free(upstream_ref);
	git3_annotated_commit_free(branch_head);
	git3_annotated_commit_free(upstream_head);
	git3_commit_free(commit);
	git3_rebase_free(rebase);
}

static int create_cb_error(
	git3_oid *out,
	const git3_signature *author,
	const git3_signature *committer,
	const char *message_encoding,
	const char *message,
	const git3_tree *tree,
	size_t parent_count,
	const git3_commit *parents[],
	void *payload)
{
	GIT3_UNUSED(out);
	GIT3_UNUSED(author);
	GIT3_UNUSED(committer);
	GIT3_UNUSED(message_encoding);
	GIT3_UNUSED(message);
	GIT3_UNUSED(tree);
	GIT3_UNUSED(parent_count);
	GIT3_UNUSED(parents);
	GIT3_UNUSED(payload);

	return GIT3_EUSER;
}

/* git checkout gravy ; git rebase --merge veal */
void test_rebase_sign__create_propagates_error(void)
{
	git3_rebase *rebase;
	git3_reference *branch_ref, *upstream_ref;
	git3_annotated_commit *branch_head, *upstream_head;
	git3_oid commit_id;
	git3_rebase_operation *rebase_operation;
	git3_rebase_options rebase_opts = GIT3_REBASE_OPTIONS_INIT;

	rebase_opts.commit_create_cb = create_cb_error;

	cl_git_pass(git3_reference_lookup(&branch_ref, repo, "refs/heads/gravy"));
	cl_git_pass(git3_reference_lookup(&upstream_ref, repo, "refs/heads/veal"));

	cl_git_pass(git3_annotated_commit_from_ref(&branch_head, repo, branch_ref));
	cl_git_pass(git3_annotated_commit_from_ref(&upstream_head, repo, upstream_ref));

	cl_git_pass(git3_rebase_init(&rebase, repo, branch_head, upstream_head, NULL, &rebase_opts));

	cl_git_pass(git3_rebase_next(&rebase_operation, rebase));
	cl_git_fail_with(GIT3_EUSER, git3_rebase_commit(&commit_id, rebase, NULL, signature, NULL, NULL));

	git3_reference_free(branch_ref);
	git3_reference_free(upstream_ref);
	git3_annotated_commit_free(branch_head);
	git3_annotated_commit_free(upstream_head);
	git3_rebase_free(rebase);
}

#ifndef GIT3_DEPRECATE_HARD
static const char *expected_commit_content = "\
tree cd99b26250099fc38d30bfaed7797a7275ed3366\n\
parent f87d14a4a236582a0278a916340a793714256864\n\
author Edward Thomson <ethomson@edwardthomson.com> 1405625055 -0400\n\
committer Rebaser <rebaser@rebaser.rb> 1405694510 +0000\n\
\n\
Modification 3 to gravy\n";

int signing_cb_passthrough(
	git3_buf *signature,
	git3_buf *signature_field,
	const char *commit_content,
	void *payload)
{
	cl_assert_equal_i(0, signature->size);
	cl_assert_equal_i(0, signature_field->size);
	cl_assert_equal_s(expected_commit_content, commit_content);
	cl_assert_equal_p(NULL, payload);
	return GIT3_PASSTHROUGH;
}
#endif /* !GIT3_DEPRECATE_HARD */

/* git checkout gravy ; git rebase --merge veal */
void test_rebase_sign__passthrough_signing_cb(void)
{
#ifndef GIT3_DEPRECATE_HARD
	git3_rebase *rebase;
	git3_reference *branch_ref, *upstream_ref;
	git3_annotated_commit *branch_head, *upstream_head;
	git3_rebase_operation *rebase_operation;
	git3_oid commit_id, expected_id;
	git3_rebase_options rebase_opts = GIT3_REBASE_OPTIONS_INIT;
	git3_commit *commit;
	const char *expected_commit_raw_header = "tree cd99b26250099fc38d30bfaed7797a7275ed3366\n\
parent f87d14a4a236582a0278a916340a793714256864\n\
author Edward Thomson <ethomson@edwardthomson.com> 1405625055 -0400\n\
committer Rebaser <rebaser@rebaser.rb> 1405694510 +0000\n";

	rebase_opts.signing_cb = signing_cb_passthrough;

	cl_git_pass(git3_reference_lookup(&branch_ref, repo, "refs/heads/gravy"));
	cl_git_pass(git3_reference_lookup(&upstream_ref, repo, "refs/heads/veal"));

	cl_git_pass(git3_annotated_commit_from_ref(&branch_head, repo, branch_ref));
	cl_git_pass(git3_annotated_commit_from_ref(&upstream_head, repo, upstream_ref));

	cl_git_pass(git3_rebase_init(&rebase, repo, branch_head, upstream_head, NULL, &rebase_opts));

	cl_git_pass(git3_rebase_next(&rebase_operation, rebase));
	cl_git_pass(git3_rebase_commit(&commit_id, rebase, NULL, signature, NULL, NULL));

	git3_oid_from_string(&expected_id, "129183968a65abd6c52da35bff43325001bfc630", GIT3_OID_SHA1);
	cl_assert_equal_oid(&expected_id, &commit_id);

	cl_git_pass(git3_commit_lookup(&commit, repo, &commit_id));
	cl_assert_equal_s(expected_commit_raw_header, git3_commit_raw_header(commit));

	cl_git_fail_with(GIT3_ITEROVER, git3_rebase_next(&rebase_operation, rebase));

	git3_reference_free(branch_ref);
	git3_reference_free(upstream_ref);
	git3_annotated_commit_free(branch_head);
	git3_annotated_commit_free(upstream_head);
	git3_commit_free(commit);
	git3_rebase_free(rebase);
#endif /* !GIT3_DEPRECATE_HARD */
}

#ifndef GIT3_DEPRECATE_HARD
int signing_cb_gpg(
	git3_buf *signature,
	git3_buf *signature_field,
	const char *commit_content,
	void *payload)
{
	const char *gpg_signature = "\
-----BEGIN PGP SIGNATURE-----\n\
\n\
iQIzBAEBCgAdFiEEgVlDEfSlmKn0fvGgK++h5T2/ctIFAlwZcrAACgkQK++h5T2/\n\
ctIPVhAA42RyZhMdKl5Bm0KtQco2scsukIg2y7tjSwhti91zDu3HQgpusjjo0fQx\n\
ZzB+OrmlvQ9CDcGpZ0THIzXD8GRJoDMPqdrvZVrBWkGcHvw7/YPA8skzsjkauJ8W\n\
7lzF5LCuHSS6OUmPT/+5hEHPin5PB3zhfszyC+Q7aujnIuPJMrKiMnUa+w1HWifM\n\
km49OOygQ9S6NQoVuEQede22+c76DlDL7yFghGoo1f0sKCE/9LW6SEnwI/bWv9eo\n\
nom5vOPrvQeJiYCQk+2DyWo8RdSxINtY+G9bPE4RXm+6ZgcXECPm9TYDIWpL36fC\n\
jvtGLs98woWFElOziBMp5Tb630GMcSI+q5ivHfJ3WS5NKLYLHBNK4iSFN0/dgAnB\n\
dj6GcKXKWnIBWn6ZM4o40pcM5KSRUUCLtA0ZmjJH4c4zx3X5fUxd+enwkf3e9VZO\n\
fNKC/+xfq6NfoPUPK9+UnchHpJaJw7RG5tZS+sWCz2xpQ1y3/o49xImNyM3wnpvB\n\
cRAZabqIHpZa9/DIUkELOtCzln6niqkjRgg3M/YCCNznwV+0RNgz87VtyTPerdef\n\
xrqn0+ROMF6ebVqIs6PPtuPkxnAJu7TMKXVB5rFnAewS24e6cIGFzeIA7810py3l\n\
cttVRsdOoego+fiy08eFE+aJIeYiINRGhqOBTsuqG4jIdpdKxPE=\n\
=KbsY\n\
-----END PGP SIGNATURE-----";

	cl_assert_equal_i(0, signature->size);
	cl_assert_equal_i(0, signature_field->size);
	cl_assert_equal_s(expected_commit_content, commit_content);
	cl_assert_equal_p(NULL, payload);

	cl_git_pass(git3_buf_set(signature, gpg_signature, strlen(gpg_signature) + 1));
	return GIT3_OK;
}
#endif /* !GIT3_DEPRECATE_HARD */

/* git checkout gravy ; git rebase --merge veal */
void test_rebase_sign__gpg_with_no_field(void)
{
#ifndef GIT3_DEPRECATE_HARD
	git3_rebase *rebase;
	git3_reference *branch_ref, *upstream_ref;
	git3_annotated_commit *branch_head, *upstream_head;
	git3_rebase_operation *rebase_operation;
	git3_oid commit_id, expected_id;
	git3_rebase_options rebase_opts = GIT3_REBASE_OPTIONS_INIT;
	git3_commit *commit;
	const char *expected_commit_raw_header = "\
tree cd99b26250099fc38d30bfaed7797a7275ed3366\n\
parent f87d14a4a236582a0278a916340a793714256864\n\
author Edward Thomson <ethomson@edwardthomson.com> 1405625055 -0400\n\
committer Rebaser <rebaser@rebaser.rb> 1405694510 +0000\n\
gpgsig -----BEGIN PGP SIGNATURE-----\n\
 \n\
 iQIzBAEBCgAdFiEEgVlDEfSlmKn0fvGgK++h5T2/ctIFAlwZcrAACgkQK++h5T2/\n\
 ctIPVhAA42RyZhMdKl5Bm0KtQco2scsukIg2y7tjSwhti91zDu3HQgpusjjo0fQx\n\
 ZzB+OrmlvQ9CDcGpZ0THIzXD8GRJoDMPqdrvZVrBWkGcHvw7/YPA8skzsjkauJ8W\n\
 7lzF5LCuHSS6OUmPT/+5hEHPin5PB3zhfszyC+Q7aujnIuPJMrKiMnUa+w1HWifM\n\
 km49OOygQ9S6NQoVuEQede22+c76DlDL7yFghGoo1f0sKCE/9LW6SEnwI/bWv9eo\n\
 nom5vOPrvQeJiYCQk+2DyWo8RdSxINtY+G9bPE4RXm+6ZgcXECPm9TYDIWpL36fC\n\
 jvtGLs98woWFElOziBMp5Tb630GMcSI+q5ivHfJ3WS5NKLYLHBNK4iSFN0/dgAnB\n\
 dj6GcKXKWnIBWn6ZM4o40pcM5KSRUUCLtA0ZmjJH4c4zx3X5fUxd+enwkf3e9VZO\n\
 fNKC/+xfq6NfoPUPK9+UnchHpJaJw7RG5tZS+sWCz2xpQ1y3/o49xImNyM3wnpvB\n\
 cRAZabqIHpZa9/DIUkELOtCzln6niqkjRgg3M/YCCNznwV+0RNgz87VtyTPerdef\n\
 xrqn0+ROMF6ebVqIs6PPtuPkxnAJu7TMKXVB5rFnAewS24e6cIGFzeIA7810py3l\n\
 cttVRsdOoego+fiy08eFE+aJIeYiINRGhqOBTsuqG4jIdpdKxPE=\n\
 =KbsY\n\
 -----END PGP SIGNATURE-----\n";

	rebase_opts.signing_cb = signing_cb_gpg;

	cl_git_pass(git3_reference_lookup(&branch_ref, repo, "refs/heads/gravy"));
	cl_git_pass(git3_reference_lookup(&upstream_ref, repo, "refs/heads/veal"));

	cl_git_pass(git3_annotated_commit_from_ref(&branch_head, repo, branch_ref));
	cl_git_pass(git3_annotated_commit_from_ref(&upstream_head, repo, upstream_ref));

	cl_git_pass(git3_rebase_init(&rebase, repo, branch_head, upstream_head, NULL, &rebase_opts));

	cl_git_pass(git3_rebase_next(&rebase_operation, rebase));
	cl_git_pass(git3_rebase_commit(&commit_id, rebase, NULL, signature, NULL, NULL));

	git3_oid_from_string(&expected_id, "bf78348e45c8286f52b760f1db15cb6da030f2ef", GIT3_OID_SHA1);
	cl_assert_equal_oid(&expected_id, &commit_id);

	cl_git_pass(git3_commit_lookup(&commit, repo, &commit_id));
	cl_assert_equal_s(expected_commit_raw_header, git3_commit_raw_header(commit));

	cl_git_fail_with(GIT3_ITEROVER, git3_rebase_next(&rebase_operation, rebase));

	git3_reference_free(branch_ref);
	git3_reference_free(upstream_ref);
	git3_annotated_commit_free(branch_head);
	git3_annotated_commit_free(upstream_head);
	git3_commit_free(commit);
	git3_rebase_free(rebase);
#endif /* !GIT3_DEPRECATE_HARD */
}


#ifndef GIT3_DEPRECATE_HARD
int signing_cb_magic_field(
	git3_buf *signature,
	git3_buf *signature_field,
	const char *commit_content,
	void *payload)
{
	const char *signature_content = "magic word: pretty please";
	const char *signature_field_content = "magicsig";

	cl_assert_equal_p(NULL, signature->ptr);
	cl_assert_equal_i(0, signature->size);
	cl_assert_equal_p(NULL, signature_field->ptr);
	cl_assert_equal_i(0, signature_field->size);
	cl_assert_equal_s(expected_commit_content, commit_content);
	cl_assert_equal_p(NULL, payload);

	cl_git_pass(git3_buf_set(signature, signature_content,
		strlen(signature_content) + 1));
	cl_git_pass(git3_buf_set(signature_field, signature_field_content,
		strlen(signature_field_content) + 1));

	return GIT3_OK;
}
#endif /* !GIT3_DEPRECATE_HARD */

/* git checkout gravy ; git rebase --merge veal */
void test_rebase_sign__custom_signature_field(void)
{
#ifndef GIT3_DEPRECATE_HARD
	git3_rebase *rebase;
	git3_reference *branch_ref, *upstream_ref;
	git3_annotated_commit *branch_head, *upstream_head;
	git3_rebase_operation *rebase_operation;
	git3_oid commit_id, expected_id;
	git3_rebase_options rebase_opts = GIT3_REBASE_OPTIONS_INIT;
	git3_commit *commit;
	const char *expected_commit_raw_header = "\
tree cd99b26250099fc38d30bfaed7797a7275ed3366\n\
parent f87d14a4a236582a0278a916340a793714256864\n\
author Edward Thomson <ethomson@edwardthomson.com> 1405625055 -0400\n\
committer Rebaser <rebaser@rebaser.rb> 1405694510 +0000\n\
magicsig magic word: pretty please\n";

	rebase_opts.signing_cb = signing_cb_magic_field;

	cl_git_pass(git3_reference_lookup(&branch_ref, repo, "refs/heads/gravy"));
	cl_git_pass(git3_reference_lookup(&upstream_ref, repo, "refs/heads/veal"));

	cl_git_pass(git3_annotated_commit_from_ref(&branch_head, repo, branch_ref));
	cl_git_pass(git3_annotated_commit_from_ref(&upstream_head, repo, upstream_ref));

	cl_git_pass(git3_rebase_init(&rebase, repo, branch_head, upstream_head, NULL, &rebase_opts));

	cl_git_pass(git3_rebase_next(&rebase_operation, rebase));
	cl_git_pass(git3_rebase_commit(&commit_id, rebase, NULL, signature, NULL, NULL));

	git3_oid_from_string(&expected_id, "f46a4a8d26ae411b02aa61b7d69576627f4a1e1c", GIT3_OID_SHA1);
	cl_assert_equal_oid(&expected_id, &commit_id);

	cl_git_pass(git3_commit_lookup(&commit, repo, &commit_id));
	cl_assert_equal_s(expected_commit_raw_header, git3_commit_raw_header(commit));

	cl_git_fail_with(GIT3_ITEROVER, git3_rebase_next(&rebase_operation, rebase));

	git3_reference_free(branch_ref);
	git3_reference_free(upstream_ref);
	git3_annotated_commit_free(branch_head);
	git3_annotated_commit_free(upstream_head);
	git3_commit_free(commit);
	git3_rebase_free(rebase);
#endif /* !GIT3_DEPRECATE_HARD */
}
