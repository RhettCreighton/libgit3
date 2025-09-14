#include "clar_libgit3.h"
#include "git3/checkout.h"
#include "git3/rebase.h"
#include "posix.h"
#include "signature.h"
#include "../submodule/submodule_helpers.h"

#include <fcntl.h>

static git3_repository *repo;
static git3_signature *signature;

/* Fixture setup and teardown */
void test_rebase_submodule__initialize(void)
{
	git3_index *index;
	git3_oid tree_oid, commit_id;
	git3_tree *tree;
	git3_commit *parent;
	git3_object *obj;
	git3_reference *master_ref;
	git3_checkout_options opts = GIT3_CHECKOUT_OPTIONS_INIT;
	opts.checkout_strategy = GIT3_CHECKOUT_FORCE;

	repo = cl_git_sandbox_init("rebase-submodule");
	cl_git_pass(git3_signature_new(&signature,
		"Rebaser", "rebaser@rebaser.rb", 1405694510, 0));

	rewrite_gitmodules(git3_repository_workdir(repo));

	cl_git_pass(git3_submodule_set_url(repo, "my-submodule", git3_repository_path(repo)));

	/* We have to commit the rewritten .gitmodules file */
	cl_git_pass(git3_repository_index(&index, repo));
	cl_git_pass(git3_index_add_bypath(index, ".gitmodules"));
	cl_git_pass(git3_index_write(index));

	cl_git_pass(git3_index_write_tree(&tree_oid, index));
	cl_git_pass(git3_tree_lookup(&tree, repo, &tree_oid));

	cl_git_pass(git3_repository_head(&master_ref, repo));
	cl_git_pass(git3_commit_lookup(&parent, repo, git3_reference_target(master_ref)));

	cl_git_pass(git3_commit_create_v(&commit_id, repo, git3_reference_name(master_ref), signature, signature, NULL, "Fixup .gitmodules", tree, 1, parent));

	/* And a final reset, for good measure */
	cl_git_pass(git3_object_lookup(&obj, repo, &commit_id, GIT3_OBJECT_COMMIT));
	cl_git_pass(git3_reset(repo, obj, GIT3_RESET_HARD, &opts));

	git3_index_free(index);
	git3_object_free(obj);
	git3_commit_free(parent);
	git3_reference_free(master_ref);
	git3_tree_free(tree);
}

void test_rebase_submodule__cleanup(void)
{
	git3_signature_free(signature);
	cl_git_sandbox_cleanup();
}

void test_rebase_submodule__init_untracked(void)
{
	git3_rebase *rebase;
	git3_reference *branch_ref, *upstream_ref;
	git3_annotated_commit *branch_head, *upstream_head;
	git3_str untracked_path = GIT3_STR_INIT;
	FILE *fp;
	git3_submodule *submodule;

	cl_git_pass(git3_reference_lookup(&branch_ref, repo, "refs/heads/asparagus"));
	cl_git_pass(git3_reference_lookup(&upstream_ref, repo, "refs/heads/master"));

	cl_git_pass(git3_annotated_commit_from_ref(&branch_head, repo, branch_ref));
	cl_git_pass(git3_annotated_commit_from_ref(&upstream_head, repo, upstream_ref));

	cl_git_pass(git3_submodule_lookup(&submodule, repo, "my-submodule"));
	cl_git_pass(git3_submodule_update(submodule, 1, NULL));

	git3_str_printf(&untracked_path, "%s/my-submodule/untracked", git3_repository_workdir(repo));
	fp = fopen(git3_str_cstr(&untracked_path), "w");
	fprintf(fp, "An untracked file in a submodule should not block a rebase\n");
	fclose(fp);
	git3_str_dispose(&untracked_path);

	cl_git_pass(git3_rebase_init(&rebase, repo, branch_head, upstream_head, NULL, NULL));

	git3_submodule_free(submodule);
	git3_annotated_commit_free(branch_head);
	git3_annotated_commit_free(upstream_head);
	git3_reference_free(branch_ref);
	git3_reference_free(upstream_ref);
	git3_rebase_free(rebase);
}
