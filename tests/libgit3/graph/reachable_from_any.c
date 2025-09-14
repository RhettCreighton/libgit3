#include "clar_libgit3.h"

#include <git3.h>

#include "commit_graph.h"
#include "bitvec.h"
#include "vector.h"

static git3_repository *repo;

#define TEST_REPO_PATH "merge-recursive"

void test_graph_reachable_from_any__initialize(void)
{
	git3_oid oid;
	git3_commit *commit;

	repo = cl_git_sandbox_init(TEST_REPO_PATH);

	git3_oid_from_string(&oid, "539bd011c4822c560c1d17cab095006b7a10f707", GIT3_OID_SHA1);
	cl_git_pass(git3_commit_lookup(&commit, repo, &oid));
	cl_git_pass(git3_reset(repo, (git3_object *)commit, GIT3_RESET_HARD, NULL));
	git3_commit_free(commit);
}

void test_graph_reachable_from_any__cleanup(void)
{
	cl_git_sandbox_cleanup();
}

void test_graph_reachable_from_any__returns_correct_result(void)
{
	git3_object *branchA1, *branchA2, *branchB1, *branchB2, *branchC1, *branchC2, *branchH1,
			*branchH2;
	git3_oid descendants[7];

	cl_git_pass(git3_revparse_single(&branchA1, repo, "branchA-1"));
	cl_git_pass(git3_revparse_single(&branchA2, repo, "branchA-2"));
	cl_git_pass(git3_revparse_single(&branchB1, repo, "branchB-1"));
	cl_git_pass(git3_revparse_single(&branchB2, repo, "branchB-2"));
	cl_git_pass(git3_revparse_single(&branchC1, repo, "branchC-1"));
	cl_git_pass(git3_revparse_single(&branchC2, repo, "branchC-2"));
	cl_git_pass(git3_revparse_single(&branchH1, repo, "branchH-1"));
	cl_git_pass(git3_revparse_single(&branchH2, repo, "branchH-2"));

	cl_assert_equal_i(
			git3_graph_reachable_from_any(
					repo, git3_object_id(branchH1), git3_object_id(branchA1), 1),
			0);
	cl_assert_equal_i(
			git3_graph_reachable_from_any(
					repo, git3_object_id(branchH1), git3_object_id(branchA2), 1),
			0);

	cl_git_pass(git3_oid_cpy(&descendants[0], git3_object_id(branchA1)));
	cl_git_pass(git3_oid_cpy(&descendants[1], git3_object_id(branchA2)));
	cl_git_pass(git3_oid_cpy(&descendants[2], git3_object_id(branchB1)));
	cl_git_pass(git3_oid_cpy(&descendants[3], git3_object_id(branchB2)));
	cl_git_pass(git3_oid_cpy(&descendants[4], git3_object_id(branchC1)));
	cl_git_pass(git3_oid_cpy(&descendants[5], git3_object_id(branchC2)));
	cl_git_pass(git3_oid_cpy(&descendants[6], git3_object_id(branchH2)));
	cl_assert_equal_i(
			git3_graph_reachable_from_any(repo, git3_object_id(branchH2), descendants, 6),
			0);
	cl_assert_equal_i(
			git3_graph_reachable_from_any(repo, git3_object_id(branchH2), descendants, 7),
			1);

	git3_object_free(branchA1);
	git3_object_free(branchA2);
	git3_object_free(branchB1);
	git3_object_free(branchB2);
	git3_object_free(branchC1);
	git3_object_free(branchC2);
	git3_object_free(branchH1);
	git3_object_free(branchH2);
}

struct exhaustive_state {
	git3_odb *db;
	git3_vector commits;
};

/** Get all commits from the repository. */
static int exhaustive_commits(const git3_oid *id, void *payload)
{
	struct exhaustive_state *mc = (struct exhaustive_state *)payload;
	size_t header_len;
	git3_object_t header_type;
	int error = 0;

	error = git3_odb_read_header(&header_len, &header_type, mc->db, id);
	if (error < 0)
		return error;

	if (header_type == GIT3_OBJECT_COMMIT) {
		git3_commit *commit = NULL;

		cl_git_pass(git3_commit_lookup(&commit, repo, id));
		cl_git_pass(git3_vector_insert(&mc->commits, commit));
	}

	return 0;
}

/** Compare the `git3_oid`s of two `git3_commit` objects. */
static int commit_id_cmp(const void *a, const void *b)
{
	return git3_oid_cmp(
			git3_commit_id((const git3_commit *)a), git3_commit_id((const git3_commit *)b));
}

/** Find a `git3_commit` whose ID matches the provided `git3_oid` key. */
static int id_commit_id_cmp(const void *key, const void *commit)
{
	return git3_oid_cmp((const git3_oid *)key, git3_commit_id((const git3_commit *)commit));
}

void test_graph_reachable_from_any__exhaustive(void)
{
	struct exhaustive_state mc = {
			.db = NULL,
			.commits = GIT3_VECTOR_INIT,
	};
	size_t child_idx, commit_count;
	size_t n_descendants;
	git3_commit *child_commit;
	git3_bitvec reachable;

	cl_git_pass(git3_repository_odb(&mc.db, repo));
	cl_git_pass(git3_odb_foreach(mc.db, &exhaustive_commits, &mc));
	git3_vector_set_cmp(&mc.commits, commit_id_cmp);
	git3_vector_sort(&mc.commits);
	cl_git_pass(git3_bitvec_init(
			&reachable,
			git3_vector_length(&mc.commits) * git3_vector_length(&mc.commits)));

	commit_count = git3_vector_length(&mc.commits);
	git3_vector_foreach (&mc.commits, child_idx, child_commit) {
		unsigned int parent_i;

		/* We treat each commit as being able to reach itself. */
		git3_bitvec_set(&reachable, child_idx * commit_count + child_idx, true);

		for (parent_i = 0; parent_i < git3_commit_parentcount(child_commit); ++parent_i) {
			size_t parent_idx = -1;
			cl_git_pass(git3_vector_bsearch2(
					&parent_idx,
					&mc.commits,
					id_commit_id_cmp,
					git3_commit_parent_id(child_commit, parent_i)));

			/* We have established that parent_idx is reachable from child_idx */
			git3_bitvec_set(&reachable, parent_idx * commit_count + child_idx, true);
		}
	}

	/* Floyd-Warshall */
	{
		size_t i, j, k;
		for (k = 0; k < commit_count; ++k) {
			for (i = 0; i < commit_count; ++i) {
				if (!git3_bitvec_get(&reachable, i * commit_count + k))
					continue;
				for (j = 0; j < commit_count; ++j) {
					if (!git3_bitvec_get(&reachable, k * commit_count + j))
						continue;
					git3_bitvec_set(&reachable, i * commit_count + j, true);
				}
			}
		}
	}

	/* Try 1000 subsets of 1 through 10 entries each. */
	srand(0x223ddc4b);
	for (n_descendants = 1; n_descendants < 10; ++n_descendants) {
		size_t test_iteration;
		git3_oid descendants[10];

		for (test_iteration = 0; test_iteration < 1000; ++test_iteration) {
			size_t descendant_i;
			size_t child_idx, parent_idx;
			int expected_reachable = false, actual_reachable;
			git3_commit *child_commit, *parent_commit;

			parent_idx = rand() % commit_count;
			parent_commit = (git3_commit *)git3_vector_get(&mc.commits, parent_idx);
			for (descendant_i = 0; descendant_i < n_descendants; ++descendant_i) {
				child_idx = rand() % commit_count;
				child_commit = (git3_commit *)git3_vector_get(&mc.commits, child_idx);
				expected_reachable |= git3_bitvec_get(
						&reachable, parent_idx * commit_count + child_idx);
				git3_oid_cpy(&descendants[descendant_i],
					    git3_commit_id(child_commit));
			}

			actual_reachable = git3_graph_reachable_from_any(
					repo,
					git3_commit_id(parent_commit),
					descendants,
					n_descendants);
			if (actual_reachable != expected_reachable) {
				git3_str error_message_buf = GIT3_STR_INIT;
				char parent_oidbuf[9] = {0}, child_oidbuf[9] = {0};

				cl_git_pass(git3_oid_nfmt(
						parent_oidbuf, 8, git3_commit_id(parent_commit)));
				git3_str_printf(&error_message_buf,
					       "git3_graph_reachable_from_any(\"%s\", %zu, "
					       "{",
					       parent_oidbuf,
					       n_descendants);
				for (descendant_i = 0; descendant_i < n_descendants;
				     ++descendant_i) {
					cl_git_pass(
							git3_oid_nfmt(child_oidbuf,
								     8,
								     &descendants[descendant_i]));
					git3_str_printf(&error_message_buf, " \"%s\"", child_oidbuf);
				}
				git3_str_printf(&error_message_buf,
					       " }) = %d, expected = %d",
					       actual_reachable,
					       expected_reachable);
				cl_check_(actual_reachable == expected_reachable,
					  git3_str_cstr(&error_message_buf));
			}
		}
	}

	git3_vector_foreach (&mc.commits, child_idx, child_commit)
		git3_commit_free(child_commit);
	git3_bitvec_free(&reachable);
	git3_vector_dispose(&mc.commits);
	git3_odb_free(mc.db);
}
