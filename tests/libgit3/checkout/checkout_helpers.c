#include "clar_libgit3.h"
#include "checkout_helpers.h"
#include "refs.h"
#include "futils.h"
#include "index.h"

void assert_on_branch(git3_repository *repo, const char *branch)
{
	git3_reference *head;
	git3_str bname = GIT3_STR_INIT;

	cl_git_pass(git3_reference_lookup(&head, repo, GIT3_HEAD_FILE));
	cl_assert_(git3_reference_type(head) == GIT3_REFERENCE_SYMBOLIC, branch);

	cl_git_pass(git3_str_joinpath(&bname, "refs/heads", branch));
	cl_assert_equal_s(bname.ptr, git3_reference_symbolic_target(head));

	git3_reference_free(head);
	git3_str_dispose(&bname);
}

void reset_index_to_treeish(git3_object *treeish)
{
	git3_object *tree;
	git3_index *index;
	git3_repository *repo = git3_object_owner(treeish);

	cl_git_pass(git3_object_peel(&tree, treeish, GIT3_OBJECT_TREE));

	cl_git_pass(git3_repository_index(&index, repo));
	cl_git_pass(git3_index_read_tree(index, (git3_tree *)tree));
	cl_git_pass(git3_index_write(index));

	git3_object_free(tree);
	git3_index_free(index);
}

int checkout_count_callback(
	git3_checkout_notify_t why,
	const char *path,
	const git3_diff_file *baseline,
	const git3_diff_file *target,
	const git3_diff_file *workdir,
	void *payload)
{
	checkout_counts *ct = payload;

	GIT3_UNUSED(baseline); GIT3_UNUSED(target); GIT3_UNUSED(workdir);

	if (why & GIT3_CHECKOUT_NOTIFY_CONFLICT) {
		ct->n_conflicts++;

		if (ct->debug) {
			if (workdir) {
				if (baseline) {
					if (target)
						fprintf(stderr, "M %s (conflicts with M %s)\n",
							workdir->path, target->path);
					else
						fprintf(stderr, "M %s (conflicts with D %s)\n",
							workdir->path, baseline->path);
				} else {
					if (target)
						fprintf(stderr, "Existing %s (conflicts with A %s)\n",
							workdir->path, target->path);
					else
						fprintf(stderr, "How can an untracked file be a conflict (%s)\n", workdir->path);
				}
			} else {
				if (baseline) {
					if (target)
						fprintf(stderr, "D %s (conflicts with M %s)\n",
							target->path, baseline->path);
					else
						fprintf(stderr, "D %s (conflicts with D %s)\n",
							baseline->path, baseline->path);
				} else {
					if (target)
						fprintf(stderr, "How can an added file with no workdir be a conflict (%s)\n", target->path);
					else
						fprintf(stderr, "How can a nonexistent file be a conflict (%s)\n", path);
				}
			}
		}
	}

	if (why & GIT3_CHECKOUT_NOTIFY_DIRTY) {
		ct->n_dirty++;

		if (ct->debug) {
			if (workdir)
				fprintf(stderr, "M %s\n", workdir->path);
			else
				fprintf(stderr, "D %s\n", baseline->path);
		}
	}

	if (why & GIT3_CHECKOUT_NOTIFY_UPDATED) {
		ct->n_updates++;

		if (ct->debug) {
			if (baseline) {
				if (target)
					fprintf(stderr, "update: M %s\n", path);
				else
					fprintf(stderr, "update: D %s\n", path);
			} else {
				if (target)
					fprintf(stderr, "update: A %s\n", path);
				else
					fprintf(stderr, "update: this makes no sense %s\n", path);
			}
		}
	}

	if (why & GIT3_CHECKOUT_NOTIFY_UNTRACKED) {
		ct->n_untracked++;

		if (ct->debug)
			fprintf(stderr, "? %s\n", path);
	}

	if (why & GIT3_CHECKOUT_NOTIFY_IGNORED) {
		ct->n_ignored++;

		if (ct->debug)
			fprintf(stderr, "I %s\n", path);
	}

	return 0;
}

void tick_index(git3_index *index)
{
	struct timespec ts;
	struct p_timeval times[2];

	cl_assert(index->on_disk);
	cl_assert(git3_index_path(index));

	cl_git_pass(git3_index_read(index, true));
	ts = index->stamp.mtime;

	times[0].tv_sec = ts.tv_sec;
	times[0].tv_usec = ts.tv_nsec / 1000;
	times[1].tv_sec = ts.tv_sec + 5;
	times[1].tv_usec = ts.tv_nsec / 1000;

	cl_git_pass(p_utimes(git3_index_path(index), times));
	cl_git_pass(git3_index_read(index, true));
}
