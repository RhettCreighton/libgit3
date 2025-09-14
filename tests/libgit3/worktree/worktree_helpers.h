typedef struct {
	const char *reponame;
	const char *worktreename;
	git3_repository *repo;
	git3_repository *worktree;
} worktree_fixture;

#define WORKTREE_FIXTURE_INIT(repo, worktree) { (repo), (worktree), NULL, NULL }

void cleanup_fixture_worktree(worktree_fixture *fixture);
void setup_fixture_worktree(worktree_fixture *fixture);
