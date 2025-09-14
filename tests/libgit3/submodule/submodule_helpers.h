extern void rewrite_gitmodules(const char *workdir);

/* these will automatically set a cleanup callback */
extern git3_repository *setup_fixture_submodules(void);
extern git3_repository *setup_fixture_submod2(void);
extern git3_repository *setup_fixture_submod3(void);
extern git3_repository *setup_fixture_submodule_simple(void);
extern git3_repository *setup_fixture_super(void);
extern git3_repository *setup_fixture_submodule_with_path(void);

extern unsigned int get_submodule_status(git3_repository *, const char *);

extern void assert__submodule_exists(git3_repository *, const char *,
	const char *, const char *, const char *, int);

#define assert_submodule_exists(repo,name)								\
	assert__submodule_exists(repo, name, "git3_submodule_lookup(" #name ") failed", __FILE__, __func__, __LINE__)

extern void refute__submodule_exists(git3_repository *, const char *,
	int err, const char *, const char *, const char *, int);

#define refute_submodule_exists(repo,name,code) \
	refute__submodule_exists(repo, name, code, "expected git3_submodule_lookup(" #name ") to fail with error " #code, __FILE__, __func__, __LINE__)

extern void dump_submodules(git3_repository *repo);
