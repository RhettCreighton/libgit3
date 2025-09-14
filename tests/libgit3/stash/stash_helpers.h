void setup_stash(
	git3_repository *repo,
	git3_signature *signature);

void assert_status(
	git3_repository *repo,
	const char *path,
	int status_flags);
