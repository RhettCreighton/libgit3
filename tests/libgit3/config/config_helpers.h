extern void assert_config_entry_existence(
	git3_repository *repo,
	const char *name,
	bool is_supposed_to_exist);

extern void assert_config_entry_value(
	git3_repository *repo,
	const char *name,
	const char *expected_value);

extern int count_config_entries_match(
	git3_repository *repo,
	const char *pattern);
