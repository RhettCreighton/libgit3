
extern void expect_iterator_items(
	git3_iterator *i,
	size_t expected_flat,
	const char **expected_flat_paths,
	size_t expected_total,
	const char **expected_total_paths);

extern void expect_advance_over(
	git3_iterator *i,
	const char *expected_path,
	git3_iterator_status_t expected_status);

void expect_advance_into(
	git3_iterator *i,
	const char *expected_path);
