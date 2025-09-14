#ifndef INCLUDE_cl_merge_helpers_h__
#define INCLUDE_cl_merge_helpers_h__

#include "merge.h"
#include "git3/merge.h"

struct merge_index_entry {
	uint16_t mode;
	char oid_str[GIT3_OID_SHA1_HEXSIZE+1];
	int stage;
	char path[128];
};

struct merge_name_entry {
	char ancestor_path[128];
	char our_path[128];
	char their_path[128];
};

struct merge_index_with_status {
	struct merge_index_entry entry;
	unsigned int status;
};

struct merge_reuc_entry {
	char path[128];
	unsigned int ancestor_mode;
	unsigned int our_mode;
	unsigned int their_mode;
	char ancestor_oid_str[GIT3_OID_SHA1_HEXSIZE+1];
	char our_oid_str[GIT3_OID_SHA1_HEXSIZE+1];
	char their_oid_str[GIT3_OID_SHA1_HEXSIZE+1];
};

struct merge_index_conflict_data {
	struct merge_index_with_status ancestor;
	struct merge_index_with_status ours;
	struct merge_index_with_status theirs;
	git3_merge_diff_t change_type;
};

int merge_trees_from_branches(
	git3_index **index, git3_repository *repo,
	const char *ours_name, const char *theirs_name,
	git3_merge_options *opts);

int merge_commits_from_branches(
	git3_index **index, git3_repository *repo,
	const char *ours_name, const char *theirs_name,
	git3_merge_options *opts);

int merge_branches(git3_repository *repo,
	const char *ours_branch, const char *theirs_branch,
	git3_merge_options *merge_opts, git3_checkout_options *checkout_opts);

int merge_test_diff_list(git3_merge_diff_list *diff_list, const struct merge_index_entry expected[], size_t expected_len);

int merge_test_merge_conflicts(git3_vector *conflicts, const struct merge_index_conflict_data expected[], size_t expected_len);

int merge_test_index(git3_index *index, const struct merge_index_entry expected[], size_t expected_len);

int merge_test_names(git3_index *index, const struct merge_name_entry expected[], size_t expected_len);

int merge_test_reuc(git3_index *index, const struct merge_reuc_entry expected[], size_t expected_len);

int merge_test_workdir(git3_repository *repo, const struct merge_index_entry expected[], size_t expected_len);

void merge__dump_names(git3_index *index);
void merge__dump_index_entries(git3_vector *index_entries);
void merge__dump_reuc(git3_index *index);

#endif
