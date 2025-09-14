#ifndef INCLUDE_blame_h__
#define INCLUDE_blame_h__

#include "common.h"

#include "git3/blame.h"
#include "vector.h"
#include "diff.h"
#include "array.h"
#include "git3/oid.h"

/*
 * One blob in a commit that is being suspected
 */
typedef struct git3_blame__origin {
	int refcnt;
	struct git3_blame__origin *previous;
	git3_commit *commit;
	git3_blob *blob;
	char path[GIT3_FLEX_ARRAY];
} git3_blame__origin;

/*
 * Each group of lines is described by a git3_blame__entry; it can be split
 * as we pass blame to the parents.  They form a linked list in the
 * scoreboard structure, sorted by the target line number.
 */
typedef struct git3_blame__entry {
	struct git3_blame__entry *prev;
	struct git3_blame__entry *next;

	/* the first line of this group in the final image;
	 * internally all line numbers are 0 based.
	 */
	size_t lno;

	/* how many lines this group has */
	size_t num_lines;

	/* the commit that introduced this group into the final image */
	git3_blame__origin *suspect;

	/* true if the suspect is truly guilty; false while we have not
	 * checked if the group came from one of its parents.
	 */
	bool guilty;

	/* true if the entry has been scanned for copies in the current parent
	 */
	bool scanned;

	/* the line number of the first line of this group in the
	 * suspect's file; internally all line numbers are 0 based.
	 */
	size_t s_lno;

	/* how significant this entry is -- cached to avoid
	 * scanning the lines over and over.
	 */
	unsigned score;

	/* Whether this entry has been tracked to a boundary commit.
	 */
	bool is_boundary;
} git3_blame__entry;

struct git3_blame {
	char *path;
	git3_repository *repository;
	git3_mailmap *mailmap;
	git3_blame_options options;

	git3_vector hunks;
	git3_array_t(git3_blame_line) lines;
	git3_vector paths;

	git3_blob *final_blob;
	git3_array_t(size_t) line_index;

	size_t current_diff_line;
	git3_blame_hunk *current_hunk;

	/* Scoreboard fields */
	git3_commit *final;
	git3_blame__entry *ent;
	int num_lines;
	const char *final_buf;
	size_t final_buf_size;
};

git3_blame *git3_blame__alloc(
	git3_repository *repo,
	git3_blame_options opts,
	const char *path);

#endif
