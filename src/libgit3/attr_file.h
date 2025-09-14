/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_attr_file_h__
#define INCLUDE_attr_file_h__

#include "common.h"

#include "git3/oid.h"
#include "git3/attr.h"
#include "vector.h"
#include "pool.h"
#include "str.h"
#include "futils.h"

#define GIT3_ATTR_FILE			".gitattributes"
#define GIT3_ATTR_FILE_INREPO	"attributes"
#define GIT3_ATTR_FILE_SYSTEM	"gitattributes"
#define GIT3_ATTR_FILE_XDG		"attributes"

#define GIT3_ATTR_MAX_FILE_SIZE	100 * 1024 * 1024

#define GIT3_ATTR_FNMATCH_NEGATIVE	(1U << 0)
#define GIT3_ATTR_FNMATCH_DIRECTORY	(1U << 1)
#define GIT3_ATTR_FNMATCH_FULLPATH	(1U << 2)
#define GIT3_ATTR_FNMATCH_MACRO		(1U << 3)
#define GIT3_ATTR_FNMATCH_IGNORE		(1U << 4)
#define GIT3_ATTR_FNMATCH_HASWILD	(1U << 5)
#define GIT3_ATTR_FNMATCH_ALLOWSPACE	(1U << 6)
#define GIT3_ATTR_FNMATCH_ICASE		(1U << 7)
#define GIT3_ATTR_FNMATCH_MATCH_ALL	(1U << 8)
#define GIT3_ATTR_FNMATCH_ALLOWNEG   (1U << 9)
#define GIT3_ATTR_FNMATCH_ALLOWMACRO (1U << 10)

#define GIT3_ATTR_FNMATCH__INCOMING \
	(GIT3_ATTR_FNMATCH_ALLOWSPACE | GIT3_ATTR_FNMATCH_ALLOWNEG | GIT3_ATTR_FNMATCH_ALLOWMACRO)

typedef enum {
	GIT3_ATTR_FILE_SOURCE_MEMORY = 0,
	GIT3_ATTR_FILE_SOURCE_FILE   = 1,
	GIT3_ATTR_FILE_SOURCE_INDEX  = 2,
	GIT3_ATTR_FILE_SOURCE_HEAD   = 3,
	GIT3_ATTR_FILE_SOURCE_COMMIT = 4,

	GIT3_ATTR_FILE_NUM_SOURCES   = 5
} git3_attr_file_source_t;

typedef struct {
	/* The source location for the attribute file. */
	git3_attr_file_source_t type;

	/*
	 * The filename of the attribute file to read (relative to the
	 * given base path).
	 */
	const char *base;
	const char *filename;

	/*
	 * The commit ID when the given source type is a commit (or NULL
	 * for the repository's HEAD commit.)
	 */
	git3_oid *commit_id;
} git3_attr_file_source;

extern const char *git3_attr__true;
extern const char *git3_attr__false;
extern const char *git3_attr__unset;

typedef struct {
	char *pattern;
	size_t length;
	char *containing_dir;
	size_t containing_dir_length;
	unsigned int flags;
} git3_attr_fnmatch;

typedef struct {
	git3_attr_fnmatch match;
	git3_vector assigns;		/* vector of <git3_attr_assignment*> */
} git3_attr_rule;

typedef struct {
	git3_refcount unused;
	const char *name;
	uint32_t name_hash;
} git3_attr_name;

typedef struct {
	git3_refcount rc;		/* for macros */
	char *name;
	uint32_t name_hash;
	const char *value;
} git3_attr_assignment;

typedef struct git3_attr_file_entry git3_attr_file_entry;

typedef struct {
	git3_refcount rc;
	git3_mutex lock;
	git3_attr_file_entry *entry;
	git3_attr_file_source source;
	git3_vector rules;			/* vector of <rule*> or <fnmatch*> */
	git3_pool pool;
	unsigned int nonexistent:1;
	int session_key;
	union {
		git3_oid oid;
		git3_futils_filestamp stamp;
	} cache_data;
} git3_attr_file;

struct git3_attr_file_entry {
	git3_attr_file *file[GIT3_ATTR_FILE_NUM_SOURCES];
	const char *path; /* points into fullpath */
	char fullpath[GIT3_FLEX_ARRAY];
};

typedef struct {
	git3_str  full;
	char    *path;
	char    *basename;
	int      is_dir;
} git3_attr_path;

/* A git3_attr_session can provide an "instance" of reading, to prevent cache
 * invalidation during a single operation instance (like checkout).
 */

typedef struct {
	int key;
	unsigned int init_setup:1,
		init_sysdir:1;
	git3_str sysdir;
	git3_str tmp;
} git3_attr_session;

extern int git3_attr_session__init(git3_attr_session *attr_session, git3_repository *repo);
extern void git3_attr_session__free(git3_attr_session *session);

extern int git3_attr_get_many_with_session(
	const char **values_out,
	git3_repository *repo,
	git3_attr_session *attr_session,
	git3_attr_options *opts,
	const char *path,
	size_t num_attr,
	const char **names);

typedef int (*git3_attr_file_parser)(
	git3_repository *repo,
	git3_attr_file *file,
	const char *data,
	bool allow_macros);

/*
 * git3_attr_file API
 */

int git3_attr_file__new(
	git3_attr_file **out,
	git3_attr_file_entry *entry,
	git3_attr_file_source *source);

void git3_attr_file__free(git3_attr_file *file);

int git3_attr_file__load(
	git3_attr_file **out,
	git3_repository *repo,
	git3_attr_session *attr_session,
	git3_attr_file_entry *ce,
	git3_attr_file_source *source,
	git3_attr_file_parser parser,
	bool allow_macros);

int git3_attr_file__load_standalone(
	git3_attr_file **out, const char *path);

int git3_attr_file__out_of_date(
	git3_repository *repo, git3_attr_session *session, git3_attr_file *file, git3_attr_file_source *source);

int git3_attr_file__parse_buffer(
	git3_repository *repo, git3_attr_file *attrs, const char *data, bool allow_macros);

int git3_attr_file__clear_rules(
	git3_attr_file *file, bool need_lock);

int git3_attr_file__lookup_one(
	git3_attr_file *file,
	git3_attr_path *path,
	const char *attr,
	const char **value);

/* loop over rules in file from bottom to top */
#define git3_attr_file__foreach_matching_rule(file, path, iter, rule)	\
	git3_vector_rforeach(&(file)->rules, (iter), (rule)) \
		if (git3_attr_rule__match((rule), (path)))

uint32_t git3_attr_file__name_hash(const char *name);


/*
 * other utilities
 */

extern int git3_attr_fnmatch__parse(
	git3_attr_fnmatch *spec,
	git3_pool *pool,
	const char *source,
	const char **base);

extern bool git3_attr_fnmatch__match(
	git3_attr_fnmatch *rule,
	git3_attr_path *path);

extern void git3_attr_rule__free(git3_attr_rule *rule);

extern bool git3_attr_rule__match(
	git3_attr_rule *rule,
	git3_attr_path *path);

extern git3_attr_assignment *git3_attr_rule__lookup_assignment(
	git3_attr_rule *rule, const char *name);

typedef enum { GIT3_DIR_FLAG_TRUE = 1, GIT3_DIR_FLAG_FALSE = 0, GIT3_DIR_FLAG_UNKNOWN = -1 } git3_dir_flag;

extern int git3_attr_path__init(
	git3_attr_path *out,
	const char *path,
	const char *base,
	git3_dir_flag is_dir);
extern void git3_attr_path__free(git3_attr_path *info);

extern int git3_attr_assignment__parse(
	git3_repository *repo, /* needed to expand macros */
	git3_pool *pool,
	git3_vector *assigns,
	const char **scan);

#endif
