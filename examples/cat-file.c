/*
 * libgit3 "cat-file" example - shows how to print data from the ODB
 *
 * Written by the libgit3 contributors
 *
 * To the extent possible under law, the author(s) have dedicated all copyright
 * and related and neighboring rights to this software to the public domain
 * worldwide. This software is distributed without any warranty.
 *
 * You should have received a copy of the CC0 Public Domain Dedication along
 * with this software. If not, see
 * <http://creativecommons.org/publicdomain/zero/1.0/>.
 */

#include "common.h"

static void print_signature(const char *header, const git3_signature *sig)
{
	char sign;
	int offset, hours, minutes;

	if (!sig)
		return;

	offset = sig->when.offset;
	if (offset < 0) {
		sign = '-';
		offset = -offset;
	} else {
		sign = '+';
	}

	hours   = offset / 60;
	minutes = offset % 60;

	printf("%s %s <%s> %ld %c%02d%02d\n",
		   header, sig->name, sig->email, (long)sig->when.time,
		   sign, hours, minutes);
}

/** Printing out a blob is simple, get the contents and print */
static void show_blob(const git3_blob *blob)
{
	/* ? Does this need crlf filtering? */
	fwrite(git3_blob_rawcontent(blob), (size_t)git3_blob_rawsize(blob), 1, stdout);
}

/** Show each entry with its type, id and attributes */
static void show_tree(const git3_tree *tree)
{
	size_t i, max_i = (int)git3_tree_entrycount(tree);
	char oidstr[GIT3_OID_SHA1_HEXSIZE + 1];
	const git3_tree_entry *te;

	for (i = 0; i < max_i; ++i) {
		te = git3_tree_entry_byindex(tree, i);

		git3_oid_tostr(oidstr, sizeof(oidstr), git3_tree_entry_id(te));

		printf("%06o %s %s\t%s\n",
			git3_tree_entry_filemode(te),
			git3_object_type2string(git3_tree_entry_type(te)),
			oidstr, git3_tree_entry_name(te));
	}
}

/**
 * Commits and tags have a few interesting fields in their header.
 */
static void show_commit(const git3_commit *commit)
{
	unsigned int i, max_i;
	char oidstr[GIT3_OID_SHA1_HEXSIZE + 1];

	git3_oid_tostr(oidstr, sizeof(oidstr), git3_commit_tree_id(commit));
	printf("tree %s\n", oidstr);

	max_i = (unsigned int)git3_commit_parentcount(commit);
	for (i = 0; i < max_i; ++i) {
		git3_oid_tostr(oidstr, sizeof(oidstr), git3_commit_parent_id(commit, i));
		printf("parent %s\n", oidstr);
	}

	print_signature("author", git3_commit_author(commit));
	print_signature("committer", git3_commit_committer(commit));

	if (git3_commit_message(commit))
		printf("\n%s\n", git3_commit_message(commit));
}

static void show_tag(const git3_tag *tag)
{
	char oidstr[GIT3_OID_SHA1_HEXSIZE + 1];

	git3_oid_tostr(oidstr, sizeof(oidstr), git3_tag_target_id(tag));;
	printf("object %s\n", oidstr);
	printf("type %s\n", git3_object_type2string(git3_tag_target_type(tag)));
	printf("tag %s\n", git3_tag_name(tag));
	print_signature("tagger", git3_tag_tagger(tag));

	if (git3_tag_message(tag))
		printf("\n%s\n", git3_tag_message(tag));
}

typedef enum {
	SHOW_TYPE = 1,
	SHOW_SIZE = 2,
	SHOW_NONE = 3,
	SHOW_PRETTY = 4
} catfile_mode;

/* Forward declarations for option-parsing helper */
struct catfile_options {
	const char *dir;
	const char *rev;
	catfile_mode action;
	int verbose;
};

static void parse_opts(struct catfile_options *o, int argc, char *argv[]);


/** Entry point for this command */
int lg2_cat_file(git3_repository *repo, int argc, char *argv[])
{
	struct catfile_options o = { ".", NULL, 0, 0 };
	git3_object *obj = NULL;
	char oidstr[GIT3_OID_SHA1_HEXSIZE + 1];

	parse_opts(&o, argc, argv);

	check_lg2(git3_revparse_single(&obj, repo, o.rev),
			"Could not resolve", o.rev);

	if (o.verbose) {
		char oidstr[GIT3_OID_SHA1_HEXSIZE + 1];
		git3_oid_tostr(oidstr, sizeof(oidstr), git3_object_id(obj));

		printf("%s %s\n--\n",
			git3_object_type2string(git3_object_type(obj)), oidstr);
	}

	switch (o.action) {
	case SHOW_TYPE:
		printf("%s\n", git3_object_type2string(git3_object_type(obj)));
		break;
	case SHOW_SIZE: {
		git3_odb *odb;
		git3_odb_object *odbobj;

		check_lg2(git3_repository_odb(&odb, repo), "Could not open ODB", NULL);
		check_lg2(git3_odb_read(&odbobj, odb, git3_object_id(obj)),
			"Could not find obj", NULL);

		printf("%ld\n", (long)git3_odb_object_size(odbobj));

		git3_odb_object_free(odbobj);
		git3_odb_free(odb);
		}
		break;
	case SHOW_NONE:
		/* just want return result */
		break;
	case SHOW_PRETTY:

		switch (git3_object_type(obj)) {
		case GIT3_OBJECT_BLOB:
			show_blob((const git3_blob *)obj);
			break;
		case GIT3_OBJECT_COMMIT:
			show_commit((const git3_commit *)obj);
			break;
		case GIT3_OBJECT_TREE:
			show_tree((const git3_tree *)obj);
			break;
		case GIT3_OBJECT_TAG:
			show_tag((const git3_tag *)obj);
			break;
		default:
			printf("unknown %s\n", oidstr);
			break;
		}
		break;
	}

	git3_object_free(obj);

	return 0;
}

/** Print out usage information */
static void usage(const char *message, const char *arg)
{
	if (message && arg)
		fprintf(stderr, "%s: %s\n", message, arg);
	else if (message)
		fprintf(stderr, "%s\n", message);
	fprintf(stderr,
			"usage: cat-file (-t | -s | -e | -p) [-v] [-q] "
			"[-h|--help] [--git-dir=<dir>] <object>\n");
	exit(1);
}

/** Parse the command-line options taken from git */
static void parse_opts(struct catfile_options *o, int argc, char *argv[])
{
	struct args_info args = ARGS_INFO_INIT;

	for (args.pos = 1; args.pos < argc; ++args.pos) {
		char *a = argv[args.pos];

		if (a[0] != '-') {
			if (o->rev != NULL)
				usage("Only one rev should be provided", NULL);
			else
				o->rev = a;
		}
		else if (!strcmp(a, "-t"))
			o->action = SHOW_TYPE;
		else if (!strcmp(a, "-s"))
			o->action = SHOW_SIZE;
		else if (!strcmp(a, "-e"))
			o->action = SHOW_NONE;
		else if (!strcmp(a, "-p"))
			o->action = SHOW_PRETTY;
		else if (!strcmp(a, "-q"))
			o->verbose = 0;
		else if (!strcmp(a, "-v"))
			o->verbose = 1;
		else if (!strcmp(a, "--help") || !strcmp(a, "-h"))
			usage(NULL, NULL);
		else if (!match_str_arg(&o->dir, &args, "--git-dir"))
			usage("Unknown option", a);
	}

	if (!o->action || !o->rev)
		usage(NULL, NULL);

}
