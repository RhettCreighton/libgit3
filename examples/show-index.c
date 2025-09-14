/*
 * libgit3 "showindex" example - shows how to extract data from the index
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

int lg2_show_index(git3_repository *repo, int argc, char **argv)
{
	git3_index *index;
	size_t i, ecount;
	char *dir = ".";
	size_t dirlen;
	char out[GIT3_OID_SHA1_HEXSIZE+1];
	out[GIT3_OID_SHA1_HEXSIZE] = '\0';

	if (argc > 2)
		fatal("usage: showindex [<repo-dir>]", NULL);
	if (argc > 1)
		dir = argv[1];

	dirlen = strlen(dir);
	if (dirlen > 5 && strcmp(dir + dirlen - 5, "index") == 0) {
		check_lg2(git3_index_open(&index, dir), "could not open index", dir);
	} else {
		check_lg2(git3_repository_open_ext(&repo, dir, 0, NULL), "could not open repository", dir);
		check_lg2(git3_repository_index(&index, repo), "could not open repository index", NULL);
		git3_repository_free(repo);
	}

	git3_index_read(index, 0);

	ecount = git3_index_entrycount(index);
	if (!ecount)
		printf("Empty index\n");

	for (i = 0; i < ecount; ++i) {
		const git3_index_entry *e = git3_index_get_byindex(index, i);

		git3_oid_fmt(out, &e->id);

		printf("File Path: %s\n", e->path);
		printf("    Stage: %d\n", git3_index_entry_stage(e));
		printf(" Blob SHA: %s\n", out);
		printf("File Mode: %07o\n", e->mode);
		printf("File Size: %d bytes\n", (int)e->file_size);
		printf("Dev/Inode: %d/%d\n", (int)e->dev, (int)e->ino);
		printf("  UID/GID: %d/%d\n", (int)e->uid, (int)e->gid);
		printf("    ctime: %d\n", (int)e->ctime.seconds);
		printf("    mtime: %d\n", (int)e->mtime.seconds);
		printf("\n");
	}

	git3_index_free(index);

	return 0;
}
