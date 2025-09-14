#include "clar_libgit3.h"
#include "../filter/crlf.h"

#include "git3/checkout.h"
#include "repository.h"
#include "posix.h"

#define FILE_CONTENTS_LF "one\ntwo\nthree\nfour\n"
#define FILE_CONTENTS_CRLF "one\r\ntwo\r\nthree\r\nfour\r\n"

#define FILE_OID_LF "f384549cbeb481e437091320de6d1f2e15e11b4a"
#define FILE_OID_CRLF "7fbf4d847b191141d80f30c8ab03d2ad4cd543a9"

static git3_repository *g_repo;
static git3_index *g_index;

static git3_str expected_fixture = GIT3_STR_INIT;

void test_index_crlf__initialize(void)
{
	g_repo = cl_git_sandbox_init_new("crlf");
	cl_git_pass(git3_repository_index(&g_index, g_repo));
}

void test_index_crlf__cleanup(void)
{
	git3_index_free(g_index);
	cl_git_sandbox_cleanup();

	if (expected_fixture.size) {
		cl_fixture_cleanup(expected_fixture.ptr);
		git3_str_dispose(&expected_fixture);
	}
}

struct compare_data
{
	const char *systype;
	const char *dirname;
	const char *safecrlf;
	const char *autocrlf;
	const char *attrs;
};

static int add_and_check_file(void *payload, git3_str *actual_path)
{
	git3_str expected_path = GIT3_STR_INIT;
	git3_str expected_path_fail = GIT3_STR_INIT;
	git3_str expected_contents = GIT3_STR_INIT;
	struct compare_data *cd = payload;
	char *basename;
	const git3_index_entry *entry;
	git3_blob *blob;
	bool failed = true;

	basename = git3_fs_path_basename(actual_path->ptr);

	if (!strcmp(basename, ".git") || !strcmp(basename, ".gitattributes")) {
		failed = false;
		goto done;
	}

	cl_git_pass(git3_str_joinpath(&expected_path, cd->dirname, basename));

	cl_git_pass(git3_str_puts(&expected_path_fail, expected_path.ptr));
	cl_git_pass(git3_str_puts(&expected_path_fail, ".fail"));

	if (git3_fs_path_isfile(expected_path.ptr)) {
		cl_git_pass(git3_index_add_bypath(g_index, basename));

		cl_assert(entry = git3_index_get_bypath(g_index, basename, 0));
		cl_git_pass(git3_blob_lookup(&blob, g_repo, &entry->id));

		cl_git_pass(git3_futils_readbuffer(&expected_contents, expected_path.ptr));

		if (strcmp(expected_contents.ptr, git3_blob_rawcontent(blob)) != 0)
			goto done;

		git3_blob_free(blob);
	} else if (git3_fs_path_isfile(expected_path_fail.ptr)) {
		cl_git_pass(git3_futils_readbuffer(&expected_contents, expected_path_fail.ptr));
		git3_str_rtrim(&expected_contents);

		if (git3_index_add_bypath(g_index, basename) == 0 ||
			git3_error_last()->klass != GIT3_ERROR_FILTER ||
			strcmp(expected_contents.ptr, git3_error_last()->message) != 0)
			goto done;
	} else {
		cl_fail("unexpected index failure");
	}

	failed = false;

done:
	if (failed) {
		git3_str details = GIT3_STR_INIT;
		git3_str_printf(&details, "filename=%s, system=%s, autocrlf=%s, safecrlf=%s, attrs={%s}",
			basename, cd->systype, cd->autocrlf, cd->safecrlf, cd->attrs);
		clar__fail(__FILE__, __func__, __LINE__,
			"index contents did not match expected", details.ptr, 0);
		git3_str_dispose(&details);
	}

	git3__free(basename);
	git3_str_dispose(&expected_contents);
	git3_str_dispose(&expected_path);
	git3_str_dispose(&expected_path_fail);
	return 0;
}

static const char *system_type(void)
{
	if (GIT3_EOL_NATIVE == GIT3_EOL_CRLF)
		return "windows";
	else
		return "posix";
}

static void test_add_index(const char *safecrlf, const char *autocrlf, const char *attrs)
{
	git3_str attrbuf = GIT3_STR_INIT;
	git3_str expected_dirname = GIT3_STR_INIT;
	git3_str sandboxname = GIT3_STR_INIT;
	git3_str reponame = GIT3_STR_INIT;
	struct compare_data compare_data = { system_type(), NULL, safecrlf, autocrlf, attrs };
	const char *c;

	git3_str_puts(&reponame, "crlf");

	git3_str_puts(&sandboxname, "autocrlf_");
	git3_str_puts(&sandboxname, autocrlf);

	git3_str_puts(&sandboxname, ",safecrlf_");
	git3_str_puts(&sandboxname, safecrlf);

	if (*attrs) {
		git3_str_puts(&sandboxname, ",");

		for (c = attrs; *c; c++) {
			if (*c == ' ')
				git3_str_putc(&sandboxname, ',');
			else if (*c == '=')
				git3_str_putc(&sandboxname, '_');
			else
				git3_str_putc(&sandboxname, *c);
		}

		git3_str_printf(&attrbuf, "* %s\n", attrs);
		cl_git_mkfile("crlf/.gitattributes", attrbuf.ptr);
	}

	cl_repo_set_string(g_repo, "core.safecrlf", safecrlf);
	cl_repo_set_string(g_repo, "core.autocrlf", autocrlf);

	cl_git_pass(git3_index_clear(g_index));

	git3_str_joinpath(&expected_dirname, "crlf_data", system_type());
	git3_str_puts(&expected_dirname, "_to_odb");

	git3_str_joinpath(&expected_fixture, expected_dirname.ptr, sandboxname.ptr);
	cl_fixture_sandbox(expected_fixture.ptr);

	compare_data.dirname = sandboxname.ptr;
	cl_git_pass(git3_fs_path_direach(&reponame, 0, add_and_check_file, &compare_data));

	cl_fixture_cleanup(expected_fixture.ptr);
	git3_str_dispose(&expected_fixture);

	git3_str_dispose(&attrbuf);
	git3_str_dispose(&expected_fixture);
	git3_str_dispose(&expected_dirname);
	git3_str_dispose(&sandboxname);
	git3_str_dispose(&reponame);
}

static void set_up_workingdir(const char *name)
{
	git3_vector contents = GIT3_VECTOR_INIT;
	size_t i;
	const char *fn;

	git3_fs_path_dirload(&contents, name, 0, 0);
	git3_vector_foreach(&contents, i, fn) {
		char *basename = git3_fs_path_basename(fn);
		bool skip = strncasecmp(basename, ".git", 4) == 0 && strlen(basename) == 4;

		git3__free(basename);

		if (skip)
			continue;
		p_unlink(fn);
	}
	git3_vector_dispose_deep(&contents);

	/* copy input files */
	git3_fs_path_dirload(&contents, cl_fixture("crlf"), 0, 0);
	git3_vector_foreach(&contents, i, fn) {
		char *basename = git3_fs_path_basename(fn);
		git3_str dest_filename = GIT3_STR_INIT;

		if (strcmp(basename, ".gitted") &&
			strcmp(basename, ".gitattributes")) {
			git3_str_joinpath(&dest_filename, name, basename);
			cl_git_pass(git3_futils_cp(fn, dest_filename.ptr, 0644));
		}

		git3__free(basename);
		git3_str_dispose(&dest_filename);
	}
	git3_vector_dispose_deep(&contents);
}

void test_index_crlf__matches_core_git(void)
{
	const char *safecrlf[] = { "true", "false", "warn", NULL };
	const char *autocrlf[] = { "true", "false", "input", NULL };
	const char *attrs[] = { "", "-crlf", "-text", "eol=crlf", "eol=lf",
		"text", "text eol=crlf", "text eol=lf",
		"text=auto", "text=auto eol=crlf", "text=auto eol=lf",
		NULL };
	const char **a, **b, **c;

	for (a = safecrlf; *a; a++) {
		for (b = autocrlf; *b; b++) {
			for (c = attrs; *c; c++) {
				set_up_workingdir("crlf");
				test_add_index(*a, *b, *c);
			}
		}
	}
}

void test_index_crlf__autocrlf_false_no_attrs(void)
{
	const git3_index_entry *entry;
	git3_oid oid;

	cl_repo_set_bool(g_repo, "core.autocrlf", false);

	cl_git_mkfile("./crlf/newfile.txt",
		(GIT3_EOL_NATIVE == GIT3_EOL_CRLF) ? FILE_CONTENTS_CRLF : FILE_CONTENTS_LF);

	cl_git_pass(git3_index_add_bypath(g_index, "newfile.txt"));
	entry = git3_index_get_bypath(g_index, "newfile.txt", 0);

	cl_git_pass(git3_oid_from_string(&oid,
		(GIT3_EOL_NATIVE == GIT3_EOL_CRLF) ? FILE_OID_CRLF : FILE_OID_LF,
		GIT3_OID_SHA1));
	cl_assert_equal_oid(&oid, &entry->id);
}

void test_index_crlf__autocrlf_true_no_attrs(void)
{
	const git3_index_entry *entry;
	git3_oid oid;

	cl_repo_set_bool(g_repo, "core.autocrlf", true);

	cl_git_mkfile("./crlf/newfile.txt",
		(GIT3_EOL_NATIVE == GIT3_EOL_CRLF) ? FILE_CONTENTS_CRLF : FILE_CONTENTS_LF);

	cl_git_pass(git3_index_add_bypath(g_index, "newfile.txt"));
	entry = git3_index_get_bypath(g_index, "newfile.txt", 0);

	cl_git_pass(git3_oid_from_string(&oid, FILE_OID_LF, GIT3_OID_SHA1));
	cl_assert_equal_oid(&oid, &entry->id);
}

void test_index_crlf__autocrlf_input_no_attrs(void)
{
	const git3_index_entry *entry;
	git3_oid oid;

	cl_repo_set_string(g_repo, "core.autocrlf", "input");

	cl_git_mkfile("./crlf/newfile.txt",
		(GIT3_EOL_NATIVE == GIT3_EOL_CRLF) ? FILE_CONTENTS_CRLF : FILE_CONTENTS_LF);

	cl_git_pass(git3_index_add_bypath(g_index, "newfile.txt"));
	entry = git3_index_get_bypath(g_index, "newfile.txt", 0);

	cl_git_pass(git3_oid_from_string(&oid, FILE_OID_LF, GIT3_OID_SHA1));
	cl_assert_equal_oid(&oid, &entry->id);
}

void test_index_crlf__autocrlf_false_text_auto_attr(void)
{
	const git3_index_entry *entry;
	git3_oid oid;

	cl_git_mkfile("./crlf/.gitattributes", "* text=auto\n");

	cl_repo_set_bool(g_repo, "core.autocrlf", false);

	cl_git_mkfile("./crlf/newfile.txt",
		(GIT3_EOL_NATIVE == GIT3_EOL_CRLF) ? FILE_CONTENTS_CRLF : FILE_CONTENTS_LF);

	cl_git_pass(git3_index_add_bypath(g_index, "newfile.txt"));
	entry = git3_index_get_bypath(g_index, "newfile.txt", 0);

	cl_git_pass(git3_oid_from_string(&oid, FILE_OID_LF, GIT3_OID_SHA1));
	cl_assert_equal_oid(&oid, &entry->id);
}

void test_index_crlf__autocrlf_true_text_auto_attr(void)
{
	const git3_index_entry *entry;
	git3_oid oid;

	cl_git_mkfile("./crlf/.gitattributes", "* text=auto\n");

	cl_repo_set_bool(g_repo, "core.autocrlf", false);

	cl_git_mkfile("./crlf/newfile.txt",
		(GIT3_EOL_NATIVE == GIT3_EOL_CRLF) ? FILE_CONTENTS_CRLF : FILE_CONTENTS_LF);

	cl_git_pass(git3_index_add_bypath(g_index, "newfile.txt"));
	entry = git3_index_get_bypath(g_index, "newfile.txt", 0);

	cl_git_pass(git3_oid_from_string(&oid, FILE_OID_LF, GIT3_OID_SHA1));
	cl_assert_equal_oid(&oid, &entry->id);
}

void test_index_crlf__autocrlf_input_text_auto_attr(void)
{
	const git3_index_entry *entry;
	git3_oid oid;

	cl_git_mkfile("./crlf/.gitattributes", "* text=auto\n");

	cl_repo_set_string(g_repo, "core.autocrlf", "input");

	cl_git_mkfile("./crlf/newfile.txt",
		(GIT3_EOL_NATIVE == GIT3_EOL_CRLF) ? FILE_CONTENTS_CRLF : FILE_CONTENTS_LF);

	cl_git_pass(git3_index_add_bypath(g_index, "newfile.txt"));
	entry = git3_index_get_bypath(g_index, "newfile.txt", 0);

	cl_git_pass(git3_oid_from_string(&oid, FILE_OID_LF, GIT3_OID_SHA1));
	cl_assert_equal_oid(&oid, &entry->id);
}

void test_index_crlf__safecrlf_true_autocrlf_input_text_auto_attr(void)
{
	const git3_index_entry *entry;
	git3_oid oid;

	cl_git_mkfile("./crlf/.gitattributes", "* text=auto\n");

	cl_repo_set_string(g_repo, "core.autocrlf", "input");
	cl_repo_set_bool(g_repo, "core.safecrlf", true);

	cl_git_mkfile("./crlf/newfile.txt", FILE_CONTENTS_LF);

	cl_git_pass(git3_index_add_bypath(g_index, "newfile.txt"));
	entry = git3_index_get_bypath(g_index, "newfile.txt", 0);
	cl_assert(entry);

	cl_git_pass(git3_oid_from_string(&oid, FILE_OID_LF, GIT3_OID_SHA1));
	cl_assert_equal_oid(&oid, &entry->id);

	cl_git_mkfile("./crlf/newfile2.txt", FILE_CONTENTS_CRLF);
	cl_git_fail(git3_index_add_bypath(g_index, "newfile2.txt"));
}

void test_index_crlf__safecrlf_true_autocrlf_input_text__no_attr(void)
{
	const git3_index_entry *entry;
	git3_oid oid;

	cl_repo_set_string(g_repo, "core.autocrlf", "input");
	cl_repo_set_bool(g_repo, "core.safecrlf", true);

	cl_git_mkfile("./crlf/newfile.txt", FILE_CONTENTS_LF);

	cl_git_pass(git3_index_add_bypath(g_index, "newfile.txt"));
	entry = git3_index_get_bypath(g_index, "newfile.txt", 0);
	cl_assert(entry);

	cl_git_pass(git3_oid_from_string(&oid, FILE_OID_LF, GIT3_OID_SHA1));
	cl_assert_equal_oid(&oid, &entry->id);

	cl_git_mkfile("./crlf/newfile2.txt", FILE_CONTENTS_CRLF);
	cl_git_fail(git3_index_add_bypath(g_index, "newfile2.txt"));
}

void test_index_crlf__safecrlf_true_no_attrs(void)
{
	cl_repo_set_bool(g_repo, "core.autocrlf", true);
	cl_repo_set_bool(g_repo, "core.safecrlf", true);

	cl_git_mkfile("crlf/newfile.txt", ALL_LF_TEXT_RAW);
	cl_git_fail(git3_index_add_bypath(g_index, "newfile.txt"));

	cl_git_mkfile("crlf/newfile.txt", ALL_CRLF_TEXT_RAW);
	cl_git_pass(git3_index_add_bypath(g_index, "newfile.txt"));

	cl_git_mkfile("crlf/newfile.txt", MORE_CRLF_TEXT_RAW);
	cl_git_fail(git3_index_add_bypath(g_index, "newfile.txt"));

	cl_git_mkfile("crlf/newfile.txt", MORE_LF_TEXT_RAW);
	cl_git_fail(git3_index_add_bypath(g_index, "newfile.txt"));
}
