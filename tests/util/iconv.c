#include "clar_libgit3.h"
#include "fs_path.h"

#ifdef GIT3_I18N_ICONV
static git3_fs_path_iconv_t ic;
static char *nfc = "\xC3\x85\x73\x74\x72\xC3\xB6\x6D";
static char *nfd = "\x41\xCC\x8A\x73\x74\x72\x6F\xCC\x88\x6D";
#endif

void test_iconv__initialize(void)
{
#ifdef GIT3_I18N_ICONV
	cl_git_pass(git3_fs_path_iconv_init_precompose(&ic));
#endif
}

void test_iconv__cleanup(void)
{
#ifdef GIT3_I18N_ICONV
	git3_fs_path_iconv_clear(&ic);
#endif
}

void test_iconv__unchanged(void)
{
#ifdef GIT3_I18N_ICONV
	const char *data = "Ascii data", *original = data;
	size_t datalen = strlen(data);

	cl_git_pass(git3_fs_path_iconv(&ic, &data, &datalen));
	GIT3_UNUSED(datalen);

	/* There are no high bits set, so this should leave data untouched */
	cl_assert(data == original);
#endif
}

void test_iconv__decomposed_to_precomposed(void)
{
#ifdef GIT3_I18N_ICONV
	const char *data = nfd;
	size_t datalen, nfdlen = strlen(nfd);

	datalen = nfdlen;
	cl_git_pass(git3_fs_path_iconv(&ic, &data, &datalen));
	GIT3_UNUSED(datalen);

	/* The decomposed nfd string should be transformed to the nfc form
	 * (on platforms where iconv is enabled, of course).
	 */
	cl_assert_equal_s(nfc, data);

	/* should be able to do it multiple times with the same git3_fs_path_iconv_t */
	data = nfd; datalen = nfdlen;
	cl_git_pass(git3_fs_path_iconv(&ic, &data, &datalen));
	cl_assert_equal_s(nfc, data);

	data = nfd; datalen = nfdlen;
	cl_git_pass(git3_fs_path_iconv(&ic, &data, &datalen));
	cl_assert_equal_s(nfc, data);
#endif
}

void test_iconv__precomposed_is_unmodified(void)
{
#ifdef GIT3_I18N_ICONV
	const char *data = nfc;
	size_t datalen = strlen(nfc);

	cl_git_pass(git3_fs_path_iconv(&ic, &data, &datalen));
	GIT3_UNUSED(datalen);

	/* data is already in precomposed form, so even though some bytes have
	 * the high-bit set, the iconv transform should result in no change.
	 */
	cl_assert_equal_s(nfc, data);
#endif
}
