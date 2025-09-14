#include "clar_libgit3.h"

git3_repository *_repo;

void test_object_shortid__initialize(void)
{
	_repo = cl_git_sandbox_init("duplicate.git");
}

void test_object_shortid__cleanup(void)
{
	cl_git_sandbox_cleanup();
}

void test_object_shortid__select(void)
{
	git3_oid full;
	git3_object *obj;
	git3_buf shorty = {0};

	git3_oid_from_string(&full, "ce013625030ba8dba906f756967f9e9ca394464a", GIT3_OID_SHA1);
	cl_git_pass(git3_object_lookup(&obj, _repo, &full, GIT3_OBJECT_ANY));
	cl_git_pass(git3_object_short_id(&shorty, obj));
	cl_assert_equal_i(7, shorty.size);
	cl_assert_equal_s("ce01362", shorty.ptr);
	git3_object_free(obj);

	git3_oid_from_string(&full, "038d718da6a1ebbc6a7780a96ed75a70cc2ad6e2", GIT3_OID_SHA1);
	cl_git_pass(git3_object_lookup(&obj, _repo, &full, GIT3_OBJECT_ANY));
	cl_git_pass(git3_object_short_id(&shorty, obj));
	cl_assert_equal_i(7, shorty.size);
	cl_assert_equal_s("038d718", shorty.ptr);
	git3_object_free(obj);

	git3_oid_from_string(&full, "dea509d097ce692e167dfc6a48a7a280cc5e877e", GIT3_OID_SHA1);
	cl_git_pass(git3_object_lookup(&obj, _repo, &full, GIT3_OBJECT_ANY));
	cl_git_pass(git3_object_short_id(&shorty, obj));
	cl_assert_equal_i(9, shorty.size);
	cl_assert_equal_s("dea509d09", shorty.ptr);
	git3_object_free(obj);

	git3_oid_from_string(&full, "dea509d0b3cb8ee0650f6ca210bc83f4678851ba", GIT3_OID_SHA1);
	cl_git_pass(git3_object_lookup(&obj, _repo, &full, GIT3_OBJECT_ANY));
	cl_git_pass(git3_object_short_id(&shorty, obj));
	cl_assert_equal_i(9, shorty.size);
	cl_assert_equal_s("dea509d0b", shorty.ptr);
	git3_object_free(obj);

	git3_buf_dispose(&shorty);
}

void test_object_shortid__core_abbrev(void)
{
	git3_oid full;
	git3_object *obj;
	git3_buf shorty = {0};
	git3_config *cfg;

	cl_git_pass(git3_repository_config(&cfg, _repo));
	git3_oid_from_string(&full, "ce013625030ba8dba906f756967f9e9ca394464a", GIT3_OID_SHA1);
	cl_git_pass(git3_object_lookup(&obj, _repo, &full, GIT3_OBJECT_ANY));

	cl_git_pass(git3_config_set_string(cfg, "core.abbrev", "auto"));
	cl_git_pass(git3_object_short_id(&shorty, obj));
	cl_assert_equal_i(7, shorty.size);
	cl_assert_equal_s("ce01362", shorty.ptr);

	cl_git_pass(git3_config_set_string(cfg, "core.abbrev", "off"));
	cl_git_pass(git3_object_short_id(&shorty, obj));
	cl_assert_equal_i(40, shorty.size);
	cl_assert_equal_s("ce013625030ba8dba906f756967f9e9ca394464a", shorty.ptr);

	cl_git_pass(git3_config_set_string(cfg, "core.abbrev", "false"));
	cl_git_pass(git3_object_short_id(&shorty, obj));
	cl_assert_equal_i(40, shorty.size);
	cl_assert_equal_s("ce013625030ba8dba906f756967f9e9ca394464a", shorty.ptr);

	cl_git_pass(git3_config_set_string(cfg, "core.abbrev", "99"));
	cl_git_pass(git3_object_short_id(&shorty, obj));
	cl_assert_equal_i(40, shorty.size);
	cl_assert_equal_s("ce013625030ba8dba906f756967f9e9ca394464a", shorty.ptr);

	cl_git_pass(git3_config_set_string(cfg, "core.abbrev", "4"));
	cl_git_pass(git3_object_short_id(&shorty, obj));
	cl_assert_equal_i(4, shorty.size);
	cl_assert_equal_s("ce01", shorty.ptr);

	cl_git_pass(git3_config_set_string(cfg, "core.abbrev", "0"));
	cl_git_fail(git3_object_short_id(&shorty, obj));
	cl_git_pass(git3_config_set_string(cfg, "core.abbrev", "3"));
	cl_git_fail(git3_object_short_id(&shorty, obj));
	cl_git_pass(git3_config_set_string(cfg, "core.abbrev", "invalid"));
	cl_git_fail(git3_object_short_id(&shorty, obj));
	cl_git_pass(git3_config_set_string(cfg, "core.abbrev", "true"));
	cl_git_fail(git3_object_short_id(&shorty, obj));

	git3_object_free(obj);
	git3_buf_dispose(&shorty);
	git3_config_free(cfg);
}
