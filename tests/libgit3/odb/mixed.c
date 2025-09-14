#include "clar_libgit3.h"
#include "odb.h"

static git3_odb *_odb;

void test_odb_mixed__initialize(void)
{
	cl_git_pass(git3_odb_open_ext(&_odb, cl_fixture("duplicate.git/objects"), NULL));
}

void test_odb_mixed__cleanup(void)
{
	git3_odb_free(_odb);
	_odb = NULL;
}

void test_odb_mixed__dup_oid(void) {
	const char hex[] = "ce013625030ba8dba906f756967f9e9ca394464a";
	const char short_hex[] = "ce01362";
	git3_oid oid;
	git3_odb_object *obj;

	cl_git_pass(git3_oid_from_string(&oid, hex, GIT3_OID_SHA1));
	cl_git_pass(git3_odb_read_prefix(&obj, _odb, &oid, GIT3_OID_SHA1_HEXSIZE));
	git3_odb_object_free(obj);

	cl_git_pass(git3_odb_exists_prefix(NULL, _odb, &oid, GIT3_OID_SHA1_HEXSIZE));

	cl_git_pass(git3_oid_from_prefix(&oid, short_hex, sizeof(short_hex) - 1, GIT3_OID_SHA1));
	cl_git_pass(git3_odb_read_prefix(&obj, _odb, &oid, sizeof(short_hex) - 1));
	git3_odb_object_free(obj);

	cl_git_pass(git3_odb_exists_prefix(NULL, _odb, &oid, sizeof(short_hex) - 1));
}

/* some known sha collisions of file content:
 *   'aabqhq' and 'aaazvc' with prefix 'dea509d0' (+ '9' and + 'b')
 *   'aaeufo' and 'aaaohs' with prefix '81b5bff5' (+ 'f' and + 'b')
 *   'aafewy' and 'aaepta' with prefix '739e3c4c'
 *   'aahsyn' and 'aadrjg' with prefix '0ddeaded' (+ '9' and + 'e')
 */

void test_odb_mixed__dup_oid_prefix_0(void) {
	char hex[10];
	git3_oid oid, found;
	git3_odb_object *obj;

	/* ambiguous in the same pack file */

	strncpy(hex, "dea509d0", sizeof(hex));
	cl_git_pass(git3_oid_from_prefix(&oid, hex, strlen(hex), GIT3_OID_SHA1));
	cl_assert_equal_i(
		GIT3_EAMBIGUOUS, git3_odb_read_prefix(&obj, _odb, &oid, strlen(hex)));
	cl_assert_equal_i(
		GIT3_EAMBIGUOUS, git3_odb_exists_prefix(&found, _odb, &oid, strlen(hex)));

	strncpy(hex, "dea509d09", sizeof(hex));
	cl_git_pass(git3_oid_from_prefix(&oid, hex, strlen(hex), GIT3_OID_SHA1));
	cl_git_pass(git3_odb_read_prefix(&obj, _odb, &oid, strlen(hex)));
	cl_git_pass(git3_odb_exists_prefix(&found, _odb, &oid, strlen(hex)));
	cl_assert_equal_oid(&found, git3_odb_object_id(obj));
	git3_odb_object_free(obj);

	strncpy(hex, "dea509d0b", sizeof(hex));
	cl_git_pass(git3_oid_from_prefix(&oid, hex, strlen(hex), GIT3_OID_SHA1));
	cl_git_pass(git3_odb_read_prefix(&obj, _odb, &oid, strlen(hex)));
	git3_odb_object_free(obj);

	/* ambiguous in different pack files */

	strncpy(hex, "81b5bff5", sizeof(hex));
	cl_git_pass(git3_oid_from_prefix(&oid, hex, strlen(hex), GIT3_OID_SHA1));
	cl_assert_equal_i(
		GIT3_EAMBIGUOUS, git3_odb_read_prefix(&obj, _odb, &oid, strlen(hex)));
	cl_assert_equal_i(
		GIT3_EAMBIGUOUS, git3_odb_exists_prefix(&found, _odb, &oid, strlen(hex)));

	strncpy(hex, "81b5bff5b", sizeof(hex));
	cl_git_pass(git3_oid_from_prefix(&oid, hex, strlen(hex), GIT3_OID_SHA1));
	cl_git_pass(git3_odb_read_prefix(&obj, _odb, &oid, strlen(hex)));
	cl_git_pass(git3_odb_exists_prefix(&found, _odb, &oid, strlen(hex)));
	cl_assert_equal_oid(&found, git3_odb_object_id(obj));
	git3_odb_object_free(obj);

	strncpy(hex, "81b5bff5f", sizeof(hex));
	cl_git_pass(git3_oid_from_prefix(&oid, hex, strlen(hex), GIT3_OID_SHA1));
	cl_git_pass(git3_odb_read_prefix(&obj, _odb, &oid, strlen(hex)));
	git3_odb_object_free(obj);

	/* ambiguous in pack file and loose */

	strncpy(hex, "0ddeaded", sizeof(hex));
	cl_git_pass(git3_oid_from_prefix(&oid, hex, strlen(hex), GIT3_OID_SHA1));
	cl_assert_equal_i(
		GIT3_EAMBIGUOUS, git3_odb_read_prefix(&obj, _odb, &oid, strlen(hex)));
	cl_assert_equal_i(
		GIT3_EAMBIGUOUS, git3_odb_exists_prefix(&found, _odb, &oid, strlen(hex)));

	strncpy(hex, "0ddeaded9", sizeof(hex));
	cl_git_pass(git3_oid_from_prefix(&oid, hex, strlen(hex), GIT3_OID_SHA1));
	cl_git_pass(git3_odb_read_prefix(&obj, _odb, &oid, strlen(hex)));
	cl_git_pass(git3_odb_exists_prefix(&found, _odb, &oid, strlen(hex)));
	cl_assert_equal_oid(&found, git3_odb_object_id(obj));
	git3_odb_object_free(obj);

	strncpy(hex, "0ddeadede", sizeof(hex));
	cl_git_pass(git3_oid_from_prefix(&oid, hex, strlen(hex), GIT3_OID_SHA1));
	cl_git_pass(git3_odb_read_prefix(&obj, _odb, &oid, strlen(hex)));
	git3_odb_object_free(obj);
}

struct expand_id_test_data {
	char *lookup_id;
	char *expected_id;
	git3_object_t expected_type;
};

struct expand_id_test_data expand_id_test_data[] = {
	/* some prefixes and their expected values */
	{ "dea509d0",  NULL, GIT3_OBJECT_ANY },
	{ "00000000",  NULL, GIT3_OBJECT_ANY },
	{ "dea509d0",  NULL, GIT3_OBJECT_ANY },
	{ "dea509d09", "dea509d097ce692e167dfc6a48a7a280cc5e877e", GIT3_OBJECT_BLOB },
	{ "dea509d0b", "dea509d0b3cb8ee0650f6ca210bc83f4678851ba", GIT3_OBJECT_BLOB },
	{ "ce0136250", "ce013625030ba8dba906f756967f9e9ca394464a", GIT3_OBJECT_BLOB },
	{ "0ddeaded",  NULL, GIT3_OBJECT_ANY },
	{ "4d5979b",   "4d5979b468252190cb572ae758aca36928e8a91e", GIT3_OBJECT_TREE },
	{ "0ddeaded",  NULL, GIT3_OBJECT_ANY },
	{ "0ddeadede", "0ddeadede9e6d6ccddce0ee1e5749eed0485e5ea", GIT3_OBJECT_BLOB },
	{ "0ddeaded9", "0ddeaded9502971eefe1e41e34d0e536853ae20f", GIT3_OBJECT_BLOB },
	{ "f00b4e",    NULL, GIT3_OBJECT_ANY },

	/* this OID is too short and should be ambiguous! */
	{ "f00",    NULL, GIT3_OBJECT_ANY },

	/* some full-length object ids */
	{ "0000000000000000000000000000000000000000", NULL, GIT3_OBJECT_ANY },
	{
	  "dea509d097ce692e167dfc6a48a7a280cc5e877e",
	  "dea509d097ce692e167dfc6a48a7a280cc5e877e",
	  GIT3_OBJECT_BLOB
	},
	{ "f00f00f00f00f00f00f00f00f00f00f00f00f00f", NULL, GIT3_OBJECT_ANY },
	{
	  "4d5979b468252190cb572ae758aca36928e8a91e",
	  "4d5979b468252190cb572ae758aca36928e8a91e",
	  GIT3_OBJECT_TREE
	},

	 /*
	  * ensure we're not leaking the return error code for the
	  * last lookup if the last object is invalid
	  */
	{ "0ddeadedfff",  NULL, GIT3_OBJECT_ANY },
};

static void setup_prefix_query(
	git3_odb_expand_id **out_ids,
	size_t *out_num)
{
	git3_odb_expand_id *ids;
	size_t num, i;

	num = ARRAY_SIZE(expand_id_test_data);

	cl_assert((ids = git3__calloc(num, sizeof(git3_odb_expand_id))));

	for (i = 0; i < num; i++) {
		git3_odb_expand_id *id = &ids[i];

		size_t len = strlen(expand_id_test_data[i].lookup_id);

		git3_oid_from_prefix(&id->id, expand_id_test_data[i].lookup_id, len, GIT3_OID_SHA1);
		id->length = (unsigned short)len;
		id->type = expand_id_test_data[i].expected_type;
	}

	*out_ids = ids;
	*out_num = num;
}

static void assert_found_objects(git3_odb_expand_id *ids)
{
	size_t num, i;

	num = ARRAY_SIZE(expand_id_test_data);

	for (i = 0; i < num; i++) {
		git3_oid expected_id = GIT3_OID_SHA1_ZERO;
		size_t expected_len = 0;
		git3_object_t expected_type = 0;

		if (expand_id_test_data[i].expected_id) {
			git3_oid_from_string(&expected_id, expand_id_test_data[i].expected_id, GIT3_OID_SHA1);
			expected_len = GIT3_OID_SHA1_HEXSIZE;
			expected_type = expand_id_test_data[i].expected_type;
		}

		cl_assert_equal_oid(&expected_id, &ids[i].id);
		cl_assert_equal_i(expected_len, ids[i].length);
		cl_assert_equal_i(expected_type, ids[i].type);
	}
}

static void assert_notfound_objects(git3_odb_expand_id *ids)
{
	git3_oid expected_id = GIT3_OID_SHA1_ZERO;
	size_t num, i;

	num = ARRAY_SIZE(expand_id_test_data);

	for (i = 0; i < num; i++) {
		cl_assert_equal_oid(&expected_id, &ids[i].id);
		cl_assert_equal_i(0, ids[i].length);
		cl_assert_equal_i(0, ids[i].type);
	}
}

void test_odb_mixed__expand_ids(void)
{
	git3_odb_expand_id *ids;
	size_t i, num;

	/* test looking for the actual (correct) types */

	setup_prefix_query(&ids, &num);
	cl_git_pass(git3_odb_expand_ids(_odb, ids, num));
	assert_found_objects(ids);
	git3__free(ids);

	/* test looking for an explicit `type == 0` */

	setup_prefix_query(&ids, &num);

	for (i = 0; i < num; i++)
		ids[i].type = 0;

	cl_git_pass(git3_odb_expand_ids(_odb, ids, num));
	assert_found_objects(ids);
	git3__free(ids);

	/* test looking for an explicit GIT3_OBJECT_ANY */

	setup_prefix_query(&ids, &num);

	for (i = 0; i < num; i++)
		ids[i].type = GIT3_OBJECT_ANY;

	cl_git_pass(git3_odb_expand_ids(_odb, ids, num));
	assert_found_objects(ids);
	git3__free(ids);

	/* test looking for the completely wrong type */

	setup_prefix_query(&ids, &num);

	for (i = 0; i < num; i++)
		ids[i].type = (ids[i].type == GIT3_OBJECT_BLOB) ?
			GIT3_OBJECT_TREE : GIT3_OBJECT_BLOB;

	cl_git_pass(git3_odb_expand_ids(_odb, ids, num));
	assert_notfound_objects(ids);
	git3__free(ids);
}

void test_odb_mixed__expand_ids_cached(void)
{
	git3_odb_expand_id *ids;
	size_t i, num;

	/* test looking for the actual (correct) types after accessing the object */

	setup_prefix_query(&ids, &num);

	for (i = 0; i < num; i++) {
		git3_odb_object *obj;
		if (ids[i].type == GIT3_OBJECT_ANY)
			continue;
		cl_git_pass(git3_odb_read_prefix(&obj, _odb, &ids[i].id, ids[i].length));
		git3_odb_object_free(obj);
	}

	cl_git_pass(git3_odb_expand_ids(_odb, ids, num));
	assert_found_objects(ids);
	git3__free(ids);
}
