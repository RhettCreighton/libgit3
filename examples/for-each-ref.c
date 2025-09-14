#include <git3.h>
#include "common.h"

static int show_ref(git3_reference *ref, void *data)
{
	git3_repository *repo = data;
	git3_reference *resolved = NULL;
	char hex[GIT3_OID_SHA1_HEXSIZE+1];
	const git3_oid *oid;
	git3_object *obj;
	
	if (git3_reference_type(ref) == GIT3_REFERENCE_SYMBOLIC)
		check_lg2(git3_reference_resolve(&resolved, ref),
				  "Unable to resolve symbolic reference",
				  git3_reference_name(ref));
	
	oid = git3_reference_target(resolved ? resolved : ref);
	git3_oid_fmt(hex, oid);
	hex[GIT3_OID_SHA1_HEXSIZE] = 0;
	check_lg2(git3_object_lookup(&obj, repo, oid, GIT3_OBJECT_ANY),
			  "Unable to lookup object", hex);
	
	printf("%s %-6s\t%s\n",
		   hex,
		   git3_object_type2string(git3_object_type(obj)),
		   git3_reference_name(ref));
	
	git3_object_free(obj);
	git3_reference_free(ref);
	if (resolved)
		git3_reference_free(resolved);
	return 0;
}

int lg2_for_each_ref(git3_repository *repo, int argc, char **argv)
{
	UNUSED(argv);
	
	if (argc != 1)
		fatal("Sorry, no for-each-ref options supported yet", NULL);
	
	check_lg2(git3_reference_foreach(repo, show_ref, repo),
			  "Could not iterate over references", NULL);
	
	return 0;
}
