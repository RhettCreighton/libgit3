#include "git3/repository.h"
#include "git3/refs.h"
#include "common.h"
#include "util.h"
#include "path.h"
#include "ref_helpers.h"

int reference_is_packed(git3_reference *ref)
{
	git3_str ref_path = GIT3_STR_INIT;
	int packed;

	assert(ref);

	if (git3_str_joinpath(&ref_path,
		git3_repository_path(git3_reference_owner(ref)),
		git3_reference_name(ref)) < 0)
		return -1;

	packed = !git3_fs_path_isfile(ref_path.ptr);

	git3_str_dispose(&ref_path);

	return packed;
}
