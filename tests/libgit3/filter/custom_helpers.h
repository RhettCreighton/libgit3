#include "git3/sys/filter.h"

extern git3_filter *create_bitflip_filter(void);
extern git3_filter *create_reverse_filter(const char *attr);
extern git3_filter *create_erroneous_filter(const char *attr);

extern int bitflip_filter_apply(
	git3_filter     *self,
	void          **payload,
	git3_str        *to,
	const git3_str  *from,
	const git3_filter_source *source);

extern int reverse_filter_apply(
	git3_filter     *self,
	void          **payload,
	git3_str        *to,
	const git3_str  *from,
	const git3_filter_source *source);
