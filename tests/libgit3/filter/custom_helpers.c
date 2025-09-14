#include "clar_libgit3.h"
#include "posix.h"
#include "filter.h"
#include "git3/sys/filter.h"
#include "custom_helpers.h"

#define VERY_SECURE_ENCRYPTION(b) ((b) ^ 0xff)

int bitflip_filter_apply(
	git3_filter     *self,
	void          **payload,
	git3_str        *to,
	const git3_str  *from,
	const git3_filter_source *source)
{
	const unsigned char *src = (const unsigned char *)from->ptr;
	unsigned char *dst;
	size_t i;

	GIT3_UNUSED(self); GIT3_UNUSED(payload);

	/* verify that attribute path match worked as expected */
	cl_assert_equal_i(
		0, git3__strncmp("hero", git3_filter_source_path(source), 4));

	if (!from->size)
		return 0;

	cl_git_pass(git3_str_grow(to, from->size));

	dst = (unsigned char *)to->ptr;

	for (i = 0; i < from->size; i++)
		dst[i] = VERY_SECURE_ENCRYPTION(src[i]);

	to->size = from->size;

	return 0;
}

static int bitflip_filter_stream(
	git3_writestream **out,
	git3_filter *self,
	void **payload,
	const git3_filter_source *src,
	git3_writestream *next)
{
	return git3_filter_buffered_stream_new(out,
		self, bitflip_filter_apply, NULL, payload, src, next);
}

static void bitflip_filter_free(git3_filter *f)
{
	git3__free(f);
}

git3_filter *create_bitflip_filter(void)
{
	git3_filter *filter = git3__calloc(1, sizeof(git3_filter));
	cl_assert(filter);

	filter->version = GIT3_FILTER_VERSION;
	filter->attributes = "+bitflip";
	filter->shutdown = bitflip_filter_free;
	filter->stream = bitflip_filter_stream;

	return filter;
}


int reverse_filter_apply(
	git3_filter     *self,
	void          **payload,
	git3_str        *to,
	const git3_str  *from,
	const git3_filter_source *source)
{
	const unsigned char *src = (const unsigned char *)from->ptr;
	const unsigned char *end = src + from->size;
	unsigned char *dst;

	GIT3_UNUSED(self); GIT3_UNUSED(payload); GIT3_UNUSED(source);

	/* verify that attribute path match worked as expected */
	cl_assert_equal_i(
		0, git3__strncmp("hero", git3_filter_source_path(source), 4));

	if (!from->size)
		return 0;

	cl_git_pass(git3_str_grow(to, from->size));

	dst = (unsigned char *)to->ptr + from->size - 1;

	while (src < end)
		*dst-- = *src++;

	to->size = from->size;

	return 0;
}

static int reverse_filter_stream(
	git3_writestream **out,
	git3_filter *self,
	void **payload,
	const git3_filter_source *src,
	git3_writestream *next)
{
	return git3_filter_buffered_stream_new(out,
		self, reverse_filter_apply, NULL, payload, src, next);
}

static void reverse_filter_free(git3_filter *f)
{
	git3__free(f);
}

git3_filter *create_reverse_filter(const char *attrs)
{
	git3_filter *filter = git3__calloc(1, sizeof(git3_filter));
	cl_assert(filter);

	filter->version = GIT3_FILTER_VERSION;
	filter->attributes = attrs;
	filter->shutdown = reverse_filter_free;
	filter->stream = reverse_filter_stream;

	return filter;
}

static int erroneous_filter_stream(
	git3_writestream **out,
	git3_filter *self,
	void **payload,
	const git3_filter_source *src,
	git3_writestream *next)
{
	GIT3_UNUSED(out);
	GIT3_UNUSED(self);
	GIT3_UNUSED(payload);
	GIT3_UNUSED(src);
	GIT3_UNUSED(next);
	return -1;
}

static void erroneous_filter_free(git3_filter *f)
{
	git3__free(f);
}

git3_filter *create_erroneous_filter(const char *attrs)
{
	git3_filter *filter = git3__calloc(1, sizeof(git3_filter));
	cl_assert(filter);

	filter->version = GIT3_FILTER_VERSION;
	filter->attributes = attrs;
	filter->stream = erroneous_filter_stream;
	filter->shutdown = erroneous_filter_free;

	return filter;
}
