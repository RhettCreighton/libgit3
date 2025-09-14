#include "clar_libgit3.h"
#include "posix.h"
#include "blob.h"
#include "filter.h"
#include "git3/sys/filter.h"
#include "git3/sys/repository.h"

static git3_repository *g_repo = NULL;

static git3_filter *create_compress_filter(void);
static git3_filter *compress_filter;

void test_filter_stream__initialize(void)
{
	compress_filter = create_compress_filter();

	cl_git_pass(git3_filter_register("compress", compress_filter, 50));
	g_repo = cl_git_sandbox_init("empty_standard_repo");
}

void test_filter_stream__cleanup(void)
{
	cl_git_sandbox_cleanup();
	g_repo = NULL;

	git3_filter_unregister("compress");
	git3__free(compress_filter);
}

#define CHUNKSIZE 10240

struct compress_stream {
	git3_writestream parent;
	git3_writestream *next;
	git3_filter_mode_t mode;
	char current;
	size_t current_chunk;
};

static int compress_stream_write__deflated(struct compress_stream *stream, const char *buffer, size_t len)
{
	size_t idx = 0;

	while (len > 0) {
		size_t chunkremain, chunksize;

		if (stream->current_chunk == 0)
			stream->current = buffer[idx];

		chunkremain = CHUNKSIZE - stream->current_chunk;
		chunksize = min(chunkremain, len);

		stream->current_chunk += chunksize;
		len -= chunksize;
		idx += chunksize;

		if (stream->current_chunk == CHUNKSIZE) {
			cl_git_pass(stream->next->write(stream->next, &stream->current, 1));
			stream->current_chunk = 0;
		}
	}

	return 0;
}

static int compress_stream_write__inflated(struct compress_stream *stream, const char *buffer, size_t len)
{
	char inflated[CHUNKSIZE];
	size_t i, j;

	for (i = 0; i < len; i++) {
		for (j = 0; j < CHUNKSIZE; j++)
			inflated[j] = buffer[i];

		cl_git_pass(stream->next->write(stream->next, inflated, CHUNKSIZE));
	}

	return 0;
}

static int compress_stream_write(git3_writestream *s, const char *buffer, size_t len)
{
	struct compress_stream *stream = (struct compress_stream *)s;

	return (stream->mode == GIT3_FILTER_TO_ODB) ?
		compress_stream_write__deflated(stream, buffer, len) :
		compress_stream_write__inflated(stream, buffer, len);
}

static int compress_stream_close(git3_writestream *s)
{
	struct compress_stream *stream = (struct compress_stream *)s;
	cl_assert_equal_i(0, stream->current_chunk);
	stream->next->close(stream->next);
	return 0;
}

static void compress_stream_free(git3_writestream *stream)
{
	git3__free(stream);
}

static int compress_filter_stream_init(
	git3_writestream **out,
	git3_filter *self,
	void **payload,
	const git3_filter_source *src,
	git3_writestream *next)
{
	struct compress_stream *stream = git3__calloc(1, sizeof(struct compress_stream));
	cl_assert(stream);

	GIT3_UNUSED(self);
	GIT3_UNUSED(payload);

	stream->parent.write = compress_stream_write;
	stream->parent.close = compress_stream_close;
	stream->parent.free = compress_stream_free;
	stream->next = next;
	stream->mode = git3_filter_source_mode(src);

	*out = (git3_writestream *)stream;
	return 0;
}

git3_filter *create_compress_filter(void)
{
	git3_filter *filter = git3__calloc(1, sizeof(git3_filter));
	cl_assert(filter);

	filter->version = GIT3_FILTER_VERSION;
	filter->attributes = "+compress";
	filter->stream = compress_filter_stream_init;

	return filter;
}

static void writefile(const char *filename, size_t numchunks)
{
	git3_str path = GIT3_STR_INIT;
	char buf[CHUNKSIZE];
	size_t i = 0, j = 0;
	int fd;

	cl_git_pass(git3_str_joinpath(&path, "empty_standard_repo", filename));

	fd = p_open(path.ptr, O_RDWR|O_CREAT, 0666);
	cl_assert(fd >= 0);

	for (i = 0; i < numchunks; i++) {
		for (j = 0; j < CHUNKSIZE; j++) {
			buf[j] = i % 256;
		}

		cl_git_pass(p_write(fd, buf, CHUNKSIZE));
	}
	p_close(fd);

	git3_str_dispose(&path);
}

static void test_stream(size_t numchunks)
{
	git3_index *index;
	const git3_index_entry *entry;
	git3_blob *blob;
	struct stat st;
	git3_checkout_options checkout_opts = GIT3_CHECKOUT_OPTIONS_INIT;

	checkout_opts.checkout_strategy = GIT3_CHECKOUT_FORCE;

	cl_git_mkfile(
		"empty_standard_repo/.gitattributes",
		"* compress\n");

	/* write a file to disk */
	writefile("streamed_file", numchunks);

	/* place it in the index */
	cl_git_pass(git3_repository_index(&index, g_repo));
	cl_git_pass(git3_index_add_bypath(index, "streamed_file"));
	cl_git_pass(git3_index_write(index));

	/* ensure it was appropriately compressed */
	cl_assert(entry = git3_index_get_bypath(index, "streamed_file", 0));

	cl_git_pass(git3_blob_lookup(&blob, g_repo, &entry->id));
	cl_assert_equal_i(numchunks, git3_blob_rawsize(blob));

	/* check the file back out */
	cl_must_pass(p_unlink("empty_standard_repo/streamed_file"));
	cl_git_pass(git3_checkout_index(g_repo, index, &checkout_opts));

	/* ensure it was decompressed */
	cl_must_pass(p_stat("empty_standard_repo/streamed_file", &st));
	cl_assert_equal_sz((numchunks * CHUNKSIZE), st.st_size);

	git3_index_free(index);
	git3_blob_free(blob);
}

/* write a 50KB file through the "compression" stream */
void test_filter_stream__smallfile(void)
{
	test_stream(5);
}

/* optionally write a 500 MB file through the compression stream */
void test_filter_stream__bigfile(void)
{
	if (!cl_is_env_set("GITTEST_INVASIVE_FS_SIZE"))
		cl_skip();

	test_stream(51200);
}
