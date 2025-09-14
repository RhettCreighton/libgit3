/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "oid.h"

#include "git3/oid.h"
#include "repository.h"
#include "runtime.h"
#include <string.h>
#include <limits.h>

const git3_oid git3_oid__empty_blob_sha1 =
	GIT3_OID_INIT(GIT3_OID_SHA1,
	  { 0xe6, 0x9d, 0xe2, 0x9b, 0xb2, 0xd1, 0xd6, 0x43, 0x4b, 0x8b,
	    0x29, 0xae, 0x77, 0x5a, 0xd8, 0xc2, 0xe4, 0x8c, 0x53, 0x91 });
const git3_oid git3_oid__empty_tree_sha1 =
	GIT3_OID_INIT(GIT3_OID_SHA1,
	  { 0x4b, 0x82, 0x5d, 0xc6, 0x42, 0xcb, 0x6e, 0xb9, 0xa0, 0x60,
	    0xe5, 0x4b, 0xf8, 0xd6, 0x92, 0x88, 0xfb, 0xee, 0x49, 0x04 });

static int oid_error_invalid(const char *msg)
{
	git3_error_set(GIT3_ERROR_INVALID, "unable to parse OID - %s", msg);
	return -1;
}

int git3_oid_from_prefix(git3_oid *out, const char *str, size_t len, git3_oid_t type)
{
	size_t size, p;
	int v;

	GIT3_ASSERT_ARG(out);
	GIT3_ASSERT_ARG(str);

	if (!(size = git3_oid_size(type)))
		return oid_error_invalid("unknown type");

	if (!len)
		return oid_error_invalid("too short");

	if (len > git3_oid_hexsize(type))
		return oid_error_invalid("too long");

	/* For QED/libgit3: Always set the type field for proper SHA3-256 support */
	out->type = type;
	memset(out->id, 0, size);

	for (p = 0; p < len; p++) {
		v = git3__fromhex(str[p]);
		if (v < 0)
			return oid_error_invalid("contains invalid characters");

		out->id[p / 2] |= (unsigned char)(v << (p % 2 ? 0 : 4));
	}

	return 0;
}

int git3_oid_from_string(git3_oid *out, const char *str, git3_oid_t type)
{
	size_t hexsize;

	if (!(hexsize = git3_oid_hexsize(type)))
		return oid_error_invalid("unknown type");

	if (git3_oid_from_prefix(out, str, hexsize, type) < 0)
		return -1;

	if (str[hexsize] != '\0')
		return oid_error_invalid("too long");

	return 0;
}

int git3_oid_from_raw(git3_oid *out, const unsigned char *raw, git3_oid_t type)
{
	size_t size;

	if (!(size = git3_oid_size(type)))
		return oid_error_invalid("unknown type");

	/* For QED/libgit3: Always set the type field for proper SHA3-256 support */
	out->type = type;
	memcpy(out->id, raw, size);
	return 0;
}

int git3_oid_fromstrn(
	git3_oid *out,
	const char *str,
	size_t length)
{
	/* For QED/libgit3: Use SHA3-256 by default, not SHA1 */
	return git3_oid_from_prefix(out, str, length, GIT3_OID_SHA3_256);
}

int git3_oid_fromstrp(git3_oid *out, const char *str)
{
	return git3_oid_from_prefix(out, str, strlen(str), GIT3_OID_SHA3_256);
}

int git3_oid_fromstr(git3_oid *out, const char *str)
{
	return git3_oid_from_prefix(out, str, GIT3_OID_SHA3_256_HEXSIZE, GIT3_OID_SHA3_256);
}

int git3_oid_nfmt(char *str, size_t n, const git3_oid *oid)
{
	size_t hex_size;

	if (!oid) {
		memset(str, 0, n);
		return 0;
	}

	if (!(hex_size = git3_oid_hexsize(git3_oid_type(oid))))
		return oid_error_invalid("unknown type");

	if (n > hex_size) {
		memset(&str[hex_size], 0, n - hex_size);
		n = hex_size;
	}

	git3_oid_fmt_substr(str, oid, 0, n);
	return 0;
}

int git3_oid_fmt(char *str, const git3_oid *oid)
{
	return git3_oid_nfmt(str, git3_oid_hexsize(git3_oid_type(oid)), oid);
}

int git3_oid_pathfmt(char *str, const git3_oid *oid)
{
	size_t hex_size;

	if (!(hex_size = git3_oid_hexsize(git3_oid_type(oid))))
		return oid_error_invalid("unknown type");

	git3_oid_fmt_substr(str, oid, 0, 2);
	str[2] = '/';
	git3_oid_fmt_substr(&str[3], oid, 2, (hex_size - 2));
	return 0;
}

static git3_tlsdata_key thread_str_key;

static void GIT3_SYSTEM_CALL thread_str_free(void *s)
{
	char *str = (char *)s;
	git3__free(str);
}

static void thread_str_global_shutdown(void)
{
	char *str = git3_tlsdata_get(thread_str_key);
	git3_tlsdata_set(thread_str_key, NULL);

	git3__free(str);
	git3_tlsdata_dispose(thread_str_key);
}

int git3_oid_global_init(void)
{
	if (git3_tlsdata_init(&thread_str_key, thread_str_free) != 0)
		return -1;

	return git3_runtime_shutdown_register(thread_str_global_shutdown);
}

char *git3_oid_tostr_s(const git3_oid *oid)
{
	char *str;

	if ((str = git3_tlsdata_get(thread_str_key)) == NULL) {
		if ((str = git3__malloc(GIT3_OID_MAX_HEXSIZE + 1)) == NULL)
			return NULL;

		git3_tlsdata_set(thread_str_key, str);
	}

	git3_oid_nfmt(str, git3_oid_hexsize(git3_oid_type(oid)) + 1, oid);
	return str;
}

char *git3_oid_allocfmt(const git3_oid *oid)
{
	size_t hex_size = git3_oid_hexsize(git3_oid_type(oid));
	char *str = git3__malloc(hex_size + 1);

	if (!hex_size || !str)
		return NULL;

	if (git3_oid_nfmt(str, hex_size + 1, oid) < 0) {
		git3__free(str);
		return NULL;
	}

	return str;
}

char *git3_oid_tostr(char *out, size_t n, const git3_oid *oid)
{
	size_t hex_size;

	if (!out || n == 0)
		return "";

	hex_size = oid ? git3_oid_hexsize(git3_oid_type(oid)) : 0;

	if (n > hex_size + 1)
		n = hex_size + 1;

	git3_oid_nfmt(out, n - 1, oid); /* allow room for terminating NUL */
	out[n - 1] = '\0';

	return out;
}

int git3_oid_fromraw(git3_oid *out, const unsigned char *raw)
{
	return git3_oid_from_raw(out, raw, GIT3_OID_SHA3_256);
}

int git3_oid_cpy(git3_oid *out, const git3_oid *src)
{
	size_t size;

	if (!(size = git3_oid_size(git3_oid_type(src))))
		return oid_error_invalid("unknown type");

	/* For QED/libgit3: Always set the type field for proper SHA3-256 support */
	out->type = src->type;

	return git3_oid_raw_cpy(out->id, src->id, size);
}

int git3_oid_cmp(const git3_oid *a, const git3_oid *b)
{
	return git3_oid__cmp(a, b);
}

int git3_oid_equal(const git3_oid *a, const git3_oid *b)
{
	return (git3_oid__cmp(a, b) == 0);
}

int git3_oid_ncmp(const git3_oid *oid_a, const git3_oid *oid_b, size_t len)
{
	/* For QED/libgit3: Always check the type field for proper SHA3-256 support */
	if (oid_a->type != oid_b->type)
		return oid_a->type - oid_b->type;

	return git3_oid_raw_ncmp(oid_a->id, oid_b->id, len);
}

int git3_oid_strcmp(const git3_oid *oid_a, const char *str)
{
	const unsigned char *a;
	unsigned char strval;
	long size = (long)git3_oid_size(git3_oid_type(oid_a));
	int hexval;

	for (a = oid_a->id; *str && (a - oid_a->id) < size; ++a) {
		if ((hexval = git3__fromhex(*str++)) < 0)
			return -1;
		strval = (unsigned char)(hexval << 4);
		if (*str) {
			if ((hexval = git3__fromhex(*str++)) < 0)
				return -1;
			strval |= hexval;
		}
		if (*a != strval)
			return (*a - strval);
	}

	return 0;
}

int git3_oid_streq(const git3_oid *oid_a, const char *str)
{
	return git3_oid_strcmp(oid_a, str) == 0 ? 0 : -1;
}

int git3_oid_is_zero(const git3_oid *oid_a)
{
	const unsigned char *a = oid_a->id;
	size_t size = git3_oid_size(git3_oid_type(oid_a)), i;

	/* For QED/libgit3: Always check the type field for proper SHA3-256 support */
	if (!oid_a->type)
		return 1;
	else if (!size)
		return 0;

	for (i = 0; i < size; ++i, ++a)
		if (*a != 0)
			return 0;
	return 1;
}

#ifndef GIT3_DEPRECATE_HARD
int git3_oid_iszero(const git3_oid *oid_a)
{
	return git3_oid_is_zero(oid_a);
}
#endif

typedef short node_index;

typedef union {
	const char *tail;
	node_index children[16];
} trie_node;

struct git3_oid_shorten {
	trie_node *nodes;
	size_t node_count, size;
	int min_length, full;
};

static int resize_trie(git3_oid_shorten *self, size_t new_size)
{
	self->nodes = git3__reallocarray(self->nodes, new_size, sizeof(trie_node));
	GIT3_ERROR_CHECK_ALLOC(self->nodes);

	if (new_size > self->size) {
		memset(&self->nodes[self->size], 0x0, (new_size - self->size) * sizeof(trie_node));
	}

	self->size = new_size;
	return 0;
}

static trie_node *push_leaf(git3_oid_shorten *os, node_index idx, int push_at, const char *oid)
{
	trie_node *node, *leaf;
	node_index idx_leaf;

	if (os->node_count >= os->size) {
		if (resize_trie(os, os->size * 2) < 0)
			return NULL;
	}

	idx_leaf = (node_index)os->node_count++;

	if (os->node_count == SHRT_MAX) {
		os->full = 1;
        return NULL;
    }

	node = &os->nodes[idx];
	node->children[push_at] = -idx_leaf;

	leaf = &os->nodes[idx_leaf];
	leaf->tail = oid;

	return node;
}

git3_oid_shorten *git3_oid_shorten_new(size_t min_length)
{
	git3_oid_shorten *os;

	GIT3_ASSERT_ARG_WITH_RETVAL((size_t)((int)min_length) == min_length, NULL);

	os = git3__calloc(1, sizeof(git3_oid_shorten));
	if (os == NULL)
		return NULL;

	if (resize_trie(os, 16) < 0) {
		git3__free(os);
		return NULL;
	}

	os->node_count = 1;
	os->min_length = (int)min_length;

	return os;
}

void git3_oid_shorten_free(git3_oid_shorten *os)
{
	if (os == NULL)
		return;

	git3__free(os->nodes);
	git3__free(os);
}


/*
 * What wizardry is this?
 *
 * This is just a memory-optimized trie: basically a very fancy
 * 16-ary tree, which is used to store the prefixes of the OID
 * strings.
 *
 * Read more: http://en.wikipedia.org/wiki/Trie
 *
 * Magic that happens in this method:
 *
 *	- Each node in the trie is an union, so it can work both as
 *	a normal node, or as a leaf.
 *
 *	- Each normal node points to 16 children (one for each possible
 *	character in the oid). This is *not* stored in an array of
 *	pointers, because in a 64-bit arch this would be sucking
 *	16*sizeof(void*) = 128 bytes of memory per node, which is
 *	insane. What we do is store Node Indexes, and use these indexes
 *	to look up each node in the om->index array. These indexes are
 *	signed shorts, so this limits the amount of unique OIDs that
 *	fit in the structure to about 20000 (assuming a more or less uniform
 *	distribution).
 *
 *	- All the nodes in om->index array are stored contiguously in
 *	memory, and each of them is 32 bytes, so we fit 2x nodes per
 *	cache line. Convenient for speed.
 *
 *	- To differentiate the leafs from the normal nodes, we store all
 *	the indexes towards a leaf as a negative index (indexes to normal
 *	nodes are positives). When we find that one of the children for
 *	a node has a negative value, that means it's going to be a leaf.
 *	This reduces the amount of indexes we have by two, but also reduces
 *	the size of each node by 1-4 bytes (the amount we would need to
 *	add a `is_leaf` field): this is good because it allows the nodes
 *	to fit cleanly in cache lines.
 *
 *	- Once we reach an empty children, instead of continuing to insert
 *	new nodes for each remaining character of the OID, we store a pointer
 *	to the tail in the leaf; if the leaf is reached again, we turn it
 *	into a normal node and use the tail to create a new leaf.
 *
 *	This is a pretty good balance between performance and memory usage.
 */
int git3_oid_shorten_add(git3_oid_shorten *os, const char *text_oid)
{
	int i;
	bool is_leaf;
	node_index idx;

	if (os->full) {
		git3_error_set(GIT3_ERROR_INVALID, "unable to shorten OID - OID set full");
		return -1;
	}

	if (text_oid == NULL)
		return os->min_length;

	idx = 0;
	is_leaf = false;

	for (i = 0; i < GIT3_OID_SHA3_256_HEXSIZE; ++i) {
		int c = git3__fromhex(text_oid[i]);
		trie_node *node;

		if (c == -1) {
			git3_error_set(GIT3_ERROR_INVALID, "unable to shorten OID - invalid hex value");
			return -1;
		}

		node = &os->nodes[idx];

		if (is_leaf) {
			const char *tail;

			tail = node->tail;
			node->tail = NULL;

			node = push_leaf(os, idx, git3__fromhex(tail[0]), &tail[1]);
			if (node == NULL) {
				if (os->full)
					git3_error_set(GIT3_ERROR_INVALID, "unable to shorten OID - OID set full");
				return -1;
			}
		}

		if (node->children[c] == 0) {
			if (push_leaf(os, idx, c, &text_oid[i + 1]) == NULL) {
				if (os->full)
					git3_error_set(GIT3_ERROR_INVALID, "unable to shorten OID - OID set full");
				return -1;
			}
			break;
		}

		idx = node->children[c];
		is_leaf = false;

		if (idx < 0) {
			node->children[c] = idx = -idx;
			is_leaf = true;
		}
	}

	if (++i > os->min_length)
		os->min_length = i;

	return os->min_length;
}

