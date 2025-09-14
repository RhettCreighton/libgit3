/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "common.h"

#include "git3/sys/config.h"
#include "config.h"

typedef struct git3_config_list git3_config_list;

typedef struct {
	git3_config_backend_entry base;
	git3_config_list *config_list;
} git3_config_list_entry;

int git3_config_list_new(git3_config_list **out);
int git3_config_list_dup(git3_config_list **out, git3_config_list *list);
int git3_config_list_dup_entry(git3_config_list *list, const git3_config_entry *entry);
void git3_config_list_incref(git3_config_list *list);
void git3_config_list_free(git3_config_list *list);
/* Add or append the new config option */
int git3_config_list_append(git3_config_list *list, git3_config_list_entry *entry);
int git3_config_list_get(git3_config_list_entry **out, git3_config_list *list, const char *key);
int git3_config_list_get_unique(git3_config_list_entry **out, git3_config_list *list, const char *key);
int git3_config_list_iterator_new(git3_config_iterator **out, git3_config_list *list);
const char *git3_config_list_add_string(git3_config_list *list, const char *str);

void git3_config_list_entry_free(git3_config_backend_entry *entry);
